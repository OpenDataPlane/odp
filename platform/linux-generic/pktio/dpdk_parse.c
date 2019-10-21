/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/autoheader_internal.h>

#ifdef _ODP_PKTIO_DPDK

#include <odp_packet_io_internal.h>
#include <odp_packet_dpdk.h>
#include <odp/api/byteorder.h>
#include <odp/api/plat/byteorder_inlines.h>

#include <protocols/eth.h>
#include <protocols/udp.h>
#include <protocols/tcp.h>

#include <rte_config.h>
#include <rte_mbuf.h>

#define IP4_CSUM_RESULT(ol_flags) (ol_flags & PKT_RX_IP_CKSUM_MASK)
#define L4_CSUM_RESULT(ol_flags) (ol_flags & PKT_RX_L4_CKSUM_MASK)

/** Parser helper function for Ethernet packets */
static inline uint16_t dpdk_parse_eth(packet_parser_t *prs,
				      const uint8_t **parseptr,
				      uint32_t *offset, uint32_t frame_len,
				      uint32_t mbuf_packet_type,
				      uint32_t supported_ptypes)
{
	uint16_t ethtype;
	const _odp_ethhdr_t *eth;
	uint16_t macaddr0, macaddr2, macaddr4;
	const _odp_vlanhdr_t *vlan;
	_odp_packet_input_flags_t input_flags;
	uint32_t l2_ptype;
	int vlan_supported = supported_ptypes & PTYPE_VLAN;
	int qinq_supported = supported_ptypes & PTYPE_VLAN_QINQ;
	int arp_supported  = supported_ptypes & PTYPE_ARP;

	input_flags.all = 0;
	input_flags.l2  = 1;
	input_flags.eth = 1;

	eth = (const _odp_ethhdr_t *)*parseptr;

	/* Detect jumbo frames */
	if (odp_unlikely(frame_len > _ODP_ETH_LEN_MAX))
		input_flags.jumbo = 1;

	/* Handle Ethernet broadcast/multicast addresses */
	macaddr0 = odp_be_to_cpu_16(*((const uint16_t *)(const void *)eth));
	if (odp_unlikely((macaddr0 & 0x0100) == 0x0100))
		input_flags.eth_mcast = 1;

	if (odp_unlikely(macaddr0 == 0xffff)) {
		macaddr2 =
			odp_be_to_cpu_16(*((const uint16_t *)
					    (const void *)eth + 1));
		macaddr4 =
			odp_be_to_cpu_16(*((const uint16_t *)
					    (const void *)eth + 2));

		if ((macaddr2 == 0xffff) && (macaddr4 == 0xffff))
			input_flags.eth_bcast = 1;
	}

	/* Get Ethertype */
	l2_ptype = mbuf_packet_type & RTE_PTYPE_L2_MASK;

	/* RTE_PTYPE_L2_ETHER type cannot be trusted when some L2 types are
	 * not supported. E.g. if VLAN is not supported, both VLAN and non-VLAN
	 * packets are marked as RTE_PTYPE_L2_ETHER. */
	ethtype = odp_be_to_cpu_16(eth->type);

	if (vlan_supported && l2_ptype == RTE_PTYPE_L2_ETHER_VLAN)
		ethtype = _ODP_ETHTYPE_VLAN;
	else if (qinq_supported && l2_ptype == RTE_PTYPE_L2_ETHER_QINQ)
		ethtype = _ODP_ETHTYPE_VLAN_OUTER;
	else if (arp_supported && l2_ptype == RTE_PTYPE_L2_ETHER_ARP)
		ethtype = _ODP_ETHTYPE_ARP;

	*offset += sizeof(*eth);
	*parseptr += sizeof(*eth);

	/* Check for SNAP vs. DIX */
	if (odp_unlikely(ethtype < _ODP_ETH_LEN_MAX)) {
		input_flags.snap = 1;
		if (ethtype > frame_len - *offset) {
			prs->flags.snap_len_err = 1;
			ethtype = 0;
			goto error;
		}
		ethtype = odp_be_to_cpu_16(*((const uint16_t *)(uintptr_t)
					      (parseptr + 6)));
		*offset   += 8;
		*parseptr += 8;
	}

	/* Parse the VLAN header(s), if present */
	if (odp_unlikely(ethtype == _ODP_ETHTYPE_VLAN_OUTER)) {
		input_flags.vlan_qinq = 1;
		input_flags.vlan = 1;

		vlan = (const _odp_vlanhdr_t *)*parseptr;
		ethtype = odp_be_to_cpu_16(vlan->type);
		*offset += sizeof(_odp_vlanhdr_t);
		*parseptr += sizeof(_odp_vlanhdr_t);
	}

	if (ethtype == _ODP_ETHTYPE_VLAN) {
		input_flags.vlan = 1;
		vlan = (const _odp_vlanhdr_t *)*parseptr;
		ethtype = odp_be_to_cpu_16(vlan->type);
		*offset += sizeof(_odp_vlanhdr_t);
		*parseptr += sizeof(_odp_vlanhdr_t);
	}

error:
	prs->input_flags.all |= input_flags.all;

	return ethtype;
}

/**
 * Parser helper function for IPv4
 */
static inline uint8_t dpdk_parse_ipv4(packet_parser_t *prs,
				      const uint8_t **parseptr,
				      uint32_t *offset, uint32_t frame_len,
				      uint32_t mbuf_packet_type,
				      uint64_t mbuf_ol,
				      uint32_t do_csum)
{
	const _odp_ipv4hdr_t *ipv4 = (const _odp_ipv4hdr_t *)*parseptr;
	uint32_t dstaddr = odp_be_to_cpu_32(ipv4->dst_addr);
	uint32_t l3_len = odp_be_to_cpu_16(ipv4->tot_len);
	uint8_t ver = _ODP_IPV4HDR_VER(ipv4->ver_ihl);
	uint8_t ihl = _ODP_IPV4HDR_IHL(ipv4->ver_ihl);
	uint32_t l4_packet_type = mbuf_packet_type & RTE_PTYPE_L4_MASK;
	uint16_t frag_offset;
	uint8_t proto;

	if (odp_unlikely(ihl < _ODP_IPV4HDR_IHL_MIN ||
			 ver != 4 ||
			 (l3_len > frame_len - *offset))) {
		prs->flags.ip_err = 1;
		return 0;
	}

	*offset   += ihl * 4;
	*parseptr += ihl * 4;

	if (do_csum) {
		uint64_t packet_csum_result = IP4_CSUM_RESULT(mbuf_ol);

		if (packet_csum_result == PKT_RX_IP_CKSUM_GOOD) {
			prs->input_flags.l3_chksum_done = 1;
		} else if (packet_csum_result != PKT_RX_IP_CKSUM_UNKNOWN) {
			prs->input_flags.l3_chksum_done = 1;
			prs->flags.ip_err = 1;
			prs->flags.l3_chksum_err = 1;
		}
	}

	if (odp_unlikely(ihl > _ODP_IPV4HDR_IHL_MIN))
		prs->input_flags.ipopt = 1;

	if (l4_packet_type == RTE_PTYPE_L4_UDP) {
		proto = _ODP_IPPROTO_UDP;
	} else if (l4_packet_type == RTE_PTYPE_L4_TCP) {
		proto = _ODP_IPPROTO_TCP;
	} else {
		proto = ipv4->proto;
		frag_offset = odp_be_to_cpu_16(ipv4->frag_offset);

		/* A packet is a fragment if:
		*  "more fragments" flag is set (all fragments except the last)
		*     OR
		*  "fragment offset" field is nonzero (all fragments except
		*  the first)
		*/
		if (odp_unlikely(l4_packet_type == RTE_PTYPE_L4_FRAG ||
				 _ODP_IPV4HDR_IS_FRAGMENT(frag_offset)))
			prs->input_flags.ipfrag = 1;
	}

	/**/
	/* Handle IPv4 broadcast / multicast */
	if (odp_unlikely(dstaddr == 0xffffffff))
		prs->input_flags.ip_bcast = 1;

	if (odp_unlikely((dstaddr >> 28) == 0xe))
		prs->input_flags.ip_mcast = 1;

	return proto;
}

static inline uint8_t dpdk_parse_ipv6(packet_parser_t *prs,
				      const uint8_t **parseptr,
				      uint32_t *offset, uint32_t frame_len,
				      uint32_t seg_len,
				      uint32_t mbuf_packet_type)
{
	const _odp_ipv6hdr_t *ipv6 = (const _odp_ipv6hdr_t *)*parseptr;
	const _odp_ipv6hdr_ext_t *ipv6ext;
	uint32_t dstaddr0 = odp_be_to_cpu_32(ipv6->dst_addr.u8[0]);
	uint32_t l3_len = odp_be_to_cpu_16(ipv6->payload_len) +
			  _ODP_IPV6HDR_LEN;
	uint32_t l4_packet_type = mbuf_packet_type & RTE_PTYPE_L4_MASK;

	/* Basic sanity checks on IPv6 header */
	if ((odp_be_to_cpu_32(ipv6->ver_tc_flow) >> 28) != 6 ||
	    l3_len > frame_len - *offset) {
		prs->flags.ip_err = 1;
		return 0;
	}

	/* IPv6 broadcast / multicast flags */
	prs->input_flags.ip_mcast = (dstaddr0 & 0xff000000) == 0xff000000;
	prs->input_flags.ip_bcast = 0;

	/* Skip past IPv6 header */
	*offset   += sizeof(_odp_ipv6hdr_t);
	*parseptr += sizeof(_odp_ipv6hdr_t);

	if (l4_packet_type == RTE_PTYPE_L4_UDP)
		return _ODP_IPPROTO_UDP;
	else if (l4_packet_type == RTE_PTYPE_L4_TCP)
		return _ODP_IPPROTO_TCP;

	/* Skip past any IPv6 extension headers */
	if (ipv6->next_hdr == _ODP_IPPROTO_HOPOPTS ||
	    ipv6->next_hdr == _ODP_IPPROTO_ROUTE) {
		prs->input_flags.ipopt = 1;

		do  {
			ipv6ext    = (const _odp_ipv6hdr_ext_t *)*parseptr;
			uint16_t extlen = 8 + ipv6ext->ext_len * 8;

			*offset   += extlen;
			*parseptr += extlen;
		} while ((ipv6ext->next_hdr == _ODP_IPPROTO_HOPOPTS ||
			  ipv6ext->next_hdr == _ODP_IPPROTO_ROUTE) &&
			 *offset < seg_len);

		if (*offset >= prs->l3_offset +
		    odp_be_to_cpu_16(ipv6->payload_len)) {
			prs->flags.ip_err = 1;
			return 0;
		}

		if (ipv6ext->next_hdr == _ODP_IPPROTO_FRAG)
			prs->input_flags.ipfrag = 1;

		return ipv6ext->next_hdr;
	}

	if (odp_unlikely(ipv6->next_hdr == _ODP_IPPROTO_FRAG)) {
		prs->input_flags.ipopt = 1;
		prs->input_flags.ipfrag = 1;
	}

	return ipv6->next_hdr;
}

/**
 * Parser helper function for TCP
 */
static inline void dpdk_parse_tcp(packet_parser_t *prs,
				  const uint8_t **parseptr,
				  uint64_t mbuf_ol,
				  uint32_t do_csum)
{
	const _odp_tcphdr_t *tcp = (const _odp_tcphdr_t *)*parseptr;
	uint32_t len = tcp->hl * 4;

	if (odp_unlikely(tcp->hl < sizeof(_odp_tcphdr_t) / sizeof(uint32_t)))
		prs->flags.tcp_err = 1;

	if (do_csum) {
		uint64_t packet_csum_result = L4_CSUM_RESULT(mbuf_ol);

		if (packet_csum_result == PKT_RX_L4_CKSUM_GOOD) {
			prs->input_flags.l4_chksum_done = 1;
		} else if (packet_csum_result != PKT_RX_L4_CKSUM_UNKNOWN) {
			prs->input_flags.l4_chksum_done = 1;
			prs->flags.tcp_err = 1;
			prs->flags.l4_chksum_err = 1;
		}
	}

	*parseptr += len;
}

/**
 * Parser helper function for UDP
 */
static inline void dpdk_parse_udp(packet_parser_t *prs,
				  const uint8_t **parseptr,
				  uint64_t mbuf_ol,
				  uint32_t do_csum)
{
	const _odp_udphdr_t *udp = (const _odp_udphdr_t *)*parseptr;
	uint32_t udplen = odp_be_to_cpu_16(udp->length);
	uint16_t ipsec_port = odp_cpu_to_be_16(_ODP_UDP_IPSEC_PORT);

	if (odp_unlikely(udplen < sizeof(_odp_udphdr_t)))
		prs->flags.udp_err = 1;

	if (do_csum) {
		uint64_t packet_csum_result = L4_CSUM_RESULT(mbuf_ol);

		if (packet_csum_result == PKT_RX_L4_CKSUM_GOOD) {
			prs->input_flags.l4_chksum_done = 1;
		} else if (packet_csum_result != PKT_RX_L4_CKSUM_UNKNOWN) {
			if (prs->input_flags.ipv4 && !udp->chksum) {
				prs->input_flags.l4_chksum_done = 1;
			} else {
				prs->input_flags.l4_chksum_done = 1;
				prs->flags.udp_err = 1;
				prs->flags.l4_chksum_err = 1;
			}
		}
	}

	if (odp_unlikely(ipsec_port == udp->dst_port && udplen > 4)) {
		uint32_t val;

		memcpy(&val, udp + 1, 4);
		if (val != 0) {
			prs->input_flags.ipsec = 1;
			prs->input_flags.ipsec_udp = 1;
		}
	}

	*parseptr += sizeof(_odp_udphdr_t);
}

static inline
int dpdk_packet_parse_common_l3_l4(packet_parser_t *prs,
				   const uint8_t *parseptr,
				   uint32_t offset,
				   uint32_t frame_len, uint32_t seg_len,
				   int layer, uint16_t ethtype,
				   uint32_t mbuf_packet_type,
				   uint64_t mbuf_ol,
				   odp_pktin_config_opt_t pktin_cfg)
{
	uint8_t  ip_proto;

	prs->l3_offset = offset;

	if (odp_unlikely(layer <= ODP_PROTO_LAYER_L2))
		return 0;

	/* Set l3 flag only for known ethtypes */
	prs->input_flags.l3 = 1;

	/* Parse Layer 3 headers */
	switch (ethtype) {
	case _ODP_ETHTYPE_IPV4:
		prs->input_flags.ipv4 = 1;
		ip_proto = dpdk_parse_ipv4(prs, &parseptr, &offset, frame_len,
					   mbuf_packet_type, mbuf_ol,
					   pktin_cfg.bit.ipv4_chksum);
		prs->l4_offset = offset;
		if (prs->flags.ip_err && pktin_cfg.bit.drop_ipv4_err)
			return -1; /* drop */
		break;

	case _ODP_ETHTYPE_IPV6:
		prs->input_flags.ipv6 = 1;
		ip_proto = dpdk_parse_ipv6(prs, &parseptr, &offset, frame_len,
					   seg_len, mbuf_packet_type);
		prs->l4_offset = offset;
		if (prs->flags.ip_err && pktin_cfg.bit.drop_ipv6_err)
			return -1; /* drop */
		break;

	case _ODP_ETHTYPE_ARP:
		prs->input_flags.arp = 1;
		ip_proto = 255;  /* Reserved invalid by IANA */
		break;

	default:
		prs->input_flags.l3 = 0;
		ip_proto = 255;  /* Reserved invalid by IANA */
	}

	if (layer == ODP_PROTO_LAYER_L3)
		return 0;

	/* Set l4 flag only for known ip_proto */
	prs->input_flags.l4 = 1;

	/* Parse Layer 4 headers */
	switch (ip_proto) {
	case _ODP_IPPROTO_ICMPV4:
	/* Fall through */

	case _ODP_IPPROTO_ICMPV6:
		prs->input_flags.icmp = 1;
		break;

	case _ODP_IPPROTO_IPIP:
		/* Do nothing */
		break;

	case _ODP_IPPROTO_TCP:
		if (odp_unlikely(offset + _ODP_TCPHDR_LEN > seg_len))
			return -1; /* drop */
		prs->input_flags.tcp = 1;
		dpdk_parse_tcp(prs, &parseptr, mbuf_ol,
			       pktin_cfg.bit.tcp_chksum);
		if (prs->flags.tcp_err && pktin_cfg.bit.drop_tcp_err)
			return -1; /* drop */
		break;

	case _ODP_IPPROTO_UDP:
		if (odp_unlikely(offset + _ODP_UDPHDR_LEN > seg_len))
			return -1; /* drop */
		prs->input_flags.udp = 1;
		dpdk_parse_udp(prs, &parseptr, mbuf_ol,
			       pktin_cfg.bit.udp_chksum);
		if (prs->flags.udp_err && pktin_cfg.bit.drop_udp_err)
			return -1; /* drop */
		break;

	case _ODP_IPPROTO_AH:
		prs->input_flags.ipsec = 1;
		prs->input_flags.ipsec_ah = 1;
		break;

	case _ODP_IPPROTO_ESP:
		prs->input_flags.ipsec = 1;
		prs->input_flags.ipsec_esp = 1;
		break;

	case _ODP_IPPROTO_SCTP:
		prs->input_flags.sctp = 1;
		break;

	case _ODP_IPPROTO_NO_NEXT:
		prs->input_flags.no_next_hdr = 1;
		break;

	default:
		prs->input_flags.l4 = 0;
		break;
	}

	return 0;
}

/**
 * DPDK packet parser
 */
int _odp_dpdk_packet_parse_common(packet_parser_t *prs, const uint8_t *ptr,
				  uint32_t frame_len, uint32_t seg_len,
				  struct rte_mbuf *mbuf, int layer,
				  uint32_t supported_ptype,
				  odp_pktin_config_opt_t pktin_cfg)
{
	uint32_t offset;
	uint16_t ethtype;
	const uint8_t *parseptr;
	uint32_t mbuf_packet_type;
	uint64_t mbuf_ol;

	parseptr = ptr;
	offset = 0;

	if (odp_unlikely(layer == ODP_PROTO_LAYER_NONE))
		return 0;

	mbuf_packet_type = mbuf->packet_type;
	mbuf_ol = mbuf->ol_flags;

	/* Assume valid L2 header, no CRC/FCS check in SW */
	prs->l2_offset = offset;

	ethtype = dpdk_parse_eth(prs, &parseptr, &offset, frame_len,
				 mbuf_packet_type, supported_ptype);

	return dpdk_packet_parse_common_l3_l4(prs, parseptr, offset, frame_len,
					      seg_len, layer, ethtype,
					      mbuf_packet_type, mbuf_ol,
					      pktin_cfg);
}

#endif /* _ODP_PKTIO_DPDK */

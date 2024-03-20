/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2022 Nokia
 */

#include <odp_parse_internal.h>
#include <odp_chksum_internal.h>
#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/sctp.h>
#include <protocols/tcp.h>
#include <protocols/udp.h>
#include <odp/api/hash.h>
#include <odp/api/packet_io.h>
#include <odp/api/packet_types.h>
#include <stdint.h>
#include <string.h>

/** Parser helper function for Ethernet packets
 *
 *  Requires up to PARSE_ETH_BYTES bytes of contiguous packet data.
 */
uint16_t _odp_parse_eth(packet_parser_t *prs, const uint8_t **parseptr,
			uint32_t *offset, uint32_t frame_len)
{
	uint16_t ethtype;
	const _odp_ethhdr_t *eth;
	uint16_t macaddr0, macaddr2, macaddr4;
	const _odp_vlanhdr_t *vlan;
	_odp_packet_input_flags_t input_flags;

	input_flags.all = 0;
	input_flags.l2  = 1;
	input_flags.eth = 1;

	eth = (const _odp_ethhdr_t *)*parseptr;

	/* Detect jumbo frames */
	if (odp_unlikely(frame_len - *offset > _ODP_ETH_LEN_MAX))
		input_flags.jumbo = 1;

	/* Handle Ethernet broadcast/multicast addresses */
	macaddr0 = odp_be_to_cpu_16(*((const odp_una_u16_t *)eth));
	if (odp_unlikely((macaddr0 & 0x0100) == 0x0100))
		input_flags.eth_mcast = 1;

	if (odp_unlikely(macaddr0 == 0xffff)) {
		macaddr2 = odp_be_to_cpu_16(*((const odp_una_u16_t *)eth + 1));
		macaddr4 = odp_be_to_cpu_16(*((const odp_una_u16_t *)eth + 2));

		if ((macaddr2 == 0xffff) && (macaddr4 == 0xffff))
			input_flags.eth_bcast = 1;
	}

	/* Get Ethertype */
	ethtype = odp_be_to_cpu_16(eth->type);
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
		ethtype = odp_be_to_cpu_16(*((const odp_una_u16_t *)(*parseptr + 6)));
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

	/*
	 * The packet was too short for what we parsed. We just give up
	 * entirely without trying to parse what fits in the packet.
	 */
	if (odp_unlikely(*offset > frame_len)) {
		input_flags.all = 0;
		input_flags.l2  = 1;
		ethtype = 0;
	}

error:
	prs->input_flags.all |= input_flags.all;

	return ethtype;
}

/**
 * Parser helper function for IPv4
 *
 * Requires up to PARSE_IPV4_BYTES bytes of contiguous packet data.
 */
static inline uint8_t parse_ipv4(packet_parser_t *prs, const uint8_t **parseptr,
				 uint32_t *offset, uint32_t frame_len,
				 odp_pktin_config_opt_t opt,
				 uint64_t *l4_part_sum)
{
	const _odp_ipv4hdr_t *ipv4 = (const _odp_ipv4hdr_t *)*parseptr;
	uint32_t dstaddr = odp_be_to_cpu_32(ipv4->dst_addr);
	uint32_t l3_len = odp_be_to_cpu_16(ipv4->tot_len);
	uint16_t frag_offset = odp_be_to_cpu_16(ipv4->frag_offset);
	uint8_t ver = _ODP_IPV4HDR_VER(ipv4->ver_ihl);
	uint8_t ihl = _ODP_IPV4HDR_IHL(ipv4->ver_ihl);

	if (odp_unlikely(prs->flags.l3_chksum_err ||
			 ihl < _ODP_IPV4HDR_IHL_MIN ||
			 ver != 4 ||
			 sizeof(*ipv4) > frame_len - *offset ||
			 (l3_len > frame_len - *offset))) {
		prs->flags.ip_err = 1;
		return 0;
	}

	if (opt.bit.ipv4_chksum) {
		prs->input_flags.l3_chksum_done = 1;
		if (chksum_finalize(chksum_partial(ipv4, ihl * 4, 0)) != 0xffff) {
			prs->flags.ip_err = 1;
			prs->flags.l3_chksum_err = 1;
			return 0;
		}
	}

	*offset   += ihl * 4;
	*parseptr += ihl * 4;

	if (opt.bit.udp_chksum || opt.bit.tcp_chksum)
		*l4_part_sum = chksum_partial((const uint8_t *)&ipv4->src_addr,
					      2 * _ODP_IPV4ADDR_LEN, 0);

	if (odp_unlikely(ihl > _ODP_IPV4HDR_IHL_MIN))
		prs->input_flags.ipopt = 1;

	/* A packet is a fragment if:
	*  "more fragments" flag is set (all fragments except the last)
	*     OR
	*  "fragment offset" field is nonzero (all fragments except the first)
	*/
	if (odp_unlikely(_ODP_IPV4HDR_IS_FRAGMENT(frag_offset)))
		prs->input_flags.ipfrag = 1;

	/* Handle IPv4 broadcast / multicast */
	if (odp_unlikely(dstaddr == 0xffffffff))
		prs->input_flags.ip_bcast = 1;

	if (odp_unlikely((dstaddr >> 28) == 0xe))
		prs->input_flags.ip_mcast = 1;

	return ipv4->proto;
}

/**
 * Parser helper function for IPv6
 *
 * Requires at least PARSE_IPV6_BYTES bytes of contiguous packet data.
 *
 * - offset is the offset of the first byte of the data pointed to by parseptr
 * - seg_end is the maximum offset that can be accessed plus one
 */
static inline uint8_t parse_ipv6(packet_parser_t *prs, const uint8_t **parseptr,
				 uint32_t *offset, uint32_t frame_len,
				 uint32_t seg_end,
				 odp_pktin_config_opt_t opt,
				 uint64_t *l4_part_sum)
{
	const _odp_ipv6hdr_t *ipv6 = (const _odp_ipv6hdr_t *)*parseptr;
	const _odp_ipv6hdr_ext_t *ipv6ext;
	uint32_t dstaddr0 = odp_be_to_cpu_32(ipv6->dst_addr.u8[0]);
	uint32_t l3_len = odp_be_to_cpu_16(ipv6->payload_len) +
			  _ODP_IPV6HDR_LEN;

	/* Basic sanity checks on IPv6 header */
	if (odp_unlikely(prs->flags.l3_chksum_err ||
			 (odp_be_to_cpu_32(ipv6->ver_tc_flow) >> 28) != 6 ||
			 sizeof(*ipv6) > frame_len - *offset ||
			 l3_len > frame_len - *offset)) {
		prs->flags.ip_err = 1;
		return 0;
	}

	/* IPv6 broadcast / multicast flags */
	prs->input_flags.ip_mcast = (dstaddr0 & 0xff000000) == 0xff000000;
	prs->input_flags.ip_bcast = 0;

	/* Skip past IPv6 header */
	*offset   += sizeof(_odp_ipv6hdr_t);
	*parseptr += sizeof(_odp_ipv6hdr_t);

	if (opt.bit.udp_chksum || opt.bit.tcp_chksum)
		*l4_part_sum = chksum_partial((const uint8_t *)&ipv6->src_addr,
					      2 * _ODP_IPV6ADDR_LEN, 0);

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
			 *offset < seg_end);

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
 *
 * Requires PARSE_TCP_BYTES bytes of contiguous packet data.
 */
static inline void parse_tcp(packet_parser_t *prs, const uint8_t **parseptr,
			     uint16_t tcp_len,
			     odp_pktin_config_opt_t opt,
			     uint64_t *l4_part_sum)
{
	const _odp_tcphdr_t *tcp = (const _odp_tcphdr_t *)*parseptr;
	uint32_t len = tcp->hl * 4;

	if (odp_unlikely(tcp->hl < sizeof(_odp_tcphdr_t) / sizeof(uint32_t)))
		prs->flags.tcp_err = 1;

	if (opt.bit.tcp_chksum &&
	    !prs->input_flags.ipfrag) {
		*l4_part_sum += odp_cpu_to_be_16(tcp_len);
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
		*l4_part_sum += _ODP_IPPROTO_TCP;
#else
		*l4_part_sum += _ODP_IPPROTO_TCP << 8;
#endif
	}

	*parseptr += len;
}

/**
 * Parser helper function for UDP
 *
 * Requires PARSE_UDP_BYTES bytes of contiguous packet data.
 */
static inline void parse_udp(packet_parser_t *prs, const uint8_t **parseptr,
			     odp_pktin_config_opt_t opt,
			     uint64_t *l4_part_sum)
{
	const _odp_udphdr_t *udp = (const _odp_udphdr_t *)*parseptr;
	uint32_t udplen = odp_be_to_cpu_16(udp->length);
	uint16_t ipsec_port = odp_cpu_to_be_16(_ODP_UDP_IPSEC_PORT);

	if (odp_unlikely(udplen < sizeof(_odp_udphdr_t))) {
		prs->flags.udp_err = 1;
		return;
	}

	if (opt.bit.udp_chksum &&
	    !prs->input_flags.ipfrag) {
		if (udp->chksum == 0) {
			prs->input_flags.l4_chksum_done = 1;
			prs->flags.l4_chksum_err =
				(prs->input_flags.ipv4 != 1);
		} else {
			*l4_part_sum += udp->length;
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			*l4_part_sum += _ODP_IPPROTO_UDP;
#else
			*l4_part_sum += _ODP_IPPROTO_UDP << 8;
#endif
		}
		prs->input_flags.udp_chksum_zero = (udp->chksum == 0);
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

/**
 * Parser helper function for SCTP
 *
 * Requires PARSE_SCTP_BYTES bytes of contiguous packet data.
 */
static inline void parse_sctp(packet_parser_t *prs, const uint8_t **parseptr,
			      uint16_t sctp_len,
			      odp_pktin_config_opt_t opt,
			      uint64_t *l4_part_sum)
{
	if (odp_unlikely(sctp_len < sizeof(_odp_sctphdr_t))) {
		prs->flags.sctp_err = 1;
		return;
	}

	if (opt.bit.sctp_chksum &&
	    !prs->input_flags.ipfrag) {
		const _odp_sctphdr_t *sctp =
			(const _odp_sctphdr_t *)*parseptr;
		uint32_t crc = ~0;
		uint32_t zero = 0;

		crc = odp_hash_crc32c(sctp, sizeof(*sctp) - 4, crc);
		crc = odp_hash_crc32c(&zero, 4, crc);
		*l4_part_sum = crc;
	}

	*parseptr += sizeof(_odp_sctphdr_t);
}

/*
 * Requires up to PARSE_L3_L4_BYTES bytes of contiguous packet data.
 *
 * - offset is the offset of the first byte of the data pointed to by parseptr
 * - seg_end is the maximum offset that can be accessed plus one
 */
int _odp_packet_parse_common_l3_l4(packet_parser_t *prs,
				   const uint8_t *parseptr, uint32_t offset,
				   uint32_t frame_len, uint32_t seg_end,
				   int layer, uint16_t ethtype,
				   uint64_t *l4_part_sum,
				   odp_pktin_config_opt_t opt)
{
	uint8_t  ip_proto;

	prs->l3_offset = offset;

	if (odp_unlikely(layer <= ODP_PROTO_LAYER_L2))
		return prs->flags.all.error != 0;

	/* Set l3 flag only for known ethtypes */
	prs->input_flags.l3 = 1;

	/* Parse Layer 3 headers */
	switch (ethtype) {
	case _ODP_ETHTYPE_IPV4:
		prs->input_flags.ipv4 = 1;
		ip_proto = parse_ipv4(prs, &parseptr, &offset, frame_len,
				      opt, l4_part_sum);
		if (odp_likely(!prs->flags.ip_err))
			prs->l4_offset = offset;
		else if (opt.bit.drop_ipv4_err)
			return -1; /* drop */
		break;

	case _ODP_ETHTYPE_IPV6:
		prs->input_flags.ipv6 = 1;
		ip_proto = parse_ipv6(prs, &parseptr, &offset, frame_len,
				      seg_end, opt, l4_part_sum);
		if (odp_likely(!prs->flags.ip_err))
			prs->l4_offset = offset;
		else if (opt.bit.drop_ipv6_err)
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
		return prs->flags.all.error != 0;

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
		if (odp_unlikely(offset + _ODP_TCPHDR_LEN > seg_end))
			return -1;
		prs->input_flags.tcp = 1;
		parse_tcp(prs, &parseptr, frame_len - prs->l4_offset, opt,
			  l4_part_sum);
		if (prs->flags.tcp_err && opt.bit.drop_tcp_err)
			return -1; /* drop */
		break;

	case _ODP_IPPROTO_UDP:
		if (odp_unlikely(offset + _ODP_UDPHDR_LEN > seg_end))
			return -1;
		prs->input_flags.udp = 1;
		parse_udp(prs, &parseptr, opt, l4_part_sum);
		if (prs->flags.udp_err && opt.bit.drop_udp_err)
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
		parse_sctp(prs, &parseptr, frame_len - prs->l4_offset, opt,
			   l4_part_sum);
		if (prs->flags.sctp_err && opt.bit.drop_sctp_err)
			return -1; /* drop */
		break;

	case _ODP_IPPROTO_NO_NEXT:
		prs->input_flags.no_next_hdr = 1;
		break;

	default:
		prs->input_flags.l4 = 0;
		break;
	}

	return prs->flags.all.error != 0;
}

/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_packet.h>
#include <odp_packet_internal.h>
#include <odp_hints.h>
#include <odp_byteorder.h>

#include <odph_eth.h>
#include <odph_ip.h>

#include <string.h>
#include <stdio.h>

#define ODP_PACKET_HDR_OFFSET_INVALID ((uint16_t)-1)

static inline uint8_t parse_ipv4(struct odp_pkthdr *pkt_hdr,
				 odph_ipv4hdr_t *ipv4,
				 size_t *offset_out);
static inline uint8_t parse_ipv6(struct odp_pkthdr *pkt_hdr,
				 odph_ipv6hdr_t *ipv6,
				 size_t *offset_out);

void odp_packet_init(odp_packet_t pkt)
{
	struct odp_pkthdr *const pkt_hdr = odp_packet_hdr(pkt);

	pkt_hdr->l2_offset = ODP_PACKET_HDR_OFFSET_INVALID;
	pkt_hdr->l3_offset = ODP_PACKET_HDR_OFFSET_INVALID;
	pkt_hdr->l4_offset = ODP_PACKET_HDR_OFFSET_INVALID;
}

void odp_packet_set_len(odp_packet_t pkt, size_t len)
{
	odp_buffer_t buf = odp_buffer_from_packet(pkt);
	Pktlib_setPacketLen(_odp_buf_to_ti_pkt(buf), len);
	/**
	 * @todo: Buffer length should be modified by buffer API when it
	 * become available
	 */
	_odp_buf_to_cppi_desc(buf)->buffLen = len;
}

size_t odp_packet_get_len(odp_packet_t pkt)
{
	odp_buffer_t buf = odp_buffer_from_packet(pkt);
	return Pktlib_getPacketLen(_odp_buf_to_ti_pkt(buf));
}

uint8_t *odp_packet_buf_addr(odp_packet_t pkt)
{
	return odp_buffer_addr(odp_buffer_from_packet(pkt));
}

uint8_t *odp_packet_start(odp_packet_t pkt)
{
	return odp_packet_buf_addr(pkt) + odp_packet_hdr(pkt)->frame_offset;
}


uint8_t *odp_packet_l2(odp_packet_t pkt)
{
	const size_t offset = odp_packet_l2_offset(pkt);

	if (odp_unlikely(offset == ODP_PACKET_HDR_OFFSET_INVALID))
		return NULL;

	return odp_packet_buf_addr(pkt) + offset;
}

size_t odp_packet_l2_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l2_offset;
}

void odp_packet_set_l2_offset(odp_packet_t pkt, size_t offset)
{
	odp_packet_hdr(pkt)->l2_offset = offset;
}

uint8_t *odp_packet_l3(odp_packet_t pkt)
{
	const size_t offset = odp_packet_l3_offset(pkt);

	if (odp_unlikely(offset == ODP_PACKET_HDR_OFFSET_INVALID))
		return NULL;

	return odp_packet_buf_addr(pkt) + offset;
}

size_t odp_packet_l3_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l3_offset;
}

void odp_packet_set_l3_offset(odp_packet_t pkt, size_t offset)
{
	odp_packet_hdr(pkt)->l3_offset = offset;
}

uint8_t *odp_packet_l4(odp_packet_t pkt)
{
	const size_t offset = odp_packet_l4_offset(pkt);

	if (odp_unlikely(offset == ODP_PACKET_HDR_OFFSET_INVALID))
		return NULL;

	return odp_packet_buf_addr(pkt) + offset;
}

size_t odp_packet_l4_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l4_offset;
}

void odp_packet_set_l4_offset(odp_packet_t pkt, size_t offset)
{
	odp_packet_hdr(pkt)->l4_offset = offset;
}

/**
 * Simple packet parser: eth, VLAN, IP, TCP/UDP/ICMP
 *
 * Internal function: caller is responsible for passing only
 * valid packet handles, lengths and offsets
 * (usually done&called in packet input).
 *
 * @param pkt        Packet handle
 * @param len        Packet length in bytes
 * @param frame_offset  Byte offset to L2 header
 */
void odp_packet_parse(odp_packet_t pkt, size_t len, size_t frame_offset)
{
	struct odp_pkthdr *const pkt_hdr = odp_packet_hdr(pkt);
	odph_ethhdr_t *eth;
	odph_vlanhdr_t *vlan;
	odph_ipv4hdr_t *ipv4;
	odph_ipv6hdr_t *ipv6;
	uint16_t ethtype;
	size_t offset = 0;
	uint8_t ip_proto = 0;

	pkt_hdr->input_flags.eth = 1;
	pkt_hdr->frame_offset = frame_offset;

	if (odp_unlikely(len < ODPH_ETH_LEN_MIN)) {
		pkt_hdr->error_flags.frame_len = 1;
		return;
	} else if (len > ODPH_ETH_LEN_MAX) {
		pkt_hdr->input_flags.jumbo = 1;
	}

	len -= 4; /* Crop L2 CRC */
	odp_packet_set_len(pkt, len);

	/* Assume valid L2 header, no CRC/FCS check in SW */
	pkt_hdr->input_flags.l2 = 1;
	pkt_hdr->l2_offset = frame_offset;

	eth = (odph_ethhdr_t *)odp_packet_start(pkt);
	ethtype = odp_be_to_cpu_16(eth->type);
	vlan = (odph_vlanhdr_t *)&eth->type;

	if (ethtype == ODPH_ETHTYPE_VLAN_OUTER) {
		pkt_hdr->input_flags.vlan_qinq = 1;
		ethtype = odp_be_to_cpu_16(vlan->tpid);
		offset += sizeof(odph_vlanhdr_t);
		vlan = &vlan[1];
	}

	if (ethtype == ODPH_ETHTYPE_VLAN) {
		pkt_hdr->input_flags.vlan = 1;
		ethtype = odp_be_to_cpu_16(vlan->tpid);
		offset += sizeof(odph_vlanhdr_t);
	}

	/* Set l3_offset+flag only for known ethtypes */
	switch (ethtype) {
	case ODPH_ETHTYPE_IPV4:
		pkt_hdr->input_flags.ipv4 = 1;
		pkt_hdr->input_flags.l3 = 1;
		pkt_hdr->l3_offset = frame_offset + ODPH_ETHHDR_LEN + offset;
		ipv4 = (odph_ipv4hdr_t *)odp_packet_l3(pkt);
		ip_proto = parse_ipv4(pkt_hdr, ipv4, &offset);
		break;
	case ODPH_ETHTYPE_IPV6:
		pkt_hdr->input_flags.ipv6 = 1;
		pkt_hdr->input_flags.l3 = 1;
		pkt_hdr->l3_offset = frame_offset + ODPH_ETHHDR_LEN + offset;
		ipv6 = (odph_ipv6hdr_t *)odp_packet_l3(pkt);
		ip_proto = parse_ipv6(pkt_hdr, ipv6, &offset);
		break;
	case ODPH_ETHTYPE_ARP:
		pkt_hdr->input_flags.arp = 1;
		/* fall through */
	default:
		ip_proto = 0;
		break;
	}

	switch (ip_proto) {
	case ODPH_IPPROTO_UDP:
		pkt_hdr->input_flags.udp = 1;
		pkt_hdr->input_flags.l4 = 1;
		pkt_hdr->l4_offset = pkt_hdr->l3_offset + offset;
		break;
	case ODPH_IPPROTO_TCP:
		pkt_hdr->input_flags.tcp = 1;
		pkt_hdr->input_flags.l4 = 1;
		pkt_hdr->l4_offset = pkt_hdr->l3_offset + offset;
		break;
	case ODPH_IPPROTO_SCTP:
		pkt_hdr->input_flags.sctp = 1;
		pkt_hdr->input_flags.l4 = 1;
		pkt_hdr->l4_offset = pkt_hdr->l3_offset + offset;
		break;
	case ODPH_IPPROTO_ICMP:
		pkt_hdr->input_flags.icmp = 1;
		pkt_hdr->input_flags.l4 = 1;
		pkt_hdr->l4_offset = pkt_hdr->l3_offset + offset;
		break;
	default:
		/* 0 or unhandled IP protocols, don't set L4 flag+offset */
		if (pkt_hdr->input_flags.ipv6) {
			/* IPv6 next_hdr is not L4, mark as IP-option instead */
			pkt_hdr->input_flags.ipopt = 1;
		}
		break;
	}
}

static inline uint8_t parse_ipv4(struct odp_pkthdr *pkt_hdr,
				 odph_ipv4hdr_t *ipv4,
				 size_t *offset_out)
{
	uint8_t ihl;
	uint16_t frag_offset;

	ihl = ODPH_IPV4HDR_IHL(ipv4->ver_ihl);
	if (odp_unlikely(ihl < ODPH_IPV4HDR_IHL_MIN)) {
		pkt_hdr->error_flags.ip_err = 1;
		return 0;
	}

	if (odp_unlikely(ihl > ODPH_IPV4HDR_IHL_MIN)) {
		pkt_hdr->input_flags.ipopt = 1;
		return 0;
	}

	/* A packet is a fragment if:
	*  "more fragments" flag is set (all fragments except the last)
	*     OR
	*  "fragment offset" field is nonzero (all fragments except the first)
	*/
	frag_offset = odp_be_to_cpu_16(ipv4->frag_offset);
	if (odp_unlikely(ODPH_IPV4HDR_IS_FRAGMENT(frag_offset))) {
		pkt_hdr->input_flags.ipfrag = 1;
		return 0;
	}

	if (ipv4->proto == ODPH_IPPROTO_ESP ||
	    ipv4->proto == ODPH_IPPROTO_AH) {
		pkt_hdr->input_flags.ipsec = 1;
		return 0;
	}

	/* Set pkt_hdr->input_flags.ipopt when checking L4 hdrs after return */

	*offset_out = sizeof(uint32_t) * ihl;
	return ipv4->proto;
}

static inline uint8_t parse_ipv6(struct odp_pkthdr *pkt_hdr,
				 odph_ipv6hdr_t *ipv6,
				 size_t *offset_out)
{
	if (ipv6->next_hdr == ODPH_IPPROTO_ESP ||
	    ipv6->next_hdr == ODPH_IPPROTO_AH) {
		pkt_hdr->input_flags.ipopt = 1;
		pkt_hdr->input_flags.ipsec = 1;
		return 0;
	}

	if (odp_unlikely(ipv6->next_hdr == ODPH_IPPROTO_FRAG)) {
		pkt_hdr->input_flags.ipopt = 1;
		pkt_hdr->input_flags.ipfrag = 1;
		return 0;
	}

	/* Don't step through more extensions */
	*offset_out = ODPH_IPV6HDR_LEN;
	return ipv6->next_hdr;
}

void odp_packet_print(odp_packet_t pkt)
{
	int max_len = 512;
	char str[max_len];
	int len = 0;
	int n = max_len-1;
	Cppi_HostDesc *desc;
	struct odp_pkthdr *hdr = odp_packet_hdr(pkt);
	odp_buffer_t buf = odp_buffer_from_packet(pkt);

	len += snprintf(&str[len], n-len, "Packet ");
	len += odp_buffer_snprint(&str[len], n-len, (odp_buffer_t) pkt);
	len += snprintf(&str[len], n-len,
			"  input_flags  0x%x\n", hdr->input_flags.all);
	len += snprintf(&str[len], n-len,
			"  error_flags  0x%x\n", hdr->error_flags.all);
	len += snprintf(&str[len], n-len,
			"  output_flags 0x%x\n", hdr->output_flags.all);
	len += snprintf(&str[len], n-len,
			"  frame_offset %u\n", hdr->frame_offset);
	len += snprintf(&str[len], n-len,
			"  l2_offset    %u\n", hdr->l2_offset);
	len += snprintf(&str[len], n-len,
			"  l3_offset    %u\n", hdr->l3_offset);
	len += snprintf(&str[len], n-len,
			"  l4_offset    %u\n", hdr->l4_offset);
	len += snprintf(&str[len], n-len,
			"  packet len   %u\n", odp_packet_get_len(pkt));
	len += snprintf(&str[len], n-len,
			"  input        %u\n", hdr->input);
	str[len] = '\0';

	printf("\n%s\n", str);
	desc = _odp_buf_to_cppi_desc(buf);
	odp_print_mem(desc, sizeof(*desc), "Descriptor dump");
	odp_print_mem((void *)desc->origBuffPtr,
		      desc->buffPtr - desc->origBuffPtr + 128,
		      "Buffer start");
}

int odp_packet_copy(odp_packet_t pkt_dst, odp_packet_t pkt_src)
{
	(void) pkt_dst;
	(void) pkt_src;
	return -1;
}

/* Copyright (c) 2013, Linaro Limited
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

static inline uint8_t parse_ipv4(odp_packet_hdr_t *pkt_hdr,
				 odph_ipv4hdr_t *ipv4, size_t *offset_out);
static inline uint8_t parse_ipv6(odp_packet_hdr_t *pkt_hdr,
				 odph_ipv6hdr_t *ipv6, size_t *offset_out);

void odp_packet_init(odp_packet_t pkt)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	const size_t start_offset = ODP_FIELD_SIZEOF(odp_packet_hdr_t, buf_hdr);
	uint8_t *start;
	size_t len;

	start = (uint8_t *)pkt_hdr + start_offset;
	len = ODP_OFFSETOF(odp_packet_hdr_t, payload) - start_offset;
	memset(start, 0, len);

	pkt_hdr->l2_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l3_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l4_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
}

odp_packet_t odp_packet_from_buffer(odp_buffer_t buf)
{
	return (odp_packet_t)buf;
}

odp_buffer_t odp_buffer_from_packet(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}

void odp_packet_set_len(odp_packet_t pkt, size_t len)
{
	/* for rte_pktmbuf */
	odp_buffer_hdr_t *buf_hdr = odp_buf_to_hdr(odp_buffer_from_packet(pkt));
	buf_hdr->pkt.data_len = len;

	odp_packet_hdr(pkt)->frame_len = len;
}

size_t odp_packet_get_len(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->frame_len;
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

	if (odp_unlikely(offset == ODP_PACKET_OFFSET_INVALID))
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

	if (odp_unlikely(offset == ODP_PACKET_OFFSET_INVALID))
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

	if (odp_unlikely(offset == ODP_PACKET_OFFSET_INVALID))
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
 * Internal function: caller is resposible for passing only valid packet handles
 * , lengths and offsets (usually done&called in packet input).
 *
 * @param pkt        Packet handle
 * @param len        Packet length in bytes
 * @param frame_offset  Byte offset to L2 header
 */
void odp_packet_parse(odp_packet_t pkt, size_t len, size_t frame_offset)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	odph_ethhdr_t *eth;
	odph_vlanhdr_t *vlan;
	odph_ipv4hdr_t *ipv4;
	odph_ipv6hdr_t *ipv6;
	uint16_t ethtype;
	size_t offset = 0;
	uint8_t ip_proto = 0;

	pkt_hdr->input_flags.eth = 1;
	pkt_hdr->frame_offset = frame_offset;
	pkt_hdr->frame_len = len;

	if (odp_unlikely(len < ODPH_ETH_LEN_MIN)) {
		pkt_hdr->error_flags.frame_len = 1;
		return;
	} else if (len > ODPH_ETH_LEN_MAX) {
		pkt_hdr->input_flags.jumbo = 1;
	}

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

static inline uint8_t parse_ipv4(odp_packet_hdr_t *pkt_hdr,
				 odph_ipv4hdr_t *ipv4, size_t *offset_out)
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

static inline uint8_t parse_ipv6(odp_packet_hdr_t *pkt_hdr,
				 odph_ipv6hdr_t *ipv6, size_t *offset_out)
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
	odp_packet_hdr_t *hdr = odp_packet_hdr(pkt);

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
			"  frame_len    %u\n", hdr->frame_len);
	len += snprintf(&str[len], n-len,
			"  input        %u\n", hdr->input);
	str[len] = '\0';

	printf("\n%s\n", str);
}

int odp_packet_copy(odp_packet_t pkt_dst, odp_packet_t pkt_src)
{
	odp_packet_hdr_t *const pkt_hdr_dst = odp_packet_hdr(pkt_dst);
	odp_packet_hdr_t *const pkt_hdr_src = odp_packet_hdr(pkt_src);
	const size_t start_offset = ODP_FIELD_SIZEOF(odp_packet_hdr_t, buf_hdr);
	uint8_t *start_src;
	uint8_t *start_dst;
	size_t len;

	if (pkt_dst == ODP_PACKET_INVALID || pkt_src == ODP_PACKET_INVALID)
		return -1;

	/* if (pkt_hdr_dst->buf_hdr.size < */
	/*	pkt_hdr_src->frame_len + pkt_hdr_src->frame_offset) */
	if (pkt_hdr_dst->buf_hdr.buf_len <
		pkt_hdr_src->frame_len + pkt_hdr_src->frame_offset)
		return -1;

	/* Copy packet header */
	start_dst = (uint8_t *)pkt_hdr_dst + start_offset;
	start_src = (uint8_t *)pkt_hdr_src + start_offset;
	len = ODP_OFFSETOF(odp_packet_hdr_t, payload) - start_offset;
	memcpy(start_dst, start_src, len);

	/* Copy frame payload */
	start_dst = (uint8_t *)odp_packet_start(pkt_dst);
	start_src = (uint8_t *)odp_packet_start(pkt_src);
	len = pkt_hdr_src->frame_len;
	memcpy(start_dst, start_src, len);

	/* Copy useful things from the buffer header */
	/* pkt_hdr_dst->buf_hdr.cur_offset = pkt_hdr_src->buf_hdr.cur_offset; */

	/* Create a copy of the scatter list */
	/* odp_buffer_copy_scatter(odp_buffer_from_packet(pkt_dst), */
	/*			odp_buffer_from_packet(pkt_src)); */

	return 0;
}

void odp_packet_set_ctx(odp_packet_t pkt, const void *ctx)
{
	odp_packet_hdr(pkt)->user_ctx = (intptr_t)ctx;
}

void *odp_packet_get_ctx(odp_packet_t pkt)
{
	return (void *)(intptr_t)odp_packet_hdr(pkt)->user_ctx;
}

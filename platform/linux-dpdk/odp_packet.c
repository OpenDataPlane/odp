/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_packet.h>
#include <odp_packet_internal.h>
#include <odp_hints.h>
#include <odp_byteorder.h>
#include <odp_debug_internal.h>

#include <odph_eth.h>
#include <odph_ip.h>

#include <string.h>
#include <stdio.h>

static inline uint8_t parse_ipv4(odp_packet_hdr_t *pkt_hdr,
				 odph_ipv4hdr_t *ipv4, size_t *offset_out);
static inline uint8_t parse_ipv6(odp_packet_hdr_t *pkt_hdr,
				 odph_ipv6hdr_t *ipv6, size_t *offset_out);

odp_packet_t odp_packet_alloc(odp_buffer_pool_t pool_hdl, uint32_t len)
{
	odp_packet_t pkt;
	odp_buffer_t buf;
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);

	if (pool->s.params.buf_type != ODP_BUFFER_TYPE_PACKET)
		return ODP_PACKET_INVALID;

	buf = odp_buffer_alloc(pool_hdl);
	if (odp_unlikely(!odp_buffer_is_valid(buf)))
		return ODP_PACKET_INVALID;

	pkt = odp_packet_from_buffer(buf);
	odp_packet_init(pkt);

	return pkt;
}

void odp_packet_free(odp_packet_t pkt)
{
	odp_buffer_t buf = odp_packet_to_buffer(pkt);

	odp_buffer_free(buf);
}

void odp_packet_init(odp_packet_t pkt)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	struct rte_mbuf *mb;
	void *start;

	mb = &pkt_hdr->buf_hdr.mb;

	start = mb->buf_addr;
	memset(start, 0, mb->buf_len);

	pkt_hdr->l2_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l3_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l4_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
}

odp_packet_t odp_packet_from_buffer(odp_buffer_t buf)
{
	return (odp_packet_t)buf;
}

odp_buffer_t odp_packet_to_buffer(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}

/* Advance the pkt data pointer and set len in one call */
static int odp_packet_set_offset_len(odp_packet_t pkt, size_t frame_offset,
				     size_t len)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	uint16_t offset;
	uint16_t data_len;

	/* The pkt buf may have been pulled back into the headroom
	 * so we cannot rely on finding the data right after the
	 * ODP header and HEADROOM */
	offset = (uint16_t)((unsigned long)mb->pkt.data -
			    (unsigned long)mb->buf_addr);
	ODP_ASSERT(mb->buf_len >= offset, "Corrupted mbuf");
	data_len = mb->buf_len - offset;

	if (data_len < frame_offset) {
		ODP_ERR("Frame offset too big");
		return -1;
	}
	mb->pkt.data = (void *)((char *)mb->pkt.data + frame_offset);
	data_len -= frame_offset;

	if (data_len < len) {
		ODP_ERR("Packet len too big");
		return -1;
	}
	mb->pkt.pkt_len = len;
	mb->pkt.data_len = len;

	return 0;
}

void odp_packet_set_len(odp_packet_t pkt, size_t len)
{
	(void)odp_packet_set_offset_len(pkt, 0, len);
}

size_t odp_packet_get_len(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return mb->pkt.pkt_len;
}

uint8_t *odp_packet_addr(odp_packet_t pkt)
{
	return odp_buffer_addr(odp_packet_to_buffer(pkt));
}

uint8_t *odp_packet_data(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return mb->pkt.data;
}


uint8_t *odp_packet_l2(odp_packet_t pkt)
{
	const size_t offset = odp_packet_l2_offset(pkt);

	if (odp_unlikely(offset == ODP_PACKET_OFFSET_INVALID))
		return NULL;

	return odp_packet_data(pkt) + offset;
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

	return odp_packet_data(pkt) + offset;
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

	return odp_packet_data(pkt) + offset;
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

	/* The frame_offset is not relevant for frames from DPDK */
	pkt_hdr->input_flags.eth = 1;
	(void) frame_offset;
	pkt_hdr->frame_offset = 0;
	if (odp_packet_set_offset_len(pkt, 0, len)) {
		return;
	}

	if (odp_unlikely(len < ODPH_ETH_LEN_MIN)) {
		pkt_hdr->error_flags.frame_len = 1;
		return;
	} else if (len > ODPH_ETH_LEN_MAX) {
		pkt_hdr->input_flags.jumbo = 1;
	}

	/* Assume valid L2 header, no CRC/FCS check in SW */
	pkt_hdr->input_flags.l2 = 1;
	pkt_hdr->l2_offset = 0;

	eth = (odph_ethhdr_t *)odp_packet_data(pkt);
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
		pkt_hdr->l3_offset = ODPH_ETHHDR_LEN + offset;
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
	uint8_t *p;
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
			"  frame_len    %u\n", hdr->buf_hdr.mb.pkt.pkt_len);
	len += snprintf(&str[len], n-len,
			"  input        %u\n", hdr->input);
	str[len] = '\0';

	printf("\n%s\n", str);
	rte_pktmbuf_dump(stdout, &hdr->buf_hdr.mb, 32);

	p = odp_packet_data(pkt);
	printf("00000000: %02X %02X %02X %02X %02X %02X %02X %02X\n",
	       p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
	printf("00000008: %02X %02X %02X %02X %02X %02X %02X %02X\n",
	       p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

}

/* For now we can only copy between packets of the same segment size
 * We should probably refine this API, maybe introduce a clone API */
int odp_packet_copy(odp_packet_t pkt_dst, odp_packet_t pkt_src)
{
	struct rte_mbuf *mb_dst, *mb_src;
	uint8_t nb_segs, i;

	ODP_ASSERT(odp_buffer_type(pkt_dst) == ODP_BUFFER_TYPE_PACKET &&
		   odp_buffer_type(pkt_src) == ODP_BUFFER_TYPE_PACKET,
		   "dst_pkt or src_pkt not of type ODP_BUFFER_TYPE_PACKET");

	if (pkt_dst == ODP_PACKET_INVALID || pkt_src == ODP_PACKET_INVALID)
		return -1;

	mb_dst = &(odp_packet_hdr(pkt_dst)->buf_hdr.mb);
	mb_src = &(odp_packet_hdr(pkt_src)->buf_hdr.mb);

	if (mb_dst->pkt.nb_segs != mb_src->pkt.nb_segs) {
		ODP_ERR("Different nb_segs in pkt_dst and pkt_src");
		return -1;
	}

	nb_segs = mb_src->pkt.nb_segs;

	if (mb_dst->buf_len < mb_src->buf_len) {
		ODP_ERR("dst_pkt smaller than src_pkt");
		return -1;
	}

	for (i = 0; i < nb_segs; i++) {
		if (mb_src == NULL || mb_dst == NULL) {
			ODP_ERR("Corrupted packets");
			return -1;
		}
		memcpy(mb_dst->buf_addr, mb_src->buf_addr, mb_src->buf_len);
		mb_dst = mb_dst->pkt.next;
		mb_src = mb_src->pkt.next;
	}
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

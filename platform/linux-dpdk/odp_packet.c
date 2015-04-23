/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/packet.h>
#include <odp_packet_internal.h>
#include <odp/hints.h>
#include <odp/byteorder.h>
#include <odp_debug_internal.h>

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

#include <string.h>
#include <stdio.h>
#include <stddef.h>

/* This is the offset for packet length inside odp_packet_t. */
const unsigned int pkt_len_offset = offsetof(odp_packet_hdr_t, buf_hdr) +
				    offsetof(struct odp_buffer_hdr_t, mb) +
				    offsetof(struct rte_mbuf, pkt) +
				    offsetof(struct rte_pktmbuf, pkt_len);

static inline uint8_t parse_ipv4(odp_packet_hdr_t *pkt_hdr,
				 odph_ipv4hdr_t *ipv4, size_t *offset_out);
static inline uint8_t parse_ipv6(odp_packet_hdr_t *pkt_hdr,
				 odph_ipv6hdr_t *ipv6, size_t *offset_out);

odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf)
{
	return (odp_packet_t)buf;
}

odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}

odp_packet_t odp_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
{
	odp_packet_t pkt;
	odp_buffer_t buf;
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);

	if (pool->s.params.type != ODP_POOL_PACKET)
		return ODP_PACKET_INVALID;

	buf = odp_buffer_alloc(pool_hdl);
	if (odp_unlikely(!odp_buffer_is_valid(buf)))
		return ODP_PACKET_INVALID;

	pkt = _odp_packet_from_buffer(buf);
	if (!odp_packet_reset(pkt, len))
		return ODP_PACKET_INVALID;

	return pkt;
}

void odp_packet_free(odp_packet_t pkt)
{
	odp_buffer_t buf = _odp_packet_to_buffer(pkt);

	odp_buffer_free(buf);
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	struct rte_mbuf *ms, *mb = &pkt_hdr->buf_hdr.mb;
	uint32_t buf_ofs;
	uint8_t nb_segs = 0;
	char *start;

	if (RTE_PKTMBUF_HEADROOM + len >= odp_packet_buf_len(pkt))
		return -1;

	start = (char *)mb + sizeof(mb) +
		ODP_OFFSETOF(odp_packet_hdr_t, l2_offset);
	memset((void *)start, 0, (char *)mb->buf_addr - start);

	pkt_hdr->l2_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l3_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l4_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;

	mb->pkt.in_port = 0xff;
	mb->pkt.pkt_len = len;
	ms = mb;
	do {
		ms->pkt.vlan_macip.data = 0;
		ms->ol_flags = 0;
		buf_ofs = (RTE_PKTMBUF_HEADROOM <= ms->buf_len) ?
				RTE_PKTMBUF_HEADROOM : ms->buf_len;
		ms->pkt.data = (char *)ms->buf_addr + buf_ofs;
		if (len > (ms->buf_len - buf_ofs)) {
			len -= ms->buf_len - buf_ofs;
			ms->pkt.data_len = ms->buf_len - buf_ofs;
		} else {
			ms->pkt.data_len = len;
			len = 0;
		}
		++nb_segs;
		ms = ms->pkt.next;
	} while (ms);

	mb->pkt.nb_segs = nb_segs;

	return 0;
}

odp_packet_t odp_packet_from_event(odp_event_t ev)
{
	return (odp_packet_t)ev;
}

odp_event_t odp_packet_to_event(odp_packet_t pkt)
{
	return (odp_event_t)pkt;
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

void *odp_packet_head(odp_packet_t pkt)
{
	return odp_buffer_addr(_odp_packet_to_buffer(pkt));
}

void *odp_packet_data(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return mb->pkt.data;
}

uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return rte_pktmbuf_data_len(mb);
}

uint32_t odp_packet_headroom(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return rte_pktmbuf_headroom(mb);
}

uint32_t odp_packet_tailroom(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return rte_pktmbuf_tailroom(rte_pktmbuf_lastseg(mb));
}

void *odp_packet_tail(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	mb = rte_pktmbuf_lastseg(mb);
	return (void *)((char *)mb->pkt.data + mb->pkt.data_len);
}

void *odp_packet_push_head(odp_packet_t pkt, uint32_t len)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return (void *)rte_pktmbuf_prepend(mb, len);
}

void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return (void *)rte_pktmbuf_adj(mb, len);
}


void *odp_packet_offset(odp_packet_t pkt, uint32_t offset, uint32_t *len,
			odp_packet_seg_t *seg)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);

	do {
		if (mb->pkt.data_len > offset) {
			break;
		} else {
			offset -= mb->pkt.data_len;
			mb = mb->pkt.next;
		}
	} while (mb);

	if (mb) {
		if (len)
			*len = mb->pkt.data_len - offset;
		if (seg)
			*seg = (odp_packet_seg_t)mb;
		return (void *)((char *)mb->pkt.data + offset);
	} else {
		return NULL;
	}
}

odp_pool_t odp_packet_pool(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.pool_hdl;
}

static inline void *packet_offset_to_ptr(odp_packet_t pkt, uint32_t *len,
					 const size_t offset)
{
	if (odp_unlikely(offset == ODP_PACKET_OFFSET_INVALID))
		return NULL;

	if (len)
		return odp_packet_offset(pkt, offset, len, NULL);
	else
		return odp_packet_offset(pkt, offset, NULL, NULL);
}

void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	const size_t offset = odp_packet_l2_offset(pkt);
	return packet_offset_to_ptr(pkt, len, offset);
}

uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l2_offset;
}

int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset)
{
	if (odp_unlikely(offset >= (odp_packet_len(pkt) - 1)))
		return -1;
	odp_packet_hdr(pkt)->l2_offset = offset;
	return 0;
}

void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	const size_t offset = odp_packet_l3_offset(pkt);

	return packet_offset_to_ptr(pkt, len, offset);
}

uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l3_offset;
}

int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	if (odp_unlikely(offset >= (odp_packet_len(pkt) - 1)))
		return -1;
	odp_packet_hdr(pkt)->l3_offset = offset;
	return 0;
}

void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	const size_t offset = odp_packet_l4_offset(pkt);

	return packet_offset_to_ptr(pkt, len, offset);
}

uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l4_offset;
}

int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	if (odp_unlikely(offset >= (odp_packet_len(pkt) - 1)))
		return -1;
	odp_packet_hdr(pkt)->l4_offset = offset;
	return 0;
}

int odp_packet_is_segmented(odp_packet_t pkt)
{
	return !rte_pktmbuf_is_contiguous(&odp_packet_hdr(pkt)->buf_hdr.mb);
}

int odp_packet_num_segs(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return mb->pkt.nb_segs;
}

odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)pkt;
}

odp_packet_seg_t odp_packet_last_seg(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return (odp_packet_seg_t)rte_pktmbuf_lastseg(mb);
}

odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt ODP_UNUSED,
				     odp_packet_seg_t seg)
{
	struct rte_mbuf *mb = (struct rte_mbuf *)seg;
	if (mb->pkt.next == NULL)
		return ODP_PACKET_SEG_INVALID;
	else
		return (odp_packet_seg_t)mb->pkt.next;
}

/*
 *
 * Segment level
 * ********************************************************
 *
 */

void *odp_packet_seg_buf_addr(odp_packet_t pkt ODP_UNUSED,
			      odp_packet_seg_t seg)
{
	return odp_packet_head((odp_packet_t)seg);
}

uint32_t odp_packet_seg_buf_len(odp_packet_t pkt ODP_UNUSED,
				odp_packet_seg_t seg)
{
	struct rte_mbuf *mb = (struct rte_mbuf *)seg;
	return mb->buf_len;
}

void *odp_packet_seg_data(odp_packet_t pkt ODP_UNUSED, odp_packet_seg_t seg)
{
	return odp_packet_data((odp_packet_t)seg);
}

uint32_t odp_packet_seg_data_len(odp_packet_t pkt ODP_UNUSED,
				 odp_packet_seg_t seg)
{
	return odp_packet_seg_len((odp_packet_t)seg);
}

/*
 *
 * Manipulation
 * ********************************************************
 *
 */

odp_packet_t odp_packet_add_data(odp_packet_t pkt, uint32_t offset,
				 uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t pktlen = odp_packet_len(pkt);
	odp_packet_t newpkt;

	if (offset > pktlen)
		return ODP_PACKET_INVALID;

	newpkt = odp_packet_alloc(pkt_hdr->buf_hdr.pool_hdl, pktlen + len);

	if (newpkt != ODP_PACKET_INVALID) {
		if (_odp_packet_copy_to_packet(pkt, 0,
					       newpkt, 0, offset) != 0 ||
		    _odp_packet_copy_to_packet(pkt, offset, newpkt,
					       offset + len,
					       pktlen - offset) != 0) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		} else {
			_odp_packet_copy_md_to_packet(pkt, newpkt);
			odp_packet_free(pkt);
		}
	}

	return newpkt;
}

odp_packet_t odp_packet_rem_data(odp_packet_t pkt, uint32_t offset,
				 uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t pktlen = odp_packet_len(pkt);
	odp_packet_t newpkt;

	if (offset > pktlen || offset + len > pktlen)
		return ODP_PACKET_INVALID;

	newpkt = odp_packet_alloc(pkt_hdr->buf_hdr.pool_hdl, pktlen - len);

	if (newpkt != ODP_PACKET_INVALID) {
		if (_odp_packet_copy_to_packet(pkt, 0,
					       newpkt, 0, offset) != 0 ||
		    _odp_packet_copy_to_packet(pkt, offset + len,
					       newpkt, offset,
					       pktlen - offset - len) != 0) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		} else {
			_odp_packet_copy_md_to_packet(pkt, newpkt);
			odp_packet_free(pkt);
		}
	}

	return newpkt;
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
	if (odp_packet_set_offset_len(pkt, 0, len))
		return;

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
		ipv4 = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
		ip_proto = parse_ipv4(pkt_hdr, ipv4, &offset);
		break;
	case ODPH_ETHTYPE_IPV6:
		pkt_hdr->input_flags.ipv6 = 1;
		pkt_hdr->input_flags.l3 = 1;
		pkt_hdr->l3_offset = frame_offset + ODPH_ETHHDR_LEN + offset;
		ipv6 = (odph_ipv6hdr_t *)odp_packet_l3_ptr(pkt, NULL);
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
			"  input        %" PRIu64 "\n",
			odp_pktio_to_u64(hdr->input));
	str[len] = '\0';

	ODP_ERR("\n%s\n", str);
	rte_pktmbuf_dump(stdout, &hdr->buf_hdr.mb, 32);

	p = odp_packet_data(pkt);
	ODP_ERR("00000000: %02X %02X %02X %02X %02X %02X %02X %02X\n",
		p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
	ODP_ERR("00000008: %02X %02X %02X %02X %02X %02X %02X %02X\n",
		p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

void _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt)
{
	odp_packet_hdr_t *srchdr = odp_packet_hdr(srcpkt);
	odp_packet_hdr_t *dsthdr = odp_packet_hdr(dstpkt);
	uint8_t *newstart, *srcstart;
	uint32_t meta_offset = ODP_FIELD_SIZEOF(odp_packet_hdr_t, buf_hdr);

	newstart = (uint8_t *)dsthdr + meta_offset;
	srcstart = (uint8_t *)srchdr + meta_offset;

	memcpy(newstart, srcstart,
	       sizeof(odp_packet_hdr_t) - meta_offset);

	dsthdr->buf_hdr.buf_u64 = srchdr->buf_hdr.buf_u64;

	dsthdr->buf_hdr.mb.pkt.in_port = srchdr->buf_hdr.mb.pkt.in_port;
	dsthdr->buf_hdr.mb.pkt.vlan_macip =
			srchdr->buf_hdr.mb.pkt.vlan_macip;
	dsthdr->buf_hdr.mb.pkt.hash = srchdr->buf_hdr.mb.pkt.hash;
	dsthdr->buf_hdr.mb.ol_flags = srchdr->buf_hdr.mb.ol_flags;
}

int _odp_packet_copy_to_packet(odp_packet_t srcpkt, uint32_t srcoffset,
			       odp_packet_t dstpkt, uint32_t dstoffset,
			       uint32_t len)
{
	void *srcmap;
	void *dstmap;
	uint32_t cpylen, minseg;
	uint32_t srcseglen = 0; /* GCC */
	uint32_t dstseglen = 0; /* GCC */

	if (srcoffset + len > odp_packet_len(srcpkt) ||
	    dstoffset + len > odp_packet_len(dstpkt))
		return -1;

	while (len > 0) {
		srcmap = odp_packet_offset(srcpkt, srcoffset, &srcseglen, NULL);
		dstmap = odp_packet_offset(dstpkt, dstoffset, &dstseglen, NULL);

		minseg = dstseglen > srcseglen ? srcseglen : dstseglen;
		cpylen = len > minseg ? minseg : len;
		memcpy(dstmap, srcmap, cpylen);

		srcoffset += cpylen;
		dstoffset += cpylen;
		len       -= cpylen;
	}

	return 0;
}

odp_packet_t odp_packet_copy(odp_packet_t pkt_src, odp_pool_t pool)
{
	uint32_t pktlen = odp_packet_len(pkt_src);
	odp_packet_t newpkt = odp_packet_alloc(pool, pktlen);

	if (newpkt != ODP_PACKET_INVALID) {
		/* Must copy metadata first, followed by packet data */
		_odp_packet_copy_md_to_packet(pkt_src, newpkt);

		if (_odp_packet_copy_to_packet(pkt_src, 0,
					       newpkt, 0, pktlen) != 0) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		}
	}

	return newpkt;
}

int odp_packet_copydata_out(odp_packet_t pkt, uint32_t offset,
			    uint32_t len, void *dst)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cpylen;
	uint8_t *dstaddr = (uint8_t *)dst;

	if (offset + len > odp_packet_len(pkt))
		return -1;

	while (len > 0) {
		mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		cpylen = len > seglen ? seglen : len;
		memcpy(dstaddr, mapaddr, cpylen);
		offset  += cpylen;
		dstaddr += cpylen;
		len     -= cpylen;
	}

	return 0;
}

int odp_packet_copydata_in(odp_packet_t pkt, uint32_t offset,
			   uint32_t len, const void *src)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint32_t cpylen;
	const uint8_t *srcaddr = (const uint8_t *)src;

	if (offset + len > odp_packet_len(pkt))
		return -1;

	while (len > 0) {
		mapaddr = odp_packet_offset(pkt, offset, &seglen, NULL);
		cpylen = len > seglen ? seglen : len;
		memcpy(mapaddr, srcaddr, cpylen);
		offset  += cpylen;
		srcaddr += cpylen;
		len     -= cpylen;
	}

	return 0;
}

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx)
{
	odp_packet_hdr(pkt)->buf_hdr.buf_cctx = ctx;
}

void *odp_packet_user_ptr(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.buf_ctx;
}

void odp_packet_user_u64_set(odp_packet_t pkt, uint64_t ctx)
{
	odp_packet_hdr(pkt)->buf_hdr.buf_u64 = ctx;
}

uint64_t odp_packet_user_u64(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.buf_u64;
}

int odp_packet_is_valid(odp_packet_t pkt)
{
	odp_buffer_t buf = _odp_packet_to_buffer(pkt);

	return odp_buffer_is_valid(buf);
}

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	uint32_t buf_len = mb->buf_len;
	while (mb->pkt.next != NULL) {
		mb = mb->pkt.next;
		buf_len += mb->buf_len;
	}
	return buf_len;
}

void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	if (rte_pktmbuf_trim(mb, len))
		return NULL;
	else
		return odp_packet_tail(pkt);
}

void *odp_packet_push_tail(odp_packet_t pkt, uint32_t len)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return (void *)rte_pktmbuf_append(mb, len);
}

odp_pktio_t odp_packet_input(odp_packet_t pkt)
{
	odp_pool_t pool_hdl = odp_buffer_pool(_odp_packet_to_buffer(pkt));
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	return pool->s.pktio;
}

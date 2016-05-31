/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/packet.h>
#include <odp_packet_internal.h>
#include <odp/api/hints.h>
#include <odp/api/byteorder.h>
#include <odp_debug_internal.h>

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/tcp.h>
#include <odp/helper/udp.h>

#include <string.h>
#include <stdio.h>
#include <stddef.h>

/* These are the offsets for packet accessors for inlining. */
const unsigned int buf_addr_offset = offsetof(odp_packet_hdr_t, buf_hdr) +
				     offsetof(struct odp_buffer_hdr_t, mb) +
				     offsetof(struct rte_mbuf, buf_addr);
const unsigned int data_off_offset = offsetof(odp_packet_hdr_t, buf_hdr) +
				     offsetof(struct odp_buffer_hdr_t, mb) +
				     offsetof(struct rte_mbuf, data_off);

/* The last bit is an expanded version of offsetof(), to make sure that if
 * rte_pktmbuf_[pkt|data]_len() changes, we will either adapt automatically, or
 * throw a compile failure
 */
const unsigned int pkt_len_offset = offsetof(odp_packet_hdr_t, buf_hdr) +
				    offsetof(struct odp_buffer_hdr_t, mb) +
				    (size_t)&rte_pktmbuf_pkt_len((struct rte_mbuf *)0);
const unsigned int seg_len_offset = offsetof(odp_packet_hdr_t, buf_hdr) +
				    offsetof(struct odp_buffer_hdr_t, mb) +
				    (size_t)&rte_pktmbuf_data_len((struct rte_mbuf *)0);

const unsigned int udata_len_offset = offsetof(odp_packet_hdr_t, uarea_size);
const unsigned int udata_offset = sizeof(odp_packet_hdr_t);
const unsigned int rss_offset = offsetof(odp_packet_hdr_t, buf_hdr) +
				offsetof(struct odp_buffer_hdr_t, mb) +
				offsetof(struct rte_mbuf, hash.rss);
const unsigned int ol_flags_offset = offsetof(odp_packet_hdr_t, buf_hdr) +
				     offsetof(struct odp_buffer_hdr_t, mb) +
				     offsetof(struct rte_mbuf, ol_flags);
const uint64_t rss_flag = PKT_RX_RSS_HASH;

struct rte_mbuf dummy;
ODP_STATIC_ASSERT(sizeof(dummy.data_off) == sizeof(uint16_t),
		  "data_off should be uint16_t");
ODP_STATIC_ASSERT(sizeof(dummy.pkt_len) == sizeof(uint32_t),
		  "pkt_len should be uint32_t");
ODP_STATIC_ASSERT(sizeof(dummy.data_len) == sizeof(uint16_t),
		  "data_len should be uint16_t");
ODP_STATIC_ASSERT(sizeof(dummy.hash.rss) == sizeof(uint32_t),
		  "hash.rss should be uint32_t");
ODP_STATIC_ASSERT(sizeof(dummy.ol_flags) == sizeof(uint64_t),
		  "ol_flags should be uint64_t");


odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf)
{
	return (odp_packet_t)buf;
}

odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}

void packet_parse_reset(odp_packet_hdr_t *pkt_hdr)
{
	/* Reset parser metadata before new parse */
	pkt_hdr->error_flags.all  = 0;
	pkt_hdr->input_flags.all  = 0;
	pkt_hdr->output_flags.all = 0;
	pkt_hdr->l2_offset        = 0;
	pkt_hdr->l3_offset        = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l4_offset        = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->payload_offset   = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->vlan_s_tag       = 0;
	pkt_hdr->vlan_c_tag       = 0;
}

static odp_packet_t packet_alloc(pool_entry_t* pool, uint32_t len)
{
	odp_packet_t pkt;
	uintmax_t totsize = RTE_PKTMBUF_HEADROOM + len;
	odp_packet_hdr_t *pkt_hdr;
	struct rte_mbuf *mbuf;

	if (pool->s.params.type != ODP_POOL_PACKET)
		return ODP_PACKET_INVALID;

	mbuf = rte_pktmbuf_alloc(pool->s.rte_mempool);
	if (mbuf == NULL) {
		rte_errno = ENOMEM;
		return ODP_PACKET_INVALID;
	}
	pkt_hdr = (odp_packet_hdr_t *)mbuf;
	pkt_hdr->buf_hdr.totsize = mbuf->buf_len;

	if (mbuf->buf_len < totsize) {
		intmax_t needed = totsize - mbuf->buf_len;
		struct rte_mbuf *curseg = mbuf;

		do {
			struct rte_mbuf *nextseg =
				rte_pktmbuf_alloc(pool->s.rte_mempool);

			if (nextseg == NULL) {
				rte_pktmbuf_free(mbuf);
				return ODP_PACKET_INVALID;
			}

			curseg->next = nextseg;
			curseg = nextseg;
			curseg->data_off = 0;
			pkt_hdr->buf_hdr.totsize += curseg->buf_len;
			needed -= curseg->buf_len;
		} while (needed > 0);
	}

	pkt = (odp_packet_t)mbuf;

	if (odp_packet_reset(pkt, len) != 0)
		return ODP_PACKET_INVALID;

	return pkt;
}

odp_packet_t odp_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);

	return packet_alloc(pool, len);
}

int odp_packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
			   odp_packet_t pkt[], int num)
{
	int i;
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);

	for (i = 0; i < num; i++) {
		pkt[i] = packet_alloc(pool, len);
		if (pkt[i] == ODP_PACKET_INVALID)
			return rte_errno == ENOMEM ? i : -EINVAL;
	}
	return i;
}

void odp_packet_free(odp_packet_t pkt)
{
	struct rte_mbuf *mbuf = (struct rte_mbuf *)pkt;
	rte_pktmbuf_free(mbuf);
}

void odp_packet_free_multi(const odp_packet_t pkt[], int num)
{
	int i;

	for (i = 0; i < num; i++) {
		struct rte_mbuf *mbuf = (struct rte_mbuf *)pkt[i];

		rte_pktmbuf_free(mbuf);
	}
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	struct rte_mbuf *ms, *mb = &pkt_hdr->buf_hdr.mb;
	uint8_t nb_segs = 0;
	int32_t lenleft = len;
	char *start;

	if (RTE_PKTMBUF_HEADROOM + len > odp_packet_buf_len(pkt)) {
		ODP_DBG("Not enought head room for that packet %d/%d\n",
			RTE_PKTMBUF_HEADROOM + len,
			odp_packet_buf_len(pkt));
		return -1;
	}

	start = (char *)&pkt_hdr->l2_offset;
	memset((void *)start, 0,
	       ODP_OFFSETOF(odp_packet_hdr_t, uarea_size) -
	       ODP_OFFSETOF(odp_packet_hdr_t, l2_offset));

	pkt_hdr->l2_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l3_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l4_offset = (uint32_t) ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->buf_hdr.next = NULL;

	mb->port = 0xff;
	mb->pkt_len = len;
	mb->data_off = RTE_PKTMBUF_HEADROOM;
	mb->vlan_tci = 0;
	nb_segs = 1;

	if (RTE_PKTMBUF_HEADROOM + lenleft <= mb->buf_len) {
		mb->data_len = lenleft;
	} else {
		mb->data_len = mb->buf_len - RTE_PKTMBUF_HEADROOM;
		lenleft -= mb->data_len;
		ms = mb->next;
		while (lenleft > 0) {
			nb_segs++;
			ms->data_len = lenleft <= ms->buf_len ?
				lenleft : ms->buf_len;
			lenleft -= ms->buf_len;
			ms = ms->next;
		}
	}

	mb->nb_segs = nb_segs;
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

void *odp_packet_head(odp_packet_t pkt)
{
	return odp_buffer_addr(_odp_packet_to_buffer(pkt));
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
	return (void *)(rte_pktmbuf_mtod(mb, char *) + mb->data_len);
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
		if (mb->data_len > offset) {
			break;
		} else {
			offset -= mb->data_len;
			mb = mb->next;
		}
	} while (mb);

	if (mb) {
		if (len)
			*len = mb->data_len - offset;
		if (seg)
			*seg = (odp_packet_seg_t)mb;
		return (void *)(rte_pktmbuf_mtod(mb, char *) + offset);
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
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	if (!packet_hdr_has_l2(pkt_hdr))
		return NULL;
	return packet_offset_to_ptr(pkt, len, offset);
}

uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	if (!packet_hdr_has_l2(pkt_hdr))
		return ODP_PACKET_OFFSET_INVALID;
	return pkt_hdr->l2_offset;
}

int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	if (odp_unlikely(offset >= (odp_packet_len(pkt) - 1)))
		return -1;
	packet_hdr_has_l2_set(pkt_hdr, 1);
	pkt_hdr->l2_offset = offset;
	return 0;
}

void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	const size_t offset = odp_packet_l3_offset(pkt);
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	if (packet_parse_not_complete(pkt_hdr))
		_odp_packet_parse(pkt_hdr);

	return packet_offset_to_ptr(pkt, len, offset);
}

uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	if (packet_parse_not_complete(pkt_hdr))
		_odp_packet_parse(pkt_hdr);
	return pkt_hdr->l3_offset;
}

int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	if (odp_unlikely(offset >= (odp_packet_len(pkt) - 1)))
		return -1;
	if (packet_parse_not_complete(pkt_hdr))
		_odp_packet_parse(pkt_hdr);
	pkt_hdr->l3_offset = offset;
	return 0;
}

void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	const size_t offset = odp_packet_l4_offset(pkt);
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	if (packet_parse_not_complete(pkt_hdr))
		_odp_packet_parse(pkt_hdr);

	return packet_offset_to_ptr(pkt, len, offset);
}

uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	if (packet_parse_not_complete(pkt_hdr))
		_odp_packet_parse(pkt_hdr);
	return pkt_hdr->l4_offset;
}

int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	if (odp_unlikely(offset >= (odp_packet_len(pkt) - 1)))
		return -1;
	if (packet_parse_not_complete(pkt_hdr))
		_odp_packet_parse(pkt_hdr);
	pkt_hdr->l4_offset = offset;
	return 0;
}

odp_time_t odp_packet_ts(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->timestamp;
}

void odp_packet_ts_set(odp_packet_t pkt, odp_time_t timestamp)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	pkt_hdr->timestamp = timestamp;
	pkt_hdr->input_flags.timestamp = 1;
}

int odp_packet_is_segmented(odp_packet_t pkt)
{
	return !rte_pktmbuf_is_contiguous(&odp_packet_hdr(pkt)->buf_hdr.mb);
}

int odp_packet_num_segs(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &(odp_packet_hdr(pkt)->buf_hdr.mb);
	return mb->nb_segs;
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
	if (mb->next == NULL)
		return ODP_PACKET_SEG_INVALID;
	else
		return (odp_packet_seg_t)mb->next;
}

/*
 *
 * Segment level
 * ********************************************************
 *
 */

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

int odp_packet_add_data(odp_packet_t *pkt_ptr, uint32_t offset, uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t pktlen = odp_packet_len(pkt);
	odp_packet_t newpkt;

	if (offset > pktlen)
		return -1;

	newpkt = odp_packet_alloc(pkt_hdr->buf_hdr.pool_hdl, pktlen + len);

	if (newpkt == ODP_PACKET_INVALID)
		return -1;

	if (odp_packet_copy_from_pkt(newpkt, 0, pkt, 0, offset) != 0 ||
	    odp_packet_copy_from_pkt(newpkt, offset + len, pkt, offset,
				     pktlen - offset) != 0) {
		odp_packet_free(newpkt);
		return -1;
	}

	_odp_packet_copy_md_to_packet(pkt, newpkt);
	odp_packet_free(pkt);
	*pkt_ptr = newpkt;

	return 1;
}

int odp_packet_rem_data(odp_packet_t *pkt_ptr, uint32_t offset, uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t pktlen = odp_packet_len(pkt);
	odp_packet_t newpkt;

	if (offset > pktlen || offset + len > pktlen)
		return -1;

	newpkt = odp_packet_alloc(pkt_hdr->buf_hdr.pool_hdl, pktlen - len);

	if (newpkt == ODP_PACKET_INVALID)
		return -1;

	if (odp_packet_copy_from_pkt(newpkt, 0, pkt, 0, offset) != 0 ||
	    odp_packet_copy_from_pkt(newpkt, offset, pkt, offset + len,
				     pktlen - offset - len) != 0) {
		odp_packet_free(newpkt);
		return -1;
	}

	_odp_packet_copy_md_to_packet(pkt, newpkt);
	odp_packet_free(pkt);
	*pkt_ptr = newpkt;

	return 1;
}

/**
 * Parser helper function for IPv4
 */
static inline uint8_t parse_ipv4(odp_packet_hdr_t *pkt_hdr,
				 uint8_t **parseptr, uint32_t *offset)
{
	odph_ipv4hdr_t *ipv4 = (odph_ipv4hdr_t *)*parseptr;
	uint8_t ver = ODPH_IPV4HDR_VER(ipv4->ver_ihl);
	uint8_t ihl = ODPH_IPV4HDR_IHL(ipv4->ver_ihl);
	uint16_t frag_offset;

	pkt_hdr->l3_len = odp_be_to_cpu_16(ipv4->tot_len);

	if (odp_unlikely(ihl < ODPH_IPV4HDR_IHL_MIN) ||
	    odp_unlikely(ver != 4) ||
	    (pkt_hdr->l3_len > pkt_hdr->buf_hdr.mb.pkt_len - *offset)) {
		pkt_hdr->error_flags.ip_err = 1;
		return 0;
	}

	*offset   += ihl * 4;
	*parseptr += ihl * 4;

	if (odp_unlikely(ihl > ODPH_IPV4HDR_IHL_MIN))
		pkt_hdr->input_flags.ipopt = 1;

	/* A packet is a fragment if:
	*  "more fragments" flag is set (all fragments except the last)
	*     OR
	*  "fragment offset" field is nonzero (all fragments except the first)
	*/
	frag_offset = odp_be_to_cpu_16(ipv4->frag_offset);
	if (odp_unlikely(ODPH_IPV4HDR_IS_FRAGMENT(frag_offset)))
		pkt_hdr->input_flags.ipfrag = 1;

	return ipv4->proto;
}

/**
 * Parser helper function for IPv6
 */
static inline uint8_t parse_ipv6(odp_packet_hdr_t *pkt_hdr,
				 uint8_t **parseptr, uint32_t *offset)
{
	odph_ipv6hdr_t *ipv6 = (odph_ipv6hdr_t *)*parseptr;
	odph_ipv6hdr_ext_t *ipv6ext;

	pkt_hdr->l3_len = odp_be_to_cpu_16(ipv6->payload_len);

	/* Basic sanity checks on IPv6 header */
	if ((ipv6->ver_tc_flow >> 28) != 6 ||
	    pkt_hdr->l3_len > pkt_hdr->buf_hdr.mb.pkt_len - *offset) {
		pkt_hdr->error_flags.ip_err = 1;
		return 0;
	}

	/* Skip past IPv6 header */
	*offset   += sizeof(odph_ipv6hdr_t);
	*parseptr += sizeof(odph_ipv6hdr_t);


	/* Skip past any IPv6 extension headers */
	if (ipv6->next_hdr == ODPH_IPPROTO_HOPOPTS ||
	    ipv6->next_hdr == ODPH_IPPROTO_ROUTE) {
		pkt_hdr->input_flags.ipopt = 1;

		do  {
			ipv6ext    = (odph_ipv6hdr_ext_t *)*parseptr;
			uint16_t extlen = 8 + ipv6ext->ext_len * 8;

			*offset   += extlen;
			*parseptr += extlen;
		} while ((ipv6ext->next_hdr == ODPH_IPPROTO_HOPOPTS ||
			  ipv6ext->next_hdr == ODPH_IPPROTO_ROUTE) &&
			*offset < pkt_hdr->buf_hdr.mb.pkt_len);

		if (*offset >= pkt_hdr->l3_offset + ipv6->payload_len) {
			pkt_hdr->error_flags.ip_err = 1;
			return 0;
		}

		if (ipv6ext->next_hdr == ODPH_IPPROTO_FRAG)
			pkt_hdr->input_flags.ipfrag = 1;

		return ipv6ext->next_hdr;
	}

	if (odp_unlikely(ipv6->next_hdr == ODPH_IPPROTO_FRAG)) {
		pkt_hdr->input_flags.ipopt = 1;
		pkt_hdr->input_flags.ipfrag = 1;
	}

	return ipv6->next_hdr;
}

/**
 * Parser helper function for TCP
 */
static inline void parse_tcp(odp_packet_hdr_t *pkt_hdr,
			     uint8_t **parseptr, uint32_t *offset)
{
	odph_tcphdr_t *tcp = (odph_tcphdr_t *)*parseptr;

	if (tcp->hl < sizeof(odph_tcphdr_t)/sizeof(uint32_t))
		pkt_hdr->error_flags.tcp_err = 1;
	else if ((uint32_t)tcp->hl * 4 > sizeof(odph_tcphdr_t))
		pkt_hdr->input_flags.tcpopt = 1;

	pkt_hdr->l4_len = pkt_hdr->l3_len +
		pkt_hdr->l3_offset - pkt_hdr->l4_offset;

	*offset   += (uint32_t)tcp->hl * 4;
	*parseptr += (uint32_t)tcp->hl * 4;
}

/**
 * Parser helper function for UDP
 */
static inline void parse_udp(odp_packet_hdr_t *pkt_hdr,
			     uint8_t **parseptr, uint32_t *offset)
{
	odph_udphdr_t *udp = (odph_udphdr_t *)*parseptr;
	uint32_t udplen = odp_be_to_cpu_16(udp->length);

	if (udplen < sizeof(odph_udphdr_t) ||
	    udplen > (pkt_hdr->l3_len +
		      pkt_hdr->l3_offset - pkt_hdr->l4_offset)) {
		pkt_hdr->error_flags.udp_err = 1;
	}

	pkt_hdr->l4_len = udplen;

	*offset   += sizeof(odph_udphdr_t);
	*parseptr += sizeof(odph_udphdr_t);
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
int _odp_packet_parse(odp_packet_hdr_t *pkt_hdr)
{
	odph_ethhdr_t *eth;
	odph_vlanhdr_t *vlan;
	uint16_t ethtype;
	uint8_t *parseptr;
	uint32_t offset;
	uint8_t ip_proto = 0;
	uint32_t len = pkt_hdr->buf_hdr.mb.pkt_len;
	odp_packet_t pkt = (odp_packet_t)pkt_hdr;

	packet_parse_reset(pkt_hdr);

	if (packet_parse_l2_not_done(pkt_hdr))
		packet_parse_l2(pkt_hdr);

	eth = (odph_ethhdr_t *)odp_packet_data(pkt);
	offset = sizeof(odph_ethhdr_t);
	parseptr = (uint8_t *)&eth->type;
	ethtype = odp_be_to_cpu_16(eth->type);

	/* Parse the VLAN header(s), if present */
	if (ethtype == ODPH_ETHTYPE_VLAN_OUTER) {
		pkt_hdr->input_flags.vlan_qinq = 1;
		pkt_hdr->input_flags.vlan = 1;
		vlan = (odph_vlanhdr_t *)(void *)parseptr;
		pkt_hdr->vlan_s_tag = ((ethtype << 16) |
				       odp_be_to_cpu_16(vlan->tci));
		offset += sizeof(odph_vlanhdr_t);
		parseptr += sizeof(odph_vlanhdr_t);
		ethtype = odp_be_to_cpu_16(*((uint16_t *)(void *)parseptr));
	}

	if (ethtype == ODPH_ETHTYPE_VLAN) {
		pkt_hdr->input_flags.vlan = 1;
		vlan = (odph_vlanhdr_t *)(void *)parseptr;
		pkt_hdr->vlan_c_tag = ((ethtype << 16) |
				       odp_be_to_cpu_16(vlan->tci));
		offset += sizeof(odph_vlanhdr_t);
		parseptr += sizeof(odph_vlanhdr_t);
		ethtype = odp_be_to_cpu_16(*((uint16_t *)(void *)parseptr));
	}

	/* Check for SNAP vs. DIX */
	if (ethtype < ODPH_ETH_LEN_MAX) {
		pkt_hdr->input_flags.snap = 1;
		if (ethtype > len - offset) {
			pkt_hdr->error_flags.snap_len = 1;
			goto parse_exit;
		}
		offset   += 8;
		parseptr += 8;
		ethtype = odp_be_to_cpu_16(*((uint16_t *)(void *)parseptr));
	}

	/* Consume Ethertype for Layer 3 parse */
	parseptr += 2;

	/* Set l3_offset+flag only for known ethtypes */
	pkt_hdr->input_flags.l3 = 1;
	pkt_hdr->l3_offset = offset;

	/* Set l3_offset+flag only for known ethtypes */
	switch (ethtype) {
	case ODPH_ETHTYPE_IPV4:
		pkt_hdr->input_flags.ipv4 = 1;
		ip_proto = parse_ipv4(pkt_hdr, &parseptr, &offset);
		break;

	case ODPH_ETHTYPE_IPV6:
		pkt_hdr->input_flags.ipv6 = 1;
		pkt_hdr->input_flags.l3 = 1;
		ip_proto = parse_ipv6(pkt_hdr, &parseptr, &offset);
		break;

	case ODPH_ETHTYPE_ARP:
		pkt_hdr->input_flags.arp = 1;
		ip_proto = 255;  /* Reserved invalid by IANA */
		break;

	default:
		pkt_hdr->input_flags.l3 = 0;
		pkt_hdr->l2_offset = ODP_PACKET_OFFSET_INVALID;
		ip_proto = 255;  /* Reserved invalid by IANA */
	}

	/* Set l4_offset+flag only for known ip_proto */
	pkt_hdr->input_flags.l4 = 1;
	pkt_hdr->l4_offset = offset;

	/* Parse Layer 4 headers */
	switch (ip_proto) {
	case ODPH_IPPROTO_ICMP:
		pkt_hdr->input_flags.icmp = 1;
		break;

	case ODPH_IPPROTO_TCP:
		pkt_hdr->input_flags.tcp = 1;
		parse_tcp(pkt_hdr, &parseptr, &offset);
		break;

	case ODPH_IPPROTO_UDP:
		pkt_hdr->input_flags.udp = 1;
		parse_udp(pkt_hdr, &parseptr, &offset);
		break;

	case ODPH_IPPROTO_AH:
		pkt_hdr->input_flags.ipsec = 1;
		pkt_hdr->input_flags.ipsec_ah = 1;
		break;
	case ODPH_IPPROTO_ESP:
		pkt_hdr->input_flags.ipsec = 1;
		pkt_hdr->input_flags.ipsec_esp = 1;
		break;

	default:
		pkt_hdr->input_flags.l4 = 0;
		pkt_hdr->l4_offset = ODP_PACKET_OFFSET_INVALID;
		break;
	}

       /*
	* Anything beyond what we parse here is considered payload.
	* Note: Payload is really only relevant for TCP and UDP.  For
	* all other protocols, the payload offset will point to the
	* final header (ARP, ICMP, AH, ESP, or IP Fragment).
	*/
	pkt_hdr->payload_offset = offset;

parse_exit:
	pkt_hdr->input_flags.parsed_all = 1;
	return pkt_hdr->error_flags.all != 0;
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
			"  l2_offset    %u\n", hdr->l2_offset);
	len += snprintf(&str[len], n-len,
			"  l3_offset    %u\n", hdr->l3_offset);
	len += snprintf(&str[len], n-len,
			"  l4_offset    %u\n", hdr->l4_offset);
	len += snprintf(&str[len], n-len,
			"  frame_len    %u\n", hdr->buf_hdr.mb.pkt_len);
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

	dsthdr->buf_hdr.mb.port = srchdr->buf_hdr.mb.port;
	dsthdr->buf_hdr.mb.vlan_tci = srchdr->buf_hdr.mb.vlan_tci;
	dsthdr->buf_hdr.mb.hash = srchdr->buf_hdr.mb.hash;
	dsthdr->buf_hdr.mb.ol_flags = srchdr->buf_hdr.mb.ol_flags;

	if (odp_packet_user_area_size(dstpkt) != 0)
		memcpy(odp_packet_user_area(dstpkt),
		       odp_packet_user_area(srcpkt),
		       odp_packet_user_area_size(dstpkt) <=
		       odp_packet_user_area_size(srcpkt) ?
		       odp_packet_user_area_size(dstpkt) :
		       odp_packet_user_area_size(srcpkt));

	copy_packet_parser_metadata(srchdr, dsthdr);
}

int odp_packet_align(odp_packet_t *pkt, uint32_t offset, uint32_t len,
		     uint32_t align)
{
	int rc;
	uint32_t shift;
	uint32_t seglen = 0;  /* GCC */
	void *addr = odp_packet_offset(*pkt, offset, &seglen, NULL);
	uint64_t uaddr = (uint64_t)(uintptr_t)addr;
	uint64_t misalign;

	if (align > ODP_CACHE_LINE_SIZE)
		return -1;

	if (seglen >= len) {
		misalign = align <= 1 ? 0 :
			ODP_ALIGN_ROUNDUP(uaddr, align) - uaddr;
		if (misalign == 0)
			return 0;
		shift = align - misalign;
	} else {
		if (len > odp_packet_seg_len(*pkt))
			return -1;
		shift  = len - seglen;
		uaddr -= shift;
		misalign = align <= 1 ? 0 :
			ODP_ALIGN_ROUNDUP(uaddr, align) - uaddr;
		if (misalign)
			shift += align - misalign;
	}

	rc = odp_packet_extend_head(pkt, shift, NULL, NULL);
	if (rc < 0)
		return rc;

	(void)odp_packet_move_data(*pkt, 0, shift,
				   odp_packet_len(*pkt) - shift);

	(void)odp_packet_trunc_tail(pkt, shift, NULL, NULL);
	return 1;
}

int odp_packet_concat(odp_packet_t *dst, odp_packet_t src)
{
	uint32_t dst_len = odp_packet_len(*dst);
	uint32_t src_len = odp_packet_len(src);

	if (odp_packet_extend_tail(dst, src_len, NULL, NULL) >= 0) {
		(void)odp_packet_copy_from_pkt(*dst, dst_len,
					       src, 0, src_len);
		if (src != *dst)
			odp_packet_free(src);
		return 0;
	}

	return -1;
}

int odp_packet_split(odp_packet_t *pkt, uint32_t len, odp_packet_t *tail)
{
	uint32_t pktlen = odp_packet_len(*pkt);

	if (len >= pktlen || tail == NULL)
		return -1;

	*tail = odp_packet_copy_part(*pkt, len, pktlen - len,
				     odp_packet_pool(*pkt));

	if (*tail == ODP_PACKET_INVALID)
		return -1;

	return odp_packet_trunc_tail(pkt, pktlen - len, NULL, NULL);
}

odp_packet_t odp_packet_copy(odp_packet_t pkt, odp_pool_t pool)
{
	uint32_t pktlen = odp_packet_len(pkt);
	odp_packet_t newpkt = odp_packet_alloc(pool, pktlen);

	if (newpkt != ODP_PACKET_INVALID) {
		/* Must copy metadata first, followed by packet data */
		_odp_packet_copy_md_to_packet(pkt, newpkt);

		if (odp_packet_copy_from_pkt(newpkt, 0, pkt, 0, pktlen) != 0) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		}
	}

	return newpkt;
}

odp_packet_t odp_packet_copy_part(odp_packet_t pkt, uint32_t offset,
				  uint32_t len, odp_pool_t pool)
{
	uint32_t pktlen = odp_packet_len(pkt);
	odp_packet_t newpkt;

	if (offset >= pktlen || offset + len > pktlen)
		return ODP_PACKET_INVALID;

	newpkt = odp_packet_alloc(pool, len);
	if (newpkt != ODP_PACKET_INVALID)
		odp_packet_copy_from_pkt(newpkt, 0, pkt, offset, len);

	return newpkt;
}

int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
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

int odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
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

int odp_packet_copy_from_pkt(odp_packet_t dst, uint32_t dst_offset,
			     odp_packet_t src, uint32_t src_offset,
			     uint32_t len)
{
	odp_packet_hdr_t *dst_hdr = odp_packet_hdr(dst);
	odp_packet_hdr_t *src_hdr = odp_packet_hdr(src);
	void *dst_map;
	void *src_map;
	uint32_t cpylen, minseg;
	uint32_t dst_seglen = 0; /* GCC */
	uint32_t src_seglen = 0; /* GCC */
	int overlap;

	if (dst_offset + len > odp_packet_len(dst) ||
	    src_offset + len > odp_packet_len(src))
		return -1;

	overlap = (dst_hdr == src_hdr &&
		   ((dst_offset <= src_offset &&
		     dst_offset + len >= src_offset) ||
		    (src_offset <= dst_offset &&
		     src_offset + len >= dst_offset)));

	if (overlap && src_offset < dst_offset) {
		odp_packet_t temp =
			odp_packet_copy_part(src, src_offset, len,
					     odp_packet_pool(src));
		if (temp == ODP_PACKET_INVALID)
			return -1;
		odp_packet_copy_from_pkt(dst, dst_offset, temp, 0, len);
		odp_packet_free(temp);
		return 0;
	}

	while (len > 0) {
		dst_map = odp_packet_offset(dst, dst_offset, &dst_seglen, NULL);
		src_map = odp_packet_offset(src, src_offset, &src_seglen, NULL);

		minseg = dst_seglen > src_seglen ? src_seglen : dst_seglen;
		cpylen = len > minseg ? minseg : len;

		if (overlap)
			memmove(dst_map, src_map, cpylen);
		else
			memcpy(dst_map, src_map, cpylen);

		dst_offset += cpylen;
		src_offset += cpylen;
		len        -= cpylen;
	}

	return 0;
}

int odp_packet_copy_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len)
{
	return odp_packet_copy_from_pkt(pkt, dst_offset,
					pkt, src_offset, len);
}

int odp_packet_move_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len)
{
	return odp_packet_copy_from_pkt(pkt, dst_offset,
					pkt, src_offset, len);
}

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx)
{
	odp_packet_hdr(pkt)->buf_hdr.buf_cctx = ctx;
}

void *odp_packet_user_ptr(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.buf_ctx;
}

int odp_packet_is_valid(odp_packet_t pkt)
{
	odp_buffer_t buf = _odp_packet_to_buffer(pkt);

	return odp_buffer_is_valid(buf);
}

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.totsize;
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
	return odp_packet_hdr(pkt)->input;
}

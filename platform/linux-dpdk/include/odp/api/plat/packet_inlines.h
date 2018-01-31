/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet inline functions
 */

#ifndef _ODP_PLAT_PACKET_INLINES_H_
#define _ODP_PLAT_PACKET_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/packet_types.h>
#include <odp/api/pool.h>
#include <odp/api/packet_io.h>
#include <odp/api/hints.h>

/* Required by rte_mbuf.h */
#include <sys/types.h>
#include <rte_mbuf.h>

/** @internal Inline function offsets */
extern const _odp_packet_inline_offset_t _odp_packet_inline;

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_data(odp_packet_t pkt)
{
	uint8_t *buf_addr = (uint8_t *)_odp_pkt_get(pkt, void *, buf_addr);
	uint16_t data_off = _odp_pkt_get(pkt, uint16_t, data);

	return (void *)(buf_addr + data_off);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_seg_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, seg_len);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, pkt_len);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_headroom(odp_packet_t pkt)
{
	return rte_pktmbuf_headroom(&_odp_pkt_get(pkt, struct rte_mbuf, mb));
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_tailroom(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &_odp_pkt_get(pkt, struct rte_mbuf, mb);

	return rte_pktmbuf_tailroom(rte_pktmbuf_lastseg(mb));
}

/** @internal Inline function @param pkt @return */
static inline odp_pool_t _odp_packet_pool(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_pool_t, pool);
}

/** @internal Inline function @param pkt @return */
static inline odp_pktio_t _odp_packet_input(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_pktio_t, input);
}

/** @internal Inline function @param pkt @return */
static inline int _odp_packet_num_segs(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint8_t, nb_segs);
}

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_user_ptr(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, user_ptr);
}

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_user_area(odp_packet_t pkt)
{
	return (void *)((char *)pkt + _odp_packet_inline.udata);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_user_area_size(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, udata_len);
}

/** @internal Inline function @param pkt @return */
static inline uint32_t _odp_packet_flow_hash(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, rss);
}

/** @internal Inline function @param pkt @param flow_hash */
static inline void _odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	uint32_t *rss = &_odp_pkt_get(pkt, uint32_t, rss);
	uint64_t *ol_flags = &_odp_pkt_get(pkt, uint64_t, ol_flags);

	*rss = flow_hash;
	*ol_flags |= _odp_packet_inline.rss_flag;
}

/** @internal Inline function @param pkt @return */
static inline odp_time_t _odp_packet_ts(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_time_t, timestamp);
}

/** @internal Inline function @param pkt @return */
static inline void *_odp_packet_head(odp_packet_t pkt)
{
	return (uint8_t *)_odp_packet_data(pkt) - _odp_packet_headroom(pkt);
}

/** @internal Inline function @param pkt @return */
static inline int _odp_packet_is_segmented(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &_odp_pkt_get(pkt, struct rte_mbuf, mb);

	return !rte_pktmbuf_is_contiguous(mb);
}

/** @internal Inline function @param pkt @return */
static inline odp_packet_seg_t _odp_packet_first_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)(uintptr_t)pkt;
}

/** @internal Inline function @param pkt @return */
static inline odp_packet_seg_t _odp_packet_last_seg(odp_packet_t pkt)
{
	struct rte_mbuf *mb = &_odp_pkt_get(pkt, struct rte_mbuf, mb);

	return (odp_packet_seg_t)(uintptr_t)rte_pktmbuf_lastseg(mb);
}

/** @internal Inline function @param pkt @param seg @return */
static inline odp_packet_seg_t _odp_packet_next_seg(odp_packet_t pkt,
						    odp_packet_seg_t seg)
{
	struct rte_mbuf *mb = (struct rte_mbuf *)(uintptr_t)seg;
	(void)pkt;

	if (mb->next == NULL)
		return ODP_PACKET_SEG_INVALID;
	else
		return (odp_packet_seg_t)(uintptr_t)mb->next;
}

/** @internal Inline function @param pkt @param offset @param len */
static inline void _odp_packet_prefetch(odp_packet_t pkt, uint32_t offset, uint32_t len)
{
	const char *addr = (char *)_odp_packet_data(pkt) + offset;
	size_t ofs;

	for (ofs = 0; ofs < len; ofs += RTE_CACHE_LINE_SIZE)
		rte_prefetch0(addr + ofs);
}

/* Include inlined versions of API functions */
#include <odp/api/plat/static_inline.h>

#if ODP_ABI_COMPAT == 0

#include <odp/api/plat/packet_inlines_api.h>

#endif /* ODP_ABI_COMPAT */

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_PACKET_INLINES_H_ */

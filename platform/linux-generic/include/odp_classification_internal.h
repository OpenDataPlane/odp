/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2023 Nokia
 */

/**
 * @file
 *
 * ODP Classification Internal
 * Describes the classification internal Functions
 */

#ifndef __ODP_CLASSIFICATION_INTERNAL_H_
#define __ODP_CLASSIFICATION_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/atomic.h>
#include <odp/api/classification.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/pool.h>
#include <odp/api/queue.h>
#include <odp/api/std_types.h>

#include <odp_debug_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_datamodel.h>

#include <stdint.h>

extern cls_global_t *_odp_cls_global;

static inline cos_t *_odp_cos_entry_from_idx(uint32_t ndx)
{
	return &_odp_cls_global->cos_tbl.cos_entry[ndx];
}

static inline int _odp_cos_queue_idx(const cos_t *cos, odp_queue_t queue)
{
	uint32_t i, tbl_idx;
	int queue_idx = -1;

	if (cos->num_queue == 1) {
		if (odp_unlikely(cos->queue != queue))
			return -1;
		return 0;
	}

	tbl_idx = cos->index * CLS_COS_QUEUE_MAX;
	for (i = 0; i < cos->num_queue; i++) {
		if (_odp_cls_global->queue_grp_tbl.queue[tbl_idx + i] == queue) {
			queue_idx = i;
			break;
		}
	}
	return queue_idx;
}

static inline void _odp_cos_queue_stats_add(cos_t *cos, odp_queue_t queue,
					    uint64_t packets, uint64_t discards)
{
	int queue_idx = _odp_cos_queue_idx(cos, queue);

	if (odp_unlikely(queue_idx < 0)) {
		_ODP_ERR("Queue not attached to the CoS\n");
		return;
	}

	if (packets)
		odp_atomic_add_u64(&cos->queue_stats[queue_idx].packets, packets);
	if (discards)
		odp_atomic_add_u64(&cos->queue_stats[queue_idx].discards, discards);
}

static inline void _odp_cos_vector_enq(odp_queue_t queue, odp_event_t events[], uint32_t num,
				       cos_t *cos)
{
	odp_packet_vector_t pktv;
	const odp_pool_t pool = cos->vector.pool;
	const uint32_t max_size = cos->vector.max_size;
	uint32_t num_enq;
	int num_pktv = (num + max_size - 1) / max_size;
	int ret;
	int i;
	odp_packet_vector_t pktv_tbl[num_pktv];
	odp_event_t event_tbl[num_pktv];

	for (i = 0; i < num_pktv; i++) {
		pktv = odp_packet_vector_alloc(pool);
		if (odp_unlikely(pktv == ODP_PACKET_VECTOR_INVALID))
			break;
		pktv_tbl[i] = pktv;
		event_tbl[i] = odp_packet_vector_to_event(pktv);
	}
	if (odp_unlikely(i == 0)) {
		odp_event_free_multi(events, num);
		_odp_cos_queue_stats_add(cos, queue, 0, num);
		return;
	}
	num_pktv = i;
	num_enq = 0;
	for (i = 0; i < num_pktv; i++) {
		odp_packet_t *pkt_tbl;
		int pktv_size = max_size;

		pktv = pktv_tbl[i];

		if (num_enq + max_size > num)
			pktv_size = num - num_enq;

		odp_packet_vector_tbl(pktv, &pkt_tbl);
		odp_packet_from_event_multi(pkt_tbl, &events[num_enq], pktv_size);
		odp_packet_vector_size_set(pktv, pktv_size);
		num_enq += pktv_size;
	}

	ret = odp_queue_enq_multi(queue, event_tbl, num_pktv);
	if (odp_likely(ret == num_pktv)) {
		_odp_cos_queue_stats_add(cos, queue, num_enq, num - num_enq);
	} else {
		uint32_t enqueued;

		if (ret < 0)
			ret = 0;
		enqueued = max_size * ret;
		_odp_cos_queue_stats_add(cos, queue, enqueued, num - enqueued);
		odp_event_free_multi(&event_tbl[ret], num_pktv - ret);
	}
}

/**
 * Enqueue packets into destination CoS
 */
static inline void _odp_cos_enq(uint16_t cos_id, odp_queue_t dst, odp_packet_t packets[], int num)
{
	_ODP_ASSERT(cos_id != CLS_COS_IDX_NONE);
	_ODP_ASSERT(dst != ODP_QUEUE_INVALID);

	cos_t *cos = _odp_cos_entry_from_idx(cos_id);

	if (num < 2 || !cos->vector.enable) {
		int ret = odp_queue_enq_multi(dst, (odp_event_t *)packets, num);

		if (odp_unlikely(ret != num)) {
			if (ret < 0)
				ret = 0;

			odp_packet_free_multi(&packets[ret], num - ret);
		}
		_odp_cos_queue_stats_add(cos, dst, ret, num - ret);
	} else {
		_odp_cos_vector_enq(dst, (odp_event_t *)packets, num, cos);
	}
}

/**
 * Enqueue all remaining packets in 'packets' array
 */
static inline void _odp_cls_enq_all(odp_packet_t packets[], int num)
{
	odp_packet_hdr_t *prev_hdr;
	odp_packet_hdr_t *latest_hdr = packet_hdr(packets[num - 1]);

	if (num < 2) {
		_odp_cos_enq(latest_hdr->cos, latest_hdr->dst_queue, packets, 1);
		return;
	}

	prev_hdr = packet_hdr(packets[num - 2]);

	if (prev_hdr->dst_queue == latest_hdr->dst_queue && prev_hdr->cos == latest_hdr->cos) {
		_odp_cos_enq(prev_hdr->cos, prev_hdr->dst_queue, packets, num);
	} else {
		_odp_cos_enq(prev_hdr->cos, prev_hdr->dst_queue, packets, num - 1);
		_odp_cos_enq(latest_hdr->cos, latest_hdr->dst_queue, &packets[num - 1], 1);
	}
}

/**
 * Enqueue packets into classifier destination queue
 *
 * Called by pktio devices for each received packet when classifier has been enabled. Postpones the
 * actual enqueue operation and stores packets in 'packets' array until destination queue or CoS
 * change, or 'last' flag is set.
 *
 * @param[out] packets Packet array to be enqueued
 * @param      num     Number of handles in 'packets' array
 * @param      last    Enqueue all packets
 *
 * @return Number of packets remaining in 'packets' array
 */
static inline int _odp_cls_enq(odp_packet_t packets[], int num, odp_bool_t last)
{
	odp_packet_hdr_t *prev_hdr, *latest_hdr;

	_ODP_ASSERT(num > 0);

	if (last) {
		_odp_cls_enq_all(packets, num);
		return 0;
	}

	/* Only one packet, so postpone enqueue */
	if (num < 2)
		return num;

	prev_hdr = packet_hdr(packets[num - 2]);
	latest_hdr = packet_hdr(packets[num - 1]);

	/* Postpone enqueue if destination queue and CoS have not changed */
	if (prev_hdr->dst_queue == latest_hdr->dst_queue && prev_hdr->cos == latest_hdr->cos)
		return num;

	/* Perform previously postponed enqueue operation and move the last packet (different
	 * destination) in 'packets' array to be the first entry */
	_odp_cos_enq(prev_hdr->cos, prev_hdr->dst_queue, packets, num - 1);
	packets[0] = packets[num - 1];

	return 1;
}

/** Classification Internal function **/

/**
@internal

Packet Classifier

Start function for Packet Classifier
This function calls Classifier module internal functions for a given packet and
selects destination queue and packet pool based on selected PMR and CoS.
**/
int _odp_cls_classify_packet(pktio_entry_t *entry, const uint8_t *base,
			     odp_pool_t *pool, odp_packet_hdr_t *pkt_hdr);

/**
Packet IO classifier init

This function does initialization of classifier object associated with pktio.
This function should be called during pktio initialization.
**/
int _odp_pktio_classifier_init(pktio_entry_t *pktio);

#ifdef __cplusplus
}
#endif
#endif

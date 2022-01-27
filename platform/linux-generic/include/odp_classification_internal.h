/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
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
#include <odp/api/hints.h>
#include <odp/api/queue.h>
#include <odp_packet_internal.h>
#include <odp/api/packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_datamodel.h>

extern cls_global_t *_odp_cls_global;

static inline cos_t *_odp_cos_entry_from_idx(uint32_t ndx)
{
	return &_odp_cls_global->cos_tbl.cos_entry[ndx];
}

static inline int _odp_cos_queue_idx(const cos_t *cos, odp_queue_t queue)
{
	uint32_t i, tbl_idx;
	int queue_idx = -1;

	if (cos->s.num_queue == 1) {
		if (odp_unlikely(cos->s.queue != queue))
			return -1;
		return 0;
	}

	tbl_idx = cos->s.index * CLS_COS_QUEUE_MAX;
	for (i = 0; i < cos->s.num_queue; i++) {
		if (_odp_cls_global->queue_grp_tbl.s.queue[tbl_idx + i] == queue) {
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
		ODP_ERR("Queue not attached to the CoS\n");
		return;
	}

	if (packets)
		odp_atomic_add_u64(&cos->s.queue_stats[queue_idx].packets, packets);
	if (discards)
		odp_atomic_add_u64(&cos->s.queue_stats[queue_idx].discards, discards);
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

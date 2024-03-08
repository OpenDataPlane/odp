/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015 EZchip Semiconductor Ltd.
 * Copyright (c) 2015-2018 Linaro Limited
 */

#ifndef _ODP_INT_PKT_QUEUE_H_
#define _ODP_INT_PKT_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/packet.h>

#include <stdint.h>

typedef uint64_t _odp_int_queue_pool_t;
typedef uint32_t _odp_int_pkt_queue_t;

#define _ODP_INT_QUEUE_POOL_INVALID  0
#define _ODP_INT_PKT_QUEUE_INVALID   0

/* None of the functions in this file do any locking.  Thats because the
 * expected usage model is that each TM system will create its own
 * _odp_int_queue_pool, and then only call _odp_int_pkt_queue_append and
 * _odp_int_pkt_queue_remove from a single thread associated/dedicated to this
 * same TM system/_odp_int_queue_pool.  The main difficulty that this file
 * tries to deal with is the possibility of a huge number of queues (e.g. 16
 * million), where each such queue could have a huge range in the number of
 * pkts queued (say 0 to > 1,000) - yet the total "peak" number of pkts queued
 * is many orders of magnitude smaller than the product of max_num_queues
 * times max_queue_cnt.  In particular, it is assumed that even at peak usage,
 * only a small fraction of max_num_queues will be "active" - i.e. have any
 * pkts queued, yet over time it is expected that most every queue will have
 * some sort of backlog.
 */

/* max_num_queues must be <= 16 * 1024 * 1024. */
_odp_int_queue_pool_t _odp_queue_pool_create(uint32_t max_num_queues,
					     uint32_t max_queued_pkts);

_odp_int_pkt_queue_t _odp_pkt_queue_create(_odp_int_queue_pool_t queue_pool);

void _odp_pkt_queue_destroy(_odp_int_queue_pool_t queue_pool,
			    _odp_int_pkt_queue_t  pkt_queue);

int _odp_pkt_queue_append(_odp_int_queue_pool_t queue_pool,
			  _odp_int_pkt_queue_t  pkt_queue,
			  odp_packet_t          pkt);

int _odp_pkt_queue_remove(_odp_int_queue_pool_t queue_pool,
			  _odp_int_pkt_queue_t  pkt_queue,
			  odp_packet_t         *pkt);

void _odp_pkt_queue_stats_print(_odp_int_queue_pool_t queue_pool);

void _odp_queue_pool_destroy(_odp_int_queue_pool_t queue_pool);

#ifdef __cplusplus
}
#endif

#endif

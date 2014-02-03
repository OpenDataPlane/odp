/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet IO - implementation internal
 */

#ifndef ODP_PACKET_IO_QUEUE_H_
#define ODP_PACKET_IO_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_queue_internal.h>
#include <odp_buffer_internal.h>

#define ODP_PKTIN_QUEUE_MAX_BURST 16

int pktin_enqueue(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
odp_buffer_hdr_t *pktin_dequeue(queue_entry_t *queue);

int pktout_enqueue(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
odp_buffer_hdr_t *pktout_dequeue(queue_entry_t *queue);

#ifdef __cplusplus
}
#endif

#endif


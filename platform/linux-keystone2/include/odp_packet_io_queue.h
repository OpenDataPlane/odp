/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
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

odp_buffer_t pktin_dequeue(queue_entry_t *queue);
int pktin_deq_multi(queue_entry_t *queue, odp_buffer_t buf[], int num);
int pktout_enqueue(queue_entry_t *queue, odp_buffer_t buf);
int pktout_enq_multi(queue_entry_t *queue, odp_buffer_t buf[], int num);

#ifdef __cplusplus
}
#endif

#endif

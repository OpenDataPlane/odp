/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Linaro Limited nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIALDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


/**
 * @file
 *
 * ODP queue - implementation internal
 */

#ifndef ODP_QUEUE_INTERNAL_H_
#define ODP_QUEUE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_queue.h>
#include <odp_buffer_internal.h>
#include <odp_packet_io.h>
#include <odp_spinlock.h>
#include <odp_align.h>

#define QUEUE_STATUS_FREE     0
#define QUEUE_STATUS_READY    1
#define QUEUE_STATUS_NOTSCHED 2
#define QUEUE_STATUS_SCHED    3

/* forward declaration */
union queue_entry_u;

typedef int (*enqueue_func_t)(union queue_entry_u *, odp_buffer_hdr_t *);
typedef	odp_buffer_hdr_t *(*dequeue_func_t)(union queue_entry_u *);

struct queue_entry_s {
	odp_spinlock_t    lock ODP_ALIGNED_CACHE;
	enqueue_func_t    enqueue ODP_ALIGNED_CACHE;
	dequeue_func_t    dequeue;
	odp_buffer_hdr_t *head;
	odp_buffer_hdr_t *tail;
	odp_queue_t       handle;
	odp_queue_type_t  type;
	int               status;
	odp_queue_param_t param;
	odp_pktio_t       pktin;
	odp_pktio_t       pktout;
	char              name[ODP_QUEUE_NAME_LEN];
};

typedef union queue_entry_u {
	struct queue_entry_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct queue_entry_s))];
} queue_entry_t;


queue_entry_t *get_qentry(uint32_t queue_id);
odp_queue_t to_qhandle(uint32_t queue_id);
uint32_t from_qhandle(odp_queue_t handle);

/* local function prototypes */
int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
odp_buffer_hdr_t *queue_deq(queue_entry_t *queue);

#ifdef __cplusplus
}
#endif

#endif


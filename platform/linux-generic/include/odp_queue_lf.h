/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_QUEUE_LF_H_
#define ODP_QUEUE_LF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_queue_if.h>
#include <odp_queue_internal.h>

/* Lock-free queue functions */
typedef struct {
	queue_enq_fn_t enq;
	queue_enq_multi_fn_t enq_multi;
	queue_deq_fn_t deq;
	queue_deq_multi_fn_t deq_multi;

} queue_lf_func_t;

uint32_t queue_lf_init_global(uint32_t *queue_lf_size,
			      queue_lf_func_t *lf_func);
void queue_lf_term_global(void);
void *queue_lf_create(queue_entry_t *queue);
void queue_lf_destroy(void *queue_lf);

#ifdef __cplusplus
}
#endif

#endif

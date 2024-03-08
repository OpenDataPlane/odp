/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef ODP_QUEUE_LF_H_
#define ODP_QUEUE_LF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_queue_if.h>

/* Lock-free queue functions */
typedef struct {
	queue_enq_fn_t enq;
	queue_enq_multi_fn_t enq_multi;
	queue_deq_fn_t deq;
	queue_deq_multi_fn_t deq_multi;

} queue_lf_func_t;

uint32_t _odp_queue_lf_init_global(uint32_t *queue_lf_size,
				   queue_lf_func_t *lf_func);
void _odp_queue_lf_term_global(void);
void *_odp_queue_lf_create(queue_entry_t *queue);
void _odp_queue_lf_destroy(void *queue_lf);
uint32_t _odp_queue_lf_length(void *queue_lf);
uint32_t _odp_queue_lf_max_length(void);

#ifdef __cplusplus
}
#endif

#endif

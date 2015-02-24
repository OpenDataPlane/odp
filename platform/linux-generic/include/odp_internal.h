/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP HW system information
 */

#ifndef ODP_INTERNAL_H_
#define ODP_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/init.h>

extern __thread int __odp_errno;

struct odp_global_data_s {
	odp_log_func_t log_fn;
	odp_abort_func_t abort_fn;
};

extern struct odp_global_data_s odp_global_data;

int odp_system_info_init(void);

int odp_thread_init_global(void);
int odp_thread_init_local(void);
int odp_thread_term_local(void);

int odp_shm_init_global(void);
int odp_shm_init_local(void);

int odp_pool_init_global(void);

int odp_pktio_init_global(void);
int odp_pktio_term_global(void);
int odp_pktio_init_local(void);

int odp_classification_init_global(void);
int odp_classification_term_global(void);

int odp_queue_init_global(void);
int odp_queue_term_global(void);

int odp_crypto_init_global(void);
int odp_crypto_term_global(void);

int odp_schedule_init_global(void);
int odp_schedule_term_global(void);
int odp_schedule_init_local(void);

int odp_timer_init_global(void);
int odp_timer_disarm_all(void);

void _odp_flush_caches(void);

#ifdef __cplusplus
}
#endif

#endif

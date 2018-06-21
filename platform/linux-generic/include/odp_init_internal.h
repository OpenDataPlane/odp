/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_INIT_INTERNAL_H_
#define ODP_INIT_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/init.h>
#include <odp/api/thread.h>

int odp_cpumask_init_global(const odp_init_t *params);
int odp_cpumask_term_global(void);

int odp_system_info_init(void);
int odp_system_info_term(void);

int odp_thread_init_global(void);
int odp_thread_init_local(odp_thread_type_t type);
int odp_thread_term_local(void);
int odp_thread_term_global(void);

int odp_pool_init_global(void);
int odp_pool_init_local(void);
int odp_pool_term_global(void);
int odp_pool_term_local(void);

int _odp_queue_init_global(void);
int _odp_queue_term_global(void);

int _odp_schedule_init_global(void);
int _odp_schedule_term_global(void);

int odp_pktio_init_global(void);
int odp_pktio_term_global(void);
int odp_pktio_init_local(void);

int odp_classification_init_global(void);
int odp_classification_term_global(void);

int odp_queue_init_global(void);
int odp_queue_term_global(void);

int _odp_random_init_local(void);
int _odp_random_term_local(void);

int odp_crypto_init_global(void);
int odp_crypto_term_global(void);
int _odp_crypto_init_local(void);
int _odp_crypto_term_local(void);

int odp_timer_init_global(const odp_init_t *params);
int odp_timer_term_global(void);
int odp_timer_disarm_all(void);

int odp_time_init_global(void);
int odp_time_term_global(void);

int odp_tm_init_global(void);
int odp_tm_term_global(void);

int _odp_int_name_tbl_init_global(void);
int _odp_int_name_tbl_term_global(void);

int _odp_fdserver_init_global(void);
int _odp_fdserver_term_global(void);

int _odp_ishm_init_global(const odp_init_t *init);
int _odp_ishm_init_local(void);
int _odp_ishm_term_global(void);
int _odp_ishm_term_local(void);

int _odp_ipsec_init_global(void);
int _odp_ipsec_term_global(void);

int _odp_ipsec_sad_init_global(void);
int _odp_ipsec_sad_term_global(void);

int _odp_ipsec_events_init_global(void);
int _odp_ipsec_events_term_global(void);

int _odp_cpu_cycles_init_global(void);

int _odp_hash_init_global(void);

#ifdef __cplusplus
}
#endif

#endif

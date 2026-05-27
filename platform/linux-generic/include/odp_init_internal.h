/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 */

#ifndef ODP_INIT_INTERNAL_H_
#define ODP_INIT_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/cpumask.h>
#include <odp/api/init.h>
#include <odp/api/thread.h>

#include <odp/api/plat/thread_inline_types.h>

/* Internal variant of odp_init_local() that takes the extended internal
 * thread type. Linux-generic implementation internal threads must use this
 * directly with _ODP_THR_INTERNAL instead of odp_init_local(). */
int _odp_init_local(odp_instance_t instance, _odp_internal_thread_type_t thr_type);

int _odp_cpumask_init_global(const odp_init_t *params);
int _odp_cpumask_term_global(void);

/* Reserve CPUs for ODP-internal threads. Adds 'cpus' to
 * odp_global_ro.service_cpus and removes them from the application-visible
 * all_cpus / worker_cpus / control_cpus masks, also updating
 * num_cpus_installed and num_service_cpus.
 *
 * Intended for use by linux-generic implementation internal subsystems
 * (e.g. an internal service thread pool) that want their CPUs hidden from
 * the public CPU and thread APIs. Calls are additive and 'cpus' must be a
 * subset of the currently visible CPUs in odp_global_ro.all_cpus. Re-reserving
 * a CPU that is already a service CPU is not allowed, each CPU can be reserved
 * only once. At least one visible CPU must remain for application threads,
 * and 'cpus' must not overlap with worker or control CPUs given in
 * odp_init_t. A default worker or control mask left empty is refilled from
 * the remaining visible CPUs.
 *
 * Must be called during odp_init_global(), before the application starts
 * spawning threads or querying cpumask helpers. Not thread-safe.
 *
 * Returns 0 on success, -1 on error. */
int _odp_service_cpus_reserve(const odp_cpumask_t *cpus);

int _odp_system_info_init(void);
int _odp_system_info_term(void);

int _odp_thread_init_global(void);
int _odp_thread_init_local(_odp_internal_thread_type_t type);
int _odp_thread_term_local(void);
int _odp_thread_term_global(void);

void _odp_print_term_local(void);

/* Returns the number of thread id slots, including those of ODP-internal
 * threads. Unlike odp_thread_count_max(), this covers every value that
 * odp_thread_id() may return, so implementation-internal per-thread state
 * indexed by thread id must be sized and iterated with this. */
int _odp_thread_count_max(void);

int _odp_pcapng_init_global(void);
int _odp_pcapng_term_global(void);

int _odp_pool_init_global(void);
int _odp_pool_init_local(void);
int _odp_pool_term_global(void);
int _odp_pool_term_local(void);

int _odp_event_validation_init_global(void);
int _odp_event_validation_term_global(void);

int _odp_queue_init_global(void);
int _odp_queue_term_global(void);

int _odp_schedule_init_global(void);
int _odp_schedule_term_global(void);

int _odp_pktio_init_global(void);
int _odp_pktio_term_global(void);
int _odp_pktio_init_local(void);

int _odp_classification_init_global(void);
int _odp_classification_term_global(void);

int _odp_queue_init_global(void);
int _odp_queue_term_global(void);

int _odp_random_init_global(void);
int _odp_random_term_global(void);
int _odp_random_init_local(void);
int _odp_random_term_local(void);

int _odp_crypto_init_global(void);
int _odp_crypto_term_global(void);
int _odp_crypto_init_local(void);
int _odp_crypto_term_local(void);

int _odp_comp_init_global(void);
int _odp_comp_term_global(void);

int _odp_timer_init_global(const odp_init_t *params);
int _odp_timer_init_local(void);
int _odp_timer_term_global(void);
int _odp_timer_term_local(void);

int _odp_time_init_global(void);
int _odp_time_term_global(void);

int _odp_tm_init_global(void);
int _odp_tm_term_global(void);

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
int _odp_hash_term_global(void);

int _odp_stash_init_global(void);
int _odp_stash_term_global(void);

int _odp_dma_init_global(void);
int _odp_dma_term_global(void);

int _odp_ml_init_global(void);
int _odp_ml_term_global(void);

#ifdef __cplusplus
}
#endif

#endif

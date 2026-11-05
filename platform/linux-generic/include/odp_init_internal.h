/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 */

#ifndef ODP_INIT_INTERNAL_H_
#define ODP_INIT_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/atomic.h>
#include <odp/api/cpumask.h>
#include <odp/api/init.h>
#include <odp/api/thread.h>

#include <odp/api/plat/thread_inline_types.h>

#include <pthread.h>

/* Service thread parameters */
typedef struct {
	/* Thread body. Called after the thread has been locally initialized as
	 * _ODP_THR_INTERNAL. When it returns, the thread terminates locally and exits. */
	void (*run)(void *arg);
	/* Argument passed to 'run' */
	void *arg;
	/* CPU to pin the thread to. Must have been reserved with
	 * _odp_service_cpus_reserve(). */
	int cpu;
} _odp_service_thread_param_t;

/* Service thread handle. Owned by the caller, must stay valid and in place
 * from _odp_service_thread_create() until _odp_service_thread_join(). */
typedef struct {
	_odp_service_thread_param_t param;
	pthread_t thread;
	odp_atomic_u32_t state;
} _odp_service_thread_t;

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

/* Create 'num' service threads as described by 'param' and block until all
 * of them have completed local initialization. On success, all threads have
 * started executing their 'run' function. On failure, no threads remain
 * running.
 *
 * Must be called after odp_init_global() has completed (e.g. from
 * odp_schedule_config()), as the threads call _odp_init_local().
 *
 * Returns 0 on success, -1 on error. */
int _odp_service_thread_create(_odp_service_thread_t thr[],
			       const _odp_service_thread_param_t param[], int num);

/* Wait for 'num' service threads created with _odp_service_thread_create()
 * to exit. Stopping the threads, i.e. making their 'run' function return, is
 * the caller's responsibility.
 *
 * Returns 0 on success, -1 on error. */
int _odp_service_thread_join(_odp_service_thread_t thr[], int num);

int _odp_system_info_init(void);
int _odp_system_info_term(void);

int _odp_thread_init_global(void);
int _odp_thread_init_local(_odp_internal_thread_type_t type);
int _odp_thread_term_local(void);
int _odp_thread_term_global(void);

void _odp_print_term_local(void);
/* Returns 1 if the slot 'thr_id' is currently allocated to an ODP-internal
 * thread, 0 otherwise (including unallocated and out-of-range slots).
 *
 * Intended for use by subsystems (e.g. pool) that need to specialize
 * per-thread state by internal vs. application thread type when iterating
 * all thread id slots. */
int _odp_thread_is_internal(int thr_id);

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

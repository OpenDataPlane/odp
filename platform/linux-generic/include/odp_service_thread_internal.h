/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#ifndef ODP_SERVICE_THREAD_INTERNAL_H_
#define ODP_SERVICE_THREAD_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/atomic.h>
#include <odp/api/cpumask.h>

#include <pthread.h>

/* Service thread parameters */
typedef struct {
	/* Thread body. Called after the thread has been locally initialized as
	 * _ODP_THR_INTERNAL. When it returns, the thread terminates locally and exits.
	 * A non-zero return value is reported by _odp_service_thread_join(). */
	int (*run)(void *arg);
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
	/* Return value of 'run', zero if 'run' was not called */
	int ret;
} _odp_service_thread_t;

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
 * Not supported in process mode (ODP_MEM_MODEL_PROCESS), fails in that case.
 *
 * Returns 0 on success, -1 on error. */
int _odp_service_thread_create(_odp_service_thread_t thr[],
			       const _odp_service_thread_param_t param[], int num);

/* Wait for 'num' service threads created with _odp_service_thread_create()
 * to exit. Stopping the threads, i.e. making their 'run' function return, is
 * the caller's responsibility. Non-zero 'run' return values are logged.
 *
 * Returns 0 on success, -1 on error or if any 'run' returned non-zero. */
int _odp_service_thread_join(_odp_service_thread_t thr[], int num);

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

#ifdef __cplusplus
}
#endif

#endif

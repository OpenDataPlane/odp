/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#ifndef ODP_SERVICE_THREAD_INTERNAL_H_
#define ODP_SERVICE_THREAD_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/cpumask.h>

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

/* Returns the number of thread id slots, including those of ODP-internal
 * threads. Unlike odp_thread_count_max(), this covers every value that
 * odp_thread_id() may return, so implementation-internal per-thread state
 * indexed by thread id must be sized and iterated with this. */
int _odp_thread_count_max(void);

#ifdef __cplusplus
}
#endif

#endif

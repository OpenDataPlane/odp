/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <sched.h>
#include <pthread.h>

#include <odp/api/cpumask.h>
#include <odp_debug_internal.h>

int odp_cpumask_default_worker(odp_cpumask_t *mask, int num)
{
	odp_cpumask_t overlap;
	int cpu, i;

	/*
	 * If no user supplied number or it's too large, then attempt
	 * to use all CPUs
	 */
	cpu = odp_cpumask_count(&odp_global_ro.worker_cpus);
	if (0 == num || cpu < num)
		num = cpu;

	/* build the mask, allocating down from highest numbered CPU */
	odp_cpumask_zero(mask);
	for (cpu = 0, i = CPU_SETSIZE - 1; i >= 0 && cpu < num; --i) {
		if (odp_cpumask_isset(&odp_global_ro.worker_cpus, i)) {
			odp_cpumask_set(mask, i);
			cpu++;
		}
	}

	odp_cpumask_and(&overlap, mask, &odp_global_ro.control_cpus);
	if (odp_cpumask_count(&overlap))
		ODP_DBG("\n\tWorker CPUs overlap with control CPUs...\n"
			"\tthis will likely have a performance impact on the worker threads.\n");

	return cpu;
}

int odp_cpumask_default_control(odp_cpumask_t *mask, int num)
{
	odp_cpumask_t overlap;
	int cpu, i;

	/*
	 * If no user supplied number then default to one control CPU.
	 */
	if (0 == num) {
		num = 1;
	} else {
		/*
		 * If user supplied number is too large, then attempt
		 * to use all installed control CPUs
		 */
		cpu = odp_cpumask_count(&odp_global_ro.control_cpus);
		if (cpu < num)
			num = cpu;
	}

	/* build the mask, allocating upwards from lowest numbered CPU */
	odp_cpumask_zero(mask);
	for (cpu = 0, i = 0; i < CPU_SETSIZE && cpu < num; i++) {
		if (odp_cpumask_isset(&odp_global_ro.control_cpus, i)) {
			odp_cpumask_set(mask, i);
			cpu++;
		}
	}

	odp_cpumask_and(&overlap, mask, &odp_global_ro.worker_cpus);
	if (odp_cpumask_count(&overlap))
		ODP_DBG("\n\tControl CPUs overlap with worker CPUs...\n"
			"\tthis will likely have a performance impact on the worker threads.\n");

	return cpu;
}

int odp_cpumask_all_available(odp_cpumask_t *mask)
{
	odp_cpumask_or(mask, &odp_global_ro.worker_cpus,
		       &odp_global_ro.control_cpus);

	return odp_cpumask_count(mask);
}

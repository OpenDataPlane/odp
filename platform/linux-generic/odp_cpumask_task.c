/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2021-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <sched.h>
#include <pthread.h>

#include <odp/api/cpumask.h>
#include <odp_debug_internal.h>

int odp_cpumask_default_worker(odp_cpumask_t *mask, int max_num)
{
	int num, cpu, ret;
	odp_cpumask_t *worker_cpus = &odp_global_ro.worker_cpus;

	num = odp_cpumask_count(worker_cpus);

	if (max_num && num > max_num)
		num = max_num;

	if (mask == NULL)
		return num;

	odp_cpumask_zero(mask);

	/* Allocate down from the highest numbered CPU */
	cpu = odp_cpumask_last(worker_cpus);
	ret = num;

	while (cpu >= 0 && num > 0) {
		if (odp_cpumask_isset(worker_cpus, cpu)) {
			odp_cpumask_set(mask, cpu);
			num--;
		}

		cpu--;
	}

	return ret;
}

int odp_cpumask_default_control(odp_cpumask_t *mask, int max_num)
{
	int num, cpu, last, ret;
	odp_cpumask_t *control_cpus = &odp_global_ro.control_cpus;

	num = odp_cpumask_count(control_cpus);

	if (max_num && num > max_num)
		num = max_num;

	if (mask == NULL)
		return num;

	odp_cpumask_zero(mask);

	/* Allocate up from the lowest numbered CPU */
	cpu  = odp_cpumask_first(control_cpus);
	last = odp_cpumask_last(control_cpus);
	ret  = num;

	while (cpu <= last && num > 0) {
		if (odp_cpumask_isset(control_cpus, cpu)) {
			odp_cpumask_set(mask, cpu);
			num--;
		}

		cpu++;
	}

	return ret;
}

int odp_cpumask_all_available(odp_cpumask_t *mask)
{
	odp_cpumask_or(mask, &odp_global_ro.worker_cpus,
		       &odp_global_ro.control_cpus);

	return odp_cpumask_count(mask);
}

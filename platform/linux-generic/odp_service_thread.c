/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#include <odp/api/cpumask.h>
#include <odp/api/init.h>

#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp_service_thread_internal.h>

static int check_overlap(const odp_cpumask_t *cpus, const odp_cpumask_t *mask, const char *type)
{
	odp_cpumask_t overlap;
	char str[ODP_CPUMASK_STR_SIZE];

	odp_cpumask_and(&overlap, cpus, mask);

	if (odp_cpumask_count(&overlap) == 0)
		return 0;

	odp_cpumask_to_str(&overlap, str, sizeof(str));
	_ODP_ERR("Requested service CPUs %s overlap with %s CPUs set in init parameters\n", str,
		 type);

	return -1;
}

static void refill_default_mask(odp_cpumask_t *mask, const odp_cpumask_t *other)
{
	if (odp_cpumask_count(mask) > 0)
		return;

	/* Prefer CPUs not used by the other thread type, share all CPUs if none are left. 'other'
	 * is a subset of 'all_cpus'. */
	odp_cpumask_xor(mask, &odp_global_ro.all_cpus, other);

	if (odp_cpumask_count(mask) == 0)
		odp_cpumask_copy(mask, &odp_global_ro.all_cpus);
}

int _odp_service_cpus_reserve(const odp_cpumask_t *cpus)
{
	const odp_init_t *param = &odp_global_ro.init_param;
	odp_cpumask_t check;

	if (cpus == NULL || odp_cpumask_count(cpus) == 0)
		return 0;

	odp_cpumask_and(&check, cpus, &odp_global_ro.service_cpus);

	if (odp_cpumask_count(&check) > 0) {
		char conflict_str[ODP_CPUMASK_STR_SIZE];

		odp_cpumask_to_str(&check, conflict_str, sizeof(conflict_str));
		_ODP_ERR("Requested service CPUs %s already reserved\n", conflict_str);
		return -1;
	}

	odp_cpumask_and(&check, cpus, &odp_global_ro.all_cpus);

	if (!odp_cpumask_equal(&check, cpus)) {
		char req_str[ODP_CPUMASK_STR_SIZE];
		char vis_str[ODP_CPUMASK_STR_SIZE];

		odp_cpumask_to_str(cpus, req_str, sizeof(req_str));
		odp_cpumask_to_str(&odp_global_ro.all_cpus, vis_str, sizeof(vis_str));
		_ODP_ERR("Requested service CPUs %s not all available in %s\n",
			 req_str, vis_str);
		return -1;
	}

	if (odp_cpumask_equal(cpus, &odp_global_ro.all_cpus)) {
		char req_str[ODP_CPUMASK_STR_SIZE];

		odp_cpumask_to_str(cpus, req_str, sizeof(req_str));
		_ODP_ERR("Requested service CPUs %s would leave no CPUs for application threads\n",
			 req_str);
		return -1;
	}

	if (param->worker_cpus && check_overlap(cpus, &odp_global_ro.worker_cpus, "worker"))
		return -1;

	if (param->control_cpus && check_overlap(cpus, &odp_global_ro.control_cpus, "control"))
		return -1;

	odp_cpumask_or(&odp_global_ro.service_cpus, &odp_global_ro.service_cpus, cpus);
	odp_cpumask_xor(&odp_global_ro.all_cpus, &odp_global_ro.all_cpus, cpus);
	odp_cpumask_and(&odp_global_ro.worker_cpus, &odp_global_ro.worker_cpus,
			&odp_global_ro.all_cpus);
	odp_cpumask_and(&odp_global_ro.control_cpus, &odp_global_ro.control_cpus,
			&odp_global_ro.all_cpus);

	if (!param->worker_cpus)
		refill_default_mask(&odp_global_ro.worker_cpus, &odp_global_ro.control_cpus);

	if (!param->control_cpus)
		refill_default_mask(&odp_global_ro.control_cpus, &odp_global_ro.worker_cpus);

	odp_global_ro.num_service_cpus = odp_cpumask_count(&odp_global_ro.service_cpus);
	odp_global_ro.num_cpus_installed = odp_cpumask_count(&odp_global_ro.all_cpus);

	return 0;
}

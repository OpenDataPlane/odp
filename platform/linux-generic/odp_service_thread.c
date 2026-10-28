/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#include <odp_posix_extensions.h>

#include <odp/api/cpu.h>
#include <odp/api/cpumask.h>
#include <odp/api/init.h>

#include <odp/api/plat/atomic_inlines.h>

#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_service_thread_internal.h>

#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>

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

/* Service thread startup states */
#define SVC_THR_STARTING 0u
#define SVC_THR_READY    1u
#define SVC_THR_FAILED   2u
#define SVC_THR_RUN      3u
#define SVC_THR_EXIT     4u

static void *service_thread_main(void *arg)
{
	_odp_service_thread_t *thr = arg;
	uint32_t state;

	if (_odp_init_local((odp_instance_t)odp_global_ro.main_pid, _ODP_THR_INTERNAL) < 0) {
		odp_atomic_store_rel_u32(&thr->state, SVC_THR_FAILED);
		return NULL;
	}

	odp_atomic_store_rel_u32(&thr->state, SVC_THR_READY);

	while ((state = odp_atomic_load_acq_u32(&thr->state)) == SVC_THR_READY)
		odp_cpu_pause();

	if (state == SVC_THR_RUN)
		thr->ret = thr->param.run(thr->param.arg);

	if (odp_term_local() < 0)
		_ODP_ERR("Service thread local term failed\n");

	return NULL;
}

static int service_thread_start(_odp_service_thread_t *thr)
{
	pthread_attr_t attr;
	cpu_set_t cpu_set;
	int ret;

	ret = pthread_attr_init(&attr);

	if (ret) {
		_ODP_ERR("pthread_attr_init() failed: %s\n", strerror(ret));
		return -1;
	}

	CPU_ZERO(&cpu_set);
	CPU_SET(thr->param.cpu, &cpu_set);
	ret = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpu_set);

	if (ret) {
		_ODP_ERR("pthread_attr_setaffinity_np() failed: %s\n", strerror(ret));
		goto out;
	}

	ret = pthread_create(&thr->thread, &attr, service_thread_main, thr);

	if (ret)
		_ODP_ERR("pthread_create() failed: %s\n", strerror(ret));

out:
	(void)pthread_attr_destroy(&attr);

	return ret ? -1 : 0;
}

int _odp_service_thread_create(_odp_service_thread_t thr[],
			       const _odp_service_thread_param_t param[], int num)
{
	int num_created = 0;
	int ret = 0;

	if (odp_global_ro.init_param.mem_model == ODP_MEM_MODEL_PROCESS) {
		_ODP_ERR("Service threads not supported in process mode\n");
		return -1;
	}

	for (int i = 0; i < num; i++) {
		if (param[i].run == NULL || param[i].cpu < 0 || param[i].cpu >= CPU_SETSIZE ||
		    !odp_cpumask_isset(&odp_global_ro.service_cpus, param[i].cpu)) {
			_ODP_ERR("Bad service thread parameters (index: %i, CPU: %i)\n", i,
				 param[i].cpu);
			ret = -1;
			break;
		}

		thr[i].param = param[i];
		thr[i].ret = 0;
		odp_atomic_init_u32(&thr[i].state, SVC_THR_STARTING);

		if (service_thread_start(&thr[i])) {
			ret = -1;
			break;
		}

		num_created++;
	}

	for (int i = 0; i < num_created; i++) {
		uint32_t state;

		while ((state = odp_atomic_load_acq_u32(&thr[i].state)) == SVC_THR_STARTING)
			odp_cpu_pause();

		if (state == SVC_THR_FAILED) {
			_ODP_ERR("Service thread %i local init failed\n", i);
			ret = -1;
		}
	}

	for (int i = 0; i < num_created; i++) {
		if (odp_atomic_load_u32(&thr[i].state) == SVC_THR_READY)
			odp_atomic_store_rel_u32(&thr[i].state, ret ? SVC_THR_EXIT : SVC_THR_RUN);
	}

	if (ret)
		(void)_odp_service_thread_join(thr, num_created);

	return ret;
}

int _odp_service_thread_join(_odp_service_thread_t thr[], int num)
{
	int ret = 0;

	for (int i = 0; i < num; i++) {
		int err = pthread_join(thr[i].thread, NULL);

		if (err) {
			_ODP_ERR("pthread_join() failed: %s\n", strerror(err));
			ret = -1;
			continue;
		}

		if (thr[i].ret) {
			_ODP_ERR("Service thread %i (CPU %i) returned %i\n", i, thr[i].param.cpu,
				 thr[i].ret);
			ret = -1;
		}
	}

	return ret;
}

/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <odp/helper/linux.h>
#include <odp_internal.h>
#include <odp/thread.h>
#include <odp/init.h>
#include <odp/system_info.h>
#include <odp_debug_internal.h>

#include <rte_lcore.h>

int odph_linux_cpumask_default(odp_cpumask_t *mask, int num_in)
{
	int i;
	int first_cpu = 1;
	int num = num_in;
	int cpu_count;

	cpu_count = odp_cpu_count();

	/*
	 * If no user supplied number or it's too large, then attempt
	 * to use all CPUs
	 */
	if (0 == num)
		num = cpu_count;
	if (cpu_count < num)
		num = cpu_count;

	/*
	 * Always force "first_cpu" to a valid CPU
	 */
	if (first_cpu >= cpu_count)
		first_cpu = cpu_count - 1;

	/* Build the mask */
	odp_cpumask_zero(mask);
	for (i = 0; i < num; i++) {
		int cpu;

		cpu = (first_cpu + i) % cpu_count;
		odp_cpumask_set(mask, cpu);
	}

	return num;
}

static void *odp_run_start_routine(void *arg)
{
	odp_start_args_t *start_args = arg;

	/* ODP thread local init */
	if (odp_init_local()) {
		ODP_ERR("Local init failed\n");
		return NULL;
	}

	return start_args->start_routine(start_args->arg);
}


void odph_linux_pthread_create(odph_linux_pthread_t *thread_tbl,
			       const odp_cpumask_t *mask_in,
			       void *(*start_routine) (void *), void *arg)
{
	int i, num;
	int cpu;
	odp_cpumask_t mask;

	odp_cpumask_copy(&mask, mask_in);
	num = odp_cpumask_count(&mask);

	memset(thread_tbl, 0, num * sizeof(odph_linux_pthread_t));
        if (num < 1 || num > odp_cpu_count()) {
                ODP_ERR("Bad num\n");
                return;
        }

	cpu = odp_cpumask_first(&mask);
	for (i = 0; i < num; i++) {
		thread_tbl[i].cpu = cpu;

                /* pthread affinity is not set here because, DPDK
                 * creates, initialises and sets the affinity for pthread
                 * part of rte_eal_init()
                 */

		thread_tbl[i].start_args = malloc(sizeof(odp_start_args_t));
		if (thread_tbl[i].start_args == NULL)
			ODP_ABORT("Malloc failed");

		thread_tbl[i].start_args->start_routine = start_routine;
		thread_tbl[i].start_args->arg           = arg;

		/* If not master core */
		if (cpu != 0) {
			rte_eal_remote_launch(
				(int(*)(void *))odp_run_start_routine,
				thread_tbl[i].start_args, cpu);
		} else {
			lcore_config[cpu].ret = (int)(uint64_t)
				odp_run_start_routine(thread_tbl[i].start_args);
			lcore_config[cpu].state = FINISHED;
		}
		cpu = odp_cpumask_next(&mask, cpu);
	}
}


void odph_linux_pthread_join(odph_linux_pthread_t *thread_tbl, int num)
{
	uint32_t lcore_id;

	(void) thread_tbl;
	(void) num;

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		int ret = rte_eal_wait_lcore(lcore_id);
		free(thread_tbl[lcore_id].start_args);
		if (ret < 0)
			return;
	}
}

int odph_linux_process_fork_n(odph_linux_process_t *proc_tbl ODP_UNUSED,
			      const odp_cpumask_t *mask_in ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	ODP_ABORT("");
	return 0;
}

int odph_linux_process_wait_n(odph_linux_process_t *proc_tbl ODP_UNUSED, int num ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	ODP_ABORT("");
	return 0;
}

/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

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

#define MAX_WORKERS 32

int odph_linux_cpumask_default(odp_cpumask_t *mask, int num_in)
{
	int i;
	int first_cpu = 1;
	int num = num_in;
	int cpu_count;

	cpu_count = odp_sys_cpu_count();

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

	void *ret_ptr = start_args->start_routine(start_args->arg);
	_odp_flush_caches();
	int ret = odp_term_local();
	if (ret < 0)
		ODP_ERR("Local term failed\n");
	else if (ret == 0 && odp_term_global())
		ODP_ERR("Global term failed\n");

	return ret_ptr;
}


void odph_linux_pthread_create(odph_linux_pthread_t *thread_tbl,
			       const odp_cpumask_t *mask_in,
			       void *(*start_routine) (void *), void *arg)
{
	int i;
	int num;
	odp_cpumask_t mask;
	int cpu_count;
	int cpu;

	odp_cpumask_copy(&mask, mask_in);
	num = odp_cpumask_count(&mask);

	memset(thread_tbl, 0, num * sizeof(odph_linux_pthread_t));

	cpu_count = odp_sys_cpu_count();

	if (num < 1 || num > cpu_count) {
		ODP_ERR("Bad num\n");
		return;
	}

	cpu = odp_cpumask_first(&mask);
	for (i = 0; i < num; i++) {
		odp_cpumask_t thd_mask;

		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);

		pthread_attr_init(&thread_tbl[i].attr);

		thread_tbl[i].cpu = cpu;

		pthread_attr_setaffinity_np(&thread_tbl[i].attr,
					    sizeof(cpu_set_t), &thd_mask.set);

		thread_tbl[i].start_args = malloc(sizeof(odp_start_args_t));
		if (thread_tbl[i].start_args == NULL)
			ODP_ABORT("Malloc failed");

		thread_tbl[i].start_args->start_routine = start_routine;
		thread_tbl[i].start_args->arg           = arg;

		pthread_create(&thread_tbl[i].thread, &thread_tbl[i].attr,
			       odp_run_start_routine, thread_tbl[i].start_args);

		cpu = odp_cpumask_next(&mask, cpu);
	}
}


void odph_linux_pthread_join(odph_linux_pthread_t *thread_tbl, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		/* Wait thread to exit */
		pthread_join(thread_tbl[i].thread, NULL);
		free(thread_tbl[i].start_args);
	}

}


int odph_linux_process_fork_n(odph_linux_process_t *proc_tbl,
			      const odp_cpumask_t *mask_in)
{
	odp_cpumask_t mask;
	pid_t pid;
	int num;
	int cpu_count;
	int cpu;
	int i;

	odp_cpumask_copy(&mask, mask_in);
	num = odp_cpumask_count(&mask);

	memset(proc_tbl, 0, num * sizeof(odph_linux_process_t));

	cpu_count = odp_sys_cpu_count();

	if (num < 1 || num > cpu_count) {
		ODP_ERR("Bad num\n");
		return -1;
	}

	cpu = odp_cpumask_first(&mask);
	for (i = 0; i < num; i++) {
		odp_cpumask_t proc_mask;

		odp_cpumask_zero(&proc_mask);
		odp_cpumask_set(&proc_mask, cpu);

		pid = fork();

		if (pid < 0) {
			ODP_ERR("fork() failed\n");
			return -1;
		}

		/* Parent continues to fork */
		if (pid > 0) {
			proc_tbl[i].pid  = pid;
			proc_tbl[i].cpu = cpu;

			cpu = odp_cpumask_next(&mask, cpu);
			continue;
		}

		/* Child process */
		if (sched_setaffinity(0, sizeof(cpu_set_t), &proc_mask.set)) {
			ODP_ERR("sched_setaffinity() failed\n");
			return -2;
		}

		if (odp_init_local()) {
			ODP_ERR("Local init failed\n");
			return -2;
		}

		return 0;
	}

	return 1;
}


int odph_linux_process_fork(odph_linux_process_t *proc, int cpu)
{
	odp_cpumask_t mask;

	odp_cpumask_zero(&mask);
	odp_cpumask_set(&mask, cpu);
	return odph_linux_process_fork_n(proc, &mask);
}


int odph_linux_process_wait_n(odph_linux_process_t *proc_tbl, int num)
{
	pid_t pid;
	int i, j;
	int status;

	for (i = 0; i < num; i++) {
		pid = wait(&status);

		if (pid < 0) {
			ODP_ERR("wait() failed\n");
			return -1;
		}

		for (j = 0; j < num; j++) {
			if (proc_tbl[j].pid == pid) {
				proc_tbl[j].status = status;
				break;
			}
		}

		if (j == num) {
			ODP_ERR("Bad pid\n");
			return -1;
		}
	}

	return 0;
}

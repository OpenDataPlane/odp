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


#include <odph_linux.h>
#include <odp_internal.h>
#include <odp_thread.h>
#include <odp_init.h>
#include <odp_system_info.h>
#include <odp_debug_internal.h>


typedef struct {
	void *(*start_routine) (void *);
	void *arg;

} odp_start_args_t;


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


void odph_linux_pthread_create(odph_linux_pthread_t *thread_tbl, int num,
			       int first_cpu,
			       void *(*start_routine) (void *), void *arg)
{
	int i;
	cpu_set_t cpu_set;
	odp_start_args_t *start_args;
	int cpu_count;
	int cpu;

	cpu_count = odp_sys_cpu_count();

	assert((first_cpu >= 0) && (first_cpu < cpu_count));
	assert((num >= 0) && (num <= cpu_count));

	memset(thread_tbl, 0, num * sizeof(odph_linux_pthread_t));

	for (i = 0; i < num; i++) {
		pthread_attr_init(&thread_tbl[i].attr);

		cpu = (first_cpu + i) % cpu_count;
		thread_tbl[i].cpu = cpu;
		CPU_ZERO(&cpu_set);
		CPU_SET(cpu, &cpu_set);

		pthread_attr_setaffinity_np(&thread_tbl[i].attr,
					    sizeof(cpu_set_t), &cpu_set);

		start_args = malloc(sizeof(odp_start_args_t));
		if (start_args == NULL)
			ODP_ABORT("Malloc failed");

		memset(start_args, 0, sizeof(odp_start_args_t));
		start_args->start_routine = start_routine;
		start_args->arg           = arg;

		pthread_create(&thread_tbl[i].thread, &thread_tbl[i].attr,
			       odp_run_start_routine, start_args);
	}
}


void odph_linux_pthread_join(odph_linux_pthread_t *thread_tbl, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		/* Wait thread to exit */
		pthread_join(thread_tbl[i].thread, NULL);
	}
}


int odph_linux_process_fork_n(odph_linux_process_t *proc_tbl,
			      int num, int first_cpu)
{
	cpu_set_t cpu_set;
	pid_t pid;
	int cpu_count;
	int cpu;
	int i;

	memset(proc_tbl, 0, num*sizeof(odph_linux_process_t));

	cpu_count = odp_sys_cpu_count();

	if (first_cpu < 0 || first_cpu >= cpu_count) {
		ODP_ERR("Bad first_cpu\n");
		return -1;
	}

	if (num < 0 || num > cpu_count) {
		ODP_ERR("Bad num\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		cpu = (first_cpu + i) % cpu_count;
		pid = fork();

		if (pid < 0) {
			ODP_ERR("fork() failed\n");
			return -1;
		}

		/* Parent continues to fork */
		if (pid > 0) {
			proc_tbl[i].pid  = pid;
			proc_tbl[i].cpu = cpu;
			continue;
		}

		/* Child process */
		CPU_ZERO(&cpu_set);
		CPU_SET(cpu, &cpu_set);

		if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set)) {
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
	return odph_linux_process_fork_n(proc, 1, cpu);
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

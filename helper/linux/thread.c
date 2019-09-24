/* Copyright (c) 2016-2018, Linaro Limited
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
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <odp_api.h>
#include <odp/helper/linux/pthread.h>
#include <odp/helper/linux/process.h>
#include <odp/helper/odph_debug.h>

static void *_odph_run_start_routine(void *arg)
{
	odph_linux_thr_params_t *thr_params = arg;

	/* ODP thread local init */
	if (odp_init_local(thr_params->instance, thr_params->thr_type)) {
		ODPH_ERR("Local init failed\n");
		return NULL;
	}

	void *ret_ptr = thr_params->start(thr_params->arg);
	int ret = odp_term_local();

	if (ret < 0)
		ODPH_ERR("Local term failed\n");

	return ret_ptr;
}

int odph_linux_pthread_create(odph_linux_pthread_t *pthread_tbl,
			      const odp_cpumask_t *mask,
			      const odph_linux_thr_params_t *thr_params)
{
	int i;
	int num;
	int cpu_count;
	int cpu;
	int ret;

	num = odp_cpumask_count(mask);

	memset(pthread_tbl, 0, num * sizeof(odph_linux_pthread_t));

	cpu_count = odp_cpu_count();

	if (num < 1 || num > cpu_count) {
		ODPH_ERR("Invalid number of threads:%d (%d cores available)\n",
			 num, cpu_count);
		return 0;
	}

	cpu = odp_cpumask_first(mask);
	for (i = 0; i < num; i++) {
		cpu_set_t cpu_set;

		CPU_ZERO(&cpu_set);
		CPU_SET(cpu, &cpu_set);

		pthread_attr_init(&pthread_tbl[i].attr);

		pthread_tbl[i].cpu = cpu;

		pthread_attr_setaffinity_np(&pthread_tbl[i].attr,
					    sizeof(cpu_set_t), &cpu_set);

		pthread_tbl[i].thr_params.start    = thr_params->start;
		pthread_tbl[i].thr_params.arg      = thr_params->arg;
		pthread_tbl[i].thr_params.thr_type = thr_params->thr_type;
		pthread_tbl[i].thr_params.instance = thr_params->instance;

		ret = pthread_create(&pthread_tbl[i].thread,
				     &pthread_tbl[i].attr,
				     _odph_run_start_routine,
				     &pthread_tbl[i].thr_params);
		if (ret != 0) {
			ODPH_ERR("Failed to start thread on cpu #%d\n", cpu);
			break;
		}

		cpu = odp_cpumask_next(mask, cpu);
	}

	return i;
}

void odph_linux_pthread_join(odph_linux_pthread_t *thread_tbl, int num)
{
	int i;
	int ret;

	for (i = 0; i < num; i++) {
		/* Wait thread to exit */
		ret = pthread_join(thread_tbl[i].thread, NULL);
		if (ret != 0) {
			ODPH_ERR("Failed to join thread from cpu #%d\n",
				 thread_tbl[i].cpu);
		}
		pthread_attr_destroy(&thread_tbl[i].attr);
	}
}

int odph_linux_process_fork_n(odph_linux_process_t *proc_tbl,
			      const odp_cpumask_t *mask,
			      const odph_linux_thr_params_t *thr_params)
{
	pid_t pid;
	int num;
	int cpu_count;
	int cpu;
	int i;

	num = odp_cpumask_count(mask);

	memset(proc_tbl, 0, num * sizeof(odph_linux_process_t));

	cpu_count = odp_cpu_count();

	if (num < 1 || num > cpu_count) {
		ODPH_ERR("Bad num\n");
		return -1;
	}

	cpu = odp_cpumask_first(mask);
	for (i = 0; i < num; i++) {
		cpu_set_t cpu_set;

		CPU_ZERO(&cpu_set);
		CPU_SET(cpu, &cpu_set);

		pid = fork();

		if (pid < 0) {
			ODPH_ERR("fork() failed\n");
			return -1;
		}

		/* Parent continues to fork */
		if (pid > 0) {
			proc_tbl[i].pid  = pid;
			proc_tbl[i].cpu = cpu;

			cpu = odp_cpumask_next(mask, cpu);
			continue;
		}

		/* Child process */

		/* Request SIGTERM if parent dies */
		prctl(PR_SET_PDEATHSIG, SIGTERM);
		/* Parent died already? */
		if (getppid() == 1)
			kill(getpid(), SIGTERM);

		if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set)) {
			ODPH_ERR("sched_setaffinity() failed\n");
			return -2;
		}

		if (odp_init_local(thr_params->instance,
				   thr_params->thr_type)) {
			ODPH_ERR("Local init failed\n");
			return -2;
		}

		return 0;
	}

	return 1;
}

int odph_linux_process_fork(odph_linux_process_t *proc, int cpu,
			    const odph_linux_thr_params_t *thr_params)
{
	odp_cpumask_t mask;

	odp_cpumask_zero(&mask);
	odp_cpumask_set(&mask, cpu);
	return odph_linux_process_fork_n(proc, &mask, thr_params);
}

int odph_linux_process_wait_n(odph_linux_process_t *proc_tbl, int num)
{
	pid_t pid;
	int i, j;
	int status = 0;

	for (i = 0; i < num; i++) {
		pid = wait(&status);

		if (pid < 0) {
			ODPH_ERR("wait() failed\n");
			return -1;
		}

		for (j = 0; j < num; j++) {
			if (proc_tbl[j].pid == pid) {
				proc_tbl[j].status = status;
				break;
			}
		}

		if (j == num) {
			ODPH_ERR("Bad pid:%d\n", (int)pid);
			return -1;
		}

		/* Examine the child process' termination status */
		if (WIFEXITED(status) && WEXITSTATUS(status) != EXIT_SUCCESS) {
			ODPH_ERR("Child exit status:%d (pid:%d)\n",
				 WEXITSTATUS(status), (int)pid);
			return -1;
		}
		if (WIFSIGNALED(status)) {
			int signo = WTERMSIG(status);

			ODPH_ERR("Child term signo:%d - %s (pid:%d)\n",
				 signo, strsignal(signo), (int)pid);
			return -1;
		}
	}

	return 0;
}

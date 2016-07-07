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
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <odp_api.h>
#include <odp/helper/linux.h>
#include "odph_debug.h"

static struct {
	int proc; /* true when process mode is required, false otherwise */
} helper_options;

static void *odp_run_start_routine(void *arg)
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
	else if (ret == 0 && odp_term_global(thr_params->instance))
		ODPH_ERR("Global term failed\n");

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
				     odp_run_start_routine,
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

/*
 * wrapper for odpthreads, either implemented as linux threads or processes.
 * (in process mode, if start_routine returns NULL, the process return FAILURE).
 */
static void *odpthread_run_start_routine(void *arg)
{
	int status;
	int ret;
	odph_odpthread_params_t *thr_params;

	odph_odpthread_start_args_t *start_args = arg;

	thr_params = &start_args->thr_params;

	/* ODP thread local init */
	if (odp_init_local(thr_params->instance, thr_params->thr_type)) {
		ODPH_ERR("Local init failed\n");
		if (start_args->linuxtype == ODPTHREAD_PROCESS)
			_exit(EXIT_FAILURE);
		return (void *)-1;
	}

	ODPH_DBG("helper: ODP %s thread started as linux %s. (pid=%d)\n",
		 thr_params->thr_type == ODP_THREAD_WORKER ?
		 "worker" : "control",
		 (start_args->linuxtype == ODPTHREAD_PTHREAD) ?
		 "pthread" : "process",
		 (int)getpid());

	status = thr_params->start(thr_params->arg);
	ret = odp_term_local();

	if (ret < 0)
		ODPH_ERR("Local term failed\n");
	else if (ret == 0 && odp_term_global(thr_params->instance))
		ODPH_ERR("Global term failed\n");

	/* for process implementation of odp threads, just return status... */
	if (start_args->linuxtype == ODPTHREAD_PROCESS)
		_exit(status);

	/* threads implementation return void* pointers: cast status to that. */
	return (void *)(intptr_t)status;
}

/*
 * Create a single ODPthread as a linux process
 */
static int odph_linux_process_create(odph_odpthread_t *thread_tbl,
				     int cpu,
				     const odph_odpthread_params_t *thr_params)
{
	int ret;
	cpu_set_t cpu_set;
	pid_t pid;

	CPU_ZERO(&cpu_set);
	CPU_SET(cpu, &cpu_set);

	thread_tbl->start_args.thr_params    = *thr_params; /* copy */
	thread_tbl->start_args.linuxtype     = ODPTHREAD_PROCESS;
	thread_tbl->cpu = cpu;

	pid = fork();
	if (pid < 0) {
		ODPH_ERR("fork() failed\n");
		thread_tbl->start_args.linuxtype = ODPTHREAD_NOT_STARTED;
		return -1;
	}

	/* Parent continues to fork */
	if (pid > 0) {
		thread_tbl->proc.pid  = pid;
		return 0;
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

	odpthread_run_start_routine(&thread_tbl->start_args);

	return 0; /* never reached */
}

/*
 * Create a single ODPthread as a linux thread
 */
static int odph_linux_thread_create(odph_odpthread_t *thread_tbl,
				    int cpu,
				    const odph_odpthread_params_t *thr_params)
{
	int ret;
	cpu_set_t cpu_set;

	CPU_ZERO(&cpu_set);
	CPU_SET(cpu, &cpu_set);

	pthread_attr_init(&thread_tbl->thread.attr);

	thread_tbl->cpu = cpu;

	pthread_attr_setaffinity_np(&thread_tbl->thread.attr,
				    sizeof(cpu_set_t), &cpu_set);

	thread_tbl->start_args.thr_params    = *thr_params; /* copy */
	thread_tbl->start_args.linuxtype     = ODPTHREAD_PTHREAD;

	ret = pthread_create(&thread_tbl->thread.thread_id,
			     &thread_tbl->thread.attr,
			     odpthread_run_start_routine,
			     &thread_tbl->start_args);
	if (ret != 0) {
		ODPH_ERR("Failed to start thread on cpu #%d\n", cpu);
		thread_tbl->start_args.linuxtype = ODPTHREAD_NOT_STARTED;
		return ret;
	}

	return 0;
}

/*
 * create an odpthread set (as linux processes or linux threads or both)
 */
int odph_odpthreads_create(odph_odpthread_t *thread_tbl,
			   const odp_cpumask_t *mask,
			   const odph_odpthread_params_t *thr_params)
{
	int i;
	int num;
	int cpu_count;
	int cpu;

	num = odp_cpumask_count(mask);

	memset(thread_tbl, 0, num * sizeof(odph_odpthread_t));

	cpu_count = odp_cpu_count();

	if (num < 1 || num > cpu_count) {
		ODPH_ERR("Invalid number of odpthreads:%d"
			 " (%d cores available)\n",
			 num, cpu_count);
		return -1;
	}

	cpu = odp_cpumask_first(mask);
	for (i = 0; i < num; i++) {
		if (!helper_options.proc) {
			if (odph_linux_thread_create(&thread_tbl[i],
						     cpu,
						     thr_params))
				break;
		 } else {
			if (odph_linux_process_create(&thread_tbl[i],
						      cpu,
						      thr_params))
				break;
		}

		cpu = odp_cpumask_next(mask, cpu);
	}
	thread_tbl[num - 1].last = 1;

	return i;
}

/*
 * wait for the odpthreads termination (linux processes and threads)
 */
int odph_odpthreads_join(odph_odpthread_t *thread_tbl)
{
	pid_t pid;
	int i = 0;
	int terminated = 0;
	/* child process return code (!=0 is error) */
	int status = 0;
	/* "child" thread return code (!NULL is error) */
	void *thread_ret = NULL;
	int ret;
	int retval = 0;

	/* joins linux threads or wait for processes */
	do {
		/* pthreads: */
		switch (thread_tbl[i].start_args.linuxtype) {
		case ODPTHREAD_PTHREAD:
			/* Wait thread to exit */
			ret = pthread_join(thread_tbl[i].thread.thread_id,
					   &thread_ret);
			if (ret != 0) {
				ODPH_ERR("Failed to join thread from cpu #%d\n",
					 thread_tbl[i].cpu);
				retval = -1;
			} else {
				terminated++;
				if (thread_ret != NULL) {
					ODPH_ERR("Bad exit status cpu #%d %p\n",
						 thread_tbl[i].cpu, thread_ret);
					retval = -1;
				}
			}
			pthread_attr_destroy(&thread_tbl[i].thread.attr);
			break;

		case ODPTHREAD_PROCESS:

			/* processes: */
			pid = waitpid(thread_tbl[i].proc.pid, &status, 0);

			if (pid < 0) {
				ODPH_ERR("waitpid() failed\n");
				retval = -1;
				break;
			}

			terminated++;

			/* Examine the child process' termination status */
			if (WIFEXITED(status) &&
			    WEXITSTATUS(status) != EXIT_SUCCESS) {
				ODPH_ERR("Child exit status:%d (pid:%d)\n",
					 WEXITSTATUS(status), (int)pid);
				retval = -1;
			}
			if (WIFSIGNALED(status)) {
				int signo = WTERMSIG(status);

				ODPH_ERR("Child term signo:%d - %s (pid:%d)\n",
					 signo, strsignal(signo), (int)pid);
				retval = -1;
			}
			break;

		case ODPTHREAD_NOT_STARTED:
			ODPH_DBG("No join done on not started ODPthread.\n");
			break;
		default:
			ODPH_DBG("Invalid case statement value!\n");
			break;
		}

	} while (!thread_tbl[i++].last);

	return (retval < 0) ? retval : terminated;
}

/* man gettid() notes:
 * Glibc does not provide a wrapper for this system call;
 */
static inline pid_t __gettid(void)
{
	return (pid_t)syscall(SYS_gettid);
}

int odph_odpthread_setaffinity(const int cpu)
{
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);

	/* determine main process or pthread based on
	 * equality of thread and thread group IDs.
	 */
	if (__gettid() == getpid()) {
		return sched_setaffinity(
			0, /* pid zero means calling process */
			sizeof(cpu_set_t), &cpuset);
	}

	/* on error, they return a nonzero error number. */
	return (0 == pthread_setaffinity_np(
		pthread_self(), sizeof(cpu_set_t), &cpuset)) ? 0 : -1;
}

int odph_odpthread_getaffinity(void)
{
	int cpu, result;
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	if (__gettid() == getpid()) {
		result = sched_getaffinity(
			0, sizeof(cpu_set_t), &cpuset);
	} else {
		result = pthread_getaffinity_np(
			pthread_self(), sizeof(cpu_set_t), &cpuset);
	}

	/* ODP thread mean to run on single CPU core */
	if ((result == 0) && (CPU_COUNT(&cpuset) == 1)) {
		for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
			if (CPU_ISSET(cpu, &cpuset))
				return cpu;
		}
	}
	return -1;
}

/*
 * return the number of elements in an array of getopt options, excluding the
 * terminating {0,0,0,0}
 */
static int get_getopt_options_length(const struct option *longopts)
{
	int l = 0;

	if (!longopts)
		return 0;

	while (longopts[l].name)
		l++;

	return l;
}

/* Merge getopt options */
int odph_merge_getopt_options(const char *shortopts1,
			      const char *shortopts2,
			      const struct option *longopts1,
			      const struct option *longopts2,
			      char **shortopts,
			      struct option **longopts)
{
	int shortopts1_len;
	int shortopts2_len;
	int longopts1_len;
	int longopts2_len;
	int index;
	int res_index = 0;
	struct option termination = {0, 0, 0, 0};

	/* merge short options: */
	if (shortopts) {
		shortopts1_len = (shortopts1) ? strlen(shortopts1) : 0;
		shortopts2_len = (shortopts2) ? strlen(shortopts2) : 0;
		*shortopts = malloc(shortopts1_len + shortopts2_len + 1);
		if (!*shortopts)
			return -1;

		(*shortopts)[0] = 0;

		if (shortopts1)
			strcpy((*shortopts), shortopts1);
		if (shortopts2)
			strcat((*shortopts), shortopts2);
	}

	/* merge long options */
	if (!longopts)
		return 0;

	longopts1_len = get_getopt_options_length(longopts1);
	longopts2_len = get_getopt_options_length(longopts2);
	*longopts = malloc(sizeof(struct option) *
					(longopts1_len + longopts2_len + 1));
	if (!*longopts) {
		if (shortopts)
			free(*shortopts);
		return -1;
	}

	for (index = 0; (longopts1) && (longopts1[index].name); index++)
		(*longopts)[res_index++] = longopts1[index];

	for (index = 0; (longopts2) && (longopts2[index].name); index++)
		(*longopts)[res_index++] = longopts2[index];

	(*longopts)[res_index] = termination;

	return 0;
}

/*
 * Parse command line options to extract options affecting helpers.
 */
int odph_parse_options(int argc, char *argv[],
		       const char *caller_shortopts,
		       const struct option *caller_longopts)
{
	int c;
	char *shortopts;
	struct option *longopts;
	int res = 0;

	static struct option helper_long_options[] = {
		/* These options set a flag. */
		{"odph_proc",   no_argument, &helper_options.proc, 1},
		{0, 0, 0, 0}
		};

	static char *helper_short_options = "";

	/* defaults: */
	helper_options.proc = false;

	/* merge caller's command line options descriptions with helper's: */
	if (odph_merge_getopt_options(caller_shortopts, helper_short_options,
				      caller_longopts, helper_long_options,
				      &shortopts, &longopts) < 0)
		return -1;

	while (1) {
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv,
				 shortopts, longopts, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		/* check for unknown options or missing arguments */
		if (c == '?' || c == ':')
			res = -1;
	}

	optind = 0; /* caller expects this to be zero if it parses too*/

	free(shortopts);
	free(longopts);

	return res;
}

/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
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
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <odp_api.h>
#include <odp/helper/threads.h>
#include <odp/helper/odph_debug.h>

#define FAILED_CPU -1

/* Thread status codes */
#define NOT_STARTED 0
#define SYNC_INIT   1
#define INIT_DONE   2
#define STARTED     3

static odph_helper_options_t helper_options;

/*
 * Run a thread, either as Linux pthread or process.
 * In process mode, if start_routine returns NULL, the process return FAILURE.
 */
static void *run_thread(void *arg)
{
	int status;
	int ret;
	odp_instance_t instance;
	odph_odpthread_params_t *thr_params;

	odph_thread_start_args_t *start_args = arg;

	thr_params = &start_args->thr_params;
	instance   = start_args->instance;

	/* ODP thread local init */
	if (odp_init_local(instance, thr_params->thr_type)) {
		ODPH_ERR("Local init failed\n");
		if (start_args->mem_model == ODP_MEM_MODEL_PROCESS)
			_exit(EXIT_FAILURE);
		return (void *)-1;
	}

	ODPH_DBG("helper: ODP %s thread started as linux %s. (pid=%d)\n",
		 thr_params->thr_type == ODP_THREAD_WORKER ?
		 "worker" : "control",
		 (start_args->mem_model == ODP_MEM_MODEL_THREAD) ?
		 "pthread" : "process",
		 (int)getpid());

	if (odp_atomic_load_u32(&start_args->status) == SYNC_INIT)
		odp_atomic_store_rel_u32(&start_args->status, INIT_DONE);

	status = thr_params->start(thr_params->arg);
	ret = odp_term_local();

	if (ret < 0)
		ODPH_ERR("Local term failed\n");

	/* for process implementation of odp threads, just return status... */
	if (start_args->mem_model == ODP_MEM_MODEL_PROCESS)
		_exit(status);

	/* threads implementation return void* pointers: cast status to that. */
	return (void *)(intptr_t)status;
}

/*
 * Create a single linux process
 */
static int create_process(odph_thread_t *thread, int cpu)
{
	cpu_set_t cpu_set;
	pid_t pid;

	CPU_ZERO(&cpu_set);
	CPU_SET(cpu, &cpu_set);

	thread->start_args.mem_model = ODP_MEM_MODEL_PROCESS;
	thread->cpu = cpu;

	pid = fork();
	if (pid < 0) {
		ODPH_ERR("fork() failed\n");
		thread->cpu = FAILED_CPU;
		return -1;
	}

	/* Parent continues to fork */
	if (pid > 0) {
		thread->proc.pid  = pid;
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

	run_thread(&thread->start_args);

	return 0; /* never reached */
}

/*
 * Wait single process to exit
 */
static int wait_process(odph_thread_t *thread)
{
	pid_t pid;
	int status = 0;

	pid = waitpid(thread->proc.pid, &status, 0);

	if (pid < 0) {
		ODPH_ERR("waitpid() failed\n");
		return -1;
	}

	/* Examine the child process' termination status */
	if (WIFEXITED(status) &&
	    WEXITSTATUS(status) != EXIT_SUCCESS) {
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

	return 0;
}

/*
 * Create a single linux pthread
 */
static int create_pthread(odph_thread_t *thread, int cpu)
{
	int ret;
	cpu_set_t cpu_set;

	CPU_ZERO(&cpu_set);
	CPU_SET(cpu, &cpu_set);

	pthread_attr_init(&thread->thread.attr);

	thread->cpu = cpu;

	pthread_attr_setaffinity_np(&thread->thread.attr,
				    sizeof(cpu_set_t), &cpu_set);

	thread->start_args.mem_model = ODP_MEM_MODEL_THREAD;

	ret = pthread_create(&thread->thread.thread_id,
			     &thread->thread.attr,
			     run_thread,
			     &thread->start_args);
	if (ret != 0) {
		ODPH_ERR("Failed to start thread on cpu #%d\n", cpu);
		thread->cpu = FAILED_CPU;
		return ret;
	}

	return 0;
}

/*
 * Wait single pthread to exit
 */
static int wait_pthread(odph_thread_t *thread)
{
	int ret;
	void *thread_ret = NULL;

	/* Wait thread to exit */
	ret = pthread_join(thread->thread.thread_id, &thread_ret);

	if (ret) {
		ODPH_ERR("pthread_join failed (%i) from cpu #%i\n",
			 ret, thread->cpu);
		return -1;
	}

	if (thread_ret) {
		ODPH_ERR("Bad exit status cpu #%i %p\n",
			 thread->cpu, thread_ret);
		return -1;
	}

	ret = pthread_attr_destroy(&thread->thread.attr);

	if (ret) {
		ODPH_ERR("pthread_attr_destroy failed (%i) from cpu #%i\n",
			 ret, thread->cpu);
		return -1;
	}

	return 0;
}

int odph_thread_create(odph_thread_t thread[],
		       const odph_thread_common_param_t *param,
		       const odph_thread_param_t thr_param[],
		       int num)
{
	int i, num_cpu, cpu;
	const odp_cpumask_t *cpumask = param->cpumask;
	int use_pthread = 1;

	if (param->thread_model == 1)
		use_pthread = 0;

	if (helper_options.mem_model == ODP_MEM_MODEL_PROCESS)
		use_pthread = 0;

	if (num < 1) {
		ODPH_ERR("Bad number of threads (%i)\n", num);
		return -1;
	}

	num_cpu = odp_cpumask_count(cpumask);

	if (num_cpu != num) {
		ODPH_ERR("Number of threads (%i) and CPUs (%i) does not match"
			 "\n", num, num_cpu);
		return -1;
	}

	memset(thread, 0, num * sizeof(odph_thread_t));

	cpu = odp_cpumask_first(cpumask);
	for (i = 0; i < num; i++) {
		odph_thread_start_args_t *start_args = &thread[i].start_args;

		/* Copy thread parameters */
		if (param->share_param)
			start_args->thr_params = thr_param[0];
		else
			start_args->thr_params = thr_param[i];

		start_args->instance   = param->instance;

		if (param->sync)
			odp_atomic_init_u32(&start_args->status, SYNC_INIT);
		else
			odp_atomic_init_u32(&start_args->status, NOT_STARTED);

		if (use_pthread) {
			if (create_pthread(&thread[i], cpu))
				break;
		} else {
			if (create_process(&thread[i], cpu))
				break;
		}

		/* Wait newly created thread to update status */
		if (param->sync) {
			odp_time_t t1, t2;
			uint64_t diff_ns;
			uint32_t status;
			int timeout = 0;
			odp_atomic_u32_t *atomic = &start_args->status;

			t1 = odp_time_local();

			do {
				odp_cpu_pause();
				t2 = odp_time_local();
				diff_ns = odp_time_diff_ns(t2, t1);
				timeout = diff_ns > ODP_TIME_SEC_IN_NS;
				status = odp_atomic_load_acq_u32(atomic);

			} while (status != INIT_DONE && timeout == 0);

			if (timeout) {
				ODPH_ERR("Thread (i:%i) start up timeout\n", i);
				break;
			}
		}

		odp_atomic_store_u32(&start_args->status, STARTED);

		cpu = odp_cpumask_next(cpumask, cpu);
	}

	return i;
}

int odph_thread_join(odph_thread_t thread[], int num)
{
	odph_thread_start_args_t *start_args;
	int i;

	for (i = 0; i < num; i++) {
		start_args = &thread[i].start_args;

		if (odp_atomic_load_u32(&start_args->status) != STARTED) {
			ODPH_DBG("Thread (i:%i) not started.\n", i);
			break;
		}

		if (thread[i].start_args.mem_model == ODP_MEM_MODEL_THREAD) {
			if (wait_pthread(&thread[i]))
				break;
		} else {
			if (wait_process(&thread[i]))
				break;
		}

		odp_atomic_store_u32(&start_args->status, NOT_STARTED);
	}

	return i;
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
		odph_thread_start_args_t *start_args;

		start_args = &thread_tbl[i].start_args;

		/* Copy thread parameters */
		start_args->thr_params = *thr_params;
		start_args->instance   = thr_params->instance;

		if (helper_options.mem_model == ODP_MEM_MODEL_THREAD) {
			if (create_pthread(&thread_tbl[i], cpu))
				break;
		 } else {
			if (create_process(&thread_tbl[i], cpu))
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
		if (thread_tbl[i].cpu == FAILED_CPU) {
			ODPH_DBG("ODP thread %d not started.\n", i);
			continue;
		}
		/* pthreads: */
		if (thread_tbl[i].start_args.mem_model ==
				ODP_MEM_MODEL_THREAD) {
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
		} else {
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

int odph_parse_options(int argc, char *argv[])
{
	char *env;
	int i, j;

	helper_options.mem_model = ODP_MEM_MODEL_THREAD;

	/* Enable process mode using environment variable. Setting environment
	 * variable is easier for CI testing compared to command line
	 * argument. */
	env = getenv("ODPH_PROC_MODE");
	if (env && atoi(env))
		helper_options.mem_model = ODP_MEM_MODEL_PROCESS;

	/* Find and remove option */
	for (i = 0; i < argc;) {
		if (strcmp(argv[i], "--odph_proc") == 0) {
			helper_options.mem_model = ODP_MEM_MODEL_PROCESS;

			for (j = i; j < argc - 1; j++)
				argv[j] = argv[j + 1];

			argc--;
			continue;
		}

		i++;
	}

	return argc;
}

int odph_options(odph_helper_options_t *options)
{
	memset(options, 0, sizeof(odph_helper_options_t));

	options->mem_model = helper_options.mem_model;

	return 0;
}

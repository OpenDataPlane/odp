/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2024 Nokia
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
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <inttypes.h>

#include <odp_api.h>
#include <odp/helper/threads.h>
#include <odp/helper/odph_debug.h>

#define FAILED_CPU -1

/* Thread status codes */
#define NOT_STARTED 0
#define INIT_DONE   1
#define STARTED     2

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
	odph_thread_param_t *thr_params;
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

	if (start_args->init_status)
		odp_atomic_store_rel_u32(start_args->init_status, INIT_DONE);

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
static int create_process(odph_thread_t *thread, int cpu, uint64_t stack_size)
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

	if (stack_size) {
		struct rlimit rlimit;

		if (getrlimit(RLIMIT_STACK, &rlimit)) {
			ODPH_ERR("getrlimit() failed: %s\n", strerror(errno));
			return -3;
		}

		rlimit.rlim_cur = stack_size;

		if (setrlimit(RLIMIT_STACK, &rlimit)) {
			ODPH_ERR("setrlimit() failed: %s\n", strerror(errno));
			return -4;
		}
	}

	run_thread(&thread->start_args);

	return 0; /* never reached */
}

/*
 * Wait single process to exit
 */
static int wait_process(odph_thread_t *thread, odph_thread_join_result_t *res)
{
	pid_t pid;
	int status = 0, estatus;

	pid = waitpid(thread->proc.pid, &status, 0);

	if (pid < 0) {
		ODPH_ERR("waitpid() failed\n");
		return -1;
	}

	/* Examine the child process' termination status */
	if (WIFEXITED(status)) {
		estatus = WEXITSTATUS(status);

		if (res != NULL) {
			res->is_sig = false;
			res->ret = estatus;
		} else if (estatus != EXIT_SUCCESS) {
			ODPH_ERR("Child exit status:%d (pid:%d)\n", estatus, (int)pid);
			return -1;
		}
	} else {
		int signo = WTERMSIG(status);

		if (res != NULL) {
			res->is_sig = true;
			res->ret = signo;
		} else {
			ODPH_ERR("Child term signo:%d - %s (pid:%d)\n", signo, strsignal(signo),
				 (int)pid);
			return -1;
		}
	}

	return 0;
}

/*
 * Create a single linux pthread
 */
static int create_pthread(odph_thread_t *thread, int cpu, uint64_t stack_size)
{
	int ret;
	cpu_set_t cpu_set;

	CPU_ZERO(&cpu_set);
	CPU_SET(cpu, &cpu_set);

	pthread_attr_init(&thread->thread.attr);

	thread->cpu = cpu;

	pthread_attr_setaffinity_np(&thread->thread.attr,
				    sizeof(cpu_set_t), &cpu_set);

	if (stack_size) {
		/*
		 * Round up to page size. "On some systems,
		 * pthread_attr_setstacksize() can fail with the error EINVAL if
		 * stacksize is not a multiple of the system page size." (man
		 * page)
		 */
		stack_size = (stack_size + ODP_PAGE_SIZE - 1) & ~(ODP_PAGE_SIZE - 1);

		if (stack_size < (uint64_t)PTHREAD_STACK_MIN)
			stack_size = PTHREAD_STACK_MIN;

		if (pthread_attr_setstacksize(&thread->thread.attr, stack_size)) {
			ODPH_ERR("pthread_attr_setstacksize() failed\n");
			return -1;
		}
	}

	thread->start_args.mem_model = ODP_MEM_MODEL_THREAD;

	ret = pthread_create(&thread->thread.thread_id,
			     &thread->thread.attr,
			     run_thread,
			     &thread->start_args);
	if (ret != 0) {
		ODPH_ERR("Failed to start thread on CPU #%d: %d\n", cpu, ret);
		thread->cpu = FAILED_CPU;
		return ret;
	}

	return 0;
}

/*
 * Wait single pthread to exit
 */
static int wait_pthread(odph_thread_t *thread, odph_thread_join_result_t *res)
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

	if (res != NULL) {
		res->is_sig = false;
		res->ret = (int)(intptr_t)thread_ret;
	} else if (thread_ret) {
		ODPH_ERR("Bad exit status cpu #%i %p\n", thread->cpu, thread_ret);
		return -1;
	}

	ret = pthread_attr_destroy(&thread->thread.attr);

	if (ret) {
		ODPH_ERR("pthread_attr_destroy failed (%i) from cpu #%i\n",
			 ret, thread->cpu);

		if (res == NULL)
			return -1;
	}

	return 0;
}

void odph_thread_param_init(odph_thread_param_t *param)
{
	memset(param, 0, sizeof(*param));
}

void odph_thread_common_param_init(odph_thread_common_param_t *param)
{
	memset(param, 0, sizeof(*param));
	param->sync_timeout = ODP_TIME_SEC_IN_NS;
}

int odph_thread_create(odph_thread_t thread[],
		       const odph_thread_common_param_t *param,
		       const odph_thread_param_t thr_param[],
		       int num)
{
	int i, num_cpu, cpu;
	const odp_cpumask_t *cpumask = param->cpumask;
	int use_pthread = 1;
	odp_atomic_u32_t *init_status = NULL;

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

	if (param->sync) {
		init_status = mmap(NULL, sizeof(odp_atomic_u32_t), PROT_READ | PROT_WRITE,
				   MAP_SHARED | MAP_ANONYMOUS, -1, 0);

		if (init_status == MAP_FAILED) {
			ODPH_ERR("mmap() failed: %s\n", strerror(errno));
			return -1;
		}
	}

	cpu = odp_cpumask_first(cpumask);
	for (i = 0; i < num; i++) {
		odph_thread_start_args_t *start_args = &thread[i].start_args;

		/* Copy thread parameters */
		if (param->share_param)
			start_args->thr_params = thr_param[0];
		else
			start_args->thr_params = thr_param[i];

		start_args->instance   = param->instance;
		start_args->status = NOT_STARTED;
		start_args->init_status = init_status;
		if (init_status)
			odp_atomic_init_u32(init_status, NOT_STARTED);

		if (use_pthread) {
			if (create_pthread(&thread[i], cpu, start_args->thr_params.stack_size))
				break;
		} else {
			if (create_process(&thread[i], cpu, start_args->thr_params.stack_size))
				break;
		}

		/* Wait newly created thread to update status */
		if (init_status) {
			odp_time_t t1, t2;
			uint64_t diff_ns;
			uint32_t status;
			int timeout = 0;
			uint64_t timeout_ns = param->sync_timeout;

			if (!timeout_ns)
				timeout_ns = ODP_TIME_SEC_IN_NS;

			t1 = odp_time_local();

			do {
				odp_cpu_pause();
				t2 = odp_time_local();
				diff_ns = odp_time_diff_ns(t2, t1);
				timeout = diff_ns > timeout_ns;
				status = odp_atomic_load_acq_u32(init_status);

			} while (status != INIT_DONE && timeout == 0);

			if (timeout) {
				ODPH_ERR("Thread (i:%i) start up timeout: sync timeout %" PRIu64 ""
					 " , t1 %" PRIu64 ", t2 %" PRIu64 "\n", i,
					 param->sync_timeout, odp_time_to_ns(t1),
					 odp_time_to_ns(t2));
				break;
			}
		}

		start_args->status = STARTED;

		cpu = odp_cpumask_next(cpumask, cpu);
	}

	if (init_status) {
		if (munmap(init_status, sizeof(odp_atomic_u32_t)))
			ODPH_ERR("munmap() failed: %s\n", strerror(errno));
	}

	return i;
}

static int join_threads(odph_thread_t thread[], odph_thread_join_result_t res[], int num)
{
	odph_thread_start_args_t *start_args;
	int i;

	for (i = 0; i < num; i++) {
		start_args = &thread[i].start_args;

		if (start_args->status != STARTED) {
			ODPH_ERR("Thread (i:%i) not started.\n", i);
			break;
		}

		if (thread[i].start_args.mem_model == ODP_MEM_MODEL_THREAD) {
			if (wait_pthread(&thread[i], res != NULL ? &res[i] : NULL))
				break;
		} else {
			if (wait_process(&thread[i], res != NULL ? &res[i] : NULL))
				break;
		}

		start_args->status = NOT_STARTED;
	}

	return i;
}

int odph_thread_join(odph_thread_t thread[], int num)
{
	if (thread == NULL) {
		ODPH_ERR("Bad thread table pointer\n");
		return -1;
	}

	return join_threads(thread, NULL, num);
}

int odph_thread_join_result(odph_thread_t thread[], odph_thread_join_result_t res[], int num)
{
	if (thread == NULL) {
		ODPH_ERR("Bad thread table pointer\n");
		return -1;
	}

	if (res == NULL) {
		ODPH_ERR("Bad result table pointer\n");
		return -1;
	}

	return join_threads(thread, res, num);
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

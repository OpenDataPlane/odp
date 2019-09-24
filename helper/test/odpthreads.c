/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*
 * This program tests the ability of the linux helper to create ODP threads,
 * either implemented as linux pthreads or as linux processes, depending on
 * the option passed to the program (--odph_proc, --odph_thread or both)
 */

#include <unistd.h>
#include <stdlib.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define NUMBER_WORKERS 16

/* register odp_term_local/global() calls atexit() */
static void main_exit(void);

/* ODP application instance */
static odp_instance_t odp_instance;

static int worker_fn(void *arg ODP_UNUSED)
{
	int cpu;
	odp_cpumask_t workers;

	/* depend on the odp helper to call odp_init_local */

	printf("Worker thread on CPU %d\n", odp_cpu_id());

	/* verify CPU affinity was already set and among the
	 * allowed worker cpu
	 */
	odp_cpumask_zero(&workers);
	odp_cpumask_default_worker(&workers, NUMBER_WORKERS);

	cpu = odph_odpthread_getaffinity();
	if ((cpu < 0) || !odp_cpumask_isset(&workers, cpu)) {
		printf("Worker thread(%d)'s CPU "
		       "affinity was invalid.\n", odp_cpu_id());
		return -1;
	}

	/* verify helper API is workable by re-configure the same */
	if (odph_odpthread_setaffinity(cpu) != 0) {
		printf("Re-configure worker thread(%d)'s "
		       "CPU affinity failed.\n", odp_cpu_id());
		return -1;
	}

	/* depend on the odp helper to call odp_term_local */

	return 0;
}

/* Create additional dataplane opdthreads */
int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	odph_odpthread_params_t thr_params;
	odph_odpthread_t thread_tbl[NUMBER_WORKERS];
	odp_cpumask_t cpu_mask;
	odp_init_t init_param;
	int num_workers;
	int cpu, affinity;
	int ret;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (odp_init_global(&odp_instance, &init_param, NULL)) {
		ODPH_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(odp_instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* register termination callback */
	atexit(main_exit);

	odp_cpumask_zero(&cpu_mask);
	/* allocate the 1st available control cpu to main process */
	if (odp_cpumask_default_control(&cpu_mask, 1) != 1) {
		ODPH_ERR("Allocate main process CPU core failed.\n");
		exit(EXIT_FAILURE);
	}

	cpu = odp_cpumask_first(&cpu_mask);
	if (odph_odpthread_setaffinity(cpu) != 0) {
		ODPH_ERR("Set main process affinify to "
			"cpu(%d) failed.\n", cpu);
		exit(EXIT_FAILURE);
	}

	/* read back affinity to verify */
	affinity = odph_odpthread_getaffinity();
	if ((affinity < 0) || (cpu != affinity)) {
		ODPH_ERR("Verify main process affinity failed: "
			"set(%d) read(%d).\n", cpu, affinity);
		exit(EXIT_FAILURE);
	}
	cpu = 0;
	affinity = 0;
	odp_cpumask_zero(&cpu_mask);

	/* discover how many opdthreads this system can support */
	num_workers = odp_cpumask_default_worker(&cpu_mask, NUMBER_WORKERS);
	if (num_workers < NUMBER_WORKERS) {
		printf("System can only support %d threads and not the %d requested\n",
		       num_workers, NUMBER_WORKERS);
	}

	/* generate a summary for the user */
	(void)odp_cpumask_to_str(&cpu_mask, cpumaskstr, sizeof(cpumaskstr));
	printf("default cpu mask:           %s\n", cpumaskstr);
	printf("default num worker threads: %i\n", num_workers);

	cpu = odp_cpumask_first(&cpu_mask);
	printf("the first CPU:              %i\n", cpu);

	/* If possible, remove CPU 0 from the default mask to reserve it for the
	 * control plane. */
	if (num_workers > 1)
		odp_cpumask_clr(&cpu_mask, 0);
	num_workers = odp_cpumask_count(&cpu_mask);
	(void)odp_cpumask_to_str(&cpu_mask, cpumaskstr, sizeof(cpumaskstr));
	printf("new cpu mask:               %s\n", cpumaskstr);
	printf("new num worker threads:     %i\n\n", num_workers);

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.start    = worker_fn;
	thr_params.arg      = NULL;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = odp_instance;

	odph_odpthreads_create(&thread_tbl[0], &cpu_mask, &thr_params);

	ret = odph_odpthreads_join(thread_tbl);
	if (ret < 0)
		exit(EXIT_FAILURE);

	return 0;
}

static void main_exit(void)
{
	if (odp_term_local()) {
		ODPH_ERR("Error: ODP local term failed.\n");
		_exit(EXIT_FAILURE);
	}

	if (odp_term_global(odp_instance)) {
		ODPH_ERR("Error: ODP global term failed.\n");
		_exit(EXIT_FAILURE);
	}
}

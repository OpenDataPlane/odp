/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*
 * This program tests the ability of the linux helper to create ODP threads,
 * either implemented as linux pthreads or as linux processes, depending on
 * the option passed to the program (--odph_proc, --odph_thread or both)
 */

#include <test_debug.h>
#include <odp_api.h>
#include <odp/helper/linux.h>

#define NUMBER_WORKERS 16
static int worker_fn(void *arg TEST_UNUSED)
{
	/* depend on the odp helper to call odp_init_local */

	printf("Worker thread on CPU %d\n", odp_cpu_id());

	/* depend on the odp helper to call odp_term_local */

	return 0;
}

/* Create additional dataplane opdthreads */
int main(int argc, char *argv[])
{
	odp_instance_t instance;
	odph_odpthread_params_t thr_params;
	odph_odpthread_t thread_tbl[NUMBER_WORKERS];
	odp_cpumask_t cpu_mask;
	int num_workers;
	int cpu;
	int ret;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];

	/* let helper collect its own arguments (e.g. --odph_proc) */
	odph_parse_options(argc, argv, NULL, NULL);

	if (odp_init_global(&instance, NULL, NULL)) {
		LOG_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		LOG_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

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

	/* reserve cpu 0 for the control plane so remove it from
	 * the default mask */
	odp_cpumask_clr(&cpu_mask, 0);
	num_workers = odp_cpumask_count(&cpu_mask);
	(void)odp_cpumask_to_str(&cpu_mask, cpumaskstr, sizeof(cpumaskstr));
	printf("new cpu mask:               %s\n", cpumaskstr);
	printf("new num worker threads:     %i\n\n", num_workers);

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.start    = worker_fn;
	thr_params.arg      = NULL;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;

	odph_odpthreads_create(&thread_tbl[0], &cpu_mask, &thr_params);

	ret = odph_odpthreads_join(thread_tbl);
	if (ret < 0)
		exit(EXIT_FAILURE);

	if (odp_term_local()) {
		LOG_ERR("Error: ODP local term failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		LOG_ERR("Error: ODP global term failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* This is a minimal application which demonstrates the startup and shutdown
 * steps of an ODP application. It can be also used to debug API related
 * build problems, etc. It does not use helpers to minimize dependency to
 * anything else than the ODP API header file.
 */

/* Linux CPU affinity */
#define _GNU_SOURCE
#include <sched.h>

/* Linux PID */
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>

#include <odp_api.h>

typedef struct {
	int cpu;
	int num;
} options_t;

static int parse_args(int argc, char *argv[], options_t *opt)
{
	static const char * const args[] = {"-c", "-n"};
	int i, tmp;

	for (i = 1; i < argc; i++) {
		if ((strcmp(argv[i], args[0]) == 0) &&
		    (sscanf(argv[i + 1], "%i", &tmp) == 1)) {
			opt->cpu = tmp;
			i++;
		} else if ((strcmp(argv[i], args[1]) == 0) &&
			   (sscanf(argv[i + 1], "%i", &tmp) == 1)) {
			opt->num = tmp;
			i++;
		} else {
			printf("\nUsage:\n"
			       "  %s  CPU number\n"
			       "  %s  Number of iterations\n\n",
			       args[0], args[1]);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char mask_str[ODP_CPUMASK_STR_SIZE];
	odp_instance_t inst;
	options_t opt;
	pid_t pid;
	cpu_set_t cpu_set;
	int i, cpu;
	odp_cpumask_t mask;

	memset(&opt, 0, sizeof(opt));
	opt.cpu = 1;
	opt.num = 1;

	if (parse_args(argc, argv, &opt))
		return -1;

	pid = getpid();

	if (odp_init_global(&inst, NULL, NULL)) {
		printf("Global init failed.\n");
		return -1;
	}

	odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);
	while (cpu >= 0) {
		if (cpu == opt.cpu)
			break;
		cpu = odp_cpumask_next(&mask, cpu);
	}
	if (cpu != opt.cpu) {
		if (odp_cpumask_to_str(&mask, mask_str, sizeof(mask_str)) < 0)
			mask_str[0] = '\0';
		printf("Requested CPU %d is not part of available mask[%s]\n",
		       opt.cpu, mask_str);
		return -1;
	}

	CPU_ZERO(&cpu_set);
	CPU_SET(opt.cpu, &cpu_set);

	if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpu_set)) {
		printf("Set CPU affinity failed.\n");
		return -1;
	}

	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		printf("Local init failed.\n");
		return -1;
	}

	for (i = 0; i < opt.num; i++) {
		printf("Hello world from CPU %i!\n", odp_cpu_id());
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS);
	}

	if (odp_term_local()) {
		printf("Local term failed.\n");
		return -1;
	}

	if (odp_term_global(inst)) {
		printf("Global term failed.\n");
		return -1;
	}

	return 0;
}

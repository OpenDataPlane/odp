/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @example odp_hello.c
 *
 * This is a minimal application which demonstrates the startup and shutdown
 * steps of an ODP application. It can be also used to debug API related
 * build problems, etc. It does not use helpers to minimize dependency to
 * anything else than the ODP API header file.
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <stdio.h>
#include <string.h>

#include <odp_api.h>

typedef struct {
	int num;
} options_t;

static int parse_args(int argc, char *argv[], options_t *opt)
{
	static const char * const args[] = {"-n"};
	int i, tmp;

	for (i = 1; i < argc; i++) {
		if ((strcmp(argv[i], args[0]) == 0) && argv[i + 1] &&
		    (sscanf(argv[i + 1], "%i", &tmp) == 1)) {
			opt->num = tmp;
			i++;
		} else {
			printf("\nUsage:\n"
			       "  [%s  Number of iterations]\n\n",
			       args[0]);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	odp_instance_t inst;
	options_t opt;
	int i;

	memset(&opt, 0, sizeof(opt));
	opt.num = 1;

	if (parse_args(argc, argv, &opt))
		return -1;

	if (odp_init_global(&inst, NULL, NULL)) {
		printf("Global init failed.\n");
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

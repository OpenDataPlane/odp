/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP test application common
 */

#include <string.h>
#include <stdio.h>
#include <odp.h>
#include <odp_linux.h>
#include "odp_common.h"
#include "odp_atomic_test.h"
#include "odp_shm_test.h"

/* Globals */
odp_linux_pthread_t thread_tbl[MAX_WORKERS];
int num_workers;
__thread test_shared_data_t *test_shared_data;

void odp_print_system_info(void)
{
	odp_coremask_t coremask;
	char str[32];

	memset(str, 1, sizeof(str));

	odp_coremask_zero(&coremask);

	odp_coremask_from_str("0x1", &coremask);
	odp_coremask_to_str(str, sizeof(str), &coremask);

	printf("\n");
	printf("ODP system info\n");
	printf("---------------\n");
	printf("ODP API version: %s\n",        odp_version_api_str());
	printf("CPU model:       %s\n",        odp_sys_cpu_model_str());
	printf("CPU freq (hz):   %"PRIu64"\n", odp_sys_cpu_hz());
	printf("Cache line size: %i\n",        odp_sys_cache_line_size());
	printf("Core count:      %i\n",        odp_sys_core_count());
	printf("Core mask:       %s\n",        str);

	printf("\n");
}

int odp_test_global_init(void)
{
	memset(thread_tbl, 0, sizeof(thread_tbl));

	if (odp_init_global()) {
		printf("ODP global init failed.\n");
		return -1;
	}

	num_workers = odp_sys_core_count();
	/* force to max core count */
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	return 0;
}

int odp_test_thread_create(void *func_ptr(void *), pthrd_arg *arg)
{
	/* Create and init additional threads */
	odp_linux_pthread_create(thread_tbl, num_workers, 0, func_ptr,
				 (void *)arg);

	return 0;
}

int odp_test_thread_exit(void)
{
	/* Wait for other threads to exit */
	odp_linux_pthread_join(thread_tbl, num_workers);

	return 0;
}

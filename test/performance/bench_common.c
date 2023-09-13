/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "bench_common.h"

#include <stdint.h>

void bench_run_indef(bench_info_t *info, odp_atomic_u32_t *exit_thread)
{
	const char *desc;

	desc = info->desc != NULL ? info->desc : info->name;

	printf("Running odp_%s test indefinitely\n", desc);

	while (!odp_atomic_load_u32(exit_thread)) {
		int ret;

		if (info->init != NULL)
			info->init();

		ret = info->run();

		if (info->term != NULL)
			info->term();

		if (!ret)
			ODPH_ABORT("Benchmark %s failed\n", desc);
	}
}

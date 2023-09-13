/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "bench_common.h"

#include <inttypes.h>
#include <stdint.h>
#include <string.h>

void bench_suite_init(bench_suite_t *suite)
{
	memset(suite, 0, sizeof(bench_suite_t));

	suite->measure_time = true;

	odp_atomic_init_u32(&suite->exit_worker, 0);
}

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

int bench_run(void *arg)
{
	uint64_t c1, c2;
	odp_time_t t1, t2;
	bench_suite_t *suite = arg;
	const uint64_t repeat_count = suite->repeat_count;
	const odp_bool_t meas_time = suite->measure_time;

	printf("\nAverage %s per function call\n", meas_time ? "time (nsec)" : "CPU cycles");
	printf("-------------------------------------------------\n");

	/* Run each test twice. Results from the first warm-up round are ignored. */
	for (int i = 0; i < 2; i++) {
		uint64_t total = 0;
		uint64_t round = 1;

		for (int j = 0; j < suite->num_bench; round++) {
			int ret;
			const char *desc;
			const bench_info_t *bench = &suite->bench[j];
			uint64_t max_rounds = suite->rounds;

			if (bench->max_rounds &&  bench->max_rounds < max_rounds)
				max_rounds = bench->max_rounds;

			/* Run selected test indefinitely */
			if (suite->indef_idx) {
				if ((j + 1) != suite->indef_idx) {
					j++;
					continue;
				}
				bench_run_indef(&suite->bench[j], &suite->exit_worker);
				return 0;
			}

			desc = bench->desc != NULL ? bench->desc : bench->name;

			if (bench->init != NULL)
				bench->init();

			if (meas_time)
				t1 = odp_time_local_strict();
			else
				c1 = odp_cpu_cycles();

			ret = bench->run();

			if (meas_time)
				t2 = odp_time_local_strict();
			else
				c2 = odp_cpu_cycles();

			if (bench->term != NULL)
				bench->term();

			if (!ret) {
				ODPH_ERR("Benchmark odp_%s failed\n", desc);
				suite->retval = -1;
				return -1;
			}

			if (meas_time)
				total += odp_time_diff_ns(t2, t1);
			else
				total += odp_cpu_cycles_diff(c2, c1);

			if (round >= max_rounds) {
				double result;

				/* Each benchmark runs internally 'repeat_count' times. */
				result = ((double)total) / (max_rounds * repeat_count);

				/* No print or results from warm-up round */
				if (i > 0) {
					printf("[%02d] odp_%-26s: %12.2f\n", j + 1, desc, result);

					if (suite->result)
						suite->result[j] = result;
				}
				j++;
				total = 0;
				round = 1;
			}
		}
	}
	printf("\n");
	/* Print dummy result to prevent compiler to optimize it away*/
	if (suite->dummy)
		printf("(dummy result: 0x%" PRIx64 ")\n\n", suite->dummy);

	return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

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
	double result;

	printf("\nAverage %s per function call\n", meas_time ? "time (nsec)" : "CPU cycles");
	printf("-------------------------------------------------\n");

	for (int j = 0; j < suite->num_bench; j++) {
		int ret;
		const char *desc;
		const bench_info_t *bench = &suite->bench[j];
		uint64_t max_rounds = suite->rounds;
		uint64_t total = 0;

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

		/* The zeroeth round is a warmup round that will be ignored */
		for (uint64_t round = 0; round <= max_rounds; round++)  {
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

			if (odp_unlikely(round == 0))
				continue;
			if (meas_time)
				total += odp_time_diff_ns(t2, t1);
			else
				total += odp_cpu_cycles_diff(c2, c1);
		}

		/* Each benchmark runs internally 'repeat_count' times. */
		result = ((double)total) / (max_rounds * repeat_count);

		printf("[%02d] odp_%-26s: %12.2f\n", j + 1, desc, result);
		if (suite->result)
			suite->result[j] = result;
	}
	printf("\n");
	/* Print dummy result to prevent compiler to optimize it away*/
	if (suite->dummy)
		printf("(dummy result: 0x%" PRIx64 ")\n\n", suite->dummy);

	return 0;
}

void bench_tm_suite_init(bench_tm_suite_t *suite)
{
	memset(suite, 0, sizeof(bench_tm_suite_t));

	odp_atomic_init_u32(&suite->exit_worker, 0);
}

uint8_t bench_tm_func_register(bench_tm_result_t *res, const char *func_name)
{
	uint8_t num_func = res->num;

	if (num_func >= BENCH_TM_MAX_FUNC)
		ODPH_ABORT("Too many test functions (max %d)\n", BENCH_TM_MAX_FUNC);

	res->func[num_func].name = func_name;
	res->num++;

	return num_func;
}

void bench_tm_func_record(odp_time_t t2, odp_time_t t1, bench_tm_result_t *res, uint8_t id)
{
	odp_time_t diff = odp_time_diff(t2, t1);

	ODPH_ASSERT(id < BENCH_TM_MAX_FUNC);

	res->func[id].tot = odp_time_sum(res->func[id].tot, diff);

	if (odp_time_cmp(diff, res->func[id].min) < 0)
		res->func[id].min = diff;

	if (odp_time_cmp(diff, res->func[id].max) > 0)
		res->func[id].max = diff;

	res->func[id].num++;
}

static void init_result(bench_tm_result_t *res)
{
	memset(res, 0, sizeof(bench_tm_result_t));

	for (int i = 0; i < BENCH_TM_MAX_FUNC; i++) {
		res->func[i].tot = ODP_TIME_NULL;
		res->func[i].min = odp_time_local_from_ns(ODP_TIME_HOUR_IN_NS);
		res->func[i].max = ODP_TIME_NULL;
	}
}

static void print_results(bench_tm_result_t *res)
{
	for (uint8_t i = 0; i < res->num; i++) {
		uint64_t num = res->func[i].num ? res->func[i].num : 1;

		printf("     %-38s    %-12" PRIu64 " %-12" PRIu64 " %-12" PRIu64 "\n",
		       res->func[i].name,
		       odp_time_to_ns(res->func[i].min),
		       odp_time_to_ns(res->func[i].tot) / num,
		       odp_time_to_ns(res->func[i].max));
	}
}

int bench_tm_run(void *arg)
{
	bench_tm_suite_t *suite = arg;

	printf("\nLatency (nsec) per function call               min          avg          max\n");
	printf("------------------------------------------------------------------------------\n");

	for (uint32_t j = 0; j < suite->num_bench; j++) {
		const bench_tm_info_t *bench = &suite->bench[j];
		uint64_t rounds = suite->rounds;
		bench_tm_result_t res;

		/* Run only selected test case */
		if (suite->bench_idx && (j + 1) != suite->bench_idx)
			continue;

		if (bench->cond != NULL && !bench->cond()) {
			printf("[%02d] %-41s n/a          n/a          n/a\n",
			       j + 1, bench->name);
			continue;
		}

		if (bench->max_rounds && bench->max_rounds < rounds)
			rounds = bench->max_rounds;

		/*
		 * Run each test twice.
		 * Results from the first warm-up round are ignored.
		 */
		for (uint32_t i = 0; i < 2; i++) {
			if (odp_atomic_load_u32(&suite->exit_worker))
				return 0;

			init_result(&res);

			if (bench->init != NULL)
				bench->init();

			if (bench->run(&res, rounds)) {
				ODPH_ERR("Benchmark %s failed\n", bench->name);
				suite->retval = -1;
				return -1;
			}

			if (bench->term != NULL)
				bench->term();

		}
		printf("[%02d] %-26s\n", j + 1, bench->name);
		print_results(&res);

		if (suite->result)
			suite->result[j] = res;
	}
	printf("\n");

	return 0;
}

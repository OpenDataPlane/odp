/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 Nokia
 * Copyright (c) 2015-2018 Linaro Limited
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "odp_cunit_common.h"
#include "test_common_macros.h"

#define PERIODS_100_MSEC  160
#define RES_TRY_NUM       10
#define GIGA_HZ           1000000000ULL
#define KILO_HZ           1000ULL

/* 10 usec wait time assumes >100kHz resolution on CPU cycles counter */
#define WAIT_TIME (10 * ODP_TIME_USEC_IN_NS)

/* Data for cache prefetch test cases */
static uint8_t global_data[8 * ODP_CACHE_LINE_SIZE] ODP_ALIGNED_CACHE;

static int check_cycle_counter(void)
{
	if (odp_cpu_cycles_max() == 0) {
		printf("Cycle counter is not supported, skipping test\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

static int check_cpu_hz(void)
{
	if (odp_cpu_hz() == 0) {
		printf("odp_cpu_hz() is not supported, skipping test\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

static int check_cpu_hz_max(void)
{
	if (odp_cpu_hz_max() == 0) {
		printf("odp_cpu_hz_max() is not supported, skipping test\n");
		return ODP_TEST_INACTIVE;
	}
	return ODP_TEST_ACTIVE;
}

static int check_cpu_hz_id(void)
{
	uint64_t hz;
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		hz = odp_cpu_hz_id(cpu);
		if (hz == 0) {
			printf("odp_cpu_hz_id() is not supported by CPU %d, skipping test\n", cpu);
			return ODP_TEST_INACTIVE;
		}
		cpu = odp_cpumask_next(&mask, cpu);
	}

	return ODP_TEST_ACTIVE;
}

static int check_cpu_hz_max_id(void)
{
	uint64_t hz;
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		hz = odp_cpu_hz_max_id(cpu);
		if (hz == 0) {
			printf("odp_cpu_hz_max_id() is not supported by CPU %d, skipping test\n",
			       cpu);
			return ODP_TEST_INACTIVE;
		}
		cpu = odp_cpumask_next(&mask, cpu);
	}

	return ODP_TEST_ACTIVE;
}

static void cpu_id(void)
{
	CU_ASSERT(odp_cpu_id() >= 0);
}

static void cpu_count(void)
{
	int cpus;

	cpus = odp_cpu_count();
	CU_ASSERT(0 < cpus);
}

static void cpu_model_str(void)
{
	char model[128];

	snprintf(model, 128, "%s", odp_cpu_model_str());
	CU_ASSERT(strlen(model) > 0);
	CU_ASSERT(strlen(model) < 127);
}

static void cpu_model_str_id(void)
{
	char model[128];
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		snprintf(model, 128, "%s", odp_cpu_model_str_id(cpu));
		CU_ASSERT(strlen(model) > 0);
		CU_ASSERT(strlen(model) < 127);
		cpu = odp_cpumask_next(&mask, cpu);
	}
}

static void cpu_hz(void)
{
	uint64_t hz = odp_cpu_hz();

	/* Test value sanity: less than 10GHz */
	CU_ASSERT(hz < 10 * GIGA_HZ);

	/* larger than 1kHz */
	CU_ASSERT(hz > 1 * KILO_HZ);
}

static void cpu_hz_id(void)
{
	uint64_t hz;
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		hz = odp_cpu_hz_id(cpu);
		/* Test value sanity: less than 10GHz */
		CU_ASSERT(hz < 10 * GIGA_HZ);
		/* larger than 1kHz */
		CU_ASSERT(hz > 1 * KILO_HZ);
		cpu = odp_cpumask_next(&mask, cpu);
	}
}

static void cpu_hz_max(void)
{
	uint64_t hz = odp_cpu_hz_max();

	/* Sanity check value */
	CU_ASSERT(hz > 1 * KILO_HZ);
	CU_ASSERT(hz < 20 * GIGA_HZ);
}

static void cpu_hz_max_id(void)
{
	uint64_t hz;
	odp_cpumask_t mask;
	int i, num, cpu;

	num = odp_cpumask_all_available(&mask);
	cpu = odp_cpumask_first(&mask);

	for (i = 0; i < num; i++) {
		hz = odp_cpu_hz_max_id(cpu);
		/* Sanity check value */
		CU_ASSERT(hz > 1 * KILO_HZ);
		CU_ASSERT(hz < 20 * GIGA_HZ);
		cpu = odp_cpumask_next(&mask, cpu);
	}
}

static void cpu_cycles(void)
{
	uint64_t c2, c1, diff, max;

	c1 = odp_cpu_cycles();
	odp_time_wait_ns(WAIT_TIME);
	c2 = odp_cpu_cycles();

	CU_ASSERT(c2 != c1);

	max = odp_cpu_cycles_max();

	/* With 10 usec delay, diff should be small compared to the maximum.
	 * Otherwise, counter is going backwards. */
	if (c2 > c1) {
		diff = c2 - c1;
		CU_ASSERT(diff < (max - diff));
	}

	/* Same applies also when there was a wrap. */
	if (c2 < c1) {
		diff = max - c1 + c2;
		CU_ASSERT(diff < (max - diff));
	}
}

static void cpu_cycles_strict(void)
{
	uint64_t c2, c1, diff, max;

	c1 = odp_cpu_cycles_strict();
	odp_time_wait_ns(WAIT_TIME);
	c2 = odp_cpu_cycles_strict();

	CU_ASSERT(c2 != c1);

	max = odp_cpu_cycles_max();

	/* With 10 usec delay, diff should be small compared to the maximum.
	 * Otherwise, counter is going backwards. */
	if (c2 > c1) {
		diff = c2 - c1;
		CU_ASSERT(diff < (max - diff));
	}

	/* Same applies also when there was a wrap. */
	if (c2 < c1) {
		diff = max - c1 + c2;
		CU_ASSERT(diff < (max - diff));
	}
}

static void cpu_cycles_diff(void)
{
	uint64_t c2, c1, max;
	uint64_t tmp, diff, res;

	res = odp_cpu_cycles_resolution();
	max = odp_cpu_cycles_max();

	c1 = res;
	c2 = 2 * res;
	diff = odp_cpu_cycles_diff(c2, c1);
	CU_ASSERT(diff == res);

	c1 = odp_cpu_cycles();
	odp_time_wait_ns(WAIT_TIME);
	c2 = odp_cpu_cycles();
	diff = odp_cpu_cycles_diff(c2, c1);
	CU_ASSERT(diff > 0);
	CU_ASSERT(diff < (max - diff));

	/* check resolution for wrap */
	c1 = max - 2 * res;
	do
		c2 = odp_cpu_cycles();
	while (c1 < c2);

	diff = odp_cpu_cycles_diff(c1, c1);
	CU_ASSERT(diff == 0);

	/* wrap */
	tmp = c2 + (max - c1) + res;
	diff = odp_cpu_cycles_diff(c2, c1);
	CU_ASSERT(diff == tmp);

	/* no wrap, revert args */
	tmp = c1 - c2;
	diff = odp_cpu_cycles_diff(c1, c2);
	CU_ASSERT(diff == tmp);
}

static void cpu_cycles_max(void)
{
	uint64_t c2, c1;
	uint64_t max1, max2;

	max1 = odp_cpu_cycles_max();
	odp_time_wait_ns(WAIT_TIME);
	max2 = odp_cpu_cycles_max();

	CU_ASSERT(max1 >= UINT32_MAX / 2);
	CU_ASSERT(max1 == max2);

	c1 = odp_cpu_cycles();
	odp_time_wait_ns(WAIT_TIME);
	c2 = odp_cpu_cycles();

	CU_ASSERT(c1 <= max1 && c2 <= max1);
}

static void cpu_cycles_resolution(void)
{
	int i;
	uint64_t res;
	uint64_t c2, c1, max;
	uint64_t test_cycles = odp_cpu_hz() / 100; /* CPU cycles in 10 msec */

	max = odp_cpu_cycles_max();

	res = odp_cpu_cycles_resolution();
	CU_ASSERT(res != 0);
	CU_ASSERT(res < max / 1024);

	for (i = 0; i < RES_TRY_NUM; i++) {
		c1 = odp_cpu_cycles();
		odp_time_wait_ns(10 * ODP_TIME_MSEC_IN_NS + i);
		c2 = odp_cpu_cycles();

		/* Diff may be zero with low resolution */
		if (test_cycles && test_cycles > res) {
			uint64_t diff = odp_cpu_cycles_diff(c2, c1);

			CU_ASSERT(diff >= res);
		}
	}
}

static void cpu_cycles_long_period(void)
{
	int i;
	int periods = PERIODS_100_MSEC;
	uint64_t max_period_duration = 100 * ODP_TIME_MSEC_IN_NS + periods - 1;
	uint64_t c2, c1, c3, max;
	uint64_t tmp, diff, res;

	res = odp_cpu_cycles_resolution();
	max = odp_cpu_cycles_max();

	c3 = odp_cpu_cycles();

	CU_ASSERT(c3 <= max);
	/*
	 * If the cycle counter is not close to wrapping around during
	 * the test, then speed up the test by not trying to see the wrap
	 * around too hard. Assume cycle counter frequency of less than 10 GHz.
	 */
	CU_ASSERT(odp_cpu_hz_max() < 10ULL * ODP_TIME_SEC_IN_NS);
	if (max - c3 > 10 * periods * max_period_duration)
		periods = 10;

	printf("\n        Testing CPU cycles for %i seconds... ", periods / 10);

	for (i = 0; i < periods; i++) {
		c1 = odp_cpu_cycles();
		odp_time_wait_ns(100 * ODP_TIME_MSEC_IN_NS + i);
		c2 = odp_cpu_cycles();

		CU_ASSERT(c2 != c1);
		CU_ASSERT(c1 <= max && c2 <= max);

		if (c2 > c1)
			tmp = c2 - c1;
		else
			tmp = c2 + (max - c1) + res;

		diff = odp_cpu_cycles_diff(c2, c1);
		CU_ASSERT(diff == tmp);

		/* wrap is detected and verified */
		if (c2 < c1)
			break;
	}

	/* wrap was detected, no need to continue */
	if (i < periods) {
		printf("wrap was detected.\n");
		return;
	}

	/* wrap has to be detected if possible */
	CU_ASSERT(max > UINT32_MAX);
	CU_ASSERT((max - c3) > UINT32_MAX);

	printf("wrap was not detected.\n");
}

static void cpu_pause(void)
{
	odp_cpu_pause();
}

static void cpu_prefetch(void)
{
	/* Cacheline aligned address */
	odp_prefetch(&global_data[0]);

	/* Not cacheline aligned address */
	odp_prefetch(&global_data[ODP_CACHE_LINE_SIZE + 11]);

	/* An invalid address */
	odp_prefetch(NULL);

	odp_prefetch_l1(&global_data[0]);
	odp_prefetch_l1(&global_data[ODP_CACHE_LINE_SIZE + 11]);
	odp_prefetch_l1(NULL);

	odp_prefetch_l2(&global_data[0]);
	odp_prefetch_l2(&global_data[ODP_CACHE_LINE_SIZE + 11]);
	odp_prefetch_l2(NULL);

	odp_prefetch_l3(&global_data[0]);
	odp_prefetch_l3(&global_data[ODP_CACHE_LINE_SIZE + 11]);
	odp_prefetch_l3(NULL);
}

static void cpu_prefetch_store(void)
{
	odp_prefetch_store(&global_data[0]);
	odp_prefetch_store(&global_data[ODP_CACHE_LINE_SIZE + 11]);
	odp_prefetch_store(NULL);

	odp_prefetch_store_l1(&global_data[0]);
	odp_prefetch_store_l1(&global_data[ODP_CACHE_LINE_SIZE + 11]);
	odp_prefetch_store_l1(NULL);

	odp_prefetch_store_l2(&global_data[0]);
	odp_prefetch_store_l2(&global_data[ODP_CACHE_LINE_SIZE + 11]);
	odp_prefetch_store_l2(NULL);

	odp_prefetch_store_l3(&global_data[0]);
	odp_prefetch_store_l3(&global_data[ODP_CACHE_LINE_SIZE + 11]);
	odp_prefetch_store_l3(NULL);
}

static void cpu_prefetch_strm(void)
{
	odp_prefetch_strm_l1(&global_data[0]);
	odp_prefetch_strm_l1(&global_data[ODP_CACHE_LINE_SIZE + 11]);
	odp_prefetch_strm_l1(NULL);

	odp_prefetch_store_strm_l1(&global_data[0]);
	odp_prefetch_store_strm_l1(&global_data[ODP_CACHE_LINE_SIZE + 11]);
	odp_prefetch_store_strm_l1(NULL);
}

static void cpu_prefetch_instr(void)
{
	/* Prefetch a function that is likely not inlined. Extra casts avoid -pedantic
	 * warning about passing function pointer as ‘void *' argument */
	const void *addr = (void *)(uintptr_t)odp_init_global;

	printf("\n        Prefetching odp_init_global: %p\n", addr);
	odp_prefetch_l1i(addr);
	odp_prefetch_l1i(NULL);
}

odp_testinfo_t cpu_suite[] = {
	ODP_TEST_INFO(cpu_id),
	ODP_TEST_INFO(cpu_count),
	ODP_TEST_INFO(cpu_model_str),
	ODP_TEST_INFO(cpu_model_str_id),
	ODP_TEST_INFO_CONDITIONAL(cpu_hz, check_cpu_hz),
	ODP_TEST_INFO_CONDITIONAL(cpu_hz_id, check_cpu_hz_id),
	ODP_TEST_INFO_CONDITIONAL(cpu_hz_max, check_cpu_hz_max),
	ODP_TEST_INFO_CONDITIONAL(cpu_hz_max_id, check_cpu_hz_max_id),
	ODP_TEST_INFO_CONDITIONAL(cpu_cycles, check_cycle_counter),
	ODP_TEST_INFO_CONDITIONAL(cpu_cycles_strict, check_cycle_counter),
	ODP_TEST_INFO_CONDITIONAL(cpu_cycles_diff, check_cycle_counter),
	ODP_TEST_INFO_CONDITIONAL(cpu_cycles_max, check_cycle_counter),
	ODP_TEST_INFO_CONDITIONAL(cpu_cycles_resolution, check_cycle_counter),
	ODP_TEST_INFO_CONDITIONAL(cpu_cycles_long_period, check_cycle_counter),
	ODP_TEST_INFO(cpu_pause),
	ODP_TEST_INFO(cpu_prefetch),
	ODP_TEST_INFO(cpu_prefetch_store),
	ODP_TEST_INFO(cpu_prefetch_strm),
	ODP_TEST_INFO(cpu_prefetch_instr),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t cpu_suites[] = {
	{"CPU", NULL, NULL, cpu_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(cpu_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

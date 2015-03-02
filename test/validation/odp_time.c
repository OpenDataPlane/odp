/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <odp.h>
#include "odp_cunit_common.h"

#define TOLERANCE 1
#define BUSY_LOOP_CNT 100

/* check that a cycles difference gives a reasonable result */
static void test_odp_cycles_diff(void)
{
	/* volatile to stop optimization of busy loop */
	volatile int count = 0;
	uint64_t diff, cycles1, cycles2;

	cycles1 = odp_time_cycles();

	while (count < BUSY_LOOP_CNT) {
		count++;
	};

	cycles2 = odp_time_cycles();
	CU_ASSERT(cycles2 > cycles1);

	diff = odp_time_diff_cycles(cycles1, cycles2);
	CU_ASSERT(diff > 0);
}

/* check that a negative cycles difference gives a reasonable result */
static void test_odp_cycles_negative_diff(void)
{
	uint64_t diff, cycles1, cycles2;
	cycles1 = 10;
	cycles2 = 5;
	diff = odp_time_diff_cycles(cycles1, cycles2);
	CU_ASSERT(diff > 0);
}

/* check that related conversions come back to the same value */
static void test_odp_time_conversion(void)
{
	uint64_t ns1, ns2, cycles;
	uint64_t upper_limit, lower_limit;
	ns1 = 100;
	cycles = odp_time_ns_to_cycles(ns1);
	CU_ASSERT(cycles > 0);

	ns2 = odp_time_cycles_to_ns(cycles);

	/* need to check within arithmetic tolerance that the same
	 * value in ns is returned after conversions */
	upper_limit = ns1 + TOLERANCE;
	lower_limit = ns1 - TOLERANCE;
	CU_ASSERT((ns2 <= upper_limit) && (ns2 >= lower_limit));
}

CU_TestInfo test_odp_time[] = {
	{"cycles diff", test_odp_cycles_diff},
	{"negative diff", test_odp_cycles_negative_diff},
	{"conversion", test_odp_time_conversion},
	 CU_TEST_INFO_NULL
};

CU_SuiteInfo odp_testsuites[] = {
		{"Time", NULL, NULL, NULL, NULL, test_odp_time},
		 CU_SUITE_INFO_NULL
};

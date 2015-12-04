/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <odp.h>
#include "odp_cunit_common.h"
#include "time.h"

#define TOLERANCE 1
#define BUSY_LOOP_CNT 100

/* check that a time difference gives a reasonable result */
void time_test_odp_diff(void)
{
	/* volatile to stop optimization of busy loop */
	volatile int count = 0;
	odp_time_t diff, t1, t2;

	t1 = odp_time_local();

	while (count < BUSY_LOOP_CNT) {
		count++;
	};

	t2 = odp_time_local();
	CU_ASSERT(odp_time_cmp(t2, t1) > 0);

	diff = odp_time_diff(t2, t1);
	CU_ASSERT(odp_time_cmp(diff, ODP_TIME_NULL) > 0);
}

/* check that a negative time difference gives a reasonable result */
void time_test_odp_negative_diff(void)
{
	odp_time_t diff, t1, t2;

	t1 = odp_time_local_from_ns(10);
	t2 = odp_time_local_from_ns(5);
	diff = odp_time_diff(t2, t1);
	CU_ASSERT(odp_time_cmp(diff, ODP_TIME_NULL) > 0);
}

/* check that related conversions come back to the same value */
void time_test_odp_conversion(void)
{
	uint64_t ns1, ns2;
	odp_time_t time;
	uint64_t upper_limit, lower_limit;

	ns1 = 100;
	time = odp_time_local_from_ns(ns1);
	CU_ASSERT(odp_time_cmp(time, ODP_TIME_NULL) > 0);

	ns2 = odp_time_to_ns(time);

	/* need to check within arithmetic tolerance that the same
	 * value in ns is returned after conversions */
	upper_limit = ns1 + TOLERANCE;
	lower_limit = ns1 - TOLERANCE;
	CU_ASSERT((ns2 <= upper_limit) && (ns2 >= lower_limit));
}

odp_testinfo_t time_suite_time[] = {
	ODP_TEST_INFO(time_test_odp_diff),
	ODP_TEST_INFO(time_test_odp_negative_diff),
	ODP_TEST_INFO(time_test_odp_conversion),
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t time_suites[] = {
		{"Time", NULL, NULL, time_suite_time},
		ODP_SUITE_INFO_NULL
};

int time_main(void)
{
	int ret = odp_cunit_register(time_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

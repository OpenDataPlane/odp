/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2024 Nokia
 */

#include <odp_posix_extensions.h>

#include <odp/api/hints.h>
#include <odp/api/time_types.h>

#include <odp/api/abi/time_cpu.h>

#include <odp_debug_internal.h>

#include <time.h>
#include <errno.h>
#include <string.h>

static int nwait(uint64_t nsec)
{
	struct timespec ts1, ts2;
	uint64_t diff;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts1))
		return 1;

	do {
		if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts2))
			return 1;

		diff = (ts2.tv_sec - ts1.tv_sec) * ODP_TIME_SEC_IN_NS +
			ts2.tv_nsec - ts1.tv_nsec;
	} while (diff < nsec);

	return 0;
}

static void sort(uint64_t values[], int num)
{
	for (int n = 0; n < num; n++) {
		for (int i = n + 1; i < num; i++) {
			if (values[i] < values[n]) {
				uint64_t tmp = values[i];

				values[i] = values[n];
				values[n] = tmp;
			}
		}
	}
}

static uint64_t median(uint64_t values[], int num)
{
	sort(values, num);
	if (num % 2 == 0)
		return (values[num / 2 - 1] + values[num / 2]) / 2;
	else
		return values[num / 2];
}

/* Measure TSC frequency. */
uint64_t _odp_time_cpu_global_freq(void)
{
	struct timespec ts1, ts2;
	uint64_t t1, t2, ts_nsec, cycles;
	int i;
	const int rounds = 6; /* first round is warmup */
	int warm_up = 1;
	uint64_t hz[rounds];

	for (i = 0; i < rounds; i++) {
		uint64_t wait_nsec = ODP_TIME_SEC_IN_NS / 50;

		if (warm_up)
			wait_nsec = ODP_TIME_SEC_IN_NS / 1000;

		if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts1))
			goto err_out;

		t1 = _odp_time_cpu_global();

		if (nwait(wait_nsec))
			goto err_out;

		if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts2))
			goto err_out;

		t2 = _odp_time_cpu_global();

		ts_nsec  = (ts2.tv_sec - ts1.tv_sec) * ODP_TIME_SEC_IN_NS;
		ts_nsec += ts2.tv_nsec - ts1.tv_nsec;

		cycles = t2 - t1;

		hz[i] = (cycles * ODP_TIME_SEC_IN_NS) / ts_nsec;

		if (warm_up)
			warm_up = 0;
	}

	return median(&hz[1], rounds - 1);

err_out:
	_ODP_ERR("clock_gettime() failed (%s)\n", strerror(errno));
	return 0;
}

/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <time.h>

#include <odp/api/hints.h>
#include <odp_debug_internal.h>
#include <odp/api/abi/cpu_time.h>

#define SEC_IN_NS 1000000000ULL

/* Measure TSC frequency. Frequency information registers are defined for x86,
 * but those are often not enumerated. */
uint64_t _odp_cpu_global_time_freq(void)
{
	struct timespec sleep, ts1, ts2;
	uint64_t t1, t2, ts_nsec, cycles, hz;
	int i;
	uint64_t avg = 0;
	int rounds = 3;
	int warm_up = 1;

	for (i = 0; i < rounds; i++) {
		sleep.tv_sec = 0;

		if (warm_up)
			sleep.tv_nsec = SEC_IN_NS / 1000;
		else
			sleep.tv_nsec = SEC_IN_NS / 4;

		if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts1)) {
			ODP_DBG("clock_gettime failed\n");
			return 0;
		}

		t1 = _odp_cpu_global_time();

		if (nanosleep(&sleep, NULL) < 0) {
			ODP_DBG("nanosleep failed\n");
			return 0;
		}

		if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts2)) {
			ODP_DBG("clock_gettime failed\n");
			return 0;
		}

		t2 = _odp_cpu_global_time();

		ts_nsec  = (ts2.tv_sec - ts1.tv_sec) * SEC_IN_NS;
		ts_nsec += ts2.tv_nsec - ts1.tv_nsec;

		cycles = t2 - t1;

		hz = (cycles * SEC_IN_NS) / ts_nsec;

		if (warm_up)
			warm_up = 0;
		else
			avg += hz;
	}

	return avg / (rounds - 1);
}

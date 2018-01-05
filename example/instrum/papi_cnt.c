/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <papi.h>
#include <papi_cnt.h>

static int papi_event_tab[SAMPLE_COUNTER_TAB_SIZE] = {PAPI_BR_CN, PAPI_L2_DCM};

static __thread int event_set = PAPI_NULL;

int papi_init(void)
{
	int retval, i;

	retval = PAPI_library_init(PAPI_VER_CURRENT);
	if (retval != PAPI_VER_CURRENT) {
		printf("PAPI Library initialization error!\n");
		return -1;
	}

	retval = PAPI_thread_init((unsigned long(*)(void))(pthread_self));
	if (retval != PAPI_OK) {
		printf("PAPI_thread_init error!\n");
		goto err_shutdown;
	}

	if (PAPI_set_granularity(PAPI_GRN_THR) != PAPI_OK) {
		printf("PAPI_set_granularity error!\n");
		goto err_shutdown;
	}

	for (i = 0; i < SAMPLE_COUNTER_TAB_SIZE; i++) {
		retval = PAPI_query_event(papi_event_tab[i]);
		if (retval != PAPI_OK) {
			printf("PAPI_query_event %d - error\n", i);
			goto err_shutdown;
		}
	}

	return 0;

err_shutdown:
	PAPI_shutdown();

	return -1;
}

void papi_term(void)
{
	PAPI_shutdown();
}

int papi_init_local(void)
{
	int retval;

	retval = PAPI_register_thread();
	if (retval != PAPI_OK) {
		printf("PAPI_register_thread failed - %d\n", retval);
		return -1;
	}

	/* Create LL event set */
	event_set = PAPI_NULL;
	retval = PAPI_create_eventset(&event_set);
	if (retval != PAPI_OK) {
		printf("PAPI_create_eventset error: %d\n", retval);
		return -1;
	}

	retval = PAPI_add_events(event_set, papi_event_tab,
				 SAMPLE_COUNTER_TAB_SIZE);
	if (retval != PAPI_OK) {
		printf("PAPI_add_events error: %d\n", retval);
		goto err_clean_evset;
	}

	retval = PAPI_start(event_set);
	if (retval != PAPI_OK) {
		printf("PAPI_start error: %d\n", retval);
		goto err_clean_evset;
	}

	return 0;

err_clean_evset:
	PAPI_cleanup_eventset(event_set);
	PAPI_destroy_eventset(&event_set);

	return -1;
}

int papi_term_local(void)
{
	long long last_counters[SAMPLE_COUNTER_TAB_SIZE];

	if (PAPI_stop(event_set, last_counters) == PAPI_OK) {
		int i;

		for (i = 0; i < SAMPLE_COUNTER_TAB_SIZE; i++)
			printf("Counter[%d] = %lld\n", i, last_counters[i]);
	}

	PAPI_cleanup_eventset(event_set);
	PAPI_destroy_eventset(&event_set);

	return 0;
}

int papi_sample_start(profiling_sample_t *spl)
{
	spl->timestamp_ns = PAPI_get_real_nsec();
	if (PAPI_read_ts(event_set, spl->counters, &spl->diff_cyc) != PAPI_OK) {
		fprintf(stderr, "PAPI_read_counters - FAILED\n");
		return -1;
	}

	return 0;
}

int papi_sample_end(profiling_sample_t *spl)
{
	long long end_counters[SAMPLE_COUNTER_TAB_SIZE], end_cyc;
	int i;

	if (PAPI_read_ts(event_set, end_counters, &end_cyc) != PAPI_OK) {
		fprintf(stderr, "PAPI_read_counters - FAILED\n");
		return -1;
	}

	for (i = 0; i < SAMPLE_COUNTER_TAB_SIZE; i++)
		spl->counters[i] = end_counters[i] - spl->counters[i];

	spl->diff_cyc = end_cyc - spl->diff_cyc;

	return 0;
}

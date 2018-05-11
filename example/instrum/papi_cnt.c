/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <papi.h>
#include <papi_cnt.h>

#define PAPI_EVENTS_ENV "ODP_INSTRUM_PAPI_EVENTS"

#define PAPI_EVENT_TAB_SIZE_DFLT 2
int papi_event_tab_dflt[PAPI_EVENT_TAB_SIZE_DFLT] = {PAPI_BR_CN, PAPI_L2_DCM};

static int papi_event_tab[SAMPLE_COUNTER_TAB_SIZE];
static int papi_event_tab_size;

static __thread int event_set = PAPI_NULL;

int papi_init(void)
{
	int retval, i;
	char *papi_events_env = NULL;

	retval = PAPI_library_init(PAPI_VER_CURRENT);
	if (retval != PAPI_VER_CURRENT) {
		fprintf(stderr, "PAPI Library initialization error!\n");
		return -1;
	}

	retval = PAPI_thread_init((unsigned long(*)(void))(pthread_self));
	if (retval != PAPI_OK) {
		fprintf(stderr, "PAPI_thread_init error!\n");
		goto err_shutdown;
	}

	if (PAPI_set_granularity(PAPI_GRN_THR) != PAPI_OK) {
		fprintf(stderr, "PAPI_set_granularity error!\n");
		goto err_shutdown;
	}

	papi_events_env = getenv(PAPI_EVENTS_ENV);
	if (papi_events_env) {
		char *tk = strtok(papi_events_env, ",");
		int papi_event;

		while (tk != NULL &&
		       papi_event_tab_size < SAMPLE_COUNTER_TAB_SIZE) {
			if (PAPI_event_name_to_code(tk, &papi_event) == PAPI_OK)
				papi_event_tab[papi_event_tab_size++] =
					papi_event;

			tk = strtok(NULL, ",");
		}
	}

	if (!papi_event_tab_size) {
		for (i = 0; i < PAPI_EVENT_TAB_SIZE_DFLT; i++)
			papi_event_tab[i] = papi_event_tab_dflt[i];
		papi_event_tab_size = PAPI_EVENT_TAB_SIZE_DFLT;
	}

	for (i = 0; i < papi_event_tab_size; i++) {
		retval = PAPI_query_event(papi_event_tab[i]);
		if (retval != PAPI_OK) {
			fprintf(stderr, "PAPI_query_event %d - error\n", i);
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
		fprintf(stderr, "PAPI_register_thread failed - %d\n", retval);
		return -1;
	}

	/* Create LL event set */
	event_set = PAPI_NULL;
	retval = PAPI_create_eventset(&event_set);
	if (retval != PAPI_OK) {
		fprintf(stderr, "PAPI_create_eventset error: %d\n", retval);
		return -1;
	}

	retval = PAPI_add_events(event_set, papi_event_tab,
				 papi_event_tab_size);
	if (retval != PAPI_OK) {
		fprintf(stderr, "PAPI_add_events error: %d\n", retval);
		goto err_clean_evset;
	}

	retval = PAPI_start(event_set);
	if (retval != PAPI_OK) {
		fprintf(stderr, "PAPI_start error: %d\n", retval);
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

		for (i = 0; i < papi_event_tab_size; i++)
			fprintf(stderr, "Counter[%d] = %lld\n", i,
				last_counters[i]);
	}

	PAPI_cleanup_eventset(event_set);
	PAPI_destroy_eventset(&event_set);

	return 0;
}

int papi_counters_cnt(void)
{
	return papi_event_tab_size;
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

	for (i = 0; i < papi_event_tab_size; i++)
		spl->counters[i] = end_counters[i] - spl->counters[i];

	spl->diff_cyc = end_cyc - spl->diff_cyc;

	return 0;
}

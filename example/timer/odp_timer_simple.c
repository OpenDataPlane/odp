/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
/**
 * @file
 *
 * @example odp_timer_simple.c  ODP simple example to schedule timer
 *				action for 1 second.
 */

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

/* ODP main header */
#include <odp_api.h>

#include <odp/helper/odph_api.h>

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	odp_instance_t instance;
	odp_pool_param_t params;
	odp_timer_pool_param_t tparams;
	odp_pool_t timeout_pool;
	odp_timer_pool_t timer_pool;
	odp_queue_param_t qparam;
	odp_queue_t queue;
	odp_event_t ev = ODP_EVENT_INVALID;
	odp_timer_t tim;
	uint64_t sched_tmo;
	int i, rc;
	uint64_t period;
	uint64_t tick;
	odp_timeout_t tmo;
	int ret = 0;
	odp_timer_capability_t timer_capa;

	/*
	 * Init ODP app
	 */
	if (odp_init_global(&instance, NULL, NULL))
		goto err_global;

	if (odp_init_local(instance, ODP_THREAD_CONTROL))
		goto err_local;

	/*
	 * Create pool for timeouts
	 */
	odp_pool_param_init(&params);
	params.tmo.num   = 10;
	params.type      = ODP_POOL_TIMEOUT;

	timeout_pool = odp_pool_create("timeout_pool", &params);
	if (timeout_pool == ODP_POOL_INVALID) {
		ret += 1;
		goto err_tp;
	}

	/*
	 * Create pool of timeouts
	 */
	if (odp_timer_capability(ODP_CLOCK_CPU, &timer_capa)) {
		ret += 1;
		goto err_tp;
	}
	tparams.res_ns = MAX(10 * ODP_TIME_MSEC_IN_NS,
			     timer_capa.highest_res_ns);
	tparams.min_tmo = 10 * ODP_TIME_MSEC_IN_NS;
	tparams.max_tmo = 1 * ODP_TIME_SEC_IN_NS;
	tparams.num_timers = 1; /* One timer per worker */
	tparams.priv = 0; /* Shared */
	tparams.clk_src = ODP_CLOCK_CPU;
	timer_pool = odp_timer_pool_create("timer_pool", &tparams);
	if (timer_pool == ODP_TIMER_POOL_INVALID) {
		ret += 1;
		goto err;
	}

	/* Configure scheduler */
	odp_schedule_config(NULL);

	/*
	 * Create a queue for timer test
	 */
	odp_queue_param_init(&qparam);
	qparam.type        = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	queue = odp_queue_create("timer_queue", &qparam);
	if (queue == ODP_QUEUE_INVALID) {
		ret += 1;
		goto err;
	}

	tim = odp_timer_alloc(timer_pool, queue, NULL);
	if (tim == ODP_TIMER_INVALID) {
		ODPH_ERR("Failed to allocate timer\n");
		ret += 1;
		goto err;
	}

	tmo = odp_timeout_alloc(timeout_pool);
	if (tmo == ODP_TIMEOUT_INVALID) {
		ODPH_ERR("Failed to allocate timeout\n");
		return -1;
	}

	ev = odp_timeout_to_event(tmo);

	/* Calculate period for timer in uint64_t value, in current case
	 * we will schedule timer for 1 second */
	period = odp_timer_ns_to_tick(timer_pool, 1 * ODP_TIME_SEC_IN_NS);

	/* Wait time to return from odp_schedule() if there are no
	 * events
	 */
	sched_tmo = odp_schedule_wait_time(2 * ODP_TIME_SEC_IN_NS);

	for (i = 0; i < 5; i++) {
		odp_time_t time;

		/* Program timeout action on current tick + period */
		tick = odp_timer_current_tick(timer_pool);
		rc = odp_timer_set_abs(tim, tick + period, &ev);
		/* Too early or too late timeout requested */
		if (odp_unlikely(rc != ODP_TIMER_SUCCESS))
			ODPH_ABORT("odp_timer_set_abs() failed: %d\n", rc);

		/* Wait for 2 seconds for timeout action to be generated */
		ev = odp_schedule(&queue, sched_tmo);
		if (ev == ODP_EVENT_INVALID)
			ODPH_ABORT("Invalid event\n");
		if (odp_event_type(ev) != ODP_EVENT_TIMEOUT)
			ODPH_ABORT("Unexpected event type (%u) received\n",
				   odp_event_type(ev));

		time = odp_time_global();
		printf("timer tick %d, time ns %" PRIu64 "\n",
		       i, odp_time_to_ns(time));

		/* Do not free current event, just go back to loop and program
		 * timeout to next second.
		 */
	}

	/* Destroy created resources */
	rc += odp_timer_cancel(tim, &ev);
	rc += -(odp_timer_free(tim) == ODP_EVENT_INVALID);
	odp_event_free(ev);

	ret += odp_queue_destroy(queue);
err:
	odp_timer_pool_destroy(timer_pool);
err_tp:
	ret += odp_pool_destroy(timeout_pool);
	ret += odp_term_local();
err_local:
	ret += odp_term_global(instance);
err_global:
	return ret;
}

/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include <odp_cunit_common.h>
#include "queue.h"

#define MAX_BUFFER_QUEUE        (8)
#define MSG_POOL_SIZE           (4 * 1024 * 1024)
#define CONFIG_MAX_ITERATION    (100)

static int queue_contest = 0xff;
static odp_pool_t pool;

int queue_suite_init(void)
{
	odp_pool_param_t params;

	params.buf.size  = 0;
	params.buf.align = ODP_CACHE_LINE_SIZE;
	params.buf.num   = 1024 * 10;
	params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("msg_pool", &params);

	if (ODP_POOL_INVALID == pool) {
		printf("Pool create failed.\n");
		return -1;
	}
	return 0;
}

int queue_suite_term(void)
{
	return odp_pool_destroy(pool);
}

void queue_test_sunnydays(void)
{
	odp_queue_t queue_creat_id, queue_id;
	odp_event_t enev[MAX_BUFFER_QUEUE];
	odp_event_t deev[MAX_BUFFER_QUEUE];
	odp_buffer_t buf;
	odp_event_t ev;
	odp_pool_t msg_pool;
	odp_event_t *pev_tmp;
	int i, deq_ret, ret;
	int nr_deq_entries = 0;
	int max_iteration = CONFIG_MAX_ITERATION;
	void *prtn = NULL;
	odp_queue_param_t qparams;

	odp_queue_param_init(&qparams);
	qparams.sched.prio = ODP_SCHED_PRIO_LOWEST;
	qparams.sched.sync = ODP_SCHED_SYNC_NONE;
	qparams.sched.group = ODP_SCHED_GROUP_WORKER;

	queue_creat_id = odp_queue_create("test_queue",
					  ODP_QUEUE_TYPE_POLL, &qparams);
	CU_ASSERT(ODP_QUEUE_INVALID != queue_creat_id);

	CU_ASSERT_EQUAL(ODP_QUEUE_TYPE_POLL,
			odp_queue_type(queue_creat_id));

	queue_id = odp_queue_lookup("test_queue");
	CU_ASSERT_EQUAL(queue_creat_id, queue_id);

	CU_ASSERT_EQUAL(ODP_SCHED_GROUP_WORKER,
			odp_queue_sched_group(queue_id));
	CU_ASSERT_EQUAL(ODP_SCHED_PRIO_LOWEST, odp_queue_sched_prio(queue_id));
	CU_ASSERT_EQUAL(ODP_SCHED_SYNC_NONE, odp_queue_sched_type(queue_id));

	CU_ASSERT(0 == odp_queue_context_set(queue_id, &queue_contest));

	prtn = odp_queue_context(queue_id);
	CU_ASSERT(&queue_contest == (int *)prtn);

	msg_pool = odp_pool_lookup("msg_pool");
	buf = odp_buffer_alloc(msg_pool);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
	ev  = odp_buffer_to_event(buf);

	if (!(CU_ASSERT(odp_queue_enq(queue_id, ev) == 0))) {
		odp_buffer_free(buf);
	} else {
		CU_ASSERT_EQUAL(ev, odp_queue_deq(queue_id));
		odp_buffer_free(buf);
	}

	for (i = 0; i < MAX_BUFFER_QUEUE; i++) {
		odp_buffer_t buf = odp_buffer_alloc(msg_pool);
		enev[i] = odp_buffer_to_event(buf);
	}

	/*
	 * odp_queue_enq_multi may return 0..n buffers due to the resource
	 * constraints in the implementation at that given point of time.
	 * But here we assume that we succeed in enqueuing all buffers.
	 */
	ret = odp_queue_enq_multi(queue_id, enev, MAX_BUFFER_QUEUE);
	CU_ASSERT(MAX_BUFFER_QUEUE == ret);
	i = ret < 0 ? 0 : ret;
	for ( ; i < MAX_BUFFER_QUEUE; i++)
		odp_event_free(enev[i]);

	pev_tmp = deev;
	do {
		deq_ret  = odp_queue_deq_multi(queue_id, pev_tmp,
					       MAX_BUFFER_QUEUE);
		nr_deq_entries += deq_ret;
		max_iteration--;
		pev_tmp += deq_ret;
		CU_ASSERT(max_iteration >= 0);
	} while (nr_deq_entries < MAX_BUFFER_QUEUE);

	for (i = 0; i < MAX_BUFFER_QUEUE; i++) {
		odp_buffer_t enbuf = odp_buffer_from_event(enev[i]);
		CU_ASSERT_EQUAL(enev[i], deev[i]);
		odp_buffer_free(enbuf);
	}

	CU_ASSERT(odp_queue_destroy(queue_id) == 0);
}

CU_TestInfo queue_suite[] = {
	{"queue sunnyday",  queue_test_sunnydays},
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo queue_suites[] = {
	{"Queue", queue_suite_init, queue_suite_term,
			NULL, NULL, queue_suite},
	CU_SUITE_INFO_NULL,
};

int queue_main(void)
{
	return odp_cunit_run(queue_suites);
}

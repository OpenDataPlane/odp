/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include "queue.h"

#define MAX_BUFFER_QUEUE        (8)
#define MSG_POOL_SIZE           (4 * 1024 * 1024)
#define CONFIG_MAX_ITERATION    (100)
#define MAX_QUEUES              (64 * 1024)

static int queue_context = 0xff;
static odp_pool_t pool;

static void generate_name(char *name, uint32_t index)
{
	/* Uniqueue name for up to 300M queues */
	name[0] = 'A' + ((index / (26 * 26 * 26 * 26 * 26)) % 26);
	name[1] = 'A' + ((index / (26 * 26 * 26 * 26)) % 26);
	name[2] = 'A' + ((index / (26 * 26 * 26)) % 26);
	name[3] = 'A' + ((index / (26 * 26)) % 26);
	name[4] = 'A' + ((index / 26) % 26);
	name[5] = 'A' + (index % 26);
}

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

void queue_test_capa(void)
{
	odp_queue_capability_t capa;
	odp_queue_param_t qparams;
	char name[ODP_QUEUE_NAME_LEN];
	odp_queue_t queue[MAX_QUEUES];
	uint32_t num_queues, i;

	memset(&capa, 0, sizeof(odp_queue_capability_t));
	CU_ASSERT(odp_queue_capability(&capa) == 0);

	CU_ASSERT(capa.max_queues != 0);
	CU_ASSERT(capa.max_ordered_locks != 0);
	CU_ASSERT(capa.max_sched_groups != 0);
	CU_ASSERT(capa.sched_prios != 0);

	for (i = 0; i < ODP_QUEUE_NAME_LEN; i++)
		name[i] = 'A' + (i % 26);

	name[ODP_QUEUE_NAME_LEN - 1] = 0;

	if (capa.max_queues > MAX_QUEUES)
		num_queues = MAX_QUEUES;
	else
		num_queues = capa.max_queues;

	odp_queue_param_init(&qparams);

	for (i = 0; i < num_queues; i++) {
		generate_name(name, i);
		queue[i] = odp_queue_create(name, &qparams);

		if (queue[i] == ODP_QUEUE_INVALID) {
			CU_FAIL("Queue create failed");
			num_queues = i;
			break;
		}

		CU_ASSERT(odp_queue_lookup(name) != ODP_QUEUE_INVALID);
	}

	for (i = 0; i < num_queues; i++)
		CU_ASSERT(odp_queue_destroy(queue[i]) == 0);
}

void queue_test_mode(void)
{
	odp_queue_param_t qparams;
	odp_queue_t queue;
	int i, j;
	odp_queue_op_mode_t mode[3] = { ODP_QUEUE_OP_MT,
					ODP_QUEUE_OP_MT_UNSAFE,
					ODP_QUEUE_OP_DISABLED };

	odp_queue_param_init(&qparams);

	/* Plain queue modes */
	for (i = 0; i < 3; i++) {
		for (j = 0; j < 3; j++) {
			/* Should not disable both enq and deq */
			if (i == 2 && j == 2)
				break;

			qparams.enq_mode = mode[i];
			qparams.deq_mode = mode[j];
			queue = odp_queue_create("test_queue", &qparams);
			CU_ASSERT(queue != ODP_QUEUE_INVALID);
			if (queue != ODP_QUEUE_INVALID)
				CU_ASSERT(odp_queue_destroy(queue) == 0);
		}
	}

	odp_queue_param_init(&qparams);
	qparams.type = ODP_QUEUE_TYPE_SCHED;

	/* Scheduled queue modes. Dequeue mode is fixed. */
	for (i = 0; i < 3; i++) {
		qparams.enq_mode = mode[i];
		queue = odp_queue_create("test_queue", &qparams);
		CU_ASSERT(queue != ODP_QUEUE_INVALID);
		if (queue != ODP_QUEUE_INVALID)
			CU_ASSERT(odp_queue_destroy(queue) == 0);
	}
}

void queue_test_param(void)
{
	odp_queue_t queue;
	odp_event_t enev[MAX_BUFFER_QUEUE];
	odp_event_t deev[MAX_BUFFER_QUEUE];
	odp_buffer_t buf;
	odp_event_t ev;
	odp_pool_t msg_pool;
	odp_event_t *pev_tmp;
	int i, deq_ret, ret;
	int nr_deq_entries = 0;
	int max_iteration = CONFIG_MAX_ITERATION;
	odp_queue_param_t qparams;

	/* Schedule type queue */
	odp_queue_param_init(&qparams);
	qparams.type       = ODP_QUEUE_TYPE_SCHED;
	qparams.sched.prio = ODP_SCHED_PRIO_LOWEST;
	qparams.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparams.sched.group = ODP_SCHED_GROUP_WORKER;

	queue = odp_queue_create("test_queue", &qparams);
	CU_ASSERT(ODP_QUEUE_INVALID != queue);
	CU_ASSERT(odp_queue_to_u64(queue) !=
		  odp_queue_to_u64(ODP_QUEUE_INVALID));
	CU_ASSERT(queue == odp_queue_lookup("test_queue"));
	CU_ASSERT(ODP_QUEUE_TYPE_SCHED    == odp_queue_type(queue));
	CU_ASSERT(ODP_SCHED_PRIO_LOWEST   == odp_queue_sched_prio(queue));
	CU_ASSERT(ODP_SCHED_SYNC_PARALLEL == odp_queue_sched_type(queue));
	CU_ASSERT(ODP_SCHED_GROUP_WORKER  == odp_queue_sched_group(queue));

	CU_ASSERT(0 == odp_queue_context_set(queue, &queue_context,
					     sizeof(queue_context)));

	CU_ASSERT(&queue_context == odp_queue_context(queue));
	CU_ASSERT(odp_queue_destroy(queue) == 0);

	/* Plain type queue */
	odp_queue_param_init(&qparams);
	qparams.type        = ODP_QUEUE_TYPE_PLAIN;
	qparams.context     = &queue_context;
	qparams.context_len = sizeof(queue_context);

	queue = odp_queue_create("test_queue", &qparams);
	CU_ASSERT(ODP_QUEUE_INVALID != queue);
	CU_ASSERT(queue == odp_queue_lookup("test_queue"));
	CU_ASSERT(ODP_QUEUE_TYPE_PLAIN == odp_queue_type(queue));
	CU_ASSERT(&queue_context == odp_queue_context(queue));

	msg_pool = odp_pool_lookup("msg_pool");
	buf = odp_buffer_alloc(msg_pool);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
	ev  = odp_buffer_to_event(buf);

	if (!(CU_ASSERT(odp_queue_enq(queue, ev) == 0))) {
		odp_buffer_free(buf);
	} else {
		CU_ASSERT(ev == odp_queue_deq(queue));
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
	ret = odp_queue_enq_multi(queue, enev, MAX_BUFFER_QUEUE);
	CU_ASSERT(MAX_BUFFER_QUEUE == ret);
	i = ret < 0 ? 0 : ret;
	for ( ; i < MAX_BUFFER_QUEUE; i++)
		odp_event_free(enev[i]);

	pev_tmp = deev;
	do {
		deq_ret  = odp_queue_deq_multi(queue, pev_tmp,
					       MAX_BUFFER_QUEUE);
		nr_deq_entries += deq_ret;
		max_iteration--;
		pev_tmp += deq_ret;
		CU_ASSERT(max_iteration >= 0);
	} while (nr_deq_entries < MAX_BUFFER_QUEUE);

	for (i = 0; i < MAX_BUFFER_QUEUE; i++) {
		odp_buffer_t enbuf = odp_buffer_from_event(enev[i]);
		CU_ASSERT(enev[i] == deev[i]);
		odp_buffer_free(enbuf);
	}

	CU_ASSERT(odp_queue_destroy(queue) == 0);
}

void queue_test_info(void)
{
	odp_queue_t q_plain, q_order;
	const char *const nq_plain = "test_q_plain";
	const char *const nq_order = "test_q_order";
	odp_queue_info_t info;
	odp_queue_param_t param;
	char q_plain_ctx[] = "test_q_plain context data";
	char q_order_ctx[] = "test_q_order context data";
	unsigned lock_count;
	char *ctx;
	int ret;

	/* Create a plain queue and set context */
	q_plain = odp_queue_create(nq_plain, NULL);
	CU_ASSERT(ODP_QUEUE_INVALID != q_plain);
	CU_ASSERT(odp_queue_context_set(q_plain, q_plain_ctx,
					sizeof(q_plain_ctx)) == 0);

	/* Create a scheduled ordered queue with explicitly set params */
	odp_queue_param_init(&param);
	param.type       = ODP_QUEUE_TYPE_SCHED;
	param.sched.prio = ODP_SCHED_PRIO_NORMAL;
	param.sched.sync = ODP_SCHED_SYNC_ORDERED;
	param.sched.group = ODP_SCHED_GROUP_ALL;
	param.sched.lock_count = 1;
	param.context = q_order_ctx;
	q_order = odp_queue_create(nq_order, &param);
	CU_ASSERT(ODP_QUEUE_INVALID != q_order);

	/* Check info for the plain queue */
	CU_ASSERT(odp_queue_info(q_plain, &info) == 0);
	CU_ASSERT(strcmp(nq_plain, info.name) == 0);
	CU_ASSERT(info.param.type == ODP_QUEUE_TYPE_PLAIN);
	CU_ASSERT(info.param.type == odp_queue_type(q_plain));
	ctx = info.param.context; /* 'char' context ptr */
	CU_ASSERT(ctx == q_plain_ctx);
	CU_ASSERT(info.param.context == odp_queue_context(q_plain));

	/* Check info for the scheduled ordered queue */
	CU_ASSERT(odp_queue_info(q_order, &info) == 0);
	CU_ASSERT(strcmp(nq_order, info.name) == 0);
	CU_ASSERT(info.param.type == ODP_QUEUE_TYPE_SCHED);
	CU_ASSERT(info.param.type == odp_queue_type(q_order));
	ctx = info.param.context; /* 'char' context ptr */
	CU_ASSERT(ctx == q_order_ctx);
	CU_ASSERT(info.param.context == odp_queue_context(q_order));
	CU_ASSERT(info.param.sched.prio == odp_queue_sched_prio(q_order));
	CU_ASSERT(info.param.sched.sync == odp_queue_sched_type(q_order));
	CU_ASSERT(info.param.sched.group == odp_queue_sched_group(q_order));
	ret = odp_queue_lock_count(q_order);
	CU_ASSERT(ret >= 0);
	lock_count = (unsigned) ret;
	CU_ASSERT(info.param.sched.lock_count == lock_count);

	CU_ASSERT(odp_queue_destroy(q_plain) == 0);
	CU_ASSERT(odp_queue_destroy(q_order) == 0);
}

odp_testinfo_t queue_suite[] = {
	ODP_TEST_INFO(queue_test_capa),
	ODP_TEST_INFO(queue_test_mode),
	ODP_TEST_INFO(queue_test_param),
	ODP_TEST_INFO(queue_test_info),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t queue_suites[] = {
	{"Queue", queue_suite_init, queue_suite_term, queue_suite},
	ODP_SUITE_INFO_NULL,
};

int queue_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(queue_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

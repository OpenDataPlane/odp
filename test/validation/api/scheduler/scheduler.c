/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include "odp_cunit_common.h"
#include <odp/helper/odph_api.h>

#define MAX_ORDERED_LOCKS       2
#define MSG_POOL_SIZE		(64 * 1024)
#define QUEUES_PER_PRIO		16
#define BUF_SIZE		64
#define BUFS_PER_QUEUE          100
#define BUFS_PER_QUEUE_EXCL     10000
#define BURST_BUF_SIZE		4
#define NUM_BUFS_PAUSE		1000
#define NUM_BUFS_BEFORE_PAUSE	10
#define NUM_GROUPS              2
#define MAX_QUEUES              (64 * 1024)

#define DEFAULT_NUM_EV          50

#define MAX_FLOWS               16
#define FLOW_TEST_NUM_EV        (10 * MAX_FLOWS)

#define GLOBALS_SHM_NAME	"test_globals"
#define MSG_POOL_NAME		"msg_pool"
#define QUEUE_CTX_POOL_NAME     "queue_ctx_pool"
#define SHM_THR_ARGS_NAME	"shm_thr_args"

#define ONE_Q			1
#define ONE_PRIO		1

#define SCHD_ONE		0
#define SCHD_MULTI		1

#define DISABLE_EXCL_ATOMIC	0
#define ENABLE_EXCL_ATOMIC	1

#define MAGIC                   0xdeadbeef
#define MAGIC1                  0xdeadbeef
#define MAGIC2                  0xcafef00d

#define CHAOS_NUM_QUEUES 6
#define CHAOS_NUM_BUFS_PER_QUEUE 6
#define CHAOS_NUM_ROUNDS 1000
#define CHAOS_NUM_EVENTS (CHAOS_NUM_QUEUES * CHAOS_NUM_BUFS_PER_QUEUE)
#define CHAOS_DEBUG (CHAOS_NUM_ROUNDS < 1000)
#define CHAOS_PTR_TO_NDX(p) ((uint64_t)(uint32_t)(uintptr_t)p)
#define CHAOS_NDX_TO_PTR(n) ((void *)(uintptr_t)n)

#define WAIT_TOLERANCE (150 * ODP_TIME_MSEC_IN_NS)
#define WAIT_1MS_RETRIES 1000

/* Test global variables */
typedef struct {
	int num_workers;
	odp_barrier_t barrier;
	int buf_count;
	int buf_count_cpy;
	int queues_per_prio;
	odp_pool_t pool;
	odp_pool_t queue_ctx_pool;
	uint32_t max_sched_queue_size;
	uint64_t num_flows;
	odp_ticketlock_t lock;
	odp_spinlock_t atomic_lock;
	struct {
		odp_queue_t handle;
		char name[ODP_QUEUE_NAME_LEN];
	} chaos_q[CHAOS_NUM_QUEUES];
} test_globals_t;

typedef struct {
	pthrd_arg cu_thr;
	test_globals_t *globals;
	odp_schedule_sync_t sync;
	int num_queues;
	int num_prio;
	int num_bufs;
	int num_workers;
	int enable_schd_multi;
	int enable_excl_atomic;
} thread_args_t;

typedef struct {
	uint64_t sequence;
	uint64_t lock_sequence[MAX_ORDERED_LOCKS];
	uint64_t output_sequence;
} buf_contents;

typedef struct {
	odp_buffer_t ctx_handle;
	odp_queue_t pq_handle;
	uint64_t sequence;
	uint64_t lock_sequence[MAX_ORDERED_LOCKS];
} queue_context;

typedef struct {
	uint64_t evno;
	uint64_t seqno;
} chaos_buf;

static test_globals_t *globals;

static int drain_queues(void)
{
	odp_event_t ev;
	uint64_t wait = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);
	int ret = 0;

	while ((ev = odp_schedule(NULL, wait)) != ODP_EVENT_INVALID) {
		odp_event_free(ev);
		ret++;
	}

	return ret;
}

static void release_context(odp_schedule_sync_t sync)
{
	if (sync == ODP_SCHED_SYNC_ATOMIC)
		odp_schedule_release_atomic();
	else if (sync == ODP_SCHED_SYNC_ORDERED)
		odp_schedule_release_ordered();
}

static void scheduler_test_capa(void)
{
	odp_schedule_capability_t sched_capa;
	odp_queue_capability_t queue_capa;

	memset(&sched_capa, 0, sizeof(odp_schedule_capability_t));
	CU_ASSERT_FATAL(odp_schedule_capability(&sched_capa) == 0);
	CU_ASSERT_FATAL(odp_queue_capability(&queue_capa) == 0);

	CU_ASSERT(sched_capa.max_groups != 0);
	CU_ASSERT(sched_capa.max_prios != 0);
	CU_ASSERT(sched_capa.max_queues != 0);
	CU_ASSERT(queue_capa.max_queues >= sched_capa.max_queues);
}

static void scheduler_test_wait_time(void)
{
	int i;
	odp_queue_t queue;
	uint64_t wait_time;
	odp_queue_param_t qp;
	odp_time_t lower_limit, upper_limit;
	odp_time_t start_time, end_time, diff;

	/* check on read */
	wait_time = odp_schedule_wait_time(0);
	wait_time = odp_schedule_wait_time(1);

	/* check ODP_SCHED_NO_WAIT */
	odp_queue_param_init(&qp);
	qp.type        = ODP_QUEUE_TYPE_SCHED;
	qp.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	qp.sched.prio  = odp_schedule_default_prio();
	qp.sched.group = ODP_SCHED_GROUP_ALL;
	queue = odp_queue_create("dummy_queue", &qp);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	wait_time = odp_schedule_wait_time(ODP_TIME_SEC_IN_NS);
	start_time = odp_time_local();
	odp_schedule(&queue, ODP_SCHED_NO_WAIT);
	end_time = odp_time_local();

	diff = odp_time_diff(end_time, start_time);
	lower_limit = ODP_TIME_NULL;
	upper_limit = odp_time_local_from_ns(WAIT_TOLERANCE);

	CU_ASSERT(odp_time_cmp(diff, lower_limit) >= 0);
	CU_ASSERT(odp_time_cmp(diff, upper_limit) <= 0);

	/* check time correctness */
	start_time = odp_time_local();
	for (i = 1; i < 6; i++)
		odp_schedule(&queue, wait_time);
	end_time = odp_time_local();

	diff = odp_time_diff(end_time, start_time);
	lower_limit = odp_time_local_from_ns(5 * ODP_TIME_SEC_IN_NS -
					     WAIT_TOLERANCE);
	upper_limit = odp_time_local_from_ns(5 * ODP_TIME_SEC_IN_NS +
					     WAIT_TOLERANCE);

	if (odp_time_cmp(diff, lower_limit) <= 0) {
		fprintf(stderr, "Exceed lower limit: "
			"diff is %" PRIu64 ", lower_limit %" PRIu64 "\n",
			odp_time_to_ns(diff), odp_time_to_ns(lower_limit));
		CU_FAIL("Exceed lower limit\n");
	}

	if (odp_time_cmp(diff, upper_limit) >= 0) {
		fprintf(stderr, "Exceed upper limit: "
			"diff is %" PRIu64 ", upper_limit %" PRIu64 "\n",
			odp_time_to_ns(diff), odp_time_to_ns(upper_limit));
		CU_FAIL("Exceed upper limit\n");
	}

	CU_ASSERT_FATAL(odp_queue_destroy(queue) == 0);
}

static void scheduler_test_num_prio(void)
{
	int num_prio, min_prio, max_prio, default_prio;

	num_prio = odp_schedule_num_prio();
	CU_ASSERT(num_prio > 0);

	min_prio = odp_schedule_min_prio();
	max_prio = odp_schedule_max_prio();
	default_prio = odp_schedule_default_prio();

	CU_ASSERT(min_prio <= max_prio);
	CU_ASSERT(min_prio <= default_prio);
	CU_ASSERT(default_prio <= max_prio);
	CU_ASSERT(num_prio == (max_prio - min_prio + 1));

	CU_ASSERT(min_prio == ODP_SCHED_PRIO_LOWEST);
	CU_ASSERT(max_prio == ODP_SCHED_PRIO_HIGHEST);
	CU_ASSERT(default_prio == ODP_SCHED_PRIO_DEFAULT);
	CU_ASSERT(default_prio == ODP_SCHED_PRIO_NORMAL);
}

static void scheduler_test_queue_destroy(void)
{
	odp_pool_t p;
	odp_pool_param_t params;
	odp_queue_param_t qp;
	odp_queue_t queue, from;
	odp_buffer_t buf;
	odp_event_t ev;
	uint32_t *u32;
	int i;
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_PARALLEL,
				      ODP_SCHED_SYNC_ATOMIC,
				      ODP_SCHED_SYNC_ORDERED};

	odp_queue_param_init(&qp);
	odp_pool_param_init(&params);
	params.buf.size  = 100;
	params.buf.align = 0;
	params.buf.num   = 1;
	params.type      = ODP_POOL_BUFFER;

	p = odp_pool_create("sched_destroy_pool", &params);

	CU_ASSERT_FATAL(p != ODP_POOL_INVALID);

	for (i = 0; i < 3; i++) {
		qp.type        = ODP_QUEUE_TYPE_SCHED;
		qp.sched.prio  = odp_schedule_default_prio();
		qp.sched.sync  = sync[i];
		qp.sched.group = ODP_SCHED_GROUP_ALL;

		queue = odp_queue_create("sched_destroy_queue", &qp);

		CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

		buf = odp_buffer_alloc(p);

		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

		u32 = odp_buffer_addr(buf);
		u32[0] = MAGIC;

		ev = odp_buffer_to_event(buf);
		if (!(CU_ASSERT(odp_queue_enq(queue, ev) == 0)))
			odp_buffer_free(buf);

		ev = odp_schedule(&from, ODP_SCHED_WAIT);

		CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);

		CU_ASSERT_FATAL(from == queue);

		buf = odp_buffer_from_event(ev);
		u32 = odp_buffer_addr(buf);

		CU_ASSERT_FATAL(u32[0] == MAGIC);

		odp_buffer_free(buf);
		release_context(qp.sched.sync);

		/*  Make sure atomic/ordered context is released */
		CU_ASSERT(drain_queues() == 0);

		CU_ASSERT_FATAL(odp_queue_destroy(queue) == 0);
	}

	CU_ASSERT_FATAL(odp_pool_destroy(p) == 0);
}

static void scheduler_test_wait(void)
{
	odp_pool_t p;
	odp_pool_param_t pool_param;
	odp_queue_param_t queue_param;
	odp_queue_t queue, from;
	odp_buffer_t buf;
	odp_event_t ev;
	uint32_t *u32;
	uint32_t i, j, num_enq, retry;
	int ret;
	uint32_t num_ev = 50;
	uint32_t num_retry = 1000;

	odp_pool_param_init(&pool_param);
	pool_param.buf.size  = 10;
	pool_param.buf.num   = num_ev;
	pool_param.type      = ODP_POOL_BUFFER;

	p = odp_pool_create("sched_test_wait", &pool_param);

	CU_ASSERT_FATAL(p != ODP_POOL_INVALID);

	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio  = odp_schedule_default_prio();
	queue_param.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	queue = odp_queue_create("sched_test_wait", &queue_param);

	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	for (i = 0; i < 4; i++) {
		num_enq = 0;

		for (j = 0; j < num_ev; j++) {
			buf = odp_buffer_alloc(p);

			CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

			u32 = odp_buffer_addr(buf);
			u32[0] = MAGIC;

			ev = odp_buffer_to_event(buf);
			if (!(CU_ASSERT(odp_queue_enq(queue, ev) == 0))) {
				odp_buffer_free(buf);
				continue;
			}

			num_enq++;
		}

		CU_ASSERT(num_enq == num_ev);

		for (j = 0; j < num_enq; j++) {
			if (i == 0) {
				ev = odp_schedule(&from, ODP_SCHED_WAIT);
			} else if (i == 1) {
				ret = odp_schedule_multi_wait(&from, &ev, 1);
				CU_ASSERT_FATAL(ret == 1);
			} else if (i == 2) {
				retry = 0;
				do {
					ev = odp_schedule(&from,
							  ODP_SCHED_NO_WAIT);
					retry++;
				} while (ev == ODP_EVENT_INVALID &&
					 retry < num_retry);
			} else {
				retry = 0;
				do {
					ret = odp_schedule_multi_no_wait(&from,
									 &ev,
									 1);
					retry++;
				} while (ret == 0 && retry < num_retry);
				CU_ASSERT_FATAL(ret == 1);
			}

			CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
			CU_ASSERT(from == queue);

			buf = odp_buffer_from_event(ev);
			u32 = odp_buffer_addr(buf);

			CU_ASSERT(u32[0] == MAGIC);

			odp_buffer_free(buf);
		}
	}

	/* Make sure that scheduler is empty */
	drain_queues();

	CU_ASSERT_FATAL(odp_queue_destroy(queue) == 0);
	CU_ASSERT_FATAL(odp_pool_destroy(p) == 0);
}

static void scheduler_test_queue_size(void)
{
	odp_schedule_config_t default_config;
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	odp_queue_param_t queue_param;
	odp_queue_t queue, from;
	odp_event_t ev;
	odp_buffer_t buf;
	uint32_t i, j, queue_size, num;
	int ret;
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_PARALLEL,
				      ODP_SCHED_SYNC_ATOMIC,
				      ODP_SCHED_SYNC_ORDERED};

	queue_size = DEFAULT_NUM_EV;

	/* Scheduler has been already configured. Use default config as max
	 * queue size. */
	odp_schedule_config_init(&default_config);
	if (default_config.queue_size &&
	    queue_size > default_config.queue_size)
		queue_size = default_config.queue_size;

	odp_pool_param_init(&pool_param);
	pool_param.buf.size  = 100;
	pool_param.buf.align = 0;
	pool_param.buf.num   = DEFAULT_NUM_EV;
	pool_param.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("test_queue_size", &pool_param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < 3; i++) {
		/* Ensure that scheduler is empty */
		for (j = 0; j < 10;) {
			ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
			CU_ASSERT(ev == ODP_EVENT_INVALID);

			if (ev != ODP_EVENT_INVALID)
				odp_event_free(ev);
			else
				j++;
		}

		odp_queue_param_init(&queue_param);
		queue_param.type = ODP_QUEUE_TYPE_SCHED;
		queue_param.sched.prio  = odp_schedule_default_prio();
		queue_param.sched.sync  = sync[i];
		queue_param.sched.group = ODP_SCHED_GROUP_ALL;
		queue_param.size = queue_size;

		queue = odp_queue_create("test_queue_size", &queue_param);

		CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

		for (j = 0; j < queue_size; j++) {
			buf = odp_buffer_alloc(pool);
			CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

			ev = odp_buffer_to_event(buf);
			ret = odp_queue_enq(queue, ev);
			CU_ASSERT(ret == 0);

			if (ret)
				odp_event_free(ev);
		}

		num = 0;
		for (j = 0; j < 100 * DEFAULT_NUM_EV; j++) {
			ev = odp_schedule(&from, ODP_SCHED_NO_WAIT);

			if (ev == ODP_EVENT_INVALID)
				continue;

			CU_ASSERT(from == queue);
			odp_event_free(ev);
			num++;
		}

		CU_ASSERT(num == queue_size);

		CU_ASSERT(drain_queues() == 0);

		CU_ASSERT_FATAL(odp_queue_destroy(queue) == 0);
	}

	CU_ASSERT_FATAL(odp_pool_destroy(pool) == 0);
}

static void scheduler_test_order_ignore(void)
{
	odp_queue_capability_t queue_capa;
	odp_schedule_config_t default_config;
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	odp_queue_param_t queue_param;
	odp_queue_t ordered, plain, from;
	odp_event_t ev;
	odp_buffer_t buf;
	uint32_t j, queue_size, num;
	int ret;

	odp_schedule_config_init(&default_config);
	CU_ASSERT_FATAL(odp_queue_capability(&queue_capa) == 0);

	queue_size = DEFAULT_NUM_EV;
	if (default_config.queue_size &&
	    queue_size > default_config.queue_size)
		queue_size = default_config.queue_size;

	if (queue_capa.plain.max_size &&
	    queue_size > queue_capa.plain.max_size)
		queue_size = queue_capa.plain.max_size;

	odp_pool_param_init(&pool_param);
	pool_param.buf.size  = 100;
	pool_param.buf.align = 0;
	pool_param.buf.num   = DEFAULT_NUM_EV;
	pool_param.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("test_order_ignore", &pool_param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	/* Ensure that scheduler is empty */
	for (j = 0; j < 10;) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
		CU_ASSERT(ev == ODP_EVENT_INVALID);

		if (ev != ODP_EVENT_INVALID)
			odp_event_free(ev);
		else
			j++;
	}

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio  = odp_schedule_default_prio();
	queue_param.sched.sync  = ODP_SCHED_SYNC_ORDERED;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	ordered = odp_queue_create("ordered", &queue_param);
	CU_ASSERT_FATAL(ordered != ODP_QUEUE_INVALID);

	odp_queue_param_init(&queue_param);
	queue_param.type  = ODP_QUEUE_TYPE_PLAIN;
	queue_param.order = ODP_QUEUE_ORDER_IGNORE;

	plain = odp_queue_create("plain", &queue_param);
	CU_ASSERT_FATAL(plain != ODP_QUEUE_INVALID);

	num = 0;
	for (j = 0; j < queue_size; j++) {
		buf = odp_buffer_alloc(pool);
		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

		ev = odp_buffer_to_event(buf);
		ret = odp_queue_enq(ordered, ev);

		if (ret)
			odp_event_free(ev);
		else
			num++;
	}

	CU_ASSERT(num == queue_size);

	num = 0;
	for (j = 0; j < 100 * DEFAULT_NUM_EV; j++) {
		ev = odp_schedule(&from, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			continue;

		CU_ASSERT(from == ordered);
		ret = odp_queue_enq(plain, ev);

		if (ret)
			odp_event_free(ev);
		else
			num++;
	}

	CU_ASSERT(num == queue_size);

	num = 0;
	for (j = 0; j < 100 * DEFAULT_NUM_EV; j++) {
		ev = odp_queue_deq(plain);

		if (ev == ODP_EVENT_INVALID)
			continue;

		odp_event_free(ev);
		num++;
	}

	CU_ASSERT(num == queue_size);

	CU_ASSERT(drain_queues() == 0);
	CU_ASSERT_FATAL(odp_queue_destroy(ordered) == 0);
	CU_ASSERT_FATAL(odp_queue_destroy(plain) == 0);
	CU_ASSERT_FATAL(odp_pool_destroy(pool) == 0);
}

static void scheduler_test_groups(void)
{
	odp_pool_t p;
	odp_pool_param_t params;
	odp_queue_t queue_grp1, queue_grp2;
	odp_buffer_t buf;
	odp_event_t ev;
	uint32_t *u32;
	int i, j, rc;
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_PARALLEL,
				      ODP_SCHED_SYNC_ATOMIC,
				      ODP_SCHED_SYNC_ORDERED};
	int thr_id = odp_thread_id();
	odp_thrmask_t zeromask, mymask, testmask;
	odp_schedule_group_t mygrp1, mygrp2, null_grp, lookup;
	odp_schedule_group_info_t info;

	odp_thrmask_zero(&zeromask);
	odp_thrmask_zero(&mymask);
	odp_thrmask_set(&mymask, thr_id);

	/* Can't find a group before we create it */
	lookup = odp_schedule_group_lookup("Test Group 1");
	CU_ASSERT(lookup == ODP_SCHED_GROUP_INVALID);

	/* Now create the group */
	mygrp1 = odp_schedule_group_create("Test Group 1", &zeromask);
	CU_ASSERT_FATAL(mygrp1 != ODP_SCHED_GROUP_INVALID);

	/* Verify we can now find it */
	lookup = odp_schedule_group_lookup("Test Group 1");
	CU_ASSERT(lookup == mygrp1);

	/* Threadmask should be retrievable and be what we expect */
	rc = odp_schedule_group_thrmask(mygrp1, &testmask);
	CU_ASSERT(rc == 0);
	CU_ASSERT(!odp_thrmask_isset(&testmask, thr_id));

	/* Now join the group and verify we're part of it */
	rc = odp_schedule_group_join(mygrp1, &mymask);
	CU_ASSERT(rc == 0);

	rc = odp_schedule_group_thrmask(mygrp1, &testmask);
	CU_ASSERT(rc == 0);
	CU_ASSERT(odp_thrmask_isset(&testmask, thr_id));

	/* Info struct */
	memset(&info, 0, sizeof(odp_schedule_group_info_t));
	rc = odp_schedule_group_info(mygrp1, &info);
	CU_ASSERT(rc == 0);
	CU_ASSERT(odp_thrmask_equal(&info.thrmask, &mymask) != 0);
	CU_ASSERT(strcmp(info.name, "Test Group 1") == 0);

	/* We can't join or leave an unknown group */
	rc = odp_schedule_group_join(ODP_SCHED_GROUP_INVALID, &mymask);
	CU_ASSERT(rc != 0);

	rc = odp_schedule_group_leave(ODP_SCHED_GROUP_INVALID, &mymask);
	CU_ASSERT(rc != 0);

	/* But we can leave our group */
	rc = odp_schedule_group_leave(mygrp1, &mymask);
	CU_ASSERT(rc == 0);

	rc = odp_schedule_group_thrmask(mygrp1, &testmask);
	CU_ASSERT(rc == 0);
	CU_ASSERT(!odp_thrmask_isset(&testmask, thr_id));

	/* Create group with no name */
	null_grp = odp_schedule_group_create(NULL, &zeromask);
	CU_ASSERT(null_grp != ODP_SCHED_GROUP_INVALID);

	/* We shouldn't be able to find our second group before creating it */
	lookup = odp_schedule_group_lookup("Test Group 2");
	CU_ASSERT(lookup == ODP_SCHED_GROUP_INVALID);

	/* Now create it and verify we can find it */
	mygrp2 = odp_schedule_group_create("Test Group 2", &zeromask);
	CU_ASSERT_FATAL(mygrp2 != ODP_SCHED_GROUP_INVALID);

	lookup = odp_schedule_group_lookup("Test Group 2");
	CU_ASSERT(lookup == mygrp2);

	/* Destroy group with no name */
	CU_ASSERT_FATAL(odp_schedule_group_destroy(null_grp) == 0);

	/* Verify we're not part of it */
	rc = odp_schedule_group_thrmask(mygrp2, &testmask);
	CU_ASSERT(rc == 0);
	CU_ASSERT(!odp_thrmask_isset(&testmask, thr_id));

	/* Now join the group and verify we're part of it */
	rc = odp_schedule_group_join(mygrp2, &mymask);
	CU_ASSERT(rc == 0);

	rc = odp_schedule_group_thrmask(mygrp2, &testmask);
	CU_ASSERT(rc == 0);
	CU_ASSERT(odp_thrmask_isset(&testmask, thr_id));

	/* Leave group 2 */
	rc = odp_schedule_group_leave(mygrp2, &mymask);
	CU_ASSERT(rc == 0);

	/* Now verify scheduler adherence to groups */
	odp_pool_param_init(&params);
	params.buf.size  = 100;
	params.buf.align = 0;
	params.buf.num   = 2;
	params.type      = ODP_POOL_BUFFER;

	p = odp_pool_create("sched_group_pool", &params);

	CU_ASSERT_FATAL(p != ODP_POOL_INVALID);

	for (i = 0; i < 3; i++) {
		odp_queue_param_t qp;
		odp_queue_t queue, from;
		odp_schedule_group_t mygrp[NUM_GROUPS];
		odp_queue_t queue_grp[NUM_GROUPS];
		uint64_t wait_time;
		int num = NUM_GROUPS;
		int schedule_retries;

		odp_queue_param_init(&qp);
		qp.type        = ODP_QUEUE_TYPE_SCHED;
		qp.sched.prio  = odp_schedule_default_prio();
		qp.sched.sync  = sync[i];
		qp.sched.group = mygrp1;

		/* Create and populate a group in group 1 */
		queue_grp1 = odp_queue_create("sched_group_test_queue_1", &qp);
		CU_ASSERT_FATAL(queue_grp1 != ODP_QUEUE_INVALID);
		CU_ASSERT_FATAL(odp_queue_sched_group(queue_grp1) == mygrp1);

		buf = odp_buffer_alloc(p);

		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

		u32 = odp_buffer_addr(buf);
		u32[0] = MAGIC1;

		ev = odp_buffer_to_event(buf);
		rc = odp_queue_enq(queue_grp1, ev);
		CU_ASSERT(rc == 0);
		if (rc)
			odp_buffer_free(buf);

		/* Now create and populate a queue in group 2 */
		qp.sched.group = mygrp2;
		queue_grp2 = odp_queue_create("sched_group_test_queue_2", &qp);
		CU_ASSERT_FATAL(queue_grp2 != ODP_QUEUE_INVALID);
		CU_ASSERT_FATAL(odp_queue_sched_group(queue_grp2) == mygrp2);

		buf = odp_buffer_alloc(p);
		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

		u32 = odp_buffer_addr(buf);
		u32[0] = MAGIC2;

		ev = odp_buffer_to_event(buf);
		rc = odp_queue_enq(queue_grp2, ev);
		CU_ASSERT(rc == 0);
		if (rc)
			odp_buffer_free(buf);

		/* Swap between two groups. Application should serve both
		 * groups to avoid potential head of line blocking in
		 * scheduler. */
		mygrp[0]     = mygrp1;
		mygrp[1]     = mygrp2;
		queue_grp[0] = queue_grp1;
		queue_grp[1] = queue_grp2;
		j = 0;

		/* Ensure that each test run starts from mygrp1 */
		odp_schedule_group_leave(mygrp1, &mymask);
		odp_schedule_group_leave(mygrp2, &mymask);
		odp_schedule_group_join(mygrp1, &mymask);

		wait_time = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);
		schedule_retries = 0;
		while (num) {
			queue = queue_grp[j];
			ev    = odp_schedule(&from, wait_time);

			if (ev == ODP_EVENT_INVALID) {
				CU_ASSERT_FATAL(schedule_retries <
						WAIT_1MS_RETRIES);
				schedule_retries++;
				continue;
			} else {
				schedule_retries = 0;
			}

			CU_ASSERT_FATAL(from == queue);

			buf = odp_buffer_from_event(ev);
			u32 = odp_buffer_addr(buf);

			if (from == queue_grp1) {
				/* CU_ASSERT_FATAL needs these brackets */
				CU_ASSERT_FATAL(u32[0] == MAGIC1);
			} else {
				CU_ASSERT_FATAL(u32[0] == MAGIC2);
			}

			odp_buffer_free(buf);

			/* Change group */
			rc = odp_schedule_group_leave(mygrp[j], &mymask);
			CU_ASSERT_FATAL(rc == 0);

			j = (j + 1) % NUM_GROUPS;
			rc = odp_schedule_group_join(mygrp[j], &mymask);
			CU_ASSERT_FATAL(rc == 0);

			/* Tell scheduler we're about to request an event.
			 * Not needed, but a convenient place to test this API.
			 */
			odp_schedule_prefetch(1);

			num--;
		}

		/* Release schduler context and leave groups */
		odp_schedule_group_join(mygrp1, &mymask);
		odp_schedule_group_join(mygrp2, &mymask);
		CU_ASSERT(drain_queues() == 0);
		odp_schedule_group_leave(mygrp1, &mymask);
		odp_schedule_group_leave(mygrp2, &mymask);

		/* Done with queues for this round */
		CU_ASSERT_FATAL(odp_queue_destroy(queue_grp1) == 0);
		CU_ASSERT_FATAL(odp_queue_destroy(queue_grp2) == 0);

		/* Verify we can no longer find our queues */
		CU_ASSERT_FATAL(odp_queue_lookup("sched_group_test_queue_1") ==
				ODP_QUEUE_INVALID);
		CU_ASSERT_FATAL(odp_queue_lookup("sched_group_test_queue_2") ==
				ODP_QUEUE_INVALID);
	}

	CU_ASSERT_FATAL(odp_schedule_group_destroy(mygrp1) == 0);
	CU_ASSERT_FATAL(odp_schedule_group_destroy(mygrp2) == 0);
	CU_ASSERT_FATAL(odp_pool_destroy(p) == 0);
}

static int chaos_thread(void *arg)
{
	uint64_t i, wait;
	int rc;
	chaos_buf *cbuf;
	odp_event_t ev;
	odp_queue_t from;
	thread_args_t *args = (thread_args_t *)arg;
	test_globals_t *globals = args->globals;
	int me = odp_thread_id();
	odp_time_t start_time, end_time, diff;

	if (CHAOS_DEBUG)
		printf("Chaos thread %d starting...\n", me);

	/* Wait for all threads to start */
	odp_barrier_wait(&globals->barrier);
	start_time = odp_time_local();

	/* Run the test */
	wait = odp_schedule_wait_time(5 * ODP_TIME_MSEC_IN_NS);
	for (i = 0; i < CHAOS_NUM_ROUNDS; i++) {
		ev = odp_schedule(&from, wait);
		if (ev == ODP_EVENT_INVALID)
			continue;

		cbuf = odp_buffer_addr(odp_buffer_from_event(ev));
		CU_ASSERT_FATAL(cbuf != NULL);
		if (CHAOS_DEBUG)
			printf("Thread %d received event %" PRIu64
			       " seq %" PRIu64
			       " from Q %s, sending to Q %s\n",
			       me, cbuf->evno, cbuf->seqno,
			       globals->
			       chaos_q
			       [CHAOS_PTR_TO_NDX(odp_queue_context(from))].name,
			       globals->
			       chaos_q[cbuf->seqno % CHAOS_NUM_QUEUES].name);

		rc = odp_queue_enq(
			globals->
			chaos_q[cbuf->seqno++ % CHAOS_NUM_QUEUES].handle,
			ev);
		CU_ASSERT_FATAL(rc == 0);
	}

	if (CHAOS_DEBUG)
		printf("Thread %d completed %d rounds...terminating\n",
		       odp_thread_id(), CHAOS_NUM_EVENTS);

	end_time = odp_time_local();
	diff = odp_time_diff(end_time, start_time);

	printf("Thread %d ends, elapsed time = %" PRIu64 "us\n",
	       odp_thread_id(), odp_time_to_ns(diff) / 1000);

	/* Make sure scheduling context is released */
	odp_schedule_pause();
	while ((ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT))
	      != ODP_EVENT_INVALID) {
		odp_event_free(ev);
	}

	/* Don't resume scheduling until all threads have finished */
	odp_barrier_wait(&globals->barrier);
	odp_schedule_resume();

	drain_queues();

	return 0;
}

static void chaos_run(unsigned int qtype)
{
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_queue_param_t qp;
	odp_buffer_t buf;
	chaos_buf *cbuf;
	test_globals_t *globals;
	thread_args_t *args;
	odp_shm_t shm;
	int i, rc;
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_PARALLEL,
				      ODP_SCHED_SYNC_ATOMIC,
				      ODP_SCHED_SYNC_ORDERED};
	const unsigned num_sync = (sizeof(sync) / sizeof(odp_schedule_sync_t));
	const char *const qtypes[] = {"parallel", "atomic", "ordered"};

	/* Set up the scheduling environment */
	shm = odp_shm_lookup(GLOBALS_SHM_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	globals = odp_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL_FATAL(globals);

	shm = odp_shm_lookup(SHM_THR_ARGS_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	args = odp_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL_FATAL(args);

	args->globals = globals;

	odp_queue_param_init(&qp);
	odp_pool_param_init(&params);
	params.buf.size = sizeof(chaos_buf);
	params.buf.align = 0;
	params.buf.num = CHAOS_NUM_EVENTS;
	params.type = ODP_POOL_BUFFER;

	pool = odp_pool_create("sched_chaos_pool", &params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	qp.type        = ODP_QUEUE_TYPE_SCHED;
	qp.sched.prio  = odp_schedule_default_prio();
	qp.sched.group = ODP_SCHED_GROUP_ALL;

	for (i = 0; i < CHAOS_NUM_QUEUES; i++) {
		uint32_t ndx = (qtype == num_sync ? i % num_sync : qtype);

		qp.sched.sync = sync[ndx];
		snprintf(globals->chaos_q[i].name,
			 sizeof(globals->chaos_q[i].name),
			 "chaos queue %d - %s", i,
			 qtypes[ndx]);

		globals->chaos_q[i].handle =
			odp_queue_create(globals->chaos_q[i].name, &qp);
		CU_ASSERT_FATAL(globals->chaos_q[i].handle !=
				ODP_QUEUE_INVALID);
		rc = odp_queue_context_set(globals->chaos_q[i].handle,
					   CHAOS_NDX_TO_PTR(i), 0);
		CU_ASSERT_FATAL(rc == 0);
	}

	/* Now populate the queues with the initial seed elements */
	for (i = 0; i < CHAOS_NUM_EVENTS; i++) {
		buf = odp_buffer_alloc(pool);
		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
		cbuf = odp_buffer_addr(buf);
		cbuf->evno = i;
		cbuf->seqno = 0;
		rc = odp_queue_enq(
			globals->chaos_q[i % CHAOS_NUM_QUEUES].handle,
			odp_buffer_to_event(buf));
		CU_ASSERT_FATAL(rc == 0);
	}

	/* Test runs also on the main thread */
	args->cu_thr.numthrds = globals->num_workers - 1;
	if (args->cu_thr.numthrds > 0)
		odp_cunit_thread_create(chaos_thread, &args->cu_thr);

	chaos_thread(args);

	if (args->cu_thr.numthrds > 0)
		odp_cunit_thread_exit(&args->cu_thr);

	if (CHAOS_DEBUG)
		printf("Thread %d returning from chaos threads..cleaning up\n",
		       odp_thread_id());

	for (i = 0; i < CHAOS_NUM_QUEUES; i++) {
		if (CHAOS_DEBUG)
			printf("Destroying queue %s\n",
			       globals->chaos_q[i].name);
		rc = odp_queue_destroy(globals->chaos_q[i].handle);
		CU_ASSERT(rc == 0);
	}

	rc = odp_pool_destroy(pool);
	CU_ASSERT(rc == 0);
}

static void scheduler_test_parallel(void)
{
	chaos_run(0);
}

static void scheduler_test_atomic(void)
{
	chaos_run(1);
}

static void scheduler_test_ordered(void)
{
	chaos_run(2);
}

static void scheduler_test_chaos(void)
{
	chaos_run(3);
}

static int schedule_common_(void *arg)
{
	thread_args_t *args = (thread_args_t *)arg;
	odp_schedule_sync_t sync;
	test_globals_t *globals;
	queue_context *qctx;
	buf_contents *bctx, *bctx_cpy;
	odp_pool_t pool;
	int locked;
	int num;
	odp_event_t ev;
	odp_buffer_t buf, buf_cpy;
	odp_queue_t from;

	globals = args->globals;
	sync = args->sync;

	pool = odp_pool_lookup(MSG_POOL_NAME);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	if (args->num_workers > 1)
		odp_barrier_wait(&globals->barrier);

	while (1) {
		from = ODP_QUEUE_INVALID;
		num = 0;

		odp_ticketlock_lock(&globals->lock);
		if (globals->buf_count == 0) {
			odp_ticketlock_unlock(&globals->lock);
			break;
		}
		odp_ticketlock_unlock(&globals->lock);

		if (args->enable_schd_multi) {
			odp_event_t events[BURST_BUF_SIZE],
				ev_cpy[BURST_BUF_SIZE];
			odp_buffer_t buf_cpy[BURST_BUF_SIZE];
			int j;

			num = odp_schedule_multi(&from, ODP_SCHED_NO_WAIT,
						 events, BURST_BUF_SIZE);
			CU_ASSERT(num >= 0);
			CU_ASSERT(num <= BURST_BUF_SIZE);
			if (num == 0)
				continue;

			if (sync == ODP_SCHED_SYNC_ORDERED) {
				uint32_t ndx;
				uint32_t ndx_max;
				int rc;

				ndx_max = odp_queue_lock_count(from);
				CU_ASSERT_FATAL(ndx_max > 0);

				qctx = odp_queue_context(from);

				for (j = 0; j < num; j++) {
					bctx = odp_buffer_addr(
						odp_buffer_from_event
						(events[j]));

					buf_cpy[j] = odp_buffer_alloc(pool);
					CU_ASSERT_FATAL(buf_cpy[j] !=
							ODP_BUFFER_INVALID);
					bctx_cpy = odp_buffer_addr(buf_cpy[j]);
					memcpy(bctx_cpy, bctx,
					       sizeof(buf_contents));
					bctx_cpy->output_sequence =
						bctx_cpy->sequence;
					ev_cpy[j] =
						odp_buffer_to_event(buf_cpy[j]);
				}

				rc = odp_queue_enq_multi(qctx->pq_handle,
							 ev_cpy, num);
				CU_ASSERT(rc == num);

				bctx = odp_buffer_addr(
					odp_buffer_from_event(events[0]));
				for (ndx = 0; ndx < ndx_max; ndx++) {
					odp_schedule_order_lock(ndx);
					CU_ASSERT(bctx->sequence ==
						  qctx->lock_sequence[ndx]);
					qctx->lock_sequence[ndx] += num;
					odp_schedule_order_unlock(ndx);
				}
			}

			for (j = 0; j < num; j++)
				odp_event_free(events[j]);
		} else {
			ev  = odp_schedule(&from, ODP_SCHED_NO_WAIT);
			if (ev == ODP_EVENT_INVALID)
				continue;

			buf = odp_buffer_from_event(ev);
			num = 1;
			if (sync == ODP_SCHED_SYNC_ORDERED) {
				uint32_t ndx;
				uint32_t ndx_max;
				int rc;

				ndx_max = odp_queue_lock_count(from);
				CU_ASSERT_FATAL(ndx_max > 0);

				qctx = odp_queue_context(from);
				bctx = odp_buffer_addr(buf);
				buf_cpy = odp_buffer_alloc(pool);
				CU_ASSERT_FATAL(buf_cpy != ODP_BUFFER_INVALID);
				bctx_cpy = odp_buffer_addr(buf_cpy);
				memcpy(bctx_cpy, bctx, sizeof(buf_contents));
				bctx_cpy->output_sequence = bctx_cpy->sequence;

				rc = odp_queue_enq(qctx->pq_handle,
						   odp_buffer_to_event
						   (buf_cpy));
				CU_ASSERT(rc == 0);

				for (ndx = 0; ndx < ndx_max; ndx++) {
					odp_schedule_order_lock(ndx);
					CU_ASSERT(bctx->sequence ==
						  qctx->lock_sequence[ndx]);
					qctx->lock_sequence[ndx] += num;
					odp_schedule_order_unlock(ndx);
				}
			}

			odp_buffer_free(buf);
		}

		if (args->enable_excl_atomic) {
			locked = odp_spinlock_trylock(&globals->atomic_lock);
			CU_ASSERT(locked != 0);
			CU_ASSERT(from != ODP_QUEUE_INVALID);
			if (locked) {
				int cnt;
				odp_time_t time = ODP_TIME_NULL;
				/* Do some work here to keep the thread busy */
				for (cnt = 0; cnt < 1000; cnt++)
					time = odp_time_sum(time,
							    odp_time_local());

				odp_spinlock_unlock(&globals->atomic_lock);
			}
		}

		release_context(sync);
		odp_ticketlock_lock(&globals->lock);

		globals->buf_count -= num;

		if (globals->buf_count < 0) {
			odp_ticketlock_unlock(&globals->lock);
			CU_FAIL_FATAL("Buffer counting failed");
		}

		odp_ticketlock_unlock(&globals->lock);
	}

	if (args->num_workers > 1)
		odp_barrier_wait(&globals->barrier);

	if (sync == ODP_SCHED_SYNC_ORDERED)
		locked = odp_ticketlock_trylock(&globals->lock);
	else
		locked = 0;

	if (locked && globals->buf_count_cpy > 0) {
		odp_event_t ev;
		odp_queue_t pq;
		uint64_t seq;
		uint64_t bcount = 0;
		int i, j;
		char name[32];
		uint64_t num_bufs = args->num_bufs;
		uint64_t buf_count = globals->buf_count_cpy;

		for (i = 0; i < args->num_prio; i++) {
			for (j = 0; j < args->num_queues; j++) {
				snprintf(name, sizeof(name),
					 "plain_%d_%d_o", i, j);
				pq = odp_queue_lookup(name);
				CU_ASSERT_FATAL(pq != ODP_QUEUE_INVALID);

				seq = 0;
				while (1) {
					ev = odp_queue_deq(pq);

					if (ev == ODP_EVENT_INVALID) {
						CU_ASSERT(seq == num_bufs);
						break;
					}

					bctx = odp_buffer_addr(
						odp_buffer_from_event(ev));

					CU_ASSERT(bctx->sequence == seq);
					seq++;
					bcount++;
					odp_event_free(ev);
				}
			}
		}
		CU_ASSERT(bcount == buf_count);
		globals->buf_count_cpy = 0;
	}

	if (locked)
		odp_ticketlock_unlock(&globals->lock);

	/* Clear scheduler atomic / ordered context between tests */
	CU_ASSERT(drain_queues() == 0);

	if (num)
		printf("\nDROPPED %i events\n\n", num);

	return 0;
}

static void fill_queues(thread_args_t *args)
{
	odp_schedule_sync_t sync;
	int num_queues, num_prio;
	odp_pool_t pool;
	int i, j, k;
	int buf_count = 0;
	test_globals_t *globals;
	char name[32];
	int ret;
	odp_buffer_t buf;
	odp_event_t ev;

	globals = args->globals;
	sync = args->sync;
	num_queues = args->num_queues;
	num_prio = args->num_prio;

	pool = odp_pool_lookup(MSG_POOL_NAME);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < num_prio; i++) {
		for (j = 0; j < num_queues; j++) {
			odp_queue_t queue;

			switch (sync) {
			case ODP_SCHED_SYNC_PARALLEL:
				snprintf(name, sizeof(name),
					 "sched_%d_%d_n", i, j);
				break;
			case ODP_SCHED_SYNC_ATOMIC:
				snprintf(name, sizeof(name),
					 "sched_%d_%d_a", i, j);
				break;
			case ODP_SCHED_SYNC_ORDERED:
				snprintf(name, sizeof(name),
					 "sched_%d_%d_o", i, j);
				break;
			default:
				CU_ASSERT_FATAL(0);
				break;
			}

			queue = odp_queue_lookup(name);
			CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

			for (k = 0; k < args->num_bufs; k++) {
				buf = odp_buffer_alloc(pool);
				CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
				ev = odp_buffer_to_event(buf);
				if (sync == ODP_SCHED_SYNC_ORDERED) {
					queue_context *qctx =
						odp_queue_context(queue);
					buf_contents *bctx =
						odp_buffer_addr(buf);
					bctx->sequence = qctx->sequence++;
				}

				ret = odp_queue_enq(queue, ev);
				CU_ASSERT_FATAL(ret == 0);

				if (ret)
					odp_buffer_free(buf);
				else
					buf_count++;
			}
		}
	}

	globals->buf_count = buf_count;
	globals->buf_count_cpy = buf_count;
}

static void reset_queues(thread_args_t *args)
{
	int i, j, k;
	int num_prio = args->num_prio;
	int num_queues = args->num_queues;
	char name[32];

	for (i = 0; i < num_prio; i++) {
		for (j = 0; j < num_queues; j++) {
			odp_queue_t queue;

			snprintf(name, sizeof(name),
				 "sched_%d_%d_o", i, j);
			queue = odp_queue_lookup(name);
			CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

			for (k = 0; k < args->num_bufs; k++) {
				queue_context *qctx =
					odp_queue_context(queue);
				uint32_t ndx;
				uint32_t ndx_max;

				ndx_max = odp_queue_lock_count(queue);
				CU_ASSERT_FATAL(ndx_max > 0);
				qctx->sequence = 0;
				for (ndx = 0; ndx < ndx_max; ndx++)
					qctx->lock_sequence[ndx] = 0;
			}
		}
	}
}

static void schedule_common(odp_schedule_sync_t sync, int num_queues,
			    int num_prio, int enable_schd_multi)
{
	thread_args_t args;
	odp_shm_t shm;
	test_globals_t *globals;

	shm = odp_shm_lookup(GLOBALS_SHM_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	globals = odp_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL_FATAL(globals);

	memset(&args, 0, sizeof(thread_args_t));
	args.globals = globals;
	args.sync = sync;
	args.num_queues = num_queues;
	args.num_prio = num_prio;
	args.num_bufs = BUFS_PER_QUEUE;
	args.num_workers = 1;
	args.enable_schd_multi = enable_schd_multi;
	args.enable_excl_atomic = 0;	/* Not needed with a single CPU */

	fill_queues(&args);

	schedule_common_(&args);
	if (sync == ODP_SCHED_SYNC_ORDERED)
		reset_queues(&args);
}

static void parallel_execute(odp_schedule_sync_t sync, int num_queues,
			     int num_prio, int enable_schd_multi,
			     int enable_excl_atomic)
{
	odp_shm_t shm;
	test_globals_t *globals;
	thread_args_t *args;

	shm = odp_shm_lookup(GLOBALS_SHM_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	globals = odp_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL_FATAL(globals);

	shm = odp_shm_lookup(SHM_THR_ARGS_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	args = odp_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL_FATAL(args);

	args->globals = globals;
	args->sync = sync;
	args->num_queues = num_queues;
	args->num_prio = num_prio;
	if (enable_excl_atomic)
		args->num_bufs = globals->max_sched_queue_size;
	else
		args->num_bufs = BUFS_PER_QUEUE;
	args->num_workers = globals->num_workers;
	args->enable_schd_multi = enable_schd_multi;
	args->enable_excl_atomic = enable_excl_atomic;

	fill_queues(args);

	/* Create and launch worker threads */

	/* Test runs also on the main thread */
	args->cu_thr.numthrds = globals->num_workers - 1;
	if (args->cu_thr.numthrds > 0)
		odp_cunit_thread_create(schedule_common_, &args->cu_thr);

	schedule_common_(args);

	/* Wait for worker threads to terminate */
	if (args->cu_thr.numthrds > 0)
		odp_cunit_thread_exit(&args->cu_thr);

	/* Cleanup ordered queues for next pass */
	if (sync == ODP_SCHED_SYNC_ORDERED)
		reset_queues(args);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_PARALLEL */
static void scheduler_test_1q_1t_n(void)
{
	schedule_common(ODP_SCHED_SYNC_PARALLEL, ONE_Q, ONE_PRIO, SCHD_ONE);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_ATOMIC */
static void scheduler_test_1q_1t_a(void)
{
	schedule_common(ODP_SCHED_SYNC_ATOMIC, ONE_Q, ONE_PRIO, SCHD_ONE);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_ORDERED */
static void scheduler_test_1q_1t_o(void)
{
	schedule_common(ODP_SCHED_SYNC_ORDERED, ONE_Q, ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread ODP_SCHED_SYNC_PARALLEL */
static void scheduler_test_mq_1t_n(void)
{
	/* Only one priority involved in these tests, but use
	   the same number of queues the more general case uses */
	schedule_common(ODP_SCHED_SYNC_PARALLEL, globals->queues_per_prio,
			ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ATOMIC */
static void scheduler_test_mq_1t_a(void)
{
	schedule_common(ODP_SCHED_SYNC_ATOMIC, globals->queues_per_prio,
			ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ORDERED */
static void scheduler_test_mq_1t_o(void)
{
	schedule_common(ODP_SCHED_SYNC_ORDERED, globals->queues_per_prio,
			ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_PARALLEL */
static void scheduler_test_mq_1t_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_PARALLEL, globals->queues_per_prio, prio,
			SCHD_ONE);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ATOMIC */
static void scheduler_test_mq_1t_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ATOMIC, globals->queues_per_prio, prio,
			SCHD_ONE);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ORDERED */
static void scheduler_test_mq_1t_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ORDERED, globals->queues_per_prio, prio,
			SCHD_ONE);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_PARALLEL */
static void scheduler_test_mq_mt_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_PARALLEL, globals->queues_per_prio,
			 prio, SCHD_ONE, DISABLE_EXCL_ATOMIC);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ATOMIC */
static void scheduler_test_mq_mt_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ATOMIC, globals->queues_per_prio, prio,
			 SCHD_ONE, DISABLE_EXCL_ATOMIC);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ORDERED */
static void scheduler_test_mq_mt_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ORDERED, globals->queues_per_prio, prio,
			 SCHD_ONE, DISABLE_EXCL_ATOMIC);
}

/* 1 queue many threads check exclusive access on ATOMIC queues */
static void scheduler_test_1q_mt_a_excl(void)
{
	parallel_execute(ODP_SCHED_SYNC_ATOMIC, ONE_Q, ONE_PRIO, SCHD_ONE,
			 ENABLE_EXCL_ATOMIC);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_PARALLEL multi */
static void scheduler_test_multi_1q_1t_n(void)
{
	schedule_common(ODP_SCHED_SYNC_PARALLEL, ONE_Q, ONE_PRIO, SCHD_MULTI);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_ATOMIC multi */
static void scheduler_test_multi_1q_1t_a(void)
{
	schedule_common(ODP_SCHED_SYNC_ATOMIC, ONE_Q, ONE_PRIO, SCHD_MULTI);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_ORDERED multi */
static void scheduler_test_multi_1q_1t_o(void)
{
	schedule_common(ODP_SCHED_SYNC_ORDERED, ONE_Q, ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread ODP_SCHED_SYNC_PARALLEL multi */
static void scheduler_test_multi_mq_1t_n(void)
{
	/* Only one priority involved in these tests, but use
	   the same number of queues the more general case uses */
	schedule_common(ODP_SCHED_SYNC_PARALLEL, globals->queues_per_prio,
			ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ATOMIC multi */
static void scheduler_test_multi_mq_1t_a(void)
{
	schedule_common(ODP_SCHED_SYNC_ATOMIC, globals->queues_per_prio,
			ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ORDERED multi */
static void scheduler_test_multi_mq_1t_o(void)
{
	schedule_common(ODP_SCHED_SYNC_ORDERED, globals->queues_per_prio,
			ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_PARALLEL multi */
static void scheduler_test_multi_mq_1t_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_PARALLEL, globals->queues_per_prio, prio,
			SCHD_MULTI);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ATOMIC multi */
static void scheduler_test_multi_mq_1t_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ATOMIC, globals->queues_per_prio, prio,
			SCHD_MULTI);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ORDERED multi */
static void scheduler_test_multi_mq_1t_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ORDERED, globals->queues_per_prio, prio,
			SCHD_MULTI);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_PARALLEL multi */
static void scheduler_test_multi_mq_mt_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_PARALLEL, globals->queues_per_prio,
			 prio, SCHD_MULTI, 0);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ATOMIC multi */
static void scheduler_test_multi_mq_mt_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ATOMIC, globals->queues_per_prio, prio,
			 SCHD_MULTI, 0);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ORDERED multi */
static void scheduler_test_multi_mq_mt_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ORDERED, globals->queues_per_prio, prio,
			 SCHD_MULTI, 0);
}

/* 1 queue many threads check exclusive access on ATOMIC queues multi */
static void scheduler_test_multi_1q_mt_a_excl(void)
{
	parallel_execute(ODP_SCHED_SYNC_ATOMIC, ONE_Q, ONE_PRIO, SCHD_MULTI,
			 ENABLE_EXCL_ATOMIC);
}

static void scheduler_test_pause_resume(void)
{
	odp_queue_t queue;
	odp_buffer_t buf;
	odp_event_t ev;
	odp_queue_t from;
	odp_pool_t pool;
	int i;
	int local_bufs = 0;
	int ret;

	queue = odp_queue_lookup("sched_0_0_n");
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	pool = odp_pool_lookup(MSG_POOL_NAME);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < NUM_BUFS_PAUSE; i++) {
		buf = odp_buffer_alloc(pool);
		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
		ev = odp_buffer_to_event(buf);
		ret = odp_queue_enq(queue, ev);
		CU_ASSERT_FATAL(ret == 0);
	}

	for (i = 0; i < NUM_BUFS_BEFORE_PAUSE; i++) {
		from = ODP_QUEUE_INVALID;
		ev = odp_schedule(&from, ODP_SCHED_WAIT);
		CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
		CU_ASSERT(from == queue);
		buf = odp_buffer_from_event(ev);
		odp_buffer_free(buf);
	}

	odp_schedule_pause();

	while (1) {
		ev = odp_schedule(&from, ODP_SCHED_NO_WAIT);
		if (ev == ODP_EVENT_INVALID)
			break;

		CU_ASSERT(from == queue);
		buf = odp_buffer_from_event(ev);
		odp_buffer_free(buf);
		local_bufs++;
	}

	CU_ASSERT(local_bufs <= NUM_BUFS_PAUSE - NUM_BUFS_BEFORE_PAUSE);

	odp_schedule_resume();

	for (i = local_bufs + NUM_BUFS_BEFORE_PAUSE; i < NUM_BUFS_PAUSE; i++) {
		ev = odp_schedule(&from, ODP_SCHED_WAIT);
		CU_ASSERT(from == queue);
		buf = odp_buffer_from_event(ev);
		odp_buffer_free(buf);
	}

	CU_ASSERT(drain_queues() == 0);
}

/* Basic, single threaded ordered lock API testing */
static void scheduler_test_ordered_lock(void)
{
	odp_queue_t queue;
	odp_buffer_t buf;
	odp_event_t ev;
	odp_queue_t from;
	odp_pool_t pool;
	int i;
	int ret;
	uint32_t lock_count;

	queue = odp_queue_lookup("sched_0_0_o");
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);
	CU_ASSERT_FATAL(odp_queue_type(queue) == ODP_QUEUE_TYPE_SCHED);
	CU_ASSERT_FATAL(odp_queue_sched_type(queue) == ODP_SCHED_SYNC_ORDERED);

	lock_count = odp_queue_lock_count(queue);

	if (lock_count == 0) {
		printf("  NO ORDERED LOCKS. Ordered locks not tested.\n");
		return;
	}

	pool = odp_pool_lookup(MSG_POOL_NAME);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < BUFS_PER_QUEUE; i++) {
		buf = odp_buffer_alloc(pool);
		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
		ev = odp_buffer_to_event(buf);
		ret = odp_queue_enq(queue, ev);
		CU_ASSERT(ret == 0);

		if (ret)
			odp_buffer_free(buf);
	}

	for (i = 0; i < BUFS_PER_QUEUE / 2; i++) {
		from = ODP_QUEUE_INVALID;
		ev = odp_schedule(&from, ODP_SCHED_WAIT);
		CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
		CU_ASSERT(from == queue);
		buf = odp_buffer_from_event(ev);
		odp_schedule_order_lock(0);
		odp_schedule_order_unlock(0);
		odp_buffer_free(buf);
	}

	if (lock_count < 2) {
		printf("  ONLY ONE ORDERED LOCK. Unlock_lock not tested.\n");
		CU_ASSERT(drain_queues() == BUFS_PER_QUEUE / 2);
		return;
	}

	for (i = 0; i < BUFS_PER_QUEUE / 2; i++) {
		from = ODP_QUEUE_INVALID;
		ev = odp_schedule(&from, ODP_SCHED_WAIT);
		CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
		CU_ASSERT(from == queue);
		buf = odp_buffer_from_event(ev);
		odp_schedule_order_lock(0);
		odp_schedule_order_unlock_lock(0, 1);
		odp_schedule_order_unlock(1);
		odp_buffer_free(buf);
	}

	CU_ASSERT(drain_queues() == 0);
}

static int create_queues(test_globals_t *globals)
{
	int i, j, prios, rc;
	odp_queue_capability_t queue_capa;
	odp_schedule_capability_t sched_capa;
	odp_schedule_config_t default_config;
	odp_pool_t queue_ctx_pool;
	odp_pool_param_t params;
	odp_buffer_t queue_ctx_buf;
	queue_context *qctx, *pqctx;
	uint32_t ndx;
	odp_queue_param_t p;
	unsigned int num_sched;
	unsigned int num_plain;
	int queues_per_prio;
	int sched_types;

	if (odp_queue_capability(&queue_capa) < 0) {
		printf("Queue capability query failed\n");
		return -1;
	}

	if (odp_schedule_capability(&sched_capa) < 0) {
		printf("Queue capability query failed\n");
		return -1;
	}

	/* Limit to test maximum */
	if (sched_capa.max_ordered_locks > MAX_ORDERED_LOCKS) {
		sched_capa.max_ordered_locks = MAX_ORDERED_LOCKS;
		printf("Testing only %u ordered locks\n",
		       sched_capa.max_ordered_locks);
	}

	globals->max_sched_queue_size = BUFS_PER_QUEUE_EXCL;
	odp_schedule_config_init(&default_config);
	if (default_config.queue_size &&
	    globals->max_sched_queue_size > default_config.queue_size) {
		printf("Max sched queue size %u\n", default_config.queue_size);
		globals->max_sched_queue_size = default_config.queue_size;
	}

	prios = odp_schedule_num_prio();

	/* Adjust 'queues_per_prio' until all required queues can be created */
	sched_types = 3;
	queues_per_prio = QUEUES_PER_PRIO;
	num_sched = (prios * queues_per_prio * sched_types) + CHAOS_NUM_QUEUES;
	num_plain = (prios * queues_per_prio);
	while ((num_sched > default_config.num_queues ||
		num_plain > queue_capa.plain.max_num ||
		num_sched + num_plain > queue_capa.max_queues) &&
		queues_per_prio) {
		queues_per_prio--;
		num_sched = (prios * queues_per_prio * sched_types) +
				CHAOS_NUM_QUEUES;
		num_plain = (prios * queues_per_prio);
	}
	if (!queues_per_prio) {
		printf("Not enough queues. At least %d scheduled queues and "
		       "%d plain queus required.\n",
		       ((prios * sched_types) + CHAOS_NUM_QUEUES), prios);
		return -1;
	}
	globals->queues_per_prio = queues_per_prio;

	odp_pool_param_init(&params);
	params.buf.size = sizeof(queue_context);
	params.buf.num  = prios * queues_per_prio * 2;
	params.type     = ODP_POOL_BUFFER;

	queue_ctx_pool = odp_pool_create(QUEUE_CTX_POOL_NAME, &params);

	if (queue_ctx_pool == ODP_POOL_INVALID) {
		printf("Pool creation failed (queue ctx).\n");
		return -1;
	}
	globals->queue_ctx_pool = queue_ctx_pool;

	for (i = 0; i < prios; i++) {
		odp_queue_param_init(&p);
		p.type        = ODP_QUEUE_TYPE_SCHED;
		p.sched.prio  = i;

		for (j = 0; j < queues_per_prio; j++) {
			/* Per sched sync type */
			char name[32];
			odp_queue_t q, pq;

			snprintf(name, sizeof(name), "sched_%d_%d_n", i, j);
			p.sched.sync = ODP_SCHED_SYNC_PARALLEL;
			q = odp_queue_create(name, &p);

			if (q == ODP_QUEUE_INVALID) {
				printf("Parallel queue create failed.\n");
				return -1;
			}

			snprintf(name, sizeof(name), "sched_%d_%d_a", i, j);
			p.sched.sync = ODP_SCHED_SYNC_ATOMIC;
			p.size = globals->max_sched_queue_size;
			q = odp_queue_create(name, &p);

			if (q == ODP_QUEUE_INVALID) {
				printf("Atomic queue create failed.\n");
				return -1;
			}

			snprintf(name, sizeof(name), "plain_%d_%d_o", i, j);
			pq = odp_queue_create(name, NULL);
			if (pq == ODP_QUEUE_INVALID) {
				printf("Plain queue create failed.\n");
				return -1;
			}

			queue_ctx_buf = odp_buffer_alloc(queue_ctx_pool);

			if (queue_ctx_buf == ODP_BUFFER_INVALID) {
				printf("Cannot allocate plain queue ctx buf\n");
				return -1;
			}

			pqctx = odp_buffer_addr(queue_ctx_buf);
			pqctx->ctx_handle = queue_ctx_buf;
			pqctx->sequence = 0;

			rc = odp_queue_context_set(pq, pqctx, 0);

			if (rc != 0) {
				printf("Cannot set plain queue context\n");
				return -1;
			}

			snprintf(name, sizeof(name), "sched_%d_%d_o", i, j);
			p.sched.sync = ODP_SCHED_SYNC_ORDERED;
			p.sched.lock_count = sched_capa.max_ordered_locks;
			p.size = 0;
			q = odp_queue_create(name, &p);

			if (q == ODP_QUEUE_INVALID) {
				printf("Ordered queue create failed.\n");
				return -1;
			}
			if (odp_queue_lock_count(q) !=
			    sched_capa.max_ordered_locks) {
				printf("Queue %" PRIu64 " created with "
				       "%d locks instead of expected %d\n",
				       odp_queue_to_u64(q),
				       odp_queue_lock_count(q),
				       sched_capa.max_ordered_locks);
				return -1;
			}

			queue_ctx_buf = odp_buffer_alloc(queue_ctx_pool);

			if (queue_ctx_buf == ODP_BUFFER_INVALID) {
				printf("Cannot allocate queue ctx buf\n");
				return -1;
			}

			qctx = odp_buffer_addr(queue_ctx_buf);
			qctx->ctx_handle = queue_ctx_buf;
			qctx->pq_handle = pq;
			qctx->sequence = 0;

			for (ndx = 0;
			     ndx < sched_capa.max_ordered_locks;
			     ndx++) {
				qctx->lock_sequence[ndx] = 0;
			}

			rc = odp_queue_context_set(q, qctx, 0);

			if (rc != 0) {
				printf("Cannot set queue context\n");
				return -1;
			}
		}
	}

	return 0;
}

static int scheduler_suite_init(void)
{
	odp_cpumask_t mask;
	odp_shm_t shm;
	odp_pool_t pool;
	thread_args_t *args;
	odp_pool_param_t params;
	uint64_t num_flows;
	odp_schedule_capability_t sched_capa;
	odp_schedule_config_t sched_config;

	if (odp_schedule_capability(&sched_capa)) {
		printf("odp_schedule_capability() failed\n");
		return -1;
	}

	num_flows = 0;
	odp_schedule_config_init(&sched_config);

	/* Enable flow aware scheduling */
	if (sched_capa.max_flow_id > 0) {
		num_flows = MAX_FLOWS;
		if ((MAX_FLOWS - 1) > sched_capa.max_flow_id)
			num_flows = sched_capa.max_flow_id + 1;

		sched_config.max_flow_id = num_flows - 1;
	}

	/* Configure the scheduler. All test cases share the config. */
	if (odp_schedule_config(&sched_config)) {
		printf("odp_schedule_config() failed.\n");
		return -1;
	}

	odp_pool_param_init(&params);
	params.buf.size  = BUF_SIZE;
	params.buf.align = 0;
	params.buf.num   = MSG_POOL_SIZE;
	params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create(MSG_POOL_NAME, &params);

	if (pool == ODP_POOL_INVALID) {
		printf("Pool creation failed (msg).\n");
		return -1;
	}

	shm = odp_shm_reserve(GLOBALS_SHM_NAME,
			      sizeof(test_globals_t), ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		printf("Shared memory reserve failed (globals).\n");
		return -1;
	}

	globals = odp_shm_addr(shm);

	if (!globals) {
		printf("Shared memory reserve failed (globals).\n");
		return -1;
	}

	memset(globals, 0, sizeof(test_globals_t));

	globals->num_flows = num_flows;

	globals->num_workers = odp_cpumask_default_worker(&mask, 0);
	if (globals->num_workers > MAX_WORKERS)
		globals->num_workers = MAX_WORKERS;

	shm = odp_shm_reserve(SHM_THR_ARGS_NAME, sizeof(thread_args_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		printf("Shared memory reserve failed (args).\n");
		return -1;
	}

	args = odp_shm_addr(shm);

	if (!args) {
		printf("Shared memory reserve failed (args).\n");
		return -1;
	}

	memset(args, 0, sizeof(thread_args_t));

	/* Barrier to sync test case execution */
	odp_barrier_init(&globals->barrier, globals->num_workers);
	odp_ticketlock_init(&globals->lock);
	odp_spinlock_init(&globals->atomic_lock);

	if (create_queues(globals) != 0)
		return -1;

	return 0;
}

static int destroy_queue(const char *name)
{
	odp_queue_t q;
	queue_context *qctx;

	q = odp_queue_lookup(name);

	if (q == ODP_QUEUE_INVALID)
		return -1;
	qctx = odp_queue_context(q);
	if (qctx)
		odp_buffer_free(qctx->ctx_handle);

	return odp_queue_destroy(q);
}

static int destroy_queues(void)
{
	int i, j, prios;

	prios = odp_schedule_num_prio();

	for (i = 0; i < prios; i++) {
		for (j = 0; j < globals->queues_per_prio; j++) {
			char name[32];

			snprintf(name, sizeof(name), "sched_%d_%d_n", i, j);
			if (destroy_queue(name) != 0)
				return -1;

			snprintf(name, sizeof(name), "sched_%d_%d_a", i, j);
			if (destroy_queue(name) != 0)
				return -1;

			snprintf(name, sizeof(name), "sched_%d_%d_o", i, j);
			if (destroy_queue(name) != 0)
				return -1;

			snprintf(name, sizeof(name), "plain_%d_%d_o", i, j);
			if (destroy_queue(name) != 0)
				return -1;
		}
	}

	if (odp_pool_destroy(globals->queue_ctx_pool) != 0) {
		fprintf(stderr, "error: failed to destroy queue ctx pool\n");
		return -1;
	}

	return 0;
}

static int scheduler_suite_term(void)
{
	odp_pool_t pool;
	odp_shm_t shm;

	if (destroy_queues() != 0) {
		fprintf(stderr, "error: failed to destroy queues\n");
		return -1;
	}

	pool = odp_pool_lookup(MSG_POOL_NAME);
	if (odp_pool_destroy(pool) != 0)
		fprintf(stderr, "error: failed to destroy pool\n");

	shm = odp_shm_lookup(SHM_THR_ARGS_NAME);
	if (odp_shm_free(shm) != 0)
		fprintf(stderr, "error: failed to free shm\n");

	shm = odp_shm_lookup(GLOBALS_SHM_NAME);
	if (odp_shm_free(shm) != 0)
		fprintf(stderr, "error: failed to free shm\n");

	if (odp_cunit_print_inactive())
		return -1;

	return 0;
}

static int check_flow_aware_support(void)
{
	if (globals->num_flows == 0) {
		printf("\nTest: scheduler_test_flow_aware: SKIPPED\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

static void scheduler_test_flow_aware(void)
{
	odp_schedule_capability_t sched_capa;
	odp_schedule_config_t sched_config;
	odp_pool_param_t pool_param;
	odp_pool_t pool;
	odp_queue_param_t queue_param;
	odp_queue_t queue, from;
	uint32_t j, queue_size, num, num_flows, flow_id;
	odp_buffer_t buf;
	odp_event_t ev;
	int i, ret;
	uint32_t flow_stat[MAX_FLOWS];
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_PARALLEL,
				      ODP_SCHED_SYNC_ATOMIC,
				      ODP_SCHED_SYNC_ORDERED};

	/* Test should be skipped when no flows */
	CU_ASSERT_FATAL(globals->num_flows);
	CU_ASSERT_FATAL(odp_schedule_capability(&sched_capa) == 0);

	num_flows = globals->num_flows;

	queue_size = FLOW_TEST_NUM_EV;
	odp_schedule_config_init(&sched_config);
	if (sched_config.queue_size &&
	    queue_size > sched_config.queue_size)
		queue_size = sched_config.queue_size;

	odp_pool_param_init(&pool_param);
	pool_param.buf.size  = 100;
	pool_param.buf.align = 0;
	pool_param.buf.num   = FLOW_TEST_NUM_EV;
	pool_param.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("test_flow_aware", &pool_param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < 3; i++) {
		memset(flow_stat, 0, sizeof(flow_stat));
		flow_id = 0;

		odp_queue_param_init(&queue_param);
		queue_param.type = ODP_QUEUE_TYPE_SCHED;
		queue_param.sched.prio  = odp_schedule_default_prio();
		queue_param.sched.sync  = sync[i];
		queue_param.sched.group = ODP_SCHED_GROUP_ALL;
		queue_param.size = queue_size;

		queue = odp_queue_create("test_flow_aware", &queue_param);

		CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

		for (j = 0; j < queue_size; j++) {
			buf = odp_buffer_alloc(pool);
			CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

			ev = odp_buffer_to_event(buf);

			odp_event_flow_id_set(ev, flow_id);
			CU_ASSERT(odp_event_flow_id(ev) == flow_id);

			ret = odp_queue_enq(queue, ev);
			CU_ASSERT(ret == 0);

			if (ret) {
				odp_event_free(ev);
				continue;
			}

			flow_stat[flow_id]++;

			flow_id++;
			if (flow_id == num_flows)
				flow_id = 0;
		}

		num = 0;
		for (j = 0; j < 100 * FLOW_TEST_NUM_EV; j++) {
			ev = odp_schedule(&from, ODP_SCHED_NO_WAIT);

			if (ev == ODP_EVENT_INVALID)
				continue;

			CU_ASSERT(from == queue);

			flow_id = odp_event_flow_id(ev);
			flow_stat[flow_id]--;

			odp_event_free(ev);
			num++;
		}

		CU_ASSERT(num == queue_size);

		for (j = 0; j < num_flows; j++) {
			CU_ASSERT(flow_stat[j] == 0);
			if (flow_stat[j])
				printf("flow id %" PRIu32 ", missing %" PRIi32
				       " events\n", j, flow_stat[j]);
		}

		drain_queues();
		CU_ASSERT_FATAL(odp_queue_destroy(queue) == 0);
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

/* Default scheduler config */
odp_testinfo_t scheduler_suite[] = {
	ODP_TEST_INFO(scheduler_test_capa),
	ODP_TEST_INFO(scheduler_test_wait_time),
	ODP_TEST_INFO(scheduler_test_num_prio),
	ODP_TEST_INFO(scheduler_test_queue_destroy),
	ODP_TEST_INFO(scheduler_test_wait),
	ODP_TEST_INFO(scheduler_test_queue_size),
	ODP_TEST_INFO(scheduler_test_order_ignore),
	ODP_TEST_INFO(scheduler_test_groups),
	ODP_TEST_INFO(scheduler_test_pause_resume),
	ODP_TEST_INFO(scheduler_test_ordered_lock),
	ODP_TEST_INFO_CONDITIONAL(scheduler_test_flow_aware,
				  check_flow_aware_support),
	ODP_TEST_INFO(scheduler_test_parallel),
	ODP_TEST_INFO(scheduler_test_atomic),
	ODP_TEST_INFO(scheduler_test_ordered),
	ODP_TEST_INFO(scheduler_test_chaos),
	ODP_TEST_INFO(scheduler_test_1q_1t_n),
	ODP_TEST_INFO(scheduler_test_1q_1t_a),
	ODP_TEST_INFO(scheduler_test_1q_1t_o),
	ODP_TEST_INFO(scheduler_test_mq_1t_n),
	ODP_TEST_INFO(scheduler_test_mq_1t_a),
	ODP_TEST_INFO(scheduler_test_mq_1t_o),
	ODP_TEST_INFO(scheduler_test_mq_1t_prio_n),
	ODP_TEST_INFO(scheduler_test_mq_1t_prio_a),
	ODP_TEST_INFO(scheduler_test_mq_1t_prio_o),
	ODP_TEST_INFO(scheduler_test_mq_mt_prio_n),
	ODP_TEST_INFO(scheduler_test_mq_mt_prio_a),
	ODP_TEST_INFO(scheduler_test_mq_mt_prio_o),
	ODP_TEST_INFO(scheduler_test_1q_mt_a_excl),
	ODP_TEST_INFO(scheduler_test_multi_1q_1t_n),
	ODP_TEST_INFO(scheduler_test_multi_1q_1t_a),
	ODP_TEST_INFO(scheduler_test_multi_1q_1t_o),
	ODP_TEST_INFO(scheduler_test_multi_mq_1t_n),
	ODP_TEST_INFO(scheduler_test_multi_mq_1t_a),
	ODP_TEST_INFO(scheduler_test_multi_mq_1t_o),
	ODP_TEST_INFO(scheduler_test_multi_mq_1t_prio_n),
	ODP_TEST_INFO(scheduler_test_multi_mq_1t_prio_a),
	ODP_TEST_INFO(scheduler_test_multi_mq_1t_prio_o),
	ODP_TEST_INFO(scheduler_test_multi_mq_mt_prio_n),
	ODP_TEST_INFO(scheduler_test_multi_mq_mt_prio_a),
	ODP_TEST_INFO(scheduler_test_multi_mq_mt_prio_o),
	ODP_TEST_INFO(scheduler_test_multi_1q_mt_a_excl),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t scheduler_suites[] = {
	{"Scheduler",
	 scheduler_suite_init, scheduler_suite_term, scheduler_suite
	},
	ODP_SUITE_INFO_NULL,
};

static int global_init(odp_instance_t *inst)
{
	odp_init_t init_param;
	odph_helper_options_t helper_options;

	if (odph_options(&helper_options)) {
		fprintf(stderr, "error: odph_options() failed.\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (0 != odp_init_global(inst, &init_param, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}

	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	odp_cunit_register_global_init(global_init);
	ret = odp_cunit_register(scheduler_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

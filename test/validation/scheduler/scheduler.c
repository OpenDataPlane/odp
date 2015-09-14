/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include "odp_cunit_common.h"
#include "scheduler.h"

#define MAX_WORKERS_THREADS	32
#define MSG_POOL_SIZE		(4 * 1024 * 1024)
#define QUEUES_PER_PRIO		16
#define BUF_SIZE		64
#define TEST_NUM_BUFS		100
#define BURST_BUF_SIZE		4
#define NUM_BUFS_EXCL		10000
#define NUM_BUFS_PAUSE		1000
#define NUM_BUFS_BEFORE_PAUSE	10

#define GLOBALS_SHM_NAME	"test_globals"
#define MSG_POOL_NAME		"msg_pool"
#define QUEUE_CTX_POOL_NAME     "queue_ctx_pool"
#define SHM_MSG_POOL_NAME	"shm_msg_pool"
#define SHM_THR_ARGS_NAME	"shm_thr_args"

#define ONE_Q			1
#define MANY_QS			QUEUES_PER_PRIO

#define ONE_PRIO		1

#define SCHD_ONE		0
#define SCHD_MULTI		1

#define DISABLE_EXCL_ATOMIC	0
#define ENABLE_EXCL_ATOMIC	1

#define MAGIC                   0xdeadbeef
#define MAGIC1                  0xdeadbeef
#define MAGIC2                  0xcafef00d

/* Test global variables */
typedef struct {
	int num_workers;
	odp_barrier_t barrier;
	int buf_count;
	odp_ticketlock_t lock;
	odp_spinlock_t atomic_lock;
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
	uint64_t lock_sequence[ODP_CONFIG_MAX_ORDERED_LOCKS_PER_QUEUE];
} buf_contents;

typedef struct {
	odp_buffer_t ctx_handle;
	uint64_t sequence;
	uint64_t lock_sequence[ODP_CONFIG_MAX_ORDERED_LOCKS_PER_QUEUE];
} queue_context;

odp_pool_t pool;
odp_pool_t queue_ctx_pool;

static int exit_schedule_loop(void)
{
	odp_event_t ev;
	int ret = 0;

	odp_schedule_pause();

	while ((ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT))
	      != ODP_EVENT_INVALID) {
		odp_event_free(ev);
		ret++;
	}

	return ret;
}

void scheduler_test_wait_time(void)
{
	uint64_t wait_time;

	wait_time = odp_schedule_wait_time(0);
	wait_time = odp_schedule_wait_time(1);

	wait_time = odp_schedule_wait_time((uint64_t)-1LL);
	CU_ASSERT(wait_time > 0);
}

void scheduler_test_num_prio(void)
{
	int prio;

	prio = odp_schedule_num_prio();

	CU_ASSERT(prio > 0);
	CU_ASSERT(prio == odp_schedule_num_prio());
}

void scheduler_test_queue_destroy(void)
{
	odp_pool_t p;
	odp_pool_param_t params;
	odp_queue_param_t qp;
	odp_queue_t queue, from;
	odp_buffer_t buf;
	odp_event_t ev;
	uint32_t *u32;
	int i;
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_NONE,
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
		qp.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qp.sched.sync  = sync[i];

		queue = odp_queue_create("sched_destroy_queue",
					 ODP_QUEUE_TYPE_SCHED, &qp);

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
		odp_schedule_release_ordered();

		CU_ASSERT_FATAL(odp_queue_destroy(queue) == 0);
	}

	CU_ASSERT_FATAL(odp_pool_destroy(p) == 0);
}

void scheduler_test_groups(void)
{
	odp_pool_t p;
	odp_pool_param_t params;
	odp_queue_param_t qp;
	odp_queue_t queue_grp1, queue_grp2, from;
	odp_buffer_t buf;
	odp_event_t ev;
	uint32_t *u32;
	int i, j, rc;
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_NONE,
				      ODP_SCHED_SYNC_ATOMIC,
				      ODP_SCHED_SYNC_ORDERED};
	int thr_id = odp_thread_id();
	odp_thrmask_t zeromask, mymask, testmask;
	odp_schedule_group_t mygrp1, mygrp2, lookup;

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

	/* We shouldn't be able to find our second group before creating it */
	lookup = odp_schedule_group_lookup("Test Group 2");
	CU_ASSERT(lookup == ODP_SCHED_GROUP_INVALID);

	/* Now create it and verify we can find it */
	mygrp2 = odp_schedule_group_create("Test Group 2", &zeromask);
	CU_ASSERT_FATAL(mygrp2 != ODP_SCHED_GROUP_INVALID);

	lookup = odp_schedule_group_lookup("Test Group 2");
	CU_ASSERT(lookup == mygrp2);

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

	/* Now verify scheduler adherence to groups */
	odp_queue_param_init(&qp);
	odp_pool_param_init(&params);
	params.buf.size  = 100;
	params.buf.align = 0;
	params.buf.num   = 2;
	params.type      = ODP_POOL_BUFFER;

	p = odp_pool_create("sched_group_pool", &params);

	CU_ASSERT_FATAL(p != ODP_POOL_INVALID);

	for (i = 0; i < 3; i++) {
		qp.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qp.sched.sync  = sync[i];
		qp.sched.group = mygrp1;

		/* Create and populate a group in group 1 */
		queue_grp1 = odp_queue_create("sched_group_test_queue_1",
					      ODP_QUEUE_TYPE_SCHED, &qp);
		CU_ASSERT_FATAL(queue_grp1 != ODP_QUEUE_INVALID);
		CU_ASSERT_FATAL(odp_queue_sched_group(queue_grp1) == mygrp1);

		buf = odp_buffer_alloc(p);

		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

		u32 = odp_buffer_addr(buf);
		u32[0] = MAGIC1;

		ev = odp_buffer_to_event(buf);
		if (!(CU_ASSERT(odp_queue_enq(queue_grp1, ev) == 0)))
			odp_buffer_free(buf);

		/* Now create and populate a queue in group 2 */
		qp.sched.group = mygrp2;
		queue_grp2 = odp_queue_create("sched_group_test_queue_2",
					      ODP_QUEUE_TYPE_SCHED, &qp);
		CU_ASSERT_FATAL(queue_grp2 != ODP_QUEUE_INVALID);
		CU_ASSERT_FATAL(odp_queue_sched_group(queue_grp2) == mygrp2);

		buf = odp_buffer_alloc(p);
		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

		u32 = odp_buffer_addr(buf);
		u32[0] = MAGIC2;

		ev = odp_buffer_to_event(buf);
		if (!(CU_ASSERT(odp_queue_enq(queue_grp2, ev) == 0)))
			odp_buffer_free(buf);

		/* Scheduler should give us the event from Group 2 */
		ev = odp_schedule(&from, ODP_SCHED_WAIT);
		CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
		CU_ASSERT_FATAL(from == queue_grp2);

		buf = odp_buffer_from_event(ev);
		u32 = odp_buffer_addr(buf);

		CU_ASSERT_FATAL(u32[0] == MAGIC2);

		odp_buffer_free(buf);

		/* Scheduler should not return anything now since we're
		 * not in Group 1 and Queue 2 is empty.  Do this several
		 * times to confirm.
		 */

		for (j = 0; j < 10; j++) {
			ev = odp_schedule(&from, ODP_SCHED_NO_WAIT);
			CU_ASSERT_FATAL(ev == ODP_EVENT_INVALID)
		}

		/* Now join group 1 and verify we can get the event */
		rc = odp_schedule_group_join(mygrp1, &mymask);
		CU_ASSERT_FATAL(rc == 0);

		/* Tell scheduler we're about to request an event.
		 * Not needed, but a convenient place to test this API.
		 */
		odp_schedule_prefetch(1);

		/* Now get the event from Queue 1 */
		ev = odp_schedule(&from, ODP_SCHED_WAIT);
		CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
		CU_ASSERT_FATAL(from == queue_grp1);

		buf = odp_buffer_from_event(ev);
		u32 = odp_buffer_addr(buf);

		CU_ASSERT_FATAL(u32[0] == MAGIC1);

		odp_buffer_free(buf);

		/* Leave group 1 for next pass */
		rc = odp_schedule_group_leave(mygrp1, &mymask);
		CU_ASSERT_FATAL(rc == 0);

		/* We must release order before destroying queues */
		odp_schedule_release_ordered();

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

static void *schedule_common_(void *arg)
{
	thread_args_t *args = (thread_args_t *)arg;
	odp_schedule_sync_t sync;
	test_globals_t *globals;
	queue_context *qctx;
	buf_contents *bctx;

	globals = args->globals;
	sync = args->sync;

	if (args->num_workers > 1)
		odp_barrier_wait(&globals->barrier);

	while (1) {
		odp_event_t ev;
		odp_buffer_t buf;
		odp_queue_t from = ODP_QUEUE_INVALID;
		int num = 0;
		int locked;

		odp_ticketlock_lock(&globals->lock);
		if (globals->buf_count == 0) {
			odp_ticketlock_unlock(&globals->lock);
			break;
		}
		odp_ticketlock_unlock(&globals->lock);

		if (args->enable_schd_multi) {
			odp_event_t events[BURST_BUF_SIZE];
			int j;
			num = odp_schedule_multi(&from, ODP_SCHED_NO_WAIT,
						 events, BURST_BUF_SIZE);
			CU_ASSERT(num >= 0);
			CU_ASSERT(num <= BURST_BUF_SIZE);
			if (num == 0)
				continue;

			if (sync == ODP_SCHED_SYNC_ORDERED) {
				uint32_t ndx;
				uint32_t ndx_max = odp_queue_lock_count(from);

				qctx = odp_queue_context(from);
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
			buf = odp_buffer_from_event(ev);
			if (buf == ODP_BUFFER_INVALID)
				continue;
			num = 1;
			if (sync == ODP_SCHED_SYNC_ORDERED) {
				uint32_t ndx;
				uint32_t ndx_max = odp_queue_lock_count(from);

				qctx = odp_queue_context(from);
				bctx = odp_buffer_addr(buf);

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
			CU_ASSERT(locked == 1);
			CU_ASSERT(from != ODP_QUEUE_INVALID);
			if (locked) {
				int cnt;
				uint64_t cycles = 0;
				/* Do some work here to keep the thread busy */
				for (cnt = 0; cnt < 1000; cnt++)
					cycles += odp_time_cycles();

				odp_spinlock_unlock(&globals->atomic_lock);
			}
		}

		if (sync == ODP_SCHED_SYNC_ATOMIC)
			odp_schedule_release_atomic();

		if (sync == ODP_SCHED_SYNC_ORDERED)
			odp_schedule_release_ordered();

		odp_ticketlock_lock(&globals->lock);
		globals->buf_count -= num;

		if (globals->buf_count < 0) {
			odp_ticketlock_unlock(&globals->lock);
			CU_FAIL_FATAL("Buffer counting failed");
		}

		odp_ticketlock_unlock(&globals->lock);
	}

	return NULL;
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
			case ODP_SCHED_SYNC_NONE:
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
				CU_ASSERT(0);
				break;
			}

			queue = odp_queue_lookup(name);
			CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

			for (k = 0; k < args->num_bufs; k++) {
				odp_buffer_t buf;
				odp_event_t ev;
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
				if (!(CU_ASSERT(odp_queue_enq(queue, ev) == 0)))
					odp_buffer_free(buf);
				else
					buf_count++;
			}
		}
	}

	globals->buf_count = buf_count;
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
				uint32_t ndx_max =
					odp_queue_lock_count(queue);
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

	args.globals = globals;
	args.sync = sync;
	args.num_queues = num_queues;
	args.num_prio = num_prio;
	args.num_bufs = TEST_NUM_BUFS;
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
		args->num_bufs = NUM_BUFS_EXCL;
	else
		args->num_bufs = TEST_NUM_BUFS;
	args->num_workers = globals->num_workers;
	args->enable_schd_multi = enable_schd_multi;
	args->enable_excl_atomic = enable_excl_atomic;

	fill_queues(args);

	/* Create and launch worker threads */
	args->cu_thr.numthrds = globals->num_workers;
	odp_cunit_thread_create(schedule_common_, &args->cu_thr);

	/* Wait for worker threads to terminate */
	odp_cunit_thread_exit(&args->cu_thr);

	/* Cleanup ordered queues for next pass */
	if (sync == ODP_SCHED_SYNC_ORDERED)
		reset_queues(args);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_NONE */
void scheduler_test_1q_1t_n(void)
{
	schedule_common(ODP_SCHED_SYNC_NONE, ONE_Q, ONE_PRIO, SCHD_ONE);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_ATOMIC */
void scheduler_test_1q_1t_a(void)
{
	schedule_common(ODP_SCHED_SYNC_ATOMIC, ONE_Q, ONE_PRIO, SCHD_ONE);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_ORDERED */
void scheduler_test_1q_1t_o(void)
{
	schedule_common(ODP_SCHED_SYNC_ORDERED, ONE_Q, ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread ODP_SCHED_SYNC_NONE */
void scheduler_test_mq_1t_n(void)
{
	/* Only one priority involved in these tests, but use
	   the same number of queues the more general case uses */
	schedule_common(ODP_SCHED_SYNC_NONE, MANY_QS, ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ATOMIC */
void scheduler_test_mq_1t_a(void)
{
	schedule_common(ODP_SCHED_SYNC_ATOMIC, MANY_QS, ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ORDERED */
void scheduler_test_mq_1t_o(void)
{
	schedule_common(ODP_SCHED_SYNC_ORDERED, MANY_QS, ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_NONE */
void scheduler_test_mq_1t_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_NONE, MANY_QS, prio, SCHD_ONE);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ATOMIC */
void scheduler_test_mq_1t_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ATOMIC, MANY_QS, prio, SCHD_ONE);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ORDERED */
void scheduler_test_mq_1t_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ORDERED, MANY_QS, prio, SCHD_ONE);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_NONE */
void scheduler_test_mq_mt_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_NONE, MANY_QS, prio, SCHD_ONE,
			 DISABLE_EXCL_ATOMIC);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ATOMIC */
void scheduler_test_mq_mt_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ATOMIC, MANY_QS, prio, SCHD_ONE,
			 DISABLE_EXCL_ATOMIC);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ORDERED */
void scheduler_test_mq_mt_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ORDERED, MANY_QS, prio, SCHD_ONE,
			 DISABLE_EXCL_ATOMIC);
}

/* 1 queue many threads check exclusive access on ATOMIC queues */
void scheduler_test_1q_mt_a_excl(void)
{
	parallel_execute(ODP_SCHED_SYNC_ATOMIC, ONE_Q, ONE_PRIO, SCHD_ONE,
			 ENABLE_EXCL_ATOMIC);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_NONE multi */
void scheduler_test_multi_1q_1t_n(void)
{
	schedule_common(ODP_SCHED_SYNC_NONE, ONE_Q, ONE_PRIO, SCHD_MULTI);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_ATOMIC multi */
void scheduler_test_multi_1q_1t_a(void)
{
	schedule_common(ODP_SCHED_SYNC_ATOMIC, ONE_Q, ONE_PRIO, SCHD_MULTI);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_ORDERED multi */
void scheduler_test_multi_1q_1t_o(void)
{
	schedule_common(ODP_SCHED_SYNC_ORDERED, ONE_Q, ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread ODP_SCHED_SYNC_NONE multi */
void scheduler_test_multi_mq_1t_n(void)
{
	/* Only one priority involved in these tests, but use
	   the same number of queues the more general case uses */
	schedule_common(ODP_SCHED_SYNC_NONE, MANY_QS, ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ATOMIC multi */
void scheduler_test_multi_mq_1t_a(void)
{
	schedule_common(ODP_SCHED_SYNC_ATOMIC, MANY_QS, ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ORDERED multi */
void scheduler_test_multi_mq_1t_o(void)
{
	schedule_common(ODP_SCHED_SYNC_ORDERED, MANY_QS, ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_NONE multi */
void scheduler_test_multi_mq_1t_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_NONE, MANY_QS, prio, SCHD_MULTI);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ATOMIC multi */
void scheduler_test_multi_mq_1t_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ATOMIC, MANY_QS, prio, SCHD_MULTI);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ORDERED multi */
void scheduler_test_multi_mq_1t_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ORDERED, MANY_QS, prio, SCHD_MULTI);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_NONE multi */
void scheduler_test_multi_mq_mt_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_NONE, MANY_QS, prio, SCHD_MULTI, 0);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ATOMIC multi */
void scheduler_test_multi_mq_mt_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ATOMIC, MANY_QS, prio, SCHD_MULTI, 0);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ORDERED multi */
void scheduler_test_multi_mq_mt_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ORDERED, MANY_QS, prio, SCHD_MULTI, 0);
}

/* 1 queue many threads check exclusive access on ATOMIC queues multi */
void scheduler_test_multi_1q_mt_a_excl(void)
{
	parallel_execute(ODP_SCHED_SYNC_ATOMIC, ONE_Q, ONE_PRIO, SCHD_MULTI,
			 ENABLE_EXCL_ATOMIC);
}

void scheduler_test_pause_resume(void)
{
	odp_queue_t queue;
	odp_buffer_t buf;
	odp_event_t ev;
	odp_queue_t from;
	int i;
	int local_bufs = 0;

	queue = odp_queue_lookup("sched_0_0_n");
	CU_ASSERT(queue != ODP_QUEUE_INVALID);

	pool = odp_pool_lookup(MSG_POOL_NAME);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < NUM_BUFS_PAUSE; i++) {
		buf = odp_buffer_alloc(pool);
		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
		ev = odp_buffer_to_event(buf);
		if (odp_queue_enq(queue, ev))
			odp_buffer_free(buf);
	}

	for (i = 0; i < NUM_BUFS_BEFORE_PAUSE; i++) {
		from = ODP_QUEUE_INVALID;
		ev = odp_schedule(&from, ODP_SCHED_WAIT);
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

	CU_ASSERT(local_bufs < NUM_BUFS_PAUSE - NUM_BUFS_BEFORE_PAUSE);

	odp_schedule_resume();

	for (i = local_bufs + NUM_BUFS_BEFORE_PAUSE; i < NUM_BUFS_PAUSE; i++) {
		ev = odp_schedule(&from, ODP_SCHED_WAIT);
		CU_ASSERT(from == queue);
		buf = odp_buffer_from_event(ev);
		odp_buffer_free(buf);
	}

	CU_ASSERT(exit_schedule_loop() == 0);
}

static int create_queues(void)
{
	int i, j, prios, rc;
	odp_pool_param_t params;
	odp_buffer_t queue_ctx_buf;
	queue_context *qctx;
	uint32_t ndx;

	prios = odp_schedule_num_prio();
	odp_pool_param_init(&params);
	params.buf.size = sizeof(queue_context);
	params.buf.num  = prios * QUEUES_PER_PRIO;
	params.type     = ODP_POOL_BUFFER;

	queue_ctx_pool = odp_pool_create(QUEUE_CTX_POOL_NAME, &params);

	if (queue_ctx_pool == ODP_POOL_INVALID) {
		printf("Pool creation failed (queue ctx).\n");
		return -1;
	}

	for (i = 0; i < prios; i++) {
		odp_queue_param_t p;
		odp_queue_param_init(&p);
		p.sched.prio  = i;

		for (j = 0; j < QUEUES_PER_PRIO; j++) {
			/* Per sched sync type */
			char name[32];
			odp_queue_t q;

			snprintf(name, sizeof(name), "sched_%d_%d_n", i, j);
			p.sched.sync = ODP_SCHED_SYNC_NONE;
			q = odp_queue_create(name, ODP_QUEUE_TYPE_SCHED, &p);

			if (q == ODP_QUEUE_INVALID) {
				printf("Schedule queue create failed.\n");
				return -1;
			}

			snprintf(name, sizeof(name), "sched_%d_%d_a", i, j);
			p.sched.sync = ODP_SCHED_SYNC_ATOMIC;
			q = odp_queue_create(name, ODP_QUEUE_TYPE_SCHED, &p);

			if (q == ODP_QUEUE_INVALID) {
				printf("Schedule queue create failed.\n");
				return -1;
			}

			snprintf(name, sizeof(name), "sched_%d_%d_o", i, j);
			p.sched.sync = ODP_SCHED_SYNC_ORDERED;
			p.sched.lock_count =
				ODP_CONFIG_MAX_ORDERED_LOCKS_PER_QUEUE;
			q = odp_queue_create(name, ODP_QUEUE_TYPE_SCHED, &p);

			if (q == ODP_QUEUE_INVALID) {
				printf("Schedule queue create failed.\n");
				return -1;
			}
			if (odp_queue_lock_count(q) !=
			    ODP_CONFIG_MAX_ORDERED_LOCKS_PER_QUEUE) {
				printf("Queue %" PRIu64 " created with "
				       "%d locks instead of expected %d\n",
				       odp_queue_to_u64(q),
				       odp_queue_lock_count(q),
				       ODP_CONFIG_MAX_ORDERED_LOCKS_PER_QUEUE);
				return -1;
			}

			queue_ctx_buf = odp_buffer_alloc(queue_ctx_pool);

			if (queue_ctx_buf == ODP_BUFFER_INVALID) {
				printf("Cannot allocate queue ctx buf\n");
				return -1;
			}

			qctx = odp_buffer_addr(queue_ctx_buf);
			qctx->ctx_handle = queue_ctx_buf;
			qctx->sequence = 0;

			for (ndx = 0;
			     ndx < ODP_CONFIG_MAX_ORDERED_LOCKS_PER_QUEUE;
			     ndx++) {
				qctx->lock_sequence[ndx] = 0;
			}

			rc = odp_queue_context_set(q, qctx);

			if (rc != 0) {
				printf("Cannot set queue context\n");
				return -1;
			}
		}
	}

	return 0;
}

int scheduler_suite_init(void)
{
	odp_cpumask_t mask;
	odp_shm_t shm;
	odp_pool_t pool;
	test_globals_t *globals;
	thread_args_t *args;
	odp_pool_param_t params;

	odp_pool_param_init(&params);
	params.buf.size  = BUF_SIZE;
	params.buf.align = 0;
	params.buf.num   = MSG_POOL_SIZE / BUF_SIZE;
	params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create(MSG_POOL_NAME, &params);

	if (pool == ODP_POOL_INVALID) {
		printf("Pool creation failed (msg).\n");
		return -1;
	}

	shm = odp_shm_reserve(GLOBALS_SHM_NAME,
			      sizeof(test_globals_t), ODP_CACHE_LINE_SIZE, 0);

	globals = odp_shm_addr(shm);

	if (!globals) {
		printf("Shared memory reserve failed (globals).\n");
		return -1;
	}

	memset(globals, 0, sizeof(test_globals_t));

	globals->num_workers = odp_cpumask_default_worker(&mask, 0);
	if (globals->num_workers > MAX_WORKERS)
		globals->num_workers = MAX_WORKERS;

	shm = odp_shm_reserve(SHM_THR_ARGS_NAME, sizeof(thread_args_t),
			      ODP_CACHE_LINE_SIZE, 0);
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

	if (create_queues() != 0)
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
		for (j = 0; j < QUEUES_PER_PRIO; j++) {
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
		}
	}

	if (odp_pool_destroy(queue_ctx_pool) != 0)
		return -1;

	return 0;
}

int scheduler_suite_term(void)
{
	odp_pool_t pool;

	if (destroy_queues() != 0) {
		fprintf(stderr, "error: failed to destroy queues\n");
		return -1;
	}

	pool = odp_pool_lookup(MSG_POOL_NAME);
	if (odp_pool_destroy(pool) != 0)
		fprintf(stderr, "error: failed to destroy pool\n");

	return 0;
}

CU_TestInfo scheduler_suite[] = {
	_CU_TEST_INFO(scheduler_test_wait_time),
	_CU_TEST_INFO(scheduler_test_num_prio),
	_CU_TEST_INFO(scheduler_test_queue_destroy),
	_CU_TEST_INFO(scheduler_test_groups),
	_CU_TEST_INFO(scheduler_test_1q_1t_n),
	_CU_TEST_INFO(scheduler_test_1q_1t_a),
	_CU_TEST_INFO(scheduler_test_1q_1t_o),
	_CU_TEST_INFO(scheduler_test_mq_1t_n),
	_CU_TEST_INFO(scheduler_test_mq_1t_a),
	_CU_TEST_INFO(scheduler_test_mq_1t_o),
	_CU_TEST_INFO(scheduler_test_mq_1t_prio_n),
	_CU_TEST_INFO(scheduler_test_mq_1t_prio_a),
	_CU_TEST_INFO(scheduler_test_mq_1t_prio_o),
	_CU_TEST_INFO(scheduler_test_mq_mt_prio_n),
	_CU_TEST_INFO(scheduler_test_mq_mt_prio_a),
	_CU_TEST_INFO(scheduler_test_mq_mt_prio_o),
	_CU_TEST_INFO(scheduler_test_1q_mt_a_excl),
	_CU_TEST_INFO(scheduler_test_multi_1q_1t_n),
	_CU_TEST_INFO(scheduler_test_multi_1q_1t_a),
	_CU_TEST_INFO(scheduler_test_multi_1q_1t_o),
	_CU_TEST_INFO(scheduler_test_multi_mq_1t_n),
	_CU_TEST_INFO(scheduler_test_multi_mq_1t_a),
	_CU_TEST_INFO(scheduler_test_multi_mq_1t_o),
	_CU_TEST_INFO(scheduler_test_multi_mq_1t_prio_n),
	_CU_TEST_INFO(scheduler_test_multi_mq_1t_prio_a),
	_CU_TEST_INFO(scheduler_test_multi_mq_1t_prio_o),
	_CU_TEST_INFO(scheduler_test_multi_mq_mt_prio_n),
	_CU_TEST_INFO(scheduler_test_multi_mq_mt_prio_a),
	_CU_TEST_INFO(scheduler_test_multi_mq_mt_prio_o),
	_CU_TEST_INFO(scheduler_test_multi_1q_mt_a_excl),
	_CU_TEST_INFO(scheduler_test_pause_resume),
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo scheduler_suites[] = {
	{"Scheduler",
	 scheduler_suite_init, scheduler_suite_term, NULL, NULL, scheduler_suite
	},
	CU_SUITE_INFO_NULL,
};

int scheduler_main(void)
{
	return odp_cunit_run(scheduler_suites);
}

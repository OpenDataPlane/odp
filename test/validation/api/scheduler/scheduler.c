/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2019-2024 Nokia
 */

#include <odp_api.h>
#include "odp_cunit_common.h"
#include <odp/helper/odph_api.h>

#define MAX_WORKERS             32
#define MAX_ORDERED_LOCKS       2
#define MAX_POOL_SIZE		(1024 * 1024)
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

#define WAIT_TIMEOUT     (100 * ODP_TIME_MSEC_IN_NS)
#define WAIT_ROUNDS      5
#define WAIT_TOLERANCE   (15 * ODP_TIME_MSEC_IN_NS)
#define WAIT_1MS_RETRIES 1000

#define SCHED_AND_PLAIN_ROUNDS 10000
#define ATOMICITY_ROUNDS 100

#define FIFO_MAX_EVENTS  151

/* Test global variables */
typedef struct {
	int num_workers;
	odp_barrier_t barrier;
	int buf_count;
	int buf_count_cpy;
	int queues_per_prio;
	int test_debug_print;
	odp_shm_t shm_glb;
	odp_shm_t shm_args;
	odp_pool_t pool;
	odp_pool_t queue_ctx_pool;
	uint32_t max_sched_queue_size;
	uint64_t num_flows;
	odp_ticketlock_t lock;
	odp_spinlock_t atomic_lock;
	struct {
		odp_queue_t handle;
		odp_atomic_u32_t state;
	} atomicity_q;
	struct {
		odp_queue_t handle;
		char name[ODP_QUEUE_NAME_LEN];
	} chaos_q[CHAOS_NUM_QUEUES];
	struct {
		odp_queue_t sched;
		odp_queue_t plain;
	} sched_and_plain_q;
	struct {
		odp_atomic_u32_t helper_ready;
		odp_atomic_u32_t helper_active;
	} order_wait;
	struct {
		odp_barrier_t barrier;
		int multi;
		odp_queue_t queue;
		odp_pool_t pool;
		uint32_t num_events;
		uint32_t num_enq;
		uint32_t burst;
		odp_atomic_u32_t cur_thr;
		uint16_t num_thr;
		odp_event_t event[FIFO_MAX_EVENTS];
	} fifo;

} test_globals_t;

typedef struct {
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

static void test_init(uint8_t fill)
{
	odp_schedule_config_t default_config;

	memset(&default_config, fill, sizeof(default_config));
	odp_schedule_config_init(&default_config);

	CU_ASSERT(default_config.max_flow_id == 0);

	CU_ASSERT(default_config.sched_group.all);
	CU_ASSERT(default_config.sched_group.control);
	CU_ASSERT(default_config.sched_group.worker);
}

static void scheduler_test_init(void)
{
	test_init(0);
	test_init(0xff);
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

static void sched_queue_param_init(odp_queue_param_t *param)
{
	odp_queue_param_init(param);
	param->type        = ODP_QUEUE_TYPE_SCHED;
	param->sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	param->sched.prio  = odp_schedule_default_prio();
	param->sched.group = ODP_SCHED_GROUP_ALL;
}

static void scheduler_test_wait_time(void)
{
	int i;
	odp_queue_t queue;
	odp_event_t ev;
	uint64_t wait_time;
	odp_queue_param_t qp;
	odp_time_t lower_limit, upper_limit;
	odp_time_t start_time, end_time, diff;
	uint64_t duration_ns = WAIT_ROUNDS * WAIT_TIMEOUT;

	/* check on read */
	wait_time = odp_schedule_wait_time(0);
	wait_time = odp_schedule_wait_time(1);

	/* check ODP_SCHED_NO_WAIT */
	sched_queue_param_init(&qp);
	queue = odp_queue_create("dummy_queue", &qp);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	wait_time = odp_schedule_wait_time(WAIT_TIMEOUT);
	start_time = odp_time_local();
	ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
	end_time = odp_time_local();
	CU_ASSERT_FATAL(ev == ODP_EVENT_INVALID);

	diff = odp_time_diff(end_time, start_time);
	lower_limit = ODP_TIME_NULL;
	upper_limit = odp_time_local_from_ns(WAIT_TOLERANCE);

	CU_ASSERT(odp_time_cmp(diff, lower_limit) >= 0);
	CU_ASSERT(odp_time_cmp(diff, upper_limit) <= 0);

	/* check time correctness */
	printf("\nTesting wait time for %.3f sec ...\n", (double)duration_ns / ODP_TIME_SEC_IN_NS);
	start_time = odp_time_local();
	for (i = 0; i < WAIT_ROUNDS; i++) {
		ev = odp_schedule(NULL, wait_time);
		CU_ASSERT_FATAL(ev == ODP_EVENT_INVALID);
	}
	end_time = odp_time_local();

	diff = odp_time_diff(end_time, start_time);
	lower_limit = odp_time_local_from_ns(duration_ns - WAIT_TOLERANCE);
	upper_limit = odp_time_local_from_ns(duration_ns + WAIT_TOLERANCE);

	if (odp_time_cmp(diff, lower_limit) <= 0) {
		ODPH_ERR("Exceed lower limit: diff is %" PRIu64 ", lower_limit %" PRIu64 "\n",
			 odp_time_to_ns(diff), odp_time_to_ns(lower_limit));
		CU_FAIL("Exceed lower limit\n");
	}

	if (odp_time_cmp(diff, upper_limit) >= 0) {
		ODPH_ERR("Exceed upper limit: diff is %" PRIu64 ", upper_limit %" PRIu64 "\n",
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
	int i, ret;
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_PARALLEL,
				      ODP_SCHED_SYNC_ATOMIC,
				      ODP_SCHED_SYNC_ORDERED};

	odp_pool_param_init(&params);
	params.buf.size  = 100;
	params.buf.align = 0;
	params.buf.num   = 1;
	params.type      = ODP_POOL_BUFFER;

	p = odp_pool_create("sched_destroy_pool", &params);

	CU_ASSERT_FATAL(p != ODP_POOL_INVALID);

	sched_queue_param_init(&qp);

	for (i = 0; i < 3; i++) {
		qp.sched.sync = sync[i];
		queue = odp_queue_create("sched_destroy_queue", &qp);

		CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

		buf = odp_buffer_alloc(p);

		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

		u32 = odp_buffer_addr(buf);
		u32[0] = MAGIC;

		ev = odp_buffer_to_event(buf);

		ret = odp_queue_enq(queue, ev);
		CU_ASSERT(ret == 0);
		if (ret)
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

	sched_queue_param_init(&queue_param);
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
			ret = odp_queue_enq(queue, ev);
			CU_ASSERT(ret == 0);
			if (ret) {
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

		sched_queue_param_init(&queue_param);
		queue_param.sched.sync  = sync[i];
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

static void scheduler_test_full_queues(void)
{
	odp_schedule_config_t default_config;
	odp_pool_t pool;
	odp_pool_capability_t pool_capa;
	odp_pool_param_t pool_param;
	odp_schedule_capability_t sched_capa;
	odp_queue_param_t queue_param;
	odp_event_t ev;
	uint32_t i, j, k, num_bufs, events_per_queue, num_queues;
	uint32_t queue_size = 2048;
	int ret;
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_PARALLEL,
				      ODP_SCHED_SYNC_ATOMIC,
				      ODP_SCHED_SYNC_ORDERED};

	CU_ASSERT_FATAL(!odp_schedule_capability(&sched_capa));
	if (sched_capa.max_queue_size && queue_size > sched_capa.max_queue_size)
		queue_size = sched_capa.max_queue_size;

	/* Scheduler has been already configured. Use default config as queue
	 * size and queue count. */
	odp_schedule_config_init(&default_config);
	if (default_config.queue_size)
		queue_size = default_config.queue_size;
	num_queues = default_config.num_queues;

	odp_queue_t queue[num_queues];

	CU_ASSERT_FATAL(!odp_pool_capability(&pool_capa));
	num_bufs = num_queues * queue_size;
	if (pool_capa.buf.max_num && num_bufs > pool_capa.buf.max_num)
		num_bufs = pool_capa.buf.max_num;
	if (num_bufs > MAX_POOL_SIZE)
		num_bufs = MAX_POOL_SIZE;
	events_per_queue = num_bufs / num_queues;

	/* Make sure there is at least one event for each queue */
	while (events_per_queue == 0) {
		num_queues--;
		events_per_queue = num_bufs / num_queues;
	}

	odp_pool_param_init(&pool_param);
	pool_param.buf.size  = 100;
	pool_param.buf.align = 0;
	pool_param.buf.num   = num_bufs;
	pool_param.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("test_full_queues", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	/* Ensure that scheduler is empty */
	drain_queues();

	/* Run test for each scheduler synchronization type */
	for (i = 0; i < 3; i++) {
		uint64_t wait_time;
		uint32_t num_enq = 0;
		uint32_t num = 0;

		/* Create and fill all queues */
		for (j = 0; j < num_queues; j++) {
			sched_queue_param_init(&queue_param);
			queue_param.sched.sync  = sync[i];
			queue_param.size = events_per_queue;

			queue[j] = odp_queue_create("test_full_queues",
						    &queue_param);
			CU_ASSERT_FATAL(queue[j] != ODP_QUEUE_INVALID);

			for (k = 0; k < events_per_queue; k++) {
				odp_buffer_t buf = odp_buffer_alloc(pool);

				CU_ASSERT(buf != ODP_BUFFER_INVALID);
				if (buf == ODP_BUFFER_INVALID)
					continue;

				ev = odp_buffer_to_event(buf);
				ret = odp_queue_enq(queue[j], ev);
				CU_ASSERT(ret == 0);
				if (ret) {
					odp_event_free(ev);
					continue;
				}
				num_enq++;
			}
		}
		/* Run normal scheduling rounds */
		wait_time = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);
		for (j = 0; j < num_bufs; j++) {
			odp_queue_t src_queue;

			ev = odp_schedule(&src_queue, wait_time);
			if (ev == ODP_EVENT_INVALID)
				continue;

			ret = odp_queue_enq(src_queue, ev);
			CU_ASSERT(ret == 0);
			if (ret) {
				odp_event_free(ev);
				num_enq--;
			}
		}
		/* Clean-up */
		wait_time = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);
		for (j = 0; j < num_enq; j++) {
			ev = odp_schedule(NULL, wait_time);

			if (ev == ODP_EVENT_INVALID)
				continue;

			odp_event_free(ev);
			num++;
		}

		CU_ASSERT(num == num_enq);
		CU_ASSERT(drain_queues() == 0);

		for (j = 0; j < num_queues; j++)
			CU_ASSERT_FATAL(odp_queue_destroy(queue[j]) == 0);
	}
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void scheduler_test_max_queues(odp_schedule_sync_t sync)
{
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	odp_schedule_capability_t sched_capa;
	odp_queue_param_t queue_param;
	odp_buffer_t buf;
	odp_event_t ev;
	odp_queue_t src_queue;
	uint64_t wait_time;
	uint32_t i, src_idx;
	uint32_t num_rounds = 4;
	uint32_t num_queues = 64 * 1024;

	CU_ASSERT_FATAL(odp_schedule_capability(&sched_capa) == 0);
	if (num_queues > sched_capa.max_queues)
		num_queues = sched_capa.max_queues;

	CU_ASSERT_FATAL(num_queues > 0);

	odp_queue_t queue[num_queues];

	odp_pool_param_init(&pool_param);
	pool_param.type      = ODP_POOL_BUFFER;
	pool_param.buf.size  = 100;
	pool_param.buf.num   = 1;

	pool = odp_pool_create("test_max_queues", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	/* Ensure that scheduler is empty */
	drain_queues();

	sched_queue_param_init(&queue_param);
	queue_param.sched.sync = sync;

	for (i = 0; i < num_queues; i++) {
		queue[i] = odp_queue_create("test_max_queues", &queue_param);
		if (queue[i] == ODP_QUEUE_INVALID)
			ODPH_ERR("Queue create failed %u/%u\n", i, num_queues);

		CU_ASSERT_FATAL(queue[i] != ODP_QUEUE_INVALID);
	}

	buf = odp_buffer_alloc(pool);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
	ev = odp_buffer_to_event(buf);

	CU_ASSERT_FATAL(odp_queue_enq(queue[0], ev) == 0);

	wait_time = odp_schedule_wait_time(500 * ODP_TIME_MSEC_IN_NS);
	src_idx = 0;

	/* Send one event through all queues couple of times */
	for (i = 0; i < (num_rounds * num_queues); i++) {
		uint32_t round = i / num_queues;

		ev = odp_schedule(&src_queue, wait_time);
		if (ev == ODP_EVENT_INVALID) {
			ODPH_ERR("Event was lost. Round %u, queue idx %u\n", round, src_idx);
			CU_FAIL("Event was lost\n");
			break;
		}

		CU_ASSERT(src_queue == queue[src_idx]);

		src_idx++;
		if (src_idx == num_queues)
			src_idx = 0;

		if (odp_queue_enq(queue[src_idx], ev)) {
			ODPH_ERR("Enqueue failed. Round %u, queue idx %u\n", round, src_idx);
			CU_FAIL("Enqueue failed\n")
			odp_event_free(ev);
			break;
		}
	}

	/* Free event and scheduling context */
	for (i = 0; i < 2; i++) {
		ev = odp_schedule(NULL, wait_time);

		if (ev == ODP_EVENT_INVALID)
			continue;

		odp_event_free(ev);
	}

	CU_ASSERT(drain_queues() == 0);

	for (i = 0; i < num_queues; i++)
		CU_ASSERT_FATAL(odp_queue_destroy(queue[i]) == 0);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void scheduler_test_max_queues_p(void)
{
	scheduler_test_max_queues(ODP_SCHED_SYNC_PARALLEL);
}

static void scheduler_test_max_queues_a(void)
{
	scheduler_test_max_queues(ODP_SCHED_SYNC_ATOMIC);
}

static void scheduler_test_max_queues_o(void)
{
	scheduler_test_max_queues(ODP_SCHED_SYNC_ORDERED);
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

	sched_queue_param_init(&queue_param);
	queue_param.sched.sync = ODP_SCHED_SYNC_ORDERED;

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

static void scheduler_test_group_info_predef(void)
{
	odp_schedule_group_info_t info;
	odp_thrmask_t thrmask;
	odp_schedule_group_t group;
	int thr;

	thr = odp_thread_id();

	group = ODP_SCHED_GROUP_ALL;
	odp_thrmask_zero(&thrmask);
	CU_ASSERT(odp_schedule_group_thrmask(group, &thrmask) == 0);
	CU_ASSERT(odp_thrmask_isset(&thrmask, thr));
	memset(&info, 0, sizeof(odp_schedule_group_info_t));
	CU_ASSERT(odp_schedule_group_info(group, &info) == 0);
	CU_ASSERT(odp_thrmask_equal(&info.thrmask, &thrmask));
	printf("\n    Schedule group all name: %s\n", info.name);

	/* This test case runs a control thread */
	group = ODP_SCHED_GROUP_CONTROL;
	odp_thrmask_zero(&thrmask);
	CU_ASSERT(odp_schedule_group_thrmask(group, &thrmask) == 0);
	CU_ASSERT(odp_thrmask_isset(&thrmask, thr));
	memset(&info, 0, sizeof(odp_schedule_group_info_t));
	CU_ASSERT(odp_schedule_group_info(group, &info) == 0);
	CU_ASSERT(odp_thrmask_equal(&info.thrmask, &thrmask));
	printf("    Schedule group control name: %s\n", info.name);

	group = ODP_SCHED_GROUP_WORKER;
	odp_thrmask_zero(&thrmask);
	CU_ASSERT(odp_schedule_group_thrmask(group, &thrmask) == 0);
	CU_ASSERT(!odp_thrmask_isset(&thrmask, thr));
	memset(&info, 0, sizeof(odp_schedule_group_info_t));
	CU_ASSERT(odp_schedule_group_info(group, &info) == 0);
	CU_ASSERT(odp_thrmask_equal(&info.thrmask, &thrmask));
	printf("    Schedule group worker name: %s\n", info.name);
}

static void scheduler_test_create_group(void)
{
	odp_thrmask_t mask;
	odp_schedule_group_t group;
	int thr_id;
	odp_pool_t pool;
	odp_pool_param_t pool_params;
	odp_queue_t queue, from;
	odp_queue_param_t qp;
	odp_buffer_t buf;
	odp_event_t ev;
	uint64_t wait_time;

	thr_id = odp_thread_id();
	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr_id);

	group = odp_schedule_group_create("create_group", &mask);
	CU_ASSERT_FATAL(group != ODP_SCHED_GROUP_INVALID);

	odp_pool_param_init(&pool_params);
	pool_params.buf.size  = 100;
	pool_params.buf.num   = 2;
	pool_params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("create_group", &pool_params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	sched_queue_param_init(&qp);
	qp.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qp.sched.group = group;

	queue = odp_queue_create("create_group", &qp);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	buf = odp_buffer_alloc(pool);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

	ev = odp_buffer_to_event(buf);

	CU_ASSERT_FATAL(odp_queue_enq(queue, ev) == 0);

	wait_time = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);
	ev = odp_schedule(&from, wait_time);

	CU_ASSERT(ev != ODP_EVENT_INVALID);
	CU_ASSERT(from == queue);

	if (ev != ODP_EVENT_INVALID)
		odp_event_free(ev);

	/* Free schedule context */
	drain_queues();

	CU_ASSERT_FATAL(odp_queue_destroy(queue) == 0);
	CU_ASSERT_FATAL(odp_pool_destroy(pool) == 0);
	CU_ASSERT_FATAL(odp_schedule_group_destroy(group) == 0);

	/* Run scheduler after the group has been destroyed */
	CU_ASSERT_FATAL(odp_schedule(NULL, wait_time) == ODP_EVENT_INVALID);
}

static void scheduler_test_create_max_groups(void)
{
	odp_thrmask_t mask;
	int thr_id;
	uint32_t i;
	odp_queue_param_t queue_param;
	odp_schedule_capability_t sched_capa;

	CU_ASSERT_FATAL(!odp_schedule_capability(&sched_capa));
	uint32_t max_groups = sched_capa.max_groups - 3; /* Enabled predefined groups */
	odp_schedule_group_t group[max_groups];
	odp_queue_t queue[max_groups];

	CU_ASSERT_FATAL(max_groups > 0);
	CU_ASSERT_FATAL(sched_capa.max_queues >= sched_capa.max_groups);

	thr_id = odp_thread_id();
	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr_id);

	sched_queue_param_init(&queue_param);
	queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

	for (i = 0; i < max_groups; i++) {
		group[i] = odp_schedule_group_create("max_groups", &mask);
		if (group[i] == ODP_SCHED_GROUP_INVALID) {
			ODPH_ERR("schedule group create %u failed\n", i);
			break;
		}

		queue_param.sched.group = group[i];
		queue[i] = odp_queue_create("max_groups", &queue_param);
		CU_ASSERT_FATAL(queue[i] != ODP_QUEUE_INVALID);
	}

	CU_ASSERT(i == max_groups);
	max_groups = i;

	for (i = 0; i < max_groups; i++) {
		CU_ASSERT_FATAL(odp_queue_destroy(queue[i]) == 0);
		CU_ASSERT_FATAL(odp_schedule_group_destroy(group[i]) == 0);
	}
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
	mygrp2 = odp_schedule_group_create("Test Group 2", &mymask);
	CU_ASSERT_FATAL(mygrp2 != ODP_SCHED_GROUP_INVALID);

	lookup = odp_schedule_group_lookup("Test Group 2");
	CU_ASSERT(lookup == mygrp2);

	/* Destroy group with no name */
	CU_ASSERT_FATAL(odp_schedule_group_destroy(null_grp) == 0);

	/* Verify we're part of group 2 */
	rc = odp_schedule_group_thrmask(mygrp2, &testmask);
	CU_ASSERT(rc == 0);
	CU_ASSERT(odp_thrmask_isset(&testmask, thr_id));

	/* Leave group 2 */
	rc = odp_schedule_group_leave(mygrp2, &mymask);
	CU_ASSERT(rc == 0);

	/* Verify we're not part of group 2 anymore */
	rc = odp_schedule_group_thrmask(mygrp2, &testmask);
	CU_ASSERT(rc == 0);
	CU_ASSERT(!odp_thrmask_isset(&testmask, thr_id));

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

		sched_queue_param_init(&qp);
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

		/* Release scheduler context and leave groups */
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
	void *arg_ptr;
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_PARALLEL,
				      ODP_SCHED_SYNC_ATOMIC,
				      ODP_SCHED_SYNC_ORDERED};
	const unsigned int num_sync = ODPH_ARRAY_SIZE(sync);
	const char *const qtypes[] = {"parallel", "atomic", "ordered"};

	/* Set up the scheduling environment */
	shm = odp_shm_lookup(GLOBALS_SHM_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	globals = odp_shm_addr(shm);
	CU_ASSERT_FATAL(globals != NULL);

	shm = odp_shm_lookup(SHM_THR_ARGS_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	args = odp_shm_addr(shm);
	CU_ASSERT_FATAL(args != NULL);

	args->globals = globals;

	odp_pool_param_init(&params);
	params.buf.size = sizeof(chaos_buf);
	params.buf.align = 0;
	params.buf.num = CHAOS_NUM_EVENTS;
	params.type = ODP_POOL_BUFFER;

	pool = odp_pool_create("sched_chaos_pool", &params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	sched_queue_param_init(&qp);

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

	arg_ptr = args;
	odp_cunit_thread_create(globals->num_workers, chaos_thread, &arg_ptr, 0, 0);

	odp_cunit_thread_join(globals->num_workers);

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
	odp_buffer_t buf;
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

			for (j = 0; j < num; j++) {
				CU_ASSERT(odp_event_is_valid(events[j]) == 1);
				odp_event_free(events[j]);
			}
		} else {
			odp_event_t ev = odp_schedule(&from, ODP_SCHED_NO_WAIT);

			if (ev == ODP_EVENT_INVALID)
				continue;

			CU_ASSERT(odp_event_is_valid(ev) == 1);
			buf = odp_buffer_from_event(ev);
			num = 1;
			if (sync == ODP_SCHED_SYNC_ORDERED) {
				uint32_t ndx;
				uint32_t ndx_max;
				int rc;
				odp_buffer_t buf_cpy;

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
	CU_ASSERT_FATAL(globals != NULL);

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
	void *arg_ptr;

	shm = odp_shm_lookup(GLOBALS_SHM_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	globals = odp_shm_addr(shm);
	CU_ASSERT_FATAL(globals != NULL);

	shm = odp_shm_lookup(SHM_THR_ARGS_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	args = odp_shm_addr(shm);
	CU_ASSERT_FATAL(args != NULL);

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

	if (globals->test_debug_print)
		odp_schedule_print();

	/* Create and launch worker threads */
	arg_ptr = args;
	odp_cunit_thread_create(globals->num_workers, schedule_common_, &arg_ptr, 0, 0);

	/* Wait for worker threads to terminate */
	odp_cunit_thread_join(globals->num_workers);

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
	odp_queue_param_t qp;
	odp_queue_t queue;
	odp_buffer_t buf;
	odp_event_t ev;
	odp_queue_t from;
	odp_pool_t pool;
	int i;
	int local_bufs = 0;
	int ret;

	sched_queue_param_init(&qp);
	queue = odp_queue_create("pause_resume", &qp);
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
	CU_ASSERT(odp_queue_destroy(queue) == 0);
}

static void scheduler_test_pause_enqueue(void)
{
	odp_queue_param_t qp;
	odp_queue_t queue;
	odp_buffer_t buf;
	odp_event_t ev;
	odp_event_t ev_tbl[NUM_BUFS_BEFORE_PAUSE];
	odp_queue_t from;
	odp_pool_t pool;
	int i;
	int ret;
	int local_bufs;

	sched_queue_param_init(&qp);
	queue = odp_queue_create("pause_enqueue", &qp);
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
		ev_tbl[i] = ev;
	}

	/* Pause, enqueue, schedule, resume */
	odp_schedule_pause();

	for (i = 0; i < NUM_BUFS_BEFORE_PAUSE; i++) {
		ev = ev_tbl[i];
		ret = odp_queue_enq(queue, ev);
		CU_ASSERT_FATAL(ret == 0);
	}

	local_bufs = 0;
	while (1) {
		from = ODP_QUEUE_INVALID;
		ev = odp_schedule(&from, ODP_SCHED_NO_WAIT);
		if (ev == ODP_EVENT_INVALID)
			break;

		CU_ASSERT(from == queue);
		ret = odp_queue_enq(queue, ev);
		CU_ASSERT_FATAL(ret == 0);

		local_bufs++;
		CU_ASSERT_FATAL(local_bufs <= NUM_BUFS_PAUSE);
	}

	odp_schedule_resume();

	for (i = 0; i < NUM_BUFS_BEFORE_PAUSE; i++) {
		from = ODP_QUEUE_INVALID;
		ev = odp_schedule(&from, ODP_SCHED_WAIT);
		CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
		CU_ASSERT(from == queue);
		ev_tbl[i] = ev;
	}

	/* Pause, schedule, enqueue, resume */
	odp_schedule_pause();

	local_bufs = 0;
	while (1) {
		from = ODP_QUEUE_INVALID;
		ev = odp_schedule(&from, ODP_SCHED_NO_WAIT);
		if (ev == ODP_EVENT_INVALID)
			break;

		CU_ASSERT(from == queue);
		ret = odp_queue_enq(queue, ev);
		CU_ASSERT_FATAL(ret == 0);

		local_bufs++;
		CU_ASSERT_FATAL(local_bufs <= NUM_BUFS_PAUSE - NUM_BUFS_BEFORE_PAUSE);
	}

	for (i = 0; i < NUM_BUFS_BEFORE_PAUSE; i++) {
		ev = ev_tbl[i];
		ret = odp_queue_enq(queue, ev);
		CU_ASSERT_FATAL(ret == 0);
	}

	odp_schedule_resume();

	/* Free all */
	CU_ASSERT(drain_queues() == NUM_BUFS_PAUSE);
	CU_ASSERT(odp_queue_destroy(queue) == 0);
}

/* Basic, single threaded ordered lock API testing */
static void scheduler_test_ordered_lock(void)
{
	odp_queue_param_t qp;
	odp_queue_t queue;
	odp_buffer_t buf;
	odp_event_t ev;
	odp_queue_t from;
	odp_pool_t pool;
	int i;
	int ret;
	uint32_t lock_count;
	odp_schedule_capability_t sched_capa;

	CU_ASSERT_FATAL(!odp_schedule_capability(&sched_capa));

	sched_queue_param_init(&qp);
	qp.sched.sync = ODP_SCHED_SYNC_ORDERED;
	qp.sched.lock_count = sched_capa.max_ordered_locks;

	queue = odp_queue_create("ordered_lock", &qp);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);
	CU_ASSERT_FATAL(odp_queue_type(queue) == ODP_QUEUE_TYPE_SCHED);
	CU_ASSERT_FATAL(odp_queue_sched_type(queue) == ODP_SCHED_SYNC_ORDERED);

	lock_count = odp_queue_lock_count(queue);

	if (lock_count == 0) {
		printf("  NO ORDERED LOCKS. Ordered locks not tested.\n");
		CU_ASSERT(odp_queue_destroy(queue) == 0);
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
		CU_ASSERT(odp_queue_destroy(queue) == 0);
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
	CU_ASSERT(odp_queue_destroy(queue) == 0);
}

static void enqueue_event(odp_queue_t queue)
{
	odp_pool_t pool;
	odp_buffer_t buf;
	odp_event_t ev;
	int ret;

	pool = odp_pool_lookup(MSG_POOL_NAME);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	buf = odp_buffer_alloc(pool);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
	ev = odp_buffer_to_event(buf);
	ret = odp_queue_enq(queue, ev);
	CU_ASSERT_FATAL(ret == 0);
}

static void scheduler_test_order_wait_1_thread(void)
{
	odp_queue_param_t queue_param;
	odp_queue_t queue;
	odp_event_t ev;

	sched_queue_param_init(&queue_param);
	queue_param.sched.sync = ODP_SCHED_SYNC_ORDERED;
	queue = odp_queue_create("ordered queue", &queue_param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);
	CU_ASSERT_FATAL(odp_queue_type(queue) == ODP_QUEUE_TYPE_SCHED);
	CU_ASSERT_FATAL(odp_queue_sched_type(queue) == ODP_SCHED_SYNC_ORDERED);

	/* Set up an ordered scheduling context */
	enqueue_event(queue);
	ev = odp_schedule(NULL, ODP_SCHED_WAIT);
	CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
	odp_event_free(ev);

	/* Check that order wait does not get stuck or crash */
	odp_schedule_order_wait();

	/* Release the context */
	ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
	CU_ASSERT(ev == ODP_EVENT_INVALID);

	CU_ASSERT(odp_queue_destroy(queue) == 0);
}

static int order_wait_helper(void *arg ODP_UNUSED)
{
	odp_event_t ev;

	ev = odp_schedule(NULL, odp_schedule_wait_time(ODP_TIME_SEC_IN_NS));

	if (ev != ODP_EVENT_INVALID) {
		odp_event_free(ev);

		odp_atomic_store_rel_u32(&globals->order_wait.helper_active, 1);
		odp_atomic_store_rel_u32(&globals->order_wait.helper_ready, 1);

		/* Wait that the main thread can attempt to overtake us */
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS);

		odp_atomic_store_rel_u32(&globals->order_wait.helper_active, 0);
	}

	/* We are not interested in further events */
	odp_schedule_pause();
	/* Release context */
	while ((ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT))
	       != ODP_EVENT_INVALID) {
		/* We got an event that was meant for the main thread */
		odp_event_free(ev);
	}

	return 0;
}

static void scheduler_test_order_wait_2_threads(void)
{
	odp_schedule_capability_t sched_capa;
	odp_queue_param_t queue_param;
	odp_queue_t queue;
	int ret;
	odp_time_t start;
	odp_event_t ev;
	int num = 1;

	CU_ASSERT(!odp_schedule_capability(&sched_capa));

	sched_queue_param_init(&queue_param);
	queue_param.sched.sync = ODP_SCHED_SYNC_ORDERED;
	queue = odp_queue_create("ordered queue", &queue_param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);
	CU_ASSERT_FATAL(odp_queue_type(queue) == ODP_QUEUE_TYPE_SCHED);
	CU_ASSERT_FATAL(odp_queue_sched_type(queue) == ODP_SCHED_SYNC_ORDERED);

	odp_atomic_init_u32(&globals->order_wait.helper_ready, 0);
	odp_atomic_init_u32(&globals->order_wait.helper_active, 0);

	ret = odp_cunit_thread_create(num, order_wait_helper, NULL, 0, 0);
	CU_ASSERT_FATAL(ret == num);

	/* Send an event to the helper thread */
	enqueue_event(queue);

	/* Wait that the helper thread gets the event */
	start = odp_time_local();
	while (!odp_atomic_load_acq_u32(&globals->order_wait.helper_ready)) {
		odp_time_t now = odp_time_local();

		if (odp_time_diff_ns(now, start) > ODP_TIME_SEC_IN_NS) {
			CU_FAIL("Timeout waiting for helper\n");
			break;
		}
	}

	/* Try to send an event to ourselves */
	enqueue_event(queue);
	/*
	 * If ordered queues are implemented as atomic queues, the schedule
	 * call here will not return anything until the helper thread has
	 * released the scheduling context of the first event. So we have
	 * to wait long enough before giving up.
	 */
	ev = odp_schedule(NULL, odp_schedule_wait_time(2 * ODP_TIME_SEC_IN_NS));
	if (ev == ODP_EVENT_INVALID) {
		/* Helper thread got the event. Give up. */
		printf("SKIPPED...");
		goto out;
	}
	odp_event_free(ev);

	/*
	 * We are now in an ordered scheduling context and behind the helper
	 * thread in source queue order if the helper thread has not released
	 * the scheuduling context.
	 */

	if (!odp_atomic_load_acq_u32(&globals->order_wait.helper_active)) {
		/*
		 * Helper thread has released the context already.
		 * We cannot test order wait fully.
		 */
		printf("reduced test...");
	}

	/*
	 * The function we are testing: Wait until there are no scheduling
	 * contexts that precede ours.
	 */
	odp_schedule_order_wait();

	/*
	 * If order wait is supported, we are now first in the source queue
	 * order, so the helper thread must have released its context.
	 */
	if (sched_capa.order_wait)
		CU_ASSERT(!odp_atomic_load_acq_u32(&globals->order_wait.helper_active));

	/* Release the context */
	ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
	CU_ASSERT(ev == ODP_EVENT_INVALID);

out:
	CU_ASSERT(odp_cunit_thread_join(num) == 0);
	CU_ASSERT(odp_queue_destroy(queue) == 0);
}

static int sched_and_plain_thread(void *arg)
{
	odp_event_t ev1, ev2;
	thread_args_t *args = (thread_args_t *)arg;
	test_globals_t *globals = args->globals;
	odp_queue_t sched_queue = globals->sched_and_plain_q.sched;
	odp_queue_t plain_queue = globals->sched_and_plain_q.plain;
	odp_schedule_sync_t sync = odp_queue_sched_type(sched_queue);
	uint64_t i, wait;

	/* Wait for all threads to start */
	odp_barrier_wait(&globals->barrier);

	/* Run the test */
	wait = odp_schedule_wait_time(10 * ODP_TIME_MSEC_IN_NS);
	for (i = 0; i < SCHED_AND_PLAIN_ROUNDS; i++) {
		uint32_t rand_val;

		/* Dequeue events from scheduled and plain queues */
		ev1 = odp_schedule(NULL, wait);
		if (ev1 == ODP_EVENT_INVALID)
			continue;

		if (sync == ODP_SCHED_SYNC_ORDERED)
			odp_schedule_order_lock(0);

		ev2 = odp_queue_deq(plain_queue);
		CU_ASSERT_FATAL(ev2 != ODP_EVENT_INVALID);

		/* Add random delay to stress scheduler implementation */
		odp_random_data((uint8_t *)&rand_val, sizeof(rand_val),
				ODP_RANDOM_BASIC);
		odp_time_wait_ns(rand_val % ODP_TIME_USEC_IN_NS);

		/* Enqueue events back to the end of the queues */
		CU_ASSERT_FATAL(!odp_queue_enq(plain_queue, ev2));

		if (sync == ODP_SCHED_SYNC_ORDERED)
			odp_schedule_order_unlock(0);

		CU_ASSERT_FATAL(!odp_queue_enq(sched_queue, ev1));
	}

	/* Make sure scheduling context is released */
	odp_schedule_pause();
	while ((ev1 = odp_schedule(NULL, ODP_SCHED_NO_WAIT)) != ODP_EVENT_INVALID) {
		if (sync == ODP_SCHED_SYNC_ORDERED)
			odp_schedule_order_lock(0);

		ev2 = odp_queue_deq(plain_queue);
		CU_ASSERT_FATAL(ev2 != ODP_EVENT_INVALID);

		CU_ASSERT_FATAL(!odp_queue_enq(plain_queue, ev2));

		if (sync == ODP_SCHED_SYNC_ORDERED)
			odp_schedule_order_unlock(0);

		CU_ASSERT_FATAL(!odp_queue_enq(sched_queue, ev1));
	}

	/* Don't resume scheduling until all threads have finished */
	odp_barrier_wait(&globals->barrier);
	odp_schedule_resume();

	return 0;
}

static void scheduler_test_sched_and_plain(odp_schedule_sync_t sync)
{
	thread_args_t *args;
	test_globals_t *globals;
	odp_queue_t sched_queue;
	odp_queue_t plain_queue;
	odp_pool_t pool;
	odp_queue_param_t queue_param;
	odp_pool_param_t pool_param;
	odp_queue_capability_t queue_capa;
	odp_schedule_capability_t sched_capa;
	odp_shm_t shm;
	odp_event_t ev;
	uint32_t *buf_data;
	uint32_t seq;
	uint64_t wait = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);
	uint32_t events_per_queue = BUFS_PER_QUEUE / 2;
	uint32_t prev_seq;
	int first;
	void *arg_ptr;

	CU_ASSERT_FATAL(!odp_schedule_capability(&sched_capa));
	CU_ASSERT_FATAL(!odp_queue_capability(&queue_capa))

	if (sync == ODP_SCHED_SYNC_ORDERED &&
	    sched_capa.max_ordered_locks == 0) {
		printf("\n  NO ORDERED LOCKS. scheduler_test_ordered_and_plain skipped.\n");
		return;
	}

	/* Set up the scheduling environment */
	shm = odp_shm_lookup(GLOBALS_SHM_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	globals = odp_shm_addr(shm);
	CU_ASSERT_FATAL(globals != NULL);

	shm = odp_shm_lookup(SHM_THR_ARGS_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	args = odp_shm_addr(shm);
	CU_ASSERT_FATAL(args != NULL);
	args->globals = globals;

	/* Make sure all events fit to queues */
	if (sched_capa.max_queue_size &&
	    sched_capa.max_queue_size < events_per_queue)
		events_per_queue = sched_capa.max_queue_size;
	if (queue_capa.plain.max_size &&
	    queue_capa.plain.max_size < events_per_queue)
		events_per_queue = queue_capa.plain.max_size;

	sched_queue_param_init(&queue_param);
	queue_param.sched.sync = sync;
	queue_param.size = events_per_queue;
	if (sync == ODP_SCHED_SYNC_ORDERED)
		queue_param.sched.lock_count = 1;

	sched_queue = odp_queue_create(NULL, &queue_param);
	CU_ASSERT_FATAL(sched_queue != ODP_QUEUE_INVALID);
	globals->sched_and_plain_q.sched = sched_queue;

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_PLAIN;
	queue_param.size = events_per_queue;

	plain_queue = odp_queue_create(NULL, &queue_param);
	CU_ASSERT_FATAL(sched_queue != ODP_QUEUE_INVALID);
	globals->sched_and_plain_q.plain = plain_queue;

	odp_pool_param_init(&pool_param);
	pool_param.buf.size  = 100;
	pool_param.buf.num   = 2 * events_per_queue;
	pool_param.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("sched_to_plain_pool", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	/* Create and enq test events with sequential sequence numbers */
	for (seq = 0; seq < events_per_queue; seq++) {
		odp_buffer_t buf1, buf2;

		buf1 = odp_buffer_alloc(pool);
		if (buf1 == ODP_BUFFER_INVALID)
			break;
		buf2 = odp_buffer_alloc(pool);
		if (buf2 == ODP_BUFFER_INVALID) {
			odp_buffer_free(buf1);
			break;
		}
		buf_data = odp_buffer_addr(buf1);
		*buf_data = seq;
		buf_data = odp_buffer_addr(buf2);
		*buf_data = seq;

		/* Events flow id is 0 by default */
		CU_ASSERT_FATAL(!odp_queue_enq(sched_queue,
					       odp_buffer_to_event(buf1)));
		CU_ASSERT_FATAL(!odp_queue_enq(plain_queue,
					       odp_buffer_to_event(buf2)));
	}
	CU_ASSERT_FATAL(seq > 2);

	arg_ptr = args;
	odp_cunit_thread_create(globals->num_workers, sched_and_plain_thread, &arg_ptr, 0, 0);

	odp_cunit_thread_join(globals->num_workers);

	/* Check plain queue sequence numbers and free events */
	first = 1;
	while (1) {
		ev = odp_queue_deq(plain_queue);
		if (ev == ODP_EVENT_INVALID)
			break;

		buf_data = odp_buffer_addr(odp_buffer_from_event(ev));
		seq = *buf_data;

		if (first) {
			first = 0;
			prev_seq = seq;
			continue;
		}

		CU_ASSERT(seq == prev_seq + 1 || seq == 0)
		prev_seq = seq;
		odp_event_free(ev);
	}

	/* Check scheduled queue sequence numbers and free events */
	first = 1;
	while (1) {
		ev = odp_schedule(NULL, wait);
		if (ev == ODP_EVENT_INVALID)
			break;

		buf_data = odp_buffer_addr(odp_buffer_from_event(ev));
		seq = *buf_data;

		if (first) {
			first = 0;
			prev_seq = seq;
			continue;
		}

		CU_ASSERT(seq == prev_seq + 1 || seq == 0)
		prev_seq = seq;
		odp_event_free(ev);
	}

	CU_ASSERT(!odp_queue_destroy(sched_queue));
	CU_ASSERT(!odp_queue_destroy(plain_queue));
	CU_ASSERT(!odp_pool_destroy(pool));
}

static void scheduler_test_atomic_and_plain(void)
{
	scheduler_test_sched_and_plain(ODP_SCHED_SYNC_ATOMIC);
}

static void scheduler_test_ordered_and_plain(void)
{
	scheduler_test_sched_and_plain(ODP_SCHED_SYNC_ORDERED);
}

static void scheduler_fifo_init(odp_schedule_sync_t sync, int multi, uint32_t num_thr)
{
	odp_queue_t queue;
	odp_pool_t pool;
	odp_buffer_t buf;
	uint32_t *seq;
	uint32_t i;
	odp_queue_param_t queue_param;
	odp_pool_param_t pool_param;
	odp_schedule_capability_t sched_capa;
	uint32_t num_events = FIFO_MAX_EVENTS;

	CU_ASSERT_FATAL(!odp_schedule_capability(&sched_capa));

	/* Make sure events fit into the queue */
	if (sched_capa.max_queue_size && num_events > sched_capa.max_queue_size)
		num_events = sched_capa.max_queue_size;

	sched_queue_param_init(&queue_param);
	queue_param.sched.sync = sync;
	queue_param.size = num_events;

	queue = odp_queue_create("sched_fifo", &queue_param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	odp_pool_param_init(&pool_param);
	pool_param.type      = ODP_POOL_BUFFER;
	pool_param.buf.size  = 32;
	pool_param.buf.num   = num_events;

	pool = odp_pool_create("sched_fifo", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < num_events; i++) {
		buf = odp_buffer_alloc(pool);
		if (buf == ODP_BUFFER_INVALID)
			break;

		seq = odp_buffer_addr(buf);
		*seq = i;
		globals->fifo.event[i] = odp_buffer_to_event(buf);
	}

	CU_ASSERT_FATAL(i == num_events);

	odp_barrier_init(&globals->fifo.barrier, num_thr);

	globals->fifo.multi = multi;
	globals->fifo.queue = queue;
	globals->fifo.pool = pool;
	globals->fifo.num_events = num_events;
	globals->fifo.num_enq = 0;
	globals->fifo.burst = 0;
	globals->fifo.num_thr = num_thr;
	odp_atomic_init_u32(&globals->fifo.cur_thr, 0);
}

static int scheduler_fifo_test(void *arg)
{
	odp_queue_t from;
	odp_buffer_t buf;
	int ret;
	uint32_t *seq;
	uint32_t i, num, cur_thr;
	uint32_t num_enq = 0;
	uint32_t thr;
	uint16_t num_thr = globals->fifo.num_thr;
	uint64_t wait = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);
	int multi = globals->fifo.multi;
	odp_queue_t queue = globals->fifo.queue;
	odp_pool_t pool = globals->fifo.pool;
	uint32_t num_events = globals->fifo.num_events;
	odp_event_t events[num_events];

	/* Thread index as argument */
	thr = (uintptr_t)arg;

	odp_barrier_wait(&globals->fifo.barrier);

	/* Threads enqueue events in round robin */
	while (1) {
		cur_thr = odp_atomic_load_acq_u32(&globals->fifo.cur_thr);
		if (cur_thr != thr)
			continue;

		num_enq = globals->fifo.num_enq;

		if (num_enq >= num_events) {
			odp_atomic_store_u32(&globals->fifo.cur_thr, (cur_thr + 1) % num_thr);
			break;
		}

		if (multi) {
			num = globals->fifo.burst + 1;
			globals->fifo.burst = num % 10;

			if (num > (num_events - num_enq))
				num = num_events - num_enq;

			ret = odp_queue_enq_multi(queue, &globals->fifo.event[num_enq], num);
			CU_ASSERT(ret > 0);
			CU_ASSERT_FATAL(ret <= (int)num);
		} else {
			ret = odp_queue_enq(queue, globals->fifo.event[num_enq]);
			CU_ASSERT(ret == 0);
			if (ret == 0)
				ret = 1;
		}

		if (ret > 0)
			globals->fifo.num_enq += ret;

		odp_atomic_store_rel_u32(&globals->fifo.cur_thr, (cur_thr + 1) % num_thr);
	}

	odp_barrier_wait(&globals->fifo.barrier);

	if (thr != 0)
		return 0;

	/* Thread 0 checks event order and destroys queue/pool */
	CU_ASSERT(globals->fifo.num_enq == num_events);
	if (globals->fifo.num_enq > num_events)
		return -1;

	num_events = globals->fifo.num_enq;

	for (i = 0; i < num_events; i++)
		events[i] = ODP_EVENT_INVALID;

	num = 0;

	while (1) {
		uint32_t num_recv;
		int max_num = 3;
		odp_event_t ev[max_num];

		from = ODP_QUEUE_INVALID;

		if (multi) {
			ret = odp_schedule_multi(&from, wait, ev, max_num);
			CU_ASSERT_FATAL(ret >= 0 && ret <= max_num);

			if (ret == 0)
				break;
		} else {
			ev[0] = odp_schedule(&from, wait);
			if (ev[0] == ODP_EVENT_INVALID)
				break;

			ret = 1;
		}

		num_recv = ret;
		CU_ASSERT(num < num_events);

		if (num >= num_events) {
			/* Drop extra events */
			odp_event_free_multi(ev, num_recv);
			continue;
		}

		for (i = 0; i < num_recv; i++) {
			CU_ASSERT(odp_event_type(ev[i]) == ODP_EVENT_BUFFER);
			events[num] = ev[i];
			num++;
		}

		CU_ASSERT(from == queue);
	}

	CU_ASSERT(num == num_events);

	for (i = 0; i < num; i++) {
		buf = odp_buffer_from_event(events[i]);
		seq = odp_buffer_addr(buf);

		CU_ASSERT(*seq == i);

		if (*seq != i)
			ODPH_ERR("Bad sequence number %u,  expected %u\n", *seq, i);

		odp_buffer_free(buf);
	}

	CU_ASSERT_FATAL(!odp_queue_destroy(queue));
	CU_ASSERT_FATAL(!odp_pool_destroy(pool));

	return 0;
}

static void scheduler_fifo_parallel_single(void)
{
	scheduler_fifo_init(ODP_SCHED_SYNC_PARALLEL, 0, 1);
	scheduler_fifo_test(0);
}

static void scheduler_fifo_parallel_multi(void)
{
	scheduler_fifo_init(ODP_SCHED_SYNC_PARALLEL, 1, 1);
	scheduler_fifo_test(0);
}

static void scheduler_fifo_atomic_single(void)
{
	scheduler_fifo_init(ODP_SCHED_SYNC_ATOMIC, 0, 1);
	scheduler_fifo_test(0);
}

static void scheduler_fifo_atomic_multi(void)
{
	scheduler_fifo_init(ODP_SCHED_SYNC_ATOMIC, 1, 1);
	scheduler_fifo_test(0);
}

static void scheduler_fifo_ordered_single(void)
{
	scheduler_fifo_init(ODP_SCHED_SYNC_ORDERED, 0, 1);
	scheduler_fifo_test(0);
}

static void scheduler_fifo_ordered_multi(void)
{
	scheduler_fifo_init(ODP_SCHED_SYNC_ORDERED, 1, 1);
	scheduler_fifo_test(0);
}

static void scheduler_fifo_mt(odp_schedule_sync_t sync, int multi)
{
	uint32_t i;
	uint32_t num_thr = globals->num_workers;
	uintptr_t arg[num_thr];

	scheduler_fifo_init(sync, multi, num_thr);

	for (i = 0; i < num_thr; i++)
		arg[i] = i;

	odp_cunit_thread_create(num_thr, scheduler_fifo_test, (void **)&arg[0], 1, 0);

	/* Wait for worker threads to terminate */
	odp_cunit_thread_join(num_thr);
}

static void scheduler_fifo_mt_parallel_single(void)
{
	scheduler_fifo_mt(ODP_SCHED_SYNC_PARALLEL, 0);
}

static void scheduler_fifo_mt_parallel_multi(void)
{
	scheduler_fifo_mt(ODP_SCHED_SYNC_PARALLEL, 1);
}

static void scheduler_fifo_mt_atomic_single(void)
{
	scheduler_fifo_mt(ODP_SCHED_SYNC_ATOMIC, 0);
}

static void scheduler_fifo_mt_atomic_multi(void)
{
	scheduler_fifo_mt(ODP_SCHED_SYNC_ATOMIC, 1);
}

static void scheduler_fifo_mt_ordered_single(void)
{
	scheduler_fifo_mt(ODP_SCHED_SYNC_ORDERED, 0);
}

static void scheduler_fifo_mt_ordered_multi(void)
{
	scheduler_fifo_mt(ODP_SCHED_SYNC_ORDERED, 1);
}

static int atomicity_test_run(void *arg)
{
	thread_args_t *args = (thread_args_t *)arg;
	odp_event_t ev;
	odp_queue_t atomic_queue = args->globals->atomicity_q.handle;
	odp_queue_t from;
	odp_atomic_u32_t *state;
	uint32_t old;
	uint32_t num_processed = 0;

	if (args->num_workers > 1)
		odp_barrier_wait(&globals->barrier);

	while (num_processed < ATOMICITY_ROUNDS) {
		ev  = odp_schedule(&from, ODP_SCHED_NO_WAIT);
		if (ev == ODP_EVENT_INVALID)
			continue;

		CU_ASSERT(from == atomic_queue);
		if (from != atomic_queue) {
			odp_event_free(ev);
			continue;
		}

		state = odp_queue_context(from);
		CU_ASSERT_FATAL(state != NULL);

		old = 0;
		CU_ASSERT_FATAL(odp_atomic_cas_acq_rel_u32(state, &old, 1));

		/* Hold atomic context a while to better reveal possible atomicity bugs */
		odp_time_wait_ns(ODP_TIME_MSEC_IN_NS);

		old = 1;
		CU_ASSERT_FATAL(odp_atomic_cas_acq_rel_u32(state, &old, 0));

		CU_ASSERT_FATAL(odp_queue_enq(from, ev) == 0);

		num_processed++;
	}

	/* Release atomic context and get rid of possible prescheduled events */
	odp_schedule_pause();
	while ((ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT)) != ODP_EVENT_INVALID)
		CU_ASSERT_FATAL(odp_queue_enq(atomic_queue, ev) == 0);

	if (args->num_workers > 1)
		odp_barrier_wait(&globals->barrier);

	odp_schedule_resume();
	drain_queues();

	return 0;
}

static void scheduler_test_atomicity(void)
{
	odp_shm_t shm;
	test_globals_t *globals;
	thread_args_t *args;
	odp_pool_t pool;
	odp_queue_t queue;
	odp_queue_param_t queue_param;
	int i;
	void *arg_ptr;

	shm = odp_shm_lookup(GLOBALS_SHM_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	globals = odp_shm_addr(shm);
	CU_ASSERT_FATAL(globals != NULL);

	shm = odp_shm_lookup(SHM_THR_ARGS_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	args = odp_shm_addr(shm);
	CU_ASSERT_FATAL(args != NULL);

	pool = odp_pool_lookup(MSG_POOL_NAME);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	queue_param.size = globals->max_sched_queue_size;
	queue_param.context     = &globals->atomicity_q.state;
	queue_param.context_len = sizeof(globals->atomicity_q.state);

	queue = odp_queue_create("atomicity_test", &queue_param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	for (i = 0; i < BUFS_PER_QUEUE; i++) {
		odp_buffer_t buf = odp_buffer_alloc(pool);

		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

		CU_ASSERT_FATAL(odp_queue_enq(queue, odp_buffer_to_event(buf)) == 0);
	}
	globals->atomicity_q.handle = queue;
	odp_atomic_init_u32(&globals->atomicity_q.state, 0);

	/* Create and launch worker threads */
	args->num_workers = globals->num_workers;
	arg_ptr = args;
	odp_cunit_thread_create(globals->num_workers, atomicity_test_run, &arg_ptr, 0, 0);

	/* Wait for worker threads to terminate */
	odp_cunit_thread_join(globals->num_workers);

	odp_queue_destroy(globals->atomicity_q.handle);
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
		ODPH_ERR("Queue capability query failed\n");
		return -1;
	}

	if (odp_schedule_capability(&sched_capa) < 0) {
		ODPH_ERR("Queue capability query failed\n");
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
		ODPH_ERR("Not enough queues. At least %d scheduled queues and "
			 "%d plain queues required.\n",
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
		ODPH_ERR("Pool creation failed (queue ctx)\n");
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
				ODPH_ERR("Parallel queue create failed\n");
				return -1;
			}

			snprintf(name, sizeof(name), "sched_%d_%d_a", i, j);
			p.sched.sync = ODP_SCHED_SYNC_ATOMIC;
			p.size = globals->max_sched_queue_size;
			q = odp_queue_create(name, &p);

			if (q == ODP_QUEUE_INVALID) {
				ODPH_ERR("Atomic queue create failed\n");
				return -1;
			}

			snprintf(name, sizeof(name), "plain_%d_%d_o", i, j);
			pq = odp_queue_create(name, NULL);
			if (pq == ODP_QUEUE_INVALID) {
				ODPH_ERR("Plain queue create failed\n");
				return -1;
			}

			queue_ctx_buf = odp_buffer_alloc(queue_ctx_pool);

			if (queue_ctx_buf == ODP_BUFFER_INVALID) {
				ODPH_ERR("Cannot allocate plain queue ctx buf\n");
				return -1;
			}

			pqctx = odp_buffer_addr(queue_ctx_buf);
			pqctx->ctx_handle = queue_ctx_buf;
			pqctx->sequence = 0;

			rc = odp_queue_context_set(pq, pqctx, 0);

			if (rc != 0) {
				ODPH_ERR("Cannot set plain queue context\n");
				return -1;
			}

			snprintf(name, sizeof(name), "sched_%d_%d_o", i, j);
			p.sched.sync = ODP_SCHED_SYNC_ORDERED;
			p.sched.lock_count = sched_capa.max_ordered_locks;
			p.size = 0;
			q = odp_queue_create(name, &p);

			if (q == ODP_QUEUE_INVALID) {
				ODPH_ERR("Ordered queue create failed\n");
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
				ODPH_ERR("Cannot allocate queue ctx buf\n");
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
				ODPH_ERR("Cannot set queue context\n");
				return -1;
			}
		}
	}

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
		ODPH_ERR("Failed to destroy queue ctx pool\n");
		return -1;
	}

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

		sched_queue_param_init(&queue_param);
		queue_param.sched.sync  = sync[i];
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

/* Queues created but no events */
static void scheduler_test_print(void)
{
	odp_schedule_print();
}

/* Queues with initial events enqueued */
static void scheduler_test_mq_mt_prio_a_print(void)
{
	int prio = odp_schedule_num_prio();

	globals->test_debug_print = 1;

	parallel_execute(ODP_SCHED_SYNC_ATOMIC, globals->queues_per_prio, prio,
			 SCHD_ONE, DISABLE_EXCL_ATOMIC);

	globals->test_debug_print = 0;
}

static int scheduler_test_global_init(void)
{
	odp_shm_t shm;
	thread_args_t *args;
	odp_pool_t pool;
	odp_pool_param_t params;
	uint64_t num_flows;
	odp_schedule_capability_t sched_capa;
	odp_schedule_config_t sched_config;

	shm = odp_shm_reserve(GLOBALS_SHM_NAME,
			      sizeof(test_globals_t), ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared memory reserve failed (globals)\n");
		return -1;
	}

	globals = odp_shm_addr(shm);

	if (!globals) {
		ODPH_ERR("Shared memory reserve failed (globals)\n");
		return -1;
	}

	memset(globals, 0, sizeof(test_globals_t));
	globals->shm_glb = shm;

	globals->num_workers = odp_cpumask_default_worker(NULL, 0);
	if (globals->num_workers > MAX_WORKERS)
		globals->num_workers = MAX_WORKERS;

	shm = odp_shm_reserve(SHM_THR_ARGS_NAME, sizeof(thread_args_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared memory reserve failed (args)\n");
		return -1;
	}

	args = odp_shm_addr(shm);
	globals->shm_args = shm;

	if (!args) {
		ODPH_ERR("Shared memory reserve failed (args)\n");
		return -1;
	}

	memset(args, 0, sizeof(thread_args_t));

	/* Barrier to sync test case execution */
	odp_barrier_init(&globals->barrier, globals->num_workers);
	odp_ticketlock_init(&globals->lock);
	odp_spinlock_init(&globals->atomic_lock);

	odp_pool_param_init(&params);
	params.buf.size  = BUF_SIZE;
	params.buf.align = 0;
	params.buf.num   = MSG_POOL_SIZE;
	params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create(MSG_POOL_NAME, &params);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Pool creation failed (msg)\n");
		return -1;
	}

	globals->pool = pool;

	if (odp_schedule_capability(&sched_capa)) {
		ODPH_ERR("odp_schedule_capability() failed\n");
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

	globals->num_flows = num_flows;

	/* Configure the scheduler. All test cases share the config. */
	if (odp_schedule_config(&sched_config)) {
		ODPH_ERR("odp_schedule_config() failed\n");
		return -1;
	}

	return 0;
}

static int scheduler_multi_suite_init(void)
{
	/* Line feeds to separate output from basic suite prints */
	printf("\n\n");

	if (create_queues(globals) != 0)
		return -1;

	return 0;
}

static int scheduler_multi_suite_term(void)
{
	if (destroy_queues() != 0) {
		ODPH_ERR("Failed to destroy queues\n");
		return -1;
	}

	if (odp_cunit_print_inactive())
		return -1;

	return 0;
}

static int scheduler_basic_suite_init(void)
{
	return 0;
}

static int scheduler_basic_suite_term(void)
{
	if (odp_cunit_print_inactive())
		return -1;

	return 0;
}

static int global_init(odp_instance_t *inst)
{
	odp_init_t init_param;
	odph_helper_options_t helper_options;

	if (odph_options(&helper_options)) {
		ODPH_ERR("odph_options() failed.\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (0 != odp_init_global(inst, &init_param, NULL)) {
		ODPH_ERR("odp_init_global() failed.\n");
		return -1;
	}

	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("odp_init_local() failed.\n");
		return -1;
	}

	if (scheduler_test_global_init()) {
		ODPH_ERR("scheduler test global init failed\n");
		return -1;
	}

	return 0;
}

static int global_term(odp_instance_t inst)
{
	if (odp_pool_destroy(globals->pool))
		ODPH_ERR("Failed to destroy pool\n");

	if (odp_shm_free(globals->shm_args))
		ODPH_ERR("Failed to free shm\n");

	if (odp_shm_free(globals->shm_glb))
		ODPH_ERR("Failed to free shm\n");

	if (odp_term_local()) {
		ODPH_ERR("odp_term_local() failed.\n");
		return -1;
	}

	if (odp_term_global(inst)) {
		ODPH_ERR("odp_term_global() failed.\n");
		return -1;
	}

	return 0;
}

/* Basic scheduler test suite */
odp_testinfo_t scheduler_basic_suite[] = {
	ODP_TEST_INFO(scheduler_test_init),
	ODP_TEST_INFO(scheduler_test_capa),
	ODP_TEST_INFO(scheduler_test_wait_time),
	ODP_TEST_INFO(scheduler_test_num_prio),
	ODP_TEST_INFO(scheduler_test_queue_destroy),
	ODP_TEST_INFO(scheduler_test_wait),
	ODP_TEST_INFO(scheduler_test_queue_size),
	ODP_TEST_INFO(scheduler_test_full_queues),
	ODP_TEST_INFO(scheduler_test_max_queues_p),
	ODP_TEST_INFO(scheduler_test_max_queues_a),
	ODP_TEST_INFO(scheduler_test_max_queues_o),
	ODP_TEST_INFO(scheduler_test_order_ignore),
	ODP_TEST_INFO(scheduler_test_group_info_predef),
	ODP_TEST_INFO(scheduler_test_create_group),
	ODP_TEST_INFO(scheduler_test_create_max_groups),
	ODP_TEST_INFO(scheduler_test_groups),
	ODP_TEST_INFO(scheduler_test_pause_resume),
	ODP_TEST_INFO(scheduler_test_pause_enqueue),
	ODP_TEST_INFO(scheduler_test_ordered_lock),
	ODP_TEST_INFO(scheduler_test_order_wait_1_thread),
	ODP_TEST_INFO(scheduler_test_order_wait_2_threads),
	ODP_TEST_INFO_CONDITIONAL(scheduler_test_flow_aware,
				  check_flow_aware_support),
	ODP_TEST_INFO(scheduler_test_parallel),
	ODP_TEST_INFO(scheduler_test_atomic),
	ODP_TEST_INFO(scheduler_test_ordered),
	ODP_TEST_INFO(scheduler_test_atomic_and_plain),
	ODP_TEST_INFO(scheduler_test_ordered_and_plain),
	ODP_TEST_INFO(scheduler_fifo_parallel_single),
	ODP_TEST_INFO(scheduler_fifo_parallel_multi),
	ODP_TEST_INFO(scheduler_fifo_atomic_single),
	ODP_TEST_INFO(scheduler_fifo_atomic_multi),
	ODP_TEST_INFO(scheduler_fifo_ordered_single),
	ODP_TEST_INFO(scheduler_fifo_ordered_multi),
	ODP_TEST_INFO(scheduler_fifo_mt_parallel_single),
	ODP_TEST_INFO(scheduler_fifo_mt_parallel_multi),
	ODP_TEST_INFO(scheduler_fifo_mt_atomic_single),
	ODP_TEST_INFO(scheduler_fifo_mt_atomic_multi),
	ODP_TEST_INFO(scheduler_fifo_mt_ordered_single),
	ODP_TEST_INFO(scheduler_fifo_mt_ordered_multi),
	ODP_TEST_INFO(scheduler_test_atomicity),
	ODP_TEST_INFO_NULL
};

/* Scheduler test suite which runs events through hundreds of queues. Queues are created once
 * in suite init phase. */
odp_testinfo_t scheduler_multi_suite[] = {
	ODP_TEST_INFO(scheduler_test_print),
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
	ODP_TEST_INFO(scheduler_test_mq_mt_prio_a_print),
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t scheduler_suites[] = {
	{"Scheduler basic",
	 scheduler_basic_suite_init, scheduler_basic_suite_term, scheduler_basic_suite
	},
	{"Scheduler multi",
	 scheduler_multi_suite_init, scheduler_multi_suite_term, scheduler_multi_suite
	},

	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	odp_cunit_register_global_init(global_init);
	odp_cunit_register_global_term(global_term);

	ret = odp_cunit_register(scheduler_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

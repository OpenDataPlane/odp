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

/* Test global variables */
typedef struct {
	int cpu_count;
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
	int num_cpus;
	int enable_schd_multi;
	int enable_excl_atomic;
} thread_args_t;

odp_pool_t pool;

static int exit_schedule_loop(void)
{
	odp_event_t ev;
	int ret = 0;

	odp_schedule_pause();

	while ((ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT))
	      != ODP_EVENT_INVALID) {
		odp_buffer_t buf;

		buf = odp_buffer_from_event(ev);
		odp_buffer_free(buf);
		ret++;
	}

	return ret;
}

static void scheduler_test_wait_time(void)
{
	uint64_t wait_time;

	wait_time = odp_schedule_wait_time(0);

	wait_time = odp_schedule_wait_time(1);
	CU_ASSERT(wait_time > 0);

	wait_time = odp_schedule_wait_time((uint64_t)-1LL);
	CU_ASSERT(wait_time > 0);
}

static void scheduler_test_num_prio(void)
{
	int prio;

	prio = odp_schedule_num_prio();

	CU_ASSERT(prio > 0);
	CU_ASSERT(prio == odp_schedule_num_prio());
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
	odp_schedule_sync_t sync[] = {ODP_SCHED_SYNC_NONE,
				      ODP_SCHED_SYNC_ATOMIC,
				      ODP_SCHED_SYNC_ORDERED};

	params.buf.size  = 100;
	params.buf.align = 0;
	params.buf.num   = 1;
	params.type      = ODP_POOL_BUFFER;

	p = odp_pool_create("sched_destroy_pool", ODP_SHM_NULL, &params);

	CU_ASSERT_FATAL(p != ODP_POOL_INVALID);

	for (i = 0; i < 3; i++) {
		qp.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qp.sched.group = ODP_SCHED_GROUP_DEFAULT;
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

		CU_ASSERT_FATAL(odp_queue_destroy(queue) == 0);
	}

	CU_ASSERT_FATAL(odp_pool_destroy(p) == 0);
}

static void *schedule_common_(void *arg)
{
	thread_args_t *args = (thread_args_t *)arg;
	odp_schedule_sync_t sync;
	int num_cpus;
	test_globals_t *globals;

	globals = args->globals;
	sync = args->sync;
	num_cpus = args->num_cpus;

	if (num_cpus == globals->cpu_count)
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
			for (j = 0; j < num; j++) {
				buf = odp_buffer_from_event(events[j]);
				odp_buffer_free(buf);
			}
		} else {
			ev  = odp_schedule(&from, ODP_SCHED_NO_WAIT);
			buf = odp_buffer_from_event(ev);
			if (buf == ODP_BUFFER_INVALID)
				continue;
			num = 1;
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
				if (!(CU_ASSERT(odp_queue_enq(queue, ev) == 0)))
					odp_buffer_free(buf);
				else
					buf_count++;
			}
		}
	}

	globals->buf_count = buf_count;
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
	args.num_cpus = 1;
	args.enable_schd_multi = enable_schd_multi;
	args.enable_excl_atomic = 0;	/* Not needed with a single CPU */

	fill_queues(&args);

	schedule_common_(&args);
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
	args->num_cpus = globals->cpu_count;
	args->enable_schd_multi = enable_schd_multi;
	args->enable_excl_atomic = enable_excl_atomic;

	fill_queues(args);

	/* Create and launch worker threads */
	args->cu_thr.numthrds = globals->cpu_count;
	odp_cunit_thread_create(schedule_common_, &args->cu_thr);

	/* Wait for worker threads to terminate */
	odp_cunit_thread_exit(&args->cu_thr);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_NONE */
static void scheduler_test_1q_1t_n(void)
{
	schedule_common(ODP_SCHED_SYNC_NONE, ONE_Q, ONE_PRIO, SCHD_ONE);
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

/* Many queues 1 thread ODP_SCHED_SYNC_NONE */
static void scheduler_test_mq_1t_n(void)
{
	/* Only one priority involved in these tests, but use
	   the same number of queues the more general case uses */
	schedule_common(ODP_SCHED_SYNC_NONE, MANY_QS, ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ATOMIC */
static void scheduler_test_mq_1t_a(void)
{
	schedule_common(ODP_SCHED_SYNC_ATOMIC, MANY_QS, ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ORDERED */
static void scheduler_test_mq_1t_o(void)
{
	schedule_common(ODP_SCHED_SYNC_ORDERED, MANY_QS, ONE_PRIO, SCHD_ONE);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_NONE */
static void scheduler_test_mq_1t_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_NONE, MANY_QS, prio, SCHD_ONE);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ATOMIC */
static void scheduler_test_mq_1t_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ATOMIC, MANY_QS, prio, SCHD_ONE);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ORDERED */
static void scheduler_test_mq_1t_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ORDERED, MANY_QS, prio, SCHD_ONE);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_NONE */
static void scheduler_test_mq_mt_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_NONE, MANY_QS, prio, SCHD_ONE,
			 DISABLE_EXCL_ATOMIC);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ATOMIC */
static void scheduler_test_mq_mt_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ATOMIC, MANY_QS, prio, SCHD_ONE,
			 DISABLE_EXCL_ATOMIC);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ORDERED */
static void scheduler_test_mq_mt_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ORDERED, MANY_QS, prio, SCHD_ONE,
			 DISABLE_EXCL_ATOMIC);
}

/* 1 queue many threads check exclusive access on ATOMIC queues */
static void scheduler_test_1q_mt_a_excl(void)
{
	parallel_execute(ODP_SCHED_SYNC_ATOMIC, ONE_Q, ONE_PRIO, SCHD_ONE,
			 ENABLE_EXCL_ATOMIC);
}

/* 1 queue 1 thread ODP_SCHED_SYNC_NONE multi */
static void scheduler_test_multi_1q_1t_n(void)
{
	schedule_common(ODP_SCHED_SYNC_NONE, ONE_Q, ONE_PRIO, SCHD_MULTI);
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

/* Many queues 1 thread ODP_SCHED_SYNC_NONE multi */
static void scheduler_test_multi_mq_1t_n(void)
{
	/* Only one priority involved in these tests, but use
	   the same number of queues the more general case uses */
	schedule_common(ODP_SCHED_SYNC_NONE, MANY_QS, ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ATOMIC multi */
static void scheduler_test_multi_mq_1t_a(void)
{
	schedule_common(ODP_SCHED_SYNC_ATOMIC, MANY_QS, ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread ODP_SCHED_SYNC_ORDERED multi */
static void scheduler_test_multi_mq_1t_o(void)
{
	schedule_common(ODP_SCHED_SYNC_ORDERED, MANY_QS, ONE_PRIO, SCHD_MULTI);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_NONE multi */
static void scheduler_test_multi_mq_1t_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_NONE, MANY_QS, prio, SCHD_MULTI);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ATOMIC multi */
static void scheduler_test_multi_mq_1t_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ATOMIC, MANY_QS, prio, SCHD_MULTI);
}

/* Many queues 1 thread check priority ODP_SCHED_SYNC_ORDERED multi */
static void scheduler_test_multi_mq_1t_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	schedule_common(ODP_SCHED_SYNC_ORDERED, MANY_QS, prio, SCHD_MULTI);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_NONE multi */
static void scheduler_test_multi_mq_mt_prio_n(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_NONE, MANY_QS, prio, SCHD_MULTI, 0);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ATOMIC multi */
static void scheduler_test_multi_mq_mt_prio_a(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ATOMIC, MANY_QS, prio, SCHD_MULTI, 0);
}

/* Many queues many threads check priority ODP_SCHED_SYNC_ORDERED multi */
static void scheduler_test_multi_mq_mt_prio_o(void)
{
	int prio = odp_schedule_num_prio();

	parallel_execute(ODP_SCHED_SYNC_ORDERED, MANY_QS, prio, SCHD_MULTI, 0);
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
		ev = odp_schedule(&from, ODP_SCHED_NO_WAIT);
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
	int i, j, prios;

	prios = odp_schedule_num_prio();

	for (i = 0; i < prios; i++) {
		odp_queue_param_t p;
		p.sched.prio  = i;
		p.sched.group = ODP_SCHED_GROUP_DEFAULT;

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
			q = odp_queue_create(name, ODP_QUEUE_TYPE_SCHED, &p);

			if (q == ODP_QUEUE_INVALID) {
				printf("Schedule queue create failed.\n");
				return -1;
			}
		}
	}

	return 0;
}

static int scheduler_suite_init(void)
{
	odp_shm_t shm;
	odp_pool_t pool;
	test_globals_t *globals;
	thread_args_t *args;
	odp_pool_param_t params;

	params.buf.size  = BUF_SIZE;
	params.buf.align = 0;
	params.buf.num   = MSG_POOL_SIZE / BUF_SIZE;
	params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create(MSG_POOL_NAME, ODP_SHM_NULL, &params);

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

	globals->cpu_count = odp_cpu_count();
	if (globals->cpu_count > MAX_WORKERS)
		globals->cpu_count = MAX_WORKERS;

	shm = odp_shm_reserve(SHM_THR_ARGS_NAME, sizeof(thread_args_t),
			      ODP_CACHE_LINE_SIZE, 0);
	args = odp_shm_addr(shm);

	if (!args) {
		printf("Shared memory reserve failed (args).\n");
		return -1;
	}

	memset(args, 0, sizeof(thread_args_t));

	/* Barrier to sync test case execution */
	odp_barrier_init(&globals->barrier, globals->cpu_count);
	odp_ticketlock_init(&globals->lock);
	odp_spinlock_init(&globals->atomic_lock);

	if (create_queues() != 0)
		return -1;

	return 0;
}

static int destroy_queue(const char *name)
{
	odp_queue_t q;

	q = odp_queue_lookup(name);

	if (q == ODP_QUEUE_INVALID)
		return -1;

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

	return 0;
}

static int scheduler_suite_term(void)
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

static struct CU_TestInfo scheduler_suite[] = {
	{"schedule_wait_time",		scheduler_test_wait_time},
	{"schedule_num_prio",		scheduler_test_num_prio},
	{"schedule_queue_destroy",	scheduler_test_queue_destroy},
	{"schedule_1q_1t_n",		scheduler_test_1q_1t_n},
	{"schedule_1q_1t_a",		scheduler_test_1q_1t_a},
	{"schedule_1q_1t_o",		scheduler_test_1q_1t_o},
	{"schedule_mq_1t_n",		scheduler_test_mq_1t_n},
	{"schedule_mq_1t_a",		scheduler_test_mq_1t_a},
	{"schedule_mq_1t_o",		scheduler_test_mq_1t_o},
	{"schedule_mq_1t_prio_n",	scheduler_test_mq_1t_prio_n},
	{"schedule_mq_1t_prio_a",	scheduler_test_mq_1t_prio_a},
	{"schedule_mq_1t_prio_o",	scheduler_test_mq_1t_prio_o},
	{"schedule_mq_mt_prio_n",	scheduler_test_mq_mt_prio_n},
	{"schedule_mq_mt_prio_a",	scheduler_test_mq_mt_prio_a},
	{"schedule_mq_mt_prio_o",	scheduler_test_mq_mt_prio_o},
	{"schedule_1q_mt_a_excl",	scheduler_test_1q_mt_a_excl},
	{"schedule_multi_1q_1t_n",	scheduler_test_multi_1q_1t_n},
	{"schedule_multi_1q_1t_a",	scheduler_test_multi_1q_1t_a},
	{"schedule_multi_1q_1t_o",	scheduler_test_multi_1q_1t_o},
	{"schedule_multi_mq_1t_n",	scheduler_test_multi_mq_1t_n},
	{"schedule_multi_mq_1t_a",	scheduler_test_multi_mq_1t_a},
	{"schedule_multi_mq_1t_o",	scheduler_test_multi_mq_1t_o},
	{"schedule_multi_mq_1t_prio_n",	scheduler_test_multi_mq_1t_prio_n},
	{"schedule_multi_mq_1t_prio_a",	scheduler_test_multi_mq_1t_prio_a},
	{"schedule_multi_mq_1t_prio_o",	scheduler_test_multi_mq_1t_prio_o},
	{"schedule_multi_mq_mt_prio_n",	scheduler_test_multi_mq_mt_prio_n},
	{"schedule_multi_mq_mt_prio_a",	scheduler_test_multi_mq_mt_prio_a},
	{"schedule_multi_mq_mt_prio_o",	scheduler_test_multi_mq_mt_prio_o},
	{"schedule_multi_1q_mt_a_excl",	scheduler_test_multi_1q_mt_a_excl},
	{"schedule_pause_resume",	scheduler_test_pause_resume},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo scheduler_suites[] = {
	{"Scheduler",
	 scheduler_suite_init, scheduler_suite_term, NULL, NULL, scheduler_suite
	},
	CU_SUITE_INFO_NULL,
};

int scheduler_main(void)
{
	return odp_cunit_run(scheduler_suites);
}

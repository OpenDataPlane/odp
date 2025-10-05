/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2021-2025 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <odp_cunit_common.h>

#define MAX_WORKERS             32
#define BURST_SIZE              (8)
#define MAX_NUM_EVENT           (1 * 1024)
#define MAX_ITERATION           (100)
#define MAX_QUEUES              (64 * 1024)
#define MULTI_QUEUES            (MAX_QUEUES / 2)
#define GLOBALS_NAME            "queue_test_globals"
#define DEQ_RETRIES             100
#define ENQ_RETRIES             100

#define MAX_NUM_AGGR_PER_QUEUE 100 /* max number tested if more supported */

typedef struct {
	int              num_workers;
	odp_barrier_t    barrier;
	odp_queue_t      queue;
	odp_atomic_u32_t num_event;

	struct {
		odp_queue_t queue_a;
		odp_queue_t queue_b;
		int passed_a;
		int passed_b;
		int burst;
		odp_pool_t pool;
		odp_barrier_t barrier;
		odp_atomic_u32_t counter;
	} pair;

	struct {
		uint32_t num_event;
	} thread[ODP_THREAD_COUNT_MAX];

} test_globals_t;

static int queue_context = 0xff;
static odp_pool_t pool;

static void generate_name(char *name, uint32_t index)
{
	/* Unique name for up to 300M queues */
	name[0] = 'A' + ((index / (26 * 26 * 26 * 26 * 26)) % 26);
	name[1] = 'A' + ((index / (26 * 26 * 26 * 26)) % 26);
	name[2] = 'A' + ((index / (26 * 26 * 26)) % 26);
	name[3] = 'A' + ((index / (26 * 26)) % 26);
	name[4] = 'A' + ((index / 26) % 26);
	name[5] = 'A' + (index % 26);
}

static int queue_suite_init(void)
{
	odp_shm_t shm;
	test_globals_t *globals;
	odp_pool_param_t params;
	int num_workers;

	shm = odp_shm_reserve(GLOBALS_NAME, sizeof(test_globals_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared memory reserve failed\n");
		return -1;
	}

	globals = odp_shm_addr(shm);
	memset(globals, 0, sizeof(test_globals_t));

	num_workers = odp_cpumask_default_worker(NULL, 0);

	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	globals->num_workers = num_workers;
	odp_barrier_init(&globals->barrier, num_workers);

	odp_pool_param_init(&params);

	params.buf.size  = 4;
	/* Allocate enough buffers taking into consideration core starvation
	 * due to caching */
	params.buf.num   = MAX_NUM_EVENT + params.buf.cache_size;
	params.type      = ODP_POOL_BUFFER;

	pool = odp_pool_create("msg_pool", &params);

	if (ODP_POOL_INVALID == pool) {
		ODPH_ERR("Pool create failed\n");
		return -1;
	}
	return 0;
}

static int queue_suite_term(void)
{
	odp_shm_t shm;

	shm = odp_shm_lookup(GLOBALS_NAME);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("SHM lookup failed\n");
		return -1;
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("SHM free failed\n");
		return -1;
	}

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Pool destroy failed\n");
		return -1;
	}

	return 0;
}

static void queue_test_capa(void)
{
	odp_queue_capability_t capa;

	memset(&capa, 0, sizeof(odp_queue_capability_t));
	CU_ASSERT_FATAL(odp_queue_capability(&capa) == 0);

	CU_ASSERT(capa.max_queues > 0);
	CU_ASSERT(capa.max_queues >= capa.plain.max_num);
	CU_ASSERT(capa.max_queues >= capa.plain.lockfree.max_num);
	CU_ASSERT(capa.max_queues >= capa.plain.waitfree.max_num);
}

static void test_defaults(uint8_t fill)
{
	odp_queue_param_t param;
	odp_aggr_enq_param_t aggr_enq_param;

	memset(&param, fill, sizeof(param));
	odp_queue_param_init(&param);
	CU_ASSERT(param.type == ODP_QUEUE_TYPE_PLAIN);
	CU_ASSERT(param.enq_mode == ODP_QUEUE_OP_MT);
	CU_ASSERT(param.deq_mode == ODP_QUEUE_OP_MT);
	CU_ASSERT(param.sched.prio == odp_schedule_default_prio());
	CU_ASSERT(param.sched.sync == ODP_SCHED_SYNC_PARALLEL);
	CU_ASSERT(param.sched.group == ODP_SCHED_GROUP_ALL);
	CU_ASSERT(param.sched.lock_count == 0);
	CU_ASSERT(param.order == ODP_QUEUE_ORDER_KEEP);
	CU_ASSERT(param.nonblocking == ODP_BLOCKING);
	CU_ASSERT(param.context == NULL);
	CU_ASSERT(param.context_len == 0);
	CU_ASSERT(param.size == 0);
	CU_ASSERT(param.num_aggr == 0);
	CU_ASSERT(param.aggr == NULL);

	memset(&aggr_enq_param, fill, sizeof(aggr_enq_param));
	odp_aggr_enq_param_init(&aggr_enq_param);
	CU_ASSERT(aggr_enq_param.start_of_vector == 0);
	CU_ASSERT(aggr_enq_param.end_of_vector == 0);
}

static void queue_test_param_init(void)
{
	test_defaults(0);
	test_defaults(0xff);
}

static void queue_test_max_plain(void)
{
	odp_queue_capability_t capa;
	odp_queue_param_t qparams;
	char name[ODP_QUEUE_NAME_LEN];
	odp_queue_t queue[MAX_QUEUES];
	uint32_t num_queues, min, i;

	memset(&capa, 0, sizeof(odp_queue_capability_t));
	CU_ASSERT(odp_queue_capability(&capa) == 0);

	CU_ASSERT(capa.max_queues != 0);
	CU_ASSERT(capa.plain.max_num != 0);

	min = capa.plain.max_num;

	CU_ASSERT(capa.max_queues >= min);

	for (i = 0; i < ODP_QUEUE_NAME_LEN; i++)
		name[i] = 'A' + (i % 26);

	name[ODP_QUEUE_NAME_LEN - 1] = 0;

	odp_queue_param_init(&qparams);
	CU_ASSERT(qparams.nonblocking == ODP_BLOCKING);

	num_queues = capa.plain.max_num;

	if (num_queues > MAX_QUEUES)
		num_queues = MAX_QUEUES;

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

static int queue_create_multi(const char *name[], const odp_queue_param_t param[],
			      odp_bool_t share_param, odp_queue_t queue[], uint32_t num)
{
	const uint32_t max_retries = 100;
	uint32_t num_created = 0;
	uint32_t num_retries = 0;

	do {
		const char **cur_name = name != NULL ? &name[num_created] : NULL;
		const odp_queue_param_t *cur_param = share_param ? &param[0] : &param[num_created];
		int ret =  odp_queue_create_multi(cur_name, cur_param, share_param,
						  &queue[num_created], num - num_created);
		if (ret < 0) {
			CU_FAIL("Queue create multi failed");
			break;
		}
		CU_ASSERT_FATAL((uint32_t)ret <= num - num_created);

		num_retries = ret == 0 ? num_retries + 1 : 0;
		num_created += ret;
	} while (num_created < num && num_retries < max_retries);

	return num_created;
}

static void queue_destroy_multi(odp_queue_t queue[], uint32_t num)
{
	uint32_t num_left = num;
	uint32_t num_freed = 0;

	while (num_left) {
		int ret = odp_queue_destroy_multi(&queue[num_freed], num_left);

		CU_ASSERT_FATAL(ret > 0 && (uint32_t)ret <= num_left);

		num_left -= ret;
		num_freed += ret;
	}
	CU_ASSERT_FATAL(num_freed == num);
}

static void queue_test_create_destroy_multi(void)
{
	odp_queue_capability_t capa;
	odp_queue_param_t param_single;
	odp_queue_param_t param[MULTI_QUEUES];
	odp_queue_t queue[MULTI_QUEUES];
	const char *name[MULTI_QUEUES] = {NULL, "aaa", NULL, "bbb", "ccc", NULL, "ddd"};
	uint32_t num_queues, num_created;

	CU_ASSERT_FATAL(odp_queue_capability(&capa) == 0);
	CU_ASSERT_FATAL(capa.plain.max_num != 0);

	num_queues = capa.plain.max_num < MULTI_QUEUES ? capa.plain.max_num : MULTI_QUEUES;
	for (uint32_t i = 0; i < num_queues; i++)
		odp_queue_param_init(&param[i]);
	odp_queue_param_init(&param_single);

	/* Create queues using shared parameters */
	num_created = queue_create_multi(name, &param_single, true, queue, num_queues);
	CU_ASSERT(num_created == num_queues);
	queue_destroy_multi(queue, num_created);

	num_created = queue_create_multi(NULL, &param_single, true, queue, num_queues);
	CU_ASSERT(num_created == num_queues);
	queue_destroy_multi(queue, num_created);

	/* Use separate parameters for each queue */
	num_created = queue_create_multi(name, param, false, queue, num_queues);
	CU_ASSERT(num_created == num_queues);
	queue_destroy_multi(queue, num_created);

	num_created = queue_create_multi(NULL, param, false, queue, num_queues);
	CU_ASSERT(num_created == num_queues);
	queue_destroy_multi(queue, num_created);
}

static void queue_test_mode(void)
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

static odp_event_t dequeue_event(odp_queue_t queue)
{
	odp_event_t ev;
	int i;

	for (i = 0; i < MAX_ITERATION; i++) {
		ev = odp_queue_deq(queue);
		if (ev != ODP_EVENT_INVALID)
			break;
	}

	return ev;
}

static void test_burst(odp_nonblocking_t nonblocking,
		       odp_queue_op_mode_t enq_mode,
		       odp_queue_op_mode_t deq_mode)
{
	odp_queue_param_t param;
	odp_queue_t queue;
	odp_queue_capability_t capa;
	uint32_t max_burst, burst, i, j;
	odp_pool_t pool;
	odp_buffer_t buf;
	odp_event_t ev;
	uint32_t *data;

	CU_ASSERT_FATAL(odp_queue_capability(&capa) == 0);

	max_burst = capa.plain.max_size;

	if (nonblocking == ODP_NONBLOCKING_LF) {
		if (capa.plain.lockfree.max_num == 0) {
			printf("  NO LOCKFREE QUEUES. Test skipped.\n");
			return;
		}

		max_burst = capa.plain.lockfree.max_size;
	}

	if (max_burst == 0 || max_burst > MAX_NUM_EVENT)
		max_burst = MAX_NUM_EVENT;

	pool = odp_pool_lookup("msg_pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	odp_queue_param_init(&param);
	param.type        = ODP_QUEUE_TYPE_PLAIN;
	param.nonblocking = nonblocking;
	param.size        = max_burst;
	param.enq_mode    = enq_mode;
	param.deq_mode    = deq_mode;

	queue = odp_queue_create("burst test", &param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	CU_ASSERT(odp_queue_deq(queue) == ODP_EVENT_INVALID);

	buf = odp_buffer_alloc(pool);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
	ev = odp_buffer_to_event(buf);
	CU_ASSERT(odp_queue_enq(queue, ev) == 0);
	ev = dequeue_event(queue);
	CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
	if (ev != ODP_EVENT_INVALID)
		odp_event_free(ev);

	for (j = 0; j < 2; j++) {
		if (j == 0)
			burst = max_burst / 4;
		else
			burst = max_burst;

		for (i = 0; i < burst; i++) {
			buf = odp_buffer_alloc(pool);
			CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
			data = odp_buffer_addr(buf);
			*data = i;
			ev = odp_buffer_to_event(buf);
			CU_ASSERT(odp_queue_enq(queue, ev) == 0);
		}

		for (i = 0; i < burst; i++) {
			ev = dequeue_event(queue);
			CU_ASSERT(ev != ODP_EVENT_INVALID);
			if (ev != ODP_EVENT_INVALID) {
				buf  = odp_buffer_from_event(ev);
				data = odp_buffer_addr(buf);
				CU_ASSERT(*data == i);
				odp_event_free(ev);
			}
		}
	}

	CU_ASSERT(odp_queue_destroy(queue) == 0);
}

static void queue_test_burst(void)
{
	test_burst(ODP_BLOCKING, ODP_QUEUE_OP_MT, ODP_QUEUE_OP_MT);
}

static void queue_test_burst_spmc(void)
{
	test_burst(ODP_BLOCKING, ODP_QUEUE_OP_MT_UNSAFE, ODP_QUEUE_OP_MT);
}

static void queue_test_burst_mpsc(void)
{
	test_burst(ODP_BLOCKING, ODP_QUEUE_OP_MT, ODP_QUEUE_OP_MT_UNSAFE);
}

static void queue_test_burst_spsc(void)
{
	test_burst(ODP_BLOCKING, ODP_QUEUE_OP_MT_UNSAFE,
		   ODP_QUEUE_OP_MT_UNSAFE);
}

static void queue_test_burst_lf(void)
{
	test_burst(ODP_NONBLOCKING_LF, ODP_QUEUE_OP_MT, ODP_QUEUE_OP_MT);
}

static void queue_test_burst_lf_spmc(void)
{
	test_burst(ODP_NONBLOCKING_LF, ODP_QUEUE_OP_MT_UNSAFE, ODP_QUEUE_OP_MT);
}

static void queue_test_burst_lf_mpsc(void)
{
	test_burst(ODP_NONBLOCKING_LF, ODP_QUEUE_OP_MT, ODP_QUEUE_OP_MT_UNSAFE);
}

static void queue_test_burst_lf_spsc(void)
{
	test_burst(ODP_NONBLOCKING_LF, ODP_QUEUE_OP_MT_UNSAFE,
		   ODP_QUEUE_OP_MT_UNSAFE);
}

static int queue_pair_work_loop(void *arg)
{
	uint32_t i, events, burst, retry, max_retry;
	odp_buffer_t buf;
	odp_event_t ev;
	uint32_t *data;
	odp_queue_t src_queue, dst_queue;
	odp_pool_t pool;
	int passed;
	int thread_a;
	test_globals_t *globals = arg;

	burst = globals->pair.burst;
	pool  = globals->pair.pool;

	/* Select which thread is A */
	thread_a = odp_atomic_fetch_inc_u32(&globals->pair.counter);

	if (thread_a) {
		src_queue = globals->pair.queue_a;
		dst_queue = globals->pair.queue_b;
	} else {
		src_queue = globals->pair.queue_b;
		dst_queue = globals->pair.queue_a;
	}

	for (i = 0; i < burst; i++) {
		buf = odp_buffer_alloc(pool);
		CU_ASSERT(buf != ODP_BUFFER_INVALID);

		if (buf == ODP_BUFFER_INVALID)
			return -1;

		data = odp_buffer_addr(buf);
		*data = i;
		ev = odp_buffer_to_event(buf);
		CU_ASSERT(odp_queue_enq(dst_queue, ev) == 0);
	}

	/* Wait until both threads are ready */
	odp_barrier_wait(&globals->pair.barrier);
	events = 0;
	retry = 0;
	max_retry = 0;
	i = 0;
	while (events < 10000 && retry < 300) {
		ev = odp_queue_deq(src_queue);
		if (ev == ODP_EVENT_INVALID) {
			retry++;
			/* Slow down polling period after 100 retries. This
			 * gives time for the other thread to answer, if it
			 * was e.g. interrupted by the OS. We give up if
			 * the source queue stays empty for about 100ms. */
			if (retry > 200)
				odp_time_wait_ns(ODP_TIME_MSEC_IN_NS);
			else if (retry > 100)
				odp_time_wait_ns(ODP_TIME_USEC_IN_NS);

			if (retry > max_retry)
				max_retry = retry;

			continue;
		}

		events++;
		retry = 0;
		buf = odp_buffer_from_event(ev);
		data = odp_buffer_addr(buf);
		if (*data != i) {
			ODPH_ERR("Seq error: expected %u, recv %u\n", i, *data);
			CU_FAIL("Sequence number error");
		}

		i++;
		if (i == burst)
			i = 0;

		CU_ASSERT(odp_queue_enq(dst_queue, ev) == 0);
	}

	passed = (events == 10000);

	if (thread_a) {
		globals->pair.passed_a = passed;
		if (max_retry > 100)
			printf("\n    thread_a max_retry %u\n", max_retry);
	} else {
		globals->pair.passed_b = passed;
		if (max_retry > 100)
			printf("\n    thread_b max_retry %u\n", max_retry);
	}

	return 0;
}

static void test_pair(odp_nonblocking_t nonblocking,
		      odp_queue_op_mode_t enq_mode,
		      odp_queue_op_mode_t deq_mode)
{
	odp_queue_param_t param;
	odp_queue_t queue;
	odp_queue_capability_t capa;
	uint32_t max_burst, num;
	odp_pool_t pool;
	odp_event_t ev;
	odp_shm_t shm;
	test_globals_t *globals;
	void *arg;

	shm = odp_shm_lookup(GLOBALS_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	globals = odp_shm_addr(shm);

	CU_ASSERT_FATAL(odp_queue_capability(&capa) == 0);

	max_burst = 2 * BURST_SIZE;

	if (nonblocking == ODP_NONBLOCKING_LF) {
		if (capa.plain.lockfree.max_num == 0) {
			printf("  NO LOCKFREE QUEUES. Test skipped.\n");
			return;
		}

		if (capa.plain.lockfree.max_size &&
		    capa.plain.lockfree.max_size < max_burst)
			max_burst = capa.plain.lockfree.max_size;
	} else {
		if (capa.plain.max_size && capa.plain.max_size < max_burst)
			max_burst = capa.plain.max_size;
	}

	globals->pair.burst = max_burst / 2;

	pool = odp_pool_lookup("msg_pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	globals->pair.pool = pool;

	odp_queue_param_init(&param);
	param.type        = ODP_QUEUE_TYPE_PLAIN;
	param.nonblocking = nonblocking;
	param.size        = max_burst;
	param.enq_mode    = enq_mode;
	param.deq_mode    = deq_mode;

	queue = odp_queue_create("queue_a", &param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);
	globals->pair.queue_a = queue;
	CU_ASSERT(odp_queue_deq(queue) == ODP_EVENT_INVALID);

	queue = odp_queue_create("queue_b", &param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);
	globals->pair.queue_b = queue;
	CU_ASSERT(odp_queue_deq(queue) == ODP_EVENT_INVALID);

	odp_barrier_init(&globals->pair.barrier, 2);
	globals->pair.passed_a = 0;
	globals->pair.passed_b = 0;
	odp_atomic_init_u32(&globals->pair.counter, 0);

	/* Create one worker thread */
	arg = globals;
	odp_cunit_thread_create(1, queue_pair_work_loop, &arg, 0, 0);

	/* Run this thread as the second thread */
	CU_ASSERT(queue_pair_work_loop(globals) == 0);

	/* Wait worker to terminate */
	odp_cunit_thread_join(1);

	CU_ASSERT(globals->pair.passed_a);
	CU_ASSERT(globals->pair.passed_b);

	num = 0;

	while ((ev = dequeue_event(globals->pair.queue_a))
	       != ODP_EVENT_INVALID) {
		num++;
		odp_event_free(ev);
	}

	while ((ev = dequeue_event(globals->pair.queue_b))
	       != ODP_EVENT_INVALID) {
		num++;
		odp_event_free(ev);
	}

	CU_ASSERT(num == max_burst);
	CU_ASSERT(odp_queue_destroy(globals->pair.queue_a) == 0);
	CU_ASSERT(odp_queue_destroy(globals->pair.queue_b) == 0);
}

static void queue_test_pair(void)
{
	test_pair(ODP_BLOCKING, ODP_QUEUE_OP_MT, ODP_QUEUE_OP_MT);
}

static void queue_test_pair_spmc(void)
{
	test_pair(ODP_BLOCKING, ODP_QUEUE_OP_MT_UNSAFE, ODP_QUEUE_OP_MT);
}

static void queue_test_pair_mpsc(void)
{
	test_pair(ODP_BLOCKING, ODP_QUEUE_OP_MT, ODP_QUEUE_OP_MT_UNSAFE);
}

static void queue_test_pair_spsc(void)
{
	test_pair(ODP_BLOCKING, ODP_QUEUE_OP_MT_UNSAFE, ODP_QUEUE_OP_MT_UNSAFE);
}

static void queue_test_pair_lf(void)
{
	test_pair(ODP_NONBLOCKING_LF, ODP_QUEUE_OP_MT, ODP_QUEUE_OP_MT);
}

static void queue_test_pair_lf_spmc(void)
{
	test_pair(ODP_NONBLOCKING_LF, ODP_QUEUE_OP_MT_UNSAFE, ODP_QUEUE_OP_MT);
}

static void queue_test_pair_lf_mpsc(void)
{
	test_pair(ODP_NONBLOCKING_LF, ODP_QUEUE_OP_MT, ODP_QUEUE_OP_MT_UNSAFE);
}

static void queue_test_pair_lf_spsc(void)
{
	test_pair(ODP_NONBLOCKING_LF, ODP_QUEUE_OP_MT_UNSAFE,
		  ODP_QUEUE_OP_MT_UNSAFE);
}

static void queue_test_param(void)
{
	odp_queue_t queue, null_queue;
	odp_event_t enev[BURST_SIZE] = {ODP_EVENT_INVALID};
	odp_event_t deev[BURST_SIZE] = {ODP_EVENT_INVALID};
	odp_buffer_t buf;
	odp_event_t ev;
	odp_pool_t msg_pool;
	odp_event_t *pev_tmp;
	int i, deq_ret, ret;
	int nr_deq_entries = 0;
	int max_iteration = MAX_ITERATION;
	odp_queue_param_t qparams;
	odp_buffer_t enbuf;

	odp_queue_param_init(&qparams);

	/* Schedule type queue */
	qparams.type       = ODP_QUEUE_TYPE_SCHED;
	qparams.sched.prio = odp_schedule_min_prio();
	qparams.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparams.sched.group = ODP_SCHED_GROUP_WORKER;

	queue = odp_queue_create("test_queue", &qparams);
	CU_ASSERT_FATAL(ODP_QUEUE_INVALID != queue);
	CU_ASSERT(odp_queue_to_u64(queue) !=
		  odp_queue_to_u64(ODP_QUEUE_INVALID));
	CU_ASSERT(queue == odp_queue_lookup("test_queue"));
	CU_ASSERT(ODP_QUEUE_TYPE_SCHED    == odp_queue_type(queue));
	CU_ASSERT(odp_schedule_min_prio()   == odp_queue_sched_prio(queue));
	CU_ASSERT(ODP_SCHED_SYNC_PARALLEL == odp_queue_sched_type(queue));
	CU_ASSERT(ODP_SCHED_GROUP_WORKER  == odp_queue_sched_group(queue));

	CU_ASSERT(odp_queue_context(queue) == NULL);
	CU_ASSERT(0 == odp_queue_context_set(queue, &queue_context,
					     sizeof(queue_context)));

	CU_ASSERT(&queue_context == odp_queue_context(queue));
	CU_ASSERT(odp_queue_destroy(queue) == 0);

	/* Create queue with no name */
	odp_queue_param_init(&qparams);
	null_queue = odp_queue_create(NULL, &qparams);
	CU_ASSERT_FATAL(ODP_QUEUE_INVALID != null_queue);
	CU_ASSERT(odp_queue_context(null_queue) == NULL);

	/* Plain type queue */
	odp_queue_param_init(&qparams);
	qparams.type        = ODP_QUEUE_TYPE_PLAIN;
	qparams.context     = &queue_context;
	qparams.context_len = sizeof(queue_context);

	queue = odp_queue_create("test_queue", &qparams);
	CU_ASSERT_FATAL(ODP_QUEUE_INVALID != queue);
	CU_ASSERT(queue == odp_queue_lookup("test_queue"));
	CU_ASSERT(ODP_QUEUE_TYPE_PLAIN == odp_queue_type(queue));
	CU_ASSERT(&queue_context == odp_queue_context(queue));

	/* Destroy queue with no name */
	CU_ASSERT(odp_queue_destroy(null_queue) == 0);

	msg_pool = odp_pool_lookup("msg_pool");
	buf = odp_buffer_alloc(msg_pool);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
	ev  = odp_buffer_to_event(buf);

	ret = odp_queue_enq(queue, ev);
	CU_ASSERT(ret == 0);
	if (ret) {
		odp_buffer_free(buf);
	} else {
		CU_ASSERT(ev == odp_queue_deq(queue));
		odp_buffer_free(buf);
	}

	for (i = 0; i < BURST_SIZE; i++) {
		buf = odp_buffer_alloc(msg_pool);
		enev[i] = odp_buffer_to_event(buf);
	}

	/*
	 * odp_queue_enq_multi may return 0..n buffers due to the resource
	 * constraints in the implementation at that given point of time.
	 * But here we assume that we succeed in enqueuing all buffers.
	 */
	ret = odp_queue_enq_multi(queue, enev, BURST_SIZE);
	CU_ASSERT(BURST_SIZE == ret);
	i = ret < 0 ? 0 : ret;
	for ( ; i < BURST_SIZE; i++)
		odp_event_free(enev[i]);

	pev_tmp = deev;
	do {
		deq_ret = odp_queue_deq_multi(queue, pev_tmp, BURST_SIZE);
		nr_deq_entries += deq_ret;
		max_iteration--;
		pev_tmp += deq_ret;
		CU_ASSERT(max_iteration >= 0);
	} while (nr_deq_entries < BURST_SIZE);

	for (i = 0; i < BURST_SIZE; i++) {
		enbuf = odp_buffer_from_event(enev[i]);
		CU_ASSERT(enev[i] == deev[i]);
		odp_buffer_free(enbuf);
	}

	CU_ASSERT(odp_queue_destroy(queue) == 0);
}

static void queue_test_same_name(int sched)
{
	odp_queue_t queue, queue_a, queue_b;
	odp_queue_param_t param;
	const char *name = "same_name";

	odp_queue_param_init(&param);

	if (sched)
		param.type = ODP_QUEUE_TYPE_SCHED;

	queue_a = odp_queue_create(name, &param);
	CU_ASSERT_FATAL(queue_a != ODP_QUEUE_INVALID);

	queue = odp_queue_lookup(name);
	CU_ASSERT(queue == queue_a);

	/* Second queue with the same name */
	queue_b = odp_queue_create(name, &param);
	CU_ASSERT_FATAL(queue_b != ODP_QUEUE_INVALID);

	queue = odp_queue_lookup(name);
	CU_ASSERT(queue == queue_a || queue == queue_b);

	CU_ASSERT_FATAL(odp_queue_destroy(queue_a) == 0);
	CU_ASSERT_FATAL(odp_queue_destroy(queue_b) == 0);
}

static void queue_test_same_name_plain(void)
{
	queue_test_same_name(0);
}

static void queue_test_same_name_sched(void)
{
	queue_test_same_name(1);
}

static void queue_test_long_name(int sched)
{
	odp_queue_t queue;
	odp_queue_param_t param;
	char name[ODP_QUEUE_NAME_LEN];

	memset(name, 'a', sizeof(name));
	name[sizeof(name) - 1] = 0;

	odp_queue_param_init(&param);

	if (sched)
		param.type = ODP_QUEUE_TYPE_SCHED;

	queue = odp_queue_create(name, &param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);
	CU_ASSERT(queue == odp_queue_lookup(name));

	CU_ASSERT_FATAL(odp_queue_destroy(queue) == 0);
}

static void queue_test_long_name_plain(void)
{
	queue_test_long_name(0);
}

static void queue_test_long_name_sched(void)
{
	queue_test_long_name(1);
}

static void queue_test_info(void)
{
	odp_queue_t q_plain, q_order;
	const char *const nq_plain = "test_q_plain";
	const char *const nq_order = "test_q_order";
	odp_queue_info_t info;
	odp_queue_param_t param;
	odp_queue_capability_t capability;
	odp_schedule_capability_t sched_capa;
	char q_plain_ctx[] = "test_q_plain context data";
	char q_order_ctx[] = "test_q_order context data";
	uint32_t lock_count;
	char *ctx;
	uint32_t ret;

	/* Create a plain queue and set context */
	q_plain = odp_queue_create(nq_plain, NULL);
	CU_ASSERT_FATAL(ODP_QUEUE_INVALID != q_plain);
	CU_ASSERT(odp_queue_context_set(q_plain, q_plain_ctx,
					sizeof(q_plain_ctx)) == 0);

	memset(&capability, 0, sizeof(odp_queue_capability_t));
	CU_ASSERT(odp_queue_capability(&capability) == 0);
	CU_ASSERT(odp_schedule_capability(&sched_capa) == 0);
	/* Create a scheduled ordered queue with explicitly set params */
	odp_queue_param_init(&param);
	param.type       = ODP_QUEUE_TYPE_SCHED;
	param.sched.prio = odp_schedule_default_prio();
	param.sched.sync = ODP_SCHED_SYNC_ORDERED;
	param.sched.group = ODP_SCHED_GROUP_ALL;
	param.sched.lock_count = sched_capa.max_ordered_locks;
	if (param.sched.lock_count == 0)
		printf("\n    Ordered locks NOT supported\n");
	param.context = q_order_ctx;
	q_order = odp_queue_create(nq_order, &param);
	CU_ASSERT_FATAL(ODP_QUEUE_INVALID != q_order);

	/* Check info and call print for a plain queue */
	CU_ASSERT(odp_queue_info(q_plain, &info) == 0);
	CU_ASSERT(strcmp(nq_plain, info.name) == 0);
	CU_ASSERT(info.param.type == ODP_QUEUE_TYPE_PLAIN);
	CU_ASSERT(info.param.type == odp_queue_type(q_plain));
	CU_ASSERT(info.param.enq_mode == ODP_QUEUE_OP_MT);
	CU_ASSERT(info.param.deq_mode == ODP_QUEUE_OP_MT);
	CU_ASSERT(info.param.order == ODP_QUEUE_ORDER_KEEP);
	CU_ASSERT(info.param.nonblocking == ODP_BLOCKING);
	ctx = info.param.context; /* 'char' context ptr */
	CU_ASSERT(ctx == q_plain_ctx);
	CU_ASSERT(info.param.context == odp_queue_context(q_plain));
	odp_queue_print(q_plain);

	/* Check info and call print for a scheduled ordered queue */
	CU_ASSERT(odp_queue_info(q_order, &info) == 0);
	CU_ASSERT(strcmp(nq_order, info.name) == 0);
	CU_ASSERT(info.param.type == ODP_QUEUE_TYPE_SCHED);
	CU_ASSERT(info.param.type == odp_queue_type(q_order));
	CU_ASSERT(info.param.enq_mode == ODP_QUEUE_OP_MT);
	CU_ASSERT(info.param.deq_mode == ODP_QUEUE_OP_DISABLED);
	CU_ASSERT(info.param.order == ODP_QUEUE_ORDER_KEEP);
	CU_ASSERT(info.param.nonblocking == ODP_BLOCKING);
	ctx = info.param.context; /* 'char' context ptr */
	CU_ASSERT(ctx == q_order_ctx);
	CU_ASSERT(info.param.context == odp_queue_context(q_order));
	CU_ASSERT(info.param.sched.prio == odp_queue_sched_prio(q_order));
	CU_ASSERT(info.param.sched.sync == odp_queue_sched_type(q_order));
	CU_ASSERT(info.param.sched.group == odp_queue_sched_group(q_order));
	ret = odp_queue_lock_count(q_order);
	CU_ASSERT(ret == param.sched.lock_count);
	lock_count = ret;
	CU_ASSERT(info.param.sched.lock_count == lock_count);
	odp_queue_print(q_order);

	odp_queue_print_all();

	CU_ASSERT(odp_queue_destroy(q_plain) == 0);
	CU_ASSERT(odp_queue_destroy(q_order) == 0);
}

static uint32_t alloc_and_enqueue(odp_queue_t queue, odp_pool_t pool,
				  uint32_t num)
{
	uint32_t i, ret;
	odp_buffer_t buf;
	odp_event_t ev;

	for (i = 0; i < num; i++) {
		buf = odp_buffer_alloc(pool);

		CU_ASSERT(buf != ODP_BUFFER_INVALID);

		ev = odp_buffer_to_event(buf);

		ret = odp_queue_enq(queue, ev);

		CU_ASSERT(ret == 0);

		if (ret)
			break;
	}

	return i;
}

static uint32_t dequeue_and_free_all(odp_queue_t queue)
{
	odp_event_t ev;
	uint32_t num, retries;

	num = 0;
	retries = 0;

	while (1) {
		ev = odp_queue_deq(queue);

		if (ev == ODP_EVENT_INVALID) {
			if (retries >= DEQ_RETRIES)
				return num;

			retries++;
			continue;
		}

		retries = 0;
		num++;

		odp_event_free(ev);
	}

	return num;
}

static int enqueue_with_retry(odp_queue_t queue, odp_event_t ev)
{
	int i;

	for (i = 0; i < ENQ_RETRIES; i++)
		if (odp_queue_enq(queue, ev) == 0)
			return 0;

	return -1;
}

static int queue_test_worker(void *arg)
{
	uint32_t num, retries, num_workers;
	int thr_id, ret;
	odp_event_t ev;
	odp_queue_t queue;
	test_globals_t *globals = arg;

	thr_id      = odp_thread_id();
	queue       = globals->queue;
	num_workers = globals->num_workers;

	if (num_workers > 1)
		odp_barrier_wait(&globals->barrier);

	retries = 0;
	num     = odp_atomic_fetch_inc_u32(&globals->num_event);

	/* On average, each worker deq-enq each event once */
	while (num < (num_workers * MAX_NUM_EVENT)) {
		ev = odp_queue_deq(queue);

		if (ev == ODP_EVENT_INVALID) {
			if (retries < DEQ_RETRIES) {
				retries++;
				continue;
			}

			/* Prevent thread to starve */
			num = odp_atomic_fetch_inc_u32(&globals->num_event);
			retries = 0;
			continue;
		}

		globals->thread[thr_id].num_event++;

		ret = enqueue_with_retry(queue, ev);

		CU_ASSERT(ret == 0);

		num = odp_atomic_fetch_inc_u32(&globals->num_event);
	}

	return 0;
}

static void reset_thread_stat(test_globals_t *globals)
{
	int i;

	odp_atomic_init_u32(&globals->num_event, 0);

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		globals->thread[i].num_event = 0;
}

static void multithread_test(odp_nonblocking_t nonblocking)
{
	odp_shm_t shm;
	test_globals_t *globals;
	odp_queue_t queue;
	odp_queue_param_t qparams;
	odp_queue_capability_t capa;
	uint32_t queue_size, max_size;
	uint32_t num, sum, num_free, i;
	int num_workers;
	void *arg;

	CU_ASSERT(odp_queue_capability(&capa) == 0);

	queue_size = 2 * MAX_NUM_EVENT;

	max_size = capa.plain.max_size;

	if (nonblocking == ODP_NONBLOCKING_LF) {
		if (capa.plain.lockfree.max_num == 0) {
			printf("  NO LOCKFREE QUEUES. Test skipped.\n");
			return;
		}

		max_size = capa.plain.lockfree.max_size;
	}

	if (max_size && queue_size > max_size)
		queue_size = max_size;

	num = MAX_NUM_EVENT;

	if (num > queue_size)
		num = queue_size / 2;

	shm = odp_shm_lookup(GLOBALS_NAME);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);

	globals = odp_shm_addr(shm);
	num_workers = globals->num_workers;

	odp_queue_param_init(&qparams);
	qparams.type = ODP_QUEUE_TYPE_PLAIN;
	qparams.size = queue_size;
	qparams.nonblocking = nonblocking;

	queue = odp_queue_create("queue_test_mt", &qparams);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	globals->queue = queue;
	reset_thread_stat(globals);

	CU_ASSERT(alloc_and_enqueue(queue, pool, num) == num);

	arg = globals;
	odp_cunit_thread_create(num_workers, queue_test_worker, &arg, 0, 0);

	/* Wait for worker threads to terminate */
	odp_cunit_thread_join(num_workers);

	sum = 0;
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		sum += globals->thread[i].num_event;

	CU_ASSERT(sum != 0);

	num_free = dequeue_and_free_all(queue);

	CU_ASSERT(num_free == num);
	CU_ASSERT(odp_queue_destroy(queue) == 0);
}

static void queue_test_mt_plain_block(void)
{
	multithread_test(ODP_BLOCKING);
}

static void queue_test_mt_plain_nonblock_lf(void)
{
	multithread_test(ODP_NONBLOCKING_LF);
}

static void queue_test_aggr_capa(const odp_event_aggr_capability_t *capa)
{
	CU_ASSERT(capa->max_num_per_queue <= capa->max_num);
	CU_ASSERT(capa->max_size >= capa->min_size);
	CU_ASSERT(capa->min_size >= 2 || capa->max_num == 0);
	CU_ASSERT(capa->max_tmo_ns >= capa->min_tmo_ns);
}

static void queue_test_aggr_capa_plain(void)
{
	odp_queue_capability_t capa;

	CU_ASSERT(odp_queue_capability(&capa) == 0);
	queue_test_aggr_capa(&capa.plain.aggr);
}

static void queue_test_aggr_capa_sched(void)
{
	odp_schedule_capability_t capa;

	CU_ASSERT(odp_schedule_capability(&capa) == 0);
	queue_test_aggr_capa(&capa.aggr);
}

/*
 * Test that odp_queue_aggr() returns ODP_QUEUE_INVALID when
 * no aggregators have been configured for the queue.
 */
static void queue_test_aggr_cfg_none(odp_queue_type_t queue_type)
{
	odp_queue_param_t param;
	odp_queue_t queue;

	odp_queue_param_init(&param);
	param.type = queue_type;
	param.num_aggr = 0;
	queue = odp_queue_create("queue_test_aggr", &param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);
	CU_ASSERT(odp_queue_aggr(queue, 0) == ODP_QUEUE_INVALID);
	CU_ASSERT(odp_queue_destroy(queue) == 0);
}

static void queue_test_aggr_cfg_none_plain(void)
{
	queue_test_aggr_cfg_none(ODP_QUEUE_TYPE_PLAIN);
}

static void queue_test_aggr_cfg_none_sched(void)
{
	queue_test_aggr_cfg_none(ODP_QUEUE_TYPE_SCHED);
}

static odp_pool_t create_event_vector_pool(void)
{
	odp_pool_param_t param;
	odp_pool_t pool;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_EVENT_VECTOR;
	param.event_vector.num = 1;
	param.event_vector.max_size = 2;
	pool = odp_pool_create(NULL, &param);
	CU_ASSERT(pool != ODP_POOL_INVALID);

	return pool;
}

/*
 * Test that large/maximum number of aggregators can be configured for a queue
 * and the aggregator queue handles can be retrieved and appear valid.
 */
static void queue_test_aggr_cfg_max(const odp_event_aggr_capability_t *capa,
				    odp_queue_type_t queue_type)
{
	uint32_t num, i;
	odp_pool_t evv_pool;
	odp_queue_param_t param;
	odp_queue_t queue, prev_aggr_queue = ODP_QUEUE_INVALID;

	num = capa->max_num_per_queue;
	if (num > MAX_NUM_AGGR_PER_QUEUE)
		num = MAX_NUM_AGGR_PER_QUEUE;
	CU_ASSERT_FATAL(num > 0);

	odp_event_aggr_config_t aggr[num];

	memset(aggr, 0, sizeof(aggr));
	evv_pool = create_event_vector_pool();
	for (i = 0; i < num; i++) {
		aggr[i].pool = evv_pool;
		aggr[i].max_size = 2;
		aggr[i].event_type = ODP_EVENT_ANY;
	}
	odp_queue_param_init(&param);
	param.type = queue_type;
	param.num_aggr = num;
	param.aggr = aggr;
	queue = odp_queue_create("queue_test_aggr", &param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);
	CU_ASSERT(odp_queue_context_set(queue, &capa, 1) == 0);

	for (i = 0; i < num; i++) {
		odp_queue_t aggr_queue = odp_queue_aggr(queue, i);
		odp_queue_info_t info = {.name = NULL};

		CU_ASSERT_FATAL(aggr_queue != ODP_QUEUE_INVALID);
		CU_ASSERT(odp_queue_type(aggr_queue) == ODP_QUEUE_TYPE_AGGR);
		CU_ASSERT(aggr_queue != queue);
		CU_ASSERT(aggr_queue != prev_aggr_queue);
		prev_aggr_queue = aggr_queue;
		CU_ASSERT(odp_queue_to_u64(aggr_queue) !=
			  odp_queue_to_u64(queue));
		if (i == 0 || i == num - 1)
			odp_queue_print(aggr_queue);
		CU_ASSERT(odp_queue_info(aggr_queue, &info) == 0);
		CU_ASSERT(info.param.type == ODP_QUEUE_TYPE_AGGR);
		CU_ASSERT(info.param.context == NULL);
	}
	CU_ASSERT(odp_queue_aggr(queue, num) == ODP_QUEUE_INVALID);

	CU_ASSERT(odp_queue_destroy(queue) == 0);
	CU_ASSERT(odp_pool_destroy(evv_pool) == 0);
}

static void queue_test_aggr_cfg_max_plain(void)
{
	odp_queue_capability_t capa;

	CU_ASSERT_FATAL(odp_queue_capability(&capa) == 0);
	queue_test_aggr_cfg_max(&capa.plain.aggr, ODP_QUEUE_TYPE_PLAIN);
}

static void queue_test_aggr_cfg_max_sched(void)
{
	odp_schedule_capability_t capa;

	CU_ASSERT_FATAL(odp_schedule_capability(&capa) == 0);
	queue_test_aggr_cfg_max(&capa.aggr, ODP_QUEUE_TYPE_SCHED);
}

static int check_plain_queue_aggr(void)
{
	odp_queue_capability_t capa;

	if (odp_queue_capability(&capa) != 0) {
		ODPH_ERR("odp_queue_capability() failed\n");
		return ODP_TEST_INACTIVE;
	}
	return capa.plain.aggr.max_num > 0 ? ODP_TEST_ACTIVE :
					     ODP_TEST_INACTIVE;
}

static int check_sched_queue_aggr(void)
{
	odp_schedule_capability_t capa;

	if (odp_schedule_capability(&capa) != 0) {
		ODPH_ERR("odp_schedule_capability() failed\n");
		return ODP_TEST_INACTIVE;
	}
	return capa.aggr.max_num > 0 ? ODP_TEST_ACTIVE : ODP_TEST_INACTIVE;
}

static void aggr_queue_test(const odp_event_aggr_capability_t *capa, odp_queue_type_t queue_type)
{
	odp_pool_t evv_pool;
	odp_pool_param_t pool_param;
	odp_pool_capability_t pool_capa;
	odp_queue_param_t param;
	odp_queue_t queue, aggr_queue;
	odp_event_aggr_config_t aggr;
	uint32_t max_vectors = 64;
	uint32_t vector_size = 2;
	uint32_t uarea_size = 64;
	uint32_t num_recv = 0;
	uint32_t num_events;
	uint64_t timeout = ODP_TIME_MSEC_IN_NS;

	CU_ASSERT_FATAL(odp_pool_capability(&pool_capa) == 0);
	if (uarea_size > pool_capa.event_vector.max_uarea_size)
		uarea_size = pool_capa.event_vector.max_uarea_size;

	CU_ASSERT(capa->max_size <= pool_capa.event_vector.max_size);

	if (max_vectors > capa->max_num)
		max_vectors = capa->max_num;

	if (vector_size < capa->min_size)
		vector_size = capa->min_size;

	if (timeout > capa->max_tmo_ns)
		timeout = capa->max_tmo_ns;

	/* Send events to both normal and aggregator queue */
	num_events = 2 * (max_vectors / vector_size);

	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_EVENT_VECTOR;
	pool_param.event_vector.num = max_vectors;
	pool_param.event_vector.max_size = vector_size;
	pool_param.event_vector.uarea_size = uarea_size;
	evv_pool = odp_pool_create(NULL, &pool_param);
	CU_ASSERT_FATAL(evv_pool != ODP_POOL_INVALID);

	aggr.pool = evv_pool;
	aggr.max_size = vector_size;
	aggr.event_type = ODP_EVENT_BUFFER;
	aggr.max_tmo_ns = timeout;

	odp_queue_param_init(&param);
	param.type = queue_type;
	param.size = num_events;
	param.num_aggr = 1;
	param.aggr = &aggr;

	queue = odp_queue_create("queue_test_aggr", &param);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	aggr_queue = odp_queue_aggr(queue, 0);
	CU_ASSERT_FATAL(aggr_queue != ODP_QUEUE_INVALID);
	CU_ASSERT(odp_queue_type(aggr_queue) == ODP_QUEUE_TYPE_AGGR);

	for (uint32_t i = 0; i < num_events; i++) {
		odp_queue_t dst_queue = i % 2 ? queue : aggr_queue;
		odp_buffer_t buf = odp_buffer_alloc(pool);

		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

		CU_ASSERT_FATAL(odp_queue_enq(dst_queue, odp_buffer_to_event(buf)) == 0);
	}

	odp_time_wait_ns(timeout);

	while (1) {
		odp_queue_t src_queue;
		odp_event_t event;

		if (queue_type == ODP_QUEUE_TYPE_PLAIN) {
			src_queue = queue;
			event = odp_queue_deq(queue);
		} else {
			event = odp_schedule(&src_queue, odp_schedule_wait_time(timeout));
		}

		if (event == ODP_EVENT_INVALID)
			break;

		CU_ASSERT(src_queue == queue);

		if (odp_event_type(event) == ODP_EVENT_VECTOR) {
			odp_event_t *event_tbl;
			odp_event_vector_t evv = odp_event_vector_from_event(event);
			uint32_t num = odp_event_vector_tbl(evv, &event_tbl);

			CU_ASSERT(odp_event_vector_size(evv) == num);
			CU_ASSERT(num <= vector_size);
			CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_BUFFER);

			if (uarea_size)
				CU_ASSERT(odp_event_vector_user_area(evv) != NULL);
			CU_ASSERT(odp_event_vector_user_flag(evv) == 0);
			CU_ASSERT(odp_event_vector_pool(evv) == evv_pool);

			for (uint32_t i = 0; i < num; i++)
				CU_ASSERT(odp_event_is_valid(event_tbl[i]));
			num_recv += num;
		} else {
			CU_ASSERT(odp_event_type(event) == ODP_EVENT_BUFFER);
			CU_ASSERT(odp_event_pool(event) == pool);
			num_recv++;
		}
		odp_event_free(event);
	}
	CU_ASSERT(num_recv == num_events);

	CU_ASSERT(odp_queue_destroy(queue) == 0);
	CU_ASSERT(odp_pool_destroy(evv_pool) == 0);
}

static void queue_test_aggr_plain_queue(void)
{
	odp_queue_capability_t capa;

	CU_ASSERT_FATAL(odp_queue_capability(&capa) == 0);
	aggr_queue_test(&capa.plain.aggr, ODP_QUEUE_TYPE_PLAIN);
}

static void queue_test_aggr_sched_queue(void)
{
	odp_schedule_capability_t capa;

	CU_ASSERT_FATAL(odp_schedule_capability(&capa) == 0);
	aggr_queue_test(&capa.aggr, ODP_QUEUE_TYPE_SCHED);
}

odp_testinfo_t queue_suite[] = {
	ODP_TEST_INFO(queue_test_capa),
	ODP_TEST_INFO(queue_test_param_init),
	ODP_TEST_INFO(queue_test_mode),
	ODP_TEST_INFO(queue_test_max_plain),
	ODP_TEST_INFO(queue_test_create_destroy_multi),
	ODP_TEST_INFO(queue_test_burst),
	ODP_TEST_INFO(queue_test_burst_spmc),
	ODP_TEST_INFO(queue_test_burst_mpsc),
	ODP_TEST_INFO(queue_test_burst_spsc),
	ODP_TEST_INFO(queue_test_burst_lf),
	ODP_TEST_INFO(queue_test_burst_lf_spmc),
	ODP_TEST_INFO(queue_test_burst_lf_mpsc),
	ODP_TEST_INFO(queue_test_burst_lf_spsc),
	ODP_TEST_INFO(queue_test_pair),
	ODP_TEST_INFO(queue_test_pair_spmc),
	ODP_TEST_INFO(queue_test_pair_mpsc),
	ODP_TEST_INFO(queue_test_pair_spsc),
	ODP_TEST_INFO(queue_test_pair_lf),
	ODP_TEST_INFO(queue_test_pair_lf_spmc),
	ODP_TEST_INFO(queue_test_pair_lf_mpsc),
	ODP_TEST_INFO(queue_test_pair_lf_spsc),
	ODP_TEST_INFO(queue_test_param),
	ODP_TEST_INFO(queue_test_same_name_plain),
	ODP_TEST_INFO(queue_test_same_name_sched),
	ODP_TEST_INFO(queue_test_long_name_plain),
	ODP_TEST_INFO(queue_test_long_name_sched),
	ODP_TEST_INFO(queue_test_info),
	ODP_TEST_INFO(queue_test_mt_plain_block),
	ODP_TEST_INFO(queue_test_mt_plain_nonblock_lf),
	ODP_TEST_INFO(queue_test_aggr_capa_plain),
	ODP_TEST_INFO(queue_test_aggr_capa_sched),
	ODP_TEST_INFO(queue_test_aggr_cfg_none_plain),
	ODP_TEST_INFO(queue_test_aggr_cfg_none_sched),
	ODP_TEST_INFO_CONDITIONAL(queue_test_aggr_cfg_max_plain, check_plain_queue_aggr),
	ODP_TEST_INFO_CONDITIONAL(queue_test_aggr_cfg_max_sched, check_sched_queue_aggr),
	ODP_TEST_INFO_CONDITIONAL(queue_test_aggr_plain_queue, check_plain_queue_aggr),
	ODP_TEST_INFO_CONDITIONAL(queue_test_aggr_sched_queue, check_sched_queue_aggr),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t queue_suites[] = {
	{"Queue", queue_suite_init, queue_suite_term, queue_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(queue_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

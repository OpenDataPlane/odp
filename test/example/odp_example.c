/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP example application
 */

#include <string.h>
#include <stdio.h>

/* ODP main header */
#include <odp.h>

/* ODP helper for Linux apps */
#include <odp_linux.h>

/* Linux headers*/
#include <time.h>


#define MAX_WORKERS           32
#define MSG_POOL_SIZE         (256*1024)
#define MAX_ALLOCS            35
#define QUEUE_ROUNDS          (10*1024)
#define COUNTER_MAX           16


typedef struct {
	int msg_id;
	int seq;
} test_message_t;

#define MSG_HELLO 1
#define MSG_ACK   2


typedef struct {
	odp_spinlock_t lock;
	int counter;
	int foo;
	int bar;
} test_shared_data_t;


static __thread test_shared_data_t *test_shared_data;


static void test_shared(int thr)
{
	struct timespec delay;
	delay.tv_sec = 0;
	delay.tv_nsec = 1000;

	while (1) {
		nanosleep(&delay, NULL);

		odp_spinlock_lock(&test_shared_data->lock);

		if (test_shared_data->counter >= COUNTER_MAX) {
			odp_spinlock_unlock(&test_shared_data->lock);
			break;
		}

		test_shared_data->counter++;
		printf("  [%i] shared counter %i\n", thr,
		       test_shared_data->counter);

		if (test_shared_data->counter == COUNTER_MAX)
			printf("\n");

		odp_spinlock_unlock(&test_shared_data->lock);
	}
}


static void *run_thread(void *arg)
{
	int thr;
	odp_buffer_pool_t msg_pool;
	odp_queue_t queue;
	odp_buffer_t buf;
	test_message_t *t_msg;
	uint64_t t1, t2, cycles, ns;
	odp_buffer_t temp_buf[MAX_ALLOCS];
	int i;
	int prios;

	thr = odp_thread_id();

	printf("Thread %i starts on core %i\n", thr, odp_thread_core());

	/*
	 * Shared mem test
	 */

	test_shared_data = odp_shm_lookup("shared_data");
	printf("  [%i] shared data at %p\n",
	       thr, test_shared_data);

	test_shared(thr);

	/*
	 * Buffer pool test
	 */

	msg_pool = odp_buffer_pool_lookup("msg_pool");

	if (msg_pool == ODP_BUFFER_POOL_INVALID) {
		printf("  [%i] msg_pool not found\n", thr);
		return NULL;
	}

	for (i = 0; i < MAX_ALLOCS; i++) {
		temp_buf[i] = odp_buffer_alloc(msg_pool);

		if (!odp_buffer_is_valid(temp_buf[i]))
			break;
	}

	for (i = i; i > 0; i--)
		odp_buffer_free(temp_buf[i-1]);


	/*
	 * Poll queue test
	 *
	 * Enqueue to and dequeue from a shared queue.
	 */

	/* Alloc test message */
	buf = odp_buffer_alloc(msg_pool);

	if (!odp_buffer_is_valid(buf)) {
		printf("  [%i] msg_pool alloc failed\n", thr);
		return NULL;
	}

	/* odp_buffer_print(buf); */

	t_msg = odp_buffer_addr(buf);
	t_msg->msg_id = MSG_HELLO;
	t_msg->seq    = 0;

	queue = odp_queue_lookup("poll_queue");

	if (queue == ODP_QUEUE_INVALID) {
		printf("  [%i] Queue lookup failed.\n", thr);
		return NULL;
	}

	t1 = odp_time_get_cycles();

	for (i = 0; i < QUEUE_ROUNDS; i++) {
		if (odp_queue_enq(queue, buf)) {
			printf("  [%i] Queue enqueue failed.\n", thr);
			return NULL;
		}

		buf = odp_queue_deq(queue);

		if (!odp_buffer_is_valid(buf)) {
			printf("  [%i] Queue empty.\n", thr);
			return NULL;
		}
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);

	printf("  [%i] poll queue enq+deq %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, cycles/QUEUE_ROUNDS, ns/QUEUE_ROUNDS);


	/*
	 * Schedule queue test
	 *
	 * A shared queues per priority.
	 * Enqueue a buffer to a shared queue, schedule until
	 * a buffer is returned. Repeat over all queues (priorities).
	 */
	prios = odp_schedule_num_prio();

	t1 = odp_time_get_cycles();

	for (i = 0; i < prios; i++) {
		char name[] = "sched_XX";
		int j;

		name[6] = '0' + i/10;
		name[7] = '0' + i - 10*(i/10);

		queue = odp_queue_lookup(name);

		if (queue == ODP_QUEUE_INVALID) {
			printf("  [%i] Queue %s lookup failed.\n", thr, name);
			return NULL;
		}

		/* printf("  [%i] prio %i queue %s\n", thr, i, name); */

		for (j = 0; j < QUEUE_ROUNDS; j++) {
			if (odp_queue_enq(queue, buf)) {
				printf("  [%i] Queue enqueue failed.\n", thr);
				return NULL;
			}

			buf = odp_schedule_poll();

			if (!odp_buffer_is_valid(buf)) {
				printf("  [%i] Sched queue empty.\n", thr);
				return NULL;
			}
		}
	}

	t2     = odp_time_get_cycles();
	cycles = odp_time_diff_cycles(t1, t2);
	ns     = odp_time_cycles_to_ns(cycles);

	printf("  [%i] sched queue enq+deq %"PRIu64" cycles, %"PRIu64" ns\n",
	       thr, cycles/(prios*QUEUE_ROUNDS), ns/(prios*QUEUE_ROUNDS));

	/* Free test message */
	odp_buffer_free(buf);

	printf("Thread %i exits\n", thr);
	fflush(stdout);
	return arg;
}



int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	odp_coremask_t coremask;
	odp_linux_pthread_t thread_tbl[MAX_WORKERS];
	char str[32];
	int thr_id;
	int num_workers;
	odp_buffer_pool_t pool;
	void *pool_base;
	odp_queue_t queue;
	int i;
	int prios;

	printf("\nODP example starts\n");

	memset(thread_tbl, 0, sizeof(thread_tbl));
	memset(str, 1, sizeof(str));

	if (odp_init_global()) {
		printf("ODP global init failed.\n");
		return -1;
	}

	odp_coremask_zero(&coremask);

	odp_coremask_from_str("0x1", &coremask);
	odp_coremask_to_str(str, sizeof(str), &coremask);

	printf("\n");
	printf("ODP system info\n");
	printf("---------------\n");
	printf("ODP API version: %s\n",        odp_version_api_str());
	printf("CPU model:       %s\n",        odp_sys_cpu_model_str());
	printf("CPU freq (hz):   %"PRIu64"\n", odp_sys_cpu_hz());
	printf("Cache line size: %i\n",        odp_sys_cache_line_size());
	printf("Core count:      %i\n",        odp_sys_core_count());
	printf("Core mask:       %s\n",        str);

	printf("\n");

	/* A worker thread per core */
	num_workers = odp_sys_core_count();

	/* force to max core count */
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	/*
	 * Init this thread. It makes also ODP calls when
	 * setting up resources for worker threads.
	 */
	thr_id = odp_thread_create(0);
	odp_init_local(thr_id);

	/*
	 * Create shared data
	 */
	test_shared_data = odp_shm_reserve("shared_data",
					  sizeof(test_shared_data_t),
					  ODP_CACHE_LINE_SIZE);

	memset(test_shared_data, 0, sizeof(test_shared_data_t));
	odp_spinlock_init(&test_shared_data->lock);

	printf("test shared data at %p\n\n", test_shared_data);

	/*
	 * Create message pool
	 */
	pool_base = odp_shm_reserve("msg_pool",
				    MSG_POOL_SIZE, ODP_CACHE_LINE_SIZE);

	pool = odp_buffer_pool_create("msg_pool", pool_base, MSG_POOL_SIZE,
				      sizeof(test_message_t),
				      ODP_CACHE_LINE_SIZE, ODP_BUFFER_TYPE_RAW);

	if (pool == ODP_BUFFER_POOL_INVALID) {
		printf("Pool create failed.\n");
		return -1;
	}

	/* odp_buffer_pool_print(pool); */

	/*
	 * Create a queue for direct polling
	 */
	queue = odp_queue_create("poll_queue", ODP_QUEUE_TYPE_POLL, NULL);

	if (queue == ODP_QUEUE_INVALID) {
		printf("Poll queue create failed.\n");
		return -1;
	}


	/*
	 * Create queues for scheduling. One per priority.
	 */
	prios = odp_schedule_num_prio();

	for (i = 0; i < prios; i++) {
		odp_queue_param_t param;
		char name[] = "sched_XX";

		name[6] = '0' + i/10;
		name[7] = '0' + i - 10*(i/10);

		param.sched.prio  = i;
		param.sched.sync  = ODP_SCHED_SYNC_NONE;
		param.sched.group = ODP_SCHED_GROUP_DEFAULT;

		queue = odp_queue_create(name, ODP_QUEUE_TYPE_SCHED, &param);

		if (queue == ODP_QUEUE_INVALID) {
			printf("Schedule queue create failed.\n");
			return -1;
		}
	}

	odp_shm_print_all();

	/* Create and launch worker threads */
	odp_linux_pthread_create(thread_tbl, num_workers, 1, run_thread, NULL);

	/* Wait for worker threads to exit */
	odp_linux_pthread_join(thread_tbl, num_workers);

	printf("ODP example complete\n\n");

	return 0;
}


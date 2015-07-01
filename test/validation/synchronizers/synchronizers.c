/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <malloc.h>
#include <odp.h>
#include <CUnit/Basic.h>
#include <odp_cunit_common.h>
#include <unistd.h>
#include "synchronizers.h"

#define VERBOSE			0
#define MAX_ITERATIONS		1000
#define BARRIER_ITERATIONS	64

#define SLOW_BARRIER_DELAY	400
#define BASE_DELAY		6
#define MIN_DELAY		1

#define NUM_TEST_BARRIERS	BARRIER_ITERATIONS
#define NUM_RESYNC_BARRIERS	100

#define ADD_SUB_CNT		5

#define CNT			10
#define BARRIER_DELAY		10
#define U32_INIT_VAL		(1UL << 10)
#define U64_INIT_VAL		(1ULL << 33)

#define GLOBAL_SHM_NAME		"GlobalLockTest"

#define UNUSED			__attribute__((__unused__))

static odp_atomic_u32_t a32u;
static odp_atomic_u64_t a64u;

typedef __volatile uint32_t volatile_u32_t;
typedef __volatile uint64_t volatile_u64_t;

typedef struct {
	odp_atomic_u32_t wait_cnt;
} custom_barrier_t;

typedef struct {
	/* Global variables */
	uint32_t g_num_threads;
	uint32_t g_iterations;
	uint32_t g_verbose;
	uint32_t g_max_num_cores;

	odp_barrier_t test_barriers[NUM_TEST_BARRIERS];
	custom_barrier_t custom_barrier1[NUM_TEST_BARRIERS];
	custom_barrier_t custom_barrier2[NUM_TEST_BARRIERS];
	volatile_u32_t slow_thread_num;
	volatile_u32_t barrier_cnt1;
	volatile_u32_t barrier_cnt2;
	odp_barrier_t global_barrier;

	/* Used to periodically resync within the lock functional tests */
	odp_barrier_t barrier_array[NUM_RESYNC_BARRIERS];

	/* Locks */
	odp_spinlock_t global_spinlock;
	odp_ticketlock_t global_ticketlock;
	odp_rwlock_t global_rwlock;

	volatile_u32_t global_lock_owner;
} global_shared_mem_t;

/* Per-thread memory */
typedef struct {
	global_shared_mem_t *global_mem;

	int thread_id;
	int thread_core;

	odp_spinlock_t per_thread_spinlock;
	odp_ticketlock_t per_thread_ticketlock;
	odp_rwlock_t per_thread_rwlock;

	volatile_u64_t delay_counter;
} per_thread_mem_t;

static odp_shm_t global_shm;
static global_shared_mem_t *global_mem;

/*
* Delay a consistent amount of time.  Ideally the amount of CPU time taken
* is linearly proportional to "iterations".  The goal is to try to do some
* work that the compiler optimizer won't optimize away, and also to
* minimize loads and stores (at least to different memory addresses)
* so as to not affect or be affected by caching issues.  This does NOT have to
* correlate to a specific number of cpu cycles or be consistent across
* CPU architectures.
*/
static void thread_delay(per_thread_mem_t *per_thread_mem, uint32_t iterations)
{
	volatile_u64_t *counter_ptr;
	uint32_t cnt;

	counter_ptr = &per_thread_mem->delay_counter;

	for (cnt = 1; cnt <= iterations; cnt++)
		(*counter_ptr)++;
}

/* Initialise per-thread memory */
static per_thread_mem_t *thread_init(void)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	odp_shm_t global_shm;
	uint32_t per_thread_mem_len;

	per_thread_mem_len = sizeof(per_thread_mem_t);
	per_thread_mem = malloc(per_thread_mem_len);
	memset(per_thread_mem, 0, per_thread_mem_len);

	per_thread_mem->delay_counter = 1;

	per_thread_mem->thread_id = odp_thread_id();
	per_thread_mem->thread_core = odp_cpu_id();

	global_shm = odp_shm_lookup(GLOBAL_SHM_NAME);
	global_mem = odp_shm_addr(global_shm);
	CU_ASSERT_PTR_NOT_NULL(global_mem);

	per_thread_mem->global_mem = global_mem;

	return per_thread_mem;
}

static void thread_finalize(per_thread_mem_t *per_thread_mem)
{
	free(per_thread_mem);
}

static void custom_barrier_init(custom_barrier_t *custom_barrier,
				uint32_t num_threads)
{
	odp_atomic_init_u32(&custom_barrier->wait_cnt, num_threads);
}

static void custom_barrier_wait(custom_barrier_t *custom_barrier)
{
	volatile_u64_t counter = 1;
	uint32_t delay_cnt, wait_cnt;

	odp_atomic_sub_u32(&custom_barrier->wait_cnt, 1);

	wait_cnt = 1;
	while (wait_cnt != 0) {
		for (delay_cnt = 1; delay_cnt <= BARRIER_DELAY; delay_cnt++)
			counter++;

		wait_cnt = odp_atomic_load_u32(&custom_barrier->wait_cnt);
	}
}

static uint32_t barrier_test(per_thread_mem_t *per_thread_mem,
			     odp_bool_t no_barrier_test)
{
	global_shared_mem_t *global_mem;
	uint32_t barrier_errs, iterations, cnt, i_am_slow_thread;
	uint32_t thread_num, slow_thread_num, next_slow_thread, num_threads;
	uint32_t lock_owner_delay, barrier_cnt1, barrier_cnt2;

	thread_num = odp_thread_id();
	global_mem = per_thread_mem->global_mem;
	num_threads = global_mem->g_num_threads;
	iterations = BARRIER_ITERATIONS;

	barrier_errs = 0;
	lock_owner_delay = SLOW_BARRIER_DELAY;

	for (cnt = 1; cnt < iterations; cnt++) {
		/* Wait here until all of the threads reach this point */
		custom_barrier_wait(&global_mem->custom_barrier1[cnt]);

		barrier_cnt1 = global_mem->barrier_cnt1;
		barrier_cnt2 = global_mem->barrier_cnt2;

		if ((barrier_cnt1 != cnt) || (barrier_cnt2 != cnt)) {
			printf("thread_num=%" PRIu32 " barrier_cnts of %" PRIu32
				   " %" PRIu32 " cnt=%" PRIu32 "\n",
			       thread_num, barrier_cnt1, barrier_cnt2, cnt);
			barrier_errs++;
		}

		/* Wait here until all of the threads reach this point */
		custom_barrier_wait(&global_mem->custom_barrier2[cnt]);

		slow_thread_num = global_mem->slow_thread_num;
		i_am_slow_thread = thread_num == slow_thread_num;
		next_slow_thread = slow_thread_num + 1;
		if (num_threads < next_slow_thread)
			next_slow_thread = 1;

		/*
		* Now run the test, which involves having all but one thread
		* immediately calling odp_barrier_wait(), and one thread wait a
		* moderate amount of time and then calling odp_barrier_wait().
		* The test fails if any of the first group of threads
		* has not waited for the "slow" thread. The "slow" thread is
		* responsible for re-initializing the barrier for next trial.
		*/
		if (i_am_slow_thread) {
			thread_delay(per_thread_mem, lock_owner_delay);
			lock_owner_delay += BASE_DELAY;
			if ((global_mem->barrier_cnt1 != cnt) ||
			    (global_mem->barrier_cnt2 != cnt) ||
			    (global_mem->slow_thread_num
					!= slow_thread_num))
				barrier_errs++;
		}

		if (no_barrier_test == 0)
			odp_barrier_wait(&global_mem->test_barriers[cnt]);

		global_mem->barrier_cnt1 = cnt + 1;
		odp_sync_stores();

		if (i_am_slow_thread) {
			global_mem->slow_thread_num = next_slow_thread;
			global_mem->barrier_cnt2 = cnt + 1;
			odp_sync_stores();
		} else {
			while (global_mem->barrier_cnt2 != (cnt + 1))
				thread_delay(per_thread_mem, BASE_DELAY);
		}
	}

	if ((global_mem->g_verbose) && (barrier_errs != 0))
		printf("\nThread %" PRIu32 " (id=%d core=%d) had %" PRIu32
		       " barrier_errs in %" PRIu32 " iterations\n", thread_num,
		       per_thread_mem->thread_id,
		       per_thread_mem->thread_core, barrier_errs, iterations);

	return barrier_errs;
}

static void *no_barrier_functional_test(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;
	uint32_t barrier_errs;

	per_thread_mem = thread_init();
	barrier_errs = barrier_test(per_thread_mem, 1);

	/*
	* Note that the following CU_ASSERT MAY appear incorrect, but for the
	* no_barrier test it should see barrier_errs or else there is something
	* wrong with the test methodology or the ODP thread implementation.
	* So this test PASSES only if it sees barrier_errs!
	*/
	CU_ASSERT(barrier_errs != 0);
	thread_finalize(per_thread_mem);

	return NULL;
}

static void *barrier_functional_test(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;
	uint32_t barrier_errs;

	per_thread_mem = thread_init();
	barrier_errs = barrier_test(per_thread_mem, 0);

	CU_ASSERT(barrier_errs == 0);
	thread_finalize(per_thread_mem);

	return NULL;
}

static void spinlock_api_test(odp_spinlock_t *spinlock)
{
	odp_spinlock_init(spinlock);
	CU_ASSERT(odp_spinlock_is_locked(spinlock) == 0);

	odp_spinlock_lock(spinlock);
	CU_ASSERT(odp_spinlock_is_locked(spinlock) == 1);

	odp_spinlock_unlock(spinlock);
	CU_ASSERT(odp_spinlock_is_locked(spinlock) == 0);

	CU_ASSERT(odp_spinlock_trylock(spinlock) == 1);

	CU_ASSERT(odp_spinlock_is_locked(spinlock) == 1);

	odp_spinlock_unlock(spinlock);
	CU_ASSERT(odp_spinlock_is_locked(spinlock) == 0);
}

static void *spinlock_api_tests(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	odp_spinlock_t local_spin_lock;

	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;

	odp_barrier_wait(&global_mem->global_barrier);

	spinlock_api_test(&local_spin_lock);
	spinlock_api_test(&per_thread_mem->per_thread_spinlock);

	thread_finalize(per_thread_mem);

	return NULL;
}

static void ticketlock_api_test(odp_ticketlock_t *ticketlock)
{
	odp_ticketlock_init(ticketlock);
	CU_ASSERT(odp_ticketlock_is_locked(ticketlock) == 0);

	odp_ticketlock_lock(ticketlock);
	CU_ASSERT(odp_ticketlock_is_locked(ticketlock) == 1);

	odp_ticketlock_unlock(ticketlock);
	CU_ASSERT(odp_ticketlock_is_locked(ticketlock) == 0);

	CU_ASSERT(odp_ticketlock_trylock(ticketlock) == 1);
	CU_ASSERT(odp_ticketlock_trylock(ticketlock) == 0);
	CU_ASSERT(odp_ticketlock_is_locked(ticketlock) == 1);

	odp_ticketlock_unlock(ticketlock);
	CU_ASSERT(odp_ticketlock_is_locked(ticketlock) == 0);
}

static void *ticketlock_api_tests(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	odp_ticketlock_t local_ticket_lock;

	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;

	odp_barrier_wait(&global_mem->global_barrier);

	ticketlock_api_test(&local_ticket_lock);
	ticketlock_api_test(&per_thread_mem->per_thread_ticketlock);

	thread_finalize(per_thread_mem);

	return NULL;
}

static void rwlock_api_test(odp_rwlock_t *rw_lock)
{
	odp_rwlock_init(rw_lock);
	/* CU_ASSERT(odp_rwlock_is_locked(rw_lock) == 0); */

	odp_rwlock_read_lock(rw_lock);
	odp_rwlock_read_unlock(rw_lock);

	odp_rwlock_write_lock(rw_lock);
	/* CU_ASSERT(odp_rwlock_is_locked(rw_lock) == 1); */

	odp_rwlock_write_unlock(rw_lock);
	/* CU_ASSERT(odp_rwlock_is_locked(rw_lock) == 0); */
}

static void *rwlock_api_tests(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	odp_rwlock_t local_rwlock;

	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;

	odp_barrier_wait(&global_mem->global_barrier);

	rwlock_api_test(&local_rwlock);
	rwlock_api_test(&per_thread_mem->per_thread_rwlock);

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *no_lock_functional_test(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	uint32_t thread_num, resync_cnt, rs_idx, iterations, cnt;
	uint32_t sync_failures, current_errs, lock_owner_delay;

	thread_num = odp_cpu_id() + 1;
	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;
	iterations = global_mem->g_iterations;

	odp_barrier_wait(&global_mem->global_barrier);

	sync_failures = 0;
	current_errs = 0;
	rs_idx = 0;
	resync_cnt = iterations / NUM_RESYNC_BARRIERS;
	lock_owner_delay = BASE_DELAY;

	for (cnt = 1; cnt <= iterations; cnt++) {
		global_mem->global_lock_owner = thread_num;
		odp_sync_stores();
		thread_delay(per_thread_mem, lock_owner_delay);

		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			sync_failures++;
		}

		global_mem->global_lock_owner = 0;
		odp_sync_stores();
		thread_delay(per_thread_mem, MIN_DELAY);

		if (global_mem->global_lock_owner == thread_num) {
			current_errs++;
			sync_failures++;
		}

		if (current_errs == 0)
			lock_owner_delay++;

		/* Wait a small amount of time and rerun the test */
		thread_delay(per_thread_mem, BASE_DELAY);

		/* Try to resync all of the threads to increase contention */
		if ((rs_idx < NUM_RESYNC_BARRIERS) &&
		    ((cnt % resync_cnt) == (resync_cnt - 1)))
			odp_barrier_wait(&global_mem->barrier_array[rs_idx++]);
	}

	if (global_mem->g_verbose)
		printf("\nThread %" PRIu32 " (id=%d core=%d) had %" PRIu32
		       " sync_failures in %" PRIu32 " iterations\n",
		       thread_num,
		       per_thread_mem->thread_id,
		       per_thread_mem->thread_core,
		       sync_failures, iterations);

	/* Note that the following CU_ASSERT MAY appear incorrect, but for the
	* no_lock test it should see sync_failures or else there is something
	* wrong with the test methodology or the ODP thread implementation.
	* So this test PASSES only if it sees sync_failures
	*/
	CU_ASSERT(sync_failures != 0);

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *spinlock_functional_test(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	uint32_t thread_num, resync_cnt, rs_idx, iterations, cnt;
	uint32_t sync_failures, is_locked_errs, current_errs;
	uint32_t lock_owner_delay;

	thread_num = odp_cpu_id() + 1;
	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;
	iterations = global_mem->g_iterations;

	odp_barrier_wait(&global_mem->global_barrier);

	sync_failures = 0;
	is_locked_errs = 0;
	current_errs = 0;
	rs_idx = 0;
	resync_cnt = iterations / NUM_RESYNC_BARRIERS;
	lock_owner_delay = BASE_DELAY;

	for (cnt = 1; cnt <= iterations; cnt++) {
		/* Acquire the shared global lock */
		odp_spinlock_lock(&global_mem->global_spinlock);

		/* Make sure we have the lock AND didn't previously own it */
		if (odp_spinlock_is_locked(&global_mem->global_spinlock) != 1)
			is_locked_errs++;

		if (global_mem->global_lock_owner != 0) {
			current_errs++;
			sync_failures++;
		}

		/* Now set the global_lock_owner to be us, wait a while, and
		* then we see if anyone else has snuck in and changed the
		* global_lock_owner to be themselves
		*/
		global_mem->global_lock_owner = thread_num;
		odp_sync_stores();
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			sync_failures++;
		}

		/* Release shared lock, and make sure we no longer have it */
		global_mem->global_lock_owner = 0;
		odp_sync_stores();
		odp_spinlock_unlock(&global_mem->global_spinlock);
		if (global_mem->global_lock_owner == thread_num) {
			current_errs++;
			sync_failures++;
		}

		if (current_errs == 0)
			lock_owner_delay++;

		/* Wait a small amount of time and rerun the test */
		thread_delay(per_thread_mem, BASE_DELAY);

		/* Try to resync all of the threads to increase contention */
		if ((rs_idx < NUM_RESYNC_BARRIERS) &&
		    ((cnt % resync_cnt) == (resync_cnt - 1)))
			odp_barrier_wait(&global_mem->barrier_array[rs_idx++]);
	}

	if ((global_mem->g_verbose) &&
	    ((sync_failures != 0) || (is_locked_errs != 0)))
		printf("\nThread %" PRIu32 " (id=%d core=%d) had %" PRIu32
		       " sync_failures and %" PRIu32
		       " is_locked_errs in %" PRIu32
		       " iterations\n", thread_num,
		       per_thread_mem->thread_id, per_thread_mem->thread_core,
		       sync_failures, is_locked_errs, iterations);

	CU_ASSERT(sync_failures == 0);
	CU_ASSERT(is_locked_errs == 0);

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *ticketlock_functional_test(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	uint32_t thread_num, resync_cnt, rs_idx, iterations, cnt;
	uint32_t sync_failures, is_locked_errs, current_errs;
	uint32_t lock_owner_delay;

	thread_num = odp_cpu_id() + 1;
	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;
	iterations = global_mem->g_iterations;

	/* Wait here until all of the threads have also reached this point */
	odp_barrier_wait(&global_mem->global_barrier);

	sync_failures = 0;
	is_locked_errs = 0;
	current_errs = 0;
	rs_idx = 0;
	resync_cnt = iterations / NUM_RESYNC_BARRIERS;
	lock_owner_delay = BASE_DELAY;

	for (cnt = 1; cnt <= iterations; cnt++) {
		/* Acquire the shared global lock */
		odp_ticketlock_lock(&global_mem->global_ticketlock);

		/* Make sure we have the lock AND didn't previously own it */
		if (odp_ticketlock_is_locked(&global_mem->global_ticketlock)
				!= 1)
			is_locked_errs++;

		if (global_mem->global_lock_owner != 0) {
			current_errs++;
			sync_failures++;
		}

		/* Now set the global_lock_owner to be us, wait a while, and
		* then we see if anyone else has snuck in and changed the
		* global_lock_owner to be themselves
		*/
		global_mem->global_lock_owner = thread_num;
		odp_sync_stores();
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			sync_failures++;
		}

		/* Release shared lock, and make sure we no longer have it */
		global_mem->global_lock_owner = 0;
		odp_sync_stores();
		odp_ticketlock_unlock(&global_mem->global_ticketlock);
		if (global_mem->global_lock_owner == thread_num) {
			current_errs++;
			sync_failures++;
		}

		if (current_errs == 0)
			lock_owner_delay++;

		/* Wait a small amount of time and then rerun the test */
		thread_delay(per_thread_mem, BASE_DELAY);

		/* Try to resync all of the threads to increase contention */
		if ((rs_idx < NUM_RESYNC_BARRIERS) &&
		    ((cnt % resync_cnt) == (resync_cnt - 1)))
			odp_barrier_wait(&global_mem->barrier_array[rs_idx++]);
	}

	if ((global_mem->g_verbose) &&
	    ((sync_failures != 0) || (is_locked_errs != 0)))
		printf("\nThread %" PRIu32 " (id=%d core=%d) had %" PRIu32
		       " sync_failures and %" PRIu32
		       " is_locked_errs in %" PRIu32 " iterations\n",
		       thread_num,
		       per_thread_mem->thread_id, per_thread_mem->thread_core,
		       sync_failures, is_locked_errs, iterations);

	CU_ASSERT(sync_failures == 0);
	CU_ASSERT(is_locked_errs == 0);

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *rwlock_functional_test(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	uint32_t thread_num, resync_cnt, rs_idx, iterations, cnt;
	uint32_t sync_failures, current_errs, lock_owner_delay;

	thread_num = odp_cpu_id() + 1;
	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;
	iterations = global_mem->g_iterations;

	/* Wait here until all of the threads have also reached this point */
	odp_barrier_wait(&global_mem->global_barrier);

	sync_failures = 0;
	current_errs = 0;
	rs_idx = 0;
	resync_cnt = iterations / NUM_RESYNC_BARRIERS;
	lock_owner_delay = BASE_DELAY;

	for (cnt = 1; cnt <= iterations; cnt++) {
		/* Acquire the shared global lock */
		odp_rwlock_write_lock(&global_mem->global_rwlock);

		/* Make sure we have lock now AND didn't previously own it */
		if (global_mem->global_lock_owner != 0) {
			current_errs++;
			sync_failures++;
		}

		/* Now set the global_lock_owner to be us, wait a while, and
		* then we see if anyone else has snuck in and changed the
		* global_lock_owner to be themselves
		*/
		global_mem->global_lock_owner = thread_num;
		odp_sync_stores();
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			sync_failures++;
		}

		/* Release shared lock, and make sure we no longer have it */
		global_mem->global_lock_owner = 0;
		odp_sync_stores();
		odp_rwlock_write_unlock(&global_mem->global_rwlock);
		if (global_mem->global_lock_owner == thread_num) {
			current_errs++;
			sync_failures++;
		}

		if (current_errs == 0)
			lock_owner_delay++;

		/* Wait a small amount of time and then rerun the test */
		thread_delay(per_thread_mem, BASE_DELAY);

		/* Try to resync all of the threads to increase contention */
		if ((rs_idx < NUM_RESYNC_BARRIERS) &&
		    ((cnt % resync_cnt) == (resync_cnt - 1)))
			odp_barrier_wait(&global_mem->barrier_array[rs_idx++]);
	}

	if ((global_mem->g_verbose) && (sync_failures != 0))
		printf("\nThread %" PRIu32 " (id=%d core=%d) had %" PRIu32
		       " sync_failures in %" PRIu32 " iterations\n", thread_num,
		       per_thread_mem->thread_id,
		       per_thread_mem->thread_core,
		       sync_failures, iterations);

	CU_ASSERT(sync_failures == 0);

	thread_finalize(per_thread_mem);

	return NULL;
}

static void barrier_test_init(void)
{
	uint32_t num_threads, idx;

	num_threads = global_mem->g_num_threads;

	for (idx = 0; idx < NUM_TEST_BARRIERS; idx++) {
		odp_barrier_init(&global_mem->test_barriers[idx], num_threads);
		custom_barrier_init(&global_mem->custom_barrier1[idx],
				    num_threads);
		custom_barrier_init(&global_mem->custom_barrier2[idx],
				    num_threads);
	}

	global_mem->slow_thread_num = 1;
	global_mem->barrier_cnt1 = 1;
	global_mem->barrier_cnt2 = 1;
}

static void test_atomic_inc_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_u32(&a32u);
}

static void test_atomic_inc_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_u64(&a64u);
}

static void test_atomic_dec_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_dec_u32(&a32u);
}

static void test_atomic_dec_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_dec_u64(&a64u);
}

static void test_atomic_fetch_inc_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_inc_u32(&a32u);
}

static void test_atomic_fetch_inc_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_inc_u64(&a64u);
}

static void test_atomic_fetch_dec_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_dec_u32(&a32u);
}

static void test_atomic_fetch_dec_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_dec_u64(&a64u);
}

static void test_atomic_add_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_add_u32(&a32u, ADD_SUB_CNT);
}

static void test_atomic_add_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_add_u64(&a64u, ADD_SUB_CNT);
}

static void test_atomic_sub_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_sub_u32(&a32u, ADD_SUB_CNT);
}

static void test_atomic_sub_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_sub_u64(&a64u, ADD_SUB_CNT);
}

static void test_atomic_fetch_add_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_add_u32(&a32u, ADD_SUB_CNT);
}

static void test_atomic_fetch_add_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_add_u64(&a64u, ADD_SUB_CNT);
}

static void test_atomic_fetch_sub_32(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_sub_u32(&a32u, ADD_SUB_CNT);
}

static void test_atomic_fetch_sub_64(void)
{
	int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_fetch_sub_u64(&a64u, ADD_SUB_CNT);
}

static void test_atomic_inc_dec_32(void)
{
	test_atomic_inc_32();
	test_atomic_dec_32();
}

static void test_atomic_inc_dec_64(void)
{
	test_atomic_inc_64();
	test_atomic_dec_64();
}

static void test_atomic_fetch_inc_dec_32(void)
{
	test_atomic_fetch_inc_32();
	test_atomic_fetch_dec_32();
}

static void test_atomic_fetch_inc_dec_64(void)
{
	test_atomic_fetch_inc_64();
	test_atomic_fetch_dec_64();
}

static void test_atomic_add_sub_32(void)
{
	test_atomic_add_32();
	test_atomic_sub_32();
}

static void test_atomic_add_sub_64(void)
{
	test_atomic_add_64();
	test_atomic_sub_64();
}

static void test_atomic_fetch_add_sub_32(void)
{
	test_atomic_fetch_add_32();
	test_atomic_fetch_sub_32();
}

static void test_atomic_fetch_add_sub_64(void)
{
	test_atomic_fetch_add_64();
	test_atomic_fetch_sub_64();
}

static void test_atomic_init(void)
{
	odp_atomic_init_u32(&a32u, 0);
	odp_atomic_init_u64(&a64u, 0);
}

static void test_atomic_store(void)
{
	odp_atomic_store_u32(&a32u, U32_INIT_VAL);
	odp_atomic_store_u64(&a64u, U64_INIT_VAL);
}

static void test_atomic_validate(void)
{
	CU_ASSERT(U32_INIT_VAL == odp_atomic_load_u32(&a32u));
	CU_ASSERT(U64_INIT_VAL == odp_atomic_load_u64(&a64u));
}

/* Barrier tests */
static void synchronizers_test_no_barrier_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	barrier_test_init();
	odp_cunit_thread_create(no_barrier_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

static void synchronizers_test_barrier_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	barrier_test_init();
	odp_cunit_thread_create(barrier_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

static CU_TestInfo synchronizers_suite_barrier[] = {
	{"no_barrier_functional", synchronizers_test_no_barrier_functional},
	{"barrier_functional", synchronizers_test_barrier_functional},
	CU_TEST_INFO_NULL
};

/* Thread-unsafe tests */
static void synchronizers_test_no_lock_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_cunit_thread_create(no_lock_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

static CU_TestInfo synchronizers_suite_no_locking[] = {
	{"no_lock_functional", synchronizers_test_no_lock_functional},
	CU_TEST_INFO_NULL
};

/* Spin lock tests */
static void synchronizers_test_spinlock_api(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_cunit_thread_create(spinlock_api_tests, &arg);
	odp_cunit_thread_exit(&arg);
}

static void synchronizers_test_spinlock_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_spinlock_init(&global_mem->global_spinlock);
	odp_cunit_thread_create(spinlock_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

static CU_TestInfo synchronizers_suite_spinlock[] = {
	{"spinlock_api", synchronizers_test_spinlock_api},
	{"spinlock_functional", synchronizers_test_spinlock_functional},
	CU_TEST_INFO_NULL
};

/* Ticket lock tests */
static void synchronizers_test_ticketlock_api(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_cunit_thread_create(ticketlock_api_tests, &arg);
	odp_cunit_thread_exit(&arg);
}

static void synchronizers_test_ticketlock_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_ticketlock_init(&global_mem->global_ticketlock);

	odp_cunit_thread_create(ticketlock_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

static CU_TestInfo synchronizers_suite_ticketlock[] = {
	{"ticketlock_api", synchronizers_test_ticketlock_api},
	{"ticketlock_functional", synchronizers_test_ticketlock_functional},
	CU_TEST_INFO_NULL
};

/* RW lock tests */
static void synchronizers_test_rwlock_api(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_cunit_thread_create(rwlock_api_tests, &arg);
	odp_cunit_thread_exit(&arg);
}

static void synchronizers_test_rwlock_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_rwlock_init(&global_mem->global_rwlock);
	odp_cunit_thread_create(rwlock_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

static CU_TestInfo synchronizers_suite_rwlock[] = {
	{"rwlock_api", synchronizers_test_rwlock_api},
	{"rwlock_functional", synchronizers_test_rwlock_functional},
	CU_TEST_INFO_NULL
};

static int synchronizers_suite_init(void)
{
	uint32_t num_threads, idx;

	num_threads = global_mem->g_num_threads;
	odp_barrier_init(&global_mem->global_barrier, num_threads);
	for (idx = 0; idx < NUM_RESYNC_BARRIERS; idx++)
		odp_barrier_init(&global_mem->barrier_array[idx], num_threads);

	return 0;
}

int tests_global_init(void)
{
	uint32_t core_count, max_threads;
	int ret = 0;

	if (0 != odp_init_global(NULL, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}
	if (0 != odp_init_local()) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	global_shm = odp_shm_reserve(GLOBAL_SHM_NAME,
				     sizeof(global_shared_mem_t), 64,
				     ODP_SHM_SW_ONLY);
	if (ODP_SHM_INVALID == global_shm) {
		fprintf(stderr, "Unable reserve memory for global_shm\n");
		return -1;
	}

	global_mem = odp_shm_addr(global_shm);
	memset(global_mem, 0, sizeof(global_shared_mem_t));

	global_mem->g_num_threads = MAX_WORKERS;
	global_mem->g_iterations = MAX_ITERATIONS;
	global_mem->g_verbose = VERBOSE;

	core_count = odp_cpu_count();

	max_threads = (core_count >= MAX_WORKERS) ? MAX_WORKERS : core_count;

	if (max_threads < global_mem->g_num_threads) {
		printf("Requested num of threads is too large\n");
		printf("reducing from %" PRIu32 " to %" PRIu32 "\n",
		       global_mem->g_num_threads,
		       max_threads);
		global_mem->g_num_threads = max_threads;
	}

	printf("Num of threads used = %" PRIu32 "\n",
	       global_mem->g_num_threads);

	return ret;
}

/* Atomic tests */
static void *test_atomic_inc_dec_thread(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;

	per_thread_mem = thread_init();
	test_atomic_inc_dec_32();
	test_atomic_inc_dec_64();

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *test_atomic_add_sub_thread(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;

	per_thread_mem = thread_init();
	test_atomic_add_sub_32();
	test_atomic_add_sub_64();

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *test_atomic_fetch_inc_dec_thread(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;

	per_thread_mem = thread_init();
	test_atomic_fetch_inc_dec_32();
	test_atomic_fetch_inc_dec_64();

	thread_finalize(per_thread_mem);

	return NULL;
}

static void *test_atomic_fetch_add_sub_thread(void *arg UNUSED)
{
	per_thread_mem_t *per_thread_mem;

	per_thread_mem = thread_init();
	test_atomic_fetch_add_sub_32();
	test_atomic_fetch_add_sub_64();

	thread_finalize(per_thread_mem);

	return NULL;
}

static void test_atomic_functional(void *func_ptr(void *))
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	test_atomic_init();
	test_atomic_store();
	odp_cunit_thread_create(func_ptr, &arg);
	odp_cunit_thread_exit(&arg);
	test_atomic_validate();
}

static void synchronizers_test_atomic_inc_dec(void)
{
	test_atomic_functional(test_atomic_inc_dec_thread);
}

static void synchronizers_test_atomic_add_sub(void)
{
	test_atomic_functional(test_atomic_add_sub_thread);
}

static void synchronizers_test_atomic_fetch_inc_dec(void)
{
	test_atomic_functional(test_atomic_fetch_inc_dec_thread);
}

static void synchronizers_test_atomic_fetch_add_sub(void)
{
	test_atomic_functional(test_atomic_fetch_add_sub_thread);
}

static CU_TestInfo synchronizers_suite_atomic[] = {
	{"atomic_inc_dec", synchronizers_test_atomic_inc_dec},
	{"atomic_add_sub", synchronizers_test_atomic_add_sub},
	{"atomic_fetch_inc_dec", synchronizers_test_atomic_fetch_inc_dec},
	{"atomic_fetch_add_sub", synchronizers_test_atomic_fetch_add_sub},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo synchronizers_suites[] = {
	{"barrier", NULL,
	 NULL, NULL, NULL, synchronizers_suite_barrier},
	{"nolocking", synchronizers_suite_init,
	 NULL, NULL, NULL, synchronizers_suite_no_locking},
	{"spinlock", synchronizers_suite_init,
	 NULL, NULL, NULL, synchronizers_suite_spinlock},
	{"ticketlock", synchronizers_suite_init,
	 NULL, NULL, NULL, synchronizers_suite_ticketlock},
	{"rwlock", synchronizers_suite_init,
	 NULL, NULL, NULL, synchronizers_suite_rwlock},
	{"atomic", NULL, NULL, NULL, NULL,
	 synchronizers_suite_atomic},
	CU_SUITE_INFO_NULL
};

int synchronizers_main(void)
{
	return odp_cunit_run(synchronizers_suites);
}

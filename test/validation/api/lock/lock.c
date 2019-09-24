/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <malloc.h>
#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <CUnit/Basic.h>
#include <odp_cunit_common.h>
#include <unistd.h>

#define VERBOSE			0

#define MIN_ITERATIONS		1000
#define MAX_ITERATIONS		30000
#define ITER_MPLY_FACTOR	3

#define SLOW_BARRIER_DELAY	400
#define BASE_DELAY		6
#define MIN_DELAY		1

#define NUM_RESYNC_BARRIERS	100

#define GLOBAL_SHM_NAME		"GlobalLockTest"

#define UNUSED			__attribute__((__unused__))

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

	volatile_u32_t slow_thread_num;
	volatile_u32_t barrier_cnt1;
	volatile_u32_t barrier_cnt2;
	odp_barrier_t global_barrier;

	/* Used to periodically resync within the lock functional tests */
	odp_barrier_t barrier_array[NUM_RESYNC_BARRIERS];

	/* Locks */
	odp_spinlock_t global_spinlock;
	odp_spinlock_recursive_t global_recursive_spinlock;
	odp_ticketlock_t global_ticketlock;
	odp_rwlock_t global_rwlock;
	odp_rwlock_recursive_t global_recursive_rwlock;

	volatile_u32_t global_lock_owner;
} global_shared_mem_t;

/* Per-thread memory */
typedef struct {
	global_shared_mem_t *global_mem;

	int thread_id;
	int thread_core;

	odp_spinlock_t per_thread_spinlock;
	odp_spinlock_recursive_t per_thread_recursive_spinlock;
	odp_ticketlock_t per_thread_ticketlock;
	odp_rwlock_t per_thread_rwlock;
	odp_rwlock_recursive_t per_thread_recursive_rwlock;

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

static int spinlock_api_tests(void *arg UNUSED)
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

	return CU_get_number_of_failures();
}

static void spinlock_recursive_api_test(odp_spinlock_recursive_t *spinlock)
{
	odp_spinlock_recursive_init(spinlock);
	CU_ASSERT(odp_spinlock_recursive_is_locked(spinlock) == 0);

	odp_spinlock_recursive_lock(spinlock);
	CU_ASSERT(odp_spinlock_recursive_is_locked(spinlock) == 1);

	odp_spinlock_recursive_lock(spinlock);
	CU_ASSERT(odp_spinlock_recursive_is_locked(spinlock) == 1);

	odp_spinlock_recursive_unlock(spinlock);
	CU_ASSERT(odp_spinlock_recursive_is_locked(spinlock) == 1);

	odp_spinlock_recursive_unlock(spinlock);
	CU_ASSERT(odp_spinlock_recursive_is_locked(spinlock) == 0);

	CU_ASSERT(odp_spinlock_recursive_trylock(spinlock) == 1);
	CU_ASSERT(odp_spinlock_recursive_is_locked(spinlock) == 1);

	CU_ASSERT(odp_spinlock_recursive_trylock(spinlock) == 1);
	CU_ASSERT(odp_spinlock_recursive_is_locked(spinlock) == 1);

	odp_spinlock_recursive_unlock(spinlock);
	CU_ASSERT(odp_spinlock_recursive_is_locked(spinlock) == 1);

	odp_spinlock_recursive_unlock(spinlock);
	CU_ASSERT(odp_spinlock_recursive_is_locked(spinlock) == 0);
}

static int spinlock_recursive_api_tests(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	odp_spinlock_recursive_t local_recursive_spin_lock;

	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;

	odp_barrier_wait(&global_mem->global_barrier);

	spinlock_recursive_api_test(&local_recursive_spin_lock);
	spinlock_recursive_api_test(
		&per_thread_mem->per_thread_recursive_spinlock);

	thread_finalize(per_thread_mem);

	return CU_get_number_of_failures();
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

static int ticketlock_api_tests(void *arg UNUSED)
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

	return CU_get_number_of_failures();
}

static void rwlock_api_test(odp_rwlock_t *rw_lock)
{
	int rc = 0;

	odp_rwlock_init(rw_lock);
	/* CU_ASSERT(odp_rwlock_is_locked(rw_lock) == 0); */

	odp_rwlock_read_lock(rw_lock);

	rc = odp_rwlock_read_trylock(rw_lock);
	CU_ASSERT(rc != 0);
	if (rc == 1)
		odp_rwlock_read_unlock(rw_lock);

	rc = odp_rwlock_write_trylock(rw_lock);
	CU_ASSERT(rc == 0);
	if (rc == 1)
		odp_rwlock_write_unlock(rw_lock);

	odp_rwlock_read_unlock(rw_lock);

	rc = odp_rwlock_read_trylock(rw_lock);
	CU_ASSERT(rc != 0);
	if (rc == 1)
		odp_rwlock_read_unlock(rw_lock);

	odp_rwlock_write_lock(rw_lock);
	/* CU_ASSERT(odp_rwlock_is_locked(rw_lock) == 1); */

	rc = odp_rwlock_read_trylock(rw_lock);
	CU_ASSERT(rc == 0);
	if (rc == 1)
		odp_rwlock_read_unlock(rw_lock);

	rc = odp_rwlock_write_trylock(rw_lock);
	CU_ASSERT(rc == 0);
	if (rc == 1)
		odp_rwlock_write_unlock(rw_lock);

	odp_rwlock_write_unlock(rw_lock);
	/* CU_ASSERT(odp_rwlock_is_locked(rw_lock) == 0); */

	rc = odp_rwlock_write_trylock(rw_lock);
	CU_ASSERT(rc != 0);
	if (rc == 1)
		odp_rwlock_write_unlock(rw_lock);
}

static int rwlock_api_tests(void *arg UNUSED)
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

	return CU_get_number_of_failures();
}

static void rwlock_recursive_api_test(odp_rwlock_recursive_t *rw_lock)
{
	int rc;

	odp_rwlock_recursive_init(rw_lock);
	/* CU_ASSERT(odp_rwlock_is_locked(rw_lock) == 0); */

	odp_rwlock_recursive_read_lock(rw_lock);
	odp_rwlock_recursive_read_lock(rw_lock);
	rc = odp_rwlock_recursive_read_trylock(rw_lock);
	CU_ASSERT(rc == 1);
	rc = odp_rwlock_recursive_write_trylock(rw_lock);
	CU_ASSERT(rc == 0);

	odp_rwlock_recursive_read_unlock(rw_lock);
	odp_rwlock_recursive_read_unlock(rw_lock);
	odp_rwlock_recursive_read_unlock(rw_lock);

	odp_rwlock_recursive_write_lock(rw_lock);
	odp_rwlock_recursive_write_lock(rw_lock);
	/* CU_ASSERT(odp_rwlock_is_locked(rw_lock) == 1); */
	rc = odp_rwlock_recursive_read_trylock(rw_lock);
	CU_ASSERT(rc == 0);
	rc = odp_rwlock_recursive_write_trylock(rw_lock);
	CU_ASSERT(rc == 1);

	odp_rwlock_recursive_write_unlock(rw_lock);
	odp_rwlock_recursive_write_unlock(rw_lock);
	odp_rwlock_recursive_write_unlock(rw_lock);
	/* CU_ASSERT(odp_rwlock_is_locked(rw_lock) == 0); */
}

static int rwlock_recursive_api_tests(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	odp_rwlock_recursive_t local_recursive_rwlock;

	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;

	odp_barrier_wait(&global_mem->global_barrier);

	rwlock_recursive_api_test(&local_recursive_rwlock);
	rwlock_recursive_api_test(&per_thread_mem->per_thread_recursive_rwlock);

	thread_finalize(per_thread_mem);

	return CU_get_number_of_failures();
}

/*
 * Tests that we do have contention between threads when running.
 * Also adjust the number of iterations to be done (by other tests)
 * so we have a fair chance to see that the tested synchronizer
 * does avoid the race condition.
 */
static int no_lock_functional_test(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	uint32_t thread_num, resync_cnt, rs_idx, iterations, cnt;
	uint32_t sync_failures, current_errs, lock_owner_delay;

	thread_num = odp_cpu_id() + 1;
	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;
	iterations = 0;

	odp_barrier_wait(&global_mem->global_barrier);

	sync_failures = 0;
	current_errs = 0;
	rs_idx = 0;
	resync_cnt = MAX_ITERATIONS / NUM_RESYNC_BARRIERS;
	lock_owner_delay = BASE_DELAY;

	/*
	* Tunning the iteration number:
	* Here, we search for an iteration number that guarantees to show
	* race conditions between the odp threads.
	* Iterations is set to ITER_MPLY_FACTOR * cnt where cnt is when
	* the threads start to see "errors" (i.e. effect of other threads
	* running concurrentely without any synchronisation mechanism).
	* In other words, "iterations" is set to ITER_MPLY_FACTOR times the
	* minimum loop count necessary to see a need for synchronisation
	* mechanism.
	* If, later, these "errors" disappear when running other tests up to
	* "iterations" with synchro, the effect of the tested synchro mechanism
	* is likely proven.
	* If we reach "MAX_ITERATIONS", and "iteration" remains zero,
	* it means that we cannot see any race condition between the different
	* running theads (e.g. the OS is not preemptive) and all other tests
	* being passed won't tell much about the functionality of the
	* tested synchro mechanism.
	*/
	for (cnt = 1; cnt <=  MAX_ITERATIONS; cnt++) {
		global_mem->global_lock_owner = thread_num;
		odp_mb_full();
		thread_delay(per_thread_mem, lock_owner_delay);

		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			sync_failures++;
			if (!iterations)
				iterations = cnt;
		}

		global_mem->global_lock_owner = 0;
		odp_mb_full();
		thread_delay(per_thread_mem, MIN_DELAY);

		if (global_mem->global_lock_owner == thread_num) {
			current_errs++;
			sync_failures++;
			if (!iterations)
				iterations = cnt;
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
	* So this test PASSES only if it sees sync_failures or a single
	* worker was used.
	*/
	CU_ASSERT(sync_failures != 0 || global_mem->g_num_threads == 1);

	/*
	* set the iterration for the future tests to be far above the
	* contention level
	*/
	iterations *= ITER_MPLY_FACTOR;

	if (iterations > MAX_ITERATIONS)
		iterations = MAX_ITERATIONS;
	if (iterations < MIN_ITERATIONS)
		iterations = MIN_ITERATIONS;

	/*
	* Note that the following statement has race conditions:
	* global_mem->g_iterations should really be an atomic and a TAS
	* function be used. But this would mean that we would be testing
	* synchronisers assuming synchronisers works...
	* If we do not use atomic TAS, we may not get the grand max for
	* all threads, but we are guaranteed to have passed the error
	* threshold, for at least some threads, which is good enough
	*/
	if (iterations > global_mem->g_iterations)
		global_mem->g_iterations = iterations;

	odp_mb_full();

	thread_finalize(per_thread_mem);

	return CU_get_number_of_failures();
}

static int spinlock_functional_test(void *arg UNUSED)
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
		odp_mb_full();
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			sync_failures++;
		}

		/* Release shared lock, and make sure we no longer have it */
		global_mem->global_lock_owner = 0;
		odp_mb_full();
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

	return CU_get_number_of_failures();
}

static int spinlock_recursive_functional_test(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	uint32_t thread_num, resync_cnt, rs_idx, iterations, cnt;
	uint32_t sync_failures, recursive_errs, is_locked_errs, current_errs;
	uint32_t lock_owner_delay;

	thread_num = odp_cpu_id() + 1;
	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;
	iterations = global_mem->g_iterations;

	odp_barrier_wait(&global_mem->global_barrier);

	sync_failures = 0;
	recursive_errs = 0;
	is_locked_errs = 0;
	current_errs = 0;
	rs_idx = 0;
	resync_cnt = iterations / NUM_RESYNC_BARRIERS;
	lock_owner_delay = BASE_DELAY;

	for (cnt = 1; cnt <= iterations; cnt++) {
		/* Acquire the shared global lock */
		odp_spinlock_recursive_lock(
			&global_mem->global_recursive_spinlock);

		/* Make sure we have the lock AND didn't previously own it */
		if (odp_spinlock_recursive_is_locked(
			    &global_mem->global_recursive_spinlock) != 1)
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
		odp_mb_full();
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			sync_failures++;
		}

		/* Verify that we can acquire the lock recursively */
		odp_spinlock_recursive_lock(
			&global_mem->global_recursive_spinlock);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			recursive_errs++;
		}

		/* Release the lock and verify that we still have it*/
		odp_spinlock_recursive_unlock(
			&global_mem->global_recursive_spinlock);
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			recursive_errs++;
		}

		/* Release shared lock, and make sure we no longer have it */
		global_mem->global_lock_owner = 0;
		odp_mb_full();
		odp_spinlock_recursive_unlock(
			&global_mem->global_recursive_spinlock);
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
	    (sync_failures != 0 || recursive_errs != 0 || is_locked_errs != 0))
		printf("\nThread %" PRIu32 " (id=%d core=%d) had %" PRIu32
		       " sync_failures and %" PRIu32
		       " recursive_errs and %" PRIu32
		       " is_locked_errs in %" PRIu32
		       " iterations\n", thread_num,
		       per_thread_mem->thread_id, per_thread_mem->thread_core,
		       sync_failures, recursive_errs, is_locked_errs,
		       iterations);

	CU_ASSERT(sync_failures == 0);
	CU_ASSERT(recursive_errs == 0);
	CU_ASSERT(is_locked_errs == 0);

	thread_finalize(per_thread_mem);

	return CU_get_number_of_failures();
}

static int ticketlock_functional_test(void *arg UNUSED)
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
		odp_mb_full();
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			sync_failures++;
		}

		/* Release shared lock, and make sure we no longer have it */
		global_mem->global_lock_owner = 0;
		odp_mb_full();
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

	return CU_get_number_of_failures();
}

static int rwlock_functional_test(void *arg UNUSED)
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
		/* Verify that we can obtain a read lock */
		odp_rwlock_read_lock(&global_mem->global_rwlock);

		/* Verify lock is unowned (no writer holds it) */
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != 0) {
			current_errs++;
			sync_failures++;
		}

		/* Release the read lock */
		odp_rwlock_read_unlock(&global_mem->global_rwlock);

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
		odp_mb_full();
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			sync_failures++;
		}

		/* Release shared lock, and make sure we no longer have it */
		global_mem->global_lock_owner = 0;
		odp_mb_full();
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

	return CU_get_number_of_failures();
}

static int rwlock_recursive_functional_test(void *arg UNUSED)
{
	global_shared_mem_t *global_mem;
	per_thread_mem_t *per_thread_mem;
	uint32_t thread_num, resync_cnt, rs_idx, iterations, cnt;
	uint32_t sync_failures, recursive_errs, current_errs, lock_owner_delay;

	thread_num = odp_cpu_id() + 1;
	per_thread_mem = thread_init();
	global_mem = per_thread_mem->global_mem;
	iterations = global_mem->g_iterations;

	/* Wait here until all of the threads have also reached this point */
	odp_barrier_wait(&global_mem->global_barrier);

	sync_failures = 0;
	recursive_errs = 0;
	current_errs = 0;
	rs_idx = 0;
	resync_cnt = iterations / NUM_RESYNC_BARRIERS;
	lock_owner_delay = BASE_DELAY;

	for (cnt = 1; cnt <= iterations; cnt++) {
		/* Verify that we can obtain a read lock */
		odp_rwlock_recursive_read_lock(
			&global_mem->global_recursive_rwlock);

		/* Verify lock is unowned (no writer holds it) */
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != 0) {
			current_errs++;
			sync_failures++;
		}

		/* Verify we can get read lock recursively */
		odp_rwlock_recursive_read_lock(
			&global_mem->global_recursive_rwlock);

		/* Verify lock is unowned (no writer holds it) */
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != 0) {
			current_errs++;
			sync_failures++;
		}

		/* Release the read lock */
		odp_rwlock_recursive_read_unlock(
			&global_mem->global_recursive_rwlock);
		odp_rwlock_recursive_read_unlock(
			&global_mem->global_recursive_rwlock);

		/* Acquire the shared global lock */
		odp_rwlock_recursive_write_lock(
			&global_mem->global_recursive_rwlock);

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
		odp_mb_full();
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			sync_failures++;
		}

		/* Acquire it again and verify we still own it */
		odp_rwlock_recursive_write_lock(
			&global_mem->global_recursive_rwlock);
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			recursive_errs++;
		}

		/* Release the recursive lock and make sure we still own it */
		odp_rwlock_recursive_write_unlock(
			&global_mem->global_recursive_rwlock);
		thread_delay(per_thread_mem, lock_owner_delay);
		if (global_mem->global_lock_owner != thread_num) {
			current_errs++;
			recursive_errs++;
		}

		/* Release shared lock, and make sure we no longer have it */
		global_mem->global_lock_owner = 0;
		odp_mb_full();
		odp_rwlock_recursive_write_unlock(
			&global_mem->global_recursive_rwlock);
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
		       " sync_failures and %" PRIu32
		       " recursive_errs in %" PRIu32
		       " iterations\n", thread_num,
		       per_thread_mem->thread_id,
		       per_thread_mem->thread_core,
		       sync_failures, recursive_errs, iterations);

	CU_ASSERT(sync_failures == 0);
	CU_ASSERT(recursive_errs == 0);

	thread_finalize(per_thread_mem);

	return CU_get_number_of_failures();
}

/* Thread-unsafe tests */
static void lock_test_no_lock_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_cunit_thread_create(no_lock_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

odp_testinfo_t lock_suite_no_locking[] = {
	ODP_TEST_INFO(lock_test_no_lock_functional), /* must be first */
	ODP_TEST_INFO_NULL
};

/* Spin lock tests */
static void lock_test_spinlock_api(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_cunit_thread_create(spinlock_api_tests, &arg);
	odp_cunit_thread_exit(&arg);
}

static void lock_test_spinlock_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_spinlock_init(&global_mem->global_spinlock);
	odp_cunit_thread_create(spinlock_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

static void lock_test_spinlock_recursive_api(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_cunit_thread_create(spinlock_recursive_api_tests, &arg);
	odp_cunit_thread_exit(&arg);
}

static void lock_test_spinlock_recursive_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_spinlock_recursive_init(&global_mem->global_recursive_spinlock);
	odp_cunit_thread_create(spinlock_recursive_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

odp_testinfo_t lock_suite_spinlock[] = {
	ODP_TEST_INFO(lock_test_spinlock_api),
	ODP_TEST_INFO(lock_test_spinlock_functional),
	ODP_TEST_INFO_NULL
};

odp_testinfo_t lock_suite_spinlock_recursive[] = {
	ODP_TEST_INFO(lock_test_spinlock_recursive_api),
	ODP_TEST_INFO(lock_test_spinlock_recursive_functional),
	ODP_TEST_INFO_NULL
};

/* Ticket lock tests */
static void lock_test_ticketlock_api(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_cunit_thread_create(ticketlock_api_tests, &arg);
	odp_cunit_thread_exit(&arg);
}

static void lock_test_ticketlock_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_ticketlock_init(&global_mem->global_ticketlock);

	odp_cunit_thread_create(ticketlock_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

odp_testinfo_t lock_suite_ticketlock[] = {
	ODP_TEST_INFO(lock_test_ticketlock_api),
	ODP_TEST_INFO(lock_test_ticketlock_functional),
	ODP_TEST_INFO_NULL
};

/* RW lock tests */
static void lock_test_rwlock_api(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_cunit_thread_create(rwlock_api_tests, &arg);
	odp_cunit_thread_exit(&arg);
}

static void lock_test_rwlock_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_rwlock_init(&global_mem->global_rwlock);
	odp_cunit_thread_create(rwlock_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

odp_testinfo_t lock_suite_rwlock[] = {
	ODP_TEST_INFO(lock_test_rwlock_api),
	ODP_TEST_INFO(lock_test_rwlock_functional),
	ODP_TEST_INFO_NULL
};

static void lock_test_rwlock_recursive_api(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_cunit_thread_create(rwlock_recursive_api_tests, &arg);
	odp_cunit_thread_exit(&arg);
}

static void lock_test_rwlock_recursive_functional(void)
{
	pthrd_arg arg;

	arg.numthrds = global_mem->g_num_threads;
	odp_rwlock_recursive_init(&global_mem->global_recursive_rwlock);
	odp_cunit_thread_create(rwlock_recursive_functional_test, &arg);
	odp_cunit_thread_exit(&arg);
}

odp_testinfo_t lock_suite_rwlock_recursive[] = {
	ODP_TEST_INFO(lock_test_rwlock_recursive_api),
	ODP_TEST_INFO(lock_test_rwlock_recursive_functional),
	ODP_TEST_INFO_NULL
};

static int lock_suite_init(void)
{
	uint32_t num_threads, idx;

	num_threads = global_mem->g_num_threads;
	odp_barrier_init(&global_mem->global_barrier, num_threads);
	for (idx = 0; idx < NUM_RESYNC_BARRIERS; idx++)
		odp_barrier_init(&global_mem->barrier_array[idx], num_threads);

	return 0;
}

static int lock_init(odp_instance_t *inst)
{
	uint32_t workers_count, max_threads;
	int ret = 0;
	odp_cpumask_t mask;
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
	global_mem->g_iterations = 0; /* tuned by first test */
	global_mem->g_verbose = VERBOSE;

	workers_count = odp_cpumask_default_worker(&mask, 0);

	max_threads = (workers_count >= MAX_WORKERS) ?
			MAX_WORKERS : workers_count;

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

static int lock_term(odp_instance_t inst)
{
	odp_shm_t shm;

	shm = odp_shm_lookup(GLOBAL_SHM_NAME);
	if (0 != odp_shm_free(shm)) {
		fprintf(stderr, "error: odp_shm_free() failed.\n");
		return -1;
	}

	if (0 != odp_term_local()) {
		fprintf(stderr, "error: odp_term_local() failed.\n");
		return -1;
	}

	if (0 != odp_term_global(inst)) {
		fprintf(stderr, "error: odp_term_global() failed.\n");
		return -1;
	}

	return 0;
}

odp_suiteinfo_t lock_suites[] = {
	{"nolocking", lock_suite_init, NULL,
		lock_suite_no_locking}, /* must be first */
	{"spinlock", lock_suite_init, NULL,
		lock_suite_spinlock},
	{"spinlock_recursive", lock_suite_init, NULL,
		lock_suite_spinlock_recursive},
	{"ticketlock", lock_suite_init, NULL,
		lock_suite_ticketlock},
	{"rwlock", lock_suite_init, NULL,
		lock_suite_rwlock},
	{"rwlock_recursive", lock_suite_init, NULL,
		lock_suite_rwlock_recursive},
	ODP_SUITE_INFO_NULL
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	odp_cunit_register_global_init(lock_init);
	odp_cunit_register_global_term(lock_term);

	ret = odp_cunit_register(lock_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

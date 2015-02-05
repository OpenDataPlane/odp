/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>

#include <odp/thread.h>
#include <odp_internal.h>
#include <odp/atomic.h>
#include <odp/config.h>
#include <odp_debug_internal.h>
#include <odp/shared_memory.h>
#include <odp/align.h>
#include <odp/cpu.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>


typedef struct {
	int thr_id;
	int cpu;

} thread_state_t;


typedef struct {
	thread_state_t   thr[ODP_CONFIG_MAX_THREADS];
	odp_atomic_u32_t num;
	odp_atomic_u32_t next_id;

} thread_globals_t;


/* Globals */
static thread_globals_t *thread_globals;


/* Thread local */
static __thread thread_state_t *this_thread;


int odp_thread_init_global(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("odp_thread_globals",
			      sizeof(thread_globals_t),
			      ODP_CACHE_LINE_SIZE, 0);

	thread_globals = odp_shm_addr(shm);

	if (thread_globals == NULL)
		return -1;

	memset(thread_globals, 0, sizeof(thread_globals_t));
	odp_atomic_init_u32(&thread_globals->next_id, 0);
	odp_atomic_init_u32(&thread_globals->num, 0);
	return 0;
}


static int thread_id(void)
{
	uint32_t id;
	int cpu;

	id = odp_atomic_fetch_inc_u32(&thread_globals->next_id);

	if (id >= ODP_CONFIG_MAX_THREADS) {
		ODP_ERR("Too many threads\n");
		return -1;
	}
	odp_atomic_inc_u32(&thread_globals->num);

	cpu = sched_getcpu();

	if (cpu < 0) {
		ODP_ERR("getcpu failed\n");
		return -1;
	}

	thread_globals->thr[id].thr_id = id;
	thread_globals->thr[id].cpu    = cpu;

	return id;
}

int odp_thread_init_local(void)
{
	int id;

	id = thread_id();

	if (id < 0)
		return -1;

	this_thread = &thread_globals->thr[id];
	return 0;
}

int odp_thread_term_local(void)
{
	uint32_t num;
	num = odp_atomic_fetch_dec_u32(&thread_globals->num);
	ODP_ASSERT(num > 0, "Number of threads should be > 0");
	return num - 1; /* return a number of threads left */
}

int odp_thread_id(void)
{
	return this_thread->thr_id;
}


int odp_cpu_id(void)
{
	return this_thread->cpu;
}

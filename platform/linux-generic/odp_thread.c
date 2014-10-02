/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>

#include <odp_thread.h>
#include <odp_internal.h>
#include <odp_atomic.h>
#include <odp_config.h>
#include <odp_debug.h>
#include <odp_shared_memory.h>
#include <odp_align.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>


typedef struct {
	int thr_id;
	int cpu;

} thread_state_t;


typedef struct {
	thread_state_t   thr[ODP_CONFIG_MAX_THREADS];
	odp_atomic_int_t num;

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
	return 0;
}


static int thread_id(void)
{
	int id;
	int cpu;

	id = odp_atomic_fetch_add_int(&thread_globals->num, 1);

	if (id >= ODP_CONFIG_MAX_THREADS) {
		ODP_ERR("Too many threads\n");
		return -1;
	}

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


int odp_thread_id(void)
{
	return this_thread->thr_id;
}


int odp_thread_core(void)
{
	return this_thread->cpu;
}

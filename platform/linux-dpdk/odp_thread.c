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
#include <odp/spinlock.h>
#include <odp/config.h>
#include <odp_debug_internal.h>
#include <odp/shared_memory.h>
#include <odp/align.h>
#include <odp/cpu.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MASK_SIZE_16 ((ODP_CONFIG_MAX_THREADS+15)/16)

typedef struct {
	int thr;
	int cpu;
} thread_state_t;


typedef struct {
	thread_state_t thr[ODP_CONFIG_MAX_THREADS];
	uint16_t       mask[MASK_SIZE_16];
	uint32_t       num;
	odp_spinlock_t lock;
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
	odp_spinlock_init(&thread_globals->lock);
	return 0;
}

int odp_thread_term_global(void)
{
	int ret;

	ret = odp_shm_free(odp_shm_lookup("odp_thread_globals"));
	if (ret < 0)
		ODP_ERR("shm free failed for odp_thread_globals");

	return ret;
}

static int alloc_id(void)
{
	int i, j;
	uint16_t *mask = thread_globals->mask;

	if (thread_globals->num >= ODP_CONFIG_MAX_THREADS)
		return -1;

	for (i = 0; i < MASK_SIZE_16; i++) {
		if (mask[i] != 0xffff) {
			for (j = 0; j < 16; j++) {
				uint16_t bit = 0x1 << j;
				if ((bit & mask[i]) == 0) {
					mask[i] |= bit;
					thread_globals->num++;
					return i*16 + j;
				}
			}
			return -2;
		}
	}

	return -2;
}

static int free_id(int id)
{
	int i, j;
	uint16_t *mask = thread_globals->mask;
	uint16_t bit;

	if (id < 0 || id >= ODP_CONFIG_MAX_THREADS)
		return -1;

	i   = id / 16;
	j   = id - (i * 16);
	bit = 0x1 << j;

	if ((bit & mask[i]) == 0)
		return -1;

	mask[i] &= ~bit;
	thread_globals->num--;
	return thread_globals->num;
}

int odp_thread_init_local(void)
{
	int id;
	int cpu;

	odp_spinlock_lock(&thread_globals->lock);
	id = alloc_id();
	odp_spinlock_unlock(&thread_globals->lock);

	if (id < 0) {
		ODP_ERR("Too many threads\n");
		return -1;
	}

	cpu = sched_getcpu();

	if (cpu < 0) {
		ODP_ERR("getcpu failed\n");
		return -1;
	}

	thread_globals->thr[id].thr = id;
	thread_globals->thr[id].cpu = cpu;

	this_thread = &thread_globals->thr[id];
	return 0;
}

int odp_thread_term_local(void)
{
	int num;
	int id = this_thread->thr;

	odp_spinlock_lock(&thread_globals->lock);
	num = free_id(id);
	odp_spinlock_unlock(&thread_globals->lock);

	if (num < 0) {
		ODP_ERR("failed to free thread id %i", id);
		return -1;
	}

	return num; /* return a number of threads left */
}

int odp_thread_id(void)
{
	return this_thread->thr;
}

int odp_thread_count(void)
{
	return thread_globals->num;
}

int odp_cpu_id(void)
{
	return this_thread->cpu;
}

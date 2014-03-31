/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_thread.h>
#include <odp_internal.h>
#include <odp_atomic.h>
#include <odp_config.h>

#include <string.h>
#include <stdio.h>


typedef struct {
	int thr_id;
	int phys_core;

} odp_thread_tbl_t;


/* Globals */
static odp_thread_tbl_t odp_thread_tbl[ODP_CONFIG_MAX_THREADS];
static odp_atomic_int_t num_threads;

/* Thread local */
static __thread odp_thread_tbl_t *odp_this_thread;


void odp_thread_init_global(void)
{
	memset(odp_thread_tbl, 0, sizeof(odp_thread_tbl));
	num_threads = 0;
}


void odp_thread_init_local(int thr_id)
{
	odp_this_thread = &odp_thread_tbl[thr_id];
}


int odp_thread_create(int phys_core)
{
	int id;

	id = odp_atomic_fetch_add_int(&num_threads, 1);

	if (id < ODP_CONFIG_MAX_THREADS) {
		odp_thread_tbl[id].thr_id    = id;
		odp_thread_tbl[id].phys_core = phys_core;
	}

	return id;
}


int odp_thread_id(void)
{
	return odp_this_thread->thr_id;
}


int odp_thread_core(void)
{
	return odp_this_thread->phys_core;
}

/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include <odp/api/schedule.h>
#include <odp_schedule_if.h>
#include <odp_debug_internal.h>

static int init_global(void)
{
	ODP_DBG("Schedule SP init ...\n");

	ODP_ABORT("Not implemented.");

	return 0;
}

static int init_local(void)
{
	return 0;
}

static int term_global(void)
{
	return 0;
}

static int term_local(void)
{
	return 0;
}

/* Fill in scheduler interface */
const schedule_fn_t schedule_sp_fn = {
	.pktio_start   = NULL,
	.thr_add       = NULL,
	.thr_rem       = NULL,
	.num_grps      = NULL,
	.init_queue    = NULL,
	.destroy_queue = NULL,
	.sched_queue   = NULL,
	.init_global   = init_global,
	.term_global   = term_global,
	.init_local    = init_local,
	.term_local    = term_local
};

/* Fill in scheduler API calls */
const schedule_api_t schedule_sp_api = {
	.schedule_wait_time       = NULL,
	.schedule                 = NULL,
	.schedule_multi           = NULL,
	.schedule_pause           = NULL,
	.schedule_resume          = NULL,
	.schedule_release_atomic  = NULL,
	.schedule_release_ordered = NULL,
	.schedule_prefetch        = NULL,
	.schedule_num_prio        = NULL,
	.schedule_group_create    = NULL,
	.schedule_group_destroy   = NULL,
	.schedule_group_lookup    = NULL,
	.schedule_group_join      = NULL,
	.schedule_group_leave     = NULL,
	.schedule_group_thrmask   = NULL,
	.schedule_group_info      = NULL,
	.schedule_order_lock      = NULL,
	.schedule_order_unlock    = NULL
};

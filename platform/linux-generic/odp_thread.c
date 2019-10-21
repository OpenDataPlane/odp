/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <sched.h>
#include <odp/api/thread.h>
#include <odp/api/thrmask.h>
#include <odp/api/spinlock.h>
#include <odp_init_internal.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/align.h>
#include <odp/api/cpu.h>
#include <odp_schedule_if.h>
#include <odp/api/plat/thread_inlines.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
	_odp_thread_state_t thr[ODP_THREAD_COUNT_MAX];

	struct {
		odp_thrmask_t  all;
		odp_thrmask_t  worker;
		odp_thrmask_t  control;
	};

	uint32_t       num;
	uint32_t       num_worker;
	uint32_t       num_control;
	odp_spinlock_t lock;
} thread_globals_t;

/* Globals */
static thread_globals_t *thread_globals;

#include <odp/visibility_begin.h>

/* Thread local */
__thread _odp_thread_state_t *_odp_this_thread;

#include <odp/visibility_end.h>

int _odp_thread_init_global(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("_odp_thread_globals",
			      sizeof(thread_globals_t),
			      ODP_CACHE_LINE_SIZE, 0);

	thread_globals = odp_shm_addr(shm);

	if (thread_globals == NULL)
		return -1;

	memset(thread_globals, 0, sizeof(thread_globals_t));
	odp_spinlock_init(&thread_globals->lock);

	return 0;
}

int _odp_thread_term_global(void)
{
	int ret;

	ret = odp_shm_free(odp_shm_lookup("_odp_thread_globals"));
	if (ret < 0)
		ODP_ERR("shm free failed for _odp_thread_globals");

	return ret;
}

static int alloc_id(odp_thread_type_t type)
{
	int thr;
	odp_thrmask_t *all = &thread_globals->all;

	if (thread_globals->num >= ODP_THREAD_COUNT_MAX)
		return -1;

	for (thr = 0; thr < ODP_THREAD_COUNT_MAX; thr++) {
		if (odp_thrmask_isset(all, thr) == 0) {
			odp_thrmask_set(all, thr);

			if (type == ODP_THREAD_WORKER) {
				odp_thrmask_set(&thread_globals->worker, thr);
				thread_globals->num_worker++;
			} else {
				odp_thrmask_set(&thread_globals->control, thr);
				thread_globals->num_control++;
			}

			thread_globals->num++;
			return thr;
		}
	}

	return -2;
}

static int free_id(int thr)
{
	odp_thrmask_t *all = &thread_globals->all;

	if (thr < 0 || thr >= ODP_THREAD_COUNT_MAX)
		return -1;

	if (odp_thrmask_isset(all, thr) == 0)
		return -1;

	odp_thrmask_clr(all, thr);

	if (thread_globals->thr[thr].type == ODP_THREAD_WORKER) {
		odp_thrmask_clr(&thread_globals->worker, thr);
		thread_globals->num_worker--;
	} else {
		odp_thrmask_clr(&thread_globals->control, thr);
		thread_globals->num_control--;
	}

	thread_globals->num--;
	return thread_globals->num;
}

int _odp_thread_init_local(odp_thread_type_t type)
{
	int id;
	int cpu;
	int group_all, group_worker, group_control;

	group_all = 1;
	group_worker = 1;
	group_control = 1;

	if (sched_fn->get_config) {
		schedule_config_t schedule_config;

		sched_fn->get_config(&schedule_config);
		group_all = schedule_config.group_enable.all;
		group_worker = schedule_config.group_enable.worker;
		group_control = schedule_config.group_enable.control;
	}

	odp_spinlock_lock(&thread_globals->lock);
	id = alloc_id(type);
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

	thread_globals->thr[id].thr  = id;
	thread_globals->thr[id].cpu  = cpu;
	thread_globals->thr[id].type = type;

	_odp_this_thread = &thread_globals->thr[id];

	if (group_all)
		sched_fn->thr_add(ODP_SCHED_GROUP_ALL, id);

	if (type == ODP_THREAD_WORKER && group_worker)
		sched_fn->thr_add(ODP_SCHED_GROUP_WORKER, id);

	if (type == ODP_THREAD_CONTROL && group_control)
		sched_fn->thr_add(ODP_SCHED_GROUP_CONTROL, id);

	return 0;
}

int _odp_thread_term_local(void)
{
	int num;
	int group_all, group_worker, group_control;
	int id = _odp_this_thread->thr;
	odp_thread_type_t type = _odp_this_thread->type;

	group_all = 1;
	group_worker = 1;
	group_control = 1;

	if (sched_fn->get_config) {
		schedule_config_t schedule_config;

		sched_fn->get_config(&schedule_config);
		group_all = schedule_config.group_enable.all;
		group_worker = schedule_config.group_enable.worker;
		group_control = schedule_config.group_enable.control;
	}

	if (group_all)
		sched_fn->thr_rem(ODP_SCHED_GROUP_ALL, id);

	if (type == ODP_THREAD_WORKER && group_worker)
		sched_fn->thr_rem(ODP_SCHED_GROUP_WORKER, id);

	if (type == ODP_THREAD_CONTROL && group_control)
		sched_fn->thr_rem(ODP_SCHED_GROUP_CONTROL, id);

	odp_spinlock_lock(&thread_globals->lock);
	num = free_id(id);
	odp_spinlock_unlock(&thread_globals->lock);

	if (num < 0) {
		ODP_ERR("failed to free thread id %i", id);
		return -1;
	}

	return num; /* return a number of threads left */
}

int odp_thread_count(void)
{
	return thread_globals->num;
}

int odp_thread_count_max(void)
{
	return ODP_THREAD_COUNT_MAX;
}

int odp_thrmask_worker(odp_thrmask_t *mask)
{
	odp_thrmask_copy(mask, &thread_globals->worker);
	return thread_globals->num_worker;
}

int odp_thrmask_control(odp_thrmask_t *mask)
{
	odp_thrmask_copy(mask, &thread_globals->control);
	return thread_globals->num_control;
}

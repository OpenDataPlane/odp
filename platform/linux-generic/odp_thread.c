/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2021-2026 Nokia
 */

#include <odp_posix_extensions.h>

#include <odp/api/align.h>
#include <odp/api/atomic.h>
#include <odp/api/cpu.h>
#include <odp/api/hints.h>
#include <odp/api/shared_memory.h>
#include <odp/api/spinlock.h>
#include <odp/api/thread.h>
#include <odp/api/thrmask.h>

#include <odp/api/plat/thread_inlines.h>

#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_schedule_if.h>

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	_odp_thread_state_t thr[ODP_THREAD_COUNT_MAX];

	struct {
		odp_thrmask_t  all;
		odp_thrmask_t  worker;
		odp_thrmask_t  control;
	};

	odp_atomic_u32_t num;
	odp_atomic_u32_t num_worker;
	odp_atomic_u32_t num_control;
	odp_atomic_u32_t num_internal;
	uint32_t       num_max;
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
	int num_max = 0;
	const char *str = "system.thread_count_max";

	if (!_odp_libconfig_lookup_int(str, &num_max)) {
		_ODP_ERR("Config option '%s' not found.\n", str);
		return -1;
	}
	if (num_max <= 0) {
		_ODP_ERR("Config option '%s' not valid.\n", str);
		return -1;
	}
	if (num_max > ODP_THREAD_COUNT_MAX)
		num_max = ODP_THREAD_COUNT_MAX;

	shm = odp_shm_reserve("_odp_thread_global",
			      sizeof(thread_globals_t),
			      ODP_CACHE_LINE_SIZE, 0);

	thread_globals = odp_shm_addr(shm);

	if (thread_globals == NULL)
		return -1;

	memset(thread_globals, 0, sizeof(thread_globals_t));
	odp_atomic_init_u32(&thread_globals->num, 0);
	odp_atomic_init_u32(&thread_globals->num_worker, 0);
	odp_atomic_init_u32(&thread_globals->num_control, 0);
	odp_atomic_init_u32(&thread_globals->num_internal, 0);
	odp_spinlock_init(&thread_globals->lock);
	thread_globals->num_max = num_max;
	_ODP_PRINT("System config:\n");
	_ODP_PRINT("  system.thread_count_max: %d\n\n", num_max);

	return 0;
}

int _odp_thread_term_global(void)
{
	int ret, num;

	num = odp_atomic_load_u32(&thread_globals->num);
	if (num)
		_ODP_ERR("%u threads have not called odp_term_local().\n", num);

	ret = odp_shm_free(odp_shm_lookup("_odp_thread_global"));
	if (ret < 0)
		_ODP_ERR("shm free failed for _odp_thread_globals");

	return ret;
}

static int thread_count_max_visible(void)
{
	int num_max = (int)thread_globals->num_max;
	int num_svc = odp_global_ro.num_service_cpus;

	if (num_svc >= num_max)
		return 0;

	return num_max - num_svc;
}

static int alloc_id(_odp_internal_thread_type_t type)
{
	int thr;
	int begin, end, step;
	odp_thrmask_t *all = &thread_globals->all;
	uint32_t num = odp_atomic_load_u32(&thread_globals->num);
	uint32_t num_internal = odp_atomic_load_u32(&thread_globals->num_internal);

	if (num >= thread_globals->num_max)
		return -1;

	/* Allocate _ODP_THR_INTERNAL ids from the top of the range. Each reserved
	 * service CPU runs at most one internal thread, so application threads
	 * keep the id space [0, odp_thread_count_max()). */
	if (type == _ODP_THR_INTERNAL) {
		_ODP_ASSERT(num_internal < (uint32_t)odp_global_ro.num_service_cpus);
		begin = (int)thread_globals->num_max - 1;
		end = -1;
		step = -1;
	} else {
		if (num - num_internal >= (uint32_t)thread_count_max_visible())
			return -1;

		begin = 0;
		end = (int)thread_globals->num_max;
		step = 1;
	}

	for (thr = begin; thr != end; thr += step) {
		if (odp_thrmask_isset(all, thr) == 0) {
			odp_thrmask_set(all, thr);

			if (type == _ODP_THR_WORKER) {
				odp_thrmask_set(&thread_globals->worker, thr);
				odp_atomic_inc_u32(&thread_globals->num_worker);
			} else if (type == _ODP_THR_CONTROL) {
				odp_thrmask_set(&thread_globals->control, thr);
				odp_atomic_inc_u32(&thread_globals->num_control);
			} else {
				odp_atomic_inc_u32(&thread_globals->num_internal);
			}

			odp_atomic_inc_u32(&thread_globals->num);
			return thr;
		}
	}

	return -2;
}

static int free_id(int thr)
{
	odp_thrmask_t *all = &thread_globals->all;
	uint32_t num_internal;

	if (thr < 0 || thr >= (int)thread_globals->num_max)
		return -1;

	if (odp_thrmask_isset(all, thr) == 0)
		return -1;

	odp_thrmask_clr(all, thr);

	if (thread_globals->thr[thr].type == _ODP_THR_WORKER) {
		odp_thrmask_clr(&thread_globals->worker, thr);
		odp_atomic_dec_u32(&thread_globals->num_worker);
	} else if (thread_globals->thr[thr].type == _ODP_THR_CONTROL) {
		odp_thrmask_clr(&thread_globals->control, thr);
		odp_atomic_dec_u32(&thread_globals->num_control);
	} else {
		odp_atomic_dec_u32(&thread_globals->num_internal);
	}

	num_internal = odp_atomic_load_u32(&thread_globals->num_internal);

	/* Return remaining application thread count (excluding internal
	 * threads) so the last application thread sees zero even if internal
	 * threads are still running. */
	return odp_atomic_fetch_dec_u32(&thread_globals->num) - 1 - num_internal;
}

int odp_cpu_id(void)
{
	int cpu = sched_getcpu();

	if (odp_unlikely(cpu < 0)) {
		_ODP_ERR("sched_getcpu() failed: %s\n", strerror(errno));
		return -1;
	}
	return cpu;
}

int _odp_thread_init_local(_odp_internal_thread_type_t type)
{
	int id;
	int group_all, group_worker, group_control;

	group_all = 1;
	group_worker = 1;
	group_control = 1;

	if (_odp_sched_fn->get_config) {
		schedule_config_t schedule_config;

		_odp_sched_fn->get_config(&schedule_config);
		group_all = schedule_config.group_enable.all;
		group_worker = schedule_config.group_enable.worker;
		group_control = schedule_config.group_enable.control;
	}

	odp_spinlock_lock(&thread_globals->lock);
	id = alloc_id(type);
	if (id >= 0) {
		thread_globals->thr[id].thr  = id;
		thread_globals->thr[id].type = type;
	}
	odp_spinlock_unlock(&thread_globals->lock);

	if (id < 0) {
		_ODP_ERR("Too many threads\n");
		return -1;
	}

	_odp_this_thread = &thread_globals->thr[id];

	/* Internal threads are not part of any application scheduler group. */
	if (type == _ODP_THR_INTERNAL)
		return 0;

	if (group_all)
		_odp_sched_fn->thr_add(ODP_SCHED_GROUP_ALL, id);

	if (type == _ODP_THR_WORKER && group_worker)
		_odp_sched_fn->thr_add(ODP_SCHED_GROUP_WORKER, id);

	if (type == _ODP_THR_CONTROL && group_control)
		_odp_sched_fn->thr_add(ODP_SCHED_GROUP_CONTROL, id);

	return 0;
}

int _odp_thread_term_local(void)
{
	int num;
	int group_all, group_worker, group_control;
	int id = _odp_this_thread->thr;
	_odp_internal_thread_type_t type = _odp_this_thread->type;

	/* Flush pending prints */
	_odp_print_term_local();

	group_all = 1;
	group_worker = 1;
	group_control = 1;

	if (type != _ODP_THR_INTERNAL && _odp_sched_fn->get_config) {
		schedule_config_t schedule_config;

		_odp_sched_fn->get_config(&schedule_config);
		group_all = schedule_config.group_enable.all;
		group_worker = schedule_config.group_enable.worker;
		group_control = schedule_config.group_enable.control;
	}

	if (type != _ODP_THR_INTERNAL && group_all)
		_odp_sched_fn->thr_rem(ODP_SCHED_GROUP_ALL, id);

	if (type == _ODP_THR_WORKER && group_worker)
		_odp_sched_fn->thr_rem(ODP_SCHED_GROUP_WORKER, id);

	if (type == _ODP_THR_CONTROL && group_control)
		_odp_sched_fn->thr_rem(ODP_SCHED_GROUP_CONTROL, id);

	_odp_this_thread = NULL;

	odp_spinlock_lock(&thread_globals->lock);
	num = free_id(id);
	odp_spinlock_unlock(&thread_globals->lock);

	if (num < 0) {
		_ODP_ERR("failed to free thread id %i", id);
		return -1;
	}

	return num; /* return a number of threads left */
}

int odp_thread_count(void)
{
	uint32_t num = odp_atomic_load_u32(&thread_globals->num);
	uint32_t num_internal = odp_atomic_load_u32(&thread_globals->num_internal);

	return (int)(num - num_internal);
}

int _odp_thread_is_internal(int thr_id)
{
	int is_internal;

	if (thr_id < 0 || thr_id >= (int)thread_globals->num_max)
		return 0;

	odp_spinlock_lock(&thread_globals->lock);
	is_internal = odp_thrmask_isset(&thread_globals->all, thr_id) &&
		      thread_globals->thr[thr_id].type == _ODP_THR_INTERNAL;
	odp_spinlock_unlock(&thread_globals->lock);

	return is_internal;
}

int _odp_thread_count_max(void)
{
	return (int)thread_globals->num_max;
}

int odp_thread_control_count(void)
{
	return odp_atomic_load_u32(&thread_globals->num_control);
}

int odp_thread_worker_count(void)
{
	return odp_atomic_load_u32(&thread_globals->num_worker);
}

int odp_thread_count_max(void)
{
	return thread_count_max_visible();
}

int odp_thread_control_count_max(void)
{
	return thread_count_max_visible();
}

int odp_thread_worker_count_max(void)
{
	return thread_count_max_visible();
}

int odp_thrmask_worker(odp_thrmask_t *mask)
{
	uint32_t num_worker;

	odp_spinlock_lock(&thread_globals->lock);
	odp_thrmask_copy(mask, &thread_globals->worker);
	num_worker = odp_atomic_load_u32(&thread_globals->num_worker);
	odp_spinlock_unlock(&thread_globals->lock);
	return num_worker;
}

int odp_thrmask_control(odp_thrmask_t *mask)
{
	uint32_t num_control;

	odp_spinlock_lock(&thread_globals->lock);
	odp_thrmask_copy(mask, &thread_globals->control);
	num_control = odp_atomic_load_u32(&thread_globals->num_control);
	odp_spinlock_unlock(&thread_globals->lock);
	return num_control;
}

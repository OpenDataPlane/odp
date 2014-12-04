/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_timer.h>
#include <odp_timer_internal.h>
#include <odp_time.h>
#include <odp_buffer_pool_internal.h>
#include <odp_internal.h>
#include <odp_atomic.h>
#include <odp_spinlock.h>
#include <odp_sync.h>
#include <odp_debug_internal.h>

#include <signal.h>
#include <time.h>

#include <string.h>

#define NUM_TIMERS    1
#define MAX_TICKS     1024
#define MAX_RES       ODP_TIME_SEC
#define MIN_RES       (100*ODP_TIME_USEC)


typedef struct {
	odp_spinlock_t lock;
	timeout_t      *list;
} tick_t;

typedef struct {
	int               allocated;
	volatile int      active;
	volatile uint64_t cur_tick;
	timer_t           timerid;
	odp_timer_t       timer_hdl;
	odp_buffer_pool_t pool;
	uint64_t          resolution_ns;
	uint64_t          max_ticks;
	tick_t            tick[MAX_TICKS];

} timer_ring_t;

typedef struct {
	odp_spinlock_t lock;
	int            num_timers;
	timer_ring_t   timer[NUM_TIMERS];

} timer_global_t;

/* Global */
static timer_global_t odp_timer;

static void add_tmo(tick_t *tick, timeout_t *tmo)
{
	odp_spinlock_lock(&tick->lock);

	tmo->next  = tick->list;
	tick->list = tmo;

	odp_spinlock_unlock(&tick->lock);
}

static timeout_t *rem_tmo(tick_t *tick)
{
	timeout_t *tmo;

	odp_spinlock_lock(&tick->lock);

	tmo = tick->list;

	if (tmo)
		tick->list = tmo->next;

	odp_spinlock_unlock(&tick->lock);

	if (tmo)
		tmo->next = NULL;

	return tmo;
}

/**
 * Search and delete tmo entry from timeout list
 * return -1 : on error.. handle not in list
 *		0 : success
 */
static int find_and_del_tmo(timeout_t **tmo, odp_timer_tmo_t handle)
{
	timeout_t *cur, *prev;
	prev = NULL;

	for (cur = *tmo; cur != NULL; prev = cur, cur = cur->next) {
		if (cur->tmo_buf == handle) {
			if (prev == NULL)
				*tmo = cur->next;
			else
				prev->next = cur->next;

			break;
		}
	}

	if (!cur)
		/* couldn't find tmo in list */
		return -1;

	/* application to free tmo_buf provided by absolute_tmo call */
	return 0;
}

int odp_timer_cancel_tmo(odp_timer_t timer_hdl, odp_timer_tmo_t tmo)
{
	int id;
	int tick_idx;
	timeout_t *cancel_tmo;
	odp_timeout_hdr_t *tmo_hdr;
	tick_t *tick;

	/* get id */
	id = (int)timer_hdl - 1;

	tmo_hdr = odp_timeout_hdr((odp_timeout_t) tmo);
	/* get tmo_buf to cancel */
	cancel_tmo = &tmo_hdr->meta;

	tick_idx = cancel_tmo->tick;
	tick = &odp_timer.timer[id].tick[tick_idx];

	odp_spinlock_lock(&tick->lock);
	/* search and delete tmo from tick list */
	if (find_and_del_tmo(&tick->list, tmo) != 0) {
		odp_spinlock_unlock(&tick->lock);
		ODP_DBG("Couldn't find the tmo (%d) in tick list\n", (int)tmo);
		return -1;
	}
	odp_spinlock_unlock(&tick->lock);

	return 0;
}

static void notify_function(union sigval sigval)
{
	uint64_t cur_tick;
	timeout_t *tmo;
	tick_t *tick;
	timer_ring_t *timer;

	timer = sigval.sival_ptr;

	if (timer->active == 0) {
		ODP_DBG("Timer (%u) not active\n", timer->timer_hdl);
		return;
	}

	/* ODP_DBG("Tick\n"); */

	cur_tick = timer->cur_tick++;

	odp_sync_stores();

	tick = &timer->tick[cur_tick % MAX_TICKS];

	while ((tmo = rem_tmo(tick)) != NULL) {
		odp_queue_t  queue;
		odp_buffer_t buf;

		queue = tmo->queue;
		buf   = tmo->buf;

		if (buf != tmo->tmo_buf)
			odp_buffer_free(tmo->tmo_buf);

		odp_queue_enq(queue, buf);
	}
}

static void timer_start(timer_ring_t *timer)
{
	struct sigevent   sigev;
	struct itimerspec ispec;
	uint64_t res, sec, nsec;

	ODP_DBG("\nTimer (%u) starts\n", timer->timer_hdl);

	memset(&sigev, 0, sizeof(sigev));
	memset(&ispec, 0, sizeof(ispec));

	sigev.sigev_notify          = SIGEV_THREAD;
	sigev.sigev_notify_function = notify_function;
	sigev.sigev_value.sival_ptr = timer;

	if (timer_create(CLOCK_MONOTONIC, &sigev, &timer->timerid)) {
		ODP_DBG("Timer create failed\n");
		return;
	}

	res  = timer->resolution_ns;
	sec  = res / ODP_TIME_SEC;
	nsec = res - sec*ODP_TIME_SEC;

	ispec.it_interval.tv_sec  = (time_t)sec;
	ispec.it_interval.tv_nsec = (long)nsec;
	ispec.it_value.tv_sec     = (time_t)sec;
	ispec.it_value.tv_nsec    = (long)nsec;

	if (timer_settime(timer->timerid, 0, &ispec, NULL)) {
		ODP_DBG("Timer set failed\n");
		return;
	}

	return;
}

int odp_timer_init_global(void)
{
	ODP_DBG("Timer init ...");

	memset(&odp_timer, 0, sizeof(timer_global_t));

	odp_spinlock_init(&odp_timer.lock);

	ODP_DBG("done\n");

	return 0;
}

int odp_timer_disarm_all(void)
{
	int timers;
	struct itimerspec ispec;

	odp_spinlock_lock(&odp_timer.lock);

	timers = odp_timer.num_timers;

	ispec.it_interval.tv_sec  = 0;
	ispec.it_interval.tv_nsec = 0;
	ispec.it_value.tv_sec     = 0;
	ispec.it_value.tv_nsec    = 0;

	for (; timers >= 0; timers--) {
		if (timer_settime(odp_timer.timer[timers].timerid,
				  0, &ispec, NULL)) {
			ODP_DBG("Timer reset failed\n");
			odp_spinlock_unlock(&odp_timer.lock);
			return -1;
		}
		odp_timer.num_timers--;
	}

	odp_spinlock_unlock(&odp_timer.lock);

	return 0;
}

odp_timer_t odp_timer_create(const char *name, odp_buffer_pool_t pool,
			     uint64_t resolution_ns, uint64_t min_ns,
			     uint64_t max_ns)
{
	uint32_t id;
	timer_ring_t *timer;
	odp_timer_t timer_hdl;
	int i;
	uint64_t max_ticks;
	(void) name;

	if (resolution_ns < MIN_RES)
		resolution_ns = MIN_RES;

	if (resolution_ns > MAX_RES)
		resolution_ns = MAX_RES;

	max_ticks = max_ns / resolution_ns;

	if (max_ticks > MAX_TICKS) {
		ODP_DBG("Maximum timeout too long: %"PRIu64" ticks\n",
			max_ticks);
		return ODP_TIMER_INVALID;
	}

	if (min_ns < resolution_ns) {
		ODP_DBG("Min timeout %"PRIu64" ns < resolution %"PRIu64" ns\n",
			min_ns, resolution_ns);
		return ODP_TIMER_INVALID;
	}

	odp_spinlock_lock(&odp_timer.lock);

	if (odp_timer.num_timers >= NUM_TIMERS) {
		odp_spinlock_unlock(&odp_timer.lock);
		ODP_DBG("All timers allocated\n");
		return ODP_TIMER_INVALID;
	}

	for (id = 0; id < NUM_TIMERS; id++) {
		if (odp_timer.timer[id].allocated == 0)
			break;
	}

	timer = &odp_timer.timer[id];
	timer->allocated = 1;
	odp_timer.num_timers++;

	odp_spinlock_unlock(&odp_timer.lock);

	timer_hdl = id + 1;

	timer->timer_hdl     = timer_hdl;
	timer->pool          = pool;
	timer->resolution_ns = resolution_ns;
	timer->max_ticks     = MAX_TICKS;

	for (i = 0; i < MAX_TICKS; i++) {
		odp_spinlock_init(&timer->tick[i].lock);
		timer->tick[i].list = NULL;
	}

	timer->active = 1;
	odp_sync_stores();

	timer_start(timer);

	return timer_hdl;
}

odp_timer_tmo_t odp_timer_absolute_tmo(odp_timer_t timer_hdl, uint64_t tmo_tick,
				       odp_queue_t queue, odp_buffer_t buf)
{
	int id;
	uint64_t tick;
	uint64_t cur_tick;
	timeout_t *new_tmo;
	odp_buffer_t tmo_buf;
	odp_timeout_hdr_t *tmo_hdr;
	timer_ring_t *timer;

	id = (int)timer_hdl - 1;
	timer = &odp_timer.timer[id];

	cur_tick = timer->cur_tick;
	if (tmo_tick <= cur_tick) {
		ODP_DBG("timeout too close\n");
		return ODP_TIMER_TMO_INVALID;
	}

	if ((tmo_tick - cur_tick) > MAX_TICKS) {
		ODP_DBG("timeout too far: cur %"PRIu64" tmo %"PRIu64"\n",
			cur_tick, tmo_tick);
		return ODP_TIMER_TMO_INVALID;
	}

	tick = tmo_tick % MAX_TICKS;

	tmo_buf = odp_buffer_alloc(timer->pool);
	if (tmo_buf == ODP_BUFFER_INVALID) {
		ODP_DBG("tmo buffer alloc failed\n");
		return ODP_TIMER_TMO_INVALID;
	}

	tmo_hdr = odp_timeout_hdr((odp_timeout_t) tmo_buf);
	new_tmo = &tmo_hdr->meta;

	new_tmo->timer_id = id;
	new_tmo->tick     = (int)tick;
	new_tmo->tmo_tick = tmo_tick;
	new_tmo->queue    = queue;
	new_tmo->tmo_buf  = tmo_buf;

	if (buf != ODP_BUFFER_INVALID)
		new_tmo->buf = buf;
	else
		new_tmo->buf = tmo_buf;

	add_tmo(&timer->tick[tick], new_tmo);

	return tmo_buf;
}

uint64_t odp_timer_tick_to_ns(odp_timer_t timer_hdl, uint64_t ticks)
{
	uint32_t id;

	id = timer_hdl - 1;
	return ticks * odp_timer.timer[id].resolution_ns;
}

uint64_t odp_timer_ns_to_tick(odp_timer_t timer_hdl, uint64_t ns)
{
	uint32_t id;

	id = timer_hdl - 1;
	return ns / odp_timer.timer[id].resolution_ns;
}

uint64_t odp_timer_resolution(odp_timer_t timer_hdl)
{
	uint32_t id;

	id = timer_hdl - 1;
	return odp_timer.timer[id].resolution_ns;
}

uint64_t odp_timer_maximum_tmo(odp_timer_t timer_hdl)
{
	uint32_t id;

	id = timer_hdl - 1;
	return odp_timer.timer[id].max_ticks;
}

uint64_t odp_timer_current_tick(odp_timer_t timer_hdl)
{
	uint32_t id;

	id = timer_hdl - 1;
	return odp_timer.timer[id].cur_tick;
}

odp_timeout_t odp_timeout_from_buffer(odp_buffer_t buf)
{
	return (odp_timeout_t) buf;
}

uint64_t odp_timeout_tick(odp_timeout_t tmo)
{
	odp_timeout_hdr_t *tmo_hdr = odp_timeout_hdr(tmo);
	return tmo_hdr->meta.tmo_tick;
}

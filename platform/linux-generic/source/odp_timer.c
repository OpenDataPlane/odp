/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_timer.h>
#include <odp_internal.h>
#include <odp_atomic.h>
#include <odp_spinlock.h>
#include <odp_sync.h>
#include <odp_debug.h>

#include <signal.h>
#include <time.h>

#include <string.h>


#define NUM_TIMERS    1
#define MAX_TICKS     1024
#define RESOLUTION_NS 1000000

struct timeout_t;

typedef struct timeout_t {
	struct timeout_t *next;
	int               timer_id;
	int               tick;
	uint64_t          tmo_tick;
	odp_queue_t       queue;
	odp_buffer_t      buf;
	odp_buffer_t      tmo_buf;
} timeout_t;

typedef struct {
	odp_spinlock_t lock;
	timeout_t      *list;
} tick_t;

typedef struct {
	volatile int      active;
	volatile uint64_t cur_tick;
	timer_t           timerid;
	odp_buffer_pool_t pool;
	uint64_t          resolution_ns;
	uint64_t          max_ticks;
	tick_t            tick[MAX_TICKS];

} timer_ring_t;


typedef struct {
	timer_ring_t     timer[NUM_TIMERS];
	odp_atomic_int_t num_timers;
} timer_global_t;



/* Global */
timer_global_t odp_timer;


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



static void notify_function(union sigval sigval)
{
	(void) sigval;
	uint64_t cur_tick;
	timeout_t *tmo;
	tick_t *tick;

	if (odp_timer.timer[0].active == 0)
		return;

	/* ODP_DBG("Tick\n"); */

	cur_tick = odp_timer.timer[0].cur_tick++;

	tick = &odp_timer.timer[0].tick[cur_tick % MAX_TICKS];

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


static void timer_init(void)
{
	struct sigevent   sigev;
	struct itimerspec ispec;

	ODP_DBG("Timer thread starts\n");

	memset(&sigev, 0, sizeof(sigev));
	memset(&ispec, 0, sizeof(ispec));

	sigev.sigev_notify          = SIGEV_THREAD;
	sigev.sigev_notify_function = notify_function;

	if (timer_create(CLOCK_MONOTONIC, &sigev,
			 &odp_timer.timer[0].timerid)) {
		ODP_DBG("Timer create failed\n");
		return;
	}

	ispec.it_interval.tv_sec  = 0;
	ispec.it_interval.tv_nsec = RESOLUTION_NS;
	ispec.it_value.tv_sec     = 0;
	ispec.it_value.tv_nsec    = RESOLUTION_NS;

	if (timer_settime(odp_timer.timer[0].timerid, 0, &ispec, NULL)) {
		ODP_DBG("Timer set failed\n");
		return;
	}

	return;
}


int odp_timer_init_global(void)
{
	int i;

	memset(&odp_timer, 0, sizeof(timer_global_t));

	for (i = 0; i < MAX_TICKS; i++)
		odp_spinlock_init(&odp_timer.timer[0].tick[i].lock);

	timer_init();


	return 0;
}



odp_timer_t odp_timer_create(const char *name, odp_buffer_pool_t pool,
			     uint64_t resolution, uint64_t min_tmo,
			     uint64_t max_tmo)
{
	uint32_t id;
	(void) name; (void) resolution; (void) min_tmo; (void) max_tmo;

	if (odp_timer.num_timers >= NUM_TIMERS)
		return ODP_TIMER_INVALID;

	id = odp_atomic_fetch_inc_int(&odp_timer.num_timers);

	if (id >= NUM_TIMERS)
		return ODP_TIMER_INVALID;

	odp_timer.timer[id].pool          = pool;
	odp_timer.timer[id].resolution_ns = RESOLUTION_NS;
	odp_timer.timer[id].max_ticks     = MAX_TICKS;

	odp_sync_stores();

	odp_timer.timer[id].active = 1;

	return id + 1;
}


odp_timer_tmo_t odp_timer_absolute_tmo(odp_timer_t timer, uint64_t tmo_tick,
				       odp_queue_t queue, odp_buffer_t buf)
{
	int id;
	uint64_t tick;
	uint64_t cur_tick;
	timeout_t *new_tmo;
	odp_buffer_t tmo_buf;

	id = timer - 1;

	cur_tick = odp_timer.timer[id].cur_tick;

	if (tmo_tick <= cur_tick) {
		ODP_DBG("timeout too close\n");
		return ODP_TIMER_TMO_INVALID;
	}

	tick = tmo_tick - cur_tick;

	if (tick > MAX_TICKS) {
		ODP_DBG("timeout too far\n");
		return ODP_TIMER_TMO_INVALID;
	}

	tick = (cur_tick + tick) % MAX_TICKS;

	tmo_buf = odp_buffer_alloc(odp_timer.timer[id].pool);

	if (tmo_buf == ODP_BUFFER_INVALID) {
		ODP_DBG("alloc failed\n");
		return ODP_TIMER_TMO_INVALID;
	}

	new_tmo = (timeout_t *)odp_buffer_addr(tmo_buf);

	new_tmo->timer_id = id;
	new_tmo->tick     = (int)tick;
	new_tmo->tmo_tick = tmo_tick;
	new_tmo->queue    = queue;
	new_tmo->tmo_buf  = tmo_buf;

	if (buf != ODP_BUFFER_INVALID)
		new_tmo->buf = buf;
	else
		new_tmo->buf = tmo_buf;

	add_tmo(&odp_timer.timer[id].tick[tick], new_tmo);

	return tmo_buf;
}



uint64_t odp_timer_tick_to_ns(odp_timer_t timer, uint64_t ticks)
{
	uint32_t id;

	id = timer - 1;

	return ticks * odp_timer.timer[id].resolution_ns;
}


uint64_t odp_timer_ns_to_tick(odp_timer_t timer, uint64_t ns)
{
	uint32_t id;

	id = timer - 1;

	return ns / odp_timer.timer[id].resolution_ns;
}


uint64_t odp_timer_resolution(odp_timer_t timer)
{
	uint32_t id;

	id = timer - 1;

	return odp_timer.timer[id].resolution_ns;
}


uint64_t odp_timer_maximum_tmo(odp_timer_t timer)
{
	uint32_t id;

	id = timer - 1;

	return odp_timer.timer[id].max_ticks;
}


uint64_t odp_timer_current_tick(odp_timer_t timer)
{
	uint32_t id;

	id = timer - 1;

	return odp_timer.timer[id].cur_tick;
}

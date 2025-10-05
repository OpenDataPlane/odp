/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2025 Nokia
 */

/**
 * @file
 *
 * ODP timer service
 *
 */
#include <odp_posix_extensions.h>

#include <odp/api/align.h>
#include <odp/api/atomic.h>
#include <odp/api/cpu.h>
#include <odp/api/debug.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp/api/pool.h>
#include <odp/api/queue.h>
#include <odp/api/shared_memory.h>
#include <odp/api/spinlock.h>
#include <odp/api/std.h>
#include <odp/api/sync.h>
#include <odp/api/time.h>
#include <odp/api/timer.h>

/* Inlined API functions */
#include <odp/api/plat/atomic_inlines.h>
#include <odp/api/plat/event_inlines.h>
#include <odp/api/plat/queue_inlines.h>
#include <odp/api/plat/time_inlines.h>
#include <odp/api/plat/timer_inlines.h>

#include <odp/api/plat/timer_inline_types.h>

#include <odp_atomic_internal.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_event_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_macros_internal.h>
#include <odp_pool_internal.h>
#include <odp_string_internal.h>
#include <odp_queue_if.h>
#include <odp_timer_internal.h>
#include <odp_types_internal.h>

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Check whether 128-bit atomics should be used */
#if defined(ODP_ATOMIC_U128) && CONFIG_TIMER_128BIT_ATOMICS
#define USE_128BIT_ATOMICS 1
#else
#define USE_128BIT_ATOMICS 0
#endif

/* One divided by one nanosecond in Hz */
#define GIGA_HZ 1000000000

#define TMO_UNUSED   ((uint64_t)0xFFFFFFFFFFFFFFFF)
/* TMO_INACTIVE is or-ed with the expiration tick to indicate an expired timer.
 * The original expiration tick (63 bits) is still available so it can be used
 * for checking the freshness of received timeouts */
#define TMO_INACTIVE ((uint64_t)0x8000000000000000)

/* Flag set into periodic tick value when periodic timer cancel did not succeed.
 * Ack call checks this. */
#define PERIODIC_CANCELLED  TMO_INACTIVE

/* Max timeout in capability. One year in nsec (0x0070 09D3 2DA3 0000). */
#define MAX_TMO_NSEC (365 * 24 * ODP_TIME_HOUR_IN_NS)

/* Max inline timer resolution */
#define MAX_INLINE_RES_NS 500

/* Timer pool may be reused after this period */
#define TIMER_POOL_REUSE_NS ODP_TIME_SEC_IN_NS

/* Minimum periodic timer base frequency */
#define MIN_BASE_HZ 1

/* Maximum periodic timer multiplier */
#define MAX_MULTIPLIER 1000000

/* Maximum number of periodic timers per pool */
#define MAX_PERIODIC_TIMERS 100

/* Mutual exclusion in the absence of CAS16 */
#if !USE_128BIT_ATOMICS
#define NUM_LOCKS 256
#define IDX2LOCK(tp, idx) (&(tp)->locks[(idx) % NUM_LOCKS])
#endif

#define ACC_SIZE (1ull << 32)

#include <odp/visibility_begin.h>

/* Fill in timeout header field offsets for inline functions */
const _odp_timeout_inline_offset_t
_odp_timeout_inline_offset ODP_ALIGNED_CACHE = {
	.expiration = offsetof(odp_timeout_hdr_t, expiration),
	.timer = offsetof(odp_timeout_hdr_t, timer),
	.user_ptr = offsetof(odp_timeout_hdr_t, user_ptr),
	.uarea_addr = offsetof(odp_timeout_hdr_t, uarea_addr),
};

#include <odp/visibility_end.h>

typedef union
#if USE_128BIT_ATOMICS
ODP_ALIGNED(16) /* 16-byte atomic operations need properly aligned addresses */
#endif
tick_buf_s {
#if USE_128BIT_ATOMICS
	odp_atomic_u128_t tb_atomic_u128;

	odp_u128_t tb_u128;
#endif

	struct {
		/* Expiration tick or TMO_xxx */
		odp_atomic_u64_t exp_tck;
		union {
			/* ODP_EVENT_INVALID if timer not active */
			odp_event_t tmo_event;

			/* Ensures that tick_buf_t is 128 bits */
			uint64_t tmo_u64;
		};
	};
} tick_buf_t;

#if USE_128BIT_ATOMICS
ODP_STATIC_ASSERT(sizeof(tick_buf_t) == 16, "sizeof(tick_buf_t) == 16");
#endif

typedef struct {
	const void *user_ptr;
	odp_queue_t queue;

	/* Period of periodic timer in ticks (nanoseconds), includes PERIODIC_CANCELLED flag. */
	uint64_t periodic_ticks;

	/* Periodic ticks fractional part. */
	uint32_t periodic_ticks_frac;

	/* Periodic ticks fractional part accumulator. */
	uint32_t periodic_ticks_frac_acc;

	/* Used for free list of timers */
	uint32_t next_free;

} _odp_timer_t;

typedef struct timer_pool_s {
	/* Put frequently accessed fields in the first cache line */
	uint64_t nsec_per_scan;
	odp_atomic_u64_t cur_tick;/* Current tick value */
	uint64_t min_rel_tck;
	uint64_t max_rel_tck;
	tick_buf_t *tick_buf; /* Expiration tick and timeout buffer */
	_odp_timer_t *timers; /* User pointer and queue handle (and lock) */
	odp_atomic_u32_t high_wm;/* High watermark of allocated timers */
	odp_spinlock_t lock;
	uint32_t num_alloc;/* Current number of allocated timers */
	uint32_t first_free;/* 0..max_timers-1 => free timer */
	uint32_t tp_idx;/* Index into timer_pool array */
	odp_timer_pool_param_t param;
	char name[ODP_TIMER_POOL_NAME_LEN];
	timer_t timerid;
	/*
	 * Timer pool overrun notification (debug print). Initialize to 0
	 * (don't notify). When value is 0 and a timer is started, set to 1
	 * (notify). When notification is done, set to 2 (don't notify).
	 */
	odp_atomic_u32_t notify_overrun;
	int owner;
	pthread_t thr_pthread; /* pthread_t of timer thread */
	odp_atomic_u64_t thr_pid; /* gettid() for timer thread */
	int thr_warm_up; /* number of warm up rounds */
	odp_atomic_u32_t thr_ready; /* thread ready from warm up */
	odp_atomic_u32_t thr_exit; /* request to exit for timer thread */
	double base_freq;
	uint64_t max_multiplier;
	uint8_t periodic;
#if !USE_128BIT_ATOMICS
	/* Multiple locks per cache line! */
	_odp_atomic_flag_t locks[NUM_LOCKS] ODP_ALIGNED_CACHE;
#endif

} timer_pool_t;

/* Timer pool index must fit into 8 bits with one index value reserved to
 * ODP_TIMER_POOL_INVALID. */
#define MAX_TIMER_POOLS 32
#define INDEX_BITS 24
#define TIMER_RES_TEST_LOOP_COUNT 10
#define TIMER_RES_ROUNDUP_FACTOR 10

typedef struct timer_global_t {
	odp_ticketlock_t lock;
	odp_shm_t shm;
	/* Max timer resolution in nanoseconds */
	uint64_t highest_res_ns;
	uint64_t highest_res_hz;
	uint64_t max_base_hz;
	uint64_t poll_interval_nsec;
	int num_timer_pools;
	uint8_t timer_pool_used[MAX_TIMER_POOLS];
	odp_time_t destroy_time[MAX_TIMER_POOLS];
	odp_shm_t tp_shm[MAX_TIMER_POOLS];
	timer_pool_t *timer_pool[MAX_TIMER_POOLS];

	/* These are read frequently from inline timer */
	odp_time_t poll_interval_time;
	odp_bool_t use_inline_timers;
	int poll_interval;
	int highest_tp_idx;
	uint8_t thread_type;

} timer_global_t;

typedef struct timer_local_t {
	odp_time_t last_run;
	int        run_cnt;
	uint8_t    poll_shared;
	uint64_t   prof_nsec;
	uint64_t   prof_rounds;
} timer_local_t;

/* Points to timer global data */
static timer_global_t *timer_global;

/* Timer thread local data */
static __thread timer_local_t timer_local;

static inline void set_next_free(_odp_timer_t *tim, uint32_t nf)
{
	_ODP_ASSERT(tim->queue == ODP_QUEUE_INVALID);

	tim->next_free = nf;
}

static inline timer_pool_t *timer_pool_from_hdl(odp_timer_pool_t hdl)
{
	return (timer_pool_t *)(uintptr_t)hdl;
}

static inline odp_timer_pool_t timer_pool_to_hdl(timer_pool_t *tp)
{
	return (odp_timer_pool_t)tp;
}

static inline timer_pool_t *handle_to_tp(odp_timer_t hdl)
{
	uint32_t tp_idx = _odp_typeval(hdl) >> INDEX_BITS;
	timer_pool_t *tp;

	_ODP_ASSERT(tp_idx < MAX_TIMER_POOLS);

	tp = timer_global->timer_pool[tp_idx];

	_ODP_ASSERT(tp != NULL);

	return tp;
}

static inline uint32_t handle_to_idx(odp_timer_t hdl,
				     timer_pool_t *tp)
{
	uint32_t idx = (_odp_typeval(hdl) & ((1U << INDEX_BITS) - 1U)) - 1;

	_ODP_ASSERT(idx < odp_atomic_load_u32(&tp->high_wm));

	__builtin_prefetch(&tp->tick_buf[idx], 0, 0);

	return idx;
}

static inline odp_timer_t tp_idx_to_handle(timer_pool_t *tp,
					   uint32_t idx)
{
	_ODP_ASSERT((idx + 1) < (1U << INDEX_BITS));
	return _odp_cast_scalar(odp_timer_t, (tp->tp_idx << INDEX_BITS) |
				(idx + 1));
}

static inline odp_timeout_hdr_t *timeout_hdr_from_event(odp_event_t event)
{
	return (odp_timeout_hdr_t *)(uintptr_t)event;
}

static inline odp_timeout_hdr_t *timeout_hdr(odp_timeout_t tmo)
{
	return (odp_timeout_hdr_t *)(uintptr_t)tmo;
}

static uint64_t max_multiplier_capa(double freq)
{
	uint64_t mult;

	if (freq < MIN_BASE_HZ)
		return 0;

	mult = timer_global->max_base_hz / freq;
	if (mult > MAX_MULTIPLIER)
		mult = MAX_MULTIPLIER;

	return mult;
}

static void block_sigalarm(void)
{
	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
}

static void posix_timer_stop(timer_pool_t *tp)
{
	int ret;

	/* Stop POSIX timer signals */
	if (timer_delete(tp->timerid) != 0)
		_ODP_ABORT("timer_delete() returned error: %s\n", strerror(errno));

	/* Stop the thread */
	_ODP_DBG("stop\n");
	odp_atomic_store_u32(&tp->thr_exit, 1);
	ret = pthread_join(tp->thr_pthread, NULL);
	if (ret != 0)
		_ODP_ABORT("Unable to join thread, err %d\n", ret);
}

static void odp_timer_pool_del(timer_pool_t *tp)
{
	int highest;
	uint32_t tp_idx = tp->tp_idx;

	odp_spinlock_lock(&tp->lock);

	if (!timer_global->use_inline_timers)
		posix_timer_stop(tp);

	if (tp->num_alloc != 0) {
		/* It's a programming error to attempt to destroy a */
		/* timer pool which is still in use */
		odp_spinlock_unlock(&tp->lock);
		_ODP_ABORT("%s: timers in use\n", tp->name);
	}

	odp_spinlock_unlock(&tp->lock);

	odp_ticketlock_lock(&timer_global->lock);
	timer_global->timer_pool[tp_idx] = NULL;
	timer_global->timer_pool_used[tp_idx] = 0;
	timer_global->num_timer_pools--;
	timer_global->destroy_time[tp_idx] = odp_time_global();

	highest = -1;

	/* Disable inline timer polling */
	if (timer_global->num_timer_pools == 0) {
		odp_global_rw->inline_timers = false;
	} else {
		int i;

		for (i = 0; i < MAX_TIMER_POOLS; i++)
			if (timer_global->timer_pool_used[i])
				highest = i;
	}

	timer_global->highest_tp_idx = highest;

	odp_ticketlock_unlock(&timer_global->lock);
}

static inline odp_timer_t timer_alloc(timer_pool_t *tp, odp_queue_t queue, const void *user_ptr)
{
	odp_timer_t hdl;

	odp_spinlock_lock(&tp->lock);
	if (odp_likely(tp->num_alloc < tp->param.num_timers)) {
		tp->num_alloc++;
		/* Remove first unused timer from free list */
		_ODP_ASSERT(tp->first_free != tp->param.num_timers);
		uint32_t idx = tp->first_free;
		_odp_timer_t *tim = &tp->timers[idx];
		tick_buf_t *tb = &tp->tick_buf[idx];

		tp->first_free = tim->next_free;
		tim->queue = queue;
		tim->user_ptr = user_ptr;
		tb->tmo_u64 = 0;
		tb->tmo_event = ODP_EVENT_INVALID;

		/* Release the timer by setting timer state to inactive */
		odp_atomic_store_rel_u64(&tb->exp_tck, TMO_INACTIVE);


		if (odp_unlikely(tp->num_alloc > odp_atomic_load_u32(&tp->high_wm))) {
			/* Update high_wm last with release model to
			 * ensure timer initialization is visible */
			odp_atomic_store_rel_u32(&tp->high_wm, tp->num_alloc);
		}

		hdl = tp_idx_to_handle(tp, idx);
		/* Add timer to queue */
		_odp_queue_fn->timer_add(queue);
	} else {
		/* Reusing file table overflow */
		hdl = ODP_TIMER_INVALID;
	}
	odp_spinlock_unlock(&tp->lock);
	return hdl;
}

static bool timer_reset(uint32_t idx, uint64_t abs_tck, odp_event_t *tmo_event,
			timer_pool_t *tp)
{
	bool success = true;
	tick_buf_t *tb = &tp->tick_buf[idx];

	if (tmo_event == NULL || *tmo_event == ODP_EVENT_INVALID) {
#if USE_128BIT_ATOMICS /* Target supports 128-bit atomic operations */
		tick_buf_t new, old;

		/* Init all bits, also when tmo_event is less than 64 bits */
		new.tmo_u64 = 0;
		old.tmo_u64 = 0;

		/* Relaxed and non-atomic read of current values */
		old.exp_tck.v = tb->exp_tck.v;
		old.tmo_event = tb->tmo_event;

		do {
			/* Check if there actually is a timeout event
			 * present */
			if (old.tmo_event == ODP_EVENT_INVALID) {
				/* Cannot reset a timer with neither old nor
				 * new timeout event */
				success = false;
				break;
			}
			/* Set up new values */
			new.exp_tck.v = abs_tck;
			new.tmo_event = old.tmo_event;

			/* Atomic CAS will fail if we experienced torn reads,
			 * retry update sequence until CAS succeeds */
		} while (!odp_atomic_cas_rel_u128(&tb->tb_atomic_u128,
						  &old.tb_u128, new.tb_u128));
#else
		/* Take a related lock */
		while (_odp_atomic_flag_tas(IDX2LOCK(tp, idx)))
			/* While lock is taken, spin using relaxed loads */
			while (_odp_atomic_flag_load(IDX2LOCK(tp, idx)))
				odp_cpu_pause();

		/* Only if there is a timeout event can the timer be reset */
		if (odp_likely(tb->tmo_event != ODP_EVENT_INVALID)) {
			/* Write the new expiration tick */
			tb->exp_tck.v = abs_tck;
		} else {
			/* Cannot reset a timer with neither old nor new
			 * timeout event */
			success = false;
		}

		/* Release the lock */
		_odp_atomic_flag_clear(IDX2LOCK(tp, idx));
#endif
	} else {
		/* We have a new timeout event which replaces any old one */
		/* Fill in some (constant) header fields for timeout events */
		if (odp_event_type(*tmo_event) == ODP_EVENT_TIMEOUT) {
			/* Convert from event to timeout hdr */
			odp_timeout_hdr_t *tmo_hdr =
				timeout_hdr_from_event(*tmo_event);
			tmo_hdr->timer = tp_idx_to_handle(tp, idx);
			tmo_hdr->user_ptr = tp->timers[idx].user_ptr;
			/* expiration field filled in when timer expires */
		}
		/* Else ignore events of other types */
		odp_event_t old_event = ODP_EVENT_INVALID;
#if USE_128BIT_ATOMICS
		tick_buf_t new, old;

		/* Init all bits, also when tmo_event is less than 64 bits */
		new.tmo_u64 = 0;

		new.exp_tck.v = abs_tck;
		new.tmo_event = *tmo_event;

		/* We are releasing the new timeout event to some other
		 * thread */
		_odp_atomic_u128_xchg_mm((_odp_atomic_u128_t *)tb,
					 (_odp_u128_t *)&new,
					 (_odp_u128_t *)&old,
					 _ODP_MEMMODEL_ACQ_RLS);
		old_event = old.tmo_event;
#else
		/* Take a related lock */
		while (_odp_atomic_flag_tas(IDX2LOCK(tp, idx)))
			/* While lock is taken, spin using relaxed loads */
			while (_odp_atomic_flag_load(IDX2LOCK(tp, idx)))
				odp_cpu_pause();

		/* Swap in new event, save any old event */
		old_event = tb->tmo_event;
		tb->tmo_event = *tmo_event;

		/* Write the new expiration tick */
		tb->exp_tck.v = abs_tck;

		/* Release the lock */
		_odp_atomic_flag_clear(IDX2LOCK(tp, idx));
#endif
		/* Return old timeout event */
		*tmo_event = old_event;
	}
	return success;
}

static odp_event_t timer_set_unused(timer_pool_t *tp, uint32_t idx)
{
	tick_buf_t *tb = &tp->tick_buf[idx];
	odp_event_t old_event;

#if USE_128BIT_ATOMICS
	tick_buf_t new, old;

	/* Init all bits, also when tmo_event is less than 64 bits */
	new.tmo_u64 = 0;

	/* Update the timer state (e.g. cancel the current timeout) */
	new.exp_tck.v = TMO_UNUSED;
	/* Swap out the old event */
	new.tmo_event = ODP_EVENT_INVALID;

	_odp_atomic_u128_xchg_mm((_odp_atomic_u128_t *)tb,
				 (_odp_u128_t *)&new, (_odp_u128_t *)&old,
				 _ODP_MEMMODEL_ACQ_RLS);
	old_event = old.tmo_event;
#else
	/* Take a related lock */
	while (_odp_atomic_flag_tas(IDX2LOCK(tp, idx)))
		/* While lock is taken, spin using relaxed loads */
		while (_odp_atomic_flag_load(IDX2LOCK(tp, idx)))
			odp_cpu_pause();

	/* Update the timer state (e.g. cancel the current timeout) */
	tb->exp_tck.v = TMO_UNUSED;

	/* Swap out the old event */
	old_event = tb->tmo_event;
	tb->tmo_event = ODP_EVENT_INVALID;

	/* Release the lock */
	_odp_atomic_flag_clear(IDX2LOCK(tp, idx));
#endif
	/* Return the old event */
	return old_event;
}

int odp_timer_free(odp_timer_t hdl)
{
	timer_pool_t *tp = handle_to_tp(hdl);
	uint32_t idx = handle_to_idx(hdl, tp);
	_odp_timer_t *tim = &tp->timers[idx];
	tick_buf_t *tb = &tp->tick_buf[idx];

	/* Free the timer by setting timer state to unused and
	 * grab any timeout event */
	odp_event_t old_event = timer_set_unused(tp, idx);
	if (old_event != ODP_EVENT_INVALID) {
		_ODP_ERR("Timer is active\n");
		return -1;
	}

	/* Remove timer from queue */
	_odp_queue_fn->timer_rem(tim->queue);

	/* Destroy timer */
	_ODP_ASSERT(tb->exp_tck.v == TMO_UNUSED);
	_ODP_ASSERT(tb->tmo_event == ODP_EVENT_INVALID);
	tim->queue = ODP_QUEUE_INVALID;
	tim->user_ptr = NULL;

	/* Insert timer into free list */
	odp_spinlock_lock(&tp->lock);
	set_next_free(tim, tp->first_free);
	tp->first_free = idx;
	_ODP_ASSERT(tp->num_alloc != 0);
	tp->num_alloc--;
	odp_spinlock_unlock(&tp->lock);

	return 0;
}

static odp_event_t timer_cancel(timer_pool_t *tp, uint32_t idx)
{
	tick_buf_t *tb = &tp->tick_buf[idx];
	odp_event_t old_event;

#if USE_128BIT_ATOMICS
	tick_buf_t new, old;

	/* Init all bits, also when tmo_event is less than 64 bits */
	new.tmo_u64 = 0;
	old.tmo_u64 = 0;

	/* Relaxed and non-atomic read of current values */
	old.exp_tck.v = tb->exp_tck.v;
	old.tmo_event = tb->tmo_event;

	do {
		/* Check if it is not expired already */
		if (old.exp_tck.v & TMO_INACTIVE) {
			old.tmo_event = ODP_EVENT_INVALID;
			break;
		}

		/* Set up new values */
		new.exp_tck.v = TMO_INACTIVE;
		new.tmo_event = ODP_EVENT_INVALID;

		/* Atomic CAS will fail if we experienced torn reads,
		 * retry update sequence until CAS succeeds */
	} while (!odp_atomic_cas_rel_u128(&tb->tb_atomic_u128, &old.tb_u128,
					  new.tb_u128));

	old_event = old.tmo_event;
#else
	/* Take a related lock */
	while (_odp_atomic_flag_tas(IDX2LOCK(tp, idx)))
		/* While lock is taken, spin using relaxed loads */
		while (_odp_atomic_flag_load(IDX2LOCK(tp, idx)))
			odp_cpu_pause();

	/* Swap in new event, save any old event */
	old_event = tb->tmo_event;
	tb->tmo_event = ODP_EVENT_INVALID;

	/* Write the new expiration tick if it not cancelled */
	if (tb->exp_tck.v & TMO_INACTIVE)
		old_event = ODP_EVENT_INVALID;
	else
		tb->exp_tck.v = TMO_INACTIVE;

	/* Release the lock */
	_odp_atomic_flag_clear(IDX2LOCK(tp, idx));
#endif
	/* Return the old event */
	return old_event;
}

static inline void timer_expire(timer_pool_t *tp, uint32_t idx, uint64_t tick)
{
	uint64_t exp_tck;
	odp_queue_t queue = ODP_QUEUE_INVALID;
	_odp_timer_t *tim = &tp->timers[idx];
	tick_buf_t *tb = &tp->tick_buf[idx];
	odp_event_t tmo_event = ODP_EVENT_INVALID;

#if USE_128BIT_ATOMICS
	/* Atomic re-read for correctness */
	exp_tck = odp_atomic_load_acq_u64(&tb->exp_tck);
	/* Re-check exp_tck */
	if (odp_likely(exp_tck <= tick)) {
		/* Attempt to grab timeout event, replace with inactive timer
		 * and invalid event. */
		tick_buf_t new, old;

		/* Read queue handle between acq and rel. Timer_free overwrites the handle after
		 * it sets tick value to inactive. */
		queue = tim->queue;

		/* Init all bits, also when tmo_event is less than 64 bits. */
		new.tmo_u64 = 0;
		old.tmo_u64 = 0;

		old.exp_tck.v = exp_tck;
		old.tmo_event = tb->tmo_event;

		/* Set the inactive/expired bit keeping the expiration tick so
		 * that we can check against the expiration tick of the timeout
		 * when it is received */
		new.exp_tck.v = exp_tck | TMO_INACTIVE;
		new.tmo_event = ODP_EVENT_INVALID;

		int succ = odp_atomic_cas_rel_u128(&tb->tb_atomic_u128,
						   &old.tb_u128, new.tb_u128);
		if (succ)
			tmo_event = old.tmo_event;
		/* Else CAS failed, something changed => skip timer
		 * this tick, it will be checked again next tick */
	}
	/* Else false positive, ignore */
#else
	/* Try to take a related lock */
	if (_odp_atomic_flag_tas(IDX2LOCK(tp, idx)))
		return;

	/* Proper check for timer expired */
	exp_tck = tb->exp_tck.v;
	if (odp_likely(exp_tck <= tick)) {
		/* Verify that there is a timeout event */
		if (odp_likely(tb->tmo_event != ODP_EVENT_INVALID)) {
			queue = tim->queue;

			/* Grab timeout event, replace with inactive timer
			 * and invalid event. */
			tmo_event = tb->tmo_event;
			tb->tmo_event = ODP_EVENT_INVALID;
			/* Set the inactive/expired bit keeping the expiration
			 * tick so that we can check against the expiration
			 * tick of the timeout when it is received */
			tb->exp_tck.v |= TMO_INACTIVE;
		}
		/* Else somehow active timer without user event */
	}
	/* Else false positive, ignore */
	/* Release the lock */
	_odp_atomic_flag_clear(IDX2LOCK(tp, idx));
#endif
	if (odp_likely(tmo_event != ODP_EVENT_INVALID)) {
		/* Fill in expiration tick for timeout events */
		if (odp_event_type(tmo_event) == ODP_EVENT_TIMEOUT) {
			/* Convert from event to timeout hdr */
			odp_timeout_hdr_t *tmo_hdr =
				timeout_hdr_from_event(tmo_event);
			tmo_hdr->expiration = exp_tck;
			/* timer and user_ptr fields filled in when timer
			 * was set */
		}
		/* Else ignore events of other types */
		/* Post the timeout to the destination queue */
		int rc = odp_queue_enq(queue, tmo_event);

		if (odp_unlikely(rc != 0))
			_ODP_ABORT("Failed to enqueue timeout event (%d)\n", rc);
	}
}

static inline uint64_t timer_pool_scan(timer_pool_t *tp, uint64_t tick)
{
	tick_buf_t *array = &tp->tick_buf[0];
	uint32_t high_wm = odp_atomic_load_acq_u32(&tp->high_wm);
	uint32_t i;
	uint64_t min = UINT64_MAX;

	_ODP_ASSERT(high_wm <= tp->param.num_timers);
	for (i = 0; i < high_wm; i++) {
		/* As a rare occurrence, we can outsmart the HW prefetcher
		 * and the compiler (GCC -fprefetch-loop-arrays) with some
		 * tuned manual prefetching (32x16=512B ahead), seems to
		 * give 30% better performance on ARM C-A15 */
		__builtin_prefetch(&array[i + 32], 0, 0);
		/* Non-atomic read for speed */
		uint64_t exp_tck = array[i].exp_tck.v;

		if (odp_unlikely(exp_tck <= tick)) {
			/* Attempt to expire timer */
			timer_expire(tp, i, tick);
			min = 0;
		} else {
			min = _ODP_MIN(min, exp_tck - tick);
		}
	}

	return min;
}

/******************************************************************************
 * Inline timer processing
 *****************************************************************************/

static inline uint64_t timer_pool_scan_inline(int num, odp_time_t now, int force)
{
	timer_pool_t *tp;
	uint64_t new_tick, old_tick, ticks_to_next_expire, nsec, min = UINT64_MAX;
	int64_t diff;
	int i;

	for (i = 0; i < num; i++) {
		tp = timer_global->timer_pool[i];

		if (tp == NULL)
			continue;

		if (odp_likely(tp->owner < 0)) {
			/* Skip shared pool, if this thread is not configured
			 * to process those */
			if (odp_unlikely(timer_local.poll_shared == 0))
				continue;
		} else {
			/* Skip private pool, if this thread is not the owner */
			if (tp->owner != odp_thread_id())
				continue;
		}

		nsec     = odp_time_to_ns(now);
		new_tick = nsec / tp->nsec_per_scan;
		old_tick = odp_atomic_load_u64(&tp->cur_tick);
		diff = new_tick - old_tick;

		if (diff < 1 && !force)
			continue;

		if (odp_atomic_cas_u64(&tp->cur_tick, &old_tick, new_tick)) {
			if (ODP_DEBUG_PRINT && odp_atomic_load_u32(&tp->notify_overrun) == 1 &&
			    diff > 1) {
				if (old_tick == 0) {
					_ODP_DBG("Timer pool (%s) missed %" PRIi64 " scans in start up\n",
						 tp->name, diff - 1);
				} else {
					_ODP_DBG("Timer pool (%s) resolution too high: %" PRIi64 " scans missed\n",
						 tp->name, diff - 1);
					odp_atomic_store_u32(&tp->notify_overrun, 2);
				}
			}
			ticks_to_next_expire = timer_pool_scan(tp, nsec);
			min = _ODP_MIN(min, ticks_to_next_expire);
		}
	}

	return min;
}

uint64_t _odp_timer_run_inline(int dec)
{
	odp_time_t now;
	int num = timer_global->highest_tp_idx + 1;
	int force = (dec == TIMER_SCAN_FORCE);
	int poll_interval = force ? 0 : timer_global->poll_interval;

	if (num == 0)
		return UINT64_MAX;

	/* Rate limit how often this thread checks the timer pools. */

	if (poll_interval > 1) {
		timer_local.run_cnt -= dec;
		if (timer_local.run_cnt > 0)
			return UINT64_MAX;
		timer_local.run_cnt = poll_interval;
	}

	now = odp_time_global();

	if (poll_interval > 1) {
		odp_time_t period = odp_time_diff(now, timer_local.last_run);

		if (odp_time_cmp(period,
				 timer_global->poll_interval_time) < 0)
			return UINT64_MAX;
		timer_local.last_run = now;
	}

	if (force) {
		timer_local.run_cnt = poll_interval;
		timer_local.last_run = now;
	}

	/* Check the timer pools. */
	if (CONFIG_TIMER_PROFILE_INLINE) {
		odp_time_t t1 = odp_time_local_strict();

		uint64_t ret = timer_pool_scan_inline(num, now, force);
		odp_time_t t2 = odp_time_local_strict();

		timer_local.prof_nsec += odp_time_diff_ns(t2, t1);
		timer_local.prof_rounds++;
		return ret;
	} else {
		return timer_pool_scan_inline(num, now, force);
	}
}

/******************************************************************************
 * POSIX timer support
 * Functions that use Linux/POSIX per-process timers and related facilities
 *****************************************************************************/

static inline void timer_run_posix(timer_pool_t *tp)
{
	uint64_t nsec;
	int overrun;

	if (ODP_DEBUG_PRINT && odp_atomic_load_u32(&tp->notify_overrun) == 1) {
		overrun = timer_getoverrun(tp->timerid);
		if (overrun) {
			_ODP_DBG("\n\t%d ticks overrun on timer pool \"%s\", timer resolution too high\n",
				 overrun, tp->name);
			odp_atomic_store_u32(&tp->notify_overrun, 2);
		}
	}

	_odp_timer_t *array = &tp->timers[0];
	uint32_t i;
	/* Prefetch initial cache lines (match 32 above) */
	for (i = 0; i < 32; i += ODP_CACHE_LINE_SIZE / sizeof(array[0]))
		__builtin_prefetch(&array[i], 0, 0);

	nsec = odp_time_global_ns();
	timer_pool_scan(tp, nsec);
}

static void *timer_thread(void *arg)
{
	timer_pool_t *tp = (timer_pool_t *)arg;
	sigset_t sigset;
	int ret;
	struct timespec tmo;
	siginfo_t si;
	int warm_up = tp->thr_warm_up;
	int num = 0;
	pid_t thr_pid;

	tmo.tv_sec  = 0;
	tmo.tv_nsec = ODP_TIME_MSEC_IN_NS * 100;

	/* Unblock sigalarm in this thread */
	sigemptyset(&sigset);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	sigaddset(&sigset, SIGALRM);

	/* Signal that this thread has started */
	thr_pid = (pid_t)syscall(SYS_gettid);
	if (thr_pid <= 0) {
		_ODP_ERR("Invalid tid: %d\n", thr_pid);
		return NULL;
	}
	odp_atomic_store_u64(&tp->thr_pid, thr_pid);

	while (1) {
		ret = sigtimedwait(&sigset, &si, &tmo);

		if (odp_atomic_load_u32(&tp->thr_exit)) {
			odp_atomic_store_u64(&tp->thr_pid, 0);
			return NULL;
		}

		if (ret <= 0)
			continue;

		timer_run_posix(tp);

		if (num < warm_up) {
			num++;

			if (num == warm_up)
				odp_atomic_store_rel_u32(&tp->thr_ready, 1);
		}
	}

	return NULL;
}

/* Get the max timer resolution without overrun and fill in timer_res variable.
 *
 * Set timer's interval with candidate resolutions to get the max resolution
 * that the timer would not be overrun.
 * The candidate resolution value is from 1ms to 100us, 10us...1ns etc.
 */
static int timer_res_init(void)
{
	struct sigevent sigev;
	timer_t timerid;
	uint64_t res, sec, nsec;
	struct itimerspec ispec;
	sigset_t sigset;
	siginfo_t si;
	int loop_cnt;
	struct timespec tmo;

	sigev.sigev_notify = SIGEV_THREAD_ID;
	sigev._sigev_un._tid = (pid_t)syscall(SYS_gettid);
	sigev.sigev_value.sival_ptr = NULL;
	sigev.sigev_signo = SIGUSR1;

	/* Create timer */
	if (timer_create(CLOCK_MONOTONIC, &sigev, &timerid))
		_ODP_ABORT("timer_create() returned error %s\n", strerror(errno));

	/* Timer resolution start from 1ms */
	res = ODP_TIME_MSEC_IN_NS;
	/* Set initial value of timer_res */
	timer_global->highest_res_ns = res;
	sigemptyset(&sigset);
	/* Add SIGUSR1 to sigset */
	sigaddset(&sigset, SIGUSR1);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	while (res > 0) {
		/* Loop for 10 times to test the result */
		loop_cnt = TIMER_RES_TEST_LOOP_COUNT;
		sec  = res / ODP_TIME_SEC_IN_NS;
		nsec = res - sec * ODP_TIME_SEC_IN_NS;

		memset(&ispec, 0, sizeof(ispec));
		ispec.it_interval.tv_sec  = (time_t)sec;
		ispec.it_interval.tv_nsec = (long)nsec;
		ispec.it_value.tv_sec     = (time_t)sec;
		ispec.it_value.tv_nsec    = (long)nsec;

		if (timer_settime(timerid, 0, &ispec, NULL))
			_ODP_ABORT("timer_settime() returned error %s\n", strerror(errno));
		/* Set signal wait timeout to 10*res */
		tmo.tv_sec = 0;
		tmo.tv_nsec = res * 10;
		while (loop_cnt--) {
			if (sigtimedwait(&sigset, &si, &tmo) > 0) {
				if (timer_getoverrun(timerid))
					/* overrun at this resolution */
					/* goto the end */
					goto timer_res_init_done;
			}
		}
		/* Set timer_res */
		timer_global->highest_res_ns = res;
		/* Test the next timer resolution candidate */
		res /= 10;
	}

timer_res_init_done:
	timer_global->highest_res_ns *= TIMER_RES_ROUNDUP_FACTOR;
	if (timer_delete(timerid) != 0)
		_ODP_ABORT("timer_delete() returned error %s\n", strerror(errno));
	sigemptyset(&sigset);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	return 0;
}

static void posix_timer_start(timer_pool_t *tp)
{
	struct sigevent   sigev;
	struct itimerspec ispec;
	uint64_t res, sec, nsec;
	int ret;

	_ODP_DBG("Creating POSIX timer for timer pool %s, period %" PRIu64 " ns\n",
		 tp->name, tp->param.res_ns);

	res  = tp->param.res_ns;
	sec  = res / ODP_TIME_SEC_IN_NS;
	nsec = res - sec * ODP_TIME_SEC_IN_NS;

	odp_atomic_init_u64(&tp->thr_pid, 0);
	tp->thr_warm_up = 1;

	/* 20ms warm up */
	if (res < (20 * ODP_TIME_MSEC_IN_NS))
		tp->thr_warm_up = (20 * ODP_TIME_MSEC_IN_NS) / res;

	odp_atomic_init_u32(&tp->thr_ready, 0);
	ret = pthread_create(&tp->thr_pthread, NULL, timer_thread, tp);
	if (ret)
		_ODP_ABORT("Unable to create timer thread: %d\n", ret);

	/* wait thread set tp->thr_pid */
	while (!odp_atomic_load_u64(&tp->thr_pid))
		odp_cpu_pause();

	memset(&sigev, 0, sizeof(sigev));
	sigev.sigev_notify          = SIGEV_THREAD_ID;
	sigev.sigev_value.sival_ptr = tp;
	sigev._sigev_un._tid = odp_atomic_load_u64(&tp->thr_pid);
	sigev.sigev_signo = SIGALRM;

	if (timer_create(CLOCK_MONOTONIC, &sigev, &tp->timerid))
		_ODP_ABORT("timer_create() returned error %s\n", strerror(errno));

	memset(&ispec, 0, sizeof(ispec));
	ispec.it_interval.tv_sec  = (time_t)sec;
	ispec.it_interval.tv_nsec = (long)nsec;
	ispec.it_value.tv_sec     = (time_t)sec;
	ispec.it_value.tv_nsec    = (long)nsec;

	if (timer_settime(tp->timerid, 0, &ispec, NULL))
		_ODP_ABORT("timer_settime() returned error %s\n", strerror(errno));

	/* Wait response from timer thread that warm up signals have been
	 * processed. Warm up helps avoiding overrun on the first timeout. */
	while (odp_atomic_load_acq_u32(&tp->thr_ready) == 0)
		odp_cpu_pause();

	if (ODP_DEBUG_PRINT) {
		uint32_t old_val = 0;

		odp_atomic_cas_u32(&tp->notify_overrun, &old_val, 1);
	}
}

static odp_timer_pool_t timer_pool_new(const char *name, const odp_timer_pool_param_t *param)
{
	uint32_t i;
	int tp_idx;
	size_t sz0, sz1, sz2;
	uint64_t tp_size;
	uint64_t res_ns, nsec_per_scan;
	odp_shm_t shm;
	timer_pool_t *tp;
	odp_time_t diff, time;
	odp_time_t max_diff = ODP_TIME_NULL;
	double base_freq = 0.0;
	uint64_t max_multiplier = 0;
	uint32_t flags = 0;
	int periodic = (param->timer_type == ODP_TIMER_TYPE_PERIODIC) ? 1 : 0;

	if (param->res_ns)
		res_ns = param->res_ns;
	else
		res_ns = GIGA_HZ / param->res_hz;

	if (periodic) {
		uint64_t max_capa, min_period_ns;

		base_freq = odp_fract_u64_to_dbl(&param->periodic.base_freq_hz);
		max_multiplier = param->periodic.max_multiplier;

		if (base_freq < MIN_BASE_HZ || base_freq > timer_global->max_base_hz) {
			_ODP_ERR("Bad base frequency: %f\n", base_freq);
			return ODP_TIMER_POOL_INVALID;
		}

		max_capa = max_multiplier_capa(base_freq);

		if (max_multiplier == 0 || max_multiplier > max_capa) {
			_ODP_ERR("Bad max multiplier: %" PRIu64 "\n", max_multiplier);
			return ODP_TIMER_POOL_INVALID;
		}

		min_period_ns = GIGA_HZ / (base_freq * max_multiplier);

		if (res_ns > min_period_ns)
			res_ns = min_period_ns;
	}

	if (odp_global_ro.shm_single_va)
		flags |= ODP_SHM_SINGLE_VA;

	time = odp_time_global();

	odp_ticketlock_lock(&timer_global->lock);

	if (timer_global->num_timer_pools >= MAX_TIMER_POOLS) {
		odp_ticketlock_unlock(&timer_global->lock);
		_ODP_DBG("No more free timer pools\n");
		return ODP_TIMER_POOL_INVALID;
	}

	/* Find timer pool that has not been used for a while, or is used least recently.
	 * This ensures that inline scan of an old timer pool has completed and its memory
	 * can be freed. */
	tp_idx = -1;
	for (i = 0; i < MAX_TIMER_POOLS; i++) {
		if (timer_global->timer_pool_used[i] == 0) {
			diff = odp_time_diff(time, timer_global->destroy_time[i]);

			if (odp_time_to_ns(diff) > TIMER_POOL_REUSE_NS) {
				tp_idx = i;
				break;
			}

			if (odp_time_cmp(diff, max_diff) > 0) {
				max_diff = diff;
				tp_idx = i;
			}
		}
	}

	if (tp_idx < 0) {
		odp_ticketlock_unlock(&timer_global->lock);
		_ODP_DBG("Did not find free timer pool\n");
		return ODP_TIMER_POOL_INVALID;
	}

	shm = timer_global->tp_shm[tp_idx];
	timer_global->timer_pool_used[tp_idx] = 1;
	timer_global->num_timer_pools++;

	odp_ticketlock_unlock(&timer_global->lock);

	/* Free memory of previously destroyed timer pool */
	if (shm != ODP_SHM_INVALID) {
		if (odp_shm_free(shm)) {
			_ODP_ERR("Failed to free shared memory: tp_idx %i\n", tp_idx);
			goto error;
		}
	}

	sz0 = _ODP_ROUNDUP_CACHE_LINE(sizeof(timer_pool_t));
	sz1 = _ODP_ROUNDUP_CACHE_LINE(sizeof(tick_buf_t) * param->num_timers);
	sz2 = _ODP_ROUNDUP_CACHE_LINE(sizeof(_odp_timer_t) * param->num_timers);
	tp_size = sz0 + sz1 + sz2;

	shm = odp_shm_reserve(name, tp_size, ODP_CACHE_LINE_SIZE, flags);

	if (odp_unlikely(shm == ODP_SHM_INVALID)) {
		_ODP_ERR("Timer pool shm reserve failed %" PRIu64 "kB\n", tp_size / 1024);
		goto error;
	}

	tp = (timer_pool_t *)odp_shm_addr(shm);
	memset(tp, 0, tp_size);

	tp->periodic = periodic;

	/* Scan timer pool twice during resolution interval */
	if (res_ns > ODP_TIME_USEC_IN_NS)
		nsec_per_scan = res_ns / 2;
	else
		nsec_per_scan = res_ns;

	tp->nsec_per_scan = nsec_per_scan;

	odp_atomic_init_u64(&tp->cur_tick, 0);

	if (name == NULL)
		tp->name[0] = 0;
	else
		_odp_strcpy(tp->name, name, ODP_TIMER_POOL_NAME_LEN);

	tp->param = *param;
	tp->param.res_ns = res_ns;
	if (periodic) {
		tp->base_freq = base_freq;
		tp->max_multiplier = max_multiplier;
	} else {
		tp->min_rel_tck = odp_timer_ns_to_tick(timer_pool_to_hdl(tp), param->min_tmo);
		tp->max_rel_tck = odp_timer_ns_to_tick(timer_pool_to_hdl(tp), param->max_tmo);
	}
	tp->num_alloc = 0;
	odp_atomic_init_u32(&tp->high_wm, 0);
	odp_atomic_init_u32(&tp->notify_overrun, 0);
	odp_atomic_init_u32(&tp->thr_exit, 0);
	tp->first_free = 0;
	tp->owner = -1;

	if (param->priv)
		tp->owner = odp_thread_id();

	tp->tick_buf = (void *)((char *)odp_shm_addr(shm) + sz0);
	tp->timers = (void *)((char *)odp_shm_addr(shm) + sz0 + sz1);

#if !USE_128BIT_ATOMICS
	for (i = 0; i < NUM_LOCKS; i++)
		_odp_atomic_flag_clear(&tp->locks[i]);
#endif

	/* Initialize all odp_timer entries */
	for (i = 0; i < tp->param.num_timers; i++) {
		tp->timers[i].queue = ODP_QUEUE_INVALID;
		set_next_free(&tp->timers[i], i + 1);
		tp->timers[i].user_ptr = NULL;
		odp_atomic_init_u64(&tp->tick_buf[i].exp_tck, TMO_UNUSED);
		tp->tick_buf[i].tmo_event = ODP_EVENT_INVALID;
	}
	tp->tp_idx = tp_idx;
	odp_spinlock_init(&tp->lock);

	odp_ticketlock_lock(&timer_global->lock);

	/* Inline timer scan may find the timer pool after this */
	odp_mb_release();
	timer_global->timer_pool[tp_idx] = tp;
	timer_global->tp_shm[tp_idx] = shm;

	/* Enable inline timer polling */
	if (timer_global->use_inline_timers)
		odp_global_rw->inline_timers = true;

	/* Increase poll rate to match the highest resolution */
	if (timer_global->poll_interval_nsec > nsec_per_scan) {
		timer_global->poll_interval_nsec = nsec_per_scan;
		timer_global->poll_interval_time =
			odp_time_global_from_ns(nsec_per_scan);
	}

	/* Update the highest index for inline timer scan */
	if (tp_idx > timer_global->highest_tp_idx)
		timer_global->highest_tp_idx = tp_idx;

	odp_ticketlock_unlock(&timer_global->lock);

	if (!timer_global->use_inline_timers)
		posix_timer_start(tp);

	return timer_pool_to_hdl(tp);

error:
	odp_ticketlock_lock(&timer_global->lock);
	timer_global->tp_shm[tp_idx] = shm;
	timer_global->timer_pool_used[tp_idx] = 0;
	timer_global->num_timer_pools--;
	odp_ticketlock_unlock(&timer_global->lock);

	return ODP_TIMER_POOL_INVALID;
}

/******************************************************************************
 * Public API functions
 * Some parameter checks and error messages
 * No modificatios of internal state
 *****************************************************************************/
int odp_timer_capability(odp_timer_clk_src_t clk_src,
			 odp_timer_capability_t *capa)
{
	if (clk_src != ODP_CLOCK_DEFAULT) {
		_ODP_DBG("Only ODP_CLOCK_DEFAULT supported. Requested %i.\n", clk_src);
		return -1;
	}

	memset(capa, 0, sizeof(odp_timer_capability_t));

	capa->max_pools_combined = MAX_TIMER_POOLS;
	capa->max_pools = MAX_TIMER_POOLS;
	capa->max_timers = 0;
	capa->periodic.max_pools  = MAX_TIMER_POOLS;
	capa->periodic.max_timers = MAX_PERIODIC_TIMERS;
	capa->highest_res_ns  = timer_global->highest_res_ns;
	capa->max_res.res_ns  = timer_global->highest_res_ns;
	capa->max_res.res_hz  = timer_global->highest_res_hz;
	capa->max_res.min_tmo = 0;
	capa->max_res.max_tmo = MAX_TMO_NSEC;
	capa->max_tmo.res_ns  = timer_global->highest_res_ns;
	capa->max_tmo.res_hz  = timer_global->highest_res_hz;
	capa->max_tmo.min_tmo = 0;
	capa->max_tmo.max_tmo = MAX_TMO_NSEC;
	capa->queue_type_sched = true;
	capa->queue_type_plain = true;

	capa->periodic.min_base_freq_hz.integer = MIN_BASE_HZ;
	capa->periodic.max_base_freq_hz.integer = timer_global->max_base_hz;

	return 0;
}

int odp_timer_res_capability(odp_timer_clk_src_t clk_src,
			     odp_timer_res_capability_t *res_capa)
{
	if (clk_src != ODP_CLOCK_DEFAULT) {
		_ODP_ERR("Only ODP_CLOCK_DEFAULT supported. Requested %i.\n", clk_src);
		return -1;
	}

	if (res_capa->min_tmo) {
		_ODP_ERR("Only res_ns or max_tmo based queries supported\n");
		return -1;
	}

	if (res_capa->res_ns || res_capa->res_hz) {
		if (res_capa->res_ns && res_capa->res_ns < timer_global->highest_res_ns) {
			_ODP_DBG("Timeout resolution capability (res_ns) exceeded\n");
			return -1;
		}
		if (res_capa->res_hz && res_capa->res_hz > timer_global->highest_res_hz) {
			_ODP_DBG("Timeout resolution capability (res_hz) exceeded\n");
			return -1;
		}
		res_capa->min_tmo = 0;
		res_capa->max_tmo = MAX_TMO_NSEC;
	} else { /* max_tmo */
		if (res_capa->max_tmo > MAX_TMO_NSEC) {
			_ODP_DBG("Maximum relative timeout capability (max_tmo) exceeded\n");
			return -1;
		}
		res_capa->min_tmo = 0;
		res_capa->res_ns  = timer_global->highest_res_ns;
		res_capa->res_hz  = timer_global->highest_res_hz;
	}

	return 0;
}

int odp_timer_periodic_capability(odp_timer_clk_src_t clk_src,
				  odp_timer_periodic_capability_t *capa)
{
	double freq;
	uint64_t multiplier;

	if (clk_src != ODP_CLOCK_DEFAULT) {
		_ODP_ERR("Only ODP_CLOCK_DEFAULT supported. Requested %i.\n", clk_src);
		return -1;
	}

	freq = odp_fract_u64_to_dbl(&capa->base_freq_hz);
	if (freq < MIN_BASE_HZ || freq > timer_global->max_base_hz) {
		_ODP_ERR("Base frequency not supported (min: %f, max %f)\n",
			 (double)MIN_BASE_HZ, (double)timer_global->max_base_hz);
		return -1;
	}

	multiplier = max_multiplier_capa(freq);

	if (capa->max_multiplier > multiplier)
		return -1;

	if (capa->res_ns && capa->res_ns < timer_global->highest_res_ns)
		return -1;

	/* Update capa with supported values */
	capa->max_multiplier = multiplier;
	capa->res_ns = timer_global->highest_res_ns;

	/* All base frequencies within the range are supported */
	return 1;
}

void odp_timer_pool_param_init(odp_timer_pool_param_t *param)
{
	memset(param, 0, sizeof(odp_timer_pool_param_t));
	param->timer_type = ODP_TIMER_TYPE_SINGLE;
	param->clk_src = ODP_CLOCK_DEFAULT;
	param->exp_mode = ODP_TIMER_EXP_AFTER;
}

odp_timer_pool_t odp_timer_pool_create(const char *name,
				       const odp_timer_pool_param_t *param)
{
	if (odp_global_ro.init_param.not_used.feat.timer) {
		_ODP_ERR("Trying to use disabled ODP feature.\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->clk_src != ODP_CLOCK_DEFAULT) {
		_ODP_ERR("Only ODP_CLOCK_DEFAULT supported. Requested %i.\n", param->clk_src);
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->timer_type != ODP_TIMER_TYPE_SINGLE &&
	    param->timer_type != ODP_TIMER_TYPE_PERIODIC) {
		_ODP_ERR("Bad timer type %i\n", param->timer_type);
		return ODP_TIMER_POOL_INVALID;
	}

	if ((param->res_ns && param->res_hz) || (param->res_ns == 0 && param->res_hz == 0))
		return ODP_TIMER_POOL_INVALID;

	if (param->res_hz == 0 && param->res_ns < timer_global->highest_res_ns)
		return ODP_TIMER_POOL_INVALID;

	if (param->res_ns == 0 && param->res_hz > timer_global->highest_res_hz)
		return ODP_TIMER_POOL_INVALID;

	if (param->priority > 0) {
		_ODP_ERR("Only default timer pool priority supported.\n");
		return ODP_TIMER_POOL_INVALID;
	}

	return timer_pool_new(name, param);
}

int odp_timer_pool_start_multi(odp_timer_pool_t timer_pool[], int num)
{
	_ODP_ASSERT(timer_pool != NULL);
	_ODP_ASSERT(num > 0);
	if (ODP_DEBUG) {
		for (int i = 0; i < num; i++)
			_ODP_ASSERT(timer_pool[i] != ODP_TIMER_POOL_INVALID);
	}

	/* Nothing to do here, timer pools are started by the create call. */
	return num;
}

void odp_timer_pool_destroy(odp_timer_pool_t tpid)
{
	odp_timer_pool_del(timer_pool_from_hdl(tpid));
}

int odp_timer_sample_ticks(odp_timer_pool_t timer_pool[], uint64_t tick[], uint64_t clk_count[],
			   int num)
{
	uint64_t nsec;
	int i;

	if (num <= 0 || num > MAX_TIMER_POOLS) {
		_ODP_ERR("Bad number of timer pools: %i\n", num);
		return -1;
	}

	for (i = 0; i < num; i++) {
		if (odp_unlikely(timer_pool[i] == ODP_TIMER_POOL_INVALID)) {
			_ODP_ERR("Invalid timer pool\n");
			return -1;
		}
	}

	nsec = odp_time_global_ns();

	for (i = 0; i < num; i++) {
		tick[i] = nsec;

		if (clk_count)
			clk_count[i] = tick[i];
	}

	return 0;
}

int odp_timer_pool_info(odp_timer_pool_t tpid, odp_timer_pool_info_t *tp_info)
{
	timer_pool_t *tp;

	if (odp_unlikely(tpid == ODP_TIMER_POOL_INVALID)) {
		_ODP_ERR("Invalid timer pool.\n");
		return -1;
	}

	tp = timer_pool_from_hdl(tpid);

	memset(tp_info, 0, sizeof(odp_timer_pool_info_t));
	tp_info->param = tp->param;
	tp_info->cur_timers = tp->num_alloc;
	tp_info->hwm_timers = odp_atomic_load_u32(&tp->high_wm);
	tp_info->name = tp->name;

	/* One API timer tick is one nsec. Leave source clock information to zero
	 * as there is no direct link between a source clock signal and a timer tick. */
	tp_info->tick_info.freq.integer = ODP_TIME_SEC_IN_NS;
	tp_info->tick_info.nsec.integer = 1;

	return 0;
}

uint64_t odp_timer_pool_to_u64(odp_timer_pool_t tpid)
{
	return _odp_pri(tpid);
}

odp_timer_t odp_timer_alloc(odp_timer_pool_t tpid, odp_queue_t queue, const void *user_ptr)
{
	timer_pool_t *tp = timer_pool_from_hdl(tpid);

	if (odp_unlikely(tpid == ODP_TIMER_POOL_INVALID)) {
		_ODP_ERR("Invalid timer pool.\n");
		return ODP_TIMER_INVALID;
	}

	if (odp_unlikely(queue == ODP_QUEUE_INVALID)) {
		_ODP_ERR("%s: Invalid queue handle\n", tp->name);
		return ODP_TIMER_INVALID;
	}
	/* We don't care about the validity of user_ptr because we will not
	 * attempt to dereference it */
	return timer_alloc(tp, queue, user_ptr);
}

int odp_timer_start(odp_timer_t timer, const odp_timer_start_t *start_param)
{
	uint64_t abs_tick, rel_tick;
	timer_pool_t *tp = handle_to_tp(timer);
	uint64_t cur_tick = odp_time_global_ns();
	uint32_t idx = handle_to_idx(timer, tp);
	odp_event_t tmo_ev = start_param->tmo_ev;

	if (start_param->tick_type == ODP_TIMER_TICK_ABS) {
		abs_tick = start_param->tick;
		rel_tick = abs_tick - cur_tick;

		if (odp_unlikely(abs_tick < cur_tick + tp->min_rel_tck))
			return ODP_TIMER_TOO_NEAR;
	} else {
		rel_tick = start_param->tick;
		abs_tick = rel_tick + cur_tick;

		if (odp_unlikely(rel_tick < tp->min_rel_tck))
			return ODP_TIMER_TOO_NEAR;
	}

	if (odp_unlikely(rel_tick > tp->max_rel_tck))
		return ODP_TIMER_TOO_FAR;

	if (!timer_reset(idx, abs_tick, &tmo_ev, tp))
		return ODP_TIMER_FAIL;

	/* Check that timer was not active */
	if (odp_unlikely(tmo_ev != ODP_EVENT_INVALID)) {
		_ODP_ERR("Timer was active already\n");
		odp_event_free(tmo_ev);
	}

	if (ODP_DEBUG_PRINT) {
		uint32_t old_val = 0;

		odp_atomic_cas_u32(&tp->notify_overrun, &old_val, 1);
	}

	return ODP_TIMER_SUCCESS;
}

int odp_timer_restart(odp_timer_t timer, const odp_timer_start_t *start_param)
{
	uint64_t abs_tick, rel_tick;
	timer_pool_t *tp = handle_to_tp(timer);
	uint64_t cur_tick = odp_time_global_ns();
	uint32_t idx = handle_to_idx(timer, tp);

	if (start_param->tick_type == ODP_TIMER_TICK_ABS) {
		abs_tick = start_param->tick;
		rel_tick = abs_tick - cur_tick;

		if (odp_unlikely(abs_tick < cur_tick + tp->min_rel_tck))
			return ODP_TIMER_TOO_NEAR;
	} else {
		rel_tick = start_param->tick;
		abs_tick = rel_tick + cur_tick;

		if (odp_unlikely(rel_tick < tp->min_rel_tck))
			return ODP_TIMER_TOO_NEAR;
	}

	if (odp_unlikely(rel_tick > tp->max_rel_tck))
		return ODP_TIMER_TOO_FAR;

	/* Reset timer without changing the event */
	if (!timer_reset(idx, abs_tick, NULL, tp))
		return ODP_TIMER_FAIL;

	return ODP_TIMER_SUCCESS;
}

int odp_timer_periodic_start(odp_timer_t timer, const odp_timer_periodic_start_t *start_param)
{
	uint64_t abs_tick, period_ns;
	timer_pool_t *tp = handle_to_tp(timer);
	uint64_t cur_tick = odp_time_global_ns();
	uint32_t idx = handle_to_idx(timer, tp);
	odp_event_t tmo_ev = start_param->tmo_ev;
	_odp_timer_t *tim = &tp->timers[idx];
	uint64_t multiplier = start_param->freq_multiplier;
	double freq = multiplier * tp->base_freq;
	double period_ns_dbl;

	if (odp_unlikely(!tp->periodic)) {
		_ODP_ERR("Not a periodic timer\n");
		return ODP_TIMER_FAIL;
	}

	if (odp_unlikely(multiplier == 0 || multiplier > tp->max_multiplier)) {
		_ODP_ERR("Bad frequency multiplier: %" PRIu64 "\n", multiplier);
		return ODP_TIMER_FAIL;
	}

	if (odp_unlikely(odp_event_type(tmo_ev) != ODP_EVENT_TIMEOUT)) {
		_ODP_ERR("Event type is not timeout\n");
		return ODP_TIMER_FAIL;
	}

	period_ns_dbl = (double)ODP_TIME_SEC_IN_NS / freq;
	period_ns = period_ns_dbl;

	if (period_ns == 0) {
		_ODP_ERR("Too high periodic timer frequency: %f\n", freq);
		return ODP_TIMER_FAIL;
	}

	if (period_ns & PERIODIC_CANCELLED) {
		_ODP_ERR("Periodic timer frequency error: %f\n", freq);
		return ODP_TIMER_FAIL;
	}

	tim->periodic_ticks = period_ns;
	tim->periodic_ticks_frac = (period_ns_dbl - period_ns) * ACC_SIZE;
	tim->periodic_ticks_frac_acc = 0;
	abs_tick = start_param->first_tick;

	if (abs_tick) {
		if (odp_unlikely(abs_tick < cur_tick))
			return ODP_TIMER_TOO_NEAR;

		if (odp_unlikely(abs_tick > cur_tick + tim->periodic_ticks))
			return ODP_TIMER_TOO_FAR;
	} else {
		abs_tick = cur_tick + tim->periodic_ticks;
	}

	if (!timer_reset(idx, abs_tick, &tmo_ev, tp))
		return ODP_TIMER_FAIL;

	/* Check that timer was not active */
	if (odp_unlikely(tmo_ev != ODP_EVENT_INVALID)) {
		_ODP_ERR("Timer was active already\n");
		odp_event_free(tmo_ev);
	}

	return ODP_TIMER_SUCCESS;
}

int odp_timer_periodic_ack(odp_timer_t timer, odp_event_t tmo_ev)
{
	uint64_t abs_tick, acc;
	odp_timeout_t tmo = odp_timeout_from_event(tmo_ev);
	timer_pool_t *tp = handle_to_tp(timer);
	uint32_t idx = handle_to_idx(timer, tp);
	_odp_timer_t *tim = &tp->timers[idx];

	if (odp_unlikely(odp_event_type(tmo_ev) != ODP_EVENT_TIMEOUT)) {
		_ODP_ERR("Event type is not timeout\n");
		return -1;
	}

	abs_tick = tim->periodic_ticks;

	if (odp_unlikely(abs_tick & PERIODIC_CANCELLED)) {
		/* Timer was tried to cancel earlier, stop now. */
		return 2;
	}

	acc = (uint64_t)tim->periodic_ticks_frac_acc + (uint64_t)tim->periodic_ticks_frac;

	if (acc >= ACC_SIZE) {
		abs_tick++;
		acc -= ACC_SIZE;
	}

	tim->periodic_ticks_frac_acc = acc;
	abs_tick += odp_timeout_tick(tmo);

	if (!timer_reset(idx, abs_tick, &tmo_ev, tp))
		return -1;

	/* This should never happen. Timer should be always inactive before
	 * timer_reset() call above. */
	if (odp_unlikely(tmo_ev != ODP_EVENT_INVALID)) {
		/* Reset returned an event, free it. */
		_ODP_ERR("Timer was active already\n");
		odp_event_free(tmo_ev);
	}

	return 0;
}

int odp_timer_cancel(odp_timer_t hdl, odp_event_t *tmo_ev)
{
	timer_pool_t *tp = handle_to_tp(hdl);
	uint32_t idx = handle_to_idx(hdl, tp);
	/* Set the expiration tick of the timer to TMO_INACTIVE */
	odp_event_t old_event = timer_cancel(tp, idx);

	if (old_event != ODP_EVENT_INVALID) {
		/* Active timer cancelled, timeout returned */
		*tmo_ev = old_event;
		return ODP_TIMER_SUCCESS;
	}

	/* Timer already expired, no timeout returned */
	return ODP_TIMER_TOO_NEAR;
}

int odp_timer_periodic_cancel(odp_timer_t hdl)
{
	timer_pool_t *tp;
	uint32_t idx;
	_odp_timer_t *tim;
	odp_event_t ev;

	if (odp_unlikely(hdl == ODP_TIMER_INVALID)) {
		_ODP_ERR("Bad timer pool handle\n");
		return -1;
	}

	tp = handle_to_tp(hdl);

	if (odp_unlikely(tp->periodic == 0)) {
		_ODP_ERR("Not a periodic timer\n");
		return -1;
	}

	idx = handle_to_idx(hdl, tp);
	tim = &tp->timers[idx];
	ev  = timer_cancel(tp, idx);

	/* Cancel failed on a periodic timer. Mark timer cancelled, so that
	 * a following ack call stops restarting it. */
	tim->periodic_ticks |= PERIODIC_CANCELLED;

	if (ev != ODP_EVENT_INVALID) {
		/* Timer cancelled and timeout returned. Enqueue tmo, ack call will flag
		 * it as the last event. */
		if (odp_unlikely(odp_queue_enq(tim->queue, ev))) {
			_ODP_ERR("Failed to enqueue timeout event\n");
			_odp_event_free(ev);
			return -1;
		}
	}

	return 0;
}

uint64_t odp_timer_to_u64(odp_timer_t hdl)
{
	return _odp_pri(hdl);
}

uint64_t odp_timeout_to_u64(odp_timeout_t tmo)
{
	return _odp_pri(tmo);
}

odp_timeout_t odp_timeout_alloc(odp_pool_t pool_hdl)
{
	odp_timeout_hdr_t *hdr;
	odp_event_t event;
	pool_t *pool;

	_ODP_ASSERT(pool_hdl != ODP_POOL_INVALID);

	pool = _odp_pool_entry(pool_hdl);

	_ODP_ASSERT(pool->type == ODP_POOL_TIMEOUT);

	event = _odp_event_alloc(pool);
	if (odp_unlikely(event == ODP_EVENT_INVALID))
		return ODP_TIMEOUT_INVALID;

	hdr = timeout_hdr_from_event(event);
	hdr->timer = ODP_TIMER_INVALID;

	return odp_timeout_from_event(event);
}

int odp_timeout_alloc_multi(odp_pool_t pool_hdl, odp_timeout_t tmo[], int num)
{
	pool_t *pool;
	int ret;

	_ODP_ASSERT(pool_hdl != ODP_POOL_INVALID);
	_ODP_ASSERT(tmo != NULL);
	_ODP_ASSERT(num > 0);

	pool = _odp_pool_entry(pool_hdl);

	_ODP_ASSERT(pool->type == ODP_POOL_TIMEOUT);

	ret = _odp_event_alloc_multi(pool, (_odp_event_hdr_t **)tmo, num);

	for (int i = 0; i < ret; i++)
		timeout_hdr(tmo[i])->timer = ODP_TIMER_INVALID;

	return ret;
}

void odp_timeout_free(odp_timeout_t tmo)
{
	_odp_event_free(odp_timeout_to_event(tmo));
}

void odp_timeout_free_multi(odp_timeout_t tmo[], int num)
{
	_ODP_ASSERT(tmo != NULL);
	_ODP_ASSERT(num > 0);

	_odp_event_free_multi((_odp_event_hdr_t **)(uintptr_t)tmo, num);
}

void odp_timer_pool_print(odp_timer_pool_t timer_pool)
{
	timer_pool_t *tp;
	int len = 0;
	int max_len = 512;
	int n = max_len - 1;
	char str[max_len];

	if (timer_pool == ODP_TIMER_POOL_INVALID) {
		_ODP_ERR("Bad timer pool handle\n");
		return;
	}

	tp = timer_pool_from_hdl(timer_pool);

	len += _odp_snprint(&str[len], n - len, "Timer pool info\n");
	len += _odp_snprint(&str[len], n - len, "---------------\n");
	len += _odp_snprint(&str[len], n - len, "  handle         0x%" PRIx64 "\n",
			    odp_timer_pool_to_u64(timer_pool));
	len += _odp_snprint(&str[len], n - len, "  tp index       %u\n", tp->tp_idx);
	len += _odp_snprint(&str[len], n - len, "  num timers     %u\n", tp->num_alloc);
	len += _odp_snprint(&str[len], n - len, "  num tp         %i\n",
			    timer_global->num_timer_pools);
	len += _odp_snprint(&str[len], n - len, "  inline timers  %i\n",
			    timer_global->use_inline_timers);
	len += _odp_snprint(&str[len], n - len, "  periodic       %i\n", tp->periodic);
	str[len] = 0;

	_ODP_PRINT("%s\n", str);
}

void odp_timer_print(odp_timer_t timer)
{
	timer_pool_t *tp;
	uint32_t idx;
	_odp_timer_t *tim;
	int len = 0;
	int max_len = 512;
	int n = max_len - 1;
	char str[max_len];

	if (timer == ODP_TIMER_INVALID) {
		_ODP_ERR("Bad timer handle\n");
		return;
	}

	tp  = handle_to_tp(timer);
	idx = handle_to_idx(timer, tp);
	tim = &tp->timers[idx];

	len += _odp_snprint(&str[len], n - len, "Timer info\n");
	len += _odp_snprint(&str[len], n - len, "----------\n");
	len += _odp_snprint(&str[len], n - len, "  handle         0x%" PRIx64 "\n",
			    odp_timer_to_u64(timer));
	len += _odp_snprint(&str[len], n - len, "  timer pool     0x%" PRIx64 "\n",
			    odp_timer_pool_to_u64(timer_pool_to_hdl(tp)));
	len += _odp_snprint(&str[len], n - len, "  timer index    %u\n", idx);
	len += _odp_snprint(&str[len], n - len, "  dest queue     0x%" PRIx64 "\n",
			    odp_queue_to_u64(tim->queue));
	len += _odp_snprint(&str[len], n - len, "  user ptr       %p\n", tim->user_ptr);
	len += _odp_snprint(&str[len], n - len, "  periodic ticks %" PRIu64 "\n",
			    tim->periodic_ticks & ~PERIODIC_CANCELLED);
	str[len] = 0;

	_ODP_PRINT("%s\n", str);
}

void odp_timeout_print(odp_timeout_t tmo)
{
	const odp_timeout_hdr_t *tmo_hdr;
	odp_timer_t timer;
	int len = 0;
	int max_len = 512;
	int n = max_len - 1;
	char str[max_len];

	if (tmo == ODP_TIMEOUT_INVALID) {
		_ODP_ERR("Bad timeout handle\n");
		return;
	}

	tmo_hdr = timeout_hdr(tmo);
	timer = tmo_hdr->timer;

	len += _odp_snprint(&str[len], n - len, "Timeout info\n");
	len += _odp_snprint(&str[len], n - len, "------------\n");
	len += _odp_snprint(&str[len], n - len, "  handle         0x%" PRIx64 "\n",
			    odp_timeout_to_u64(tmo));
	len += _odp_snprint(&str[len], n - len, "  expiration     %" PRIu64 "\n",
			    tmo_hdr->expiration);
	len += _odp_snprint(&str[len], n - len, "  user ptr       %p\n", tmo_hdr->user_ptr);
	len += _odp_snprint(&str[len], n - len, "  user area      %p\n", tmo_hdr->uarea_addr);

	if (timer != ODP_TIMER_INVALID) {
		timer_pool_t *tp = handle_to_tp(timer);
		uint32_t idx = handle_to_idx(timer, tp);

		len += _odp_snprint(&str[len], n - len, "  timer pool     0x%" PRIx64 "\n",
				    odp_timer_pool_to_u64(timer_pool_to_hdl(tp)));
		len += _odp_snprint(&str[len], n - len, "  timer          0x%" PRIx64 "\n",
				    odp_timer_to_u64(timer));
		len += _odp_snprint(&str[len], n - len, "  timer index    %u\n", idx);
		len += _odp_snprint(&str[len], n - len, "  periodic       %i\n", tp->periodic);
	}
	str[len] = 0;

	_ODP_PRINT("%s\n", str);
}

int _odp_timer_init_global(const odp_init_t *params)
{
	odp_shm_t shm;
	odp_time_t time;
	const char *conf_str;
	uint32_t i;
	int val = 0;

	if (params && params->not_used.feat.timer) {
		_ODP_DBG("Timers disabled\n");
		timer_global = NULL;
		return 0;
	}

	shm = odp_shm_reserve("_odp_timer_global", sizeof(timer_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	timer_global = odp_shm_addr(shm);

	if (timer_global == NULL) {
		_ODP_ERR("Shm reserve failed for odp_timer\n");
		return -1;
	}

	memset(timer_global, 0, sizeof(timer_global_t));
	odp_ticketlock_init(&timer_global->lock);
	timer_global->shm = shm;
	timer_global->highest_res_ns = MAX_INLINE_RES_NS;
	timer_global->highest_tp_idx = -1;

	time = odp_time_global();
	for (i = 0; i < MAX_TIMER_POOLS; i++) {
		timer_global->destroy_time[i] = time;
		timer_global->tp_shm[i] = ODP_SHM_INVALID;
	}

#if USE_128BIT_ATOMICS
	_ODP_PRINT("Timer using lock-less implementation\n");
#else
	_ODP_PRINT("Timer using lock-based implementation\n");
#endif

	_ODP_PRINT("Timer config:\n");

	conf_str =  "timer.inline";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		goto error;
	}
	timer_global->use_inline_timers = val;
	_ODP_PRINT("  %s: %i\n", conf_str, val);

	conf_str =  "timer.inline_poll_interval";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		goto error;
	}
	timer_global->poll_interval = val;
	_ODP_PRINT("  %s: %i\n", conf_str, val);

	conf_str =  "timer.inline_poll_interval_nsec";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		goto error;
	}
	timer_global->poll_interval_nsec = val;
	timer_global->poll_interval_time =
		odp_time_global_from_ns(timer_global->poll_interval_nsec);
	_ODP_PRINT("  %s: %i\n", conf_str, val);

	conf_str =  "timer.inline_thread_type";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		goto error;
	}
	timer_global->thread_type = val;
	_ODP_PRINT("  %s: %i\n", conf_str, val);
	_ODP_PRINT("\n");

	if (!timer_global->use_inline_timers) {
		timer_res_init();
		block_sigalarm();
	}

	/* timer_res_init() may update highest_res_ns */
	timer_global->highest_res_hz = GIGA_HZ / timer_global->highest_res_ns;
	timer_global->max_base_hz    = timer_global->highest_res_hz;

	return 0;

error:
	odp_shm_free(shm);
	return -1;
}

int _odp_timer_term_global(void)
{
	odp_shm_t shm;
	int i;
	int rc = 0;

	if (timer_global == NULL)
		return 0;

	for (i = 0; i < MAX_TIMER_POOLS; i++) {
		shm = timer_global->tp_shm[i];

		if (timer_global->timer_pool_used[i]) {
			_ODP_ERR("Not destroyed timer pool: %i\n", i);
			rc = -1;

			/* Prevent crash from timer thread */
			if (!timer_global->use_inline_timers) {
				timer_pool_t *tp = timer_global->timer_pool[i];

				if (tp != NULL)
					posix_timer_stop(tp);
			}
		}
		if (shm != ODP_SHM_INVALID) {
			if (odp_shm_free(shm)) {
				_ODP_ERR("Shm free failed for timer pool: %i\n", i);
				rc = -1;
			}
		}
	}

	if (odp_shm_free(timer_global->shm)) {
		_ODP_ERR("Shm free failed for timer_global\n");
		return -1;
	}

	return rc;
}

int _odp_timer_init_local(void)
{
	int conf_thr_type;
	odp_thread_type_t thr_type;

	timer_local.last_run = odp_time_global_from_ns(0);
	timer_local.run_cnt = 1;
	timer_local.poll_shared = 0;
	timer_local.prof_nsec = 0;
	timer_local.prof_rounds = 0;

	/* Timer feature disabled */
	if (timer_global == NULL)
		return 0;

	/* Check if this thread polls shared (non-private) timer pools */
	conf_thr_type = timer_global->thread_type;
	thr_type = odp_thread_type();

	if (conf_thr_type == 0)
		timer_local.poll_shared = 1;
	else if (conf_thr_type == 1 && thr_type == ODP_THREAD_WORKER)
		timer_local.poll_shared = 1;
	else if (conf_thr_type == 2 && thr_type == ODP_THREAD_CONTROL)
		timer_local.poll_shared = 1;

	return 0;
}

int _odp_timer_term_local(void)
{
	if (CONFIG_TIMER_PROFILE_INLINE) {
		if (timer_local.prof_rounds) {
			_ODP_PRINT("\n"
				   "Inline timer profiling for thread %i:\n"
				   "scan rounds:   %" PRIu64 "\n"
				   "ave scan nsec: %.1f\n",
				   odp_thread_id(), timer_local.prof_rounds,
				   (double)timer_local.prof_nsec / timer_local.prof_rounds);
		}
	}

	return 0;
}

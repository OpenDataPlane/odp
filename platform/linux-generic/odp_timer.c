/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP timer service
 *
 */
#include <odp_posix_extensions.h>

#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <inttypes.h>
#include <string.h>

#include <odp/api/align.h>
#include <odp_align_internal.h>
#include <odp/api/atomic.h>
#include <odp_atomic_internal.h>
#include <odp/api/buffer.h>
#include <odp/api/cpu.h>
#include <odp/api/pool.h>
#include <odp_pool_internal.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp_init_internal.h>
#include <odp_errno_define.h>
#include <odp/api/queue.h>
#include <odp/api/shared_memory.h>
#include <odp/api/spinlock.h>
#include <odp/api/std_types.h>
#include <odp/api/sync.h>
#include <odp/api/time.h>
#include <odp/api/plat/time_inlines.h>
#include <odp/api/timer.h>
#include <odp_libconfig_internal.h>
#include <odp_queue_if.h>
#include <odp_timer_internal.h>
#include <odp/api/plat/queue_inlines.h>
#include <odp_global_data.h>

/* Inlined API functions */
#include <odp/api/plat/event_inlines.h>

#define TMO_UNUSED   ((uint64_t)0xFFFFFFFFFFFFFFFF)
/* TMO_INACTIVE is or-ed with the expiration tick to indicate an expired timer.
 * The original expiration tick (63 bits) is still available so it can be used
 * for checking the freshness of received timeouts */
#define TMO_INACTIVE ((uint64_t)0x8000000000000000)

/* Max timeout in capability. One year in nsec (0x0070 09D3 2DA3 0000). */
#define MAX_TMO_NSEC (365 * 24 * ODP_TIME_HOUR_IN_NS)

/* Max inline timer resolution */
#define MAX_INLINE_RES_NS 500

/******************************************************************************
 * Mutual exclusion in the absence of CAS16
 *****************************************************************************/

#ifndef ODP_ATOMIC_U128
#define NUM_LOCKS 1024
#define IDX2LOCK(idx) (&timer_global->locks[(idx) % NUM_LOCKS])
#endif

/******************************************************************************
 * Translation between timeout buffer and timeout header
 *****************************************************************************/

static odp_timeout_hdr_t *timeout_hdr_from_buf(odp_buffer_t buf)
{
	return (odp_timeout_hdr_t *)(void *)buf_hdl_to_hdr(buf);
}

static odp_timeout_hdr_t *timeout_hdr(odp_timeout_t tmo)
{
	odp_buffer_t buf = odp_buffer_from_event(odp_timeout_to_event(tmo));
	return timeout_hdr_from_buf(buf);
}

/******************************************************************************
 * odp_timer abstract datatype
 *****************************************************************************/

typedef struct
#ifdef ODP_ATOMIC_U128
ODP_ALIGNED(16) /* 16-byte atomic operations need properly aligned addresses */
#endif
tick_buf_s {
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	/* No atomics support for 64-bit variables, will use separate lock */
	/* Use the same layout as odp_atomic_u64_t but without lock variable */
	struct {
		uint64_t v;
	} exp_tck;/* Expiration tick or TMO_xxx */
#else
	odp_atomic_u64_t exp_tck;/* Expiration tick or TMO_xxx */
#endif

	union {
		/* ODP_BUFFER_INVALID if timer not active */
		odp_buffer_t tmo_buf;

		/* Ensures that tick_buf_t is 128 bits */
		uint64_t tmo_u64;
	};

} tick_buf_t;

#if __GCC_ATOMIC_LLONG_LOCK_FREE >= 2
/* Only assert this when we perform atomic operations on tick_buf_t */
ODP_STATIC_ASSERT(sizeof(tick_buf_t) == 16, "sizeof(tick_buf_t) == 16");
#endif

typedef struct {
	void *user_ptr;
	odp_queue_t queue;/* Used for free list when timer is free */
} _odp_timer_t;

static void timer_init(_odp_timer_t *tim,
		       tick_buf_t *tb,
		       odp_queue_t _q,
		       void *_up)
{
	tim->queue = _q;
	tim->user_ptr = _up;
	tb->tmo_u64 = 0;
	tb->tmo_buf = ODP_BUFFER_INVALID;

	/* Release the timer by setting timer state to inactive */
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	tb->exp_tck.v = TMO_INACTIVE;
#else
	_odp_atomic_u64_store_mm(&tb->exp_tck, TMO_INACTIVE, _ODP_MEMMODEL_RLS);
#endif
}

/* Teardown when timer is freed */
static void timer_fini(_odp_timer_t *tim, tick_buf_t *tb)
{
	ODP_ASSERT(tb->exp_tck.v == TMO_UNUSED);
	ODP_ASSERT(tb->tmo_buf == ODP_BUFFER_INVALID);
	tim->queue = ODP_QUEUE_INVALID;
	tim->user_ptr = NULL;
}

static inline uint32_t get_next_free(_odp_timer_t *tim)
{
	/* Reusing 'queue' for next free index */
	return _odp_typeval(tim->queue);
}

static inline void set_next_free(_odp_timer_t *tim, uint32_t nf)
{
	ODP_ASSERT(tim->queue == ODP_QUEUE_INVALID);
	/* Reusing 'queue' for next free index */
	tim->queue = _odp_cast_scalar(odp_queue_t, nf);
}

/******************************************************************************
 * timer_pool_t abstract datatype
 * Inludes alloc and free timer
 *****************************************************************************/

typedef struct timer_pool_s {
/* Put frequently accessed fields in the first cache line */
	uint64_t nsec_per_scan;
	odp_time_t start_time;
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
	odp_shm_t shm;
	timer_t timerid;
	int notify_overrun;
	pthread_t thr_pthread; /* pthread_t of timer thread */
	pid_t thr_pid; /* gettid() for timer thread */
	int thr_warm_up; /* number of warm up rounds */
	odp_atomic_u32_t thr_ready; /* thread ready from warm up */
	int thr_exit; /* request to exit for timer thread */
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
	uint64_t poll_interval_nsec;
	int num_timer_pools;
	uint8_t timer_pool_used[MAX_TIMER_POOLS];
	timer_pool_t *timer_pool[MAX_TIMER_POOLS];
#ifndef ODP_ATOMIC_U128
	/* Multiple locks per cache line! */
	_odp_atomic_flag_t ODP_ALIGNED_CACHE locks[NUM_LOCKS];
#endif
	/* These are read frequently from inline timer */
	odp_time_t poll_interval_time;
	odp_bool_t use_inline_timers;
	int poll_interval;
	int highest_tp_idx;

} timer_global_t;

static timer_global_t *timer_global;

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
	if (odp_likely(tp_idx < MAX_TIMER_POOLS)) {
		timer_pool_t *tp = timer_global->timer_pool[tp_idx];
		if (odp_likely(tp != NULL))
			return timer_global->timer_pool[tp_idx];
	}
	ODP_ABORT("Invalid timer handle %#x\n", hdl);
}

static inline uint32_t handle_to_idx(odp_timer_t hdl,
				     timer_pool_t *tp)
{
	uint32_t idx = (_odp_typeval(hdl) & ((1U << INDEX_BITS) - 1U)) - 1;
	__builtin_prefetch(&tp->tick_buf[idx], 0, 0);
	if (odp_likely(idx < odp_atomic_load_u32(&tp->high_wm)))
		return idx;
	ODP_ABORT("Invalid timer handle %#x\n", hdl);
}

static inline odp_timer_t tp_idx_to_handle(timer_pool_t *tp,
					   uint32_t idx)
{
	ODP_ASSERT((idx + 1) < (1U << INDEX_BITS));
	return _odp_cast_scalar(odp_timer_t, (tp->tp_idx << INDEX_BITS) |
				(idx + 1));
}

/* Forward declarations */
static void itimer_init(timer_pool_t *tp);
static void itimer_fini(timer_pool_t *tp);

static odp_timer_pool_t timer_pool_new(const char *name,
				       const odp_timer_pool_param_t *param)
{
	uint32_t i;
	int tp_idx;
	size_t sz0, sz1, sz2;
	uint64_t tp_size;
	uint64_t res_ns, nsec_per_scan;
	uint32_t flags = ODP_SHM_SW_ONLY;

	if (odp_global_ro.shm_single_va)
		flags |= ODP_SHM_SINGLE_VA;

	odp_ticketlock_lock(&timer_global->lock);

	if (timer_global->num_timer_pools >= MAX_TIMER_POOLS) {
		odp_ticketlock_unlock(&timer_global->lock);
		ODP_DBG("No more free timer pools\n");
		return ODP_TIMER_POOL_INVALID;
	}

	for (i = 0; i < MAX_TIMER_POOLS; i++) {
		if (timer_global->timer_pool_used[i] == 0) {
			timer_global->timer_pool_used[i] = 1;
			break;
		}
	}

	tp_idx = i;
	timer_global->num_timer_pools++;

	if (tp_idx > timer_global->highest_tp_idx)
		timer_global->highest_tp_idx = tp_idx;

	odp_ticketlock_unlock(&timer_global->lock);

	sz0 = ROUNDUP_CACHE_LINE(sizeof(timer_pool_t));
	sz1 = ROUNDUP_CACHE_LINE(sizeof(tick_buf_t) * param->num_timers);
	sz2 = ROUNDUP_CACHE_LINE(sizeof(_odp_timer_t) *
				 param->num_timers);
	tp_size = sz0 + sz1 + sz2;

	odp_shm_t shm = odp_shm_reserve(name, tp_size, ODP_CACHE_LINE_SIZE,
					flags);
	if (odp_unlikely(shm == ODP_SHM_INVALID))
		ODP_ABORT("%s: timer pool shm-alloc(%zuKB) failed\n",
			  name, (sz0 + sz1 + sz2) / 1024);
	timer_pool_t *tp = (timer_pool_t *)odp_shm_addr(shm);

	memset(tp, 0, tp_size);

	res_ns = param->res_ns;

	/* Scan timer pool twice during resolution interval */
	if (res_ns > ODP_TIME_USEC_IN_NS)
		nsec_per_scan = res_ns / 2;
	else
		nsec_per_scan = res_ns;

	tp->nsec_per_scan = nsec_per_scan;

	odp_atomic_init_u64(&tp->cur_tick, 0);

	if (name == NULL) {
		tp->name[0] = 0;
	} else {
		strncpy(tp->name, name, ODP_TIMER_POOL_NAME_LEN - 1);
		tp->name[ODP_TIMER_POOL_NAME_LEN - 1] = 0;
	}
	tp->shm = shm;
	tp->param = *param;
	tp->min_rel_tck = odp_timer_ns_to_tick(timer_pool_to_hdl(tp),
					       param->min_tmo);
	tp->max_rel_tck = odp_timer_ns_to_tick(timer_pool_to_hdl(tp),
					       param->max_tmo);
	tp->num_alloc = 0;
	odp_atomic_init_u32(&tp->high_wm, 0);
	tp->first_free = 0;
	tp->notify_overrun = 1;
	tp->tick_buf = (void *)((char *)odp_shm_addr(shm) + sz0);
	tp->timers = (void *)((char *)odp_shm_addr(shm) + sz0 + sz1);

	/* Initialize all odp_timer entries */
	for (i = 0; i < tp->param.num_timers; i++) {
		tp->timers[i].queue = ODP_QUEUE_INVALID;
		set_next_free(&tp->timers[i], i + 1);
		tp->timers[i].user_ptr = NULL;
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
		tp->tick_buf[i].exp_tck.v = TMO_UNUSED;
#else
		odp_atomic_init_u64(&tp->tick_buf[i].exp_tck, TMO_UNUSED);
#endif
		tp->tick_buf[i].tmo_buf = ODP_BUFFER_INVALID;
	}
	tp->tp_idx = tp_idx;
	odp_spinlock_init(&tp->lock);
	odp_ticketlock_lock(&timer_global->lock);
	timer_global->timer_pool[tp_idx] = tp;

	if (timer_global->num_timer_pools == 1)
		odp_global_rw->inline_timers = timer_global->use_inline_timers;

	/* Increase poll rate to match the highest resolution */
	if (timer_global->poll_interval_nsec > nsec_per_scan) {
		timer_global->poll_interval_nsec = nsec_per_scan;
		timer_global->poll_interval_time =
			odp_time_global_from_ns(nsec_per_scan);
	}

	odp_ticketlock_unlock(&timer_global->lock);
	if (!odp_global_rw->inline_timers) {
		if (tp->param.clk_src == ODP_CLOCK_CPU)
			itimer_init(tp);
	}

	tp->start_time = odp_time_global();

	return timer_pool_to_hdl(tp);
}

static void block_sigalarm(void)
{
	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
}

static void stop_timer_thread(timer_pool_t *tp)
{
	int ret;

	ODP_DBG("stop\n");
	tp->thr_exit = 1;
	ret = pthread_join(tp->thr_pthread, NULL);
	if (ret != 0)
		ODP_ABORT("unable to join thread, err %d\n", ret);
}

static void odp_timer_pool_del(timer_pool_t *tp)
{
	int rc, highest;
	odp_shm_t shm;

	odp_spinlock_lock(&tp->lock);

	if (!odp_global_rw->inline_timers) {
		/* Stop POSIX itimer signals */
		if (tp->param.clk_src == ODP_CLOCK_CPU)
			itimer_fini(tp);

		stop_timer_thread(tp);
	}

	if (tp->num_alloc != 0) {
		/* It's a programming error to attempt to destroy a */
		/* timer pool which is still in use */
		odp_spinlock_unlock(&tp->lock);
		ODP_ABORT("%s: timers in use\n", tp->name);
	}

	odp_spinlock_unlock(&tp->lock);

	odp_ticketlock_lock(&timer_global->lock);
	shm = tp->shm;
	timer_global->timer_pool[tp->tp_idx] = NULL;
	timer_global->timer_pool_used[tp->tp_idx] = 0;
	timer_global->num_timer_pools--;

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

	rc = odp_shm_free(shm);

	if (rc != 0)
		ODP_ABORT("Failed to free shared memory (%d)\n", rc);
}

static inline odp_timer_t timer_alloc(timer_pool_t *tp,
				      odp_queue_t queue,
				      void *user_ptr)
{
	odp_timer_t hdl;
	odp_spinlock_lock(&tp->lock);
	if (odp_likely(tp->num_alloc < tp->param.num_timers)) {
		tp->num_alloc++;
		/* Remove first unused timer from free list */
		ODP_ASSERT(tp->first_free != tp->param.num_timers);
		uint32_t idx = tp->first_free;
		_odp_timer_t *tim = &tp->timers[idx];
		tp->first_free = get_next_free(tim);
		/* Initialize timer */
		timer_init(tim, &tp->tick_buf[idx], queue, user_ptr);
		if (odp_unlikely(tp->num_alloc >
				 odp_atomic_load_u32(&tp->high_wm)))
			/* Update high_wm last with release model to
			 * ensure timer initialization is visible */
			_odp_atomic_u32_store_mm(&tp->high_wm,
						 tp->num_alloc,
						 _ODP_MEMMODEL_RLS);
		hdl = tp_idx_to_handle(tp, idx);
		/* Add timer to queue */
		queue_fn->timer_add(queue);
	} else {
		__odp_errno = ENFILE; /* Reusing file table overflow */
		hdl = ODP_TIMER_INVALID;
	}
	odp_spinlock_unlock(&tp->lock);
	return hdl;
}

static odp_buffer_t timer_set_unused(timer_pool_t *tp,
				     uint32_t idx);

static inline odp_buffer_t timer_free(timer_pool_t *tp, uint32_t idx)
{
	_odp_timer_t *tim = &tp->timers[idx];

	/* Free the timer by setting timer state to unused and
	 * grab any timeout buffer */
	odp_buffer_t old_buf = timer_set_unused(tp, idx);

	/* Remove timer from queue */
	queue_fn->timer_rem(tim->queue);

	/* Destroy timer */
	timer_fini(tim, &tp->tick_buf[idx]);

	/* Insert timer into free list */
	odp_spinlock_lock(&tp->lock);
	set_next_free(tim, tp->first_free);
	tp->first_free = idx;
	ODP_ASSERT(tp->num_alloc != 0);
	tp->num_alloc--;
	odp_spinlock_unlock(&tp->lock);

	return old_buf;
}

/******************************************************************************
 * Operations on timers
 * expire/reset/cancel timer
 *****************************************************************************/

static bool timer_reset(uint32_t idx,
		uint64_t abs_tck,
		odp_buffer_t *tmo_buf,
		timer_pool_t *tp)
{
	bool success = true;
	tick_buf_t *tb = &tp->tick_buf[idx];

	if (tmo_buf == NULL || *tmo_buf == ODP_BUFFER_INVALID) {
#ifdef ODP_ATOMIC_U128 /* Target supports 128-bit atomic operations */
		tick_buf_t new, old;

		/* Init all bits, also when tmo_buf is less than 64 bits */
		new.tmo_u64 = 0;
		old.tmo_u64 = 0;

		do {
			/* Relaxed and non-atomic read of current values */
			old.exp_tck.v = tb->exp_tck.v;
			old.tmo_buf = tb->tmo_buf;

			/* Check if there actually is a timeout buffer
			 * present */
			if (old.tmo_buf == ODP_BUFFER_INVALID) {
				/* Cannot reset a timer with neither old nor
				 * new timeout buffer */
				success = false;
				break;
			}
			/* Set up new values */
			new.exp_tck.v = abs_tck;
			new.tmo_buf = old.tmo_buf;

			/* Atomic CAS will fail if we experienced torn reads,
			 * retry update sequence until CAS succeeds */
		} while (!_odp_atomic_u128_cmp_xchg_mm(
					(_odp_atomic_u128_t *)tb,
					(_uint128_t *)&old,
					(_uint128_t *)&new,
					_ODP_MEMMODEL_RLS,
					_ODP_MEMMODEL_RLX));
#elif __GCC_ATOMIC_LLONG_LOCK_FREE >= 2 && \
	defined __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8
	/* Target supports lock-free 64-bit CAS (and probably exchange) */
		/* Since locks/barriers are not good for C-A15, we take an
		 * alternative approach using relaxed memory model */
		uint64_t old;
		/* Swap in new expiration tick, get back old tick which
		 * will indicate active/inactive timer state */
		old = _odp_atomic_u64_xchg_mm(&tb->exp_tck, abs_tck,
			_ODP_MEMMODEL_RLX);
		if ((old & TMO_INACTIVE) != 0) {
			/* Timer was inactive (cancelled or expired),
			 * we can't reset a timer without a timeout buffer.
			 * Attempt to restore inactive state, we don't
			 * want this timer to continue as active without
			 * timeout as this will trigger unnecessary and
			 * aborted expiration attempts.
			 * We don't care if we fail, then some other thread
			 * reset or cancelled the timer. Without any
			 * synchronization between the threads, we have a
			 * data race and the behavior is undefined */
			(void)_odp_atomic_u64_cmp_xchg_strong_mm(
					&tb->exp_tck,
					&abs_tck,
					old,
					_ODP_MEMMODEL_RLX,
					_ODP_MEMMODEL_RLX);
			success = false;
		}
#else /* Target supports neither 128-bit nor 64-bit CAS => use lock */
		/* Take a related lock */
		while (_odp_atomic_flag_tas(IDX2LOCK(idx)))
			/* While lock is taken, spin using relaxed loads */
			while (_odp_atomic_flag_load(IDX2LOCK(idx)))
				odp_cpu_pause();

		/* Only if there is a timeout buffer can be reset the timer */
		if (odp_likely(tb->tmo_buf != ODP_BUFFER_INVALID)) {
			/* Write the new expiration tick */
			tb->exp_tck.v = abs_tck;
		} else {
			/* Cannot reset a timer with neither old nor new
			 * timeout buffer */
			success = false;
		}

		/* Release the lock */
		_odp_atomic_flag_clear(IDX2LOCK(idx));
#endif
	} else {
		/* We have a new timeout buffer which replaces any old one */
		/* Fill in some (constant) header fields for timeout events */
		if (odp_event_type(odp_buffer_to_event(*tmo_buf)) ==
		    ODP_EVENT_TIMEOUT) {
			/* Convert from buffer to timeout hdr */
			odp_timeout_hdr_t *tmo_hdr =
				timeout_hdr_from_buf(*tmo_buf);
			tmo_hdr->timer = tp_idx_to_handle(tp, idx);
			tmo_hdr->user_ptr = tp->timers[idx].user_ptr;
			/* expiration field filled in when timer expires */
		}
		/* Else ignore buffers of other types */
		odp_buffer_t old_buf = ODP_BUFFER_INVALID;
#ifdef ODP_ATOMIC_U128
		tick_buf_t new, old;

		/* Init all bits, also when tmo_buf is less than 64 bits */
		new.tmo_u64 = 0;

		new.exp_tck.v = abs_tck;
		new.tmo_buf = *tmo_buf;

		/* We are releasing the new timeout buffer to some other
		 * thread */
		_odp_atomic_u128_xchg_mm((_odp_atomic_u128_t *)tb,
					 (_uint128_t *)&new,
					 (_uint128_t *)&old,
					 _ODP_MEMMODEL_ACQ_RLS);
		old_buf = old.tmo_buf;
#else
		/* Take a related lock */
		while (_odp_atomic_flag_tas(IDX2LOCK(idx)))
			/* While lock is taken, spin using relaxed loads */
			while (_odp_atomic_flag_load(IDX2LOCK(idx)))
				odp_cpu_pause();

		/* Swap in new buffer, save any old buffer */
		old_buf = tb->tmo_buf;
		tb->tmo_buf = *tmo_buf;

		/* Write the new expiration tick */
		tb->exp_tck.v = abs_tck;

		/* Release the lock */
		_odp_atomic_flag_clear(IDX2LOCK(idx));
#endif
		/* Return old timeout buffer */
		*tmo_buf = old_buf;
	}
	return success;
}

static odp_buffer_t timer_set_unused(timer_pool_t *tp,
				     uint32_t idx)
{
	tick_buf_t *tb = &tp->tick_buf[idx];
	odp_buffer_t old_buf;

#ifdef ODP_ATOMIC_U128
	tick_buf_t new, old;

	/* Init all bits, also when tmo_buf is less than 64 bits */
	new.tmo_u64 = 0;

	/* Update the timer state (e.g. cancel the current timeout) */
	new.exp_tck.v = TMO_UNUSED;
	/* Swap out the old buffer */
	new.tmo_buf = ODP_BUFFER_INVALID;

	_odp_atomic_u128_xchg_mm((_odp_atomic_u128_t *)tb,
				 (_uint128_t *)&new, (_uint128_t *)&old,
				 _ODP_MEMMODEL_RLX);
	old_buf = old.tmo_buf;
#else
	/* Take a related lock */
	while (_odp_atomic_flag_tas(IDX2LOCK(idx)))
		/* While lock is taken, spin using relaxed loads */
		while (_odp_atomic_flag_load(IDX2LOCK(idx)))
			odp_cpu_pause();

	/* Update the timer state (e.g. cancel the current timeout) */
	tb->exp_tck.v = TMO_UNUSED;

	/* Swap out the old buffer */
	old_buf = tb->tmo_buf;
	tb->tmo_buf = ODP_BUFFER_INVALID;

	/* Release the lock */
	_odp_atomic_flag_clear(IDX2LOCK(idx));
#endif
	/* Return the old buffer */
	return old_buf;
}

static odp_buffer_t timer_cancel(timer_pool_t *tp,
				 uint32_t idx)
{
	tick_buf_t *tb = &tp->tick_buf[idx];
	odp_buffer_t old_buf;

#ifdef ODP_ATOMIC_U128
	tick_buf_t new, old;

	/* Init all bits, also when tmo_buf is less than 64 bits */
	new.tmo_u64 = 0;
	old.tmo_u64 = 0;

	do {
		/* Relaxed and non-atomic read of current values */
		old.exp_tck.v = tb->exp_tck.v;
		old.tmo_buf = tb->tmo_buf;

		/* Check if it is not expired already */
		if (old.exp_tck.v & TMO_INACTIVE) {
			old.tmo_buf = ODP_BUFFER_INVALID;
			break;
		}

		/* Set up new values */
		new.exp_tck.v = TMO_INACTIVE;
		new.tmo_buf = ODP_BUFFER_INVALID;

		/* Atomic CAS will fail if we experienced torn reads,
		 * retry update sequence until CAS succeeds */
	} while (!_odp_atomic_u128_cmp_xchg_mm(
				(_odp_atomic_u128_t *)tb,
				(_uint128_t *)&old,
				(_uint128_t *)&new,
				_ODP_MEMMODEL_RLS,
				_ODP_MEMMODEL_RLX));
	old_buf = old.tmo_buf;
#else
	/* Take a related lock */
	while (_odp_atomic_flag_tas(IDX2LOCK(idx)))
		/* While lock is taken, spin using relaxed loads */
		while (_odp_atomic_flag_load(IDX2LOCK(idx)))
			odp_cpu_pause();

	/* Swap in new buffer, save any old buffer */
	old_buf = tb->tmo_buf;
	tb->tmo_buf = ODP_BUFFER_INVALID;

	/* Write the new expiration tick if it not cancelled */
	if (tb->exp_tck.v & TMO_INACTIVE)
		old_buf = ODP_BUFFER_INVALID;
	else
		tb->exp_tck.v = TMO_INACTIVE;

	/* Release the lock */
	_odp_atomic_flag_clear(IDX2LOCK(idx));
#endif
	/* Return the old buffer */
	return old_buf;
}

static inline void timer_expire(timer_pool_t *tp, uint32_t idx, uint64_t tick)
{
	_odp_timer_t *tim = &tp->timers[idx];
	tick_buf_t *tb = &tp->tick_buf[idx];
	odp_buffer_t tmo_buf = ODP_BUFFER_INVALID;
	uint64_t exp_tck;
#ifdef ODP_ATOMIC_U128
	/* Atomic re-read for correctness */
	exp_tck = _odp_atomic_u64_load_mm(&tb->exp_tck, _ODP_MEMMODEL_RLX);
	/* Re-check exp_tck */
	if (odp_likely(exp_tck <= tick)) {
		/* Attempt to grab timeout buffer, replace with inactive timer
		 * and invalid buffer */
		tick_buf_t new, old;

		/* Init all bits, also when tmo_buf is less than 64 bits */
		new.tmo_u64 = 0;
		old.tmo_u64 = 0;

		old.exp_tck.v = exp_tck;
		old.tmo_buf = tb->tmo_buf;

		/* Set the inactive/expired bit keeping the expiration tick so
		 * that we can check against the expiration tick of the timeout
		 * when it is received */
		new.exp_tck.v = exp_tck | TMO_INACTIVE;
		new.tmo_buf = ODP_BUFFER_INVALID;

		int succ = _odp_atomic_u128_cmp_xchg_mm(
				(_odp_atomic_u128_t *)tb,
				(_uint128_t *)&old, (_uint128_t *)&new,
				_ODP_MEMMODEL_RLS, _ODP_MEMMODEL_RLX);
		if (succ)
			tmo_buf = old.tmo_buf;
		/* Else CAS failed, something changed => skip timer
		 * this tick, it will be checked again next tick */
	}
	/* Else false positive, ignore */
#else
	/* Take a related lock */
	while (_odp_atomic_flag_tas(IDX2LOCK(idx)))
		/* While lock is taken, spin using relaxed loads */
		while (_odp_atomic_flag_load(IDX2LOCK(idx)))
			odp_cpu_pause();
	/* Proper check for timer expired */
	exp_tck = tb->exp_tck.v;
	if (odp_likely(exp_tck <= tick)) {
		/* Verify that there is a timeout buffer */
		if (odp_likely(tb->tmo_buf != ODP_BUFFER_INVALID)) {
			/* Grab timeout buffer, replace with inactive timer
			 * and invalid buffer */
			tmo_buf = tb->tmo_buf;
			tb->tmo_buf = ODP_BUFFER_INVALID;
			/* Set the inactive/expired bit keeping the expiration
			 * tick so that we can check against the expiration
			 * tick of the timeout when it is received */
			tb->exp_tck.v |= TMO_INACTIVE;
		}
		/* Else somehow active timer without user buffer */
	}
	/* Else false positive, ignore */
	/* Release the lock */
	_odp_atomic_flag_clear(IDX2LOCK(idx));
#endif
	if (odp_likely(tmo_buf != ODP_BUFFER_INVALID)) {
		/* Fill in expiration tick for timeout events */
		if (odp_event_type(odp_buffer_to_event(tmo_buf)) ==
		    ODP_EVENT_TIMEOUT) {
			/* Convert from buffer to timeout hdr */
			odp_timeout_hdr_t *tmo_hdr =
				timeout_hdr_from_buf(tmo_buf);
			tmo_hdr->expiration = exp_tck;
			/* timer and user_ptr fields filled in when timer
			 * was set */
		}
		/* Else ignore events of other types */
		/* Post the timeout to the destination queue */
		int rc = odp_queue_enq(tim->queue,
				       odp_buffer_to_event(tmo_buf));
		if (odp_unlikely(rc != 0)) {
			odp_buffer_free(tmo_buf);
			ODP_ABORT("Failed to enqueue timeout buffer (%d)\n",
				  rc);
		}
	}
}

static inline void timer_pool_scan(timer_pool_t *tp, uint64_t tick)
{
	tick_buf_t *array = &tp->tick_buf[0];
	uint32_t high_wm = _odp_atomic_u32_load_mm(&tp->high_wm,
			_ODP_MEMMODEL_ACQ);
	uint32_t i;

	ODP_ASSERT(high_wm <= tp->param.num_timers);
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
		}
	}
}

/******************************************************************************
 * Inline timer processing
 *****************************************************************************/

static inline uint64_t time_nsec(timer_pool_t *tp, odp_time_t now)
{
	odp_time_t start = tp->start_time;

	return odp_time_diff_ns(now, start);
}

static inline uint64_t current_nsec(timer_pool_t *tp)
{
	odp_time_t now;

	now = odp_time_global();

	return time_nsec(tp, now);
}

static inline void timer_pool_scan_inline(int num, odp_time_t now)
{
	timer_pool_t *tp;
	uint64_t new_tick, old_tick, nsec;
	int64_t diff;
	int i;

	for (i = 0; i < num; i++) {
		tp = timer_global->timer_pool[i];

		if (tp == NULL)
			continue;

		nsec     = time_nsec(tp, now);
		new_tick = nsec / tp->nsec_per_scan;
		old_tick = odp_atomic_load_u64(&tp->cur_tick);
		diff = new_tick - old_tick;

		if (diff < 1)
			continue;

		if (odp_atomic_cas_u64(&tp->cur_tick, &old_tick, new_tick)) {
			if (tp->notify_overrun && diff > 1) {
				if (old_tick == 0) {
					ODP_ERR("Timer pool (%s) missed %" PRIi64 " scans in start up\n",
						tp->name, diff - 1);
				} else {
					ODP_ERR("Timer pool (%s) resolution too high: missed %" PRIi64 " scans\n",
						tp->name, diff - 1);
					tp->notify_overrun = 0;
				}
			}
			timer_pool_scan(tp, nsec);
		}
	}
}

void _timer_run_inline(int dec)
{
	static __thread odp_time_t last_timer_run;
	static __thread int timer_run_cnt = 1;
	odp_time_t now;
	int num = timer_global->highest_tp_idx + 1;
	int poll_interval = timer_global->poll_interval;

	if (num == 0)
		return;

	/* Rate limit how often this thread checks the timer pools. */

	if (poll_interval > 1) {
		timer_run_cnt -= dec;
		if (timer_run_cnt > 0)
			return;
		timer_run_cnt = poll_interval;
	}

	now = odp_time_global();

	if (poll_interval > 1) {
		odp_time_t period = odp_time_diff(now, last_timer_run);

		if (odp_time_cmp(period,
				 timer_global->poll_interval_time) < 0)
			return;
		last_timer_run = now;
	}

	/* Check the timer pools. */
	timer_pool_scan_inline(num, now);
}

/******************************************************************************
 * POSIX timer support
 * Functions that use Linux/POSIX per-process timers and related facilities
 *****************************************************************************/

static inline void timer_run_posix(timer_pool_t *tp)
{
	uint64_t nsec;
	int overrun;

	if (tp->notify_overrun) {
		overrun = timer_getoverrun(tp->timerid);
		if (overrun) {
			ODP_ERR("\n\t%d ticks overrun on timer pool \"%s\", timer resolution too high\n",
				overrun, tp->name);
			tp->notify_overrun = 0;
		}
	}

	_odp_timer_t *array = &tp->timers[0];
	uint32_t i;
	/* Prefetch initial cache lines (match 32 above) */
	for (i = 0; i < 32; i += ODP_CACHE_LINE_SIZE / sizeof(array[0]))
		__builtin_prefetch(&array[i], 0, 0);

	nsec = current_nsec(tp);
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

	tmo.tv_sec  = 0;
	tmo.tv_nsec = ODP_TIME_MSEC_IN_NS * 100;

	/* Unblock sigalarm in this thread */
	sigemptyset(&sigset);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	sigaddset(&sigset, SIGALRM);

	/* Signal that this thread has started */
	odp_mb_full();
	tp->thr_pid = (pid_t)syscall(SYS_gettid);
	odp_mb_full();

	while (1) {
		ret = sigtimedwait(&sigset, &si, &tmo);

		if (tp->thr_exit) {
			tp->thr_pid = 0;
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
		ODP_ABORT("timer_create() returned error %s\n",
			  strerror(errno));

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
			ODP_ABORT("timer_settime() returned error %s\n",
				  strerror(errno));
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
		ODP_ABORT("timer_delete() returned error %s\n",
			  strerror(errno));
	sigemptyset(&sigset);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	return 0;
}

static void itimer_init(timer_pool_t *tp)
{
	struct sigevent   sigev;
	struct itimerspec ispec;
	uint64_t res, sec, nsec;
	int ret;

	ODP_DBG("Creating POSIX timer for timer pool %s, period %"
		PRIu64" ns\n", tp->name, tp->param.res_ns);

	res  = tp->param.res_ns;
	sec  = res / ODP_TIME_SEC_IN_NS;
	nsec = res - sec * ODP_TIME_SEC_IN_NS;

	tp->thr_pid = 0;
	tp->thr_warm_up = 1;

	/* 20ms warm up */
	if (res < (20 * ODP_TIME_MSEC_IN_NS))
		tp->thr_warm_up = (20 * ODP_TIME_MSEC_IN_NS) / res;

	odp_atomic_init_u32(&tp->thr_ready, 0);
	ret = pthread_create(&tp->thr_pthread, NULL, timer_thread, tp);
	if (ret)
		ODP_ABORT("unable to create timer thread\n");

	/* wait thread set tp->thr_pid */
	while (tp->thr_pid == 0)
		sched_yield();

	memset(&sigev, 0, sizeof(sigev));
	sigev.sigev_notify          = SIGEV_THREAD_ID;
	sigev.sigev_value.sival_ptr = tp;
	sigev._sigev_un._tid = tp->thr_pid;
	sigev.sigev_signo = SIGALRM;

	if (timer_create(CLOCK_MONOTONIC, &sigev, &tp->timerid))
		ODP_ABORT("timer_create() returned error %s\n",
			  strerror(errno));

	memset(&ispec, 0, sizeof(ispec));
	ispec.it_interval.tv_sec  = (time_t)sec;
	ispec.it_interval.tv_nsec = (long)nsec;
	ispec.it_value.tv_sec     = (time_t)sec;
	ispec.it_value.tv_nsec    = (long)nsec;

	if (timer_settime(tp->timerid, 0, &ispec, NULL))
		ODP_ABORT("timer_settime() returned error %s\n",
			  strerror(errno));

	/* Wait response from timer thread that warm up signals have been
	 * processed. Warm up helps avoiding overrun on the first timeout. */
	while (odp_atomic_load_acq_u32(&tp->thr_ready) == 0)
		sched_yield();
}

static void itimer_fini(timer_pool_t *tp)
{
	if (timer_delete(tp->timerid) != 0)
		ODP_ABORT("timer_delete() returned error %s\n",
			  strerror(errno));
}

/******************************************************************************
 * Public API functions
 * Some parameter checks and error messages
 * No modificatios of internal state
 *****************************************************************************/
int odp_timer_capability(odp_timer_clk_src_t clk_src,
			 odp_timer_capability_t *capa)
{
	if (clk_src != ODP_CLOCK_CPU) {
		ODP_ERR("Only CPU clock source supported\n");
		return -1;
	}

	memset(capa, 0, sizeof(odp_timer_capability_t));

	capa->max_pools_combined = MAX_TIMER_POOLS;
	capa->max_pools = MAX_TIMER_POOLS;
	capa->max_timers = 0;
	capa->highest_res_ns  = timer_global->highest_res_ns;
	capa->max_res.res_ns  = timer_global->highest_res_ns;
	capa->max_res.min_tmo = 0;
	capa->max_res.max_tmo = MAX_TMO_NSEC;
	capa->max_tmo.res_ns  = timer_global->highest_res_ns;
	capa->max_tmo.min_tmo = 0;
	capa->max_tmo.max_tmo = MAX_TMO_NSEC;

	return 0;
}

int odp_timer_res_capability(odp_timer_clk_src_t clk_src,
			     odp_timer_res_capability_t *res_capa)
{
	if (clk_src != ODP_CLOCK_CPU) {
		ODP_ERR("Only CPU clock source supported\n");
		return -1;
	}

	if (res_capa->min_tmo) {
		ODP_ERR("Only res_ns or max_tmo based quaries supported\n");
		return -1;
	}

	if (res_capa->res_ns) {
		res_capa->min_tmo = 0;
		res_capa->max_tmo = MAX_TMO_NSEC;
	} else { /* max_tmo */
		res_capa->min_tmo = 0;
		res_capa->res_ns  = timer_global->highest_res_ns;
	}

	return 0;
}

odp_timer_pool_t odp_timer_pool_create(const char *name,
				       const odp_timer_pool_param_t *param)
{
	if (odp_global_ro.init_param.not_used.feat.timer) {
		ODP_ERR("Trying to use disabled ODP feature.\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if (param->res_ns < timer_global->highest_res_ns) {
		__odp_errno = EINVAL;
		return ODP_TIMER_POOL_INVALID;
	}

	return timer_pool_new(name, param);
}

void odp_timer_pool_start(void)
{
	/* Nothing to do here, timer pools are started by the create call */
}

void odp_timer_pool_destroy(odp_timer_pool_t tpid)
{
	odp_timer_pool_del(timer_pool_from_hdl(tpid));
}

uint64_t odp_timer_tick_to_ns(odp_timer_pool_t tpid, uint64_t ticks)
{
	(void)tpid;

	/* Timer ticks in API are nsec */
	return ticks;
}

uint64_t odp_timer_ns_to_tick(odp_timer_pool_t tpid, uint64_t ns)
{
	(void)tpid;

	/* Timer ticks in API are nsec */
	return ns;
}

uint64_t odp_timer_current_tick(odp_timer_pool_t tpid)
{
	timer_pool_t *tp = timer_pool_from_hdl(tpid);

	return current_nsec(tp);
}

int odp_timer_pool_info(odp_timer_pool_t tpid,
			odp_timer_pool_info_t *buf)
{
	timer_pool_t *tp = timer_pool_from_hdl(tpid);

	buf->param = tp->param;
	buf->cur_timers = tp->num_alloc;
	buf->hwm_timers = odp_atomic_load_u32(&tp->high_wm);
	buf->name = tp->name;
	return 0;
}

uint64_t odp_timer_pool_to_u64(odp_timer_pool_t tpid)
{
	return _odp_pri(tpid);
}

odp_timer_t odp_timer_alloc(odp_timer_pool_t tpid,
			    odp_queue_t queue,
			    void *user_ptr)
{
	timer_pool_t *tp = timer_pool_from_hdl(tpid);

	if (odp_unlikely(tpid == ODP_TIMER_POOL_INVALID)) {
		ODP_ERR("Invalid timer pool.\n");
		return ODP_TIMER_INVALID;
	}

	if (odp_unlikely(queue == ODP_QUEUE_INVALID)) {
		ODP_ERR("%s: Invalid queue handle\n", tp->name);
		return ODP_TIMER_INVALID;
	}
	/* We don't care about the validity of user_ptr because we will not
	 * attempt to dereference it */
	return timer_alloc(tp, queue, user_ptr);
}

odp_event_t odp_timer_free(odp_timer_t hdl)
{
	timer_pool_t *tp = handle_to_tp(hdl);
	uint32_t idx = handle_to_idx(hdl, tp);
	odp_buffer_t old_buf = timer_free(tp, idx);
	return odp_buffer_to_event(old_buf);
}

int odp_timer_set_abs(odp_timer_t hdl,
		      uint64_t abs_tck,
		      odp_event_t *tmo_ev)
{
	timer_pool_t *tp = handle_to_tp(hdl);
	uint64_t cur_tick = current_nsec(tp);
	uint32_t idx = handle_to_idx(hdl, tp);

	if (odp_unlikely(abs_tck < cur_tick + tp->min_rel_tck))
		return ODP_TIMER_TOOEARLY;
	if (odp_unlikely(abs_tck > cur_tick + tp->max_rel_tck))
		return ODP_TIMER_TOOLATE;
	if (timer_reset(idx, abs_tck, (odp_buffer_t *)tmo_ev, tp))
		return ODP_TIMER_SUCCESS;
	else
		return ODP_TIMER_NOEVENT;
}

int odp_timer_set_rel(odp_timer_t hdl,
		      uint64_t rel_tck,
		      odp_event_t *tmo_ev)
{
	timer_pool_t *tp = handle_to_tp(hdl);
	uint64_t cur_tick = current_nsec(tp);
	uint64_t abs_tck = cur_tick + rel_tck;
	uint32_t idx = handle_to_idx(hdl, tp);

	if (odp_unlikely(rel_tck < tp->min_rel_tck))
		return ODP_TIMER_TOOEARLY;
	if (odp_unlikely(rel_tck > tp->max_rel_tck))
		return ODP_TIMER_TOOLATE;
	if (timer_reset(idx, abs_tck, (odp_buffer_t *)tmo_ev, tp))
		return ODP_TIMER_SUCCESS;
	else
		return ODP_TIMER_NOEVENT;
}

int odp_timer_cancel(odp_timer_t hdl, odp_event_t *tmo_ev)
{
	timer_pool_t *tp = handle_to_tp(hdl);
	uint32_t idx = handle_to_idx(hdl, tp);
	/* Set the expiration tick of the timer to TMO_INACTIVE */
	odp_buffer_t old_buf = timer_cancel(tp, idx);
	if (old_buf != ODP_BUFFER_INVALID) {
		*tmo_ev = odp_buffer_to_event(old_buf);
		return 0; /* Active timer cancelled, timeout returned */
	} else {
		return -1; /* Timer already expired, no timeout returned */
	}
}

uint64_t odp_timer_to_u64(odp_timer_t hdl)
{
	return _odp_pri(hdl);
}

odp_timeout_t odp_timeout_from_event(odp_event_t ev)
{
	/* This check not mandated by the API specification */
	if (odp_event_type(ev) != ODP_EVENT_TIMEOUT)
		ODP_ABORT("Event not a timeout");
	return (odp_timeout_t)ev;
}

odp_event_t odp_timeout_to_event(odp_timeout_t tmo)
{
	return (odp_event_t)tmo;
}

uint64_t odp_timeout_to_u64(odp_timeout_t tmo)
{
	return _odp_pri(tmo);
}

int odp_timeout_fresh(odp_timeout_t tmo)
{
	const odp_timeout_hdr_t *hdr = timeout_hdr(tmo);
	odp_timer_t hdl = hdr->timer;
	timer_pool_t *tp = handle_to_tp(hdl);
	uint32_t idx = handle_to_idx(hdl, tp);
	tick_buf_t *tb = &tp->tick_buf[idx];
#if __GCC_ATOMIC_LLONG_LOCK_FREE < 2
	uint64_t exp_tck = tb->exp_tck.v;
#else
	uint64_t exp_tck = odp_atomic_load_u64(&tb->exp_tck);
#endif
	/* Return true if the timer still has the same expiration tick
	 * (ignoring the inactive/expired bit) as the timeout */
	return hdr->expiration == (exp_tck & ~TMO_INACTIVE);
}

odp_timer_t odp_timeout_timer(odp_timeout_t tmo)
{
	return timeout_hdr(tmo)->timer;
}

uint64_t odp_timeout_tick(odp_timeout_t tmo)
{
	return timeout_hdr(tmo)->expiration;
}

void *odp_timeout_user_ptr(odp_timeout_t tmo)
{
	return timeout_hdr(tmo)->user_ptr;
}

odp_timeout_t odp_timeout_alloc(odp_pool_t pool)
{
	odp_buffer_t buf = odp_buffer_alloc(pool);
	if (odp_unlikely(buf == ODP_BUFFER_INVALID))
		return ODP_TIMEOUT_INVALID;
	return odp_timeout_from_event(odp_buffer_to_event(buf));
}

void odp_timeout_free(odp_timeout_t tmo)
{
	odp_event_t ev = odp_timeout_to_event(tmo);
	odp_buffer_free(odp_buffer_from_event(ev));
}

int _odp_timer_init_global(const odp_init_t *params)
{
	odp_shm_t shm;
	const char *conf_str;
	int val = 0;

	if (params && params->not_used.feat.timer) {
		ODP_DBG("Timers disabled\n");
		timer_global = NULL;
		return 0;
	}

	shm = odp_shm_reserve("_odp_timer", sizeof(timer_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	timer_global = odp_shm_addr(shm);

	if (timer_global == NULL) {
		ODP_ERR("Shm reserve failed for odp_timer\n");
		return -1;
	}

	memset(timer_global, 0, sizeof(timer_global_t));
	odp_ticketlock_init(&timer_global->lock);
	timer_global->shm = shm;
	timer_global->highest_res_ns = MAX_INLINE_RES_NS;
	timer_global->highest_tp_idx = -1;

#ifndef ODP_ATOMIC_U128
	uint32_t i;
	for (i = 0; i < NUM_LOCKS; i++)
		_odp_atomic_flag_clear(&timer_global->locks[i]);
#else
	ODP_DBG("Using lock-less timer implementation\n");
#endif
	conf_str =  "timer.inline";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", conf_str);
		odp_shm_free(shm);
		return -1;
	}
	timer_global->use_inline_timers = val;

	conf_str =  "timer.inline_poll_interval";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", conf_str);
		odp_shm_free(shm);
		return -1;
	}
	timer_global->poll_interval = val;

	conf_str =  "timer.inline_poll_interval_nsec";
	if (!_odp_libconfig_lookup_int(conf_str, &val)) {
		ODP_ERR("Config option '%s' not found.\n", conf_str);
		odp_shm_free(shm);
		return -1;
	}
	timer_global->poll_interval_nsec = val;
	timer_global->poll_interval_time =
		odp_time_global_from_ns(timer_global->poll_interval_nsec);

	if (!timer_global->use_inline_timers) {
		timer_res_init();
		block_sigalarm();
	}

	return 0;
}

int _odp_timer_term_global(void)
{
	if (timer_global && odp_shm_free(timer_global->shm)) {
		ODP_ERR("Shm free failed for odp_timer\n");
		return -1;
	}

	return 0;
}

int _odp_timer_init_local(void)
{
	return 0;
}

int _odp_timer_term_local(void)
{
	return 0;
}

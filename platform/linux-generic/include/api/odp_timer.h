/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP timer service
 */

#ifndef ODP_TIMER_H_
#define ODP_TIMER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <odp_std_types.h>
#include <odp_buffer.h>
#include <odp_queue.h>

/** @defgroup odp_timer ODP TIMER
 *  @{
 */

struct odp_timer_pool_s; /**< Forward declaration */

/**
* ODP timer pool handle (platform dependent)
*/
typedef struct odp_timer_pool_s *odp_timer_pool_t;

/**
 * Invalid timer pool handle (platform dependent).
 */
#define ODP_TIMER_POOL_INVALID NULL

/**
 * Clock sources for timers in timer pool.
 */
typedef enum {
	/** Use CPU clock as clock source for timers */
	ODP_CLOCK_CPU,
	/** Use external clock as clock source for timers */
	ODP_CLOCK_EXT
	/* Platform dependent which other clock sources exist */
} odp_timer_clk_src_t;

/**
* ODP timer handle (platform dependent).
*/
typedef uint32_t odp_timer_t;

/**
* ODP timeout handle (platform dependent).
*/
typedef void *odp_timeout_t;

/**
 * Invalid timer handle (platform dependent).
 */
#define ODP_TIMER_INVALID ((uint32_t)~0U)

/**
 * Return values of timer set calls.
 */
typedef enum {
/**
 * Timer set operation succeeded
 */
	ODP_TIMER_SUCCESS = 0,
/**
 * Timer set operation failed, expiration too early.
 * Either retry with a later expiration time or process the timeout
 * immediately. */
	ODP_TIMER_TOOEARLY = -1,

/**
 * Timer set operation failed, expiration too late.
 * Truncate the expiration time against the maximum timeout for the
 * timer pool. */
	ODP_TIMER_TOOLATE = -2,
/**
 * Timer set operation failed because no timeout buffer specified and no
 * timeout buffer present in the timer (timer inactive/expired).
 */
	ODP_TIMER_NOBUF = -3
} odp_timer_set_t;

/** Maximum timer pool name length in chars (including null char) */
#define ODP_TIMER_POOL_NAME_LEN  32

/** Timer pool parameters
 * Timer pool parameters are used when creating and querying timer pools.
 */
typedef struct {
	uint64_t res_ns; /**< Timeout resolution in nanoseconds */
	uint64_t min_tmo; /**< Minimum relative timeout in nanoseconds */
	uint64_t max_tmo; /**< Maximum relative timeout in nanoseconds */
	uint32_t num_timers; /**< (Minimum) number of supported timers */
	int private; /**< Shared (false) or private (true) timer pool */
	odp_timer_clk_src_t clk_src; /**< Clock source for timers */
} odp_timer_pool_param_t;

/**
 * Create a timer pool
 *
 * @param name       Name of the timer pool. The string will be copied.
 * @param params     Timer pool parameters. The content will be copied.
 *
 * @return Timer pool handle if successful, otherwise ODP_TIMER_POOL_INVALID
 * and errno set
 */
odp_timer_pool_t
odp_timer_pool_create(const char *name,
		      const odp_timer_pool_param_t *params);

/**
 * Start a timer pool
 *
 * Start all created timer pools, enabling the allocation of timers.
 * The purpose of this call is to coordinate the creation of multiple timer
 * pools that may use the same underlying HW resources.
 * This function may be called multiple times.
 */
void odp_timer_pool_start(void);

/**
 * Destroy a timer pool
 *
 * Destroy a timer pool, freeing all resources.
 * All timers must have been freed.
 *
 * @param tpid  Timer pool identifier
 */
void odp_timer_pool_destroy(odp_timer_pool_t tpid);

/**
 * Convert timer ticks to nanoseconds
 *
 * @param tpid  Timer pool identifier
 * @param ticks Timer ticks
 *
 * @return Nanoseconds
 */
uint64_t odp_timer_tick_to_ns(odp_timer_pool_t tpid, uint64_t ticks);

/**
 * Convert nanoseconds to timer ticks
 *
 * @param tpid  Timer pool identifier
 * @param ns    Nanoseconds
 *
 * @return Timer ticks
 */
uint64_t odp_timer_ns_to_tick(odp_timer_pool_t tpid, uint64_t ns);

/**
 * Current tick value
 *
 * @param tpid Timer pool identifier
 *
 * @return Current time in timer ticks
 */
uint64_t odp_timer_current_tick(odp_timer_pool_t tpid);

/**
 * ODP timer pool information and configuration
 */

typedef struct {
	odp_timer_pool_param_t param; /**< Parameters specified at creation */
	uint32_t cur_timers; /**< Number of currently allocated timers */
	uint32_t hwm_timers; /**< High watermark of allocated timers */
	const char *name; /**< Name of timer pool */
} odp_timer_pool_info_t;

/**
 * Query timer pool configuration and current state
 *
 * @param tpid Timer pool identifier
 * @param[out] info Pointer to information buffer
 *
 * @retval 0 Success
 * @retval -1 Failure. Info could not be retrieved.
 */
int odp_timer_pool_info(odp_timer_pool_t tpid,
			odp_timer_pool_info_t *info);

/**
 * Allocate a timer
 *
 * Create a timer (allocating all necessary resources e.g. timeout event) from
 * the timer pool. The user_ptr is copied to timeouts and can be retrieved
 * using the odp_timeout_user_ptr() call.
 *
 * @param tpid     Timer pool identifier
 * @param queue    Destination queue for timeout notifications
 * @param user_ptr User defined pointer or NULL to be copied to timeouts
 *
 * @return Timer handle if successful, otherwise ODP_TIMER_INVALID and
 *	   errno set.
 */
odp_timer_t odp_timer_alloc(odp_timer_pool_t tpid,
			    odp_queue_t queue,
			    void *user_ptr);

/**
 * Free a timer
 *
 * Free (destroy) a timer, reclaiming associated resources.
 * The timeout buffer for an active timer will be returned.
 * The timeout buffer for an expired timer will not be returned. It is the
 * responsibility of the application to handle this timeout when it is received.
 *
 * @param tim      Timer handle
 * @return Buffer handle of timeout buffer or ODP_BUFFER_INVALID
 */
odp_buffer_t odp_timer_free(odp_timer_t tim);

/**
 * Set a timer (absolute time) with a user-provided timeout buffer
 *
 * Set (arm) the timer to expire at specific time. The timeout
 * buffer will be enqueued when the timer expires.
 *
 * Note: any invalid parameters will be treated as programming errors and will
 * cause the application to abort.
 *
 * @param tim      Timer
 * @param abs_tck  Expiration time in absolute timer ticks
 * @param[in,out] tmo_buf  Reference to a buffer variable that points to
 * timeout buffer or NULL to reuse the existing timeout buffer. Any existing
 * timeout buffer that is replaced by a successful set operation will be
 * returned here.
 *
 * @retval ODP_TIMER_SUCCESS Operation succeeded
 * @retval ODP_TIMER_TOOEARLY Operation failed because expiration tick too
 * early
 * @retval ODP_TIMER_TOOLATE Operation failed because expiration tick too
 * late
 * @retval ODP_TIMER_NOBUF Operation failed because timeout buffer not
 * specified in odp_timer_set call and not present in timer
 */
int odp_timer_set_abs(odp_timer_t tim,
		      uint64_t abs_tck,
		      odp_buffer_t *tmo_buf);

/**
 * Set a timer with a relative expiration time and user-provided buffer.
 *
 * Set (arm) the timer to expire at a relative future time.
 *
 * Note: any invalid parameters will be treated as programming errors and will
 * cause the application to abort.
 *
 * @param tim      Timer
 * @param rel_tck  Expiration time in timer ticks relative to current time of
 *		   the timer pool the timer belongs to
 * @param[in,out] tmo_buf  Reference to a buffer variable that points to
 * timeout buffer or NULL to reuse the existing timeout buffer. Any existing
 * timeout buffer that is replaced by a successful set operation will be
 * returned here.
 *
 * @retval ODP_TIMER_SUCCESS Operation succeeded
 * @retval ODP_TIMER_TOOEARLY Operation failed because expiration tick too
 * early
 * @retval ODP_TIMER_TOOLATE Operation failed because expiration tick too
 * late
 * @retval ODP_TIMER_NOBUF Operation failed because timeout buffer not
 * specified in call and not present in timer
 */
int odp_timer_set_rel(odp_timer_t tim,
		      uint64_t rel_tck,
		      odp_buffer_t *tmo_buf);

/**
 * Cancel a timer
 *
 * Cancel a timer, preventing future expiration and delivery. Return any
 * present timeout buffer.
 *
 * A timer that has already expired may be impossible to cancel and the timeout
 * will instead be delivered to the destination queue.
 *
 * Note: any invalid parameters will be treated as programming errors and will
 * cause the application to abort.
 *
 * @param tim     Timer
 * @param[out] tmo_buf Pointer to a buffer variable
 * @retval 0  Success, active timer cancelled, timeout returned in '*tmo_buf'
 * @retval -1 Failure, timer already expired (or inactive)
 */
int odp_timer_cancel(odp_timer_t tim, odp_buffer_t *tmo_buf);

/**
 * Return timeout handle that is associated with timeout buffer
 *
 * Note: any invalid parameters will cause undefined behavior and may cause
 * the application to abort or crash.
 *
 * @param buf A buffer of type ODP_BUFFER_TYPE_TIMEOUT
 *
 * @return timeout handle
 */
odp_timeout_t odp_timeout_from_buf(odp_buffer_t buf);

/**
 * Check for fresh timeout
 * If the corresponding timer has been reset or cancelled since this timeout
 * was enqueued, the timeout is stale (not fresh).
 *
 * @param tmo Timeout handle
 * @retval 1 Timeout is fresh
 * @retval 0 Timeout is stale
 */
int odp_timeout_fresh(odp_timeout_t tmo);

/**
 * Return timer handle for the timeout
 *
 * Note: any invalid parameters will cause undefined behavior and may cause
 * the application to abort or crash.
 *
 * @param tmo Timeout handle
 *
 * @return Timer handle
 */
odp_timer_t odp_timeout_timer(odp_timeout_t tmo);

/**
 * Return expiration tick for the timeout
 *
 * Note: any invalid parameters will cause undefined behavior and may cause
 * the application to abort or crash.
 *
 * @param tmo Timeout handle
 *
 * @return Expiration tick
 */
uint64_t odp_timeout_tick(odp_timeout_t tmo);

/**
 * Return user pointer for the timeout
 * The user pointer was specified when the timer was allocated.
 *
 * Note: any invalid parameters will cause undefined behavior and may cause
 * the application to abort or crash.
 *
 * @param tmo Timeout handle
 *
 * @return User pointer
 */
void *odp_timeout_user_ptr(odp_timeout_t tmo);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

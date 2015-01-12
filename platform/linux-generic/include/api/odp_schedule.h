/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP schedule
 */

#ifndef ODP_SCHEDULE_H_
#define ODP_SCHEDULE_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp_std_types.h>
#include <odp_buffer.h>
#include <odp_queue.h>

/** @defgroup odp_scheduler ODP SCHEDULER
 *  Operations on the scheduler.
 *  @{
 */

#define ODP_SCHED_WAIT     0  /**< Wait infinitely */
#define ODP_SCHED_NO_WAIT  1  /**< Do not wait */


/**
 * Schedule wait time
 *
 * Converts nanoseconds to wait values for other schedule functions.
 *
 * @param ns Nanoseconds
 *
 * @return Value for the wait parameter in schedule functions
 */
uint64_t odp_schedule_wait_time(uint64_t ns);

/**
 * Schedule
 *
 * Schedules all queues created with ODP_QUEUE_TYPE_SCHED type. Returns
 * next highest priority buffer which is available for the calling thread.
 * Outputs the source queue of the buffer. If there's no buffer available, waits
 * for a buffer according to the wait parameter setting. Returns
 * ODP_BUFFER_INVALID if reaches end of the wait period.
 *
 * @param from    Output parameter for the source queue (where the buffer was
 *                dequeued from). Ignored if NULL.
 * @param wait    Minimum time to wait for a buffer. Waits infinitely, if set to
 *                ODP_SCHED_WAIT. Does not wait, if set to ODP_SCHED_NO_WAIT.
 *                Use odp_schedule_wait_time() to convert time to other wait
 *                values.
 *
 * @return Next highest priority buffer, or ODP_BUFFER_INVALID
 */
odp_buffer_t odp_schedule(odp_queue_t *from, uint64_t wait);

/**
 * Schedule multiple buffers
 *
 * Like odp_schedule(), but returns multiple buffers from a queue.
 *
 * @param from    Output parameter for the source queue (where the buffer was
 *                dequeued from). Ignored if NULL.
 * @param wait    Minimum time to wait for a buffer. Waits infinitely, if set to
 *                ODP_SCHED_WAIT. Does not wait, if set to ODP_SCHED_NO_WAIT.
 *                Use odp_schedule_wait_time() to convert time to other wait
 *                values.
 * @param out_buf Buffer array for output
 * @param num     Maximum number of buffers to output
 *
 * @return Number of buffers outputed (0 ... num)
 */
int odp_schedule_multi(odp_queue_t *from, uint64_t wait, odp_buffer_t out_buf[],
		       unsigned int num);

/**
 * Pause scheduling
 *
 * Pause global scheduling for this thread. After this call, all schedule calls
 * will return only locally reserved buffers (if any). User can exit the
 * schedule loop only after the schedule function indicates that there's no more
 * buffers (no more locally reserved buffers).
 *
 * Must be used with odp_schedule() and odp_schedule_multi() before exiting (or
 * stalling) the schedule loop.
 */
void odp_schedule_pause(void);

/**
 * Resume scheduling
 *
 * Resume global scheduling for this thread. After this call, all schedule calls
 * will schedule normally (perform global scheduling).
 */
void odp_schedule_resume(void);

/**
 * Release currently hold atomic context
 */
void odp_schedule_release_atomic(void);

/**
 * Number of scheduling priorities
 *
 * @return Number of scheduling priorities
 */
int odp_schedule_num_prio(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

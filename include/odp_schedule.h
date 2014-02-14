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


#include <odp_buffer.h>
#include <odp_queue.h>


/**
 * Schedule once
 *
 * Schedules all queues created with ODP_QUEUE_TYPE_SCHED type. Returns
 * next highest priority buffer which is available for the calling thread.
 * Outputs the source queue. Returns ODP_BUFFER_INVALID if no buffer
 * was available.
 *
 * @param from    Queue pointer for outputing the queue where the buffer was
 *                dequeued from. Ignored if NULL.
 *
 * @return Next highest priority buffer, or ODP_BUFFER_INVALID
 */
odp_buffer_t odp_schedule_once(odp_queue_t *from);

/**
 * Schedule
 *
 * Like odp_schedule_once(), but blocks until a buffer is available.
 *
 * @param from    Queue pointer for outputing the queue where the buffer was
 *                dequeued from. Ignored if NULL.
 *
 * @return Next highest priority buffer
 */
odp_buffer_t odp_schedule(odp_queue_t *from);

/**
 * Schedule, non-blocking
 *
 * Like odp_schedule(), but returns after 'n' empty schedule rounds.
 *
 * @param from    Queue pointer for outputing the queue where the buffer was
 *                dequeued from. Ignored if NULL.
 * @param n       Number of empty schedule rounds before returning
 *                ODP_BUFFER_INVALID
 *
 * @return Next highest priority buffer, or ODP_BUFFER_INVALID
 */
odp_buffer_t odp_schedule_n(odp_queue_t *from, unsigned int n);

/**
 * Schedule, multiple buffers
 *
 * Like odp_schedule(), but returns multiple buffers from a queue.
 *
 * @param from    Queue pointer for outputing the queue where the buffers were
 *                dequeued from. Ignored if NULL.
 * @param out_buf Buffer array for output
 * @param num     Maximum number of buffers to output
 *
 * @return Number of buffers outputed (0 ... num)
 */
int odp_schedule_multi(odp_queue_t *from, odp_buffer_t out_buf[],
		       unsigned int num);

/**
 * Schedule, multiple buffers, non-blocking
 *
 * Like odp_schedule_multi(), but returns after 'n' empty schedule rounds.
 *
 * @param from    Queue pointer for outputing the queue where the buffers were
 *                dequeued from. Ignored if NULL.
 * @param out_buf Buffer array for output
 * @param num     Maximum number of buffers to output
 * @param n       Number of empty schedule rounds before returning
 *                ODP_BUFFER_INVALID
 *
 * @return Number of buffers outputed (0 ... num)
 */
int odp_schedule_multi_n(odp_queue_t *from, odp_buffer_t out_buf[],
			 unsigned int num, unsigned int n);

/**
 * Number of scheduling priorities
 *
 * @return Number of scheduling priorities
 */
int odp_schedule_num_prio(void);

/**
 * Release currently hold atomic context
 */
void odp_schedule_release_atomic_context(void);


#ifdef __cplusplus
}
#endif

#endif



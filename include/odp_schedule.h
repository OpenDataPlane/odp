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


/**
 * Schedule
 *
 * Schedules all queues created with ODP_QUEUE_TYPE_SCHED type. Returns
 * next highest priority buffer which is available for the calling thread.
 * Returns ODP_BUFFER_INVALID if no buffer was available.
 *
 * @return Next highest priority buffer from scheduling, or ODP_BUFFER_INVALID
 */
odp_buffer_t odp_schedule(void);

/**
 * Schedule poll
 *
 * Schedules all queues created with ODP_QUEUE_TYPE_SCHED type. Returns
 * next highest priority buffer which is available for the calling thread.
 * Waits until a buffer is available.
 *
 * @return Next highest priority buffer from scheduling
 */
odp_buffer_t odp_schedule_poll(void);


/**
 * Number of scheduling priorities
 *
 * @return Number of scheduling priorities
 */
int odp_schedule_num_prio(void);


#ifdef __cplusplus
}
#endif

#endif



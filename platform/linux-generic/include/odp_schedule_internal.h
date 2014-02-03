/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */



#ifndef ODP_SCHEDULE_INTERNAL_H_
#define ODP_SCHEDULE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp_buffer.h>
#include <odp_queue.h>


odp_buffer_t odp_schedule_buffer_alloc(odp_queue_t queue);

void odp_schedule_queue(odp_queue_t queue, int prio);


#ifdef __cplusplus
}
#endif

#endif



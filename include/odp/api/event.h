/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP event
 */

#ifndef ODP_EVENT_H_
#define ODP_EVENT_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp/std_types.h>
#include <odp/platform_types.h>

/** @defgroup odp_event ODP EVENT
 *  Operations on an event.
 *  @{
 */


/**
 * Event type
 *
 * @param event    Event handle
 *
 * @return Event type or ODP_EVENT_TYPE_INVALID
 */
int odp_event_type(odp_event_t event);

/** Invalid event type */
#define ODP_EVENT_TYPE_INVALID (-1)
/** Buffer event */
#define ODP_EVENT_BUFFER         1
/** Packet event */
#define ODP_EVENT_PACKET         2
/** Timeout event */
#define ODP_EVENT_TIMEOUT        3



/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

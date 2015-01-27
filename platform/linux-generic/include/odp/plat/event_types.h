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

#ifndef ODP_EVENT_TYPES_H_
#define ODP_EVENT_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp/plat/buffer_types.h>

/** @defgroup odp_event ODP EVENT
 *  Operations on an event.
 *  @{
 */

typedef odp_buffer_t odp_event_t;

#define ODP_EVENT_INVALID ODP_BUFFER_INVALID

#define ODP_EVENT_TYPE_INVALID (-1)
#define ODP_EVENT_BUFFER         1
#define ODP_EVENT_PACKET         2
#define ODP_EVENT_TIMEOUT        3

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

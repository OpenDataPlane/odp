/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP queue
 */

#ifndef ODP_PLAT_QUEUE_H_
#define ODP_PLAT_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/event_types.h>
#include <odp/api/plat/queue_types.h>
#include <odp/api/plat/buffer_types.h>
#include <odp/api/plat/pool_types.h>

/** @ingroup odp_queue
 *  @{
 */

/* REMOVE FROM API SPEC. Typedef needed only for suppressing Doxygen
 * warning. */
typedef void odp_queue_group_t;

/**
 * @}
 */

#include <odp/api/spec/queue.h>

#ifdef __cplusplus
}
#endif

#endif

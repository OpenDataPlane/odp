/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP schedule
 */

#ifndef ODP_ABI_SCHEDULE_H_
#define ODP_ABI_SCHEDULE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @addtogroup odp_scheduler
 *  @{
 */

#define ODP_SCHED_WAIT     UINT64_MAX
#define ODP_SCHED_NO_WAIT  0

#define ODP_SCHED_GROUP_NAME_LEN 32

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

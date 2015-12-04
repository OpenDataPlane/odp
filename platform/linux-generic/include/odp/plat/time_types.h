/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP time service
 */

#ifndef ODP_TIME_TYPES_H_
#define ODP_TIME_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_time
 *  @{
 **/

typedef struct timespec odp_time_t;

odp_time_t odp_time_null(void);

#define ODP_TIME_NULL	odp_time_null()

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

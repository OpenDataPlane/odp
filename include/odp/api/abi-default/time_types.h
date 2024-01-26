/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

#ifndef ODP_ABI_TIME_TYPES_H_
#define ODP_ABI_TIME_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_time
 *  @{
 **/

typedef uint64_t odp_time_t;

#define ODP_TIME_NULL ((odp_time_t)0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

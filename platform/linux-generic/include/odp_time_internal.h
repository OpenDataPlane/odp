/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_TIME_INTERNAL_H_
#define ODP_TIME_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int cpu_has_global_time(void);
uint64_t cpu_global_time(void);
uint64_t cpu_global_time_freq(void);

#ifdef __cplusplus
}
#endif

#endif

/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP system information
 */

#ifndef ODP_SYSTEM_INFO_H_
#define ODP_SYSTEM_INFO_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp_std_types.h>


/**
 * CPU frequency in Hz
 *
 * @return CPU frequency in Hz
 */
uint64_t odp_sys_cpu_hz(void);

/**
 * CPU model name
 *
 * @return Pointer to CPU model name string
 */
const char *odp_sys_cpu_model_str(void);

/**
 * Cache line size in bytes
 *
 * @return CPU cache line size in bytes
 */
int odp_sys_cache_line_size(void);

/**
 * Core count
 *
 * @return Core count
 */
int odp_sys_core_count(void);


#ifdef __cplusplus
}
#endif

#endif








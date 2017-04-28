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

#ifndef ODP_API_SYSTEM_INFO_H_
#define ODP_API_SYSTEM_INFO_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_system ODP SYSTEM
 *  @{
 */

/**
 * Default system huge page size in bytes
 *
 * @return Default huge page size in bytes
 */
uint64_t odp_sys_huge_page_size(void);

/**
 * Page size in bytes
 *
 * @return Page size in bytes
 */
uint64_t odp_sys_page_size(void);

/**
 * Cache line size in bytes
 *
 * @return CPU cache line size in bytes
 */
int odp_sys_cache_line_size(void);

/**
 * Print system info
 *
 * Print out implementation defined information about the system. This
 * information is intended for debugging purposes and may contain e.g.
 * information about CPUs, memory and other HW configuration.
 */
void odp_sys_info_print(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

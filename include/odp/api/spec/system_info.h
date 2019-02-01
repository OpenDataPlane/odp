/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP system information
 */

#ifndef ODP_API_SPEC_SYSTEM_INFO_H_
#define ODP_API_SPEC_SYSTEM_INFO_H_
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
 * @retval 0 on no huge pages
 */
uint64_t odp_sys_huge_page_size(void);

/**
 * System huge page sizes in bytes
 *
 * Returns the number of huge page sizes supported by the system. Outputs up to
 * 'num' sizes when the 'size' array pointer is not NULL. If return value is
 * larger than 'num', there are more supported sizes than the function was
 * allowed to output. If return value (N) is less than 'num', only sizes
 * [0 ... N-1] have been written. Returned values are ordered from smallest to
 * largest.
 *
 * @param[out] size     Points to an array of huge page sizes for output
 * @param      num      Maximum number of huge page sizes to output
 *
 * @return Number of supported huge page sizes
 * @retval <0 on failure
 */
int odp_sys_huge_page_size_all(uint64_t size[], int num);

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

/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP CPU API
 */

#ifndef ODP_CPU_H_
#define ODP_CPU_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_cpu ODP CPU
 *  @{
 */


/**
 * CPU identifier
 *
 * Determine CPU identifier on which the calling is running. CPU numbering is
 * system specific.
 *
 * @return CPU identifier
 */
int odp_cpu_id(void);

/**
 * CPU count
 *
 * Report the number of CPU's available to this ODP program.
 * This may be smaller than the number of (online) CPU's in the system.
 *
 * @return Number of available CPU's
 */
int odp_cpu_count(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

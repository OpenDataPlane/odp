/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP shared memory
 */

#ifndef ODP_SHARED_MEMORY_TYPES_H_
#define ODP_SHARED_MEMORY_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_shared_memory ODP SHARED MEMORY
 *  Operations on shared memory.
 *  @{
 */

typedef uint32_t odp_shm_t;

#define ODP_SHM_INVALID 0
#define ODP_SHM_NULL ODP_SHM_INVALID

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

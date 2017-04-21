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

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 1
#include <odp/api/abi/shared_memory.h>
#else

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @ingroup odp_shared_memory
 *  @{
 */

typedef ODP_HANDLE_T(odp_shm_t);

#define ODP_SHM_INVALID _odp_cast_scalar(odp_shm_t, 0)
#define ODP_SHM_NULL ODP_SHM_INVALID

#define ODP_SHM_NAME_LEN 32

/**
 * @}
 */

#endif

#ifdef __cplusplus
}
#endif

#endif

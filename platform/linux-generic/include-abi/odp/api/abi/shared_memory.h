/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */


/**
 * @file
 *
 * ODP shared memory
 */

#ifndef ODP_API_ABI_SHARED_MEMORY_H_
#define ODP_API_ABI_SHARED_MEMORY_H_

#include <odp/api/std_types.h>

#include <odp/api/plat/strong_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_shared_memory
 *  @{
 */

typedef ODP_HANDLE_T(odp_shm_t);

#define ODP_SHM_INVALID _odp_cast_scalar(odp_shm_t, 0)

#define ODP_SHM_NAME_LEN 64

#define ODP_SHM_IOVA_INVALID ((uint64_t)-1)
#define ODP_SHM_PA_INVALID   ODP_SHM_IOVA_INVALID

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

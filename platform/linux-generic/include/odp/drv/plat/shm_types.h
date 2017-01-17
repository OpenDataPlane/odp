/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP shared memory
 */

#ifndef ODPDRV_SHM_TYPES_H_
#define ODPDRV_SHM_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/drv/std_types.h>
#include <odp/drv/plat/strong_types.h>

/** @addtogroup odpdrv_shm ODPDRV SHARED MEMORY
 *  Operations on driver shared memory.
 *  @{
 */

typedef ODPDRV_HANDLE_T(odpdrv_shm_t);

#define ODPDRV_SHM_INVALID _odpdrv_cast_scalar(odpdrv_shm_t, 0)

/** Get printable format of odpdrv_shm_t */
static inline uint64_t odpdrv_shm_to_u64(odpdrv_shm_t hdl)
{
	return _odpdrv_pri(hdl);
}

typedef ODPDRV_HANDLE_T(odpdrv_shm_pool_t);

#define ODPDRV_SHM_POOL_INVALID _odpdrv_cast_scalar(odpdrv_shm_pool_t, NULL)
/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

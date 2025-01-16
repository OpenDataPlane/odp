/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 */

#ifndef ODP_ABI_SHM_H_
#define ODP_ABI_SHM_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_shm_t;

/** @addtogroup odp_shared_memory
 *  @{
 */

typedef _odp_abi_shm_t *odp_shm_t;

#define ODP_SHM_INVALID   ((odp_shm_t)0)
#define ODP_SHM_NAME_LEN  64

#define ODP_SHM_IOVA_INVALID ((uint64_t)-1)
#define ODP_SHM_PA_INVALID   ODP_SHM_IOVA_INVALID

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

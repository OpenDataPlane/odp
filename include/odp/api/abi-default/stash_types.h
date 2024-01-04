/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_ABI_STASH_TYPES_H_
#define ODP_ABI_STASH_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_stash_t;

/** @addtogroup odp_stash
 *  @{
 */

typedef _odp_abi_stash_t *odp_stash_t;

#define ODP_STASH_INVALID   ((odp_stash_t)0)

#define ODP_STASH_NAME_LEN  32

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

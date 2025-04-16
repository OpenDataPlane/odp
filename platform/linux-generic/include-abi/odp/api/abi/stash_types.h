/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Nokia
 */

/**
 * @file
 */

#ifndef ODP_API_ABI_STASH_TYPES_H_
#define ODP_API_ABI_STASH_TYPES_H_

#include <odp/api/plat/strong_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_stash
 *  @{
 */

typedef ODP_HANDLE_T(odp_stash_t);

#define ODP_STASH_INVALID _odp_cast_scalar(odp_stash_t, 0)

#define ODP_STASH_NAME_LEN  32

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

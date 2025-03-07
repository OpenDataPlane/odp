/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 */

#ifndef ODP_ABI_COMP_H_
#define ODP_ABI_COMP_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_comp_session_t;

/** @addtogroup odp_compression
 *  @{
 */

typedef _odp_abi_comp_session_t *odp_comp_session_t;

#define ODP_COMP_SESSION_INVALID        ((odp_comp_session_t)0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

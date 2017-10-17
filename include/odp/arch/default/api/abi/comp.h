/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_COMP_H_
#define ODP_ABI_COMP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_comp_compl_t;

/** @ingroup odp_comp
 *  @{
 */

#define ODP_COMP_SESSION_INVALID (0xffffffffffffffffULL)

typedef uint64_t  odp_comp_session_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

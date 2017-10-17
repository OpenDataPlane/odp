/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP comp
 */

#ifndef ODP_COMP_TYPES_H_
#define ODP_COMP_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 1
#include <odp/api/abi/comp.h>
#else
/** @addtogroup odp_comp
 *  @{
 */

#define ODP_COMP_SESSION_INVALID (0xffffffffffffffffULL)

typedef uint64_t odp_comp_session_t;

/**
 * @}
 */

#endif

#ifdef __cplusplus
}
#endif

#endif

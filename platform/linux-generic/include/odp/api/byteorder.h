/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP byteorder
 */

#ifndef ODP_PLAT_BYTEORDER_H_
#define ODP_PLAT_BYTEORDER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/byteorder_types.h>
#include <odp/api/compiler.h>

/** @ingroup odp_compiler_optim
 *  @{
 */

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 0
#include <odp/api/plat/byteorder_inlines.h>
#endif

/**
 * @}
 */

#include <odp/api/spec/byteorder.h>

#ifdef __cplusplus
}
#endif

#endif

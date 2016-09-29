/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP atomic operations
 */

#ifndef ODP_PLAT_ATOMIC_H_
#define ODP_PLAT_ATOMIC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/plat/atomic_types.h>

/** @ingroup odp_atomic
 *  @{
 */

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 0
#include <odp/api/plat/atomic_inlines.h>
#endif

/**
 * @}
 */

#include <odp/api/spec/atomic.h>

#ifdef __cplusplus
}
#endif

#endif

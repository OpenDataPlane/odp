/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP synchronisation
 */

#ifndef ODP_PLAT_SYNC_H_
#define ODP_PLAT_SYNC_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odp_barrier
 *  @{
 */

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 0
#include <odp/api/plat/sync_inlines.h>
#endif

/**
 * @}
 */

#include <odp/api/spec/sync.h>

#ifdef __cplusplus
}
#endif

#endif

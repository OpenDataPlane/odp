/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP ticketlock
 */

#ifndef ODP_PLAT_TICKETLOCK_H_
#define ODP_PLAT_TICKETLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/ticketlock_types.h>

#if ODP_ABI_COMPAT == 0
#include <odp/api/plat/ticketlock_inlines.h>
#endif

#include <odp/api/spec/ticketlock.h>

#ifdef __cplusplus
}
#endif

#endif

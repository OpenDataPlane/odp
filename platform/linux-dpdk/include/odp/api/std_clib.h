/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_STD_CLIB_H_
#define ODP_PLAT_STD_CLIB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/spec/std_types.h>
#include <string.h>

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 0
#include <odp/api/plat/std_clib_inlines.h>
#endif

#include <odp/api/spec/std_clib.h>

#ifdef __cplusplus
}
#endif

#endif

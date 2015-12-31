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

#include <odp/api/std_types.h>

static inline void *odp_memcpy(void *dst, const void *src, size_t num)
{
	return memcpy(dst, src, num);
}

static inline void *odp_memset(void *ptr, int value, size_t num)
{
	return memset(ptr, value, num);
}

#ifdef __cplusplus
}
#endif

#endif

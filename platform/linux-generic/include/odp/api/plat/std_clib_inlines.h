/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_STD_CLIB_INLINE_H_
#define ODP_PLAT_STD_CLIB_INLINE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/spec/std_types.h>
#include <string.h>

_ODP_INLINE void *odp_memcpy(void *dst, const void *src, size_t num)
{
	return memcpy(dst, src, num);
}

_ODP_INLINE void *odp_memset(void *ptr, int value, size_t num)
{
	return memset(ptr, value, num);
}

_ODP_INLINE int odp_memcmp(const void *ptr1, const void *ptr2, size_t num)
{
	return memcmp(ptr1, ptr2, num);
}

#ifdef __cplusplus
}
#endif

#endif

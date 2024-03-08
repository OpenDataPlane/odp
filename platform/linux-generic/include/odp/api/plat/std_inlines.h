/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */

#ifndef ODP_PLAT_STD_INLINE_H_
#define ODP_PLAT_STD_INLINE_H_

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <string.h>

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_memcpy __odp_memcpy
	#define odp_memset __odp_memset
	#define odp_memcmp __odp_memcmp
#else
	#define _ODP_INLINE
#endif

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

/** @endcond */

#endif

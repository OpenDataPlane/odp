/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_memcpy.h>

#if defined(__arm__) || defined(__aarch64__)
static void *_rte_memcpy(void *dst, const void *src, size_t n)
{
	return rte_memcpy(dst, src, n);
}

void* (*const dpdk_memcpy)(void*, const void*, size_t) = &_rte_memcpy;
#else
void* (*const dpdk_memcpy)(void*, const void*, size_t) = &rte_memcpy;
#endif

#ifdef __cplusplus
}
#endif

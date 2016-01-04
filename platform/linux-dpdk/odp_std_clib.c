/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_memcpy.h>

void* (*const dpdk_memcpy)(void*, const void*, size_t) = &rte_memcpy;

#ifdef __cplusplus
}
#endif

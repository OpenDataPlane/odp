/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP version of often used C library calls
 */

#ifndef ODP_API_STD_CLIB_H_
#define ODP_API_STD_CLIB_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odp_std_clib ODP STD CLIB
 * @details
 * ODP version of often used C library calls
 * @{
 */

/**
 * Memcpy
 *
 * ODP version of C library memcpy function. It copies 'num' bytes from source
 * to destination address. Source and destination memory blocks must not
 * overlap.
 *
 * @param dst    Pointer to destination memory block
 * @param src    Pointer to source memory block
 * @param num    Number of bytes to copy
 *
 * @return 'dst' address
 */
void *odp_memcpy(void *dst, const void *src, size_t num);

/**
 * Memset
 *
 * ODP version of C library memset function. It sets 'value' to first 'num'
 * bytes of memory block pointed by 'ptr'.
 *
 * @param ptr    Pointer to the memory block
 * @param value  Value to be set
 * @param num    Number of bytes to set
 *
 * @return 'ptr' address
 */
void *odp_memset(void *ptr, int value, size_t num);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

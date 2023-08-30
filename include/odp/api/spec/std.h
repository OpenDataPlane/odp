/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

/**
 * @file
 *
 * ODP standard types and optimized C library functions
 */

#ifndef ODP_API_SPEC_STD_H_
#define ODP_API_SPEC_STD_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/**
 * @defgroup odp_std ODP STD
 * Standard types and performance optimized versions of selected C library
 * functions.
 *
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
 * Memcmp
 *
 * ODP version of C library memcmp function. It compares first 'num' bytes of
 * memory blocks pointed by 'ptr1' and 'ptr2'.
 *
 * @param ptr1   Pointer to a memory block
 * @param ptr2   Pointer to a memory block
 * @param num    Number of bytes to compare
 *
 * @retval 0  when the contents of memory blocks match
 * @retval <0 when the contents of memory blocks do not match, and
 *            block 'ptr1' is less than block 'ptr2'
 * @retval >0 when the contents of memory blocks do not match, and
 *            block 'ptr1' is greater than block 'ptr2'
 */
int odp_memcmp(const void *ptr1, const void *ptr2, size_t num);

/**
 * Convert fractional number (u64) to double
 *
 * Converts value of the unsigned 64 bit fractional number to a double-precision
 * floating-point value.
 *
 * @param fract  Pointer to a fractional number
 *
 * @return Value of the fractional number as double
 */
double odp_fract_u64_to_dbl(const odp_fract_u64_t *fract);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP byteorder
 */

#ifndef ODP_BYTEORDER_TYPES_H_
#define ODP_BYTEORDER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __BYTE_ORDER
#error __BYTE_ORDER not defined!
#endif

#ifndef __BIG_ENDIAN
#error __BIG_ENDIAN not defined!
#endif

#ifndef __LITTLE_ENDIAN
#error __LITTLE_ENDIAN not defined!
#endif


/* for use with type checkers such as sparse */
#ifdef __CHECKER__
/** @internal bitwise attribute */
#define __odp_bitwise	__attribute__((bitwise))
/** @internal force attribute */
#define __odp_force     __attribute__((force))
#else
/** @internal bitwise attribute */
#define __odp_bitwise
/** @internal force attribute */
#define __odp_force
#endif


/** @addtogroup odp_compiler_optim
 *  @{
 */

#define ODP_BIG_ENDIAN    __BIG_ENDIAN

#define ODP_LITTLE_ENDIAN __LITTLE_ENDIAN

#ifdef __BIG_ENDIAN_BITFIELD
#define ODP_BIG_ENDIAN_BITFIELD
#endif

#ifdef __LITTLE_ENDIAN_BITFIELD
#define ODP_LITTLE_ENDIAN_BITFIELD
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ODP_BYTE_ORDER ODP_LITTLE_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ODP_BYTE_ORDER ODP_BIG_ENDIAN
#endif

typedef uint16_t __odp_bitwise	uint16le_t;
typedef uint16_t __odp_bitwise	uint16be_t;

typedef uint32_t __odp_bitwise	uint32le_t;
typedef uint32_t __odp_bitwise	uint32be_t;

typedef uint64_t __odp_bitwise	uint64le_t;
typedef uint64_t __odp_bitwise	uint64be_t;

typedef uint16_t __odp_bitwise  uint16sum_t;
typedef uint32_t __odp_bitwise  uint32sum_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

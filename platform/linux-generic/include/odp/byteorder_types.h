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

/** @addtogroup odp_compiler_optim
 *  @{
 */

#ifndef __BYTE_ORDER
#error __BYTE_ORDER not defined!
#endif

#ifndef __BIG_ENDIAN
#error __BIG_ENDIAN not defined!
#endif

#ifndef __LITTLE_ENDIAN
#error __LITTLE_ENDIAN not defined!
#endif

/** Big endian byte order */
#define ODP_BIG_ENDIAN    __BIG_ENDIAN

/** Little endian byte order */
#define ODP_LITTLE_ENDIAN __LITTLE_ENDIAN

/** Big endian bit field */
#ifdef __BIG_ENDIAN_BITFIELD
#define ODP_BIG_ENDIAN_BITFIELD
#endif

/** Little endian bit field */
#ifdef __LITTLE_ENDIAN_BITFIELD
#define ODP_LITTLE_ENDIAN_BITFIELD
#endif

/** Selected byte order */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ODP_BYTE_ORDER ODP_LITTLE_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ODP_BYTE_ORDER ODP_BIG_ENDIAN
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


typedef uint16_t __odp_bitwise	uint16le_t; /**< unsigned 16bit little endian */
typedef uint16_t __odp_bitwise	uint16be_t; /**< unsigned 16bit big endian */

typedef uint32_t __odp_bitwise	uint32le_t; /**< unsigned 32bit little endian */
typedef uint32_t __odp_bitwise	uint32be_t; /**< unsigned 32bit big endian */

typedef uint64_t __odp_bitwise	uint64le_t; /**< unsigned 64bit little endian */
typedef uint64_t __odp_bitwise	uint64be_t; /**< unsigned 64bit big endian */

typedef uint16_t __odp_bitwise  uint16sum_t; /**< unsigned 16bit bitwise */
typedef uint32_t __odp_bitwise  uint32sum_t; /**< unsigned 32bit bitwise */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

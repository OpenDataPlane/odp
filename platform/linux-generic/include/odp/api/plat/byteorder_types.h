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

#ifndef __BYTE_ORDER__
#error __BYTE_ORDER not defined!
#endif

#ifndef __ORDER_BIG_ENDIAN__
#error __BIG_ENDIAN not defined!
#endif

#ifndef __ORDER_LITTLE_ENDIAN__
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
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	#define ODP_LITTLE_ENDIAN           1
	#define ODP_BIG_ENDIAN              0
	#define ODP_BYTE_ORDER              ODP_LITTLE_ENDIAN
	#define ODP_LITTLE_ENDIAN_BITFIELD  1
	#define ODP_BIG_ENDIAN_BITFIELD     0
	#define ODP_BITFIELD_ORDER          ODP_LITTLE_ENDIAN_BITFIELD
#else
	#define ODP_LITTLE_ENDIAN           0
	#define ODP_BIG_ENDIAN              1
	#define	ODP_BYTE_ORDER              ODP_BIG_ENDIAN
	#define ODP_LITTLE_ENDIAN_BITFIELD  0
	#define ODP_BIG_ENDIAN_BITFIELD     1
	#define ODP_BITFIELD_ORDER          ODP_BIG_ENDIAN_BITFIELD
#endif

typedef uint16_t __odp_bitwise	odp_u16le_t;
typedef uint16_t __odp_bitwise	odp_u16be_t;

typedef uint32_t __odp_bitwise	odp_u32le_t;
typedef uint32_t __odp_bitwise	odp_u32be_t;

typedef uint64_t __odp_bitwise	odp_u64le_t;
typedef uint64_t __odp_bitwise	odp_u64be_t;

typedef uint16_t __odp_bitwise  odp_u16sum_t;
typedef uint32_t __odp_bitwise  odp_u32sum_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

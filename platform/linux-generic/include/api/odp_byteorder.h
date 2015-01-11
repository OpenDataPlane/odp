/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP byteorder
 */

#ifndef ODP_BYTEORDER_H_
#define ODP_BYTEORDER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <endian.h>
#include <asm/byteorder.h>
#include <odp_std_types.h>
#include <odp_compiler.h>

/** @defgroup odp_compiler_optim ODP COMPILER / OPTIMIZATION
 *  Macros that check byte order and byte converting operations.
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
/*
 * Big Endian -> CPU byte order:
 */

/**
 * Convert 16bit big endian to cpu native uint16_t
 * @param be16  big endian 16bit
 * @return  cpu native uint16_t
 */
static inline uint16_t odp_be_to_cpu_16(uint16be_t be16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return __odp_builtin_bswap16((__odp_force uint16_t)be16);
#else
	return (__odp_force uint16_t)be16;
#endif
}

/**
 * Convert 32bit big endian to cpu native uint32_t
 * @param be32  big endian 32bit
 * @return  cpu native uint32_t
 */
static inline uint32_t odp_be_to_cpu_32(uint32be_t be32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return __builtin_bswap32((__odp_force uint32_t)be32);
#else
	return (__odp_force uint32_t)be32;
#endif
}

/**
 * Convert 64bit big endian to cpu native uint64_t
 * @param be64  big endian 64bit
 * @return  cpu native uint64_t
 */
static inline uint64_t odp_be_to_cpu_64(uint64be_t be64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return __builtin_bswap64((__odp_force uint64_t)be64);
#else
	return (__odp_force uint64_t)be64;
#endif
}


/*
 * CPU byte order -> Big Endian:
 */

/**
 * Convert cpu native uint16_t to 16bit big endian
 * @param cpu16  uint16_t in cpu native format
 * @return  big endian 16bit
 */
static inline uint16be_t odp_cpu_to_be_16(uint16_t cpu16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint16be_t)__odp_builtin_bswap16(cpu16);
#else
	return (__odp_force uint16be_t)cpu16;
#endif
}

/**
 * Convert cpu native uint32_t to 32bit big endian
 * @param cpu32  uint32_t in cpu native format
 * @return  big endian 32bit
 */
static inline uint32be_t odp_cpu_to_be_32(uint32_t cpu32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint32be_t)__builtin_bswap32(cpu32);
#else
	return (__odp_force uint32be_t)cpu32;
#endif
}

/**
 * Convert cpu native uint64_t to 64bit big endian
 * @param cpu64  uint64_t in cpu native format
 * @return  big endian 64bit
 */
static inline uint64be_t odp_cpu_to_be_64(uint64_t cpu64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint64be_t)__builtin_bswap64(cpu64);
#else
	return (__odp_force uint64be_t)cpu64;
#endif
}


/*
 * Little Endian -> CPU byte order:
 */

/**
 * Convert 16bit little endian to cpu native uint16_t
 * @param le16  little endian 16bit
 * @return  cpu native uint16_t
 */
static inline uint16_t odp_le_to_cpu_16(uint16le_t le16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint16_t)le16;
#else
	return __odp_builtin_bswap16((__odp_force uint16_t)le16);
#endif
}

/**
 * Convert 32bit little endian to cpu native uint32_t
 * @param le32  little endian 32bit
 * @return  cpu native uint32_t
 */
static inline uint32_t odp_le_to_cpu_32(uint32le_t le32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint32_t)le32;
#else
	return __builtin_bswap32((__odp_force uint32_t)le32);
#endif
}

/**
 * Convert 64bit little endian to cpu native uint64_t
 * @param le64  little endian 64bit
 * @return  cpu native uint64_t
 */
static inline uint64_t odp_le_to_cpu_64(uint64le_t le64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint64_t)le64;
#else
	return __builtin_bswap64((__odp_force uint64_t)le64);
#endif
}


/*
 * CPU byte order -> Little Endian:
 */

/**
 * Convert cpu native uint16_t to 16bit little endian
 * @param cpu16  uint16_t in cpu native format
 * @return  little endian 16bit
 */
static inline uint16le_t odp_cpu_to_le_16(uint16_t cpu16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint16le_t)cpu16;
#else
	return (__odp_force uint16le_t)__odp_builtin_bswap16(cpu16);
#endif
}

/**
 * Convert cpu native uint32_t to 32bit little endian
 * @param cpu32  uint32_t in cpu native format
 * @return  little endian 32bit
 */
static inline uint32le_t odp_cpu_to_le_32(uint32_t cpu32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint32le_t)cpu32;
#else
	return (__odp_force uint32le_t)__builtin_bswap32(cpu32);
#endif
}

/**
 * Convert cpu native uint64_t to 64bit little endian
 * @param cpu64  uint64_t in cpu native format
 * @return  little endian 64bit
 */
static inline uint64le_t odp_cpu_to_le_64(uint64_t cpu64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint64le_t)cpu64;
#else
	return (__odp_force uint64le_t)__builtin_bswap64(cpu64);
#endif
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

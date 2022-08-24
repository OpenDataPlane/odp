/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP byteorder
 */

#ifndef ODP_PLAT_BYTEORDER_INLINES_H_
#define ODP_PLAT_BYTEORDER_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/abi/byteorder.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef __odp_force
#define __odp_force
#endif

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_be_to_cpu_16 __odp_be_to_cpu_16
	#define odp_be_to_cpu_32 __odp_be_to_cpu_32
	#define odp_be_to_cpu_64 __odp_be_to_cpu_64
	#define odp_cpu_to_be_16 __odp_cpu_to_be_16
	#define odp_cpu_to_be_32 __odp_cpu_to_be_32
	#define odp_cpu_to_be_64 __odp_cpu_to_be_64
	#define odp_le_to_cpu_16 __odp_le_to_cpu_16
	#define odp_le_to_cpu_32 __odp_le_to_cpu_32
	#define odp_le_to_cpu_64 __odp_le_to_cpu_64
	#define odp_cpu_to_le_16 __odp_cpu_to_le_16
	#define odp_cpu_to_le_32 __odp_cpu_to_le_32
	#define odp_cpu_to_le_64 __odp_cpu_to_le_64
#else
	#define _ODP_INLINE
#endif

/** @internal GNU compiler version */
#define GCC_VERSION (__GNUC__ * 10000 \
			+ __GNUC_MINOR__ * 100 \
			+ __GNUC_PATCHLEVEL__)

/**
 * @internal
 * Compiler __builtin_bswap16() is not available on all platforms
 * until GCC 4.8.0 - work around this by offering __odp_builtin_bswap16()
 * Don't use this function directly, instead see odp_byteorder.h
 */
#if GCC_VERSION < 40800
/*
 * We have to explicitly cast back to uint16_t because clang promotes the
 * left side of << operator to int.
 */
#define __odp_builtin_bswap16(u16) ((uint16_t)(((u16)&0x00ff) << 8) | \
				    (((u16)&0xff00) >> 8))
#else
#define __odp_builtin_bswap16(u16) __builtin_bswap16(u16)
#endif

_ODP_INLINE uint16_t odp_be_to_cpu_16(odp_u16be_t be16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return __odp_builtin_bswap16((__odp_force uint16_t)be16);
#else
	return (__odp_force uint16_t)be16;
#endif
}

_ODP_INLINE uint32_t odp_be_to_cpu_32(odp_u32be_t be32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return __builtin_bswap32((__odp_force uint32_t)be32);
#else
	return (__odp_force uint32_t)be32;
#endif
}

_ODP_INLINE uint64_t odp_be_to_cpu_64(odp_u64be_t be64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return __builtin_bswap64((__odp_force uint64_t)be64);
#else
	return (__odp_force uint64_t)be64;
#endif
}

_ODP_INLINE odp_u16be_t odp_cpu_to_be_16(uint16_t cpu16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force odp_u16be_t)__odp_builtin_bswap16(cpu16);
#else
	return (__odp_force odp_u16be_t)cpu16;
#endif
}

_ODP_INLINE odp_u32be_t odp_cpu_to_be_32(uint32_t cpu32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force odp_u32be_t)__builtin_bswap32(cpu32);
#else
	return (__odp_force odp_u32be_t)cpu32;
#endif
}

_ODP_INLINE odp_u64be_t odp_cpu_to_be_64(uint64_t cpu64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force odp_u64be_t)__builtin_bswap64(cpu64);
#else
	return (__odp_force odp_u64be_t)cpu64;
#endif
}

_ODP_INLINE uint16_t odp_le_to_cpu_16(odp_u16le_t le16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint16_t)le16;
#else
	return __odp_builtin_bswap16((__odp_force uint16_t)le16);
#endif
}

_ODP_INLINE uint32_t odp_le_to_cpu_32(odp_u32le_t le32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint32_t)le32;
#else
	return __builtin_bswap32((__odp_force uint32_t)le32);
#endif
}

_ODP_INLINE uint64_t odp_le_to_cpu_64(odp_u64le_t le64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force uint64_t)le64;
#else
	return __builtin_bswap64((__odp_force uint64_t)le64);
#endif
}

_ODP_INLINE odp_u16le_t odp_cpu_to_le_16(uint16_t cpu16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force odp_u16le_t)cpu16;
#else
	return (__odp_force odp_u16le_t)__odp_builtin_bswap16(cpu16);
#endif
}

_ODP_INLINE odp_u32le_t odp_cpu_to_le_32(uint32_t cpu32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force odp_u32le_t)cpu32;
#else
	return (__odp_force odp_u32le_t)__builtin_bswap32(cpu32);
#endif
}

_ODP_INLINE odp_u64le_t odp_cpu_to_le_64(uint64_t cpu64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return (__odp_force odp_u64le_t)cpu64;
#else
	return (__odp_force odp_u64le_t)__builtin_bswap64(cpu64);
#endif
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif

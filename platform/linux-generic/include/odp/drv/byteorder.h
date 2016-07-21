/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV byteorder
 */

#ifndef ODPDRVP_PLAT_BYTEORDER_H_
#define ODPDRVP_PLAT_BYTEORDER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/drv/plat/byteorder_types.h>
#include <odp/drv/std_types.h>
#include <odp/drv/compiler.h>

/** @ingroup odpdrv_compiler_optim
 *  @{
 */

static inline uint16_t odpdrv_be_to_cpu_16(odpdrv_u16be_t be16)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return __odpdrv_builtin_bswap16((__odpdrv_force uint16_t)be16);
#else
	return (__odpdrv_force uint16_t)be16;
#endif
}

static inline uint32_t odpdrv_be_to_cpu_32(odpdrv_u32be_t be32)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return __builtin_bswap32((__odpdrv_force uint32_t)be32);
#else
	return (__odpdrv_force uint32_t)be32;
#endif
}

static inline uint64_t odpdrv_be_to_cpu_64(odpdrv_u64be_t be64)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return __builtin_bswap64((__odpdrv_force uint64_t)be64);
#else
	return (__odpdrv_force uint64_t)be64;
#endif
}

static inline odpdrv_u16be_t odpdrv_cpu_to_be_16(uint16_t cpu16)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return (__odpdrv_force odpdrv_u16be_t)__odpdrv_builtin_bswap16(cpu16);
#else
	return (__odpdrv_force odpdrv_u16be_t)cpu16;
#endif
}

static inline odpdrv_u32be_t odpdrv_cpu_to_be_32(uint32_t cpu32)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return (__odpdrv_force odpdrv_u32be_t)__builtin_bswap32(cpu32);
#else
	return (__odpdrv_force odpdrv_u32be_t)cpu32;
#endif
}

static inline odpdrv_u64be_t odpdrv_cpu_to_be_64(uint64_t cpu64)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return (__odpdrv_force odpdrv_u64be_t)__builtin_bswap64(cpu64);
#else
	return (__odpdrv_force odpdrv_u64be_t)cpu64;
#endif
}

static inline uint16_t odpdrv_le_to_cpu_16(odpdrv_u16le_t le16)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return (__odpdrv_force uint16_t)le16;
#else
	return __odpdrv_builtin_bswap16((__odpdrv_force uint16_t)le16);
#endif
}

static inline uint32_t odpdrv_le_to_cpu_32(odpdrv_u32le_t le32)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return (__odpdrv_force uint32_t)le32;
#else
	return __builtin_bswap32((__odpdrv_force uint32_t)le32);
#endif
}

static inline uint64_t odpdrv_le_to_cpu_64(odpdrv_u64le_t le64)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return (__odpdrv_force uint64_t)le64;
#else
	return __builtin_bswap64((__odpdrv_force uint64_t)le64);
#endif
}

static inline odpdrv_u16le_t odpdrv_cpu_to_le_16(uint16_t cpu16)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return (__odpdrv_force odpdrv_u16le_t)cpu16;
#else
	return (__odpdrv_force odpdrv_u16le_t)__odpdrv_builtin_bswap16(cpu16);
#endif
}

static inline odpdrv_u32le_t odpdrv_cpu_to_le_32(uint32_t cpu32)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return (__odpdrv_force odpdrv_u32le_t)cpu32;
#else
	return (__odpdrv_force odpdrv_u32le_t)__builtin_bswap32(cpu32);
#endif
}

static inline odpdrv_u64le_t odpdrv_cpu_to_le_64(uint64_t cpu64)
{
#if ODPDRVP_BYTE_ORDER == ODPDRVP_LITTLE_ENDIAN
	return (__odpdrv_force odpdrv_u64le_t)cpu64;
#else
	return (__odpdrv_force odpdrv_u64le_t)__builtin_bswap64(cpu64);
#endif
}

/**
 * @}
 */

#include <odp/drv/spec/byteorder.h>

#ifdef __cplusplus
}
#endif

#endif

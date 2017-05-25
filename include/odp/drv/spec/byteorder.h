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

#ifndef ODPDRV_BYTEORDER_H_
#define ODPDRV_BYTEORDER_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odpdrv_compiler_optim ODPDRV COMPILER / OPTIMIZATION
 *  Macros that check byte order and operations for byte order conversion.
 *  @{
 */

/**
 * @def ODPDRV_BIG_ENDIAN
 * Big endian byte order
 *
 * @def ODPDRV_LITTLE_ENDIAN
 * Little endian byte order
 *
 * @def ODPDRV_BIG_ENDIAN_BITFIELD
 * Big endian bit field
 *
 * @def ODPDRV_LITTLE_ENDIAN_BITFIELD
 * Little endian bit field
 *
 * @def ODPDRV_BYTE_ORDER
 * Selected byte order
 *
 * @def ODPDRV_BITFIELD_ORDER
 * Selected bitfield order
 */

/**
 * @typedef odpdrv_u16le_t
 * unsigned 16bit little endian
 *
 * @typedef odpdrv_u16be_t
 * unsigned 16bit big endian
 *
 * @typedef odpdrv_u32le_t
 * unsigned 32bit little endian
 *
 * @typedef odpdrv_u32be_t
 * unsigned 32bit big endian
 *
 * @typedef odpdrv_u64le_t
 * unsigned 64bit little endian
 *
 * @typedef odpdrv_u64be_t
 * unsigned 64bit big endian
 *
 * @typedef odpdrv_u16sum_t
 * unsigned 16bit bitwise
 *
 * @typedef odpdrv_u32sum_t
 * unsigned 32bit bitwise
 */

/*
 * Big Endian -> CPU byte order:
 */

/**
 * Convert 16bit big endian to cpu native uint16_t
 * @param be16  big endian 16bit
 * @return  cpu native uint16_t
 */
uint16_t odpdrv_be_to_cpu_16(odpdrv_u16be_t be16);

/**
 * Convert 32bit big endian to cpu native uint32_t
 * @param be32  big endian 32bit
 * @return  cpu native uint32_t
 */
uint32_t odpdrv_be_to_cpu_32(odpdrv_u32be_t be32);

/**
 * Convert 64bit big endian to cpu native uint64_t
 * @param be64  big endian 64bit
 * @return  cpu native uint64_t
 */
uint64_t odpdrv_be_to_cpu_64(odpdrv_u64be_t be64);

/*
 * CPU byte order -> Big Endian:
 */

/**
 * Convert cpu native uint16_t to 16bit big endian
 * @param cpu16  uint16_t in cpu native format
 * @return  big endian 16bit
 */
odpdrv_u16be_t odpdrv_cpu_to_be_16(uint16_t cpu16);

/**
 * Convert cpu native uint32_t to 32bit big endian
 * @param cpu32  uint32_t in cpu native format
 * @return  big endian 32bit
 */
odpdrv_u32be_t odpdrv_cpu_to_be_32(uint32_t cpu32);

/**
 * Convert cpu native uint64_t to 64bit big endian
 * @param cpu64  uint64_t in cpu native format
 * @return  big endian 64bit
 */
odpdrv_u64be_t odpdrv_cpu_to_be_64(uint64_t cpu64);

/*
 * Little Endian -> CPU byte order:
 */

/**
 * Convert 16bit little endian to cpu native uint16_t
 * @param le16  little endian 16bit
 * @return  cpu native uint16_t
 */
uint16_t odpdrv_le_to_cpu_16(odpdrv_u16le_t le16);

/**
 * Convert 32bit little endian to cpu native uint32_t
 * @param le32  little endian 32bit
 * @return  cpu native uint32_t
 */
uint32_t odpdrv_le_to_cpu_32(odpdrv_u32le_t le32);

/**
 * Convert 64bit little endian to cpu native uint64_t
 * @param le64  little endian 64bit
 * @return  cpu native uint64_t
 */
uint64_t odpdrv_le_to_cpu_64(odpdrv_u64le_t le64);

/*
 * CPU byte order -> Little Endian:
 */

/**
 * Convert cpu native uint16_t to 16bit little endian
 * @param cpu16  uint16_t in cpu native format
 * @return  little endian 16bit
 */
odpdrv_u16le_t odpdrv_cpu_to_le_16(uint16_t cpu16);

/**
 * Convert cpu native uint32_t to 32bit little endian
 * @param cpu32  uint32_t in cpu native format
 * @return  little endian 32bit
 */
odpdrv_u32le_t odpdrv_cpu_to_le_32(uint32_t cpu32);

/**
 * Convert cpu native uint64_t to 64bit little endian
 * @param cpu64  uint64_t in cpu native format
 * @return  little endian 64bit
 */
odpdrv_u64le_t odpdrv_cpu_to_le_64(uint64_t cpu64);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

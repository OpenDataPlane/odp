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

/** @defgroup odp_compiler_optim ODP COMPILER / OPTIMIZATION
 *  Macros that check byte order and byte converting operations.
 *  @{
 */

/*
 * Big Endian -> CPU byte order:
 */

/**
 * Convert 16bit big endian to cpu native uint16_t
 * @param be16  big endian 16bit
 * @return  cpu native uint16_t
 */
uint16_t odp_be_to_cpu_16(uint16be_t be16);

/**
 * Convert 32bit big endian to cpu native uint32_t
 * @param be32  big endian 32bit
 * @return  cpu native uint32_t
 */
uint32_t odp_be_to_cpu_32(uint32be_t be32);

/**
 * Convert 64bit big endian to cpu native uint64_t
 * @param be64  big endian 64bit
 * @return  cpu native uint64_t
 */
uint64_t odp_be_to_cpu_64(uint64be_t be64);


/*
 * CPU byte order -> Big Endian:
 */

/**
 * Convert cpu native uint16_t to 16bit big endian
 * @param cpu16  uint16_t in cpu native format
 * @return  big endian 16bit
 */
uint16be_t odp_cpu_to_be_16(uint16_t cpu16);

/**
 * Convert cpu native uint32_t to 32bit big endian
 * @param cpu32  uint32_t in cpu native format
 * @return  big endian 32bit
 */
uint32be_t odp_cpu_to_be_32(uint32_t cpu32);

/**
 * Convert cpu native uint64_t to 64bit big endian
 * @param cpu64  uint64_t in cpu native format
 * @return  big endian 64bit
 */
uint64be_t odp_cpu_to_be_64(uint64_t cpu64);


/*
 * Little Endian -> CPU byte order:
 */

/**
 * Convert 16bit little endian to cpu native uint16_t
 * @param le16  little endian 16bit
 * @return  cpu native uint16_t
 */
uint16_t odp_le_to_cpu_16(uint16le_t le16);

/**
 * Convert 32bit little endian to cpu native uint32_t
 * @param le32  little endian 32bit
 * @return  cpu native uint32_t
 */
uint32_t odp_le_to_cpu_32(uint32le_t le32);

/**
 * Convert 64bit little endian to cpu native uint64_t
 * @param le64  little endian 64bit
 * @return  cpu native uint64_t
 */
uint64_t odp_le_to_cpu_64(uint64le_t le64);


/*
 * CPU byte order -> Little Endian:
 */

/**
 * Convert cpu native uint16_t to 16bit little endian
 * @param cpu16  uint16_t in cpu native format
 * @return  little endian 16bit
 */
uint16le_t odp_cpu_to_le_16(uint16_t cpu16);

/**
 * Convert cpu native uint32_t to 32bit little endian
 * @param cpu32  uint32_t in cpu native format
 * @return  little endian 32bit
 */
uint32le_t odp_cpu_to_le_32(uint32_t cpu32);

/**
 * Convert cpu native uint64_t to 64bit little endian
 * @param cpu64  uint64_t in cpu native format
 * @return  little endian 64bit
 */
uint64le_t odp_cpu_to_le_64(uint64_t cpu64);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

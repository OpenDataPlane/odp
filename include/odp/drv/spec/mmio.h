/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * API to access memory-mapped I/O.
 *
 */

#ifndef ODPDRV_MMIO_H_
#define ODPDRV_MMIO_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odpdrv_mmio ODPDRV MMIO
 *  @{
 */

/**
 * Write value to MMIO
 * @param value	cpu native 8-bit value to write to MMIO
 * @param addr MMIO address to write at
 */
void odpdrv_mmio_u8_write(uint8_t value, volatile void *addr);

/**
 * Convert to little endian and write value to MMIO
 * @param value	cpu native 16-bit value to write to MMIO
 * @param addr MMIO address to write at
 */
void odpdrv_mmio_u16le_write(uint16_t value, volatile void *addr);

/**
 * Convert to big endian and write value to MMIO
 * @param value	cpu native 16-bit value to write to MMIO
 * @param addr MMIO address to write at
 */
void odpdrv_mmio_u16be_write(uint16_t value, volatile void *addr);

/**
 * Convert to little endian and write value to MMIO
 * @param value	cpu native 32-bit value to write to MMIO
 * @param addr MMIO address to write at
 */
void odpdrv_mmio_u32le_write(uint32_t value, volatile void *addr);

/**
 * Convert to big endian and write value to MMIO
 * @param value	cpu native 32-bit value to write to MMIO
 * @param addr MMIO address to write at
 */
void odpdrv_mmio_u32be_write(uint32_t value, volatile void *addr);

/**
 * Convert to little endian and write value to MMIO
 * @param value	cpu native 64-bit value to write to MMIO
 * @param addr MMIO address to write at
 */
void odpdrv_mmio_u64le_write(uint64_t value, volatile void *addr);

/**
 * Convert to big endian and write value to MMIO
 * @param value	cpu native 64-bit value to write to MMIO
 * @param addr MMIO address to write at
 */
void odpdrv_mmio_u64be_write(uint64_t value, volatile void *addr);

/**
 * Read from MMIO
 * @param addr MMIO address to read at
 * @return cpu native 8-bit value
 */
uint8_t odpdrv_mmio_u8_read(volatile void *addr);

/**
 * Read from MMIO and convert from little endian
 * @param addr MMIO address to read at
 * @return cpu native 16-bit value
 */
uint16_t odpdrv_mmio_u16le_read(volatile void *addr);

/**
 * Read from MMIO and convert from big endian
 * @param addr MMIO address to read at
 * @return cpu native 16-bit value
 */
uint16_t odpdrv_mmio_u16be_read(volatile void *addr);

/**
 * Read from MMIO and convert from little endian
 * @param addr MMIO address to read at
 * @return cpu native 32-bit value
 */
uint32_t odpdrv_mmio_u32le_read(volatile void *addr);

/**
 * Read from MMIO and convert from big endian
 * @param addr MMIO address to read at
 * @return cpu native 32-bit value
 */
uint32_t odpdrv_mmio_u32be_read(volatile void *addr);

/**
 * Read from MMIO and convert from little endian
 * @param addr MMIO address to read at
 * @return cpu native 64-bit value
 */
uint64_t odpdrv_mmio_u64le_read(volatile void *addr);

/**
 * Read from MMIO and convert from big endian
 * @param addr MMIO address to read at
 * @return cpu native 64-bit value
 */
uint64_t odpdrv_mmio_u64be_read(volatile void *addr);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

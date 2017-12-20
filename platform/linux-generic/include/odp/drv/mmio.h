/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * API to access memory-mapped I/O.
 */

#ifndef ODPDRV_PLAT_MMIO_H_
#define ODPDRV_PLAT_MMIO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/byteorder.h>
#include <odp/drv/byteorder.h>

/** @ingroup odpdrv_mmio ODPDRV MMIO
 *  @{
 */

/* for use with type checkers such as sparse */
#ifdef __CHECKER__
/** @internal MMIO attribute */
#define __odpdrv_mmio	__attribute__((noderef, address_space(2)))
#else
/** @internal MMIO attribute */
#define __odpdrv_mmio
#endif

#define odpdrv_io_mb() __asm__ __volatile__("" ::: "memory")
#define odpdrv_io_rmb() __asm__ __volatile__("" ::: "memory")
#define odpdrv_io_wmb() __asm__ __volatile__("" ::: "memory")

static inline void
odpdrv_mmio_u8_write(uint8_t value, volatile void __odpdrv_mmio *addr)
{
	odpdrv_io_wmb();
	*(__odp_force volatile uint8_t *)addr = value;
}

static inline void
odpdrv_mmio_u16le_write(uint16_t value, volatile void __odpdrv_mmio *addr)
{
	odpdrv_io_wmb();
	*(__odp_force volatile odp_u16le_t *)addr = odpdrv_cpu_to_le_16(value);
}

static inline void
odpdrv_mmio_u16be_write(uint16_t value, volatile void __odpdrv_mmio *addr)
{
	odpdrv_io_wmb();
	*(__odp_force volatile odp_u16be_t *)addr = odpdrv_cpu_to_be_16(value);
}

static inline void
odpdrv_mmio_u32le_write(uint32_t value, volatile void __odpdrv_mmio *addr)
{
	odpdrv_io_wmb();
	*(__odp_force volatile odp_u32le_t *)addr = odpdrv_cpu_to_le_32(value);
}

static inline void
odpdrv_mmio_u32be_write(uint32_t value, volatile void __odpdrv_mmio *addr)
{
	odpdrv_io_wmb();
	*(__odp_force volatile odp_u32be_t *)addr = odpdrv_cpu_to_be_32(value);
}

static inline void
odpdrv_mmio_u64le_write(uint64_t value, volatile void __odpdrv_mmio *addr)
{
	odpdrv_io_wmb();
	*(__odp_force volatile odp_u64le_t *)addr = odpdrv_cpu_to_le_64(value);
}

static inline void
odpdrv_mmio_u64be_write(uint64_t value, volatile void __odpdrv_mmio *addr)
{
	odpdrv_io_wmb();
	*(__odp_force volatile odp_u64be_t *)addr = odpdrv_cpu_to_be_64(value);
}

static inline uint8_t
odpdrv_mmio_u8_read(volatile void __odpdrv_mmio *addr)
{
	uint8_t value = *(__odp_force volatile uint8_t *)addr;

	odpdrv_io_rmb();
	return value;
}

static inline uint16_t
odpdrv_mmio_u16le_read(volatile void __odpdrv_mmio *addr)
{
	uint16_t value =
	    odpdrv_le_to_cpu_16(*(__odp_force volatile odp_u16le_t *)addr);

	odpdrv_io_rmb();
	return value;
}

static inline uint16_t
odpdrv_mmio_u16be_read(volatile void __odpdrv_mmio *addr)
{
	uint16_t value =
	    odpdrv_be_to_cpu_16(*(__odp_force volatile odp_u16be_t *)addr);

	odpdrv_io_rmb();
	return value;
}

static inline uint32_t
odpdrv_mmio_u32le_read(volatile void __odpdrv_mmio *addr)
{
	uint32_t value =
	    odpdrv_le_to_cpu_32(*(__odp_force volatile odp_u32le_t *)addr);

	odpdrv_io_rmb();
	return value;
}

static inline uint32_t
odpdrv_mmio_u32be_read(volatile void __odpdrv_mmio *addr)
{
	uint32_t value =
	    odpdrv_be_to_cpu_32(*(__odp_force volatile odp_u32be_t *)addr);

	odpdrv_io_rmb();
	return value;
}

static inline uint64_t
odpdrv_mmio_u64le_read(volatile void __odpdrv_mmio *addr)
{
	uint64_t value =
	    odpdrv_le_to_cpu_64(*(__odp_force volatile odp_u64le_t *)addr);

	odpdrv_io_rmb();
	return value;
}

static inline uint64_t
odpdrv_mmio_u64be_read(volatile void __odpdrv_mmio *addr)
{
	uint64_t value =
	    odpdrv_be_to_cpu_64(*(__odp_force volatile odp_u64be_t *)addr);

	odpdrv_io_rmb();
	return value;
}

/**
 * @}
 */

#include <odp/drv/spec/mmio.h>

#ifdef __cplusplus
}
#endif

#endif

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017 ARM Limited
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2024 Nokia
 */

#ifndef ODP_AARCH64_WAIT_UNTIL_H_
#define ODP_AARCH64_WAIT_UNTIL_H_

#ifndef PLATFORM_LINUXGENERIC_ARCH_ARM_ODP_CPU_H
#error This file should not be included directly, please include odp_cpu.h
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/cpu.h>

#include <odp_cpu.h>

#include <stdint.h>

static inline void _odp_sevl(void)
{
	__asm__ volatile("sevl" : : : );
}

static inline int _odp_wfe(void)
{
	__asm__ volatile("wfe" : : : "memory");
	return 1;
}

#define _odp_monitor_u8(addr, mo) ll8((addr), (mo))
#define _odp_monitor_u32(addr, mo) ll32((addr), (mo))
#define _odp_monitor_u64(addr, mo) ll64((addr), (mo))
#define _odp_monitor_u128(addr, mo) lld((addr), (mo))

#if ATOM_BITSET_SIZE <= 32
static inline bitset_t _odp_bitset_monitor(bitset_t *bs, int mo)
{
	return _odp_monitor_u32(bs, mo);
}
#elif ATOM_BITSET_SIZE <= 64
static inline bitset_t _odp_bitset_monitor(bitset_t *bs, int mo)
{
	return _odp_monitor_u64(bs, mo);
}
#elif ATOM_BITSET_SIZE <= 128
static inline bitset_t _odp_bitset_monitor(bitset_t *bs, int mo)
{
	return _odp_monitor_u128(bs, mo);
}
#else
#error Unsupported size of bit sets (ATOM_BITSET_SIZE)
#endif

/**
 * The _odp_wait_until_eq_*() functions defined in this header are intended to
 * be used only with the scalable scheduler and queue implementations. Even
 * though these functions use standard non-atomic parameter types, the
 * parameters must only be operated using atomic operations. If new functions
 * are added to this file, they should use _odp_wait_until_equal_*() prefix and
 * atomic parameter types.
 */

static inline void _odp_wait_until_eq_u32(uint32_t *val, uint32_t expected)
{
	_odp_sevl();
	while (_odp_wfe() && _odp_monitor_u32(val, __ATOMIC_RELAXED) != expected)
		odp_cpu_pause();
}

static inline void _odp_wait_until_eq_bitset(bitset_t *val, bitset_t expected)
{
	_odp_sevl();
	while (_odp_wfe() && _odp_bitset_monitor(val, __ATOMIC_RELAXED != expected))
		odp_cpu_pause();
}

static inline void _odp_wait_until_eq_acq_u8(uint8_t *val, uint8_t expected)
{
	_odp_sevl();
	while (_odp_wfe() && _odp_monitor_u8(val, __ATOMIC_ACQUIRE) != expected)
		odp_cpu_pause();
}

static inline void _odp_wait_until_eq_acq_u32(uint32_t *val, uint32_t expected)
{
	_odp_sevl();
	while (_odp_wfe() && _odp_monitor_u32(val, __ATOMIC_ACQUIRE) != expected)
		odp_cpu_pause();
}

#ifdef __cplusplus
}
#endif

#endif

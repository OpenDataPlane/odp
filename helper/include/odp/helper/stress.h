/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

/**
 * @file
 *
 * ODP helper stress
 */

#ifndef ODPH_STRESS_H_
#define ODPH_STRESS_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odph_stress ODPH STRESS
 * Dummy CPU stress functions
 *
 * These functions may be used in test applications to create dummy CPU load. Functions are not
 * highly optimized, as they try to utilize various parts of CPU instruction set (load/store,
 * branch, integer/float arithmetics, vector, etc. instructions).
 *
 * @{
 */

/**
 * Returns 'value' raised to the power of 2
 *
 * @param value    Base value
 *
 * @return The value raised to the power of 2
 */
static inline uint32_t odph_stress_pow2_u32(uint32_t value)
{
	uint64_t v   = (uint64_t)value;
	uint64_t res =  v * v;

	if (odp_unlikely(res > UINT32_MAX))
		return UINT32_MAX;

	return (uint32_t)res;
}

/**
 * Returns base 2 logarithm of 'value'
 *
 * @param value    The value for which the logarithm is being calculated
 *
 * @return Base 2 logarithm of 'value'
 */
static inline uint32_t odph_stress_log2_u32(uint32_t value)
{
	uint32_t ret = 0;

	while ((value >>= 1) != 0)
		ret++;

	return ret;
}

/**
 * Calculates square root of a 32-bit unsigned integer value
 *
 * @param value    The value for which the square root is being calculated
 *
 * @return Square root of the value
 */
static inline uint32_t odph_stress_sqrt_u32(uint32_t value)
{
	uint64_t x;
	uint64_t pow = 1;

	if (odp_unlikely(value == 0 || value == 1))
		return value;

	if (value & 0xffff0000) {
		if (value & 0xff000000) {
			if (value & 0xf0000000) {
				x = 16384;
				if (value & 0xe0000000)
					x = 23170;
				if (value & 0xc0000000)
					x = 32768;
				if (value & 0x80000000)
					x = 46340;
			} else {
				/* value & 0x0f000000 */
				x = 4096;
				if (value & 0x0e000000)
					x = 5792;
				if (value & 0x0c000000)
					x = 8192;
				if (value & 0x08000000)
					x = 11585;
			}
		} else {
			if (value & 0x00f00000) {
				x = 1024;
				if (value & 0x00e00000)
					x = 1448;
				if (value & 0x00c00000)
					x = 2048;
				if (value & 0x00800000)
					x = 2896;
			} else {
				/* value & 0x000f0000 */
				x = 256;
				if (value & 0x000e0000)
					x = 362;
				if (value & 0x000c0000)
					x = 512;
				if (value & 0x00080000)
					x = 724;
			}
		}
	} else {
		/* value & 0xffff */
		x = 1;

		if (value >= 16384) {
			x = 128;
			if (value >= 25600)
				x = 160;
			if (value >= 36864)
				x = 192;
			if (value >= 50176)
				x = 224;
		} else {
			if (value >= 1024)
				x = 32;
			if (value >= 4096)
				x = 64;
			if (value >= 9216)
				x = 96;
		}
	}

	while (pow <= value) {
		x++;
		pow = x * x;
	}

	return (uint32_t)(x - 1);
}

/**
 * Calculates square root of a floating point value
 *
 * @param value    The value for which the square root is being calculated
 *
 * @return Square root of the value
 */
static inline float odph_stress_sqrt_f32(float value)
{
	double x;
	double pow = 1;

	if (odp_unlikely(value == 0 || value == 1))
		return value;

	if (value >= 65536) {
		if (value >= 16777215) {
			if (value >= 268435456) {
				x = 16384;
				if (value >= 536870912)
					x = 23170;
				if (value >= 1073741824)
					x = 32768;
				if (value >= 2147483648)
					x = 46340;
			} else {
				x = 4096;
				if (value >= 33554432)
					x = 5792;
				if (value >= 67108864)
					x = 8192;
				if (value >= 134217728)
					x = 11585;
			}
		} else {
			if (value >= 1048576) {
				x = 1024;
				if (value >= 2097152)
					x = 1448;
				if (value >= 4194304)
					x = 2048;
				if (value >= 8388608)
					x = 2896;
			} else {
				x = 256;
				if (value >= 131072)
					x = 362;
				if (value >= 262144)
					x = 512;
				if (value >= 524288)
					x = 724;
			}
		}
	} else {
		x = 1;

		if (value >= 16384) {
			x = 128;
			if (value >= 25600)
				x = 160;
			if (value >= 36864)
				x = 192;
			if (value >= 50176)
				x = 224;
		} else {
			if (value >= 1024)
				x = 32;
			if (value >= 4096)
				x = 64;
			if (value >= 9216)
				x = 96;
		}
	}

	while (pow <= value) {
		x = x + 1;
		pow = x * x;
	}

	return (float)(x - 1);
}

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif

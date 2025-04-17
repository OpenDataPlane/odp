/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2022-2025 Nokia
 */

/**
 * @file
 *
 * ODP miscellaneous macros
 */

#ifndef ODP_MACROS_INTERNAL_H_
#define ODP_MACROS_INTERNAL_H_

#include <odp/api/align.h>

#include <odp_config_internal.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define _ODP_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define _ODP_MIN(a, b)				\
	__extension__ ({			\
		__typeof__(a) min_a = (a);	\
		__typeof__(b) min_b = (b);	\
		min_a < min_b ? min_a : min_b;	\
	})

#define _ODP_MAX(a, b)				\
	__extension__ ({			\
		__typeof__(a) max_a = (a);	\
		__typeof__(b) max_b = (b);	\
		max_a > max_b ? max_a : max_b;	\
	})

#define _ODP_MIN3(a, b, c)		\
__extension__ ({			\
	__typeof__(a) min3_a = (a);	\
	__typeof__(b) min3_b = (b);	\
	__typeof__(c) min3_c = (c);	\
	(min3_a < min3_b ? (min3_a < min3_c ? min3_a : min3_c) : \
	(min3_b < min3_c ? min3_b : min3_c)); \
})

#define _ODP_MAX3(a, b, c)		\
__extension__ ({			\
	__typeof__(a) max3_a = (a);	\
	__typeof__(b) max3_b = (b);	\
	__typeof__(c) max3_c = (c);	\
	(max3_a > max3_b ? (max3_a > max3_c ? max3_a : max3_c) : \
	(max3_b > max3_c ? max3_b : max3_c)); \
})

/* Macros to calculate ODP_ROUNDUP_POWER2_U32() in five rounds of shift
 * and OR operations. */
#define __ODP_RSHIFT_U32(x, y) (((uint32_t)(x)) >> (y))
#define __ODP_POW2_U32_R1(x)   (((uint32_t)(x)) | __ODP_RSHIFT_U32(x, 1))
#define __ODP_POW2_U32_R2(x)   (__ODP_POW2_U32_R1(x) | __ODP_RSHIFT_U32(__ODP_POW2_U32_R1(x), 2))
#define __ODP_POW2_U32_R3(x)   (__ODP_POW2_U32_R2(x) | __ODP_RSHIFT_U32(__ODP_POW2_U32_R2(x), 4))
#define __ODP_POW2_U32_R4(x)   (__ODP_POW2_U32_R3(x) | __ODP_RSHIFT_U32(__ODP_POW2_U32_R3(x), 8))
#define __ODP_POW2_U32_R5(x)   (__ODP_POW2_U32_R4(x) | __ODP_RSHIFT_U32(__ODP_POW2_U32_R4(x), 16))

/* Round up a uint32_t value 'x' to the next power of two.
 *
 * The value is not round up, if it's already a power of two (including 1).
 * The value must be larger than 0 and not exceed 0x80000000.
 */
#define _ODP_ROUNDUP_POWER2_U32(x) \
	((((uint32_t)(x)) > 0x80000000) ? 0 : (__ODP_POW2_U32_R5(x - 1) + 1))

/*
 * Round up 'x' to alignment 'align'
 */
#define _ODP_ROUNDUP_ALIGN(x, align)\
	((align) * (((x) + (align) - 1) / (align)))

/*
 * Round up 'x' to cache line size alignment
 */
#define _ODP_ROUNDUP_CACHE_LINE(x)\
	_ODP_ROUNDUP_ALIGN(x, ODP_CACHE_LINE_SIZE)

/*
 * Round down 'x' to 'align' alignment, which is a power of two
 */
#define _ODP_ROUNDDOWN_POWER2(x, align)\
	((x) & (~((align) - 1)))

/*
 * Check if value is a power of two
 */
#define _ODP_CHECK_IS_POWER2(x) ((((x) - 1) & (x)) == 0)

/*
 * Add extra padding cache line(s) to structs to prevent false sharing like effects from
 * prefetchers.
 */
#if CONFIG_CACHE_PAD_LINES
#define __ODP_CACHE_PAD2(cntr) \
	uint8_t _odp_cp_ ## cntr[CONFIG_CACHE_PAD_LINES * ODP_CACHE_LINE_SIZE] ODP_ALIGNED_CACHE;
#define __ODP_CACHE_PAD1(cntr) __ODP_CACHE_PAD2(cntr)
#define _ODP_CACHE_PAD __ODP_CACHE_PAD1(__COUNTER__)
#else
#define _ODP_CACHE_PAD
#endif

#ifdef __cplusplus
}
#endif

#endif

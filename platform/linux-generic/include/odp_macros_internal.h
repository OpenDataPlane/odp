/* Copyright (c) 2018-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP miscellaneous macros
 */

#ifndef ODP_MACROS_INTERNAL_H_
#define ODP_MACROS_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/debug.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define MIN(a, b)				\
	__extension__ ({			\
		__typeof__(a) tmp_a = (a);	\
		__typeof__(b) tmp_b = (b);	\
		tmp_a < tmp_b ? tmp_a : tmp_b;	\
	})

#define MAX(a, b)				\
	__extension__ ({			\
		__typeof__(a) tmp_a = (a);	\
		__typeof__(b) tmp_b = (b);	\
		tmp_a > tmp_b ? tmp_a : tmp_b;	\
	})

#define MAX3(a, b, c) (MAX(MAX((a), (b)), (c)))

#define odp_container_of(pointer, type, member) \
	((type *)(void *)(((char *)pointer) - offsetof(type, member)))

#define DIV_ROUND_UP(a, b)					\
	__extension__ ({					\
		__typeof__(a) tmp_a = (a);			\
		__typeof__(b) tmp_b = (b);			\
		ODP_STATIC_ASSERT(__builtin_constant_p(b), "");	\
		ODP_STATIC_ASSERT((((b) - 1) & (b)) == 0, "");	\
		(tmp_a + tmp_b - 1) >> __builtin_ctz(tmp_b);	\
	})

#ifdef __cplusplus
}
#endif

#endif

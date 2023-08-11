/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Nokia
 */

/**
 * @file
 *
 * Common helper macros
 */

#ifndef ODPH_MACROS_H_
#define ODPH_MACROS_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odph_macros ODPH MACROS
 * Helper macros
 *
 * @{
 */

/**
 * Return minimum of two numbers
 */
#define ODPH_MIN(a, b)				\
	__extension__ ({			\
		__typeof__(a) tmp_a = (a);	\
		__typeof__(b) tmp_b = (b);	\
		tmp_a < tmp_b ? tmp_a : tmp_b;	\
	})

/**
 * Return maximum of two numbers
 */
#define ODPH_MAX(a, b)				\
	__extension__ ({			\
		__typeof__(a) tmp_a = (a);	\
		__typeof__(b) tmp_b = (b);	\
		tmp_a > tmp_b ? tmp_a : tmp_b;	\
	})

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ODPH_MACROS_H_ */

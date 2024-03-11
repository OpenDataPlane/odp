/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

#ifndef TEST_COMMON_MACROS_H_
#define TEST_COMMON_MACROS_H_

/*
 * Common macros for validation tests
 */

/* Check if 'x' is a power of two value */
#define TEST_CHECK_POW2(x) ((((x) - 1) & (x)) == 0)

#endif

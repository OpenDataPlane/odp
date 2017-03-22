/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV compiler hints
 */

#ifndef ODPDRV_API_HINTS_H_
#define ODPDRV_API_HINTS_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odpdrv_compiler_optim
 *  Macros that will give hints to the compiler.
 *  @{
 */

#ifdef __GNUC__

/** Define a function that should be run at early init (constructor)
 */
#define ODPDRV_CONSTRUCTOR __attribute__((__constructor__))

/** Define a function that does not return
 */
#define ODPDRV_NORETURN __attribute__((__noreturn__))

/** Define a weak symbol
 * This is primarily useful in defining library functions that can be
 * overridden in user code.
 */
#define ODPDRV_WEAK_SYMBOL __attribute__((__weak__))

/**
 * Hot code section
 */
#define ODPDRV_HOT_CODE    __attribute__((__hot__))

/**
 * Cold code section
 */
#define ODPDRV_COLD_CODE   __attribute__((__cold__))

/**
 * Printf format attribute
 */
#define ODPDRV_PRINTF_FORMAT(x, y) __attribute__((format(printf, (x), (y))))

/**
 * Indicate deprecated variables, functions or types
 */
#define ODPDRV_DEPRECATED __attribute__((__deprecated__))

/**
 * Intentionally unused variables of functions
 */
#define ODPDRV_UNUSED     __attribute__((__unused__))

/**
 * Branch likely taken
 */
#define odpdrv_likely(x)   __builtin_expect((x), 1)

/**
 * Branch unlikely taken
 */
#define odpdrv_unlikely(x) __builtin_expect((x), 0)

/*
 * __builtin_prefetch (const void *addr, rw, locality)
 *
 * rw 0..1       (0: read, 1: write)
 * locality 0..3 (0: don't leave to cache, 3: leave on all cache levels)
 */

/**
 * Cache prefetch address
 */
#define odpdrv_prefetch(x)         __builtin_prefetch((x), 0, 3)

/**
 * Cache prefetch address for storing
 */
#define odpdrv_prefetch_store(x)   __builtin_prefetch((x), 1, 3)

#else

#define ODPDRV_CONSTRUCTOR
#define ODPDRV_NORETURN
#define ODPDRV_WEAK_SYMBOL
#define ODPDRV_HOT_CODE
#define ODPDRV_COLD_CODE
#define ODPDRV_DEPRECATED
#define ODPDRV_UNUSED
#define odpdrv_likely(x) (x)
#define odpdrv_unlikely(x) (x)
#define odpdrv_prefetch(x)
#define odpdrv_prefetch_store(x)

#endif

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

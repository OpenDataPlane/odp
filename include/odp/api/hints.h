/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP compiler hints
 */

#ifndef ODP_HINTS_H_
#define ODP_HINTS_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_compiler_optim
 *  Macros that will give hints to the compiler.
 *  @{
 */

#ifdef __GNUC__

/** Define a fn that does not return
 */
#define ODP_NORETURN __attribute__((__noreturn__))

/** Define a weak symbol
 * This is primarily useful in defining library functions that can be
 * overridden in user code.
 */
#define ODP_WEAK_SYMBOL __attribute__((__weak__))

/**
 * Hot code section
 */
#define ODP_HOT_CODE    __attribute__((__hot__))

/**
 * Cold code section
 */
#define ODP_COLD_CODE   __attribute__((__cold__))

/**
 * Branch likely taken
 */
#define odp_likely(x)   __builtin_expect((x), 1)

/**
 * Branch unlikely taken
 */
#define odp_unlikely(x) __builtin_expect((x), 0)


/*
 * __builtin_prefetch (const void *addr, rw, locality)
 *
 * rw 0..1       (0: read, 1: write)
 * locality 0..3 (0: dont leave to cache, 3: leave on all cache levels)
 */

/**
 * Cache prefetch address
 */
#define odp_prefetch(x)         __builtin_prefetch((x), 0, 3)

/**
 * Cache prefetch address for storing
 */
#define odp_prefetch_store(x)   __builtin_prefetch((x), 1, 3)



#else

#define ODP_WEAK_SYMBOL
#define ODP_HOT_CODE
#define ODP_COLD_CODE
#define odp_likely(x)
#define odp_unlikely(x)
#define odp_prefetch(x)
#define odp_prefetch_store(x)

#endif


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Compiler related for ODP driver interface
 */

#ifndef ODPDRV_COMPILER_H_
#define ODPDRV_COMPILER_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odpdrv_compiler_optim ODPDRV COMPILER / OPTIMIZATION
 *  Macro for old compilers
 *  @{
 */

/** @internal GNU compiler version */
#define GCC_VERSION (__GNUC__ * 10000 \
			+ __GNUC_MINOR__ * 100 \
			+ __GNUC_PATCHLEVEL__)

/**
 * @internal
 * Compiler __builtin_bswap16() is not available on all platforms
 * until GCC 4.8.0 - work around this by offering __odpdrv_builtin_bswap16()
 * Don't use this function directly, instead see odpdrv byteorder.h
 */
#if GCC_VERSION < 40800
#define __odpdrv_builtin_bswap16(u16) \
				((((u16)&0x00ff) << 8) | (((u16)&0xff00) >> 8))
#else
#define __odpdrv_builtin_bswap16(u16) __builtin_bswap16(u16)
#endif

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

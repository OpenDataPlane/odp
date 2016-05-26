/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Standard C language types and definitions for ODP driver interface.
 */

#ifndef ODPDRV_PLAT_STD_TYPES_H_
#define ODPDRV_PLAT_STD_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>

/** @addtogroup odpdrv_system ODPDRV SYSTEM
 *  @{
 */

typedef int odpdrv_bool_t;

/**
 * @}
 */

#include <odp/drv/spec/std_types.h>

#ifdef __cplusplus
}
#endif

#endif

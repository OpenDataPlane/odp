/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Standard C language types and definitions for ODP driver interface.
 *
 */

#ifndef ODPDRV_STD_TYPES_H_
#define ODPDRV_STD_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odpdrv_system ODPDRV SYSTEM
 *  @{
 */

/**
 * @typedef odpdrv_bool_t
 * Use odpdrv boolean type to have it well-defined and known size,
 * regardless which compiler is used as this facilities interoperability
 * between e.g. different compilers.
 */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

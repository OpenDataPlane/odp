/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPDRV Strong Types. Common macros for implementing strong typing
 * for ODPDRV abstract data types
 */

#ifndef ODPDRV_STRONG_TYPES_H_
#define ODPDRV_STRONG_TYPES_H_

/** Use strong typing for ODPDRV types */
#ifdef __cplusplus
#define ODPDRV_HANDLE_T(type) struct _##type { uint8_t unused_dummy_var; } *type
#else
#define odpdrv_handle_t struct { uint8_t unused_dummy_var; } *
/** C/C++ helper macro for strong typing */
#define ODPDRV_HANDLE_T(type) odpdrv_handle_t type
#endif

/** Internal macro to get value of an ODPDRV handle */
#define _odpdrv_typeval(handle) ((uint32_t)(uintptr_t)(handle))

/** Internal macro to get printable value of an ODPDRV handle */
#define _odpdrv_pri(handle) ((uint64_t)_odpdrv_typeval(handle))

/** Internal macro to convert a scalar to a typed handle */
#define _odpdrv_cast_scalar(type, val) ((type)(uintptr_t)(val))

#endif

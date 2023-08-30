/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP Strong Types. Common macros for implementing strong typing
 * for ODPH abstract data types
 */

#ifndef ODPH_STRONG_TYPES_H_
#define ODPH_STRONG_TYPES_H_

/** Use strong typing for ODPH types */
#ifdef __cplusplus
/** @internal C++ helper macro for strong typing  @param type @return */
#define ODPH_HANDLE_T(type) struct _##type { uint8_t unused_dummy_var; } *type
#else
#define odph_handle_t struct { uint8_t unused_dummy_var; } *
/** @internal C helper macro for strong typing @param type @return */
#define ODPH_HANDLE_T(type) odph_handle_t type
#endif

/** Internal macro to get value of an ODPH handle */
#define _odph_typeval(handle) ((uintptr_t)(handle))

/** Internal macro to get printable value of an ODPH handle */
#define _odph_pri(handle) ((uint64_t)(uintptr_t)(handle))

/** Internal macro to convert a scalar to a typed handle */
#define _odph_cast_scalar(type, val) ((type)(uintptr_t)(val))

#endif

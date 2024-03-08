/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */


/**
 * @file
 *
 * ODP Strong Types. Common macros for implementing strong typing
 * for ODP abstract data types
 */

#ifndef STRONG_TYPES_H_
#define STRONG_TYPES_H_

#include <odp/api/std_types.h>

/** Use strong typing for ODP types */
#ifdef __cplusplus
/* Allow type to be expanded before concatenation with underscore */
#define _ODP_HANDLE_T(type) struct _##type { uint8_t unused_dummy_var; } *type
#define ODP_HANDLE_T(type) _ODP_HANDLE_T(type)
#else
#define odp_handle_t struct { uint8_t unused_dummy_var; } *
/** C/C++ helper macro for strong typing */
#define ODP_HANDLE_T(type) odp_handle_t type
#endif

/** Internal macro to get value of an ODP handle */
#define _odp_typeval(handle) ((uintptr_t)(handle))

/** Internal macro to get printable value of an ODP handle */
#define _odp_pri(handle) ((uint64_t)(uintptr_t)(handle))

/** Internal macro to convert a scalar to a typed handle */
#define _odp_cast_scalar(type, val) ((type)(uintptr_t)(val))

#endif

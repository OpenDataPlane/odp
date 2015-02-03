/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Strong Types. Common macros for implementing strong typing
 * for ODP abstract data types
 */

#ifndef STRONG_TYPES_H_
#define STRONG_TYPES_H_

/** Use strong typing for ODP types */
#define odp_handle_t struct {} *

/** Internal typedefs for ODP strong type manipulation */
typedef odp_handle_t _odp_handle_t;

typedef union {
	_odp_handle_t hdl;
	uint32_t val;
} _odp_handle_u;

/** Internal macro to get value of an ODP handle */
#define _odp_typeval(handle) (((_odp_handle_u)(_odp_handle_t)handle).val)

/** Internal macro to get printable value of an ODP handle */
#define _odp_pri(handle) ((uint64_t)_odp_typeval(handle))

/** Internal macro to convert a scalar to a typed handle */
#define _odp_cast_scalar(type, val) ((type)(size_t)(val))

#endif

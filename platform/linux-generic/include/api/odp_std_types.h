/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * Standard C language types and definitions for ODP.
 *
 */

#ifndef ODP_STD_TYPES_H_
#define ODP_STD_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif



#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>

/** Use odp boolean type to have it well-defined and known size,
  * regardless which compiler is used as this facilities interoperability
  * between e.g. different compilers.
  */
typedef int odp_bool_t;

#ifdef __cplusplus
}
#endif

#endif

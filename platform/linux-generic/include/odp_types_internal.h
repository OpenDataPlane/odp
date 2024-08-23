/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_TYPES_INTERNAL_H_
#define ODP_TYPES_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <stdint.h>

#ifdef __SIZEOF_INT128__

__extension__ typedef unsigned __int128 _odp_u128_t;

#endif

/*
 * Integer types with may_alias attribute. GCC documentation: "Accesses through
 * pointers to types with this attribute are not subject to type-based alias
 * analysis, but are instead assumed to be able to alias any other type of
 * objects. [...] See -fstrict-aliasing for more information on aliasing
 * issues."
 */
typedef uint16_t __attribute__((__may_alias__)) _odp_ma_u16_t;
typedef uint32_t __attribute__((__may_alias__)) _odp_ma_u32_t;
typedef uint64_t __attribute__((__may_alias__)) _odp_ma_u64_t;

typedef _odp_ma_u16_t ODP_ALIGNED(1) _odp_una_ma_u16_t;
typedef _odp_ma_u32_t ODP_ALIGNED(1) _odp_una_ma_u32_t;
typedef _odp_ma_u64_t ODP_ALIGNED(1) _odp_una_ma_u64_t;

#ifdef __cplusplus
}
#endif

#endif

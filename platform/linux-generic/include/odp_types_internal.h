/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_TYPES_INTERNAL_H_
#define ODP_TYPES_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __SIZEOF_INT128__

__extension__ typedef unsigned __int128 _odp_u128_t;

#endif

#ifdef __cplusplus
}
#endif

#endif

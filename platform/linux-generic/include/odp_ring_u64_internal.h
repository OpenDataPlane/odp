/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_RING_U64_INTERNAL_H_
#define ODP_RING_U64_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_ring_common.h>

#undef _ODP_RING_TYPE
#define _ODP_RING_TYPE _ODP_RING_TYPE_U64

#include <odp_ring_internal.h>

#ifdef __cplusplus
}
#endif

#endif

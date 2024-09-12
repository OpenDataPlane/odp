/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024-2025 Nokia
 */

#ifndef ODP_ABI_EVENT_VECTOR_TYPES_H_
#define ODP_ABI_EVENT_VECTOR_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_event_vector_t;

/** @addtogroup odp_event_vector
 *  @{
 */

typedef _odp_abi_event_vector_t *odp_event_vector_t;

#define ODP_EVENT_VECTOR_INVALID  ((odp_event_vector_t)0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

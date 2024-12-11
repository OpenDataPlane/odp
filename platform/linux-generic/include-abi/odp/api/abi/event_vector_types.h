/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

/**
 * @file
 *
 * ODP event vector type definitions
 */

#ifndef ODP_API_ABI_EVENT_VECTOR_TYPES_H_
#define ODP_API_ABI_EVENT_VECTOR_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>

/** @addtogroup odp_event_vector
 *  @{
 */

typedef ODP_HANDLE_T(odp_event_vector_t);

#define ODP_EVENT_VECTOR_INVALID _odp_cast_scalar(odp_event_vector_t, 0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP classification descriptor
 */

#ifndef ODP_CLASSIFY_TYPES_H_
#define ODP_CLASSIFY_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_classification
 *  @{
 */

typedef uint32_t odp_cos_t;
typedef uint32_t odp_flowsig_t;

#define ODP_COS_INVALID    ((odp_cos_t)~0)
#define ODP_COS_NAME_LEN 32

typedef uint16_t odp_cos_flow_set_t;
typedef uint32_t odp_pmr_t;
typedef uint32_t odp_pmr_set_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

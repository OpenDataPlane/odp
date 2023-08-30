/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 */

#ifndef ODP_ABI_CLASSIFICATION_H_
#define ODP_ABI_CLASSIFICATION_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_cos_t;

/** Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_pmr_t;

/** @ingroup odp_classification
 *  @{
 */

typedef _odp_abi_cos_t *odp_cos_t;
typedef _odp_abi_pmr_t *odp_pmr_t;

#define ODP_COS_INVALID   ((odp_cos_t)0)
#define ODP_PMR_INVALID   ((odp_pmr_t)0)

#define ODP_COS_NAME_LEN  32

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

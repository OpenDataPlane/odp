/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP classification descriptor
 */

#ifndef ODP_API_ABI_CLASSIFICATION_H_
#define ODP_API_ABI_CLASSIFICATION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>
#include <odp/api/deprecated.h>

/** @ingroup odp_classification
 *  @{
 */

typedef ODP_HANDLE_T(odp_cos_t);
#define ODP_COS_INVALID   _odp_cast_scalar(odp_cos_t, ~0)

typedef ODP_HANDLE_T(odp_pmr_t);
#define ODP_PMR_INVALID   _odp_cast_scalar(odp_pmr_t, ~0)

#if ODP_DEPRECATED_API
#define ODP_PMR_INVAL     ODP_PMR_INVALID
#else
/* Required to prevent Doxygen warning */
#define ODP_PMR_INVAL
#undef ODP_PMR_INVAL
#endif

#define ODP_COS_NAME_LEN  32

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

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

#ifndef ODP_CLASSIFICATION_TYPES_H_
#define ODP_CLASSIFICATION_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 1
#include <odp/api/abi/classification.h>
#else

#include <odp/api/plat/strong_types.h>

/** @ingroup odp_classification
 *  @{
 */

typedef ODP_HANDLE_T(odp_cos_t);
#define ODP_COS_INVALID   _odp_cast_scalar(odp_cos_t, ~0)

typedef ODP_HANDLE_T(odp_pmr_t);
#define ODP_PMR_INVAL     _odp_cast_scalar(odp_pmr_t, ~0)

#define ODP_COS_NAME_LEN  32

/**
 * @}
 */

#endif

#ifdef __cplusplus
}
#endif

#endif

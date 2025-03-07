/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Nokia
 */

#ifndef ODP_API_ABI_ML_TYPES_H_
#define ODP_API_ABI_ML_TYPES_H_

#include <odp/api/std_types.h>

#include <odp/api/plat/strong_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Implementation specific ML parameters */
struct _odp_ml_model_extra_param_t {
	/** @internal Dummy field to avoid empty struct */
	char dummy;
};

/** @addtogroup odp_ml
 *  @{
 */

typedef ODP_HANDLE_T(odp_ml_model_t);
typedef ODP_HANDLE_T(odp_ml_compl_t);
typedef struct _odp_ml_model_extra_param_t odp_ml_model_extra_param_t;

#define ODP_ML_MODEL_INVALID  _odp_cast_scalar(odp_ml_model_t, 0)
#define ODP_ML_COMPL_INVALID  _odp_cast_scalar(odp_ml_compl_t, 0)

#define ODP_ML_MODEL_NAME_LEN      64
#define ODP_ML_MODEL_IO_NAME_LEN   64
#define ODP_ML_SHAPE_NAME_LEN      16
#define ODP_ML_EXTRA_STAT_NAME_LEN 64

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

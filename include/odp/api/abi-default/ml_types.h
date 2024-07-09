/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Nokia
 */

#ifndef ODP_ABI_ML_TYPES_H_
#define ODP_ABI_ML_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_ml_model_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_ml_compl_t;

/** @internal Implementation specific ML input info */
struct _odp_ml_input_extra_info_t {
	/** @internal Dummy field to avoid empty struct */
	char dummy;
};

/** @internal Implementation specific ML output info */
struct _odp_ml_output_extra_info_t {
	/** @internal Dummy field to avoid empty struct */
	char dummy;
};

/** @internal Implementation specific ML model info */
struct _odp_ml_model_extra_info_t {
	/** @internal Dummy field to avoid empty struct */
	char dummy;
};

/** @internal Implementation specific ML parameters */
struct _odp_ml_model_extra_param_t {
	/** @internal Dummy field to avoid empty struct */
	char dummy;
};

/** @addtogroup odp_ml
 *  @{
 */

typedef _odp_abi_ml_model_t *odp_ml_model_t;
typedef _odp_abi_ml_compl_t *odp_ml_compl_t;
typedef struct _odp_ml_input_extra_info_t odp_ml_input_extra_info_t;
typedef struct _odp_ml_output_extra_info_t odp_ml_output_extra_info_t;
typedef struct _odp_ml_model_extra_info_t odp_ml_model_extra_info_t;
typedef struct _odp_ml_model_extra_param_t odp_ml_model_extra_param_t;

#define ODP_ML_MODEL_INVALID ((odp_ml_model_t)0)
#define ODP_ML_COMPL_INVALID ((odp_ml_compl_t)0)

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

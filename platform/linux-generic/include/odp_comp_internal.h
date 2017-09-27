/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_COMP_INTERNAL_H_
#define ODP_COMP_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/** Forward declaration of session structure */
typedef struct odp_comp_generic_session odp_comp_generic_session_t;

/**
 * Algorithm handler function prototype
 */
typedef
int (*comp_func_t)(odp_comp_op_param_t       *params,
		   odp_comp_generic_session_t *session,
		   odp_comp_op_result_t *result);

/**
 * Per session data structure
 */
struct odp_comp_generic_session {
	struct odp_comp_generic_session *next;
	odp_comp_session_param_t        params;
	struct {
		void *ctx;
		uint8_t *md;
		void *dt;
		int init;
	} hash;
	struct {
	comp_func_t func;
	void *ctx;
	} comp;
};

/**
 * Per packet operation result
 */
typedef struct odp_comp_generic_op_result {
	odp_comp_op_result_t result;
} odp_comp_generic_op_result_t;

/**
 * Per session creation operation result
 */
typedef struct odp_comp_generic_session_result {
	odp_comp_ses_create_err_t rc;
	odp_comp_session_t session;
} odp_comp_generic_session_result_t;

#ifdef __cplusplus
}
#endif

#endif

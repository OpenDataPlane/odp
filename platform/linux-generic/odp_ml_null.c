/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp/api/hints.h>
#include <odp/api/ml.h>

#include <odp_init_internal.h>

#include <stdint.h>
#include <string.h>

/* Dummy ML API implementation, no capability and just return error for
 * other functions.
 */
int _odp_ml_init_global(void)
{
	return 0;
}

int _odp_ml_term_global(void)
{
	return 0;
}

int odp_ml_capability(odp_ml_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_ml_capability_t));
	return 0;
}

void odp_ml_config_init(odp_ml_config_t *config ODP_UNUSED)
{
}

int odp_ml_config(const odp_ml_config_t *config ODP_UNUSED)
{
	return -1;
}

void odp_ml_model_param_init(odp_ml_model_param_t *param ODP_UNUSED)
{
}

odp_ml_model_t odp_ml_model_create(const char *name ODP_UNUSED,
				   const odp_ml_model_param_t *param ODP_UNUSED)
{
	return ODP_ML_MODEL_INVALID;
}

int odp_ml_model_destroy(odp_ml_model_t model ODP_UNUSED)
{
	return -1;
}

int odp_ml_model_info(odp_ml_model_t model ODP_UNUSED, odp_ml_model_info_t *info ODP_UNUSED)
{
	return -1;
}

uint32_t odp_ml_model_input_info(odp_ml_model_t model ODP_UNUSED,
				 odp_ml_input_info_t info[] ODP_UNUSED,
				 uint32_t num ODP_UNUSED)
{
	return 0;
}

uint32_t odp_ml_model_output_info(odp_ml_model_t model ODP_UNUSED,
				  odp_ml_output_info_t info[] ODP_UNUSED,
				  uint32_t num ODP_UNUSED)
{
	return 0;
}

odp_ml_model_t odp_ml_model_lookup(const char *name ODP_UNUSED)
{
	return ODP_ML_MODEL_INVALID;
}

uint64_t odp_ml_model_to_u64(odp_ml_model_t model ODP_UNUSED)
{
	return 0;
}

void odp_ml_model_print(odp_ml_model_t model ODP_UNUSED)
{
}

void odp_ml_print(void)
{
}

void odp_ml_compl_pool_param_init(odp_ml_compl_pool_param_t *pool_param)
{
	memset(pool_param, 0, sizeof(odp_ml_compl_pool_param_t));
}

odp_pool_t odp_ml_compl_pool_create(const char *name ODP_UNUSED,
				    const odp_ml_compl_pool_param_t *pool_param ODP_UNUSED)
{
	return ODP_POOL_INVALID;
}

odp_ml_compl_t odp_ml_compl_alloc(odp_pool_t pool ODP_UNUSED)
{
	return ODP_ML_COMPL_INVALID;
}

void odp_ml_compl_free(odp_ml_compl_t ml_compl ODP_UNUSED)
{
}

int odp_ml_compl_run_result(odp_ml_compl_t ml_compl ODP_UNUSED,
			    odp_ml_run_result_t *result ODP_UNUSED)
{
	return -1;
}

int odp_ml_compl_load_result(odp_ml_compl_t ml_compl ODP_UNUSED,
			     odp_ml_load_result_t *result ODP_UNUSED)
{
	return -1;
}

void *odp_ml_compl_user_area(odp_ml_compl_t ml_compl ODP_UNUSED)
{
	return NULL;
}

odp_ml_compl_t odp_ml_compl_from_event(odp_event_t event ODP_UNUSED)
{
	return ODP_ML_COMPL_INVALID;
}

odp_event_t odp_ml_compl_to_event(odp_ml_compl_t ml_compl ODP_UNUSED)
{
	return ODP_EVENT_INVALID;
}

uint64_t odp_ml_compl_to_u64(odp_ml_compl_t ml_compl ODP_UNUSED)
{
	return 0;
}

void odp_ml_compl_param_init(odp_ml_compl_param_t *compl_param ODP_UNUSED)
{
}

int odp_ml_model_load(odp_ml_model_t model ODP_UNUSED, odp_ml_load_result_t *result ODP_UNUSED)
{
	return -1;
}

int odp_ml_model_load_start(odp_ml_model_t model ODP_UNUSED,
			    const odp_ml_compl_param_t *compl_param ODP_UNUSED)
{
	return -1;
}

int odp_ml_model_load_status(odp_ml_model_t model ODP_UNUSED, uint32_t compl_id ODP_UNUSED,
			     odp_ml_load_result_t *result ODP_UNUSED)
{
	return -1;
}

int odp_ml_model_unload(odp_ml_model_t model ODP_UNUSED, odp_ml_load_result_t *result ODP_UNUSED)
{
	return -1;
}

int odp_ml_model_unload_start(odp_ml_model_t model ODP_UNUSED,
			      const odp_ml_compl_param_t *compl_param ODP_UNUSED)
{
	return -1;
}

int odp_ml_model_unload_status(odp_ml_model_t model ODP_UNUSED, uint32_t compl_id ODP_UNUSED,
			       odp_ml_load_result_t *result ODP_UNUSED)
{
	return -1;
}

void odp_ml_run_param_init(odp_ml_run_param_t *param ODP_UNUSED)
{
}

int odp_ml_run(odp_ml_model_t model ODP_UNUSED, const odp_ml_data_t *data ODP_UNUSED,
	       const odp_ml_run_param_t *param ODP_UNUSED)
{
	return -1;
}

int odp_ml_run_multi(odp_ml_model_t model ODP_UNUSED, const odp_ml_data_t data[] ODP_UNUSED,
		     const odp_ml_run_param_t param[] ODP_UNUSED, int num ODP_UNUSED)
{
	return -1;
}

int odp_ml_run_start(odp_ml_model_t model ODP_UNUSED, const odp_ml_data_t *data ODP_UNUSED,
		     const odp_ml_compl_param_t *compl_param ODP_UNUSED,
		     const odp_ml_run_param_t *run_param ODP_UNUSED)
{
	return -1;
}

int odp_ml_run_start_multi(odp_ml_model_t model ODP_UNUSED,
			   const odp_ml_data_t data[] ODP_UNUSED,
			   const odp_ml_compl_param_t compl_param[] ODP_UNUSED,
			   const odp_ml_run_param_t run_param[] ODP_UNUSED,
			   int num ODP_UNUSED)
{
	return -1;
}

int odp_ml_run_status(odp_ml_model_t model ODP_UNUSED, uint32_t compl_id ODP_UNUSED,
		      odp_ml_run_result_t *result ODP_UNUSED)
{
	return -1;
}

int odp_ml_model_extra_stat_info(odp_ml_model_t model ODP_UNUSED,
				 odp_ml_extra_stat_info_t info[] ODP_UNUSED,
				 int num ODP_UNUSED)
{
	return -1;
}

int odp_ml_model_extra_stats(odp_ml_model_t model ODP_UNUSED,
			     uint64_t stats[] ODP_UNUSED, int num ODP_UNUSED)
{
	return -1;
}

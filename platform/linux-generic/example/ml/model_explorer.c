/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp_api.h>
#include <stdio.h>
#include <stdlib.h>

#include "model_read.h"

/**
 * Read basic model information, e.g. inputs/outputs.
 */

int main(int argc, char *argv[])
{
	odp_instance_t inst;
	odp_ml_model_t ml_model;
	odp_ml_capability_t capa;
	odp_ml_config_t ml_config;
	odp_ml_model_param_t model_param;
	int ret = 0;

	if (argc != 2) {
		printf("Please specify model path\n"
		       "\nUsage:\n"
		       "  %s model_path\n"
		       "\nThis example prints model information\n\n",
		       argv[0]);
		return -1;
	}

	if (odp_init_global(&inst, NULL, NULL)) {
		printf("Global init failed.\n");
		return -1;
	}

	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		printf("Local init failed.\n");
		return -1;
	}

	if (odp_ml_capability(&capa)) {
		printf("odp_ml_capability() failed\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_config_init(&ml_config);
	ml_config.max_model_size = capa.max_model_size;
	ml_config.load_mode_mask = ODP_ML_COMPL_MODE_SYNC;
	ml_config.run_mode_mask = ODP_ML_COMPL_MODE_SYNC;

	if (odp_ml_config(&ml_config)) {
		printf("odp_ml_config() failed\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_model_param_init(&model_param);
	if (read_model_from_file(argv[1], &model_param)) {
		ret = -1;
		goto odp_term;
	}

	ml_model = odp_ml_model_create("model-explorer", &model_param);
	free(model_param.model);
	if (ml_model == ODP_ML_MODEL_INVALID) {
		printf("odp_ml_model_create failed.\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_model_print(ml_model);

	if (odp_ml_model_destroy(ml_model)) {
		printf("odp_ml_model_destroy failed.\n");
		ret = -1;
	}

odp_term:
	if (odp_term_local()) {
		printf("Local term failed.\n");
		return -1;
	}

	if (odp_term_global(inst)) {
		printf("Global term failed.\n");
		return -1;
	}

	return ret;
}

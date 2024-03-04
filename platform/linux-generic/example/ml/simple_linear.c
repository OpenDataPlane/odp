/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "model_read.h"

/**
 * About model simple_linear.onnx used in this example.
 *
 * Model info:
 * Inputs: name: x, type: int32, shape: [1]
 * Outputs: name: y, type: int32, shape: [1]
 *
 * The model is of form y = 3 * x + 4 where x is given as the second argument.
 * Thus when x = 5, the output y should be 19.
 */

#define NUM_INPUTS	1
#define NUM_OUTPUTS	1
#define MAX_NUM_WORKERS	10
#define MAX_MODEL_SIZE	500

typedef struct infer_param_t {
	int32_t x;
	odp_ml_model_t ml_model;
} infer_param_t;

typedef struct {
	odp_shm_t shm;
	/* Thread specific arguments */
	infer_param_t infer_param[MAX_NUM_WORKERS];
} thread_args_t;

/* Global pointer to thread_args */
static thread_args_t *thread_args;

static int run_inference(void *infer_param)
{
	int32_t y;
	odp_ml_data_t data;
	odp_ml_data_seg_t input;
	odp_ml_data_seg_t output;
	infer_param_t *param = (infer_param_t *)infer_param;

	data.num_input_seg = NUM_INPUTS;
	data.input_seg = &input;
	input.addr = &param->x;
	input.size = sizeof(int32_t);

	data.num_output_seg = NUM_OUTPUTS;
	data.output_seg = &output;
	output.addr = &y;
	output.size = sizeof(int32_t);

	while (1) {
		int ret = odp_ml_run(param->ml_model, &data, NULL);

		if (ret == 1)
			break;

		if (ret < 0) {
			ODPH_ERR("odp_ml_model_run() failed: %d\n", ret);
			return -1;
		}
	}

	printf("y = 3 * %d + 4: %d\n", param->x, y);

	return 0;
}

static int parse_argv1(char *argv1, uint32_t *num, int32_t *x)
{
	char *token;
	int i;

	if (!strstr(argv1, "[")) {
		*num = 1;
		*x = strtol(argv1, NULL, 10);
		return 0;
	}

	token = strtok(argv1, "[,]");
	if (token == NULL) {
		ODPH_ERR("Invalid argv[1]\n");
		return -1;
	}
	x[0] = strtol(token, NULL, 10);

	for (i = 0; i < MAX_NUM_WORKERS; i++) {
		token = strtok(NULL, "[,]");
		if (token == NULL)
			break;

		x[i + 1] = strtol(token, NULL, 10);
	}

	if (i == MAX_NUM_WORKERS) {
		ODPH_ERR("Too much xs, maximum number is: %d\n", MAX_NUM_WORKERS);
		return -1;
	}

	*num = i + 1;
	return 0;
}

int main(int argc, char *argv[])
{
	odp_shm_t shm;
	int num_workers;
	odp_instance_t inst;
	odp_cpumask_t cpumask;
	odp_ml_model_t ml_model;
	odp_ml_capability_t capa;
	odp_ml_config_t ml_config;
	int32_t x[MAX_NUM_WORKERS];
	odp_ml_model_param_t model_param;
	odph_thread_t thread_tbl[MAX_NUM_WORKERS];
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param[MAX_NUM_WORKERS];
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	int ret = 0;
	uint32_t num = 0;

	if (argc != 2) {
		ODPH_ERR("Please specify x\n"
			 "\nUsage:\n"
			 "  %s x\n"
			 "\nThis example runs inference on model y = 3x + 4\n\n",
			 argv[0]);
		return -1;
	}

	if (parse_argv1(argv[1], &num, x))
		return -1;

	if (odp_init_global(&inst, NULL, NULL)) {
		ODPH_ERR("Global init failed.\n");
		return -1;
	}

	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		return -1;
	}

	if (odp_ml_capability(&capa)) {
		ODPH_ERR("odp_ml_capability() failed\n");
		ret = -1;
		goto odp_term;
	}

	if (MAX_MODEL_SIZE > capa.max_model_size) {
		ODPH_ERR("Configured max model size %d exceeds max mode size %" PRIu64 " in capa\n",
			 MAX_MODEL_SIZE, capa.max_model_size);
		ret = -1;
		goto odp_term;
	}

	/* Set ML configuration parameter */
	odp_ml_config_init(&ml_config);
	ml_config.max_model_size = MAX_MODEL_SIZE;
	ml_config.load_mode_mask = ODP_ML_COMPL_MODE_SYNC;
	ml_config.run_mode_mask = ODP_ML_COMPL_MODE_SYNC;

	if (odp_ml_config(&ml_config)) {
		ODPH_ERR("odp_ml_config() failed\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_model_param_init(&model_param);
	if (read_model_from_file("simple_linear.onnx", &model_param)) {
		ret = -1;
		goto odp_term;
	}

	ml_model = odp_ml_model_create("simple linear", &model_param);
	free(model_param.model);
	if (ml_model == ODP_ML_MODEL_INVALID) {
		ODPH_ERR("odp_ml_model_create() failed\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_model_print(ml_model);
	odp_ml_print();

	if (odp_ml_model_load(ml_model, NULL)) {
		ODPH_ERR("odp_ml_model_load() failed\n");
		ret = -1;
		goto destroy_model;
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("_thread_args", sizeof(thread_args_t),
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem reserve failed.\n");
		ret = -1;
		goto unload;
	}

	thread_args = odp_shm_addr(shm);
	if (thread_args == NULL) {
		ODPH_ERR("Error: shared mem alloc failed.\n");
		ret = -1;
		goto free_shm;
	}
	thread_args->shm = shm;
	memset(thread_args, 0, sizeof(thread_args_t));

	/* Prepare inference parameter */
	for (uint32_t i = 0; i < num; i++) {
		thread_args->infer_param[i].x = x[i];
		thread_args->infer_param[i].ml_model = ml_model;
	}

	num_workers = odp_cpumask_default_worker(&cpumask, num);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	odph_thread_common_param_init(&thr_common);
	thr_common.instance    = inst;
	thr_common.cpumask     = &cpumask;

	for (int i = 0; i < num_workers; ++i) {
		odph_thread_param_init(&thr_param[i]);
		thr_param[i].start = run_inference;
		thr_param[i].arg = &thread_args->infer_param[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;
	}

	odph_thread_create(thread_tbl, &thr_common, thr_param, num_workers);

	odph_thread_join(thread_tbl, num_workers);

free_shm:
	if (odp_shm_free(shm)) {
		ODPH_ERR("Error: shm free global data\n");
		return -1;
	}

unload:
	/* Unload a model */
	if (odp_ml_model_unload(ml_model, NULL)) {
		ODPH_ERR("odp_ml_model_load() failed\n");
		ret = -1;
	}

destroy_model:
	if (odp_ml_model_destroy(ml_model)) {
		ODPH_ERR("odp_ml_model_destroy() failed\n");
		ret = -1;
	}

odp_term:
	if (odp_term_local()) {
		ODPH_ERR("Local term failed.\n");
		return -1;
	}

	if (odp_term_global(inst)) {
		ODPH_ERR("Global term failed.\n");
		return -1;
	}

	return ret;
}

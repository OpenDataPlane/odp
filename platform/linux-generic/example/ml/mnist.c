/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <inttypes.h>

#include "model_read.h"

/**
 * About MNIST model used in this example.
 *
 * The model predicts handwritten digits. It has one input and one output whose
 * detailed information is as follows:
 *
 * Input:
 *	Name: Input3, type: float32, shape: [1, 1, 28, 28]
 *
 * Output:
 *	Name: Plus214_Output_0, type: float32, shape: [1, 10]
 *
 * Refer https://github.com/onnx/models/tree/main/validated/vision/classification/mnist
 * for more information about the model.
 *
 * The model outputs the likelihood of each number before softmax, so we need to
 * map the output to probabilities across the 10 classes with softmax function.
 *
 * In this example, the input image is stored in example_digit.csv file, which
 * contains, comma separated, the digit label (a number from 0 to 9) and the 784
 * pixel values (a number from 0 to 255). Pixel order is first left to right and
 * then top down. The MNIST dataset is available in this format at
 * https://www.kaggle.com/oddrationale/mnist-in-csv.
 */

#define MAX_MODEL_SIZE 30000
#define INPUT_NUM_ELEMS 784 /* Total shape for input: 1 * 1 * 28 * 28 */
#define OUTPUT_NUM_ELEMS 10 /* Total shape for output: 1 * 10 */

static int read_digit_csv(const char *file_name, uint8_t *expected_digit, float *pixels)
{
	char *tmp;
	char *token;
	char *end;
	FILE *digit_file;
	size_t size, num_elem;
	const char *delim = ","; /* Delimiter */
	size_t num_pixel = 0;

	/* Get the model file size in bytes */
	digit_file = fopen(file_name, "rb");
	fseek(digit_file, 0, SEEK_END);
	size = ftell(digit_file);
	rewind(digit_file);

	tmp = malloc(size + 1);
	memset(tmp, 0, size + 1);
	num_elem = fread(tmp, size, 1, digit_file);

	fclose(digit_file);
	if (num_elem != 1) {
		printf("Read digit file failed\n");
		free(tmp);
		return -1;
	}

	/* Get the first token which is the expected digit */
	token = strtok(tmp, delim);
	*expected_digit = (uint8_t)strtol(token, &end, 10);
	if ((*expected_digit > 9) || (end == token)/*No numeric character*/) {
		printf("Invalid digit %u or no numeric character available\n",
		       *expected_digit);
		free(tmp);
		return -1;
	}

	/* The rest 784 numbers are pixel values */
	token = strtok(NULL, delim);
	while (token != NULL) {
		pixels[num_pixel] = strtof(token, NULL);
		num_pixel++;
		token = strtok(NULL, delim);
	}

	if (num_pixel != INPUT_NUM_ELEMS) {
		printf("Wrong number of pixels: %zu (expected:784)\n", num_pixel);
		free(tmp);
		return -1;
	}

	free(tmp);
	return 0;
}

static int prepare_run_params(const char *file_name, uint8_t *expected_digit,
			      odp_ml_data_seg_t *input, odp_ml_data_seg_t *output)
{
	input->size = INPUT_NUM_ELEMS * sizeof(float);
	input->addr = malloc(input->size);
	memset(input->addr, 0, input->size);

	if (read_digit_csv(file_name, expected_digit, input->addr)) {
		free(input->addr);
		return -1;
	}

	output->size = OUTPUT_NUM_ELEMS * sizeof(float);
	output->addr = malloc(output->size);
	memset(output->addr, 0, output->size);

	return 0;
}

static float array_max(float *arr, uint8_t arr_len)
{
	float max = arr[0];

	for (size_t i = 1; i < arr_len; i++) {
		if (arr[i] > max)
			max = arr[i];
	}

	return max;
}

static void softmax(float *input, uint8_t input_len)
{
	float rowmax = array_max(input, input_len);

	float input_exp[input_len];
	float sum = 0.0f;

	for (size_t i = 0; i != input_len; ++i) {
		input_exp[i] = exp(input[i] - rowmax);
		sum += input_exp[i];
	}

	for (size_t i = 0; i != input_len; ++i)
		input[i] = input_exp[i] / sum;
}

static uint8_t index_of_max(float *arr, uint8_t arr_len)
{
	uint8_t i = 0;
	uint8_t max_index = 0;
	float max = arr[0];

	for (i = 1; i < arr_len; i++) {
		if (arr[i] > max) {
			max = arr[i];
			max_index = i;
		}
	}

	return max_index;
}

int main(int argc, char *argv[])
{
	const char *model_file;
	const char *input_file;
	float *probabilities;
	uint8_t expected_digit;
	uint8_t predicted_digit;
	odp_instance_t inst;
	odp_ml_data_t data;
	odp_ml_model_t ml_model;
	odp_ml_data_seg_t input;
	odp_ml_data_seg_t output;
	odp_ml_capability_t capa;
	odp_ml_config_t ml_config;
	odp_ml_model_param_t model_param;
	int ret = 0;

	if (argc != 3) {
		printf("Please provide an input image file for classification.\n"
		       "\nUsage:\n"
		       "  %s model_file input_image\n"
		       "\nThis example classifies digit written on the input image.\n\n",
		       argv[0]);
		return -1;
	}

	model_file = argv[1];
	input_file = argv[2];

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

	if (MAX_MODEL_SIZE > capa.max_model_size) {
		printf("Configured max model size %d exceeds max mode size %" PRIu64 " in capa\n",
		       MAX_MODEL_SIZE, capa.max_model_size);
		ret = -1;
		goto odp_term;
	}

	odp_ml_config_init(&ml_config);
	ml_config.max_model_size = MAX_MODEL_SIZE;
	ml_config.load_mode_mask = ODP_ML_COMPL_MODE_SYNC;
	ml_config.run_mode_mask = ODP_ML_COMPL_MODE_SYNC;

	if (odp_ml_config(&ml_config)) {
		printf("odp_ml_config() failed\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_model_param_init(&model_param);
	if (read_model_from_file(model_file, &model_param)) {
		printf("Read model file failed\n");
		ret = -1;
		goto odp_term;
	}

	ml_model = odp_ml_model_create("mnist", &model_param);
	free(model_param.model);
	if (ml_model == ODP_ML_MODEL_INVALID) {
		printf("odp_ml_model_create() failed\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_model_print(ml_model);

	if (odp_ml_model_load(ml_model, NULL)) {
		printf("odp_ml_model_load() failed\n");
		ret = -1;
		goto destroy_model;
	}

	data.num_input_seg = 1;
	data.num_output_seg = 1;
	data.input_seg = &input;
	data.output_seg = &output;
	if (prepare_run_params(input_file, &expected_digit, &input, &output)) {
		printf("prepare_run_params() failed\n");
		ret = -1;
		goto unload;
	}

	if (odp_ml_run(ml_model, &data, NULL) != 1) {
		printf("odp_ml_model_run() failed\n");
		ret = -1;
		goto free_model_io;
	}

	probabilities = output.addr;

	/* Post-process the model output */
	softmax(probabilities, OUTPUT_NUM_ELEMS);
	predicted_digit = index_of_max(probabilities, OUTPUT_NUM_ELEMS);
	printf("predicted_digit: %u, expected_digit: %u\n", predicted_digit, expected_digit);

free_model_io:
	free(input.addr);
	free(output.addr);

unload:
	if (odp_ml_model_unload(ml_model, NULL)) {
		printf("odp_ml_model_unload() failed\n");
		ret = -1;
		goto odp_term;
	}

destroy_model:
	/* Destroy the model */
	if (odp_ml_model_destroy(ml_model)) {
		printf("odp_ml_model_destroy() failed\n");
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

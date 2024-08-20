/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <odp_api.h>

#include "model_read.h"

int read_model_from_file(const char *file_name, odp_ml_model_param_t *model_param)
{
	FILE *model_file;
	/* Number of elements successfully read */
	size_t num_elem;

	/* Get the model file size in bytes */
	model_file = fopen(file_name, "rb");
	if (model_file == NULL) {
		perror("Failed to open model file");
		return -1;
	}

	fseek(model_file, 0, SEEK_END);
	model_param->size = ftell(model_file);
	rewind(model_file);

	/* Allocate memory for model buffer */
	model_param->model = malloc(model_param->size);
	if (!model_param->model) {
		printf("Allocating memory for model buffer failed\n");
		return -1;
	}
	memset(model_param->model, 0, model_param->size);

	/* Read the model file */
	num_elem = fread(model_param->model, model_param->size, 1, model_file);
	fclose(model_file);
	if (num_elem != 1) {
		printf("Read model file failed\n");
		free(model_param->model);
		return -1;
	}

	return 0;
}

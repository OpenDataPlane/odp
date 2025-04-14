/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

/**
 * @example odp_ml_run.c
 *
 * This example shows how to load a trained ML model and perform inference using files as input and
 * output.
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>

/* Max number of inputs and outputs */
#define MAX_IO 8
#define ENGINE_ID 0

typedef struct io_size {
	uint64_t elems, size;
	int elem_size;
} io_size;

static struct {
	struct {
		char *model_name, *input_name, *output_name, *reference_name;
		float scale_q, scale_d;
		int num_batch;
	} opt;
	odp_ml_model_t mdl;
	odp_ml_capability_t capa;
	odp_ml_model_info_t info;
	int num_inp, num_out;
	odp_ml_input_info_t inp_info[MAX_IO];
	io_size inp[MAX_IO];
	odp_ml_output_info_t out_info[MAX_IO];
	io_size out[MAX_IO];
	uint64_t inp_size_q, inp_size_d, out_size_q, out_size_d;
} glb = { .opt = { .num_batch = 1 } };

static void *read_file(const char *name, uint64_t *size)
{
	FILE *file = fopen(name, "rb");

	if (!file) {
		ODPH_ERR("Failed to open file %s: %s\n", name, strerror(errno));
		return NULL;
	}

	void *addr = NULL;

	if (fseek(file, 0, SEEK_END)) {
		ODPH_ERR("Failed to get file size for file %s\n", name);
		goto error;
	}

	long pos = ftell(file);

	if (pos < 0) {
		ODPH_ERR("Failed to get file size for file %s\n", name);
		goto error;
	}

	rewind(file);
	*size = pos;
	addr = malloc(*size);

	if (!addr) {
		ODPH_ERR("Allocating %" PRIu64 " bytes failed\n", *size);
		goto error;
	}

	if (fread(addr, *size, 1, file) != 1) {
		ODPH_ERR("Reading %" PRIu64 " bytes failed\n", *size);
		goto error;
	}

	fclose(file);
	printf("Read %" PRIu64 " bytes from %s\n", *size, name);

	return addr;

error:
	fclose(file);
	free(addr);

	return NULL;
}

static int write_file(const char *name, uint8_t *addr, uint64_t size)
{
	FILE *file = fopen(name, "wb");

	if (!file) {
		ODPH_ERR("Failed to open file %s, %s\n", name, strerror(errno));
		return -1;
	}

	if (fwrite(addr, size, 1, file) != 1) {
		ODPH_ERR("Writing %" PRIu64 " bytes failed\n", size);
		fclose(file);
		return -1;
	}

	printf("Wrote %" PRIu64 " bytes to %s\n", size, name);

	fclose(file);
	return 0;
}

static void usage(const char *prog)
{
	printf("\n"
	       "Usage: %s [options]\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -m, --model <file>      Model file\n"
	       "  -i, --input <file>      Input file\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -o, --output <file>     Output file\n"
	       "  -r, --reference <file>  Reference file\n"
	       "  -q, --quant <scale>     Quantization scale\n"
	       "  -d, --dequant <scale>   Dequantization scale\n"
	       "  -b, --batches <num>     Number of batches\n"
	       "  -h, --help              Help\n"
	       "\n",
	       prog);
}

static void parse_args(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "model", required_argument, NULL, 'm' },
		{ "input", required_argument, NULL, 'i' },
		{ "output", required_argument, NULL, 'o' },
		{ "reference", required_argument, NULL, 'r' },
		{ "quant", required_argument, NULL, 'q' },
		{ "dequant", required_argument, NULL, 'd' },
		{ "batches", required_argument, NULL, 'b' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 } };

	static const char *shortopts = "+m:i:o:r:q:d:b:h";

	while (1) {
		int c = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (c == -1)
			break; /* No more options */

		switch (c) {
		case 'm':
			glb.opt.model_name = optarg;
			break;
		case 'i':
			glb.opt.input_name = optarg;
			break;
		case 'o':
			glb.opt.output_name = optarg;
			break;
		case 'r':
			glb.opt.reference_name = optarg;
			break;
		case 'q':
			glb.opt.scale_q = atof(optarg);
			break;
		case 'd':
			glb.opt.scale_d = atof(optarg);
			break;
		case 'b':
			glb.opt.num_batch = atof(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
			break;
		}
	}

	optind = 1; /* reset 'extern optind' from the getopt lib */

	if (!glb.opt.model_name || !glb.opt.input_name) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
}

static int check_num_batch(void)
{
	int min_batch = 1, max_batch = 1;

	for (int i = 0; i < glb.num_inp; i++) {
		odp_ml_shape_info_t *shape = &glb.inp_info[i].shape;

		for (int j = 0; j < (int)shape->num_dim; j++) {
			if (shape->dim[j] == ODP_ML_DIM_DYNAMIC) {
				min_batch = shape->dim_min[j];
				max_batch = shape->dim_max[j];
				break;
			}
		}
	}

	if (glb.opt.num_batch < min_batch || glb.opt.num_batch > max_batch) {
		ODPH_ERR("Number of batches %d out of range [%d, %d]\n", glb.opt.num_batch,
			 min_batch, max_batch);
		return -1;
	}

	return 0;
}

static void calc_io_size(void)
{
	for (int i = 0; i < glb.num_inp; i++) {
		uint64_t elems = 1;
		odp_ml_input_info_t *info = &glb.inp_info[i];
		odp_ml_shape_info_t *shape = &info->shape;
		io_size *inp = &glb.inp[i];

		printf("Input %d: %s, shape:", i, info->name);

		for (int j = 0; j < (int)shape->num_dim; j++) {
			printf(" %d", shape->dim[j]);
			if (shape->dim[j] != ODP_ML_DIM_DYNAMIC)
				elems *= shape->dim[j];
		}

		if (shape->type == ODP_ML_SHAPE_BATCH)
			elems *= glb.opt.num_batch;
		inp->elems = elems;
		inp->elem_size = info->data_type_size;
		inp->size = elems * info->data_type_size;
		glb.inp_size_q += inp->size;
		glb.inp_size_d += elems * sizeof(float);

		printf(", elems: %" PRIu64 ", datatype size: %d, size: %" PRIu64 "\n",
		       inp->elems, inp->elem_size, inp->size);
	}

	printf("Input size_q: %" PRIu64 ", size_d: %" PRIu64 "\n", glb.inp_size_q, glb.inp_size_d);

	for (int i = 0; i < glb.num_out; i++) {
		uint64_t elems = 1;
		odp_ml_output_info_t *info = &glb.out_info[i];
		odp_ml_shape_info_t *shape = &info->shape;
		io_size *out = &glb.out[i];

		printf("Output %d: %s, shape:", i, info->name);

		for (int j = 0; j < (int)shape->num_dim; j++) {
			printf(" %d", shape->dim[j]);
			if (shape->dim[j] != ODP_ML_DIM_DYNAMIC)
				elems *= shape->dim[j];
		}

		if (shape->type == ODP_ML_SHAPE_BATCH)
			elems *= glb.opt.num_batch;
		out->elems = elems;
		out->elem_size = info->data_type_size;
		out->size = elems * info->data_type_size;
		glb.out_size_q += out->size;
		glb.out_size_d += elems * sizeof(float);

		printf(", elems: %" PRIu64 ", datatype size: %d, size: %" PRIu64 "\n",
		       out->elems, out->elem_size, out->size);
	}

	printf("Output size_q: %" PRIu64 ", size_d: %" PRIu64 "\n", glb.out_size_q, glb.out_size_d);
}

static int quantize_input(uint8_t *inp_q_addr, uint8_t *inp_d_addr)
{
	for (int i = 0; i < glb.num_inp; i++) {
		float scale_q = glb.opt.scale_q;
		uint64_t elems = glb.inp[i].elems;
		odp_ml_input_info_t *info = &glb.inp_info[i];

		switch (info->data_type) {
		case ODP_ML_DATA_TYPE_INT8:
			odp_ml_fp32_to_int8((int8_t *)inp_q_addr, (float *)inp_d_addr, elems,
					    scale_q, 0);
			break;
		case ODP_ML_DATA_TYPE_UINT8:
			odp_ml_fp32_to_uint8((uint8_t *)inp_q_addr, (float *)inp_d_addr, elems,
					     scale_q, 0);
			break;
		case ODP_ML_DATA_TYPE_FP16:
			odp_ml_fp32_to_fp16((uint16_t *)inp_q_addr, (float *)inp_d_addr, elems);
			break;
		default:
			ODPH_ERR("Unsupported type %d for input %d\n", info->data_type, i);
			return -1;
		}

		inp_q_addr += glb.inp[i].size;
		inp_d_addr += elems * sizeof(float);
	}

	return 0;
}

static int dequantize_output(uint8_t *out_d_addr, uint8_t *out_q_addr)
{
	for (int i = 0; i < glb.num_out; i++) {
		float scale_d = glb.opt.scale_d;
		uint64_t elems = glb.out[i].elems;
		odp_ml_output_info_t *info = &glb.out_info[i];

		switch (info->data_type) {
		case ODP_ML_DATA_TYPE_INT8:
			odp_ml_fp32_from_int8((float *)out_d_addr, (int8_t *)out_q_addr, elems,
					      scale_d, 0);
			break;
		case ODP_ML_DATA_TYPE_UINT8:
			odp_ml_fp32_from_uint8((float *)out_d_addr, (uint8_t *)out_q_addr, elems,
					       scale_d, 0);
			break;
		case ODP_ML_DATA_TYPE_FP16:
			odp_ml_fp32_from_fp16((float *)out_d_addr, (uint16_t *)out_q_addr, elems);
			break;
		default:
			ODPH_ERR("Unsupported type %d for output %d\n", info->data_type, i);
			return -1;
		}

		out_q_addr += glb.out[i].size;
		out_d_addr += elems * sizeof(float);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	odp_instance_t inst;
	odp_ml_config_t ml_config;
	odp_ml_model_param_t model_param;
	int ret = 0;
	void *input_file = NULL, *output_file = NULL, *reference_file = NULL;
	uint64_t input_file_size, reference_file_size;
	uint8_t *input = NULL, *output = NULL;
	int num_engines;

	parse_args(argc, argv);

	if (odp_init_global(&inst, NULL, NULL)) {
		ODPH_ERR("Global init failed\n");
		return -1;
	}

	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed\n");
		return -1;
	}

	num_engines = odp_ml_num_engines();
	if (num_engines < 0) {
		ODPH_ERR("odp_ml_num_engines() failed\n");
		ret = -1;
		goto odp_term;
	}

	if (num_engines == 0) {
		ODPH_ERR("ML engine not available\n");
		ret = -1;
		goto odp_term;
	}

	if (odp_ml_capability(ENGINE_ID, &glb.capa)) {
		ODPH_ERR("odp_ml_capability() failed\n");
		ret = -1;
		goto odp_term;
	}

	if (glb.capa.min_input_align > 1) {
		ODPH_ERR("Minimum input alignment %d not supported\n", glb.capa.min_input_align);
		ret = -1;
		goto odp_term;
	}

	if (glb.capa.min_output_align > 1) {
		ODPH_ERR("Minimum output alignment %d not supported\n", glb.capa.min_output_align);
		ret = -1;
		goto odp_term;
	}

	odp_ml_config_init(&ml_config);
	ml_config.max_model_size = glb.capa.max_model_size;
	ml_config.load_mode_mask = ODP_ML_COMPL_MODE_SYNC;
	ml_config.run_mode_mask = ODP_ML_COMPL_MODE_SYNC;

	if (odp_ml_config(&ml_config)) {
		ODPH_ERR("odp_ml_config() failed\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_model_param_init(&model_param);

	model_param.model = read_file(glb.opt.model_name, &model_param.size);
	if (!model_param.model) {
		ODPH_ERR("Failed to read model file\n");
		ret = -1;
		goto odp_term;
	}

	glb.mdl = odp_ml_model_create(glb.opt.model_name, &model_param);
	free(model_param.model);
	if (glb.mdl == ODP_ML_MODEL_INVALID) {
		ODPH_ERR("odp_ml_model_create() failed\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_model_print(glb.mdl);

	if (odp_ml_model_load(glb.mdl, NULL)) {
		ODPH_ERR("odp_ml_model_load() failed\n");
		ret = -1;
		goto odp_term;
	}

	if (odp_ml_model_info(glb.mdl, &glb.info)) {
		ODPH_ERR("odp_ml_model_info() failed\n");
		ret = -1;
		goto odp_term;
	}

	glb.num_inp = odp_ml_model_input_info(glb.mdl, glb.inp_info, MAX_IO);

	if (glb.num_inp < 0 || glb.num_inp > MAX_IO) {
		ODPH_ERR("odp_ml_model_input_info() failed, or too many inputs\n");
		ret = -1;
		goto odp_term;
	}

	glb.num_out = odp_ml_model_output_info(glb.mdl, glb.out_info, MAX_IO);

	if (glb.num_out < 0 || glb.num_out > MAX_IO) {
		ODPH_ERR("odp_ml_model_output_info() failed, or too many outputs\n");
		ret = -1;
		goto odp_term;
	}

	if (check_num_batch()) {
		ret = -1;
		goto odp_term;
	}

	input_file = read_file(glb.opt.input_name, &input_file_size);
	if (!input_file)
		return -1;

	calc_io_size();

	if ((glb.opt.scale_q > 0.0 && input_file_size != glb.inp_size_d) ||
	    (!(glb.opt.scale_q > 0.0) && input_file_size != glb.inp_size_q)) {
		ODPH_ERR("Input file size mismatch\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_data_seg_t inp_seg[MAX_IO];
	uint8_t *inp_addr = input_file;

	if (glb.opt.scale_q > 0.0) {
		input = malloc(glb.inp_size_q);
		if (!input) {
			ODPH_ERR("Allocating %" PRIu64 " bytes failed\n", glb.inp_size_q);
			ret = -1;
			goto odp_term;
		}

		if (quantize_input(input, input_file)) {
			ret = -1;
			goto odp_term;
		}

		inp_addr = input;
	}

	for (int i = 0; i < glb.num_inp; i++) {
		inp_seg[i].addr = inp_addr;
		inp_seg[i].size = glb.inp[i].size;
		inp_addr += glb.inp[i].size;
	}

	output = malloc(glb.out_size_q);

	if (!output) {
		ODPH_ERR("Allocating %" PRIu64 " bytes failed\n", glb.out_size_q);
		ret = -1;
		goto odp_term;
	}

	odp_ml_data_seg_t out_seg[MAX_IO];
	uint8_t *out_addr = output;

	for (int i = 0; i < glb.num_out; i++) {
		out_seg[i].addr = out_addr;
		out_seg[i].size = glb.out[i].size;
		out_addr += glb.out[i].size;
	}

	odp_ml_data_t data = {
		.input_seg = inp_seg,
		.num_input_seg = glb.num_inp,
		.output_seg = out_seg,
		.num_output_seg = glb.num_out,
	};
	odp_ml_run_param_t run_param;

	odp_ml_run_param_init(&run_param);
	run_param.batch_size = glb.opt.num_batch;

	if (odp_ml_run(glb.mdl, &data, &run_param) != 1) {
		ODPH_ERR("odp_ml_run() failed\n");
		ret = -1;
		goto odp_term;
	}

	void *output_final = output;
	uint64_t out_size_final = glb.out_size_q;

	if (glb.opt.scale_d > 0.0) {
		output_file = malloc(glb.out_size_d);
		if (!output_file) {
			ODPH_ERR("Allocating %" PRIu64 " bytes failed\n", glb.out_size_d);
			ret = -1;
			goto odp_term;
		}

		if (dequantize_output(output_file, output)) {
			ret = -1;
			goto odp_term;
		}

		output_final = output_file;
		out_size_final = glb.out_size_d;
	}

	if (glb.opt.output_name) {
		if (write_file(glb.opt.output_name, output_final, out_size_final)) {
			ret = -1;
			goto odp_term;
		}
	}

	if (glb.opt.reference_name)
		reference_file = read_file(glb.opt.reference_name, &reference_file_size);

	if (reference_file) {
		if (out_size_final != reference_file_size) {
			ODPH_ERR("Output size mismatch: %" PRIu64
				 " differs from reference file size %" PRIu64 "\n",
				 out_size_final, reference_file_size);
			ret = -1;
			goto odp_term;
		}

		if (memcmp(reference_file, output_final, out_size_final)) {
			ODPH_ERR("Output differs from reference\n");
			ret = -1;
		} else {
			printf("Output matches reference\n");
		}
	}

	if (odp_ml_model_unload(glb.mdl, NULL)) {
		ODPH_ERR("odp_ml_model_unload() failed\n");
		ret = -1;
		goto odp_term;
	}

	if (odp_ml_model_destroy(glb.mdl)) {
		ODPH_ERR("odp_ml_model_destroy() failed\n");
		ret = -1;
		goto odp_term;
	}

odp_term:
	free(input);
	free(output);
	free(input_file);
	free(output_file);
	free(reference_file);

	if (odp_term_local()) {
		ODPH_ERR("Local term failed\n");
		return -1;
	}

	if (odp_term_global(inst)) {
		ODPH_ERR("Global term failed\n");
		return -1;
	}

	return ret;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

/**
 * @example odp_ml_perf.c
 *
 * Performance test application for ML API
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Max number of inputs and outputs */
#define MAX_IO 8
#define ENGINE_ID 0

#define TEST_SKIP 77

enum {
	MODE_INFERENCE = 0,
	MODE_INFERENCE_QUANT,
	MODE_CREATE,
	MODE_LOAD,
	MODE_NUM,
};

typedef struct {
	int mode, num_threads, rounds, latency, warmup;
	char *model_name, *input_name, *reference_name;
	float scale_q, scale_d;
	int num_batch;
} test_opt_t;

static test_opt_t opt_def = {
	.num_threads = 1,
	.rounds = 50,
	.warmup = 5,
	.num_batch = 1,
};

typedef struct io_size {
	uint64_t elems, size;
	int elem_size;
} io_size;

typedef struct ODP_ALIGNED_CACHE {
	uint64_t sum, min, max;
} stat_t;

typedef struct {
	test_opt_t opt;
	odp_barrier_t barrier;
	odp_shm_t model_file_shm;
	void *model_file_data;
	uint64_t model_file_size;
	odp_shm_t inp_file_shm;
	void *inp_file_data;
	uint64_t inp_file_size;
	odp_shm_t ref_file_shm;
	void *ref_file_data;
	uint64_t ref_file_size;
	odp_ml_model_t mdl;
	odp_ml_capability_t capa;
	odp_ml_model_info_t info;
	int num_inp, num_out;
	odp_ml_input_info_t inp_info[MAX_IO];
	io_size inp[MAX_IO];
	odp_ml_output_info_t out_info[MAX_IO];
	io_size out[MAX_IO];
	uint64_t inp_size_q, inp_size_d, out_size_q, out_size_d;
	stat_t stat[ODP_THREAD_COUNT_MAX];
} test_global_t;

static test_global_t *glb;

static void time_start(odp_time_t *t)
{
	*t = odp_time_local_strict();
}

static void time_elapsed(odp_time_t *t, int thr)
{
	odp_time_t stop = odp_time_local_strict();
	uint64_t nsec = odp_time_diff_ns(stop, *t);

	*t = stop;
	glb->stat[thr].sum += nsec;
	if (nsec < glb->stat[thr].min || !glb->stat[thr].min)
		glb->stat[thr].min = nsec;
	if (nsec > glb->stat[thr].max)
		glb->stat[thr].max = nsec;
}

static void *read_file(const char *name, uint64_t *size)
{
	void *addr = NULL;
	FILE *file = fopen(name, "rb");

	if (!file) {
		ODPH_ERR("Failed to open file %s: %s\n", name, strerror(errno));
		return NULL;
	}

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

static int read_file_to_shm(odp_shm_t *shm, void **data, uint64_t *size, const char *filename,
			    const char *name)
{
	void *file = read_file(filename, size);

	if (!file)
		return -1;

	*shm = odp_shm_reserve(name, *size, ODP_CACHE_LINE_SIZE, 0);

	if (*shm != ODP_SHM_INVALID)
		*data = odp_shm_addr(*shm);

	if (!*data) {
		ODPH_ERR("Failed to reserve shm for %s\n", filename);
		free(file);
		return -1;
	}

	memcpy(*data, file, *size);
	free(file);

	return 0;
}

static void usage(const char *prog)
{
	printf("\n"
	       "Usage: %s [options]\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -M, --model         Model file\n"
	       "  -I, --input         Input file\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -c, --num_cpu	      Number of CPUs (worker threads). 0: all available CPUs. Default 1.\n"
	       "  -r, --rounds        Number of test rounds. Default %u.\n"
	       "  -m, --mode          Test mode. Default 0.\n"
	       "                        0: Inference\n"
	       "                        1: Quantization-inference-dequantization\n"
	       "                        2: Create-destroy\n"
	       "                        3: Load-unload\n"
	       "  -l, --latency       Measure each round, report min, avg, max\n"
	       "  -w, --warmup        Warmup rounds. Default %d.\n"
	       "  -R, --reference     Reference file. To verify correctness, output from the last\n"
	       "                      inference is compared to this file.\n"
	       "  -q, --quant         Quantization scale\n"
	       "  -d, --dequant       Dequantization scale\n"
	       "  -b, --batches       Number of batches\n"
	       "  -h, --help          Help\n"
	       "\n",
	       prog, opt_def.rounds, opt_def.warmup);
}

static int parse_args(int argc, char *argv[])
{
	static const struct option longopts[] = {
		{ "model", required_argument, NULL, 'M' },
		{ "input", required_argument, NULL, 'I' },
		{ "num_cpu", required_argument, NULL, 'c' },
		{ "rounds", required_argument, NULL, 'r' },
		{ "mode", required_argument, NULL, 'm' },
		{ "latency", no_argument, NULL, 'l' },
		{ "warmup", required_argument, NULL, 'w' },
		{ "reference", required_argument, NULL, 'R' },
		{ "quant", required_argument, NULL, 'q' },
		{ "dequant", required_argument, NULL, 'd' },
		{ "batches", required_argument, NULL, 'b' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 } };

	static const char *shortopts = "+M:I:c:r:m:lw:R:q:d:b:h";

	glb->opt = opt_def;

	while (1) {
		int c = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (c == -1)
			break; /* No more options */

		switch (c) {
		case 'M':
			glb->opt.model_name = optarg;
			break;
		case 'I':
			glb->opt.input_name = optarg;
			break;
		case 'c':
			glb->opt.num_threads = atoi(optarg);
			break;
		case 'r':
			glb->opt.rounds = atoi(optarg);
			break;
		case 'm':
			glb->opt.mode = atoi(optarg);
			break;
		case 'l':
			glb->opt.latency = 1;
			break;
		case 'w':
			glb->opt.warmup = atoi(optarg);
			break;
		case 'R':
			glb->opt.reference_name = optarg;
			break;
		case 'q':
			glb->opt.scale_q = atof(optarg);
			break;
		case 'd':
			glb->opt.scale_d = atof(optarg);
			break;
		case 'b':
			glb->opt.num_batch = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			return 1;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	optind = 1; /* reset 'extern optind' from the getopt lib */

	if (!glb->opt.model_name || !glb->opt.input_name) {
		ODPH_ERR("Model and input files are mandatory\n");
		exit(EXIT_FAILURE);
	}

	if (glb->opt.mode < 0 || glb->opt.mode >= MODE_NUM) {
		ODPH_ERR("Invalid mode %d\n", glb->opt.mode);
		exit(EXIT_FAILURE);
	}

	printf("Options:\n");
	printf("--------\n");
	printf("model_name: %s\n", glb->opt.model_name);
	printf("input_name: %s\n", glb->opt.input_name);
	printf("num_cpu: %d\n", glb->opt.num_threads);
	printf("rounds: %u\n", glb->opt.rounds);
	printf("mode: %u\n", glb->opt.mode);
	printf("latency: %d\n", glb->opt.latency);
	printf("warmup: %d\n", glb->opt.warmup);
	printf("reference_name: %s\n", glb->opt.reference_name);
	printf("scale_q: %g\n", glb->opt.scale_q);
	printf("scale_d: %g\n", glb->opt.scale_d);
	printf("num_batch: %d\n", glb->opt.num_batch);
	printf("\n");

	return 0;
}

static int check_num_batch(void)
{
	int min_batch = 1, max_batch = 1;

	for (int i = 0; i < glb->num_inp; i++) {
		odp_ml_shape_info_t *shape = &glb->inp_info[i].shape;

		for (int j = 0; j < (int)shape->num_dim; j++) {
			if (shape->dim[j] == ODP_ML_DIM_DYNAMIC) {
				min_batch = shape->dim_min[j];
				max_batch = shape->dim_max[j];
				break;
			}
		}
	}

	if (glb->opt.num_batch < min_batch || glb->opt.num_batch > max_batch) {
		ODPH_ERR("Number of batches %d out of range [%d, %d]\n", glb->opt.num_batch,
			 min_batch, max_batch);
		return -1;
	}

	return 0;
}

static void calc_io_size(void)
{
	for (int i = 0; i < glb->num_inp; i++) {
		uint64_t elems = 1;
		odp_ml_input_info_t *info = &glb->inp_info[i];
		odp_ml_shape_info_t *shape = &info->shape;
		io_size *inp = &glb->inp[i];

		printf("Input %d: %s, shape:", i, info->name);

		for (int j = 0; j < (int)shape->num_dim; j++) {
			printf(" %d", shape->dim[j]);
			if (shape->dim[j] != ODP_ML_DIM_DYNAMIC)
				elems *= shape->dim[j];
		}

		if (shape->type == ODP_ML_SHAPE_BATCH)
			elems *= glb->opt.num_batch;
		inp->elems = elems;
		inp->elem_size = info->data_type_size;
		inp->size = elems * info->data_type_size;
		glb->inp_size_q += inp->size;
		glb->inp_size_d += elems * sizeof(float);

		printf(", elems: %" PRIu64 ", datatype size: %d, size: %" PRIu64 "\n", inp->elems,
		       inp->elem_size, inp->size);
	}

	printf("Input size_q: %" PRIu64 ", size_d: %" PRIu64 "\n", glb->inp_size_q,
	       glb->inp_size_d);

	for (int i = 0; i < glb->num_out; i++) {
		uint64_t elems = 1;
		odp_ml_output_info_t *info = &glb->out_info[i];
		odp_ml_shape_info_t *shape = &info->shape;
		io_size *out = &glb->out[i];

		printf("Output %d: %s, shape:", i, info->name);

		for (int j = 0; j < (int)shape->num_dim; j++) {
			printf(" %d", shape->dim[j]);
			if (shape->dim[j] != ODP_ML_DIM_DYNAMIC)
				elems *= shape->dim[j];
		}

		if (shape->type == ODP_ML_SHAPE_BATCH)
			elems *= glb->opt.num_batch;
		out->elems = elems;
		out->elem_size = info->data_type_size;
		out->size = elems * info->data_type_size;
		glb->out_size_q += out->size;
		glb->out_size_d += elems * sizeof(float);

		printf(", elems: %" PRIu64 ", datatype size: %d, size: %" PRIu64 "\n", out->elems,
		       out->elem_size, out->size);
	}

	printf("Output size_q: %" PRIu64 ", size_d: %" PRIu64 "\n", glb->out_size_q,
	       glb->out_size_d);
}

static int data_type_supported(odp_ml_data_type_t data_type)
{
	switch (data_type) {
	case ODP_ML_DATA_TYPE_INT8:
	case ODP_ML_DATA_TYPE_UINT8:
	case ODP_ML_DATA_TYPE_FP16:
		return 1;
	default:
		return 0;
	}
}

static void quantize_input(uint8_t *inp_q_addr, uint8_t *inp_d_addr)
{
	for (int i = 0; i < glb->num_inp; i++) {
		float scale_q = glb->opt.scale_q;
		uint64_t elems = glb->inp[i].elems;
		odp_ml_data_type_t data_type = glb->inp_info[i].data_type;

		switch (data_type) {
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
			ODPH_ERR("Unsupported type %d for input %d\n", data_type, i);
		}

		inp_q_addr += glb->inp[i].size;
		inp_d_addr += elems * sizeof(float);
	}
}

static void dequantize_output(uint8_t *out_d_addr, uint8_t *out_q_addr)
{
	for (int i = 0; i < glb->num_out; i++) {
		float scale_d = glb->opt.scale_d;
		uint64_t elems = glb->out[i].elems;
		odp_ml_data_type_t data_type = glb->out_info[i].data_type;

		switch (data_type) {
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
			ODPH_ERR("Unsupported type %d for output %d\n", data_type, i);
		}

		out_q_addr += glb->out[i].size;
		out_d_addr += elems * sizeof(float);
	}
}

static int test_ml(void *ptr)
{
	odp_time_t time;
	odp_ml_data_seg_t inp_seg[MAX_IO];
	uint8_t *inp_addr;
	odp_ml_data_seg_t out_seg[MAX_IO];
	uint8_t *out_addr;
	int thread_idx = (int)(uintptr_t)ptr;
	void *input = NULL, *output = NULL, *output_file = NULL;
	void *output_final = NULL;
	uint64_t out_size_final = 0;
	int ret = 0;

	inp_addr = glb->inp_file_data;

	if (glb->opt.scale_q > 0.0) {
		input = malloc(glb->inp_size_q);
		if (!input) {
			ODPH_ERR("Allocating %" PRIu64 " bytes failed\n", glb->inp_size_q);
			ret = -1;
			goto error;
		}

		inp_addr = input;
	}

	for (int i = 0; i < glb->num_inp; i++) {
		inp_seg[i].addr = inp_addr;
		inp_seg[i].size = glb->inp[i].size;
		inp_addr += glb->inp[i].size;
	}

	output = malloc(glb->out_size_q);

	if (!output) {
		ODPH_ERR("Allocating %" PRIu64 " bytes failed\n", glb->out_size_q);
		ret = -1;
		goto error;
	}

	out_addr = output;
	output_final = output;
	out_size_final = glb->out_size_q;

	if (glb->opt.scale_d > 0.0) {
		output_file = malloc(glb->out_size_d);
		if (!output_file) {
			ODPH_ERR("Allocating %" PRIu64 " bytes failed\n", glb->out_size_d);
			ret = -1;
			goto error;
		}

		output_final = output_file;
		out_size_final = glb->out_size_d;
	}

	for (int i = 0; i < glb->num_out; i++) {
		out_seg[i].addr = out_addr;
		out_seg[i].size = glb->out[i].size;
		out_addr += glb->out[i].size;
	}

	odp_ml_data_t data = {
		.input_seg = inp_seg,
		.num_input_seg = glb->num_inp,
		.output_seg = out_seg,
		.num_output_seg = glb->num_out,
	};
	odp_ml_run_param_t run_param;

	odp_ml_run_param_init(&run_param);
	run_param.batch_size = glb->opt.num_batch;

	if (glb->opt.mode != MODE_INFERENCE_QUANT && glb->opt.scale_q > 0.0)
		quantize_input(input, glb->inp_file_data);

	odp_barrier_wait(&glb->barrier);

	for (int i = 0; i < glb->opt.rounds + glb->opt.warmup; i++) {
		if (i == glb->opt.warmup)
			time_start(&time);

		if (glb->opt.mode == MODE_INFERENCE_QUANT && glb->opt.scale_q > 0.0)
			quantize_input(input, glb->inp_file_data);

		int r;

		while (!(r = odp_ml_run(glb->mdl, &data, &run_param)))
			;
		if (r != 1) {
			ODPH_ERR("odp_ml_run() failed\n");
			ret = -1;
			goto error;
		}

		if (glb->opt.mode == MODE_INFERENCE_QUANT && glb->opt.scale_d > 0.0)
			dequantize_output(output_file, output);

		if (glb->opt.latency && i >= glb->opt.warmup)
			time_elapsed(&time, thread_idx);
	}

	if (!glb->opt.latency)
		time_elapsed(&time, thread_idx);

	if (glb->opt.mode != MODE_INFERENCE_QUANT && glb->opt.scale_d > 0.0)
		dequantize_output(output_file, output);

	if (glb->ref_file_data) {
		if (out_size_final != glb->ref_file_size) {
			ODPH_ERR("Output size mismatch: %" PRIu64
				 " differs from reference file size %" PRIu64 "\n",
				 out_size_final, glb->ref_file_size);
			ret = -1;
			goto error;
		}

		if (memcmp(glb->ref_file_data, output_final, out_size_final)) {
			ODPH_ERR("Output differs from reference\n");
			ret = -1;
			goto error;
		}
	}

error:
	free(input);
	free(output);
	free(output_file);

	return ret;
}

static int test_ml_create(void *ptr)
{
	odp_time_t time;
	int thread_idx = (int)(uintptr_t)ptr;
	odp_ml_model_t mdl;
	odp_ml_model_param_t model_param;
	int ret = 0;

	odp_ml_model_param_init(&model_param);
	model_param.model = glb->model_file_data;
	model_param.size = glb->model_file_size;

	odp_barrier_wait(&glb->barrier);

	for (int i = 0; i < glb->opt.rounds + glb->opt.warmup; i++) {
		if (i == glb->opt.warmup)
			time_start(&time);

		mdl = odp_ml_model_create(glb->opt.model_name, &model_param);
		if (mdl == ODP_ML_MODEL_INVALID) {
			ODPH_ERR("odp_ml_model_create() failed\n");
			ret = -1;
			goto error;
		}

		if (odp_ml_model_destroy(mdl)) {
			ODPH_ERR("odp_ml_model_destroy() failed\n");
			ret = -1;
			goto error;
		}

		if (glb->opt.latency && i >= glb->opt.warmup)
			time_elapsed(&time, thread_idx);
	}

	if (!glb->opt.latency)
		time_elapsed(&time, thread_idx);

error:
	return ret;
}

static int test_ml_load(void *ptr)
{
	odp_time_t time;
	int thread_idx = (int)(uintptr_t)ptr;
	odp_ml_model_t mdl;
	odp_ml_model_param_t model_param;
	int ret = 0;

	odp_ml_model_param_init(&model_param);
	model_param.model = glb->model_file_data;
	model_param.size = glb->model_file_size;

	mdl = odp_ml_model_create(glb->opt.model_name, &model_param);
	if (mdl == ODP_ML_MODEL_INVALID) {
		ODPH_ERR("odp_ml_model_create() failed\n");
		ret = -1;
		goto error;
	}

	odp_barrier_wait(&glb->barrier);

	for (int i = 0; i < glb->opt.rounds + glb->opt.warmup; i++) {
		if (i == glb->opt.warmup)
			time_start(&time);

		if (odp_ml_model_load(mdl, NULL)) {
			ODPH_ERR("odp_ml_model_load() failed\n");
			ret = -1;
			goto error;
		}

		if (odp_ml_model_unload(mdl, NULL)) {
			ODPH_ERR("odp_ml_model_unload() failed\n");
			ret = -1;
			goto error;
		}

		if (glb->opt.latency && i >= glb->opt.warmup)
			time_elapsed(&time, thread_idx);
	}

	if (!glb->opt.latency)
		time_elapsed(&time, thread_idx);

	if (odp_ml_model_destroy(mdl)) {
		ODPH_ERR("odp_ml_model_destroy() failed\n");
		ret = -1;
		goto error;
	}

error:
	return ret;
}

static void print_results_avg(void)
{
	int num_threads = glb->opt.num_threads;
	int rounds = glb->opt.rounds;

	printf("thread %15s %15s\n", "avg (nsec)", "rounds / sec");
	printf("--------------------------------------\n");
	if (num_threads > 1) {
		uint64_t avg = 0;

		for (int i = 0; i < num_threads; i++)
			avg += glb->stat[i].sum;

		avg /= rounds * num_threads;
		printf("%-6s %15" PRIu64 " %15.1f\n", "all", avg, (float)ODP_TIME_SEC_IN_NS / avg);
	}
	for (int i = 0; i < num_threads; i++) {
		glb->stat[i].sum /= rounds;
		printf("%-6d %15" PRIu64 " %15.1f\n", i, glb->stat[i].sum,
		       (float)ODP_TIME_SEC_IN_NS / glb->stat[i].sum);
	}
}

static void print_stat(stat_t *stat)
{
	printf("%15" PRIu64 " %15" PRIu64 " %15" PRIu64, stat->min, stat->sum, stat->max);
}

static void print_results_min_avg_max(void)
{
	int num_threads = glb->opt.num_threads;
	int rounds = glb->opt.rounds;

	printf("thread %15s %15s %15s\n", "min (nsec)", "avg (nsec)", "max (nsec)");
	printf("------------------------------------------------------\n");
	if (num_threads > 1) {
		stat_t s = { 0 };

		for (int i = 0; i < num_threads; i++) {
			s.sum += glb->stat[i].sum;
			if (glb->stat[i].min && (glb->stat[i].min < s.min || !s.min))
				s.min = glb->stat[i].min;
			if (glb->stat[i].max > s.max)
				s.max = glb->stat[i].max;
		}

		s.sum /= rounds * num_threads;
		printf("%-6s ", "all");
		print_stat(&s);
		printf("\n");
	}
	for (int i = 0; i < num_threads; i++) {
		glb->stat[i].sum /= rounds;
		printf("%-6d ", i);
		print_stat(&glb->stat[i]);
		printf("\n");
	}
}

static void print_results(void)
{
	printf("\n");

	if (glb->opt.latency)
		print_results_min_avg_max();
	else
		print_results_avg();

	printf("\n");
}

int main(int argc, char *argv[])
{
	odp_instance_t inst;
	odph_helper_options_t helper_options;
	odp_init_t init;
	odp_shm_t shm_glb;
	int num_engines;
	int ret = 0;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);

	if (odph_options(&helper_options)) {
		ODPH_ERR("Failed to read ODP helper options.\n");
		exit(EXIT_FAILURE);
	}

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto = 1;
	init.not_used.feat.dma = 1;
	init.not_used.feat.ipsec = 1;
	init.not_used.feat.schedule = 1;
	init.not_used.feat.timer = 1;
	init.not_used.feat.tm = 1;
	init.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&inst, &init, NULL)) {
		ODPH_ERR("Global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(inst, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_sys_info_print();

	shm_glb = odp_shm_reserve("test_globals", sizeof(test_global_t), ODP_CACHE_LINE_SIZE, 0);

	if (shm_glb != ODP_SHM_INVALID)
		glb = (test_global_t *)odp_shm_addr(shm_glb);

	if (!glb) {
		ODPH_ERR("Failed to reserve shm\n");
		ret = -1;
		goto odp_term;
	}

	memset(glb, 0, sizeof(test_global_t));

	ret = parse_args(argc, argv);
	if (ret) {
		if (ret > 0)
			ret = 0;
		goto odp_term;
	}

	if (read_file_to_shm(&glb->model_file_shm, &glb->model_file_data, &glb->model_file_size,
			     glb->opt.model_name, "ml_perf_model")) {
		ret = -1;
		goto odp_term;
	}

	if (read_file_to_shm(&glb->inp_file_shm, &glb->inp_file_data, &glb->inp_file_size,
			     glb->opt.input_name, "ml_perf_input")) {
		ret = -1;
		goto odp_term;
	}

	if (glb->opt.reference_name) {
		if (read_file_to_shm(&glb->ref_file_shm, &glb->ref_file_data, &glb->ref_file_size,
				     glb->opt.reference_name, "ml_perf_reference")) {
			ret = -1;
			goto odp_term;
		}
	}

	num_engines = odp_ml_num_engines();
	if (num_engines < 0) {
		ODPH_ERR("odp_ml_num_engines() failed\n");
		ret = num_engines;
		goto odp_term;
	}

	if (num_engines == 0) {
		ODPH_ERR("ML engine not available\n");
		ret = -1;
		goto odp_term;
	}

	if (odp_ml_capability(ENGINE_ID, &glb->capa)) {
		ODPH_ERR("odp_ml_capability() failed\n");
		ret = -1;
		goto odp_term;
	}

	if (glb->capa.max_models < 1) {
		ODPH_ERR("ML not supported (maximum number of models is zero)\n");
		ret = TEST_SKIP;
		goto odp_term;
	}

	if (glb->capa.max_model_size < glb->model_file_size) {
		ODPH_ERR("Model size %" PRIu64 " exceeds maximum %" PRIu64 "\n",
			 glb->model_file_size, glb->capa.max_model_size);
		ret = -1;
		goto odp_term;
	}

	if (glb->capa.min_input_align > 1) {
		ODPH_ERR("Minimum input alignment %u not supported\n", glb->capa.min_input_align);
		ret = -1;
		goto odp_term;
	}

	if (glb->capa.min_output_align > 1) {
		ODPH_ERR("Minimum output alignment %u not supported\n", glb->capa.min_output_align);
		ret = -1;
		goto odp_term;
	}

	if ((glb->opt.mode == MODE_CREATE || glb->opt.mode == MODE_LOAD) &&
	    (int)glb->capa.max_models < glb->opt.num_threads) {
		ODPH_ERR("Maximum number of models %u less than number of threads %d\n",
			 glb->capa.max_models, glb->opt.num_threads);
		ret = -1;
		goto odp_term;
	}

	if (glb->opt.mode == MODE_LOAD && (int)glb->capa.max_models_loaded < glb->opt.num_threads) {
		ODPH_ERR("Maximum number of models loaded %u less than number of threads %d\n",
			 glb->capa.max_models_loaded, glb->opt.num_threads);
		ret = -1;
		goto odp_term;
	}

	odp_ml_config_t ml_config;
	odp_ml_model_param_t model_param;

	odp_ml_config_init(&ml_config);
	ml_config.max_model_size = glb->capa.max_model_size;
	ml_config.load_mode_mask = ODP_ML_COMPL_MODE_SYNC;
	ml_config.run_mode_mask = ODP_ML_COMPL_MODE_SYNC;

	if (odp_ml_config(&ml_config)) {
		ODPH_ERR("odp_ml_config() failed\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_model_param_init(&model_param);
	model_param.model = glb->model_file_data;
	model_param.size = glb->model_file_size;

	glb->mdl = odp_ml_model_create(glb->opt.model_name, &model_param);
	if (glb->mdl == ODP_ML_MODEL_INVALID) {
		ODPH_ERR("odp_ml_model_create() failed\n");
		ret = -1;
		goto odp_term;
	}

	odp_ml_model_print(glb->mdl);

	if (odp_ml_model_load(glb->mdl, NULL)) {
		ODPH_ERR("odp_ml_model_load() failed\n");
		ret = -1;
		goto odp_term;
	}

	if (odp_ml_model_info(glb->mdl, &glb->info)) {
		ODPH_ERR("odp_ml_model_info() failed\n");
		ret = -1;
		goto odp_term;
	}

	glb->num_inp = odp_ml_model_input_info(glb->mdl, glb->inp_info, MAX_IO);

	if (glb->num_inp < 0 || glb->num_inp > MAX_IO) {
		ODPH_ERR("odp_ml_model_input_info() failed, or too many inputs\n");
		ret = -1;
		goto odp_term;
	}

	glb->num_out = odp_ml_model_output_info(glb->mdl, glb->out_info, MAX_IO);

	if (glb->num_out < 0 || glb->num_out > MAX_IO) {
		ODPH_ERR("odp_ml_model_output_info() failed, or too many outputs\n");
		ret = -1;
		goto odp_term;
	}

	if (check_num_batch()) {
		ret = -1;
		goto odp_term;
	}

	calc_io_size();

	if (glb->opt.scale_q > 0.0) {
		for (int i = 0; i < glb->num_inp; i++) {
			if (!data_type_supported(glb->inp_info[i].data_type)) {
				ODPH_ERR("Unsupported data type %d for input %d quantization\n",
					 glb->inp_info[i].data_type, i);
				ret = -1;
				goto odp_term;
			}
		}
		for (int i = 0; i < glb->num_out; i++) {
			if (!data_type_supported(glb->out_info[i].data_type)) {
				ODPH_ERR("Unsupported data type %d for output %d dequantization\n",
					 glb->out_info[i].data_type, i);
				ret = -1;
				goto odp_term;
			}
		}
	}

	if ((glb->opt.scale_q > 0.0 && glb->inp_file_size != glb->inp_size_d) ||
	    (!(glb->opt.scale_q > 0.0) && glb->inp_file_size != glb->inp_size_q)) {
		ODPH_ERR("Input file size mismatch\n");
		ret = -1;
		goto odp_term;
	}

	if (glb->opt.mode != MODE_INFERENCE && glb->opt.mode != MODE_INFERENCE_QUANT) {
		const odp_ml_model_t mdl = glb->mdl;

		glb->mdl = ODP_ML_MODEL_INVALID;

		if (odp_ml_model_unload(mdl, NULL)) {
			ODPH_ERR("odp_ml_model_unload() failed\n");
			ret = -1;
			goto odp_term;
		}

		if (odp_ml_model_destroy(mdl)) {
			ODPH_ERR("odp_ml_model_destroy() failed\n");
			ret = -1;
			goto odp_term;
		}
	}

	int num_threads = glb->opt.num_threads;

	odp_barrier_init(&glb->barrier, num_threads);

	odp_cpumask_t cpumask;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param[ODP_THREAD_COUNT_MAX];
	odph_thread_t thr_worker[ODP_THREAD_COUNT_MAX];
	odph_thread_join_result_t res[ODP_THREAD_COUNT_MAX];

	if (odp_cpumask_default_worker(&cpumask, num_threads) != num_threads) {
		ODPH_ERR("Failed to get default CPU mask.\n");
		ret = -1;
		goto odp_term;
	}

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = inst;
	thr_common.cpumask = &cpumask;

	for (int i = 0; i < num_threads; i++) {
		odph_thread_param_init(&thr_param[i]);
		thr_param[i].thr_type = ODP_THREAD_WORKER;
		thr_param[i].arg = (void *)(uintptr_t)i;
		switch (glb->opt.mode) {
		case MODE_INFERENCE:
		case MODE_INFERENCE_QUANT:
			thr_param[i].start = test_ml;
			break;
		case MODE_CREATE:
			thr_param[i].start = test_ml_create;
			break;
		case MODE_LOAD:
			thr_param[i].start = test_ml_load;
			break;
		}
	}

	memset(&thr_worker, 0, sizeof(thr_worker));

	if (odph_thread_create(thr_worker, &thr_common, thr_param, num_threads) != num_threads) {
		ODPH_ERR("Failed to create worker threads.\n");
		ret = -1;
		goto odp_term;
	}

	if (odph_thread_join_result(thr_worker, res, num_threads) != num_threads) {
		ODPH_ERR("Failed to join worker threads.\n");
		ret = -1;
		goto odp_term;
	}

	for (int i = 0; i < num_threads; i++) {
		if (res[i].is_sig || res[i].ret != 0) {
			ODPH_ERR("Worker thread failure%s: %d\n",
				 res[i].is_sig ? " (signaled)" : "", res[i].ret);
			ret = -1;
			goto odp_term;
		}
	}

	print_results();

odp_term:

	if (glb->mdl != ODP_ML_MODEL_INVALID) {
		if (odp_ml_model_unload(glb->mdl, NULL)) {
			ODPH_ERR("odp_ml_model_unload() failed\n");
			ret = -1;
		}

		if (odp_ml_model_destroy(glb->mdl)) {
			ODPH_ERR("odp_ml_model_destroy() failed\n");
			ret = -1;
		}
	}

	if (glb->model_file_shm != ODP_SHM_INVALID && odp_shm_free(glb->model_file_shm)) {
		ODPH_ERR("odp_shm_free() failed\n");
		ret = -1;
	}

	if (glb->inp_file_shm != ODP_SHM_INVALID && odp_shm_free(glb->inp_file_shm)) {
		ODPH_ERR("odp_shm_free() failed\n");
		ret = -1;
	}

	if (glb->ref_file_shm != ODP_SHM_INVALID && odp_shm_free(glb->ref_file_shm)) {
		ODPH_ERR("odp_shm_free() failed\n");
		ret = -1;
	}

	if (shm_glb != ODP_SHM_INVALID && odp_shm_free(shm_glb)) {
		ODPH_ERR("odp_shm_free() failed\n");
		ret = -1;
	}

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

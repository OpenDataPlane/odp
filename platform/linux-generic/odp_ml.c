/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp/autoheader_external.h>

#include <odp/api/atomic.h>
#include <odp/api/buffer.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp/api/ml.h>
#include <odp/api/pool.h>
#include <odp/api/queue.h>
#include <odp/api/shared_memory.h>
#include <odp/api/std_types.h>
#include <odp/api/ticketlock.h>

#include <odp/api/plat/event_inline_types.h>
#include <odp/api/plat/strong_types.h>

#include <odp_buffer_internal.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_macros_internal.h>
#include <odp_pool_internal.h>

#include <onnxruntime_c_api.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ML_MAX_IO_SEGS UINT32_MAX
#define ML_MAX_COMPL_ID 32
#define ML_MAX_CONFIG_STR_LEN 65
#define ML_MAX_MODEL_SIZE (1024 * 1024 * 1024)
#define ML_MAX_MODELS_CREATED CONFIG_ML_MAX_MODELS
#define ML_MAX_MODELS_LOADED CONFIG_ML_MAX_MODELS

/* Error codes */
enum {
	/* Feature not supported */
	ML_FEATURE_NOT_SUPPORTED = 1,

	/* Model is not created */
	ML_NOT_CREATED,

	/* Model was not loaded */
	ML_NOT_LOADED,

	/* Model has already loaded */
	ML_LOADED,

	/* Bad input */
	ML_BAD_INPUT,

	/* Fail from underlying library onnxruntime */
	ML_LIB_FAILED,

	/* Bad output */
	ML_BAD_OUTPUT,

	/* Bad handle */
	ML_BAD_HDL
};

typedef struct ort_run_opts_t {
	int enable_profiling;

	ExecutionMode execution_mode;

	int inter_op_num_threads;

	int intra_op_num_threads;

	GraphOptimizationLevel graph_opt_level;

	char opt_model_filepath[ML_MAX_CONFIG_STR_LEN];
} ort_run_opts_t;

typedef struct ml_input_t {
	/* Combined input start address */
	void *addr;
	/* Data size in bytes */
	uint64_t size;
} ml_input_t;

/* Onnxruntime model info */
typedef struct ml_model_t {
	/* Guards state, which must be accessed atomically */
	odp_ticketlock_t	lock;

	enum {
		ML_STATE_FREE = 0, /* Not allocated */
		ML_STATE_CREATED, /* Model is created */
		ML_STATE_LOADED, /* Model is loaded */
		ML_STATE_INFERENCING, /* Model is inferencing */
	} state;

	OrtSession		*session;
	OrtSessionOptions	*session_opts;
	uint32_t		max_compl_id;
	odp_atomic_u32_t	compl_status[ML_MAX_COMPL_ID];

	odp_ml_model_info_t	info;
	odp_ml_input_info_t	input_info[CONFIG_ML_MAX_INPUTS];
	uint64_t		input_sizes[CONFIG_ML_MAX_INPUTS];
	odp_ml_output_info_t	output_info[CONFIG_ML_MAX_OUTPUTS];
	uint64_t		output_sizes[CONFIG_ML_MAX_OUTPUTS];

	struct {
		void *user_ptr;
	} result[ML_MAX_COMPL_ID];
} ml_model_t;

typedef struct ml_global_t {
	odp_shm_t		shm;

	odp_ml_capability_t	capa;
	odp_ml_config_t		ml_config;

	odp_pool_param_t	pool_param;

	const OrtApi		*ort_api;
	OrtEnv			*env;
	ort_run_opts_t		ort_run_opts;

	ml_model_t		models[ML_MAX_MODELS_CREATED];

} ml_global_t;

static ml_global_t *_odp_ml_glb;

static inline ml_model_t *ml_model_from_handle(odp_ml_model_t model)
{
	return (ml_model_t *)(uintptr_t)model;
}

int odp_ml_capability(odp_ml_capability_t *capa)
{
	odp_pool_capability_t pool_capa;

	memset(capa, 0, sizeof(odp_ml_capability_t));

	if (odp_global_ro.disable.ml) {
		_ODP_PRINT("ML is disabled\n");
		return 0;
	}

	capa->max_model_size = ML_MAX_MODEL_SIZE;
	capa->max_models = ML_MAX_MODELS_CREATED;
	capa->max_models_loaded = ML_MAX_MODELS_LOADED;
	capa->max_compl_id = ML_MAX_COMPL_ID;
	capa->max_inputs = CONFIG_ML_MAX_INPUTS;
	capa->max_outputs = CONFIG_ML_MAX_OUTPUTS;
	capa->max_segs_per_input = ML_MAX_IO_SEGS;
	capa->max_segs_per_output = ML_MAX_IO_SEGS;
	capa->min_input_align = 1;
	capa->min_output_align = 1;

	capa->load.compl_mode_mask = ODP_ML_COMPL_MODE_SYNC |
				     ODP_ML_COMPL_MODE_POLL |
				     ODP_ML_COMPL_MODE_EVENT;
	capa->load.compl_queue_plain = 1;
	capa->load.compl_queue_sched = 1;

	capa->run.compl_mode_mask =  ODP_ML_COMPL_MODE_SYNC |
				     ODP_ML_COMPL_MODE_POLL |
				     ODP_ML_COMPL_MODE_EVENT;
	capa->run.compl_queue_plain = 1;
	capa->run.compl_queue_sched = 1;

	if (odp_pool_capability(&pool_capa)) {
		_ODP_ERR("Pool capability failed\n");
		return -1;
	}

	capa->pool.max_pools = pool_capa.buf.max_pools;
	capa->pool.max_num = pool_capa.buf.max_num;
	capa->pool.max_uarea_size = pool_capa.buf.max_uarea_size;
	capa->pool.uarea_persistence = pool_capa.buf.uarea_persistence;
	capa->pool.max_cache_size = pool_capa.buf.max_cache_size;
	capa->pool.min_cache_size = pool_capa.buf.min_cache_size;

	return 0;
}

void odp_ml_config_init(odp_ml_config_t *config)
{
	memset(config, 0, sizeof(odp_ml_config_t));
	config->max_models_created = 1;
	config->max_models_loaded = 1;
}

int odp_ml_config(const odp_ml_config_t *config)
{
	if (!config) {
		_ODP_ERR("Error: config must not be NULL\n");
		return -1;
	}

	if (config->max_model_size == 0 || config->max_models_created == 0 ||
	    config->max_models_loaded == 0) {
		_ODP_ERR("Error: max_model_size, max_models_created and max_models_loaded"
			 " must be bigger than 0\n");
		return -1;
	}

	if (config->max_models_loaded > config->max_models_created) {
		_ODP_ERR("Error: max_models_loaded %d exceeds max_models_created %d\n",
			 config->max_models_loaded, config->max_models_created);
		return -1;
	}

	if (config->max_models_created > ML_MAX_MODELS_CREATED) {
		_ODP_ERR("Error: max_models_created %d exceeds maximum number"
			 " of models that can be created in this driver %d\n",
			 config->max_models_created, ML_MAX_MODELS_CREATED);
		return -1;
	}

	if (config->max_models_loaded > ML_MAX_MODELS_LOADED) {
		_ODP_ERR("Error: max_models_loaded %d exceeds maximum number"
			 " of models that can be loaded in this driver %d\n",
			 config->max_models_loaded, ML_MAX_MODELS_LOADED);
		return -1;
	}

	if (config->max_model_size > ML_MAX_MODEL_SIZE) {
		_ODP_ERR("max_model_size %" PRIu64 " exceeds supported maximum model size %d\n",
			 config->max_model_size, ML_MAX_MODEL_SIZE);
		return -1;
	}

	_odp_ml_glb->ml_config = *config;
	return 0;
}

void odp_ml_model_param_init(odp_ml_model_param_t *param)
{
	memset(param, 0, sizeof(odp_ml_model_param_t));
}

static int check_ortstatus(OrtStatus * const status)
{
	if (status != NULL) {
		const char *msg = _odp_ml_glb->ort_api->GetErrorMessage(status);

		_ODP_ERR("%s\n", msg);
		_odp_ml_glb->ort_api->ReleaseStatus(status);
		return -1;
	}

	return 0;
}

/* Get model input and output count */
static int get_model_io_count(OrtSession *model, uint32_t *num_inputs, uint32_t *num_outputs)
{
	size_t num = 0;
	OrtStatus *status = NULL;
	const OrtApi *ort_api = _odp_ml_glb->ort_api;

	status = ort_api->SessionGetInputCount(model, &num);
	if (check_ortstatus(status)) {
		_ODP_ERR("Get model input count failed\n");
		return -1;
	}

	*num_inputs = num;
	_ODP_DBG("num_inputs: %u\n", *num_inputs);

	status = ort_api->SessionGetOutputCount(model, &num);
	if (check_ortstatus(status)) {
		_ODP_ERR("Get model output count failed\n");
		return -1;
	}

	*num_outputs = num;
	_ODP_DBG("num_outputs: %u\n", *num_outputs);

	return 0;
}

static odp_ml_data_type_t onnx_dtype_to_odp_dtype(ONNXTensorElementDataType onnx_dtype)
{
	switch (onnx_dtype) {
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT:
		return ODP_ML_DATA_TYPE_FP32;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8:
		return ODP_ML_DATA_TYPE_UINT8;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_INT8:
		return ODP_ML_DATA_TYPE_INT8;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT16:
		return ODP_ML_DATA_TYPE_UINT16;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_INT16:
		return ODP_ML_DATA_TYPE_INT16;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_INT32:
		return ODP_ML_DATA_TYPE_INT32;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT32:
		return ODP_ML_DATA_TYPE_UINT32;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64:
		return ODP_ML_DATA_TYPE_INT64;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT64:
		return ODP_ML_DATA_TYPE_UINT64;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT16:
		return ODP_ML_DATA_TYPE_FP16;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_BFLOAT16:
		return ODP_ML_DATA_TYPE_BFP16;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_DOUBLE:
		return ODP_ML_DATA_TYPE_FP64;
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_BOOL:
		/* Fall through */
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_COMPLEX64:
		/* Fall through */
	case ONNX_TENSOR_ELEMENT_DATA_TYPE_COMPLEX128:
		/* Fall through */
	default:
		_ODP_ERR("onnx_dtype %d not supported by odp_ml\n", onnx_dtype);
		return ODP_ML_DATA_TYPE_NONE;
	}
}

/* Get the size of given odp_ml_data_type_t in bytes */
static uint32_t size_of_odp_ml_data_type(odp_ml_data_type_t data_type)
{
	switch (data_type) {
	case ODP_ML_DATA_TYPE_NONE:
		return 0;

	case ODP_ML_DATA_TYPE_INT8:
		/* Fall through */
	case ODP_ML_DATA_TYPE_UINT8:
		return 1;

	case ODP_ML_DATA_TYPE_INT16:
		/* Fall through */
	case ODP_ML_DATA_TYPE_UINT16:
		/* Fall through */
	case ODP_ML_DATA_TYPE_FP16:
		/* Fall through */
	case ODP_ML_DATA_TYPE_BFP16:
		return 2;

	case ODP_ML_DATA_TYPE_INT24:
		/* Fall through */
	case ODP_ML_DATA_TYPE_UINT24:
		return 3;

	case ODP_ML_DATA_TYPE_INT32:
		/* Fall through */
	case ODP_ML_DATA_TYPE_UINT32:
		/* Fall through */
	case ODP_ML_DATA_TYPE_FP32:
		return 4;

	case ODP_ML_DATA_TYPE_INT64:
		/* Fall through */
	case ODP_ML_DATA_TYPE_UINT64:
		/* Fall through */
	case ODP_ML_DATA_TYPE_FP64:
		return 8;

	default:
		return 0;
	}
}

static int get_shape(int64_t dims[], odp_ml_shape_info_t *shape)
{
	uint32_t dyn_cnt = 0;

	for (uint32_t i = 0; i < shape->num_dim; i++) {
		if (dims[i] == 0) {
			_ODP_ERR("Dimension value: %" PRId64 " must be at least 1\n", dims[i]);
			return -1;
		} else if (dims[i] == -1) { /* Symbolic dimension */
			dyn_cnt++;
			shape->dim[i] = ODP_ML_DIM_DYNAMIC;
			shape->dim_min[i] = 0; /*unknown*/
			shape->dim_max[i] = 0; /*unknown*/
		} else if (dims[i] > 0 && dims[i] < UINT32_MAX) {
			shape->dim[i] = dims[i];
			shape->dim_min[i] = dims[i];
			shape->dim_max[i] = dims[i];
		} else {
			_ODP_ERR("Dimension value: %" PRId64 " invalid\n", dims[i]);
			return -1;
		}
	}

	if (dyn_cnt == 0) {
		shape->type = ODP_ML_SHAPE_STATIC;
	} else if (dyn_cnt == 1) {
		shape->type = ODP_ML_SHAPE_BATCH;
	} else {
		_ODP_ERR("Data shape type not supported by ODP\n");
		return -1;
	}

	return 0;
}

static inline void calculate_model_io_size(const odp_ml_shape_info_t *shape, uint64_t *size)
{
	/* Calculate the data size in bytes of this tensor, 0 for tensors with
	 * dynamic batch sizes */
	for (size_t i = 0; i < shape->num_dim; i++) {
		/* Skip dynamic dimension size */
		if (shape->dim[i] == ODP_ML_DIM_DYNAMIC) {
			*size = 0;
			break;
		}
		(*size) *= shape->dim[i];
	}
}

static int get_model_io_type_shape_size(OrtTypeInfo *type_info, odp_ml_shape_info_t *shape,
					odp_ml_data_type_t *data_type, uint32_t *data_type_size,
					uint64_t *size)
{
	ONNXTensorElementDataType tensor_type;
	const OrtTensorTypeAndShapeInfo *tensor_info;
	size_t num_dim = 0;
	OrtStatus *status = NULL;
	int64_t dims[ODP_ML_MAX_DIMS] = {0};
	const OrtApi *ort_api = _odp_ml_glb->ort_api;

	status = ort_api->CastTypeInfoToTensorInfo(type_info, &tensor_info);
	if (check_ortstatus(status)) {
		_ODP_ERR("CastTypeInfoToTensorInfo failed\n");
		return -1;
	}

	status = ort_api->GetTensorElementType(tensor_info, &tensor_type);
	if (check_ortstatus(status)) {
		_ODP_ERR("GetTensorElementType failed\n");
		return -1;
	}

	*data_type = onnx_dtype_to_odp_dtype(tensor_type);
	if (*data_type == ODP_ML_DATA_TYPE_NONE) /* Type not supported by odp */
		return -1;

	status = ort_api->GetDimensionsCount(tensor_info, &num_dim);
	if (check_ortstatus(status)) {
		_ODP_ERR("GetDimensionsCount failed\n");
		return -1;
	}

	if (num_dim > ODP_ML_MAX_DIMS) {
		_ODP_ERR("Number of dimensions: %zu exceeds supported maximum number"
			" of dimensions: %d\n", num_dim, ODP_ML_MAX_DIMS);
		return -1;
	}
	shape->num_dim = num_dim;

	status = ort_api->GetDimensions(tensor_info, dims, num_dim);
	if (check_ortstatus(status)) {
		_ODP_ERR("GetDimensions failed\n");
		return -1;
	}

	if (get_shape(dims, shape))
		return -1;

	*data_type_size = size_of_odp_ml_data_type(*data_type);

	*size = *data_type_size;
	calculate_model_io_size(shape, size);

	return 0;
}

/* Get model input and output info */
static int get_model_io_info(OrtSession *session, ml_model_t *mdl,
			     const odp_ml_model_param_t *param)
{
	char *name;
	OrtTypeInfo *type_info;
	const odp_ml_data_format_t *data_format;
	OrtStatus *status = NULL;
	OrtAllocator *allocator = NULL;
	const OrtApi *ort_api = _odp_ml_glb->ort_api;
	odp_ml_input_info_t *input_info = mdl->input_info;
	odp_ml_output_info_t *output_info = mdl->output_info;

	status = ort_api->GetAllocatorWithDefaultOptions(&allocator);
	if (check_ortstatus(status)) {
		_ODP_ERR("GetAllocatorWithDefaultOptions failed\n");
		return -1;
	}

	/* Retrieve info about input array. */
	memset(input_info, 0, sizeof(mdl->input_info));
	for (uint32_t i = 0; i < mdl->info.num_inputs; i++) {
		name = NULL;
		status = ort_api->SessionGetInputName(session, i, allocator, &name);
		if (check_ortstatus(status)) {
			_ODP_ERR("Get %uth input name failed\n", i);
			return -1;
		}

		strncpy(input_info[i].name, name, ODP_ML_MODEL_IO_NAME_LEN - 1);
		input_info[i].name[ODP_ML_MODEL_IO_NAME_LEN - 1] = 0;

		/* Free memory allocated by SessionGetInputName */
		status = ort_api->AllocatorFree(allocator, name);
		if (check_ortstatus(status)) {
			_ODP_ERR("AllocatorFree %uth input_name failed\n", i);
			return -1;
		}

		if (param->extra_info.num_inputs) {
			data_format = &param->extra_info.input_format[i];

			input_info[i].shape = data_format->shape;
			input_info[i].data_type = data_format->data_type;
			input_info[i].data_type_size = data_format->data_type_size;

			mdl->input_sizes[i] = input_info[i].data_type_size;
			calculate_model_io_size(&data_format->shape, &mdl->input_sizes[i]);
			continue;
		}

		type_info = NULL;
		status = ort_api->SessionGetInputTypeInfo(session, i, &type_info);
		if (check_ortstatus(status)) {
			_ODP_ERR("SessionGetInputTypeInfo failed\n");
			return -1;
		}

		if (get_model_io_type_shape_size(type_info, &input_info[i].shape,
						 &input_info[i].data_type,
						 &input_info[i].data_type_size,
						 &mdl->input_sizes[i])) {
			_ODP_ERR("get_model_io_type_shape_size() for input failed\n");
			ort_api->ReleaseTypeInfo(type_info);
			return -1;
		}

		ort_api->ReleaseTypeInfo(type_info);
	}

	/* Retrieve info about output array. */
	memset(output_info, 0, sizeof(mdl->output_info));
	for (uint32_t i = 0; i < mdl->info.num_outputs; i++) {
		name = NULL;
		status = ort_api->SessionGetOutputName(session, i, allocator, &name);
		if (check_ortstatus(status)) {
			_ODP_ERR("Get %uth output name failed\n", i);
			return -1;
		}

		strncpy(output_info[i].name, name, ODP_ML_MODEL_IO_NAME_LEN - 1);
		output_info[i].name[ODP_ML_MODEL_IO_NAME_LEN - 1] = 0;

		/* Free memory allocated by SessionGetOutputName */
		status = ort_api->AllocatorFree(allocator, name);
		if (check_ortstatus(status)) {
			_ODP_ERR("AllocatorFree %uth output_name failed\n", i);
			return -1;
		}

		if (param->extra_info.num_outputs) {
			data_format = &param->extra_info.output_format[i];

			output_info[i].shape = data_format->shape;
			output_info[i].data_type = data_format->data_type;
			output_info[i].data_type_size = data_format->data_type_size;

			mdl->output_sizes[i] = output_info[i].data_type_size;
			calculate_model_io_size(&data_format->shape, &mdl->output_sizes[i]);
			continue;
		}

		type_info = NULL;
		status = ort_api->SessionGetOutputTypeInfo(session, i, &type_info);
		if (check_ortstatus(status)) {
			_ODP_ERR("SessionGetOutputTypeInfo failed\n");
			return -1;
		}

		if (get_model_io_type_shape_size(type_info, &output_info[i].shape,
						 &output_info[i].data_type,
						 &output_info[i].data_type_size,
						 &mdl->output_sizes[i])) {
			_ODP_ERR("get_model_io_type_shape_size() for output failed\n");
			ort_api->ReleaseTypeInfo(type_info);
			return -1;
		}

		ort_api->ReleaseTypeInfo(type_info);
	}

	return 0;
}

static inline int check_model_io_num(const odp_ml_model_param_t *param,
				     uint32_t num_inputs, uint32_t num_outputs)
{
	/* Make sure the number of inputs/outputs not exceeding the supported
	 * model max inputs/outputs */
	if (num_inputs > CONFIG_ML_MAX_INPUTS) {
		_ODP_ERR("The model's number of inputs %u exceeds the maximum "
			 "number of inputs supported in a model %u\n",
			 num_inputs, CONFIG_ML_MAX_INPUTS);
		return -1;
	}

	if (num_outputs > CONFIG_ML_MAX_OUTPUTS) {
		_ODP_ERR("The model's number of outputs %u exceeds the maximum "
			 "number of outputs supported in a model %u\n",
			 num_outputs, CONFIG_ML_MAX_OUTPUTS);

		return -1;
	}

	/* Make sure the numbers of inputs/outputs provided in the extra_info of
	 * param match the numbers defined in model metadata. */
	if (param->extra_info.num_inputs &&
	    param->extra_info.num_inputs != num_inputs) {
		_ODP_ERR("Provided param->extra_info.num_inputs %u does not match the"
			 " number of inputs defined in model metadata: %u\n",
			 param->extra_info.num_inputs, num_inputs);
		return -1;
	}

	if (param->extra_info.num_outputs && param->extra_info.num_outputs != num_outputs) {
		_ODP_ERR("Provided param->extra_info.num_outputs %u does not match the"
			 " number of outputs defined in model metadata: %u\n",
			 param->extra_info.num_outputs, num_outputs);
		return -1;
	}

	if (param->extra_info.num_inputs && !param->extra_info.input_format) {
		_ODP_ERR("num_inputs is provided but not input_format in param->extra_info\n");
		return -1;
	}

	if (param->extra_info.num_outputs && !param->extra_info.output_format) {
		_ODP_ERR("num_outputs is provided but not output_format in param->extra_info\n");
		return -1;
	}

	return 0;
}

static int create_ort_model(const odp_ml_model_param_t *param, OrtSession **session,
			    ml_model_t *mdl, OrtSessionOptions *session_opts)
{
	OrtStatus *status;
	int64_t model_version;
	uint32_t num_inputs = 0;
	uint32_t num_outputs = 0;
	OrtModelMetadata *metadata = {0};
	const OrtApi *ort_api = _odp_ml_glb->ort_api;

	status = ort_api->CreateSessionFromArray(_odp_ml_glb->env,
						 param->model,
						 param->size,
						 session_opts,
						 session);
	if (check_ortstatus(status) || !(*session)) {
		_ODP_ERR("CreateSessionFromArray failed\n");
		return -1;
	}

	if (get_model_io_count(*session, &num_inputs, &num_outputs)) {
		_ODP_ERR("get_model_io_count() failed\n");
		ort_api->ReleaseSession(*session);
		return -1;
	}

	if (check_model_io_num(param, num_inputs, num_outputs)) {
		ort_api->ReleaseSession(*session);
		return -1;
	}

	mdl->max_compl_id = param->max_compl_id;
	mdl->info.num_inputs = num_inputs;
	mdl->info.num_outputs = num_outputs;

	/* Get metadata */
	status = ort_api->SessionGetModelMetadata(*session, &metadata);
	if (check_ortstatus(status) || !metadata) {
		_ODP_ERR("SessionGetModelMetadata failed\n");
		ort_api->ReleaseSession(*session);
		return -1;
	}

	/* Get model version */
	status = ort_api->ModelMetadataGetVersion(metadata, &model_version);
	if (check_ortstatus(status)) {
		_ODP_ERR("ModelMetadataGetVersion failed\n");
		ort_api->ReleaseModelMetadata(metadata);
		ort_api->ReleaseSession(*session);
		return -1;
	}
	mdl->info.model_version = model_version;
	mdl->info.interface_version = 0;

	if (get_model_io_info(*session, mdl, param)) {
		_ODP_ERR("get_model_io_info() failed\n");
		ort_api->ReleaseModelMetadata(metadata);
		ort_api->ReleaseSession(*session);
		return -1;
	}

	ort_api->ReleaseModelMetadata(metadata);
	return 0;
}

static int set_ort_run_opts(const char *name, OrtSessionOptions *se_opts)
{
	OrtStatus *status;
	ort_run_opts_t *opts = &_odp_ml_glb->ort_run_opts;
	const OrtApi *ort_api = _odp_ml_glb->ort_api;

	if (opts->enable_profiling) {
		status = ort_api->EnableProfiling(se_opts, name);
		if (check_ortstatus(status)) {
			_ODP_ERR("Enable profiling failed\n");
			return -1;
		}
	}

	status = ort_api->SetSessionExecutionMode(se_opts, opts->execution_mode);
	if (check_ortstatus(status)) {
		_ODP_ERR("SetSessionExecutionMode failed\n");
		return -1;
	}

	if (opts->intra_op_num_threads) {
		status = ort_api->SetIntraOpNumThreads(se_opts, opts->intra_op_num_threads);
		if (check_ortstatus(status)) {
			_ODP_ERR("SetIntraOpNumThreads failed\n");
			return -1;
		}
	}

	if (opts->inter_op_num_threads) {
		status = ort_api->SetInterOpNumThreads(se_opts, opts->inter_op_num_threads);
		if (check_ortstatus(status)) {
			_ODP_ERR("SetInterOpNumThreads failed\n");
			return -1;
		}
	}

	status = ort_api->SetSessionGraphOptimizationLevel(se_opts, opts->graph_opt_level);
	if (check_ortstatus(status)) {
		_ODP_ERR("SetSessionGraphOptimizationLevel failed\n");
		return -1;
	}

	/* Optimized model file path is not provided */
	if (opts->opt_model_filepath[0] == '\0')
		return 0;

	status = ort_api->SetOptimizedModelFilePath(se_opts, opts->opt_model_filepath);
	if (check_ortstatus(status)) {
		_ODP_ERR("SetOptimizedModelFilePath failed\n");
		return -1;
	}

	return 0;
}

static inline void reset_mdl_info_sizes(ml_model_t *mdl)
{
	memset(&mdl->info, 0, sizeof(odp_ml_model_info_t));
	memset(mdl->input_info, 0, sizeof(mdl->input_info));
	memset(mdl->output_info, 0, sizeof(mdl->output_info));
	memset(mdl->input_sizes, 0, sizeof(mdl->input_sizes));
	memset(mdl->output_sizes, 0, sizeof(mdl->output_sizes));
}

static int check_io_shape(ml_model_t *mdl)
{
	odp_ml_shape_info_t *shape;

	for (uint32_t i = 0; i < mdl->info.num_inputs; i++) {
		shape = &mdl->input_info[i].shape;

		if (shape->type == ODP_ML_SHAPE_NONE) {
			_ODP_ERR("Undefined shape type for model input[%u]\n", i);
			return -1;
		}

		if (shape->type == ODP_ML_SHAPE_STATIC)
			continue;

		/* shape->type == ODP_ML_SHAPE_BATCH */
		for (uint32_t j = 0; j < shape->num_dim; j++) {
			if (shape->dim[j] == ODP_ML_DIM_DYNAMIC && !shape->dim_max[j]) {
				_ODP_ERR("Missing dim_max[%u] for dynamic sized input[%u], please"
					 " provide via the extra_info of model param\n", j, i);
				return -1;
			}
		}
	}

	for (uint32_t i = 0; i < mdl->info.num_outputs; i++) {
		if (mdl->output_info[i].shape.type == ODP_ML_SHAPE_NONE) {
			_ODP_ERR("Undefined shape type for model output[%u]\n", i);
			return -1;
		}
	}

	return 0;
}

odp_ml_model_t odp_ml_model_create(const char *name, const odp_ml_model_param_t *param)
{
	OrtStatus *status;
	odp_ml_model_info_t *info;
	OrtSessionOptions *session_opts;
	uint32_t i = 0;
	ml_model_t *mdl = NULL;
	OrtSession *session = NULL;
	const OrtApi *ort_api = _odp_ml_glb->ort_api;

	if (odp_unlikely(odp_global_ro.disable.ml)) {
		_ODP_ERR("ML is disabled\n");
		return ODP_ML_MODEL_INVALID;
	}

	if (odp_unlikely(param->size > _odp_ml_glb->ml_config.max_model_size)) {
		_ODP_ERR("Model size %" PRIu64 " exceeds maximum model size configured %" PRIu64 "\n",
			 param->size, _odp_ml_glb->ml_config.max_model_size);
		return ODP_ML_MODEL_INVALID;
	}

	if (odp_unlikely(!param->size || !param->model)) {
		_ODP_ERR("Invalid model param: param->model: %p, param->size: %" PRIu64 "\n",
			 param->model, param->size);
		return ODP_ML_MODEL_INVALID;
	}

	if (odp_unlikely(param->max_compl_id > ML_MAX_COMPL_ID)) {
		_ODP_ERR("param->max_compl_id: %u exceeds maximum completion id supported: %d\n",
			 param->max_compl_id, ML_MAX_COMPL_ID);
		return ODP_ML_MODEL_INVALID;
	}

	/* Find an emtpy slot to store the new model */
	for (i = 0; i < ML_MAX_MODELS_CREATED; i++) {
		if (_odp_ml_glb->models[i].state)
			continue;

		odp_ticketlock_lock(&_odp_ml_glb->models[i].lock);

		if (_odp_ml_glb->models[i].state) {
			odp_ticketlock_unlock(&_odp_ml_glb->models[i].lock);
			continue;
		}

		mdl = &_odp_ml_glb->models[i];
		break;
	}

	if (i == ML_MAX_MODELS_CREATED) {
		_ODP_ERR("Maximum number of models has already been created!\n");
		return ODP_ML_MODEL_INVALID;
	}

	/* Free model entry was found and is now locked */
	mdl->state = ML_STATE_CREATED;

	status = ort_api->CreateSessionOptions(&session_opts);
	if (check_ortstatus(status) || !session_opts) {
		_ODP_ERR("Error: CreateSessionOptions failed.\n");
		mdl->state = ML_STATE_FREE;
		odp_ticketlock_unlock(&mdl->lock);
		return ODP_ML_MODEL_INVALID;
	}

	if (set_ort_run_opts(name, session_opts)) {
		_odp_ml_glb->ort_api->ReleaseSessionOptions(session_opts);
		mdl->state = ML_STATE_FREE;
		odp_ticketlock_unlock(&mdl->lock);
		return ODP_ML_MODEL_INVALID;
	}

	/* Store model info */
	info = &mdl->info;
	memset(info, 0, sizeof(odp_ml_model_info_t));

	if (create_ort_model(param, &session, mdl, session_opts)) {
		mdl->state = ML_STATE_FREE;

		/* Initialize info back to 0 when some fields have been filled
		 * while later failed */
		reset_mdl_info_sizes(mdl);
		odp_ticketlock_unlock(&mdl->lock);

		_odp_ml_glb->ort_api->ReleaseSessionOptions(session_opts);
		_ODP_ERR("create_ort_model() failed\n");
		return ODP_ML_MODEL_INVALID;
	}

	if (check_io_shape(mdl)) {
		mdl->state = ML_STATE_FREE;
		reset_mdl_info_sizes(mdl);
		odp_ticketlock_unlock(&mdl->lock);

		ort_api->ReleaseSession(session);
		_odp_ml_glb->ort_api->ReleaseSessionOptions(session_opts);
		return ODP_ML_MODEL_INVALID;
	}

	mdl->session = session;
	mdl->session_opts = session_opts;
	info->index = i;

	if (name) {
		strncpy(info->name, name, ODP_ML_MODEL_NAME_LEN - 1);
		info->name[ODP_ML_MODEL_NAME_LEN - 1] = 0;
	}

	mdl->max_compl_id = param->max_compl_id;
	for (uint32_t j = 0; j < ML_MAX_COMPL_ID; j++)
		odp_atomic_init_u32(&mdl->compl_status[j], 1);

	odp_ticketlock_unlock(&mdl->lock);
	return (odp_ml_model_t)mdl;
}

int odp_ml_model_destroy(odp_ml_model_t model)
{
	ml_model_t *mdl = ml_model_from_handle(model);

	if (model == ODP_ML_MODEL_INVALID) {
		_ODP_ERR("Bad ML model handle\n");
		return -1;
	}

	odp_ticketlock_lock(&mdl->lock);

	if (mdl->state != ML_STATE_CREATED) {
		_ODP_ERR("Model not created\n");
		odp_ticketlock_unlock(&mdl->lock);
		return -1;
	}

	_odp_ml_glb->ort_api->ReleaseSessionOptions(mdl->session_opts);
	_odp_ml_glb->ort_api->ReleaseSession(mdl->session);
	mdl->state = ML_STATE_FREE;
	mdl->session = NULL;
	odp_ticketlock_unlock(&mdl->lock);

	return 0;
}

int odp_ml_model_info(odp_ml_model_t model, odp_ml_model_info_t *info)
{
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return -1;
	}

	if (odp_unlikely(!info)) {
		_ODP_ERR("info must not be NULL\n");
		return -1;
	}

	odp_ticketlock_lock(&mdl->lock);
	if (odp_unlikely(mdl->state == ML_STATE_FREE)) {
		_ODP_ERR("Model not created\n");
		odp_ticketlock_unlock(&mdl->lock);
		return -1;
	}

	*info = mdl->info;

	odp_ticketlock_unlock(&mdl->lock);
	return 0;
}

uint32_t odp_ml_model_input_info(odp_ml_model_t model, odp_ml_input_info_t info[], uint32_t num)
{
	uint32_t num_model_inputs;
	uint32_t num_written;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return 0;
	}

	odp_ticketlock_lock(&mdl->lock);
	num_model_inputs = mdl->info.num_inputs;
	num_written = num_model_inputs >= num ? num : num_model_inputs;

	if (num == 0) {
		odp_ticketlock_unlock(&mdl->lock);
		return num_model_inputs;
	}

	for (uint32_t i = 0; i < num_written; i++)
		info[i] = mdl->input_info[i];

	odp_ticketlock_unlock(&mdl->lock);
	return num_model_inputs;
}

uint32_t odp_ml_model_output_info(odp_ml_model_t model, odp_ml_output_info_t info[], uint32_t num)
{
	uint32_t num_model_outputs;
	uint32_t num_written;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return 0;
	}

	odp_ticketlock_lock(&mdl->lock);
	num_model_outputs = mdl->info.num_outputs;
	num_written = num_model_outputs >= num ? num : num_model_outputs;

	if (num == 0) {
		odp_ticketlock_unlock(&mdl->lock);
		return num_model_outputs;
	}

	for (uint32_t i = 0; i < num_written; i++)
		info[i] = mdl->output_info[i];

	odp_ticketlock_unlock(&mdl->lock);
	return num_model_outputs;
}

odp_ml_model_t odp_ml_model_lookup(const char *name)
{
	uint32_t i;
	ml_model_t *mdl;

	for (i = 0; i < ML_MAX_MODELS_CREATED; i++) {
		mdl = &_odp_ml_glb->models[i];

		odp_ticketlock_lock(&mdl->lock);

		if (mdl->state == ML_STATE_FREE) {
			odp_ticketlock_unlock(&mdl->lock);
			continue;
		}

		if (!strcmp(mdl->info.name, name)) {
			/* found it */
			odp_ticketlock_unlock(&mdl->lock);
			return (odp_ml_model_t)mdl;
		}
		odp_ticketlock_unlock(&mdl->lock);
	}

	return ODP_ML_MODEL_INVALID;
}

uint64_t odp_ml_model_to_u64(odp_ml_model_t model)
{
	return _odp_pri(model);
}

static const char *data_type_str(odp_ml_data_type_t data_type)
{
	switch (data_type) {
	case ODP_ML_DATA_TYPE_INT8:
		return "int8";
	case ODP_ML_DATA_TYPE_UINT8:
		return "uint8";
	case ODP_ML_DATA_TYPE_UINT16:
		return "uint16";
	case ODP_ML_DATA_TYPE_INT16:
		return "int16";
	case ODP_ML_DATA_TYPE_INT32:
		return "int32";
	case ODP_ML_DATA_TYPE_UINT32:
		return "uint32";
	case ODP_ML_DATA_TYPE_INT64:
		return "int64";
	case ODP_ML_DATA_TYPE_UINT64:
		return "uint64";
	case ODP_ML_DATA_TYPE_FP16:
		return "fp16";
	case ODP_ML_DATA_TYPE_FP32:
		return "fp32";
	case ODP_ML_DATA_TYPE_BFP16:
		return "bfp16";
	default:
		return "unknown";
	}
}

static const char *shape_type_str(odp_ml_shape_type_t shape_type)
{
	switch (shape_type) {
	case ODP_ML_SHAPE_NONE:
		return "none";
	case ODP_ML_SHAPE_STATIC:
		return "static";
	case ODP_ML_SHAPE_BATCH:
		return "batch";
	default:
		return "Unknown";
	}
}

static void print_shape(const odp_ml_shape_info_t *shape)
{
	/* Print shape */
	_ODP_PRINT("Shape: %s [", shape_type_str(shape->type));

	for (uint32_t i = 0; i < shape->num_dim; i++) {
		if (shape->dim[i] == ODP_ML_DIM_DYNAMIC)
			_ODP_PRINT("Dyn");
		else
			_ODP_PRINT("%" PRIu32, shape->dim[i]);

		if (i == (shape->num_dim - 1))
			_ODP_PRINT("]\n");
		else
			_ODP_PRINT(", ");
	}

	/* The number of dimensions for a scalar input is 0, in which case did not
	 * go into above for loop */
	if (shape->num_dim == 0)
		_ODP_PRINT("]\n");
}

void odp_ml_model_print(odp_ml_model_t model)
{
	ml_model_t *mdl	= ml_model_from_handle(model);
	const odp_ml_model_info_t * const info	= &mdl->info;
	const odp_ml_input_info_t * const input_info = mdl->input_info;
	const odp_ml_output_info_t * const output_info = mdl->output_info;

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return;
	}

	odp_ticketlock_lock(&mdl->lock);
	if (odp_unlikely(mdl->state == ML_STATE_FREE)) {
		odp_ticketlock_unlock(&mdl->lock);
		_ODP_ERR("Model not created\n");
		return;
	}

	_ODP_PRINT("\nModel info\n");
	_ODP_PRINT("----------\n");
	_ODP_PRINT("  Model handle: 0x%" PRIx64 "\n", odp_ml_model_to_u64(model));
	_ODP_PRINT("  Name: %s\n", info->name);
	_ODP_PRINT("  Model version: %" PRIu64 "\n", info->model_version);
	_ODP_PRINT("  Model interface version: %" PRIu64 "\n", info->interface_version);
	_ODP_PRINT("  Index: %u\n", info->index);
	_ODP_PRINT("  Number of inputs: %u\n", info->num_inputs);

	for (uint32_t i = 0; i < info->num_inputs; i++) {
		_ODP_PRINT("    Input[%u]: ", i);
		_ODP_PRINT("Name: %s, ", input_info[i].name);
		_ODP_PRINT("Data_type: %s, ", data_type_str(input_info[i].data_type));
		print_shape(&input_info[i].shape);
	}

	_ODP_PRINT("  Number of outputs: %u\n", info->num_outputs);
	for (uint32_t i = 0; i < info->num_outputs; i++) {
		_ODP_PRINT("    Output[%u]: ", i);
		_ODP_PRINT("Name: %s, ", output_info[i].name);
		_ODP_PRINT("Data_type: %s, ", data_type_str(output_info[i].data_type));
		print_shape(&output_info[i].shape);
	}

	odp_ticketlock_unlock(&mdl->lock);

	_ODP_PRINT("\n");
}

static inline void mode_print(odp_ml_compl_mode_t compl_mode_mask)
{
	if (compl_mode_mask & ODP_ML_COMPL_MODE_SYNC)
		_ODP_PRINT(" syn");

	if (compl_mode_mask & ODP_ML_COMPL_MODE_POLL)
		_ODP_PRINT(" poll");

	if (compl_mode_mask & ODP_ML_COMPL_MODE_EVENT)
		_ODP_PRINT(" event");
}

void odp_ml_print(void)
{
	_ODP_PRINT("\nML info\n");
	_ODP_PRINT("-----------\n");
	_ODP_PRINT("  max_model_size: %u\n", ML_MAX_MODEL_SIZE);
	_ODP_PRINT("  max_compl_id: %u\n", ML_MAX_COMPL_ID);
	_ODP_PRINT("  max_models_created: %u\n", ML_MAX_MODELS_CREATED);
	_ODP_PRINT("  max_models_loaded: %u\n", ML_MAX_MODELS_LOADED);
	_ODP_PRINT("  model_max_inputs: %u\n", CONFIG_ML_MAX_INPUTS);
	_ODP_PRINT("  model_max_outputs: %u\n", CONFIG_ML_MAX_OUTPUTS);

	_ODP_PRINT("  load:\n");
	_ODP_PRINT("    completion mode: ");
	mode_print(_odp_ml_glb->capa.load.compl_mode_mask);
	_ODP_PRINT(", plain queue: %c, schedule queue: %c\n",
		   _odp_ml_glb->capa.load.compl_queue_plain ? 'Y' : 'N',
		   _odp_ml_glb->capa.load.compl_queue_sched ? 'Y' : 'N');

	_ODP_PRINT("  run:\n");
	_ODP_PRINT("    completion mode:");
	mode_print(_odp_ml_glb->capa.run.compl_mode_mask);
	_ODP_PRINT(", plain queue: %c, schedule queue: %c\n",
		   _odp_ml_glb->capa.run.compl_queue_plain ? 'Y' : 'N',
		   _odp_ml_glb->capa.run.compl_queue_sched ? 'Y' : 'N');
	_ODP_PRINT("\n");
}

int odp_ml_model_extra_stat_info(odp_ml_model_t model,
				 odp_ml_extra_stat_info_t info[] ODP_UNUSED,
				 int num ODP_UNUSED)
{
	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return -1;
	}

	return 0;
}

int odp_ml_model_extra_stats(odp_ml_model_t model, uint64_t stats[] ODP_UNUSED, int num ODP_UNUSED)
{
	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return -1;
	}

	return 0;
}

void odp_ml_compl_pool_param_init(odp_ml_compl_pool_param_t *pool_param)
{
	if (odp_unlikely(!pool_param)) {
		_ODP_ERR("Param 'pool_param' must not NULL\n");
		return;
	}

	memset(pool_param, 0, sizeof(odp_ml_compl_pool_param_t));

	pool_param->cache_size = _odp_ml_glb->pool_param.buf.cache_size;
}

odp_pool_t odp_ml_compl_pool_create(const char *name, const odp_ml_compl_pool_param_t *pool_param)
{
	odp_pool_t pool;
	odp_pool_param_t ml_pool_param;
	uint32_t num = pool_param->num;
	uint32_t uarea_size = pool_param->uarea_size;
	uint32_t cache_size = pool_param->cache_size;
	uint32_t buf_size = _ODP_MAX(sizeof(odp_ml_run_result_t),
				     sizeof(odp_ml_load_result_t));

	if (num > _odp_ml_glb->capa.pool.max_num) {
		_ODP_ERR("Too many ML completion events: %u\n", num);
		return ODP_POOL_INVALID;
	}

	if (uarea_size > _odp_ml_glb->capa.pool.max_uarea_size) {
		_ODP_ERR("Bad uarea size: %u\n", uarea_size);
		return ODP_POOL_INVALID;
	}

	if (cache_size < _odp_ml_glb->capa.pool.min_cache_size ||
	    cache_size > _odp_ml_glb->capa.pool.max_cache_size) {
		_ODP_ERR("Bad cache size: %u\n", cache_size);
		return ODP_POOL_INVALID;
	}

	odp_pool_param_init(&ml_pool_param);
	ml_pool_param.type               = ODP_POOL_BUFFER;
	ml_pool_param.uarea_init.init_fn = pool_param->uarea_init.init_fn;
	ml_pool_param.uarea_init.args    = pool_param->uarea_init.args;
	ml_pool_param.buf.num            = num;
	ml_pool_param.buf.cache_size     = cache_size;
	ml_pool_param.buf.size           = buf_size;
	ml_pool_param.buf.uarea_size     = uarea_size;

	pool = _odp_pool_create(name, &ml_pool_param, ODP_POOL_ML_COMPL);

	return pool;
}

odp_ml_compl_t odp_ml_compl_alloc(odp_pool_t pool)
{
	odp_buffer_t buf;
	odp_event_t ev;
	odp_ml_run_result_t *result;
	uint32_t buf_size = _ODP_MAX(sizeof(odp_ml_run_result_t),
				     sizeof(odp_ml_load_result_t));

	buf = odp_buffer_alloc(pool);

	if (odp_unlikely(buf == ODP_BUFFER_INVALID))
		return ODP_ML_COMPL_INVALID;

	result = odp_buffer_addr(buf);
	memset(result, 0, buf_size);

	ev = odp_buffer_to_event(buf);
	_odp_event_type_set(ev, ODP_EVENT_ML_COMPL);

	return (odp_ml_compl_t)(uintptr_t)buf;
}

void odp_ml_compl_free(odp_ml_compl_t ml_compl)
{
	odp_event_t ev;
	odp_buffer_t buf = (odp_buffer_t)(uintptr_t)ml_compl;

	if (odp_unlikely(ml_compl == ODP_ML_COMPL_INVALID)) {
		_ODP_ERR("Bad ML job completion handle\n");
		return;
	}

	ev = odp_buffer_to_event(buf);
	_odp_event_type_set(ev, ODP_EVENT_BUFFER);

	odp_buffer_free(buf);
}

int odp_ml_compl_run_result(odp_ml_compl_t ml_compl, odp_ml_run_result_t *result)
{
	odp_event_subtype_t subtype;
	odp_ml_run_result_t *run_result;
	odp_buffer_t buf = (odp_buffer_t)(uintptr_t)ml_compl;
	odp_event_t ev = odp_buffer_to_event(buf);

	if (odp_unlikely(ml_compl == ODP_ML_COMPL_INVALID)) {
		_ODP_ERR("Given ML completion event is invalid\n");
		return -2;
	}

	if (odp_event_types(ev, &subtype) != ODP_EVENT_ML_COMPL ||
	    subtype != ODP_EVENT_ML_COMPL_RUN) {
		_ODP_ERR("Given completion event has wrong event type or subtype\n");
		return -2;
	}

	run_result = odp_buffer_addr(buf);
	if (result)
		*result = *run_result;

	return run_result->error_code ? -1 : 0;
}

int odp_ml_compl_load_result(odp_ml_compl_t ml_compl, odp_ml_load_result_t *result)
{
	odp_event_subtype_t subtype;
	odp_ml_load_result_t *load_result;
	odp_buffer_t buf = (odp_buffer_t)(uintptr_t)ml_compl;
	odp_event_t ev = odp_buffer_to_event(buf);

	if (odp_unlikely(ml_compl == ODP_ML_COMPL_INVALID)) {
		_ODP_ERR("Given ML completion event is invalid\n");
		return -2;
	}

	if (odp_event_types(ev, &subtype) != ODP_EVENT_ML_COMPL ||
	    subtype != ODP_EVENT_ML_COMPL_LOAD) {
		_ODP_ERR("Given completion event has wrong event type or subtype\n");
		return -2;
	}

	load_result = odp_buffer_addr(buf);
	if (result)
		*result = *load_result;

	return load_result->error_code ? -1 : 0;
}

void *odp_ml_compl_user_area(odp_ml_compl_t ml_compl)
{
	return odp_buffer_user_area((odp_buffer_t)(uintptr_t)ml_compl);
}

odp_ml_compl_t odp_ml_compl_from_event(odp_event_t event)
{
	_ODP_ASSERT(_odp_event_hdr_field(event, int8_t, event_type) == ODP_EVENT_ML_COMPL);

	return (odp_ml_compl_t)(uintptr_t)event;
}

odp_event_t odp_ml_compl_to_event(odp_ml_compl_t ml_compl)
{
	return (odp_event_t)(uintptr_t)ml_compl;
}

uint64_t odp_ml_compl_to_u64(odp_ml_compl_t ml_compl)
{
	return (uint64_t)(uintptr_t)ml_compl;
}

void odp_ml_compl_param_init(odp_ml_compl_param_t *compl_param)
{
	memset(compl_param, 0, sizeof(odp_ml_compl_param_t));

	compl_param->queue	= ODP_QUEUE_INVALID;
	compl_param->event	= ODP_EVENT_INVALID;
}

int odp_ml_model_load(odp_ml_model_t model, odp_ml_load_result_t *result)
{
	odp_ml_load_result_t result_local;
	int ret = -1;
	ml_model_t *mdl = ml_model_from_handle(model);

	memset(&result_local, 0, sizeof(result_local));

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		result_local.error_code = ML_BAD_HDL;
		goto load_fail;
	}

	odp_ticketlock_lock(&mdl->lock);
	if (odp_unlikely(mdl->state != ML_STATE_CREATED)) {
		_ODP_ERR("Model has not been created yet or is already loaded\n");
		odp_ticketlock_unlock(&mdl->lock);
		result_local.error_code = ML_NOT_CREATED;
		goto load_fail;
	}

	mdl->state = ML_STATE_LOADED;
	odp_ticketlock_unlock(&mdl->lock);
	ret = 0;

load_fail:
	if (result)
		*result = result_local;

	return ret;
}

static inline int check_compl_param(const odp_ml_compl_param_t *compl_param,
				    uint32_t max_compl_id, odp_bool_t is_load)
{
	odp_ml_config_t *config = &_odp_ml_glb->ml_config;

	switch (compl_param->mode) {
	case ODP_ML_COMPL_MODE_POLL:
		if (is_load && !(config->load_mode_mask & ODP_ML_COMPL_MODE_POLL)) {
			_ODP_ERR("Poll mode loading/unloading is not configured\n");
			return -1;
		}

		if (!is_load && !(config->run_mode_mask & ODP_ML_COMPL_MODE_POLL)) {
			_ODP_ERR("Poll mode run is not configured\n");
			return -1;
		}

		if (compl_param->compl_id > max_compl_id) {
			_ODP_ERR("Bad compl_id: %u, exceeding model max completion id %u\n",
				 compl_param->compl_id, max_compl_id);
			return -1;
		}
		break;
	case ODP_ML_COMPL_MODE_EVENT:
		if (is_load && !(config->load_mode_mask & ODP_ML_COMPL_MODE_EVENT)) {
			_ODP_ERR("Event mode loading/unloading is not configured\n");
			return -1;
		}

		if (!is_load && !(config->run_mode_mask & ODP_ML_COMPL_MODE_EVENT)) {
			_ODP_ERR("Event mode run is not configured\n");
			return -1;
		}

		if (compl_param->event == ODP_EVENT_INVALID ||
		    compl_param->queue == ODP_QUEUE_INVALID) {
			_ODP_ERR("Bad event or queue\n");
			return -1;
		}

		if (odp_event_type(compl_param->event) != ODP_EVENT_ML_COMPL) {
			_ODP_ERR("Bad completion event type\n");
			return -1;
		}
		break;
	default:
		/* Including ODP_ML_COMPL_MODE_SYNC, which is not supported by
		 * asynchrous functions (e.g. *_start()) either.
		 */
		_ODP_ERR("Invalid completion mode %u\n", compl_param->mode);
		return -1;
	}

	return 0;
}

int odp_ml_model_load_start(odp_ml_model_t model, const odp_ml_compl_param_t *compl_param)
{
	int ret;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad model handle\n");
		return -1;
	}

	if (odp_unlikely(check_compl_param(compl_param, mdl->max_compl_id, true)))
		return -1;

	if (compl_param->mode == ODP_ML_COMPL_MODE_POLL)
		odp_atomic_store_rel_u32(&mdl->compl_status[compl_param->compl_id], 0);

	ret = odp_ml_model_load(model, NULL);

	if (odp_unlikely(ret))
		return -1;

	/* Send a completion event to the given queue */
	if (compl_param->mode == ODP_ML_COMPL_MODE_EVENT) {
		odp_ml_load_result_t *result;
		odp_buffer_t buf = (odp_buffer_t)(uintptr_t)compl_param->event;

		_odp_buffer_subtype_set(buf, ODP_EVENT_ML_COMPL_LOAD);

		result = odp_buffer_addr(buf);
		result->error_code = 0;
		result->user_ptr = compl_param->user_ptr;

		if (odp_unlikely(odp_queue_enq(compl_param->queue, compl_param->event))) {
			_ODP_ERR("Completion event enqueue failed %" PRIu64 "\n",
				 odp_queue_to_u64(compl_param->queue));
			if (odp_ml_model_unload(model, NULL))
				_ODP_ERR("Failed to unload model\n");
			return -1;
		}

		return 0;
	}

	mdl->result[compl_param->compl_id].user_ptr = compl_param->user_ptr;
	odp_atomic_store_rel_u32(&mdl->compl_status[compl_param->compl_id], 1);
	return 0;
}

int odp_ml_model_load_status(odp_ml_model_t model, uint32_t compl_id, odp_ml_load_result_t *result)
{
	int ret;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID || compl_id > mdl->max_compl_id)) {
		_ODP_ERR("Invalid model or compl_id: %u\n", compl_id);
		return -2;
	}

	ret = odp_atomic_load_acq_u32(&mdl->compl_status[compl_id]);

	if (ret && result) {
		result->error_code = 0;
		result->user_ptr = mdl->result[compl_id].user_ptr;
	}

	return ret;
}

int odp_ml_model_unload(odp_ml_model_t model, odp_ml_load_result_t *result)
{
	odp_ml_load_result_t result_local;
	int ret = -1;
	ml_model_t *mdl = ml_model_from_handle(model);

	memset(&result_local, 0, sizeof(result_local));

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		result_local.error_code = ML_BAD_HDL;
		_ODP_ERR("Bad ML model handle\n");
		goto unload_fail;
	}

	odp_ticketlock_lock(&mdl->lock);
	/* mdl->state == ML_STATE_FREE, ML_STATE_CREATED, ML_STATE_INFERENCING */
	if (odp_unlikely(mdl->state != ML_STATE_LOADED)) {
		_ODP_ERR("Model has not been created/loaded or inferencing has not finished yet\n");
		odp_ticketlock_unlock(&mdl->lock);
		result_local.error_code = ML_NOT_LOADED;
		goto unload_fail;
	}

	mdl->state = ML_STATE_CREATED;
	odp_ticketlock_unlock(&mdl->lock);

	ret = 0;

unload_fail:
	if (result)
		*result = result_local;

	return ret;
}

int odp_ml_model_unload_start(odp_ml_model_t model, const odp_ml_compl_param_t *compl_param)
{
	int ret;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad model handle\n");
		return -1;
	}

	if (odp_unlikely(check_compl_param(compl_param, mdl->max_compl_id, true)))
		return -1;

	if (compl_param->mode == ODP_ML_COMPL_MODE_POLL)
		odp_atomic_store_rel_u32(&mdl->compl_status[compl_param->compl_id], 0);

	ret = odp_ml_model_unload(model, NULL);

	if (odp_unlikely(ret))
		return -1;

	/* Upon successful unloading, send a completion event to the given queue */
	if (compl_param->mode == ODP_ML_COMPL_MODE_EVENT) {
		odp_ml_load_result_t *result;
		odp_buffer_t buf = (odp_buffer_t)(uintptr_t)compl_param->event;

		_odp_buffer_subtype_set(buf, ODP_EVENT_ML_COMPL_LOAD);

		result = odp_buffer_addr(buf);
		result->error_code = 0;
		result->user_ptr = compl_param->user_ptr;

		if (odp_unlikely(odp_queue_enq(compl_param->queue, compl_param->event))) {
			_ODP_ERR("Completion event enqueue failed %" PRIu64 "\n",
				 odp_queue_to_u64(compl_param->queue));
			return -1;
		}

		return 0;
	}

	mdl->result[compl_param->compl_id].user_ptr = compl_param->user_ptr;
	odp_atomic_store_rel_u32(&mdl->compl_status[compl_param->compl_id], 1);
	return 0;
}

int odp_ml_model_unload_status(odp_ml_model_t model, uint32_t compl_id,
			       odp_ml_load_result_t *result)
{
	return odp_ml_model_load_status(model, compl_id, result);
}

void odp_ml_run_param_init(odp_ml_run_param_t *param)
{
	memset(param, 0, sizeof(odp_ml_run_param_t));
}

static void ml_shape_to_int64(const odp_ml_shape_info_t *shape, uint32_t batch_size, int64_t *array)
{
	for (uint32_t i = 0; i < shape->num_dim; i++) {
		/* Replace dynamic dimension size with provided batch_size */
		if (shape->dim[i] == ODP_ML_DIM_DYNAMIC)
			array[i] = batch_size;
		else
			array[i] = shape->dim[i];
	}
}

/* Get the number of elements in given shape */
static inline uint64_t get_num_elem(uint32_t batch_size, const odp_ml_shape_info_t *shape)
{
	uint64_t num_elements = 1;
	int64_t dim[ODP_ML_MAX_DIMS] = {0};

	ml_shape_to_int64(shape, batch_size, dim);

	for (uint32_t i = 0; i < shape->num_dim; i++)
		num_elements *= (uint64_t)dim[i];

	return num_elements;
}

static inline uint32_t dyn_io_size(const odp_ml_shape_info_t *shape, uint32_t data_type_size,
				   const odp_ml_run_param_t *param)
{
	uint32_t size;

	if (!param || !param->batch_size) {
		_ODP_ERR("Parameter 'param' must not be NULL and batch_size must be "
			 "provided when a input/output has dynamic dimension size\n");
		return 0;
	}

	size = get_num_elem(param->batch_size, shape);
	size *= data_type_size;

	return size;
}

static int verify_run_params(odp_ml_model_t model, const odp_ml_data_t *data,
			     const odp_ml_run_param_t *param)
{
	const ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad ML model handle\n");
		return -1;
	}

	if (odp_unlikely(!data)) {
		_ODP_ERR("Parameter 'data' must not be NULL\n");
		return -1;
	}

	/* Make sure that the number of input data segments equals or bigger than
	 * the number of model inputs. */
	if (mdl->info.num_inputs > data->num_input_seg) {
		_ODP_ERR("The num of input data segments %u must not less than "
			 "the number of model inputs %u\n", data->num_input_seg,
			 mdl->info.num_inputs);
		return -1;
	}

	if (mdl->info.num_outputs > data->num_output_seg) {
		_ODP_ERR("The num of output data segments %u must not less than "
			 "the number of model outputs %u\n", data->num_output_seg,
			 mdl->info.num_outputs);
		return -1;
	}

	if (data->num_input_seg > mdl->info.num_inputs &&
	    (_odp_ml_glb->capa.max_segs_per_input == 1)) {
		_ODP_ERR("Segmented input data is not supported\n");
		return -1;
	}

	if (data->num_output_seg > mdl->info.num_outputs &&
	    (_odp_ml_glb->capa.max_segs_per_output == 1)) {
		_ODP_ERR("Segmented output data is not supported");
		return -1;
	}

	uint32_t size = 0;
	uint32_t input_index = 0;
	uint32_t seg_size_sum = 0;
	odp_bool_t index_new = true;
	uint32_t segs_per_input = 1;

	for (uint32_t i = 0; i < data->num_input_seg; i++) {
		if (data->input_seg[i].addr == NULL) {
			_ODP_ERR("data->input_seg[%u].addr must not NULL\n", i);
			return -1;
		};

		if (index_new) {
			if (input_index > mdl->info.num_inputs - 1) {
				_ODP_ERR("Too much number of input segments given\n");
				return -1;
			}

			/* Input with dynamic batch size */
			if (mdl->input_info[input_index].shape.type == ODP_ML_SHAPE_BATCH)
				size = dyn_io_size(&mdl->input_info[input_index].shape,
						   mdl->input_info[input_index].data_type_size,
						   param);
			else
				size = mdl->input_sizes[input_index];

			if (!size) {
				_ODP_ERR("Size for %uth input is 0\n", input_index);
				return -1;
			}
		}

		seg_size_sum += data->input_seg[i].size;

		if (seg_size_sum > size) {
			_ODP_ERR("Sum of segment sizes %u exceeds %uth input data size %u\n",
				 seg_size_sum, input_index, size);
			return -1;
		}

		if (seg_size_sum == size) {
			if (segs_per_input > _odp_ml_glb->capa.max_segs_per_input) {
				_ODP_ERR("Number of segments %u for input[%u] exceeds maximum"
					 " number of data segments per model input %u\n",
					 segs_per_input, input_index,
					 _odp_ml_glb->capa.max_segs_per_input);
				return -1;
			}
			input_index++;
			index_new = true;
			seg_size_sum = 0;
			segs_per_input = 1;
		} else {
			segs_per_input++;
			index_new = false;
		}
	}

	if (input_index != mdl->info.num_inputs) {
		_ODP_ERR("Data is not provided for all model inputs\n");
		return -1;
	}

	seg_size_sum = 0;
	index_new = true;
	uint32_t output_index = 0;
	uint32_t segs_per_output = 1;

	for (uint32_t i = 0; i < data->num_output_seg; i++) {
		if (data->output_seg[i].addr == NULL) {
			_ODP_ERR("data->output_seg[%u].addr must not NULL\n", i);
			return -1;
		}

		if (index_new) {
			if (output_index > mdl->info.num_outputs - 1) {
				_ODP_ERR("Too much number of output segments given\n");
				return -1;
			}

			/* Output with dynamic batch size */
			if (mdl->output_info[output_index].shape.type == ODP_ML_SHAPE_BATCH)
				size = dyn_io_size(&mdl->output_info[output_index].shape,
						   mdl->output_info[output_index].data_type_size,
						   param);
			else
				size = mdl->output_sizes[output_index];

			if (!size) {
				_ODP_ERR("Size for %uth output is 0\n", output_index);
				return -1;
			}
		}

		seg_size_sum += data->output_seg[i].size;

		if (seg_size_sum > size) {
			_ODP_ERR("Sum of segment sizes %u exceeds %uth output data size %u\n",
				 seg_size_sum, output_index, size);
			return -1;
		}

		if (seg_size_sum >= size) {
			if (segs_per_output > _odp_ml_glb->capa.max_segs_per_output) {
				_ODP_ERR("Number of segments %u for output[%u] exceeds maximum"
					 " number of data segments per model output %u\n",
					 segs_per_output, output_index,
					 _odp_ml_glb->capa.max_segs_per_output);
				return -1;
			}
			output_index++;
			index_new = true;
			seg_size_sum = 0;
			segs_per_output = 1;
		} else {
			segs_per_output++;
			index_new = false;
		}
	}

	if (output_index != mdl->info.num_outputs) {
		_ODP_ERR("Not enough output_segs to hold all output data\n");
		return -1;
	}

	return 0;
}

static ONNXTensorElementDataType onnx_dtype_from_odp_dtype(odp_ml_data_type_t data_type)
{
	switch (data_type) {
	case ODP_ML_DATA_TYPE_NONE:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_UNDEFINED;
	case ODP_ML_DATA_TYPE_INT8:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_INT8;
	case ODP_ML_DATA_TYPE_UINT8:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT8;
	case ODP_ML_DATA_TYPE_INT16:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_INT16;
	case ODP_ML_DATA_TYPE_UINT16:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT16;
	case ODP_ML_DATA_TYPE_INT24:
		/* Fall through*/
	case ODP_ML_DATA_TYPE_UINT24:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_UNDEFINED;
	case ODP_ML_DATA_TYPE_FP64:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_DOUBLE;
	case ODP_ML_DATA_TYPE_INT32:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_INT32;
	case ODP_ML_DATA_TYPE_UINT32:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT32;
	case ODP_ML_DATA_TYPE_INT64:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_INT64;
	case ODP_ML_DATA_TYPE_UINT64:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_UINT64;
	case ODP_ML_DATA_TYPE_FP16:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT16;
	case ODP_ML_DATA_TYPE_FP32:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT;
	case ODP_ML_DATA_TYPE_BFP16:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_BFLOAT16;
	default:
		return ONNX_TENSOR_ELEMENT_DATA_TYPE_UNDEFINED;
	}
}

static int verify_tensor(const OrtValue *tensor, odp_ml_data_type_t expected_type,
			 const odp_ml_shape_info_t *expected_shape, uint32_t batch_size)
{
	OrtTensorTypeAndShapeInfo *tensor_info;
	ONNXTensorElementDataType tensor_type;
	size_t dim_count;
	OrtStatus *status = NULL;
	int64_t dims[ODP_ML_MAX_DIMS] = {0};
	int64_t shape_arr[ODP_ML_MAX_DIMS] = {0};
	const OrtApi *ort_api = _odp_ml_glb->ort_api;

	status = ort_api->GetTensorTypeAndShape(tensor, &tensor_info);
	if (check_ortstatus(status)) {
		_ODP_ERR("GetTensorTypeAndShape() failed\n");
		return -1;
	}

	status = ort_api->GetTensorElementType(tensor_info, &tensor_type);
	if (check_ortstatus(status)) {
		ort_api->ReleaseTensorTypeAndShapeInfo(tensor_info);
		_ODP_ERR("GetTensorElementType() failed\n");
		return -1;
	}

	if (onnx_dtype_to_odp_dtype(tensor_type) != expected_type) {
		ort_api->ReleaseTensorTypeAndShapeInfo(tensor_info);
		_ODP_ERR("Tensor type does not match model type\n");
		return -1;
	}

	status = ort_api->GetDimensionsCount(tensor_info, &dim_count);
	if (check_ortstatus(status)) {
		ort_api->ReleaseTensorTypeAndShapeInfo(tensor_info);
		_ODP_ERR("GetDimensionsCount() failed\n");
		return -1;
	}

	if (dim_count != expected_shape->num_dim) {
		ort_api->ReleaseTensorTypeAndShapeInfo(tensor_info);
		_ODP_ERR("Tensor dimension does not match shape_dim\n");
		return -1;
	}

	status = ort_api->GetDimensions(tensor_info, dims, dim_count);
	if (check_ortstatus(status)) {
		ort_api->ReleaseTensorTypeAndShapeInfo(tensor_info);
		_ODP_ERR("GetDimensions() failed\n");
		return -1;
	}

	ml_shape_to_int64(expected_shape, batch_size, shape_arr);

	for (uint32_t i = 0; i < dim_count; i++) {
		if (dims[i] != shape_arr[i]) {
			ort_api->ReleaseTensorTypeAndShapeInfo(tensor_info);
			_ODP_ERR("Shape[%u]: %" PRIu64 " does not match expected: %" PRIu64 "\n",
				 i, dims[i], shape_arr[i]);
			return -1;
		}
	}

	ort_api->ReleaseTensorTypeAndShapeInfo(tensor_info);
	return 0;
}

static int input_data_to_tensor(const odp_ml_input_info_t *input_info, uint32_t num_seg,
				const odp_ml_data_seg_t *input_seg, uint32_t *seg_idx,
				uint32_t batch_size, OrtValue **input_tensor)
{
	int is_tensor;
	uint64_t input_size;
	OrtAllocator *allocator;
	void *data = NULL;
	OrtStatus *status = NULL;
	int64_t shape[ODP_ML_MAX_DIMS] = {0};
	const OrtApi *ort_api = _odp_ml_glb->ort_api;
	ONNXTensorElementDataType onnx_dtype = ONNX_TENSOR_ELEMENT_DATA_TYPE_UNDEFINED;

	ml_shape_to_int64(&input_info->shape, batch_size, shape);

	onnx_dtype = onnx_dtype_from_odp_dtype(input_info->data_type);
	_ODP_ASSERT(onnx_dtype != ONNX_TENSOR_ELEMENT_DATA_TYPE_UNDEFINED);

	status = ort_api->GetAllocatorWithDefaultOptions(&allocator);
	if (check_ortstatus(status)) {
		_ODP_ERR("GetAllocatorWithDefaultOptions() failed\n");
		return -1;
	}

	status = ort_api->CreateTensorAsOrtValue(allocator,
						 shape,
						 input_info->shape.num_dim,
						 onnx_dtype,
						 input_tensor);
	if (check_ortstatus(status) || !input_tensor[0]) {
		_ODP_ERR("CreateTensorWithDataAsOrtValue() failed\n");
		return -1;
	}

	input_size = input_info->data_type_size * get_num_elem(batch_size, &input_info->shape);

	status = ort_api->GetTensorMutableData(input_tensor[0], &data);
	if (check_ortstatus(status) || !data) {
		_ODP_ERR("GetTensorMutableData() failed\n");
		return -1;
	}

	for (uint64_t i = 0; i < input_size; ) {
		if (*seg_idx >= num_seg) {
			_ODP_ERR("Insufficient input data\n");
			return -1;
		}

		uint64_t seg_size = input_seg[*seg_idx].size;

		if (i + seg_size > input_size) {
			_ODP_ERR("Excess input data in segment %" PRIu32 "\n", *seg_idx);
			return -1;
		}

		memcpy((uint8_t *)data + i, input_seg[(*seg_idx)++].addr, seg_size);
		i += seg_size;
	}

	if (!ODP_DEBUG)
		return 0;

	status = ort_api->IsTensor(input_tensor[0], &is_tensor);
	if (check_ortstatus(status) || !is_tensor) {
		_ODP_ERR("input_tensor IsTensor failed\n");
		return -1;
	}

	/* Make sure tensor shape matches input_shape */
	if (verify_tensor(input_tensor[0], input_info->data_type,
			  &input_info->shape, batch_size)) {
		_ODP_ERR("Verify input_tensor failed\n");
		return -1;
	}

	return 0;
}

static int verify_output_tensor(OrtValue *output_tensor, odp_ml_data_type_t expected_type,
				const odp_ml_shape_info_t *expected_shape, uint32_t batch_size)
{
	int is_tensor = 0;
	const OrtApi *ort_api = _odp_ml_glb->ort_api;
	OrtStatus *status = ort_api->IsTensor(output_tensor, &is_tensor);

	if (check_ortstatus(status) || !is_tensor) {
		_ODP_ERR("output_tensor IsTensor failed\n");
		return -1;
	}

	/* Make sure tensor shape matches output_shape */
	if (verify_tensor(output_tensor, expected_type, expected_shape, batch_size)) {
		_ODP_ERR("Verify output_tensor failed\n");
		return -1;
	}

	return 0;
}

static int get_tensor_data_size(OrtValue *tensor, uint32_t *size, uint32_t data_type_size)
{
	size_t num_elem;
	OrtStatus *status;
	OrtTensorTypeAndShapeInfo *tensor_info;
	const OrtApi *ort_api = _odp_ml_glb->ort_api;

	status = ort_api->GetTensorTypeAndShape(tensor, &tensor_info);
	if (check_ortstatus(status)) {
		_ODP_ERR("GetTensorTypeAndShape() failed\n");
		return -1;
	}

	status = ort_api->GetTensorShapeElementCount(tensor_info, &num_elem);
	if (check_ortstatus(status)) {
		ort_api->ReleaseTensorTypeAndShapeInfo(tensor_info);
		_ODP_ERR("GetTensorShapeElementCount() failed\n");
		return -1;
	}
	*size = data_type_size * num_elem;

	ort_api->ReleaseTensorTypeAndShapeInfo(tensor_info);
	return 0;
}

static int check_output_size(odp_bool_t is_segmented, uint32_t output_idx, uint32_t seg_idx,
			     uint64_t out_tensor_data_size, const odp_ml_data_t data[])
{
	uint64_t output_size = 0;

	/* Output is not segmented */
	if (!is_segmented) {
		/* Make sure tensor data size does not exceed size allocated for
		 * data->output_seg[seg_idx].addr */
		if (out_tensor_data_size > data->output_seg[seg_idx].size) {
			_ODP_ERR("Malloc at least %" PRIu64 " bytes for %dth output tensor\n",
				 out_tensor_data_size, output_idx);
			return -1;
		}

		return 0;
	}

	/* Output is segmented, first calculate total size for one tensor */
	for (; seg_idx < data->num_output_seg; seg_idx++) {
		output_size += data->output_seg[seg_idx].size;
		if (output_size >= out_tensor_data_size)
			break;
	}

	if (0 == output_size) {
		_ODP_ERR("No output data segments for %uth output tensor\n", output_idx);
		return -1;
	}

	if (out_tensor_data_size > output_size) {
		_ODP_ERR("Output segments (%" PRIu64 " bytes in total) for %uth output"
			 " is expected to be at least %" PRIu64 " bytes\n",
			 output_size, output_idx, out_tensor_data_size);
		return -1;
	}

	return 0;
}

static int output_tensors_to_data(OrtValue **output_tensors,
				  uint32_t model_num_outputs,
				  const odp_ml_run_param_t *param,
				  const odp_ml_output_info_t *output_info,
				  const odp_ml_data_t *data,
				  odp_ml_run_result_t *result_local)
{
	uint32_t seg_idx;
	uint64_t seg_size;
	uint64_t cpy_size;
	uint64_t left_size;
	uint64_t output_val_offset;
	uint32_t out_tensor_data_size;
	void *output_val = NULL; /* Pointer to store one raw output value */
	OrtStatus *status = NULL;
	uint32_t batch_size = (param && param->batch_size) ? param->batch_size : 0;
	const OrtApi *ort_api = _odp_ml_glb->ort_api;
	odp_bool_t is_segmented = (data->num_output_seg != model_num_outputs);

	seg_idx = 0;
	for (uint32_t i = 0; i < model_num_outputs; i++) {
		if (ODP_DEBUG &&
		    verify_output_tensor(output_tensors[i], output_info[i].data_type,
					 &output_info[i].shape, batch_size)){
			result_local->error_code = ML_BAD_OUTPUT;
			return -1;
		}

		/* Get tensor data size */
		if (get_tensor_data_size(output_tensors[i], &out_tensor_data_size,
					 output_info[i].data_type_size)) {
			result_local->error_code = ML_LIB_FAILED;
			return -1;
		}

		/* When output_tensor is an empty tensor [], skip getting data */
		if (out_tensor_data_size == 0)
			continue;

		if (ODP_DEBUG && check_output_size(is_segmented, i, seg_idx,
						   out_tensor_data_size, data)) {
			result_local->error_code = ML_BAD_OUTPUT;
			return -1;
		}

		/* Following assumes param and data->output_seg are valid */
		/* Get tensor data */
		output_val = NULL;
		status = ort_api->GetTensorMutableData(output_tensors[i], &output_val);
		if (check_ortstatus(status) || !output_val) {
			result_local->error_code = ML_LIB_FAILED;
			return -1;
		}

		/* Output is not segmented */
		if (!is_segmented) {
			/* Store output data to data->output_seg[i].addr */
			memcpy(data->output_seg[i].addr, output_val, out_tensor_data_size);
			seg_idx++;
			continue;
		}

		/* Output is segmented */
		output_val_offset = 0;
		left_size = out_tensor_data_size;
		for (; seg_idx < data->num_output_seg; seg_idx++) {
			seg_size = data->output_seg[seg_idx].size;
			cpy_size = left_size > seg_size ? seg_size : left_size;
			memcpy(data->output_seg[seg_idx].addr,
			       ((char *)output_val) + output_val_offset, cpy_size);

			output_val_offset += cpy_size;
			left_size = out_tensor_data_size - output_val_offset;

			if (!left_size) {
				seg_idx++;
				break;
			}
		}
	}

	return 0;
}

int odp_ml_run(odp_ml_model_t model, const odp_ml_data_t *data, const odp_ml_run_param_t *param)
{
	odp_ml_run_result_t result_local;

	int retval		= -1; /* Return value of this function */
	int ret			= 0;
	OrtStatus *status	= NULL;
	uint32_t batch_size	= 0;

	OrtValue *input_tensor[CONFIG_ML_MAX_INPUTS]	= {0};
	OrtValue *output_tensors[CONFIG_ML_MAX_OUTPUTS]	= {0};
	const char *input_names[CONFIG_ML_MAX_INPUTS]	= {0};
	const char *output_names[CONFIG_ML_MAX_OUTPUTS]	= {0};

	const OrtApi *ort_api			= _odp_ml_glb->ort_api;
	ml_model_t *mdl				= ml_model_from_handle(model);
	const odp_ml_model_info_t *ml_info	= &mdl->info;
	const odp_ml_input_info_t *input_info	= mdl->input_info;
	const odp_ml_output_info_t *output_info = mdl->output_info;
	OrtSession *session			= mdl->session;

	odp_ticketlock_lock(&mdl->lock);
	if (odp_unlikely(mdl->state == ML_STATE_INFERENCING)) {
		odp_ticketlock_unlock(&mdl->lock);
		return 0;
	}
	if (odp_unlikely(mdl->state != ML_STATE_LOADED)) {
		_ODP_ERR("Wrong model state: not created or not loaded\n");
		odp_ticketlock_unlock(&mdl->lock);
		return -1;
	}
	mdl->state = ML_STATE_INFERENCING;
	odp_ticketlock_unlock(&mdl->lock);

	memset(&result_local, 0, sizeof(result_local));

	if (ODP_DEBUG && verify_run_params(model, data, param)) {
		result_local.error_code = ML_BAD_INPUT;
		goto init_fail;
	}

	if (param && param->batch_size)
		batch_size = param->batch_size;

	uint32_t seg_idx = 0;

	/* Transfer input data to tensor */
	for (uint32_t i = 0; i < ml_info->num_inputs; i++) {
		ret = input_data_to_tensor(&input_info[i],
					   data->num_input_seg,
					   data->input_seg,
					   &seg_idx,
					   batch_size,
					   &input_tensor[i]);
		if (ret) {
			_ODP_ERR("%uth input data to tensor failed\n", i);
			result_local.error_code = ML_LIB_FAILED;
			goto release_input_tensors;
		}

		_ODP_DBG("input_tensor[%u]: %p\n", i, input_tensor[i]);

		/* Model input names */
		input_names[i] = input_info[i].name;
	}

	if (seg_idx < data->num_input_seg) {
		_ODP_ERR("Excess input segments\n");
		ret = -1;
	}

	for (uint32_t i = 0; i < ml_info->num_outputs; i++)
		output_names[i] = output_info[i].name;

	/* Run inference */
	status = ort_api->Run(session,
			      NULL,
			      (const char * const *)input_names,
			      (const OrtValue * const*)input_tensor,
			      ml_info->num_inputs,
			      (const char * const *)output_names,
			      ml_info->num_outputs,
			      output_tensors);

	if (check_ortstatus(status)) {
		_ODP_ERR("Run inference failed\n");
		result_local.error_code = ML_LIB_FAILED;
		goto release_all_tensors;
	}

	/* Verify output tensors and store them to output */
	if (output_tensors_to_data(output_tensors, ml_info->num_outputs, param,
				   output_info, data, &result_local)) {
		_ODP_ERR("Output tensors to data failed\n");
		goto release_all_tensors;
	}

	retval = 1;

release_all_tensors:
	for (uint32_t i = 0; i < ml_info->num_outputs; i++)
		ort_api->ReleaseValue(output_tensors[i]);

release_input_tensors:
	for (uint32_t i = 0; i < ml_info->num_inputs; i++)
		ort_api->ReleaseValue(input_tensor[i]);

init_fail:
	if (param && param->result)
		*param->result = result_local;

	odp_ticketlock_lock(&mdl->lock);
	mdl->state = ML_STATE_LOADED;
	odp_ticketlock_unlock(&mdl->lock);

	return retval;
}

int odp_ml_run_multi(odp_ml_model_t model, const odp_ml_data_t data[],
		     const odp_ml_run_param_t param[], int num)
{
	int i;
	int ret;

	if (odp_unlikely(num < 1)) {
		_ODP_ERR("Bad number of runs\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		if (param)
			ret = odp_ml_run(model, &data[i], &param[i]);
		else
			ret = odp_ml_run(model, &data[i], NULL);

		if (odp_unlikely(ret != 1))
			break;
	}

	if (odp_unlikely(i == 0))
		return ret;

	return i;
}

int odp_ml_run_start(odp_ml_model_t model, const odp_ml_data_t *data,
		     const odp_ml_compl_param_t *compl_param,
		     const odp_ml_run_param_t *run_param)
{
	int ret;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID)) {
		_ODP_ERR("Bad model handle\n");
		return -1;
	}

	if (odp_unlikely(!compl_param)) {
		_ODP_ERR("Completion parameter is NULL\n");
		return -1;
	}

	/* Check completion mode */
	if (odp_unlikely(check_compl_param(compl_param, mdl->max_compl_id, false))) {
		_ODP_ERR("Bad ML job completion parameter\n");
		return -1;
	}

	if (compl_param->mode == ODP_ML_COMPL_MODE_POLL)
		odp_atomic_store_rel_u32(&mdl->compl_status[compl_param->compl_id], 0);

	ret = odp_ml_run(model, data, run_param);

	if (odp_unlikely(ret < 1))
		return ret;

	/* Send a completion event to the given queue */
	if (compl_param->mode == ODP_ML_COMPL_MODE_EVENT) {
		odp_ml_run_result_t *result;
		odp_buffer_t buf = (odp_buffer_t)(uintptr_t)compl_param->event;

		_odp_buffer_subtype_set(buf, ODP_EVENT_ML_COMPL_RUN);

		result = odp_buffer_addr(buf);
		result->error_code = 0;
		result->user_ptr = compl_param->user_ptr;

		if (odp_unlikely(odp_queue_enq(compl_param->queue, compl_param->event))) {
			_ODP_ERR("Completion event enqueue failed %" PRIu64 "\n",
				 odp_queue_to_u64(compl_param->queue));
			return -1;
		}

		return 1;
	}

	/* compl_param->mode == ODP_ML_COMPL_MODE_POLL */
	mdl->result[compl_param->compl_id].user_ptr = compl_param->user_ptr;
	odp_atomic_store_rel_u32(&mdl->compl_status[compl_param->compl_id], 1);

	return 1;
}

int odp_ml_run_start_multi(odp_ml_model_t model, const odp_ml_data_t data[],
			   const odp_ml_compl_param_t compl_param[],
			   const odp_ml_run_param_t run_param[], int num)
{
	int i;
	int ret = 0;

	if (odp_unlikely(num < 1)) {
		_ODP_ERR("Bad number of runs\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		if (run_param)
			ret = odp_ml_run_start(model, &data[i], &compl_param[i], &run_param[i]);
		else
			ret = odp_ml_run_start(model, &data[i], &compl_param[i], NULL);

		if (odp_unlikely(ret != 1))
			break;
	}

	if (odp_unlikely(i == 0))
		return ret;

	return i;
}

int odp_ml_run_status(odp_ml_model_t model, uint32_t compl_id, odp_ml_run_result_t *result)
{
	int ret;
	ml_model_t *mdl = ml_model_from_handle(model);

	if (odp_unlikely(model == ODP_ML_MODEL_INVALID ||
			 compl_id > mdl->max_compl_id)) {
		_ODP_ERR("Invalid model handle or completion id: %u\n", compl_id);
		return -2;
	}

	ret = odp_atomic_load_acq_u32(&mdl->compl_status[compl_id]);

	if (result) {
		result->error_code = 0;
		result->user_ptr = mdl->result[compl_id].user_ptr;
	}

	return ret;
}

static int opt_level_from_str(const char *level_str, GraphOptimizationLevel *level)
{
	if (strcmp(level_str, "DISABLE_ALL") == 0)
		*level = ORT_DISABLE_ALL;
	else if (strcmp(level_str, "ENABLE_BASIC") == 0)
		*level = ORT_ENABLE_BASIC;
	else if (strcmp(level_str, "ENABLE_EXTENDED") == 0)
		*level = ORT_ENABLE_EXTENDED;
	else if (strcmp(level_str, "ENABLE_ALL") == 0)
		*level = ORT_ENABLE_ALL;
	else
		return -1;

	return 0;
}

static int execution_mode_from_str(const char *mode_str, ExecutionMode *mode)
{
	if (strcmp(mode_str, "SEQUENTIAL") == 0)
		*mode = ORT_SEQUENTIAL;
	else if (strcmp(mode_str, "PARALLEL") == 0)
		*mode = ORT_PARALLEL;
	else
		return -1;

	return 0;
}

static int read_config_file(ort_run_opts_t *opts)
{
	const char *conf_str;
	char mode_str[ML_MAX_CONFIG_STR_LEN];
	char opt_level_str[ML_MAX_CONFIG_STR_LEN];

	_ODP_PRINT("ML config:\n");

	conf_str =  "ml.enable_profiling";
	if (!_odp_libconfig_lookup_int(conf_str, &opts->enable_profiling)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		return -1;
	}
	_ODP_PRINT("  %s: %i\n", conf_str, opts->enable_profiling);

	conf_str =  "ml.execution_mode";
	if (_odp_libconfig_lookup_str(conf_str, mode_str, ML_MAX_CONFIG_STR_LEN) < 0) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		return -1;
	}

	if (execution_mode_from_str(mode_str, &opts->execution_mode)) {
		_ODP_ERR("Unsupported execution mode: %s\n", mode_str);
		return -1;
	}
	_ODP_PRINT("  %s: %s\n", conf_str, mode_str);

	conf_str =  "ml.inter_op_num_threads";
	if (!_odp_libconfig_lookup_int(conf_str, &opts->inter_op_num_threads)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		return -1;
	}
	_ODP_PRINT("  %s: %i\n", conf_str, opts->inter_op_num_threads);

	conf_str =  "ml.intra_op_num_threads";
	if (!_odp_libconfig_lookup_int(conf_str, &opts->intra_op_num_threads)) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		return -1;
	}
	_ODP_PRINT("  %s: %i\n", conf_str, opts->intra_op_num_threads);

	conf_str =  "ml.graph_optimization_level";
	if (_odp_libconfig_lookup_str(conf_str, opt_level_str,
				      ML_MAX_CONFIG_STR_LEN) < 0) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		return -1;
	}

	if (opt_level_from_str(opt_level_str, &opts->graph_opt_level)) {
		_ODP_ERR("Graph optimize level %s not supported\n", opt_level_str);
		return -1;
	}
	_ODP_PRINT("  %s: %s\n", conf_str, opt_level_str);

	conf_str =  "ml.optimized_model_filepath";
	if (_odp_libconfig_lookup_str(conf_str, opts->opt_model_filepath,
				      ML_MAX_CONFIG_STR_LEN) < 0) {
		_ODP_ERR("Config option '%s' not found.\n", conf_str);
		return -1;
	}
	_ODP_PRINT("  %s: %s\n", conf_str, opts->opt_model_filepath);

	return 0;
}

int _odp_ml_init_global(void)
{
	int i;
	OrtEnv *env;
	odp_shm_t shm;
	OrtStatus *status;
	const OrtApi *ort_api;

	if (odp_global_ro.disable.ml) {
		_ODP_ERR("ML is disabled\n");
		return 0;
	}

	shm = odp_shm_reserve("_odp_ml_global", sizeof(ml_global_t), ODP_CACHE_LINE_SIZE, 0);
	_odp_ml_glb = odp_shm_addr(shm);

	if (_odp_ml_glb == NULL) {
		_ODP_ERR("SHM reserve failed for odp_ml\n");
		return -1;
	}

	memset(_odp_ml_glb, 0, sizeof(ml_global_t));
	_odp_ml_glb->shm = shm;

	if (odp_ml_capability(&_odp_ml_glb->capa)) {
		_ODP_ERR("ML capability failed\n");
		return -1;
	}

	odp_pool_param_init(&_odp_ml_glb->pool_param);

	if (read_config_file(&_odp_ml_glb->ort_run_opts))
		return -1;

	ort_api = OrtGetApiBase()->GetApi(ORT_API_VERSION);
	if (!ort_api) {
		_ODP_ERR("Failed to init ONNX Runtime engine.\n");
		return -1;
	}
	_odp_ml_glb->ort_api = ort_api;

	status = ort_api->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "Default", &env);
	if (check_ortstatus(status) || !env) {
		_ODP_ERR("ort_api->CreateEnv() failed.\n");
		return -1;
	}
	_odp_ml_glb->env = env;

	for (i = 0; i < ML_MAX_MODELS_CREATED; i++)
		odp_ticketlock_init(&_odp_ml_glb->models[i].lock);

	return 0;
}

int _odp_ml_term_global(void)
{
	if (odp_global_ro.disable.ml)
		return 0;

	if (_odp_ml_glb == NULL)
		return 0;

	if (_odp_ml_glb->env)
		_odp_ml_glb->ort_api->ReleaseEnv(_odp_ml_glb->env);

	if (odp_shm_free(_odp_ml_glb->shm)) {
		_ODP_ERR("Shm free failed for odp_ml\n");
		return -1;
	}

	return 0;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2025 Nokia
 * Copyright (c) 2021 Marvell
 */

/**
 * @file
 *
 * ODP Machine Learning (ML) types
 */

#ifndef ODP_API_SPEC_ML_TYPES_H_
#define ODP_API_SPEC_ML_TYPES_H_
#include <odp/visibility_begin.h>

#include <odp/api/event_types.h>
#include <odp/api/queue_types.h>
#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_ml ODP ML
 *  @{
 */

/**
 * @typedef odp_ml_model_t
 * ODP ML model handle
 */

/**
 * @def ODP_ML_MODEL_INVALID
 * Invalid ML model
 */

/**
 * @typedef odp_ml_compl_t
 * ML completion event
 */

/**
 * @def ODP_ML_COMPL_INVALID
 * Invalid ML completion event
 */

/**
 * @def ODP_ML_MODEL_NAME_LEN
 * Maximum length of model name, including the null character
 */

/**
 * @def ODP_ML_MODEL_IO_NAME_LEN
 * Maximum length of model input/output name, including the null character
 */

/**
 * @def ODP_ML_SHAPE_NAME_LEN
 * Maximum length of data dimension name, including the null character
 */

/**
 * @def ODP_ML_EXTRA_STAT_NAME_LEN
 * Maximum length of extra statistics counter name, including the null character
 */

/**
 * @typedef odp_ml_model_extra_param_t
 * ODP implementation specific extra parameters for model creation
 */

/** Maximum number of dimensions in input / output data shape */
#define ODP_ML_MAX_DIMS      8

/** Dimension size is dynamic */
#define ODP_ML_DIM_DYNAMIC   0

/** Synchronous operation */
#define ODP_ML_COMPL_MODE_SYNC 0x1u

/**
 * Asynchronous poll mode operation
 *
 * A function call starts an operation and a status function call indicates when
 * the operation has finished.
 */
#define ODP_ML_COMPL_MODE_POLL 0x2u

/**
 * Asynchronous event mode operation
 *
 * A function call starts an operation and a completion event indicates when
 * the operation has finished.
 */
#define ODP_ML_COMPL_MODE_EVENT 0x4u

/** ML completion mode */
typedef uint32_t odp_ml_compl_mode_t;

/**
 * ML completion event pool capabilities
 *
 * Pool statistics are not supported with ML completion event pools.
 */
typedef struct odp_ml_compl_pool_capability_t {
	/**
	 * Maximum number of ML completion event pools
	 *
	 * See odp_pool_capability_t.max_pools for maximum number of pools of any type. It
	 * includes also ML completion event pools.
	 */
	uint32_t max_pools;

	/** Maximum number of ML completion events in a pool */
	uint32_t max_num;

	/** Maximum user area size in bytes */
	uint32_t max_uarea_size;

	/** User area persistence
	 *
	 *  See buf.uarea_persistence of odp_pool_capability_t for details
	 *  (odp_pool_capability_t.uarea_persistence).
	 */
	odp_bool_t uarea_persistence;

	/** Maximum size of local thread cache */
	uint32_t max_cache_size;

	/** Minimum size of local thread cache */
	uint32_t min_cache_size;

} odp_ml_compl_pool_capability_t;

/**
 * ML completion event pool parameters
 *
 * Use odp_ml_compl_pool_param_init() to initialize the structure to its default values.
 */
typedef struct odp_ml_compl_pool_param_t {
	/**
	 * Number of ML completion events in the pool
	 *
	 * The maximum supported value is defined by ML pool capability 'max_num'
	 * (odp_ml_compl_pool_capability_t.max_num).
	 */
	uint32_t num;

	/**
	 * User area size in bytes
	 *
	 * The maximum supported value is defined by ML pool capability 'max_uarea_size'.
	 * Specify as zero if no user area is needed. The default value is 0.
	 */
	uint32_t uarea_size;

	/** Parameters for user area initialization */
	struct {
		/** See uarea_init.init_fn of odp_pool_param_t for details
		 *  (odp_pool_param_t.init_fn). Function is called during
		 *  odp_ml_compl_pool_create(). The default value is NULL. */
		void (*init_fn)(void *uarea, uint32_t size, void *args, uint32_t index);

		/** See uarea_init.args of odp_pool_param_t for details
		 *  (odp_pool_param_t.args). The default value is NULL. */
		void *args;

	} uarea_init;

	/**
	 * Maximum number of events cached locally per thread
	 *
	 * See odp_pool_param_t.cache_size documentation for details. Valid values range from
	 * 'min_cache_size' to 'max_cache_size' ML pool capability. The default value is
	 * implementation specific and set by odp_ml_compl_pool_param_init().
	 */
	uint32_t cache_size;

} odp_ml_compl_pool_param_t;

/** Machine learning capabilities per engine */
typedef struct odp_ml_capability_t {
	/** Maximum number of models
	 *
	 *  Maximum number of models that can be created simultaneously. The value is zero when
	 *  ML offload is not available. */
	uint32_t max_models;

	/** Maximum number of models that can be loaded simultaneously */
	uint32_t max_models_loaded;

	/** Maximum model size in bytes */
	uint64_t max_model_size;

	/** Maximum completion identifier value */
	uint32_t max_compl_id;

	/** Maximum number of model inputs */
	uint32_t max_inputs;

	/** Maximum number of model outputs */
	uint32_t max_outputs;

	/**
	 * Maximum number of data segments per model input
	 *
	 * Segmented input data is not supported when 1.
	 */
	uint32_t max_segs_per_input;

	/**
	 * Maximum number of data segments per model output
	 *
	 * Segmented output data is not supported when 1.
	 */
	uint32_t max_segs_per_output;

	/**
	 * Minimum input data alignment in bytes
	 *
	 * For each model input, the first data segment must start at this or a higher power of two
	 * memory alignment in bytes. The value is 1 when there is no alignment requirement.
	 */
	uint32_t min_input_align;

	/**
	 * Minimum output data alignment in bytes
	 *
	 * For each model output, the first data segment must start at this or a higher power of two
	 * memory alignment in bytes. The value is 1 when there is no alignment requirement.
	 */
	uint32_t min_output_align;

	/**
	 * Input data packing
	 *
	 * 0: Data packing is not required.
	 * 1: Data for all model inputs must be continuous in memory. The memory block starts with
	 *    data for the first input and continues through all inputs in-order and without gaps
	 *    between inputs. The minimum alignment requirement (min_input_align) applies only for
	 *    the first input.
	 */
	odp_bool_t packed_input_data;

	/**
	 * Output data packing
	 *
	 * 0: Data packing is not required.
	 * 1: Data buffer space for all model outputs must be continuous in memory. The memory
	 *    block starts with buffer space for the first output and continues through all outputs
	 *    in-order and without gaps between outputs. The minimum alignment requirement
	 *    (min_output_align) applies only for the first output.
	 */
	odp_bool_t packed_output_data;

	/** Model load / unload capabilities */
	struct {
		/**
		 * Supported completion modes for model load / unload operations
		 *
		 * Mask of supported completion modes. Each supported mode has the corresponding
		 * flag (e.g. #ODP_ML_COMPL_MODE_SYNC) set in the mask.
		 */
		odp_ml_compl_mode_t compl_mode_mask;

		/**
		 * Support of model load / unload completion into plain queues
		 *
		 * Specifies if plain queues are supported as destination queues for
		 * load / unload completion events (#ODP_ML_COMPL_MODE_EVENT).
		 *
		 * 0: Plain queues are not supported as completion queues
		 * 1: Plain queues are supported as completion queues
		 */
		odp_bool_t compl_queue_plain;

		/**
		 * Support of model load / unload completion into scheduled queues
		 *
		 * Specifies if scheduled queues are supported as destination queues for
		 * load / unload completion events (#ODP_ML_COMPL_MODE_EVENT).
		 *
		 * 0: Scheduled queues are not supported as completion queues
		 * 1: Scheduled queues are supported as completion queues
		 */
		odp_bool_t compl_queue_sched;

	} load;

	/** Model run capabilities */
	struct {
		/**
		 * Supported completion modes for model run operations
		 *
		 * Mask of supported completion modes. Each supported mode has the corresponding
		 * flag (e.g. #ODP_ML_COMPL_MODE_SYNC) set in the mask.
		 */
		odp_ml_compl_mode_t compl_mode_mask;

		/**
		 * Support of model run completion into plain queues
		 *
		 * Specifies if plain queues are supported as destination queues for
		 * run completion events (#ODP_ML_COMPL_MODE_EVENT).
		 *
		 * 0: Plain queues are not supported as completion queues
		 * 1: Plain queues are supported as completion queues
		 */
		odp_bool_t compl_queue_plain;

		/**
		 * Support of model run completion into scheduled queues
		 *
		 * Specifies if scheduled queues are supported as destination queues for
		 * run completion events (#ODP_ML_COMPL_MODE_EVENT).
		 *
		 * 0: Scheduled queues are not supported as completion queues
		 * 1: Scheduled queues are supported as completion queues
		 */
		odp_bool_t compl_queue_sched;

	} run;

	/** ML completion event pool capabilities */
	odp_ml_compl_pool_capability_t pool;

} odp_ml_capability_t;

/** Machine learning configuration parameters */
typedef struct odp_ml_config_t {
	/**
	 * Engine ID to be configured.
	 *
	 * In a system with multiple ML engines, this parameter selects the engine
	 * to be configured. The default value is 0. Engine ID should be in the range
	 * 0..num_engines-1, where num_engines can be fetched using odp_ml_num_engines().
	 */
	uint32_t engine_id;

	/**
	 * Maximum number of models
	 *
	 * Application may create and use this many models simultaneously. The default value is 1.
	 */
	uint32_t max_models_created;

	/**
	 * Maximum number of models loaded
	 *
	 * Maximum number of models that the application will keep loaded simultaneously.
	 * The default value is 1.
	 */
	uint32_t max_models_loaded;

	/**
	 * Maximum model binary size in bytes
	 *
	 * All model binaries application will pass to odp_ml_model_create() are this size or
	 * smaller.
	 */
	uint64_t max_model_size;

	/**
	 *  Load / unload completion modes
	 *
	 *  Mask of completion modes that application will use with model load/unload operations.
	 *  Multiple modes may be selected, but it is implementation specific if some combinations
	 *  are not supported. In case of an unsupported combination odp_ml_config() returns
	 *  failure. Check odp_ml_capability_t.load for supported modes. The default value is 0.
	 */
	odp_ml_compl_mode_t load_mode_mask;

	/**
	 *  Run completion modes
	 *
	 *  Mask of completion modes that application will use with model run operations.
	 *  Multiple modes may be selected, but it is implementation specific if some combinations
	 *  are not supported. In case of an unsupported combination odp_ml_config() returns
	 *  failure. Check odp_ml_capability_t.run for supported modes. The default value is 0.
	 */
	odp_ml_compl_mode_t run_mode_mask;

} odp_ml_config_t;

/** Model input / output data type enumeration */
typedef enum {
	/** Data type is not defined */
	ODP_ML_DATA_TYPE_NONE = 0,

	/** 8-bit integer */
	ODP_ML_DATA_TYPE_INT8,

	/** 8-bit unsigned integer */
	ODP_ML_DATA_TYPE_UINT8,

	/** 16-bit integer */
	ODP_ML_DATA_TYPE_INT16,

	/** 16-bit unsigned integer */
	ODP_ML_DATA_TYPE_UINT16,

	/** 24-bit integer */
	ODP_ML_DATA_TYPE_INT24,

	/** 24-bit unsigned integer */
	ODP_ML_DATA_TYPE_UINT24,

	/** 32-bit integer */
	ODP_ML_DATA_TYPE_INT32,

	/** 32-bit unsigned integer */
	ODP_ML_DATA_TYPE_UINT32,

	/** 64-bit integer */
	ODP_ML_DATA_TYPE_INT64,

	/** 64-bit unsigned integer */
	ODP_ML_DATA_TYPE_UINT64,

	/** 16-bit floating point number */
	ODP_ML_DATA_TYPE_FP16,

	/** 16-bit brain floating point (bfloat16) number */
	ODP_ML_DATA_TYPE_BFP16,

	/** 32-bit floating point number */
	ODP_ML_DATA_TYPE_FP32,

	/** 64-bit floating point number */
	ODP_ML_DATA_TYPE_FP64,

} odp_ml_data_type_t;

/** Model input / output data shape type */
typedef enum {
	/** Type of shape is not defined */
	ODP_ML_SHAPE_NONE = 0,

	/** Static shape of data
	 *
	 *  Shape is static when all dimensions have fixed sizes.
	 */
	ODP_ML_SHAPE_STATIC,

	/** Dynamic batch size
	 *
	 *  Shape that has only one dynamic dimension, and the dimension is used as batch size of
	 *  input / output data. The same batch size is applied for all inputs and outputs of
	 *  the model.
	 */
	ODP_ML_SHAPE_BATCH,

} odp_ml_shape_type_t;

/** Model input / output data shape information */
typedef struct odp_ml_shape_info_t {
	/** Shape type */
	odp_ml_shape_type_t type;

	/** Number of dimensions
	 *
	 *  Number of input / output data dimensions. When zero, the model does not have
	 *  dimension information available. ODP API supports in maximum #ODP_ML_MAX_DIMS
	 *  dimensions.
	 */
	uint32_t num_dim;

	/** Dimension sizes
	 *
	 *  Number of data values in each ('num_dim') dimension. Type of the data is defined by
	 *  odp_ml_data_type_t enumeration. Depending on the shape type, some dimensions may have
	 *  dynamic size which is denoted with #ODP_ML_DIM_DYNAMIC value. When shape type is
	 *  #ODP_ML_SHAPE_BATCH, the shape has one dynamic dimension which is used as the batch
	 *  size.
	 *
	 *  For example, a static (#ODP_ML_SHAPE_STATIC) NCHW tensor could be presented as:
	 *
	 *      num_dim = 4;
	 *      dim[0]  = 1;    // no batching, N = 1
	 *      dim[1]  = 3;    // 3 color channels
	 *      dim[2]  = 720;  // height 720 pixels
	 *      dim[3]  = 1280; // width 1280 pixels
	 *
	 *  ... and with dynamic batch size (#ODP_ML_SHAPE_BATCH):
	 *
	 *      num_dim = 4;
	 *      dim[0]  = ODP_ML_DIM_DYNAMIC; // dynamic in range: dim_min[0] ... dim_max[0]
	 *      dim[1]  = 3;
	 *      dim[2]  = 720;
	 *      dim[3]  = 1280;
	 */
	uint32_t dim[ODP_ML_MAX_DIMS];

	/** Minimum dimension sizes
	 *
	 *  Defines the minimum value for each dynamic size (#ODP_ML_DIM_DYNAMIC) in dim[] array.
	 *  Zero is used when the minimum value is unknown. When dimension size is static, the
	 *  value is equal to dim[] array value.
	 */
	uint32_t dim_min[ODP_ML_MAX_DIMS];

	/** Maximum dimension sizes
	 *
	 *  Defines the maximum value for each dynamic size (#ODP_ML_DIM_DYNAMIC) in dim[] array.
	 *  Zero is used when the maximum value is unknown. When dimension size is static, the
	 *  value is equal to dim[] array value.
	 */
	uint32_t dim_max[ODP_ML_MAX_DIMS];

	/** Dimension name
	 *
	 *  Name of each ('num_dim') dimension as a null terminated string. Null string is used if
	 *  a dimension does not have a name. Maximum string length is #ODP_ML_SHAPE_NAME_LEN
	 *  including the null character.
	 *
	 *  For example, an NCHW tensor could have dimensions named as:
	 *      dim_name = {"N", "C", "H", "W"}
	 */
	char dim_name[ODP_ML_MAX_DIMS][ODP_ML_SHAPE_NAME_LEN];

} odp_ml_shape_info_t;

/**
 * Quantization parameters
 *
 * These parameters are used to convert between floating point and integer data. Scale and zerop
 * values can be used directly with the odp_ml_fp32_from_*() and odp_ml_fp32_to_*() functions.
 */
typedef struct odp_ml_quant_param_t {
	/**
	 * Type of quantization scale value
	 *
	 * Valid quantization scale and zero point values are provided, if set to something other
	 * than #ODP_ML_DATA_TYPE_NONE. Allowed types are #ODP_ML_DATA_TYPE_NONE and
	 * #ODP_ML_DATA_TYPE_FP32.
	 */
	odp_ml_data_type_t type;

	/** Quantization scale */
	float scale_fp32;

	/** Quantization zero point */
	int32_t zerop_i32;

} odp_ml_quant_param_t;

/** Quantization information */
typedef struct odp_ml_quant_info_t {
	/** Quantization parameters common to all data values of an input / output */
	odp_ml_quant_param_t common;

} odp_ml_quant_info_t;

/** Model input information */
typedef struct odp_ml_input_info_t {
	/** Model input name */
	char name[ODP_ML_MODEL_IO_NAME_LEN];

	/** Model input data type */
	odp_ml_data_type_t data_type;

	/** Size of model input data type in bytes */
	uint32_t data_type_size;

	/** Model input data shape */
	odp_ml_shape_info_t shape;

	/** Model input quantization information */
	odp_ml_quant_info_t quant_info;

} odp_ml_input_info_t;

/** Model output information */
typedef struct odp_ml_output_info_t {
	/** Model output name */
	char name[ODP_ML_MODEL_IO_NAME_LEN];

	/** Model output data type */
	odp_ml_data_type_t data_type;

	/** Size of model output data type in bytes */
	uint32_t data_type_size;

	/** Model output data shape */
	odp_ml_shape_info_t shape;

	/** Model output quantization information */
	odp_ml_quant_info_t quant_info;

} odp_ml_output_info_t;

/** Model information */
typedef struct odp_ml_model_info_t {
	/** Model name */
	char name[ODP_ML_MODEL_NAME_LEN];

	/**
	 * Model version number
	 *
	 * Version number of the model binary. The number changes when the model is modified
	 * in any way.
	 */
	uint64_t model_version;

	/**
	 * Model interface version number
	 *
	 * The model interface version number changes only when model input or output data
	 * format is modified. Data formats are the same for two model versions that have
	 * the same interface version number.
	 */
	uint64_t interface_version;

	/** Engine ID to which the model is assigned */
	uint32_t engine_id;

	/** Model index assigned by the implementation */
	uint32_t index;

	/** Number of model inputs */
	uint32_t num_inputs;

	/** Number of model outputs */
	uint32_t num_outputs;

	/** Auxiliary information regarding the model and its inputs / outputs */
	union {
		/** Auxiliary bit fields */
		struct {
			/**
			 * Input quantization information provision
			 *
			 * When set to 1, model input information provides quantization
			 * information. If set, each input needs to be separately checked for
			 * information validity (see odp_ml_input_info_t::quant_info).
			 *
			 * When set to 0, no quantization information is provided for inputs.
			 */
			uint32_t input_quant_info  : 1;

			/**
			 * Output quantization information provision
			 *
			 * When set to 1, model output information provides quantization
			 * information.  If set, each output needs to be separately checked for
			 * information validity (see odp_ml_output_info_t::quant_info).
			 *
			 * When set to 0, no quantization information is provided for outputs.
			 */
			uint32_t output_quant_info : 1;

		};

		/**
		 * All bits of the bit field structure
		 *
		 * This field can be used for bitwise operations over the entire structure.
		 */
		uint32_t all;

	} aux;

} odp_ml_model_info_t;

/**
 * Model input / output data format
 */
typedef struct odp_ml_data_format_t {
	/** Model input / output data type */
	odp_ml_data_type_t data_type;

	/** Size of data type in bytes */
	uint32_t data_type_size;

	/** Model input / output data shape */
	odp_ml_shape_info_t shape;

} odp_ml_data_format_t;

/**
 * Machine learning model parameters
 *
 * Use odp_ml_model_param_init() to initialize the structure to its default values.
 */
typedef struct odp_ml_model_param_t {
	/**
	 * Engine ID
	 *
	 * Engine ID to be used with the model. The default value is 0. Engine ID should be in the
	 * range 0..num_engines-1, where num_engines can be fetched using odp_ml_num_engines().
	 */
	uint32_t engine_id;

	/**
	 * Model binary
	 *
	 * Points to model binary stored into a memory buffer. Model format is
	 * implementation specific. */
	void *model;

	/** Size of the model binary in bytes */
	uint64_t size;

	/**
	 * Maximum completion identifier value
	 *
	 * When application uses asynchronous poll mode (#ODP_ML_COMPL_MODE_POLL) operations with
	 * the model, it will choose completion identifier values between 0 and this value. Valid
	 * values range from 0 to max_compl_id capability. The default value is zero.
	 */
	uint32_t max_compl_id;

	/**
	 * Enable / disable extra statistics counters
	 *
	 * Extra statistics may be read with odp_ml_model_extra_stats() when enabled. Statistics
	 * are disabled by default.
	 */
	odp_bool_t extra_stat_enable;

	/**
	 * Extra model information
	 *
	 * When model metadata misses some details of model input / output data format, user can
	 * pass those with this structure. When 'num_inputs' / 'num_outputs' is non-zero, data
	 * format of all model inputs / outputs are overridden by the provided values. Values are
	 * ignored when 'num_inputs' / 'num_outputs' is zero.
	 */
	struct {
		/**
		 * Number of model inputs
		 *
		 * Number of model inputs and elements in 'input_format' array. When non-zero,
		 * the value must match the number of inputs defined in model metadata. The default
		 * value is 0.
		 */
		uint32_t num_inputs;

		/**
		 * Number of model outputs
		 *
		 * Number of model outputs and elements in 'output_format' array. When non-zero,
		 * the value must match the number of outputs defined in model metadata. The default
		 * value is 0.
		 */
		uint32_t num_outputs;

		/**
		 * Model input data format array
		 *
		 * Points to an array of data formats. The array has 'num_inputs' elements. Inputs
		 * are defined in the same order they are listed in model metadata.
		 * An odp_ml_model_create() call copies these values. The default value is NULL.
		 */
		const odp_ml_data_format_t *input_format;

		/**
		 * Model output data format array
		 *
		 * Points to an array of data formats. The array has 'num_outputs' elements. Outputs
		 * are defined in the same order they are listed in model metadata.
		 * An odp_ml_model_create() call copies these values. The default value is NULL.
		 */
		const odp_ml_data_format_t *output_format;

	} extra_info;

	/**
	 * ODP implementation specific extra parameters
	 *
	 * See ODP implementation documentation for details about extra parameter usage. For
	 * example, extra parameters may give hints about HW resource usage with the model to be
	 * created. An odp_ml_model_create() call copies these parameter values. When NULL, all
	 * extra parameters are set to their default values. The default value is NULL.
	 */
	const odp_ml_model_extra_param_t *extra_param;

} odp_ml_model_param_t;

/** Results of model run operation */
typedef struct odp_ml_run_result_t {
	/** Model run error code
	 *
	 *  Zero when model run completed successfully. Otherwise, error code contains
	 *  an implementation specific value.
	 */
	uint64_t error_code;

	/** User context pointer value from odp_ml_compl_param_t */
	void *user_ptr;

} odp_ml_run_result_t;

/** Result of model load / unload operation */
typedef struct odp_ml_load_result_t {
	/** Model load / unload error code
	 *
	 *  Zero when model load / unload completed successfully. Otherwise, error code contains
	 *  an implementation specific value.
	 */
	uint64_t error_code;

	/** User context pointer value from odp_ml_compl_param_t */
	void *user_ptr;

} odp_ml_load_result_t;

/**
 * ML completion parameters
 *
 * Use odp_ml_compl_param_init() to initialize the structure to its default values.
 */
typedef struct odp_ml_compl_param_t {
	/**
	 * Completion mode
	 *
	 * The selected completion mode defines which other parameters are used. When
	 * #ODP_ML_COMPL_MODE_EVENT mode is selected, 'event' and 'queue' must have valid values
	 * but value of 'compl_id' is ignored, or vice versa when #ODP_ML_COMPL_MODE_POLL mode is
	 * selected.
	 */
	odp_ml_compl_mode_t mode;

	/**
	 * Completion event
	 *
	 * Event to be enqueued by ML offload to the completion queue when ML operation
	 * is complete. Event type must be ODP_EVENT_ML_COMPL. ML offload sets the subtype of
	 * the event to ODP_EVENT_ML_COMPL_LOAD or ODP_EVENT_ML_COMPL_RUN based on the completed
	 * operation.
	 */
	odp_event_t event;

	/**
	 * Completion queue
	 *
	 * Destination queue for the completion event.
	 */
	odp_queue_t queue;

	/**
	 * Completion identifier
	 *
	 * When completion mode is #ODP_ML_COMPL_MODE_POLL, ML operation completion status is
	 * reported through this completion identifier. The value passed here is used in
	 * a following status call to check model load, unload, or inference completion
	 * (see e.g. odp_ml_model_load_status()).
	 *
	 * Application selects a value between 0 and max_compl_id defined in model creation
	 * parameters (see odp_ml_model_param_t). Only single ML operation (per model) may be
	 * started with the same identifier value at a time. A value may be reused for the next
	 * ML operation only after the previous operation is complete.
	 */
	uint32_t compl_id;

	/**
	 * User defined context pointer
	 *
	 * ODP implementation does not refer to the pointer, but just copies it to the result.
	 * For example, application may use this pointer to link a received completion event
	 * to the originating model run request and its input / output data. The default value
	 * is NULL.
	 */
	void *user_ptr;

} odp_ml_compl_param_t;

/** Model input / output data segment */
typedef struct odp_ml_data_seg_t {
	/** Segment start address */
	void *addr;

	/** Segment size in bytes */
	uint64_t size;

} odp_ml_data_seg_t;

/** Model input / output data for a model inference run */
typedef struct odp_ml_data_t {
	/**
	 * Number of input data segments
	 *
	 * Number of elements in 'input_seg' array (at least one per input).
	 */
	uint32_t num_input_seg;

	/**
	 * Number of output data segments
	 *
	 * Number of elements in 'output_seg' array (at least one per output).
	 */
	uint32_t num_output_seg;

	/**
	 * Model input data segments
	 *
	 * Points to an array of data segment descriptors for model input data. Each segment
	 * (odp_ml_data_seg_t) specifies data for one input only. Multiple consecutive segments may
	 * be used to specify data for the same input. Sum of those segment sizes must match data
	 * size of the input. Inputs are defined in the same order which odp_ml_model_input_info()
	 * reports those.
	 *
	 * Input data segments may overlap in memory.
	 */
	odp_ml_data_seg_t *input_seg;

	/**
	 * Model output data segments
	 *
	 * Points to an array of data segment descriptors for model output data. Each segment
	 * (odp_ml_data_seg_t) specifies data buffer space for one output only. Multiple
	 * consecutive segments may be used to specify buffer space for the same output.
	 * Sum of those segment sizes must match data size of the output. Outputs are defined
	 * in the same order which odp_ml_model_output_info() reports those.
	 *
	 * An output data segment must not overlap with any other (input or output) segment
	 * in memory.
	 */
	odp_ml_data_seg_t *output_seg;

} odp_ml_data_t;

/**
 * Parameters for model run
 *
 * Use odp_ml_run_param_init() to initialize the structure to its default values.
 */
typedef struct odp_ml_run_param_t {
	/**
	 * Batch size
	 *
	 * Batch size for all model inputs and outputs that have #ODP_ML_SHAPE_BATCH shape type.
	 * The default value is 0.
	 */
	uint32_t batch_size;

	/**
	 * Model run results
	 *
	 * Points to a result structure for model run result output. Results are output only
	 * in synchronous mode (#ODP_ML_COMPL_MODE_SYNC). The pointer value is ignored in
	 * asynchronous modes. Use NULL when results are not required. The default value is NULL.
	 */
	odp_ml_run_result_t *result;

} odp_ml_run_param_t;

/**
 * ML extra statistics counter information
 */
typedef struct odp_ml_extra_stat_info_t {
	/** Name of the statistics counter */
	char name[ODP_ML_EXTRA_STAT_NAME_LEN];

} odp_ml_extra_stat_info_t;

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

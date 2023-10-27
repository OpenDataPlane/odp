/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Nokia
 * Copyright (c) 2021 Marvell
 */

/**
 * @file
 *
 * ODP Machine Learning (ML) offload
 */

#ifndef ODP_API_SPEC_ML_H_
#define ODP_API_SPEC_ML_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/event_types.h>
#include <odp/api/ml_types.h>
#include <odp/api/pool_types.h>
#include <odp/api/std_types.h>

/**
 * @addtogroup odp_ml
 * Machine Learning (ML) offload
 * @{
 *
 * <b> ML API call sequence </b>
 *
 * Before ML offload can be used, it must be configured with an odp_ml_config() call. An application
 * fills in configuration parameters to describe its intended ML offload usage. The parameter
 * values may help ODP implementation to optimize memory and other HW resource usage. The
 * application may use odp_ml_capability() to check ML capabilities both before and after the
 * configuration step.
 *
 * After configuration, an ML model binary is passed with other parameters to odp_ml_model_create()
 * call which checks and prepares the model for usage. The application may use odp_ml_model_info(),
 * odp_ml_model_input_info() and odp_ml_model_output_info() calls to check model input and output
 * data formats. Before the application can use the model for inference, it loads the model with
 * an odp_ml_model_load() or odp_ml_model_load_start() call. After a successful load, the
 * application may use e.g. odp_ml_run() or odp_ml_run_start() to perform inferences.
 *
 * When all previously started inference operations are complete, application uses
 * odp_ml_model_unload() or odp_ml_model_unload_start() to unload the model. After a successful
 * unload, the model may be destroyed with an odp_ml_model_destroy() call, or loaded again.
 *
 * <b> Completion identifiers </b>
 *
 * Completion identifiers are used with ML operations in asynchronous poll mode
 * (#ODP_ML_COMPL_MODE_POLL). Application declares the maximum identifier value it will
 * use per model with odp_ml_model_param_t.max_compl_id parameter. It cannot exceed
 * the implementation capability of odp_ml_capability_t.max_compl_id. Completion identifier
 * values are model specific. The same value can be used simultaneously with two different
 * models, but cannot be used simultaneously in two ML operations on the same model. A value may be
 * reused for the next ML operation (on the same model) only after the previous operation is
 * complete. Within those limitations, application may use/reuse completion identifier
 * values from 0 to max_compl_id range freely.
 */

/**
 * Query ML capabilities
 *
 * Outputs ML capabilities on success. Use this capability call to check ML offload implementation
 * limits and its support of various ML API features. When ML offload is not available,
 * odp_ml_capability_t.max_models is zero.
 *
 * @param[out] capa     Pointer to a capability structure for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_ml_capability(odp_ml_capability_t *capa);

/**
 * Initialize ML configuration parameters
 *
 * Initialize an odp_ml_config_t to its default values.
 *
 * @param[out] config   Configuration structure to be initialized
 */
void odp_ml_config_init(odp_ml_config_t *config);

/**
 * Configure ML offload
 *
 * Initializes and configures ML offload according to the configuration parameters. This function
 * must be called only once and before any ML resources are created. Use odp_ml_capability() to
 * query configuration capabilities and odp_ml_config_init() to initialize configuration
 * parameters into their default values.
 *
 * @param config        ML configuration parameters
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_ml_config(const odp_ml_config_t *config);

/**
 * Initialize ML model parameters
 *
 * Initialize an odp_ml_model_param_t to its default values.
 *
 * @param[out] param    Parameters structure to be initialized
 */
void odp_ml_model_param_init(odp_ml_model_param_t *param);

/**
 * Create an ML model
 *
 * Creates an ML model according to the parameters. Use odp_ml_model_param_init() to initialize
 * parameters into their default values. The use of model name is optional. Unique names are not
 * required. However, odp_ml_model_lookup() returns only a single matching model. Maximum name
 * string length is #ODP_ML_MODEL_NAME_LEN.
 *
 * The call copies the model binary and prepares it for loading. Application may free memory
 * buffers pointed by the parameters when the call returns. Use odp_ml_model_load()
 * or odp_ml_model_load_start() to load the model. A model is ready for inference runs
 * (see e.g. odp_ml_run()) after it has been loaded successfully.
 *
 * When model metadata misses some details of model input / output data format, user can
 * pass those with odp_ml_model_param_t.extra_info. Some ODP implementations may define
 * implementation specific extra parameters (e.g. hints about HW resource usage), user can pass
 * those with odp_ml_model_param_t.extra_param when applicable.
 *
 * @param name          Name of the model, or NULL
 * @param param         ML model parameters
 *
 * @return ML model handle on success
 * @retval ODP_ML_MODEL_INVALID on failure
 */
odp_ml_model_t odp_ml_model_create(const char *name, const odp_ml_model_param_t *param);

/**
 * Destroy an ML model
 *
 * Destroys a model and releases the resources reserved for it. If the model has been loaded, it
 * must be unloaded (see odp_ml_model_unload() or odp_ml_model_unload_start()) prior to calling
 * this function.
 *
 * @param model         ML model to be destroyed
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_ml_model_destroy(odp_ml_model_t model);

/**
 * Find a model by name
 *
 * @param name          Name of the model
 *
 * @return Handle of the first matching ML model
 * @retval ODP_ML_MODEL_INVALID Model could not be found
 */
odp_ml_model_t odp_ml_model_lookup(const char *name);

/**
 * Load ML model
 *
 * Loads ML model in synchronous mode. When the call returns, load is complete and the model is
 * ready for inference requests. A loaded model must be unloaded before it can be destroyed.
 * The same model can be loaded and unloaded multiple times before being destroyed.
 *
 * The call optionally outputs results. Use NULL as 'result' pointer if results are not required.
 *
 * Application should not try to keep loaded more than configured number of models
 * (odp_ml_config_t.max_models_loaded). Check ML capabilities for maximum number of loaded
 * models (odp_ml_capability_t.max_models_loaded) and support of load completion modes
 * (odp_ml_capability_t.load).
 *
 * @param model         ML model to be loaded
 * @param[out] result   Pointer to load result structure for output, or NULL
 *
 * @retval  0 Model load was successful
 * @retval <0 on failure
 */
int odp_ml_model_load(odp_ml_model_t model, odp_ml_load_result_t *result);

/**
 * Start asynchronous model load
 *
 * Otherwise like odp_ml_model_load(), but loads the model asynchronously. A successful call
 * requests the model to be loaded, but does not wait for load completion. Completion parameters
 * are used to select if load completion is reported in poll (#ODP_ML_COMPL_MODE_POLL) or event
 * (#ODP_ML_COMPL_MODE_EVENT) mode. For poll mode, odp_ml_model_load_status() is called to check
 * for completion. For event mode, ML offload sends the completion event into the completion
 * queue when the load is complete. Use odp_ml_compl_param_init() to initialize completion
 * parameters into their default values.
 *
 * @param model         ML model to be loaded
 * @param compl_param   Completion parameters for load
 *
 * @retval  0 Model load started successfully
 * @retval <0 on failure
 */
int odp_ml_model_load_start(odp_ml_model_t model, const odp_ml_compl_param_t *compl_param);

/**
 * Check model load completion
 *
 * Checks if a previously started model load (in #ODP_ML_COMPL_MODE_POLL mode) has completed.
 * The completion identifier value from load operation completion parameters
 * (odp_ml_compl_param_t.compl_id) is passed as a parameter. It specifies the load operation to be
 * checked. Initially 0 is returned for all configured (but unused) completion identifier values.
 * An odp_ml_model_load_start() call clears the previous completion status of an identifier, and
 * this function returns 0 while the load is in progress. When the load is successfully
 * complete, >0 is returned. If the load completed with a failure, -1 is returned. The same
 * value is returned until the next start operation that reuses the identifier (with the same
 * model). The completion identifier may be reused only after >0 or -1 is returned.
 *
 * Optionally, outputs more detailed operation results into odp_ml_load_result_t structure.
 * Use NULL as 'result' pointer if these results are not required.
 *
 * @param model         ML model being loaded
 * @param compl_id      Completion identifier that was used in load start
 * @param[out] result   Pointer to load result structure for output, or NULL
 *
 * @retval  >0 Model load was successful
 * @retval   0 Model load has not finished
 * @retval  -1 Model load failed
 * @retval <-1 Failed to read completion status (e.g. bad handle)
 */
int odp_ml_model_load_status(odp_ml_model_t model, uint32_t compl_id, odp_ml_load_result_t *result);

/**
 * Unload ML model
 *
 * Unloads ML model in synchronous mode. All previously started inference operations must have been
 * completed before model unload is attempted. When the call returns, unload is complete and the
 * model is ready to be destroyed or loaded again.
 *
 * The call optionally outputs results. Use NULL as 'result' pointer if results are not required.
 *
 * @param model         ML model to be unloaded
 * @param[out] result   Pointer to load result structure for output, or NULL
 *
 * @retval  0 Model unload was successful
 * @retval <0 on failure
 */
int odp_ml_model_unload(odp_ml_model_t model, odp_ml_load_result_t *result);

/**
 * Start asynchronous model unload
 *
 * Otherwise like odp_ml_model_unload(), but unloads the model asynchronously. A successful call
 * requests the model to be unloaded, but does not wait for unload completion. Completion
 * parameters are used to select if unload completion is reported in poll (#ODP_ML_COMPL_MODE_POLL)
 * or event (#ODP_ML_COMPL_MODE_EVENT) mode. For poll mode, odp_ml_model_unload_status() is called
 * to check for completion. For event mode, ML offload sends the completion event into the
 * completion queue when the unload is complete. Use odp_ml_compl_param_init() to initialize
 * completion parameters into their default values.
 *
 * @param model         ML model to be unloaded
 * @param compl_param   Completion parameters for unload
 *
 * @retval  0 Model unload started successfully
 * @retval <0 on failure
 */
int odp_ml_model_unload_start(odp_ml_model_t model, const odp_ml_compl_param_t *compl_param);

/**
 * Check model unload completion
 *
 * Checks if a previously started model unload (in #ODP_ML_COMPL_MODE_POLL mode) has completed.
 * The completion identifier value from unload operation completion parameters
 * (odp_ml_compl_param_t.compl_id) is passed as a parameter. It specifies the unload operation to be
 * checked. Initially 0 is returned for all configured (but unused) completion identifier values.
 * An odp_ml_model_unload_start() call clears the previous completion status of an identifier, and
 * this function returns 0 while the unload is in progress. When the unload is successfully
 * complete, >0 is returned. If the unload completed with a failure, -1 is returned. The same
 * value is returned until the next start operation that reuses the identifier (with the same
 * model). The completion identifier may be reused only after >0 or -1 is returned.
 *
 * Optionally, outputs more detailed operation results into odp_ml_load_result_t structure.
 * Use NULL as 'result' pointer if these results are not required.
 *
 * @param model         ML model being unloaded
 * @param compl_id      Completion identifier that was used in unload start
 * @param[out] result   Pointer to load result structure for output, or NULL
 *
 * @retval  >0 Model unload was successful
 * @retval   0 Model unload has not finished
 * @retval  -1 Model unload failed
 * @retval <-1 Failed to read completion status (e.g. bad handle)
 */
int odp_ml_model_unload_status(odp_ml_model_t model, uint32_t compl_id,
			       odp_ml_load_result_t *result);

/**
 * Initialize model run parameters
 *
 * Initialize an odp_ml_run_param_t to its default values.
 *
 * @param[out] param    Model run parameters structure to be initialized
 */
void odp_ml_run_param_init(odp_ml_run_param_t *param);

/**
 * Run the model in synchronous mode
 *
 * Performs an ML inference operation using the model and input data pointed by the data descriptor.
 * A successful operation writes inference output data into memory buffers pointed by the data
 * descriptor. Input/output data buffers are described as an array of segment descriptors. Each
 * segment descriptor specifies a memory buffer used with only one model input/output. Multiple
 * subsequent descriptors may be used to specify segmented data for the same input/output.
 * When the model has multiple inputs/outputs, descriptor order in the array follows the model
 * input/output order reported by odp_ml_model_input_info() and odp_ml_model_output_info() calls.
 * All memory buffers for the first input/output are specified before any buffers for the second
 * input/output, and so on.
 *
 * When some model inputs/outputs have #ODP_ML_SHAPE_BATCH shape type, the batch size is specified
 * in run parameters (odp_ml_run_param_t.batch_size). The same batch size is used for all such
 * inputs/outputs. Application may request additional operation results by setting 'result' pointer
 * in run parameters. Use odp_ml_run_param_init() to initialize run parameters into their default
 * values. Default run parameter values are used when 'param' is NULL.
 *
 * Returns 1 when model run completed successfully. Returns 0 when the operation was not performed
 * due to ML offload resources being temporarily busy. Returns <0 on failure.
 *
 * @param model         ML model to be run
 * @param data          Model input/output data descriptor
 * @param param         Model run parameters, or NULL
 *
 * @retval  1 Model run completed successfully
 * @retval  0 Resources are busy and model was not run
 * @retval <0 on failure
 */
int odp_ml_run(odp_ml_model_t model, const odp_ml_data_t *data, const odp_ml_run_param_t *param);

/**
 * Run the model multiple times in synchronous mode
 *
 * Otherwise like odp_ml_run(), but runs the model 'num' times with different input/output
 * data buffers. Output data buffers of one ML inference operation must not overlap with
 * input/output data buffers of another one.
 *
 * Returns number of model runs successfully completed. When return value is less than 'num',
 * the remaining runs were not performed due to ML offload resources being temporarily busy.
 * Returns <0 on failure.
 *
 * @param model         ML model to be run
 * @param data          Array of model input/output data descriptors. The array has 'num' elements.
 * @param param         Array of model run parameters, or NULL. The array has 'num' elements
 *                      when used.
 * @param num           Number of model runs to perform
 *
 * @return  Number of model runs completed successfully (1 ... num)
 * @retval  0 Resources are busy and model was not run
 * @retval <0 on failure
 */
int odp_ml_run_multi(odp_ml_model_t model, const odp_ml_data_t data[],
		     const odp_ml_run_param_t param[], int num);

/**
 * Start model run in asynchronous mode
 *
 * Otherwise like odp_ml_run(), but runs the model asynchronously. A successful call
 * requests the model to be run, but does not wait for run completion. Completion parameters
 * select if run completion is reported in poll (#ODP_ML_COMPL_MODE_POLL) or event
 * (#ODP_ML_COMPL_MODE_EVENT) mode. For poll mode, odp_ml_run_status() is called to check
 * for completion. For event mode, ML offload sends the completion event into the completion queue
 * when the run is complete. Use odp_ml_compl_param_init() to initialize completion parameters
 * into their default values.
 *
 * Additional operation results (odp_ml_run_result_t) are available through the status call
 * (odp_ml_run_status()) or completion event (odp_ml_compl_run_result()). Results are
 * not output through the run parameters structure (i.e. odp_ml_run_param_t.result is ignored).
 *
 * Returns 1 when model run was started successfully. Returns 0 when model run was not started
 * due to ML offload resources being temporarily busy. Returns <0 on failure.
 *
 * @param model         ML model to be run
 * @param data          Model input/output data descriptor
 * @param compl_param   Completion parameters
 * @param run_param     Model run parameters, or NULL
 *
 * @retval  1 Model run started successfully
 * @retval  0 Resources are busy and model run was not started
 * @retval <0 on failure
 */
int odp_ml_run_start(odp_ml_model_t model, const odp_ml_data_t *data,
		     const odp_ml_compl_param_t *compl_param, const odp_ml_run_param_t *run_param);

/**
 * Start multiple model runs in asynchronous mode
 *
 * Otherwise like odp_ml_run_start(), but starts 'num' model runs with different input/output
 * data buffers. Output data buffers of one ML inference operation must not overlap with
 * input/output data buffers of another one.
 *
 * Returns number of model runs started successfully. When return value is less than 'num',
 * the remaining runs were not started due to ML offload resources being temporarily busy.
 * Returns <0 on failure.
 *
 * @param model         ML model to be run
 * @param data          Array of model input/output data descriptors. The array has 'num' elements.
 * @param compl_param   Array of completion parameters. The array has 'num' elements.
 * @param run_param     Array of model run parameters, or NULL. The array has 'num' elements
 *                      when used.
 * @param num           Number of model runs to start
 *
 * @return  Number of model runs started successfully (1 ... num)
 * @retval  0 Resources are busy and model runs were not started
 * @retval <0 on failure
 */
int odp_ml_run_start_multi(odp_ml_model_t model, const odp_ml_data_t data[],
			   const odp_ml_compl_param_t compl_param[],
			   const odp_ml_run_param_t run_param[], int num);

/**
 * Check model run completion
 *
 * Checks if a previously started model run (in #ODP_ML_COMPL_MODE_POLL mode) has completed.
 * The completion identifier value from run operation completion parameters
 * (odp_ml_compl_param_t.compl_id) is passed as a parameter. It specifies the run operation to be
 * checked. Initially 0 is returned for all configured (but unused) completion identifier values.
 * An odp_ml_run_start() call clears the previous completion status of an identifier, and
 * this function returns 0 while the run is in progress. When the run is successfully
 * complete, >0 is returned. If the run completed with a failure, -1 is returned. The same
 * value is returned until the next start operation that reuses the identifier (with the same
 * model). The completion identifier may be reused only after >0 or -1 is returned.
 *
 * Optionally, outputs more detailed operation results into odp_ml_run_result_t structure.
 * Use NULL as 'result' pointer if these results are not required.
 *
 * @param model         ML model running
 * @param compl_id      Completion identifier that was used in run start
 * @param[out] result   Pointer to run result structure for output, or NULL
 *
 * @retval  >0 Model run was successful
 * @retval   0 Model run has not finished
 * @retval  -1 Model run failed
 * @retval <-1 Failed to read completion status (e.g. bad handle)
 */
int odp_ml_run_status(odp_ml_model_t model, uint32_t compl_id, odp_ml_run_result_t *result);

/**
 * Initialize ML completion event pool parameters
 *
 * Initialize an odp_ml_compl_pool_param_t to its default values.
 *
 * @param[out] param    Parameter structure to be initialized
 */
void odp_ml_compl_pool_param_init(odp_ml_compl_pool_param_t *param);

/**
 * Create ML completion event pool
 *
 * Creates a pool of ML completion events (ODP_EVENT_ML_COMPL). Pool type is ODP_POOL_ML_COMPL.
 * The use of pool name is optional. Unique names are not required. However, odp_pool_lookup()
 * returns only a single matching pool. Use odp_ml_compl_pool_param_init() to initialize pool
 * parameters into their default values. Parameters values must not exceed pool capabilities
 * (see odp_ml_compl_pool_capability_t).
 *
 * @param name          Name of the pool or NULL. Maximum string length is #ODP_POOL_NAME_LEN.
 * @param param         Pool parameters
 *
 * @return Pool handle on success
 * @retval ODP_POOL_INVALID on failure
 */
odp_pool_t odp_ml_compl_pool_create(const char *name, const odp_ml_compl_pool_param_t *param);

/**
 * Allocate ML completion event
 *
 * Allocates an ML completion event from a pool. The pool must have been created with
 * odp_ml_compl_pool_create() call. All completion event metadata are set to their default values.
 *
 * @param pool          ML completion event pool
 *
 * @return ML completion event handle
 * @retval ODP_ML_COMPL_INVALID  Completion event could not be allocated
 */
odp_ml_compl_t odp_ml_compl_alloc(odp_pool_t pool);

/**
 * Free ML completion event
 *
 * Frees an ML completion event into the pool it was allocated from.
 *
 * @param ml_compl      ML completion event handle
 */
void odp_ml_compl_free(odp_ml_compl_t ml_compl);

/**
 * Check ML model run results from completion event
 *
 * Reads model run results from an ML completion event (ODP_EVENT_ML_COMPL). The event indicates
 * completion of a previously started inference operation. Subtype of the completion event must be
 * ODP_EVENT_ML_COMPL_RUN. Function return value indicates if the model run succeeded or failed.
 * Additionally, outputs more detailed results into the provided odp_ml_run_result_t
 * structure. Use NULL as 'result' pointer if those results are not required.
 *
 * @param ml_compl      ML completion event (subtype ODP_EVENT_ML_COMPL_RUN)
 * @param[out] result   Pointer to ML run result structure for output, or NULL.
 *
 * @retval   0 Model run was successful
 * @retval  -1 Model run failed
 * @retval <-1 Failed to read results from the event (e.g. bad handle)
 */
int odp_ml_compl_run_result(odp_ml_compl_t ml_compl, odp_ml_run_result_t *result);

/**
 * Check ML model load / unload results from completion event
 *
 * Reads model load / unload results from an ML completion event (ODP_EVENT_ML_COMPL). The event
 * indicates completion of a previously started model load / unload operation. Subtype of the
 * completion event must be ODP_EVENT_ML_COMPL_LOAD. Function return value indicates if the model
 * load / unload succeeded or failed. Additionally, outputs more detailed results into the provided
 * odp_ml_load_result_t structure. Use NULL as 'result' pointer if those results are not required.
 *
 * @param ml_compl      ML completion event (subtype ODP_EVENT_ML_COMPL_LOAD)
 * @param[out] result   Pointer to model load / unload result structure for output, or NULL.
 *
 * @retval   0 Model load / unload was successful
 * @retval  -1 Model load / unload failed
 * @retval <-1 Failed to read results from the event (e.g. bad handle)
 */
int odp_ml_compl_load_result(odp_ml_compl_t ml_compl, odp_ml_load_result_t *result);

/**
 * ML completion event user area
 *
 * Returns pointer to the user area associated with the completion event. Size of the area is
 * fixed and defined in pool parameters.
 *
 * @param ml_compl      ML completion event
  *
 * @return       Pointer to the user area of the completion event
 * @retval NULL  The completion event does not have user area
 */
void *odp_ml_compl_user_area(odp_ml_compl_t ml_compl);

/**
 * Convert event to ML completion event
 *
 * Converts an ODP_EVENT_ML_COMPL type event to an ML completion event.
 *
 * @param event         Event handle
 *
 * @return ML completion event handle
 */
odp_ml_compl_t odp_ml_compl_from_event(odp_event_t event);

/**
 * Convert ML completion event to event
 *
 * @param ml_compl      ML completion event handle
 *
 * @return Event handle
 */
odp_event_t odp_ml_compl_to_event(odp_ml_compl_t ml_compl);

/**
 * Convert ML completion event handle to a uint64_t value for debugging
 *
 * @param ml_compl      ML completion event handle to be converted
 *
 * @return uint64_t value that can be used for debugging (e.g. printed)
 */
uint64_t odp_ml_compl_to_u64(odp_ml_compl_t ml_compl);

/**
 * Initialize ML completion parameters
 *
 * Initialize an odp_ml_compl_param_t to its default values.
 *
 * @param[out] param    Address of parameters structure to be initialized
 */
void odp_ml_compl_param_init(odp_ml_compl_param_t *param);

/**
 * Retrieve model information
 *
 * Retrieve information about the model. Model information includes e.g. version numbers and
 * number of model inputs/outputs. Information about each input and output can be retrieved with
 * odp_ml_model_input_info() and odp_ml_model_output_info() calls.
 *
 * @param model         ML model handle
 * @param[out] info     Pointer to model information structure for output
 *
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_ml_model_info(odp_ml_model_t model, odp_ml_model_info_t *info);

/**
 * Retrieve model input information
 *
 * Writes information about each model input into the array. If there are more inputs than array
 * elements, writes only 'num' elements. Returns the number of model inputs on success, and zero on
 * failure. When 'num' is zero, ignores value of 'info' and returns normally.
 *
 * @param model         ML model handle
 * @param[out] info     Pointer to model input information array for output
 * @param num           Number of elements in the array
 *
 * @return Number of model inputs
 * @retval 0 on failure
 */
uint32_t odp_ml_model_input_info(odp_ml_model_t model, odp_ml_input_info_t info[], uint32_t num);

/**
 * Retrieve model output information
 *
 * Writes information about each model output into the array. If there are more outputs than array
 * elements, writes only 'num' elements. Returns the number of model outputs on success, and zero on
 * failure. When 'num' is zero, ignores value of 'info' and returns normally.
 *
 * @param model         ML model handle
 * @param[out] info     Pointer to model output information array for output
 * @param num           Number of elements in the array
 *
 * @return Number of model outputs
 * @retval 0 on failure
 */
uint32_t odp_ml_model_output_info(odp_ml_model_t model, odp_ml_output_info_t info[], uint32_t num);

/**
 * Convert ML model handle to a uint64_t value for debugging
 *
 * @param model         ML model handle
 *
 * @return uint64_t value that can be used for debugging (e.g. printed)
 */
uint64_t odp_ml_model_to_u64(odp_ml_model_t model);

/**
 * Print debug information about the model.
 *
 * Print implementation defined information about ML model to the ODP log. The information is
 * intended to be used for debugging.

 * @param model         ML model handle
 */
void odp_ml_model_print(odp_ml_model_t model);

/**
 * Print ML debug information
 *
 * Print implementation defined information about ML offload to the ODP log. The information is
 * intended to be used for debugging.
 */
void odp_ml_print(void);

/**
 * Extra statistics counter information
 *
 * Returns the number of extra statistics counters supported by the ML offload, and outputs
 * information (e.g. name) about those. Counters are implementation specific and maintained
 * per model. Statistics counting is enabled through model create parameters.
 *
 * When 'info' pointer is not NULL, fills in up to 'num' counter info structures. If the return
 * value is larger than 'num', there are more counters than the function was allowed to output.
 * If the return value N is less than 'num' (on success), only first N structures have been written.
 *
 * Info array elements are filled in the same order than odp_ml_model_extra_stats() outputs
 * counter values.
 *
 * @param model         ML model
 * @param[out] info     Pointer to extra statistics counter information array for output.
 *                      NULL may be used to query only the number of counters.
 * @param num           Number of elements in the array
 *
 * @return Number of extra statistics counters
 * @retval <0 on failure
 */
int odp_ml_model_extra_stat_info(odp_ml_model_t model, odp_ml_extra_stat_info_t info[], int num);

/**
 * Read extra statistics counter values
 *
 * Reads extra statistics counter values and returns the number of supported counters. Outputs
 * up to 'num' counter values into 'stats' array. If the return value is larger than 'num',
 * there are more counters than the function was allowed to output. If the return value N is less
 * than 'num' (on success), only first N counters have been written. The order of counters in
 * the array matches the counter information array order on odp_ml_model_extra_stat_info() output.
 *
 * @param model         ML model
 * @param[out] stats    Pointer to extra statistics counter array for output
 * @param num           Number of elements in the array
 *
 * @return Number of extra statistics counters
 * @retval <0 on failure
 */
int odp_ml_model_extra_stats(odp_ml_model_t model, uint64_t stats[], int num);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

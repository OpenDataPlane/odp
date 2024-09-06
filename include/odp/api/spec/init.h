/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2024 Nokia
 */

/**
 * @file
 */

#ifndef ODP_API_SPEC_INIT_H_
#define ODP_API_SPEC_INIT_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/hints.h>
#include <odp/api/thread_types.h>
#include <odp/api/cpumask.h>

/** @defgroup odp_initialization ODP INITIALIZATION
 *  ODP instance initialization and termination.
 *  @{
 */

/**
 * @typedef odp_instance_t
 * ODP instance ID.
 */

/**
 * Called from signal handler
 */
#define ODP_TERM_FROM_SIGH	((uint64_t)0x1)

/**
 * Last standard flag for abnormal terminate
 *
 * An implementation may use this for adding its own flags after the standard flags.
 */
#define ODP_TERM_LAST_FLAG ODP_TERM_FROM_SIGH

/**
 * ODP log level.
 */
typedef enum {
	/** Debug */
	ODP_LOG_DBG,

	/** Warning */
	ODP_LOG_WARN,

	/** Error */
	ODP_LOG_ERR,

	/** Unimplemented */
	ODP_LOG_UNIMPLEMENTED,

	/** Abort */
	ODP_LOG_ABORT,

	/** Print */
	ODP_LOG_PRINT

} odp_log_level_t;

/**
 * ODP log function
 *
 * Instead of direct prints to stdout/stderr all logging in an ODP
 * implementation should be done via this function or its wrappers.
 *
 * The application can provide this function to the ODP implementation in two
 * ways:
 *
 * - A callback passed in via in odp_init_t and odp_init_global()
 * - By overriding the ODP implementation default log function
 * odp_override_log().
 *
 * @warning The latter option is less portable and GNU linker dependent
 * (utilizes function attribute "weak"). If both are defined, the odp_init_t
 * function pointer has priority over the override function.
 *
 * @param level   Log level
 * @param fmt     printf-style message format
 *
 * @return The number of characters logged on success
 * @retval <0 on failure
 */
int odp_override_log(odp_log_level_t level, const char *fmt, ...) ODP_PRINTF_FORMAT(2, 3);

/**
 * ODP abort function
 *
 * Instead of directly calling abort, all abort calls in the implementation
 * should be done via this function or its wrappers.
 *
 * The application can provide this function to the ODP implementation in two
 * ways:
 *
 * - A callback passed in via odp_init_t and odp_init_global()
 * - By overriding the ODP implementation default abort function
 *   odp_override_abort().
 *
 * The latter option is less portable and GNU linker dependent (utilizes function
 * attribute "weak"). If both are defined, the odp_init_t function pointer has
 * priority over the override function.
 *
 * Note that no ODP calls should be called in the abort function and the function
 * should not return.
 */
void odp_override_abort(void) ODP_NORETURN;

/** Replaceable logging function */
typedef int (*odp_log_func_t)(odp_log_level_t level, const char *fmt, ...) ODP_PRINTF_FORMAT(2, 3);

/** Replaceable abort function */
typedef void (*odp_abort_func_t)(void) ODP_NORETURN;

/**
 * Application memory model
 */
typedef enum {
	/** Thread memory model: by default all memory is shareable between
	 *  threads.
	 *
	 *  Within a single ODP instance all ODP handles and pointers to ODP
	 *  allocated data may be shared amongst threads independent of data
	 *  allocation time (e.g. before or after thread creation). */
	ODP_MEM_MODEL_THREAD = 0,

	/** Process memory model: by default all memory is not shareable between
	 *  processes.
	 *
	 *  Within a single ODP instance all ODP handles and pointers to ODP
	 *  allocated data (excluding non-single VA SHM blocks) may be shared
	 *  amongst processes independent of data allocation time (e.g. before
	 *  or after fork).
	 *
	 * @see ODP_SHM_SINGLE_VA
	 */
	ODP_MEM_MODEL_PROCESS

} odp_mem_model_t;

/**
 * Global initialization parameters
 *
 * These parameters may be used at global initialization time to configure and
 * optimize ODP implementation to match the intended usage. Application
 * specifies maximum resource usage. Implementation may round up resource
 * reservations as needed. Initialization function returns a failure if resource
 * requirements are too high. Init parameters may be used also to override
 * logging and abort functions.
 *
 * Use odp_init_param_init() to initialize the parameters into their default
 * values. Unused parameters are left to default values.
 */
typedef struct odp_init_t {
	/** Maximum number of worker threads the user will run concurrently.
	    Valid range is from 0 to platform specific maximum. Set both
	    num_worker and num_control to zero for default number of threads. */
	int num_worker;

	/** Maximum number of control threads the user will run concurrently.
	    Valid range is from 0 to platform specific maximum. Set both
	    num_worker and num_control to zero for default number of threads. */
	int num_control;

	/** Pointer to bit mask mapping CPUs available to this ODP instance
	    for running worker threads.
	    Initialize to a NULL pointer to use default CPU mapping.
	    When the mask is defined, odp_cpumask_default_worker()
	    uses it instead of returning a default mask.
	    Applications code should not access this cpumask directly.
	    Valid range of CPUs and optimal CPU selection
	    are platform specific, but generally it is recommended that:
		* worker CPUs are dedicated to run only ODP worker threads
		  (one thread per CPU)
		* worker and control masks do not overlap
		* different ODP instances do not specify overlapping
		  worker masks
	 */
	const odp_cpumask_t *worker_cpus;

	/** Pointer to bit mask mapping CPUs available to this ODP instance
	    for running control threads.
	    Initialize to a NULL pointer to use default CPU mapping.
	    When the mask is defined, odp_cpumask_default_control()
	    uses it instead of returning a default mask.
	    Applications code should not access this cpumask directly.
	    Valid range of CPUs and optimal CPU selection
	    are platform specific, but generally it is recommended that
	    worker and control masks do not overlap.
	 */
	const odp_cpumask_t *control_cpus;

	/** Replacement for the default log fn */
	odp_log_func_t log_fn;

	/** Replacement for the default abort fn */
	odp_abort_func_t abort_fn;

	/** Unused features. These are hints to the ODP implementation that
	 * the application will not use any APIs associated with these
	 * features. Implementations may use this information to provide
	 * optimized behavior. Results are undefined if applications assert
	 * that a feature will not be used and it is used anyway.
	 */
	odp_feature_t not_used;

	/** Application memory model. The main application thread has to call
	 *  odp_init_global() and odp_init_local() before creating threads that
	 *  share ODP data. The default value is ODP_MEM_MODEL_THREAD.
	 */
	odp_mem_model_t mem_model;

	/** Shared memory parameters */
	struct {
		/** Maximum memory usage in bytes. This is the maximum
		 *  amount of shared memory that application will reserve
		 *  concurrently. Use 0 when not set. Default value is 0.
		 */
		uint64_t max_memory;
	} shm;

} odp_init_t;

/**
 * Initialize the odp_init_t to default values for all fields
 *
 * @param[out] param Address of the odp_init_t to be initialized
 */
void odp_init_param_init(odp_init_t *param);

/**
 * @typedef odp_platform_init_t
 * ODP platform initialization data
 *
 * @note ODP API does nothing with this data. It is the underlying
 * implementation that requires it and any data passed here is not portable.
 * It is required that the application takes care of identifying and
 * passing any required platform specific data.
 */

/**
 * Global ODP initialization
 *
 * An ODP instance is created with an odp_init_global() call. By default, each
 * thread of the instance must call odp_init_local() before calling any other
 * ODP API functions. Exceptions to this are functions that are needed for
 * setting up parameters for odp_init_global() and odp_init_local() calls, and
 * some other functions that may be convenient before initialization.
 * - odp_init_param_init()
 * - odp_cpumask_zero(), odp_cpumask_set(), etc functions to format
 *   odp_cpumask_t. However, these cpumask functions are excluded as their
 *   behaviour depend on global initialization parameters:
 *   odp_cpumask_default_worker(), odp_cpumask_default_control() and
 *   odp_cpumask_all_available()
 * - odp_log_fn_get()
 *
 * A successful odp_init_global() call outputs a handle for the new instance.
 * The handle is used in other initialization and termination calls.
 * For a graceful termination, odp_term_local() must be called first on each
 * thread and then odp_term_global() only once.
 *
 * When user provides configuration parameters, the platform may configure and
 * optimize the instance to match user requirements. A failure is returned if
 * requirements cannot be met.
 *
 * Configuration parameters are divided into standard and platform specific
 * parts. Standard parameters are supported by any ODP platform, where as
 * platform specific parameters are defined outside of the ODP API
 * specification. In addition to 'platform_params' there may be other platform
 * specific configuration options available (e.g. environmental variables or
 * a configuration file), but when the application passes 'platform_params',
 * it should always supersede any other configuration method.
 *
 * @param[out] instance   Instance handle pointer for output
 * @param      params     Standard configuration parameters for the instance.
 *                        Use NULL to set all parameters to their defaults.
 * @param platform_params Platform specific configuration parameters.
 *                        The definition and usage is platform specific.
 *                        Use NULL to set all parameters to their defaults.
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_init_local(), odp_term_global(), odp_init_param_init()
 */
int odp_init_global(odp_instance_t *instance,
		    const odp_init_t *params,
		    const odp_platform_init_t *platform_params);

/**
 * Thread local ODP initialization
 *
 * All threads must call this function before calling any other ODP API
 * functions. See odp_init_global() documentation for exceptions to this rule.
 * Global initialization (odp_init_global()) must have completed prior calling
 * this function.
 *
 * The instance parameter specifies which ODP instance the thread joins.
 * A thread may only join a single ODP instance at a time. The thread
 * type parameter indicates if the thread does most part of application
 * processing (ODP_THREAD_WORKER), or if it performs mostly background
 * tasks (ODP_THREAD_CONTROL).
 *
 * @param instance        Instance handle
 * @param thr_type        Thread type
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_init_global(), odp_term_local()
 */
int odp_init_local(odp_instance_t instance, odp_thread_type_t thr_type);

/**
 * Thread local ODP termination
 *
 * This function is the second to final ODP call made when terminating
 * an ODP application in a controlled way. It cannot handle exceptional
 * circumstances. It is recommended that all ODP resources are freed before
 * the last thread (of the instance) calls this function. This helps ODP
 * to avoid memory and other resource leaks.
 *
 * odp_term_global() may be called only after all threads of the instance have
 * executed odp_term_local(). To simplify synchronization between threads
 * a return value identifies which one is the last thread of an instance.
 *
 * @retval 1 on success and more ODP threads exist
 * @retval 0 on success and this is the last ODP thread
 * @retval <0 on failure
 *
 * @see odp_init_local(), odp_term_global()
 */
int odp_term_local(void);

/**
 * Global ODP termination
 *
 * This function is the final ODP call made when terminating an ODP application
 * in a controlled way. It cannot handle exceptional circumstances.
 *
 * This function must be called only after all threads of the instance have
 * executed odp_term_local().
 *
 * @param instance        Instance handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_init_global(), odp_term_local()
 */
int odp_term_global(odp_instance_t instance);

/**
 * Abnormal ODP termination after a non-recoverable error
 *
 * Application may call this function to terminate an ODP instance after facing
 * a non-recoverable error. Depending on the implementation, this function may
 * attempt to dump stack and other memory areas, clean up and stop HW
 * operations and/or perform other actions helpful in postmortem analysis.
 * Depending on the nature of the error resulting in the abnormal termination,
 * these actions may partially or completely fail. Flags (ODP_TERM_*) parameter
 * can be used to control and data parameter can be used to pass additional
 * flag-specific information to the termination process. Implementation
 * specific flags with implementation specific data may also exist, see from
 * implementation documentation how those should be utilized.
 *
 * Some coordination across threads is required when abnormally terminating, if
 * other threads continue calling ODP functions during or after termination,
 * their operation is most likely affected.
 *
 * When the function returns, the ODP instance has been destroyed either
 * completely or partially. Application must not attempt to call any ODP
 * functions during its remaining lifetime, but terminate as soon as feasible.
 *
 * @param instance        Instance handle
 * @param flags           A bit mask of control flags (ODP_TERM_*), set to 0
 *                        when no flags
 * @param data            Additional data, set to NULL when no additional data
 *
 * @retval 0 on all actions successfully performed
 * @retval <0 on failure to perform all actions, implementation specific status
 *         code for debugging
 */
int odp_term_abnormal(odp_instance_t instance, uint64_t flags, void *data);

/**
 * Set thread specific log function
 *
 * By default, all ODP log writes use the global log function, which may be set
 * as part of odp_init_t. Using this operation, an alternative ODP log function
 * may be set for the calling thread. When set, ODP uses the thread specific log
 * function for all log writes originating from ODP API calls made by the
 * calling thread. Setting the log function to NULL causes the calling thread to
 * use the global log function.
 *
 * @param func Log function
 */
void odp_log_thread_fn_set(odp_log_func_t func);

/**
 * Get current log function
 *
 * May be called even if ODP is not initialized.
 *
 * Returns the function previously set by the calling thread via
 * odp_log_thread_fn_set(). If no thread specific log function has been set,
 * returns the log function specified in odp_init_global() parameters. If no log
 * function was specified, returns the default or override log function (see
 * odp_override_log()). Returns NULL if ODP is not initialized.
 *
 * @return Log function
 * @retval NULL ODP not initialized
 */
odp_log_func_t odp_log_fn_get(void);

/**
 * Get instance handle
 *
 * A successful call outputs the calling thread's ODP instance handle.
 *
 * @param[out] instance   Instance handle pointer for output
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_init_global(), odp_init_local()
 */
int odp_instance(odp_instance_t *instance);

/**
 * Get printable value for ODP instance handle
 *
 * @param instance        Handle to be converted for debugging
 *
 * @return uint64_t value that can be used to print/display this handle
 */
uint64_t odp_instance_to_u64(odp_instance_t instance);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

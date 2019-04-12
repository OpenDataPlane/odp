/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
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
#include <odp/api/feature.h>
#include <odp/api/thread.h>
#include <odp/api/cpumask.h>

/** @defgroup odp_initialization ODP INITIALIZATION
 *  Initialisation operations.
 *  @{
 */

/**
 * @typedef odp_instance_t
 * ODP instance ID.
 */

/**
 * ODP log level.
 */
typedef enum {
	ODP_LOG_DBG,
	ODP_LOG_ERR,
	ODP_LOG_UNIMPLEMENTED,
	ODP_LOG_ABORT,
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
int odp_override_log(odp_log_level_t level, const char *fmt, ...);

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
 * @warning The latter option is less portable and GNU linker dependent
 * (utilizes function attribute "weak"). If both are defined, the odp_init_t
 * function pointer has priority over the override function.
 *
 * @warning this function shall not return
 */
void odp_override_abort(void) ODP_NORETURN;

/** Replaceable logging function */
typedef int (*odp_log_func_t)(odp_log_level_t level, const char *fmt, ...);

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
 * setting up parameters for odp_init_global() and odp_init_local() calls:
 * - odp_init_param_init()
 * - odp_cpumask_zero(), odp_cpumask_set(), etc functions to format
 *   odp_cpumask_t. However, these cpumask functions are excluded as their
 *   behaviour depend on global initialization parameters:
 *   odp_cpumask_default_worker(), odp_cpumask_default_control() and
 *   odp_cpumask_all_available()
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
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

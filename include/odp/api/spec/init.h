/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP initialization.
 * ODP requires a global level init for the process and a local init per
 * thread before the other ODP APIs may be called.
 * - odp_init_global()
 * - odp_init_local()
 *
 * For a graceful termination the matching termination APIs exit
 * - odp_term_global()
 * - odp_term_local()
 */

#ifndef ODP_API_INIT_H_
#define ODP_API_INIT_H_
#include <odp/api/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/hints.h>
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
 * ODP initialization data
 *
 * Data that is required to initialize the ODP API with the
 * application specific data such as specifying a logging callback, the log
 * level etc.
 *
 * @note It is expected that all unassigned members are zero
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
} odp_init_t;

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
 * This function must be called once (per instance) before calling any other
 * ODP API functions. A successful call creates a new ODP instance into the
 * system and outputs a handle for it. The handle is used in other calls
 * (e.g. odp_init_local()) as a reference to the instance. When user provides
 * configuration parameters, the platform may configure and optimize the
 * instance to match user requirements.
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
 * @see odp_term_global()
 * @see odp_init_local() which is required per thread before use.
 */
int odp_init_global(odp_instance_t *instance,
		    const odp_init_t *params,
		    const odp_platform_init_t *platform_params);

/**
 * Global ODP termination
 *
 * This function is the final ODP call made when terminating
 * an ODP application in a controlled way. It cannot handle exceptional
 * circumstances. In general it calls the API modules terminate functions in
 * the reverse order to that which the module init functions were called
 * during odp_init_global().
 *
 * This function must be called only after all threads of the instance have
 * executed odp_term_local(). To simplify synchronization between threads
 * odp_term_local() identifies which one is the last thread of an instance.
 *
 * @param instance        Instance handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @warning The unwinding of HW resources to allow them to be reused without
 * reseting the device is a complex task that the application is expected to
 * coordinate. This api may have platform dependent implications.
 *
 * @see odp_init_global()
 * @see odp_term_local() which must have been called prior to this.
 */
int odp_term_global(odp_instance_t instance);

/**
 * Thread local ODP initialization
 *
 * All threads must call this function before calling any other ODP API
 * functions. The instance parameter specifies which ODP instance the thread
 * joins. A thread may be simultaneously part of single ODP instance only.
 *
 * @param instance        Instance handle
 * @param thr_type        Thread type
 *
 * @retval 0 on success
 * @retval <0 on failure
 *
 * @see odp_term_local()
 * @see odp_init_global() which must have been called prior to this.
 */
int odp_init_local(odp_instance_t instance, odp_thread_type_t thr_type);

/**
 * Thread local ODP termination
 *
 * This function is the second to final ODP call made when terminating
 * an ODP application in a controlled way. It cannot handle exceptional
 * circumstances. In general it calls the API modules per thread terminate
 * functions in the reverse order to that which the module init functions were
 * called during odp_init_local().
 *
 * @retval 1 on success and more ODP threads exist
 * @retval 0 on success and this is the last ODP thread
 * @retval <0 on failure
 *
 * @warning The unwinding of HW resources to allow them to be reused without
 * reseting the device is a complex task that the application is expected
 * to coordinate.
 *
 * @see odp_init_local()
 * @see odp_term_global() should be called by the last ODP thread before exit
 * of an application.
 */
int odp_term_local(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/api/visibility_end.h>
#endif

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

#ifndef ODP_INIT_H_
#define ODP_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif



#include <odp/std_types.h>

/** @defgroup odp_initialization ODP INITIALIZATION
 *  Initialisation operations.
 *  @{
 */

/**
 * ODP log level.
 */
typedef enum odp_log_level {
	ODP_LOG_DBG,
	ODP_LOG_ERR,
	ODP_LOG_UNIMPLEMENTED,
	ODP_LOG_ABORT,
	ODP_LOG_PRINT
} odp_log_level_e;

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
 * @param[in] level   Log level
 * @param[in] fmt     printf-style message format
 *
 * @return The number of characters logged if succeeded. Otherwise returns
 *         a negative number.
 */
int odp_override_log(odp_log_level_e level, const char *fmt, ...);


/** Replaceable logging function */
typedef int (*odp_log_func_t)(odp_log_level_e level, const char *fmt, ...);

/** ODP initialization data.
 * Data that is required to initialize the ODP API with the
 * application specific data such as specifying a logging callback, the log
 * level etc.
 *
 * @note it is expected that all unassigned members are zero
 */
typedef struct odp_init_t {
	odp_log_func_t log_fn; /**< Replacement for the default log fn */
} odp_init_t;

/** ODP platform initialization data.
 * @note ODP API does nothing with this data. It is the underlying
 * implementation that requires it and any data passed here is not portable.
 * It is required that the application takes care of identifying and
 * passing any required platform specific data.
 */

typedef struct odp_platform_init_t {
} odp_platform_init_t;


/**
 * Perform global ODP initialization.
 *
 * This function must be called once before calling any other ODP API
 * functions.
 *
 * @sa odp_term_global()
 * @sa odp_init_local() which is required per thread before use.
 *
 * @param[in] params Those parameters that are interpreted by the ODP API
 * @param[in] platform_params Those parameters that are passed without
 * interpretation by the ODP API to the implementation.
 *
 * @retval 0 if successful
 * @retval -1 on failure
 */
int odp_init_global(odp_init_t *params, odp_platform_init_t *platform_params);

/**
 * Terminate ODP session.
 *
 * This function is the final ODP call made when terminating
 * an ODP application in a controlled way. It cannot handle exceptional
 * circumstances.
 * In general it calls the API modules terminate functions in the reverse order
 * to that which the module init functions were called during odp_init_global()
 *
 * @note This function should be called by the last ODP thread. To simplify
 * synchronization between threads odp_term_local() indicates by its return
 * value if it was the last thread.
 *
 * @warning The unwinding of HW resources to allow them to be re used without reseting
 * the device is a complex task that the application is expected to coordinate.
 * This api may have  platform dependant implications.
 *
 * @sa odp_init_global()
 * @sa odp_term_local() which must have been called prior to this.
 *
 * @retval 0 if successful
 * @retval -1 on failure
 */
int odp_term_global(void);

/**
 * Perform thread local ODP initialization.
 *
 * All threads must call this function before calling
 * any other ODP API functions.
 *
 * @sa odp_term_local()
 * @sa odp_init_global() which must have been called prior to this.
 *
 * @retval 0 if successful
 * @retval -1 on failure
 */
int odp_init_local(void);


/**
 * Perform thread local ODP termination.
 *
 * This function is the second to final ODP call made when terminating
 * an ODP application in a controlled way. It cannot handle exceptional
 * circumstances.
 * In general it calls the API modules per thread terminate functions in the
 * reverse order to that which the module init functions were called during
 * odp_init_local()
 *
 * @sa odp_init_local()
 * @sa odp_term_global() should be called by the last ODP thread before exit
 * of an application.
 *
 * @warning The unwinding of HW resources to allow them to be re used without reseting
 * the device is a complex task that the application is expected to coordinate.
 *
 * @retval 1 if successful and more ODP thread exists
 * @retval 0 if successful and it was the last ODP thread
 * @retval -1 on failure
 */
int odp_term_local(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

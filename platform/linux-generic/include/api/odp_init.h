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



#include <odp_std_types.h>


/** @defgroup odp_initialization ODP INITIALIZATION
 *  Initialisation operations.
 *  @{
 */

/** ODP initialization data.
 * Data that is required to initialize the ODP API with the
 * application specific data such as specifying a logging callback, the log
 * level etc.
 */
typedef struct odp_init_t {
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
 * @retval 1 on failure
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
 * @warning The unwinding of HW resources to allow them to be re used without reseting
 * the device is a complex task that the application is expected to coordinate.
 * This api may have  platform dependant implications.
 *
 * @sa odp_init_global()
 * @sa odp_term_local() which must have been called prior to this.
 *
 * @retval 0 if successful
 * @retval 1 on failure
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
 * @retval 1 on failure
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
 * @sa odp_term_global() which is the final ODP call before exit of an application.
 *
 * @warning The unwinding of HW resources to allow them to be re used without reseting
 * the device is a complex task that the application is expected to coordinate.
 * All threads must call this function before calling
 * any other ODP API functions.
 *
 * @retval 0 if successful
 * @retval 1 on failure
 */
int odp_term_local(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

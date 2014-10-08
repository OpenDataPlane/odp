/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP initialization
 */

#ifndef ODP_INIT_H_
#define ODP_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif



#include <odp_std_types.h>



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
 * @param[in] params Those parameters that are interpreted by the ODP API
 * @param[in] platform_params Those parameters that are passed without
 * interpretation by the ODP API to the implementation.
 * @return 0 if successful
 */
int odp_init_global(odp_init_t *params, odp_platform_init_t *platform_params);

/**
 * Perform thread local ODP initialization.
 *
 * All threads must call this function before calling
 * any other ODP API functions.
 *
 * @return 0 if successful
 */
int odp_init_local(void);



#ifdef __cplusplus
}
#endif

#endif

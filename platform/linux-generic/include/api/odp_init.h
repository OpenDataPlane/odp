/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP initialisation
 */

#ifndef ODP_INIT_H_
#define ODP_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif



#include <odp_std_types.h>




/**
 * Perform global ODP initalisation.
 *
 * This function must be called once before calling
 * any other ODP API functions.
 *
 * @return 0 if successful
 */
int odp_init_global(void);


/**
 * Perform thread local ODP initalisation.
 *
 * All threads must call this function before calling
 * any other ODP API functions.
 * @param thr_id Thread id
 * @return 0 if successful
 */
int odp_init_local(int thr_id);



#ifdef __cplusplus
}
#endif

#endif

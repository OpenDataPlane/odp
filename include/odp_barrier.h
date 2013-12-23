/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP execution barriers
 */

#ifndef ODP_BARRIER_H_
#define ODP_BARRIER_H_

#ifdef __cplusplus
extern "C" {
#endif



#include <odp_std_types.h>
#include <odp_coremask.h>


/**
 * ODP execution barrier
 */
typedef struct odp_barrier_t {
	odp_coremask_t mask;
	int            num_cores;
	int            mode;

} odp_barrier_t;


/**
 * Init barrier with core mask
 *
 * @param barrier    Barrier
 * @param core_mask  Core mask
 */
void odp_barrier_init_mask(odp_barrier_t *barrier, odp_coremask_t *core_mask);


/**
 * Init barrier with number of cores
 *
 * @param barrier    Barrier
 * @param num_cores  Number of cores
 */
void odp_barrier_init_num(odp_barrier_t *barrier, int num_cores);


/**
 * Synchronise thread execution on barrier
 *
 * @param barrier    Barrier
 */
void odp_barrier_sync(odp_barrier_t *barrier);





#ifdef __cplusplus
}
#endif

#endif








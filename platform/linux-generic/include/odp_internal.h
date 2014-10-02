/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP HW system information
 */

#ifndef ODP_INTERNAL_H_
#define ODP_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif


int odp_system_info_init(void);

int odp_thread_init_global(void);
int odp_thread_init_local(void);

int odp_shm_init_global(void);
int odp_shm_init_local(void);

int odp_buffer_pool_init_global(void);

int odp_pktio_init_global(void);
int odp_pktio_init_local(void);

int odp_queue_init_global(void);

int odp_crypto_init_global(void);

int odp_schedule_init_global(void);
int odp_schedule_init_local(void);

int odp_timer_init_global(void);
int odp_timer_disarm_all(void);

#ifdef __cplusplus
}
#endif

#endif

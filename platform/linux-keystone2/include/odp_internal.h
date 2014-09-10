/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
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

#include <odp_state.h>

int odp_system_info_init(void);

void odp_thread_init_global(void);
void odp_thread_init_local(int thr_id);

int odp_shm_init_global(void);
int odp_shm_init_local(void);

int odp_buffer_pool_init_global(void);

int odp_pktio_init_global(void);

int odp_queue_init_global(void);

int odp_crypto_init_global(void);

int odp_schedule_init_global(void);
int odp_schedule_init_local(void);

int odp_timer_init_global(void);
int odp_timer_disarm_all(void);

int mcsdk_global_init(void);
int mcsdk_local_init(int thread_id);

#ifdef __cplusplus
}
#endif

#endif

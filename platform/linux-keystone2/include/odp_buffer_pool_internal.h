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
 * ODP buffer pool - internal header
 */

#ifndef ODP_BUFFER_POOL_INTERNAL_H_
#define ODP_BUFFER_POOL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_buffer_pool.h>

uint32_t _odp_pool_get_free_queue(odp_buffer_pool_t pool_id);

#ifdef __cplusplus
}
#endif

#endif

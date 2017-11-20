/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet IO pool
 */

#ifndef ODP_PACKET_IO_POOL_H_
#define ODP_PACKET_IO_POOL_H_

#ifdef __cplusplus
extern "C" {
#endif

int _odp_packet_io_pool_create(void);
int _odp_packet_io_pool_destroy(void);

#ifdef __cplusplus
}
#endif

#endif /* ODP_PACKET_IO_POOL_H_*/

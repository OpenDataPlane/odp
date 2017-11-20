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

#ifndef ODP_PACKET_IO_POOL_ACCESS_H_
#define ODP_PACKET_IO_POOL_ACCESS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/drv/shm.h>

/**
 * Packet IO operations data pool name
 */
#define ODP_PKTIO_OPS_DATA_POOL_NAME "ODP_PKTIO_OPS_DATA"

#define ODP_OPS_DATA_ALLOC(_size)					\
({									\
	odpdrv_shm_pool_t _pool;					\
	void *_ops_data = NULL;						\
									\
	_pool = odpdrv_shm_pool_lookup(ODP_PKTIO_OPS_DATA_POOL_NAME);	\
	if (_pool != ODPDRV_SHM_POOL_INVALID)				\
		_ops_data = odpdrv_shm_pool_alloc(_pool,		\
			ROUNDUP_CACHE_LINE(_size));			\
									\
	_ops_data;							\
})

#define ODP_OPS_DATA_FREE(_ops_data)					\
({									\
	odpdrv_shm_pool_t _pool;					\
	int _result = -1;						\
									\
	_pool = odpdrv_shm_pool_lookup(ODP_PKTIO_OPS_DATA_POOL_NAME);	\
	if (_pool != ODPDRV_SHM_POOL_INVALID) {				\
		odpdrv_shm_pool_free(_pool, _ops_data);			\
		_result = 0;						\
	}								\
	_result;							\
})

#ifdef __cplusplus
}
#endif

#endif /* ODP_PACKET_IO_POOL_ACCESS_H_*/

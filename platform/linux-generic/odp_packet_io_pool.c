/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_posix_extensions.h>
#include <odp/api/packet_io.h>
#include <odp/api/std_clib.h>
#include <odp/drv/shm.h>
#include "odp_packet_io_pool.h"
#include "odp_packet_io_pool_access.h"
#include "odp_debug_internal.h"

#define ODP_PKTIO_OPS_DATA_POOL_SIZE 160000

int _odp_packet_io_pool_create(void)
{
	odpdrv_shm_pool_t pktio_ops_pool;
	odpdrv_shm_pool_param_t pktio_ops_param;

	odp_memset(&pktio_ops_param, 0, sizeof(pktio_ops_param));
	pktio_ops_param.pool_size = ODP_PKTIO_OPS_DATA_POOL_SIZE;
	pktio_ops_param.min_alloc = 1;
	pktio_ops_param.max_alloc = ODP_PKTIO_OPS_DATA_POOL_SIZE;

	pktio_ops_pool = odpdrv_shm_pool_create(ODP_PKTIO_OPS_DATA_POOL_NAME,
						&pktio_ops_param);
	if (pktio_ops_pool == ODPDRV_SHM_POOL_INVALID) {
		ODP_ERR("error to pool_create pktio_ops pool\n");
		return -1;
	}

	return 0;
}

int _odp_packet_io_pool_destroy(void)
{
	odpdrv_shm_pool_t pktio_ops_pool;

	pktio_ops_pool = odpdrv_shm_pool_lookup(ODP_PKTIO_OPS_DATA_POOL_NAME);
	if (pktio_ops_pool == ODPDRV_SHM_POOL_INVALID) {
		ODP_ERR("error pool_lookup pktio_ops pool\n");
		return -1;
	}

	if (odpdrv_shm_pool_destroy(pktio_ops_pool)) {
		ODP_ERR("error pool_destroy pktio_ops pool\n");
		return -1;
	}

	return 0;
}

/* Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/autoheader_internal.h>
#include <odp_pool_internal.h>

extern const _odp_pool_mem_src_ops_t _odp_pool_dpdk_mem_src_ops;
extern const _odp_pool_mem_src_ops_t _odp_pool_sock_xdp_mem_src_ops;

/* List of available ODP packet pool memory source operations. Array must be NULL terminated */
const _odp_pool_mem_src_ops_t * const _odp_pool_mem_src_ops[] = {
#ifdef _ODP_PKTIO_DPDK
	&_odp_pool_dpdk_mem_src_ops,
#endif
#ifdef _ODP_PKTIO_XDP
	&_odp_pool_sock_xdp_mem_src_ops,
#endif
	NULL
};

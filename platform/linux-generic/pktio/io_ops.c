/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/autoheader_internal.h>
#include <odp_packet_io_internal.h>

/* Ops for all implementation of pktio.
 * Order matters. The first implementation to setup successfully
 * will be picked.
 * Array must be NULL terminated */
const pktio_if_ops_t * const _odp_pktio_if_ops[]  = {
	&_odp_loopback_pktio_ops,
#ifdef _ODP_PKTIO_DPDK
	&_odp_dpdk_pktio_ops,
#endif
#ifdef _ODP_PKTIO_XDP
	&_odp_sock_xdp_pktio_ops,
#endif
#ifdef _ODP_PKTIO_PCAP
	&_odp_pcap_pktio_ops,
#endif
	&_odp_ipc_pktio_ops,
	&_odp_tap_pktio_ops,
	&_odp_null_pktio_ops,
	&_odp_sock_mmap_pktio_ops,
	&_odp_sock_mmsg_pktio_ops,
	NULL
};

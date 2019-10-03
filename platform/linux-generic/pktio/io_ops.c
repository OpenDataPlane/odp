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
const pktio_if_ops_t * const pktio_if_ops[]  = {
	&loopback_pktio_ops,
#ifdef _ODP_PKTIO_DPDK
	&dpdk_pktio_ops,
#endif
#ifdef _ODP_PKTIO_NETMAP
	&netmap_pktio_ops,
#endif
#ifdef _ODP_PKTIO_PCAP
	&pcap_pktio_ops,
#endif
	&ipc_pktio_ops,
	&tap_pktio_ops,
	&null_pktio_ops,
	&sock_mmap_pktio_ops,
	&sock_mmsg_pktio_ops,
	NULL
};

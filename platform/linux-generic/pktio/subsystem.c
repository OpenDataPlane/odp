/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <config.h>

#include <odp_debug_internal.h>
#include <odp_packet_io_internal.h>

#define SUBSYSTEM_VERSION 0x00010000UL
ODP_SUBSYSTEM_DEFINE(pktio_ops, "packet IO operations", SUBSYSTEM_VERSION);

/* Instantiate init and term functions */
ODP_SUBSYSTEM_FOREACH_TEMPLATE(pktio_ops, init_global, ODP_ERR)
ODP_SUBSYSTEM_FOREACH_TEMPLATE(pktio_ops, init_local, ODP_ERR)
ODP_SUBSYSTEM_FOREACH_TEMPLATE(pktio_ops, term_global, ODP_ABORT)

/* Temporary variable to enable link modules,
 * will remove in Makefile scheme changes.
 */
#if defined(ODP_PKTIO_DPDK) && ODP_PKTIO_DPDK == 1
extern int enable_link_dpdk_pktio_ops;
#endif
#if defined(ODP_PKTIO_IPC) && ODP_PKTIO_IPC == 1
extern int enable_link_ipc_pktio_ops;
#endif
extern int enable_link_loopback_pktio_ops;
#if defined(ODP_NETMAP) && ODP_NETMAP == 1
extern int enable_link_netmap_pktio_ops;
#endif
#if defined(HAVE_PCAP) && HAVE_PCAP == 1
extern int enable_link_pcap_pktio_ops;
#endif
#if defined(ODP_PKTIO_SOCKET) && ODP_PKTIO_SOCKET == 1
extern int enable_link_socket_pktio_ops;
#endif
#if defined(ODP_PKTIO_SOCKET_MMAP) && ODP_PKTIO_SOCKET_MMAP == 1
extern int enable_link_socket_mmap_pktio_ops;
#endif
#if defined(ODP_PKTIO_TAP) && ODP_PKTIO_TAP == 1
extern int enable_link_tap_pktio_ops;
#endif
#if defined(_ODP_MDEV) && _ODP_MDEV == 1
extern int enable_link_cxgb4_pktio_ops;
extern int enable_link_i40e_pktio_ops;
#endif

ODP_SUBSYSTEM_CONSTRUCTOR(pktio_ops)
{
	odp_subsystem_constructor(pktio_ops);

	/* Further initialization per subsystem */

#if defined(ODP_PKTIO_DPDK) && ODP_PKTIO_DPDK == 1
	enable_link_dpdk_pktio_ops = 1;
#endif
#if defined(ODP_PKTIO_IPC) && ODP_PKTIO_IPC == 1
	enable_link_ipc_pktio_ops = 1;
#endif
	enable_link_loopback_pktio_ops = 1;
#if defined(ODP_NETMAP) && ODP_NETMAP == 1
	enable_link_netmap_pktio_ops = 1;
#endif
#if defined(HAVE_PCAP) && HAVE_PCAP == 1
	enable_link_pcap_pktio_ops = 1;
#endif
#if defined(ODP_PKTIO_SOCKET) && ODP_PKTIO_SOCKET == 1
	enable_link_socket_pktio_ops = 1;
#endif
#if defined(ODP_PKTIO_SOCKET_MMAP) && ODP_PKTIO_SOCKET_MMAP == 1
	enable_link_socket_mmap_pktio_ops = 1;
#endif
#if defined(ODP_PKTIO_TAP) && ODP_PKTIO_TAP == 1
	enable_link_tap_pktio_ops = 1;
#endif
#if defined(_ODP_MDEV) && _ODP_MDEV == 1
	enable_link_cxgb4_pktio_ops = 1;
	enable_link_i40e_pktio_ops = 1;
#endif
}

/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

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
#ifdef ODP_PKTIO_DPDK
extern int enable_link_dpdk_pktio_ops;
#endif
extern int enable_link_ipc_pktio_ops;
extern int enable_link_loopback_pktio_ops;
#ifdef ODP_NETMAP
extern int enable_link_netmap_pktio_ops;
#endif
#ifdef HAVE_PCAP
extern int enable_link_pcap_pktio_ops;
#endif
extern int enable_link_socket_pktio_ops;
extern int enable_link_socket_mmap_pktio_ops;
extern int enable_link_tap_pktio_ops;

ODP_SUBSYSTEM_CONSTRUCTOR(pktio_ops)
{
	odp_subsystem_constructor(pktio_ops);

	/* Further initialization per subsystem */

#ifdef ODP_PKTIO_DPDK
	enable_link_dpdk_pktio_ops = 1;
#endif
	enable_link_ipc_pktio_ops = 1;
	enable_link_loopback_pktio_ops = 1;
#ifdef ODP_NETMAP
	enable_link_netmap_pktio_ops = 1;
#endif
#ifdef HAVE_PCAP
	enable_link_pcap_pktio_ops = 1;
#endif
	enable_link_socket_pktio_ops = 1;
	enable_link_socket_mmap_pktio_ops = 1;
	enable_link_tap_pktio_ops = 1;
}

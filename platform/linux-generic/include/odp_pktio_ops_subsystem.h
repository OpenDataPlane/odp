/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_SUBSYSTEM_PKTIO_OPS_H
#define ODP_SUBSYSTEM_PKTIO_OPS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <module.h>
#include <odp/api/packet_io.h>

/* ODP packet IO operations subsystem declaration */
extern SUBSYSTEM(pktio_ops);

/* Subsystem APIs declarations */
SUBSYSTEM_API(pktio_ops, int, open, odp_pktio_t,
	      pktio_entry_t *, const char *, odp_pool_t);
SUBSYSTEM_API(pktio_ops, int, close, pktio_entry_t *);
SUBSYSTEM_API(pktio_ops, int, start, pktio_entry_t *);
SUBSYSTEM_API(pktio_ops, int, stop, pktio_entry_t *);
SUBSYSTEM_API(pktio_ops, int, stats, pktio_entry_t *,
	      odp_pktio_stats_t *stats);
SUBSYSTEM_API(pktio_ops, int, stats_reset, pktio_entry_t *);
SUBSYSTEM_API(pktio_ops, uint64_t, pktin_ts_res, pktio_entry_t *);
SUBSYSTEM_API(pktio_ops, odp_time_t, pktin_ts_from_ns,
	      pktio_entry_t *, uint64_t ns);
SUBSYSTEM_API(pktio_ops, int, recv, pktio_entry_t *,
	      int index, odp_packet_t packets[], int count);
SUBSYSTEM_API(pktio_ops, int, send, pktio_entry_t *,
	      int index, const odp_packet_t packets[], int count);
SUBSYSTEM_API(pktio_ops, uint32_t, mtu_get, pktio_entry_t *);
SUBSYSTEM_API(pktio_ops, int, promisc_mode_set,
	      pktio_entry_t *, int enable);
SUBSYSTEM_API(pktio_ops, int, promisc_mode_get, pktio_entry_t *);
SUBSYSTEM_API(pktio_ops, int, mac_get, pktio_entry_t *, void *);
SUBSYSTEM_API(pktio_ops, int, link_status, pktio_entry_t *);
SUBSYSTEM_API(pktio_ops, int, capability, pktio_entry_t *,
	      odp_pktio_capability_t *);
SUBSYSTEM_API(pktio_ops, int, config, pktio_entry_t *,
	      const odp_pktio_config_t *);
SUBSYSTEM_API(pktio_ops, int, input_queues_config,
	      pktio_entry_t *, const odp_pktin_queue_param_t *);
SUBSYSTEM_API(pktio_ops, int, output_queues_config,
	      pktio_entry_t *, const odp_pktout_queue_param_t *);
SUBSYSTEM_API(pktio_ops, void, print, pktio_entry_t *);

typedef MODULE_CLASS(pktio_ops)
	api_proto(pktio_ops, open) open;
	api_proto(pktio_ops, close) close;
	api_proto(pktio_ops, start) start;
	api_proto(pktio_ops, stop) stop;
	api_proto(pktio_ops, stats) stats;
	api_proto(pktio_ops, stats_reset) stats_reset;
	api_proto(pktio_ops, pktin_ts_res) pktin_ts_res;
	api_proto(pktio_ops, pktin_ts_from_ns) pktin_ts_from_ns;
	api_proto(pktio_ops, recv) recv;
	api_proto(pktio_ops, send) send;
	api_proto(pktio_ops, mtu_get) mtu_get;
	api_proto(pktio_ops, promisc_mode_set) promisc_mode_set;
	api_proto(pktio_ops, promisc_mode_get) promisc_mode_get;
	api_proto(pktio_ops, mac_get) mac_get;
	api_proto(pktio_ops, link_status) link_status;
	api_proto(pktio_ops, capability) capability;
	api_proto(pktio_ops, config) config;
	api_proto(pktio_ops, input_queues_config) input_queues_config;
	api_proto(pktio_ops, output_queues_config) output_queues_config;
	api_proto(pktio_ops, print) print;
} pktio_ops_module_t;

/* All implementations of this subsystem */
#include <odp_pktio_ops_dpdk.h>
#include <odp_pktio_ops_ipc.h>
#include <odp_pktio_ops_loopback.h>
#include <odp_pktio_ops_netmap.h>
#ifdef HAVE_PCAP
#include <odp_pktio_ops_pcap.h>
#endif
#include <odp_pktio_ops_socket.h>
#include <odp_pktio_ops_tap.h>

/* Per pktio instance data used by each implementation */
typedef union {
	pktio_ops_dpdk_data_t dpdk;
	pktio_ops_ipc_data_t ipc;
	pktio_ops_loopback_data_t loopback;
	pktio_ops_netmap_data_t netmap;
#ifdef HAVE_PCAP
	pktio_ops_pcap_data_t pcap;
#endif
	pktio_ops_socket_data_t socket;
	pktio_ops_socket_mmap_data_t mmap;
	pktio_ops_tap_data_t tap;
} pktio_ops_data_t;

/* Extract pktio ops data from pktio entry structure */
#define ops_data(mod) s.ops_data.mod

#ifdef __cplusplus
}
#endif

#endif

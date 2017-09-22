/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_PKTIO_OPS_SUBSYSTEM_H_
#define ODP_PKTIO_OPS_SUBSYSTEM_H_

#include <odp_module.h>
#include <odp/api/packet_io.h>

/* ODP packet IO operations subsystem declaration */
ODP_SUBSYSTEM_DECLARE(pktio_ops);

/* Subsystem APIs declarations */
ODP_SUBSYSTEM_API(pktio_ops, int, open, odp_pktio_t,
		  pktio_entry_t *, const char *, odp_pool_t);
ODP_SUBSYSTEM_API(pktio_ops, int, close, pktio_entry_t *);
ODP_SUBSYSTEM_API(pktio_ops, int, start, pktio_entry_t *);
ODP_SUBSYSTEM_API(pktio_ops, int, stop, pktio_entry_t *);
ODP_SUBSYSTEM_API(pktio_ops, int, stats, pktio_entry_t *,
		  odp_pktio_stats_t *stats);
ODP_SUBSYSTEM_API(pktio_ops, int, stats_reset, pktio_entry_t *);
ODP_SUBSYSTEM_API(pktio_ops, uint64_t, pktin_ts_res, pktio_entry_t *);
ODP_SUBSYSTEM_API(pktio_ops, odp_time_t, pktin_ts_from_ns,
		  pktio_entry_t *, uint64_t ns);
ODP_SUBSYSTEM_API(pktio_ops, int, recv, pktio_entry_t *,
		  int index, odp_packet_t packets[], int count);
ODP_SUBSYSTEM_API(pktio_ops, int, send, pktio_entry_t *,
		  int index, const odp_packet_t packets[], int count);
ODP_SUBSYSTEM_API(pktio_ops, uint32_t, mtu_get, pktio_entry_t *);
ODP_SUBSYSTEM_API(pktio_ops, int, promisc_mode_set,
		  pktio_entry_t *, int enable);
ODP_SUBSYSTEM_API(pktio_ops, int, promisc_mode_get, pktio_entry_t *);
ODP_SUBSYSTEM_API(pktio_ops, int, mac_get, pktio_entry_t *, void *);
ODP_SUBSYSTEM_API(pktio_ops, int, link_status, pktio_entry_t *);
ODP_SUBSYSTEM_API(pktio_ops, int, capability, pktio_entry_t *,
		  odp_pktio_capability_t *);
ODP_SUBSYSTEM_API(pktio_ops, int, config, pktio_entry_t *,
		  const odp_pktio_config_t *);
ODP_SUBSYSTEM_API(pktio_ops, int, input_queues_config,
		  pktio_entry_t *, const odp_pktin_queue_param_t *);
ODP_SUBSYSTEM_API(pktio_ops, int, output_queues_config,
		  pktio_entry_t *, const odp_pktout_queue_param_t *);
ODP_SUBSYSTEM_API(pktio_ops, void, print, pktio_entry_t *);

/* Declare subsystem init and term routines */
ODP_SUBSYSTEM_API(pktio_ops, int, init_global, bool);
ODP_SUBSYSTEM_API(pktio_ops, int, init_local, bool);
ODP_SUBSYSTEM_API(pktio_ops, int, term_global, bool);
ODP_SUBSYSTEM_API(pktio_ops, int, term_local, bool);

typedef ODP_MODULE_CLASS(pktio_ops) {
	odp_module_base_t base;

	odp_api_proto(pktio_ops, open) open;
	odp_api_proto(pktio_ops, close) close;
	odp_api_proto(pktio_ops, start) start;
	odp_api_proto(pktio_ops, stop) stop;
	odp_api_proto(pktio_ops, stats) stats;
	odp_api_proto(pktio_ops, stats_reset) stats_reset;
	odp_api_proto(pktio_ops, pktin_ts_res) pktin_ts_res;
	odp_api_proto(pktio_ops, pktin_ts_from_ns) pktin_ts_from_ns;
	odp_api_proto(pktio_ops, recv) recv;
	odp_api_proto(pktio_ops, send) send;
	odp_api_proto(pktio_ops, mtu_get) mtu_get;
	odp_api_proto(pktio_ops, promisc_mode_set) promisc_mode_set;
	odp_api_proto(pktio_ops, promisc_mode_get) promisc_mode_get;
	odp_api_proto(pktio_ops, mac_get) mac_get;
	odp_api_proto(pktio_ops, link_status) link_status;
	odp_api_proto(pktio_ops, capability) capability;
	odp_api_proto(pktio_ops, config) config;
	odp_api_proto(pktio_ops, input_queues_config) input_queues_config;
	odp_api_proto(pktio_ops, output_queues_config) output_queues_config;
	odp_api_proto(pktio_ops, print) print;
} pktio_ops_module_t;

/* All implementations of this subsystem */
#include <odp_pktio_ops_netmap.h>
#include <odp_pktio_ops_pcap.h>

/* Per implementation private data
 * TODO: refactory each implementation to hide it internally
 */
typedef union {
	void *dpdk;
	pktio_ops_netmap_data_t netmap;
	pktio_ops_pcap_data_t pcap;
} pktio_ops_data_t;

/* Extract pktio ops data from pktio entry structure */
#define ops_data(mod) s.ops_data.mod

/* Maximum size of pktio specific ops data.*/
#define ODP_PKTIO_ODPS_DATA_MAX_SIZE 80000

/* Extract pktio ops data from pktio entry structure */
#define odp_ops_data(_p, _mod) \
	((pktio_ops_ ## _mod ## _data_t *)(uintptr_t)_p->s._ops_data)

#endif

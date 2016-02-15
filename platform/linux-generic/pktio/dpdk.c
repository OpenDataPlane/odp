/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifdef ODP_PKTIO_DPDK

#include <odp_posix_extensions.h>

#include <odp_packet_io_internal.h>
#include <odp_packet_dpdk.h>
#include <odp_debug_internal.h>

#include <rte_config.h>

static int dpdk_close(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 0;
}

static int dpdk_open(odp_pktio_t id ODP_UNUSED,
		     pktio_entry_t *pktio_entry ODP_UNUSED,
		     const char *netdev ODP_UNUSED,
		     odp_pool_t pool ODP_UNUSED)
{
	return 0;
}

static int dpdk_start(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 0;
}

static int dpdk_stop(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 0;
}

static int dpdk_recv_queue(pktio_entry_t *pktio_entry ODP_UNUSED,
			   int index ODP_UNUSED,
			   odp_packet_t pkt_table[] ODP_UNUSED,
			   int num ODP_UNUSED)
{
	return 0;
}

static int dpdk_recv(pktio_entry_t *pktio_entry ODP_UNUSED,
		     odp_packet_t pkt_table[] ODP_UNUSED,
		     unsigned num ODP_UNUSED)
{
	return 0;
}

static int dpdk_send_queue(pktio_entry_t *pktio_entry ODP_UNUSED,
			   int index ODP_UNUSED,
			   odp_packet_t pkt_table[] ODP_UNUSED,
			   int num ODP_UNUSED)
{
	return 0;
}

static int dpdk_send(pktio_entry_t *pktio_entry ODP_UNUSED,
		     odp_packet_t pkt_table[] ODP_UNUSED,
		     unsigned num ODP_UNUSED)
{
	return 0;
}

const pktio_if_ops_t dpdk_pktio_ops = {
	.name = "dpdk",
	.init_global = NULL,
	.init_local = NULL,
	.term = NULL,
	.open = dpdk_open,
	.close = dpdk_close,
	.start = dpdk_start,
	.stop = dpdk_stop,
	.recv = dpdk_recv,
	.send = dpdk_send,
	.recv_queue = dpdk_recv_queue,
	.send_queue = dpdk_send_queue,
	.link_status = NULL,
	.mtu_get = NULL,
	.promisc_mode_set = NULL,
	.promisc_mode_get = NULL,
	.mac_get = NULL,
	.capability = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL,
	.in_queues = NULL,
	.pktin_queues = NULL,
	.pktout_queues = NULL
};

#endif /* ODP_PKTIO_DPDK */

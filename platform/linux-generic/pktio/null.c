/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

#include <odp/api/debug.h>
#include <odp/api/hints.h>
#include <odp/api/packet_io.h>

#include <odp_packet_io_internal.h>

#include <stdint.h>

static int null_close(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 0;
}

static int null_open(odp_pktio_t id ODP_UNUSED, pktio_entry_t *pktio_entry ODP_UNUSED,
		     const char *devname, odp_pool_t pool ODP_UNUSED)
{
	if (strncmp(devname, "null:", 5) != 0)
		return -1;

	return 0;
}

static int null_recv(pktio_entry_t *pktio_entry ODP_UNUSED,
		     int index ODP_UNUSED, odp_packet_t pkt_table[] ODP_UNUSED,
		     int len ODP_UNUSED)
{
	return 0;
}

static int null_fd_set(pktio_entry_t *pktio_entry ODP_UNUSED,
		       int index ODP_UNUSED, fd_set *readfds ODP_UNUSED)
{
	return 0;
}

static int null_recv_tmo(pktio_entry_t *pktio_entry ODP_UNUSED,
			 int index ODP_UNUSED,
			 odp_packet_t pkt_table[] ODP_UNUSED,
			 int num ODP_UNUSED, uint64_t usecs)
{
	struct timeval timeout;
	int maxfd = -1;
	fd_set readfds;

	timeout.tv_sec = usecs / (1000 * 1000);
	timeout.tv_usec = usecs - timeout.tv_sec * (1000ULL * 1000ULL);
	FD_ZERO(&readfds);

	select(maxfd + 1, &readfds, NULL, NULL, &timeout);

	return 0;
}

static int null_recv_mq_tmo(pktio_entry_t *pktio_entry[] ODP_UNUSED,
			    int index[] ODP_UNUSED, uint32_t num_q ODP_UNUSED,
			    odp_packet_t pkt_table[] ODP_UNUSED,
			    int num ODP_UNUSED, uint32_t *from ODP_UNUSED,
			    uint64_t usecs)
{
	struct timeval timeout;
	int maxfd = -1;
	fd_set readfds;

	timeout.tv_sec = usecs / (1000 * 1000);
	timeout.tv_usec = usecs - timeout.tv_sec * (1000ULL * 1000ULL);

	FD_ZERO(&readfds);

	select(maxfd + 1, &readfds, NULL, NULL, &timeout);

	return 0;
}

static int null_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
		     const odp_packet_t pkt_table[], int num)
{
	odp_bool_t set_tx_ts = false;

	if (_odp_pktio_tx_ts_enabled(pktio_entry)) {
		int i;

		for (i = 0; i < num; i++) {
			if (odp_unlikely(packet_hdr(pkt_table[i])->p.flags.ts_set)) {
				set_tx_ts = true;
				break;
			}
		}
	}

	odp_packet_free_multi(pkt_table, num);

	if (odp_unlikely(set_tx_ts))
		_odp_pktio_tx_ts_set(pktio_entry);

	return num;
}

#define PKTIO_NULL_MTU (64 * 1024)

static uint32_t null_mtu_get(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return PKTIO_NULL_MTU;
}

static const uint8_t null_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x05};

static int null_mac_addr_get(pktio_entry_t *pktio_entry ODP_UNUSED,
			     void *mac_addr)
{
	memcpy(mac_addr, null_mac, ETH_ALEN);
	return ETH_ALEN;
}

static int null_promisc_mode_get(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	/* Promisc mode disabled. Mode does not matter, as packet input does not
	 * return any packets.*/
	return 0;
}

static int null_capability(pktio_entry_t *pktio_entry ODP_UNUSED,
			   odp_pktio_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues  = ODP_PKTIN_MAX_QUEUES;
	capa->max_output_queues = ODP_PKTOUT_MAX_QUEUES;
	capa->set_op.op.promisc_mode = 0;

	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;

	capa->config.pktout.bit.ts_ena = 1;

	capa->tx_compl.mode_event = 1;
	capa->tx_compl.mode_poll = 1;

	return 0;
}

static int null_inqueues_config(pktio_entry_t *pktio_entry ODP_UNUSED,
				const odp_pktin_queue_param_t *p ODP_UNUSED)
{
	return 0;
}

static int null_outqueues_config(pktio_entry_t *pktio_entry ODP_UNUSED,
				 const odp_pktout_queue_param_t *p ODP_UNUSED)
{
	return 0;
}

static int null_init_global(void)
{
	_ODP_PRINT("PKTIO: initialized null interface.\n");
	return 0;
}

static int null_link_status(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return ODP_PKTIO_LINK_STATUS_UP;
}

static int null_link_info(pktio_entry_t *pktio_entry ODP_UNUSED, odp_pktio_link_info_t *info)
{
	memset(info, 0, sizeof(odp_pktio_link_info_t));

	info->autoneg = ODP_PKTIO_LINK_AUTONEG_OFF;
	info->duplex = ODP_PKTIO_LINK_DUPLEX_FULL;
	info->media = "virtual";
	info->pause_rx = ODP_PKTIO_LINK_PAUSE_OFF;
	info->pause_tx = ODP_PKTIO_LINK_PAUSE_OFF;
	info->speed = ODP_PKTIO_LINK_SPEED_UNKNOWN;
	info->status = ODP_PKTIO_LINK_STATUS_UP;

	return 0;
}

const pktio_if_ops_t _odp_null_pktio_ops = {
	.name = "null",
	.print = NULL,
	.init_global = null_init_global,
	.init_local = NULL,
	.term = NULL,
	.open = null_open,
	.close = null_close,
	.start = NULL,
	.stop = NULL,
	.recv = null_recv,
	.recv_tmo = null_recv_tmo,
	.recv_mq_tmo = null_recv_mq_tmo,
	.fd_set = null_fd_set,
	.send = null_send,
	.maxlen_get = null_mtu_get,
	.promisc_mode_set = NULL,
	.promisc_mode_get = null_promisc_mode_get,
	.mac_get = null_mac_addr_get,
	.capability = null_capability,
	.pktio_ts_res = NULL,
	.pktio_ts_from_ns = NULL,
	.pktio_time = NULL,
	.config = NULL,
	.input_queues_config = null_inqueues_config,
	.output_queues_config = null_outqueues_config,
	.link_status = null_link_status,
	.link_info = null_link_info
};

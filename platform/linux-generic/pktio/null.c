/* Copyright (c) 2018-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_packet_io_internal.h>

typedef struct {
	int promisc;			/**< whether promiscuous mode is on */
} pkt_null_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_null_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_null_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_null_t *)(uintptr_t)(pktio_entry->s.pkt_priv);
}

static int null_close(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 0;
}

static int null_open(odp_pktio_t id ODP_UNUSED,
		     pktio_entry_t *pktio_entry,
		     const char *devname, odp_pool_t pool ODP_UNUSED)
{
	if (strncmp(devname, "null:", 5) != 0)
		return -1;
	pkt_priv(pktio_entry)->promisc = 0;
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
			    int index[] ODP_UNUSED, int num_q ODP_UNUSED,
			    odp_packet_t pkt_table[] ODP_UNUSED,
			    int num ODP_UNUSED, unsigned *from ODP_UNUSED,
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

static int null_send(pktio_entry_t *pktio_entry ODP_UNUSED,
		     int index ODP_UNUSED, const odp_packet_t pkt_table[],
		     int num)
{
	odp_packet_free_multi(pkt_table, num);

	return num;
}

#define PKTIO_NULL_MTU (64 * 1024)

static uint32_t null_mtu_get(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return PKTIO_NULL_MTU;
}

static const char null_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x05};

static int null_mac_addr_get(pktio_entry_t *pktio_entry ODP_UNUSED,
			     void *mac_addr)
{
	memcpy(mac_addr, null_mac, ETH_ALEN);
	return ETH_ALEN;
}

static int null_promisc_mode_set(pktio_entry_t *pktio_entry, odp_bool_t enable)
{
	pkt_priv(pktio_entry)->promisc = !!enable;
	return 0;
}

static int null_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return pkt_priv(pktio_entry)->promisc;
}

static int null_capability(pktio_entry_t *pktio_entry ODP_UNUSED,
			   odp_pktio_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues  = PKTIO_MAX_QUEUES;
	capa->max_output_queues = PKTIO_MAX_QUEUES;
	capa->set_op.op.promisc_mode = 1;

	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;
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
	ODP_PRINT("PKTIO: initialized null interface.\n");
	return 0;
}

const pktio_if_ops_t null_pktio_ops = {
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
	.mtu_get = null_mtu_get,
	.promisc_mode_set = null_promisc_mode_set,
	.promisc_mode_get = null_promisc_mode_get,
	.mac_get = null_mac_addr_get,
	.capability = null_capability,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL,
	.input_queues_config = null_inqueues_config,
	.output_queues_config = null_outqueues_config,
};

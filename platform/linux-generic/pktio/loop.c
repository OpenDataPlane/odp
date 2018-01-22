/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_api.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp_queue_if.h>

#include <protocols/eth.h>
#include <protocols/ip.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>

#define MAX_LOOP 16
#define LOOP_MTU (64 * 1024)

/* MAC address for the "loop" interface */
static const char pktio_loop_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x01};

static int loopback_stats_reset(pktio_entry_t *pktio_entry);

static int loopback_open(odp_pktio_t id, pktio_entry_t *pktio_entry,
			 const char *devname, odp_pool_t pool ODP_UNUSED)
{
	long idx;
	char loopq_name[ODP_QUEUE_NAME_LEN];

	if (!strcmp(devname, "loop")) {
		idx = 0;
	} else if (!strncmp(devname, "loop", 4)) {
		char *end;

		idx = strtol(devname + 4, &end, 10);
		if (idx <= 0 || idx >= MAX_LOOP || *end)
			return -1;
	} else {
		return -1;
	}

	snprintf(loopq_name, sizeof(loopq_name), "%" PRIu64 "-pktio_loopq",
		 odp_pktio_to_u64(id));
	pktio_entry->s.pkt_loop.loopq =
		odp_queue_create(loopq_name, NULL);
	pktio_entry->s.pkt_loop.idx = idx;

	if (pktio_entry->s.pkt_loop.loopq == ODP_QUEUE_INVALID)
		return -1;

	loopback_stats_reset(pktio_entry);

	return 0;
}

static int loopback_close(pktio_entry_t *pktio_entry)
{
	return odp_queue_destroy(pktio_entry->s.pkt_loop.loopq);
}

static int loopback_recv(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			 odp_packet_t pkts[], int num)
{
	int nbr, i;
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	queue_t queue;
	odp_packet_hdr_t *pkt_hdr;
	odp_packet_t pkt;
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	int num_rx = 0;
	int failed = 0;

	if (odp_unlikely(num > QUEUE_MULTI_MAX))
		num = QUEUE_MULTI_MAX;

	odp_ticketlock_lock(&pktio_entry->s.rxl);

	queue = queue_fn->from_ext(pktio_entry->s.pkt_loop.loopq);
	nbr = queue_fn->deq_multi(queue, hdr_tbl, num);

	if (pktio_entry->s.config.pktin.bit.ts_all ||
	    pktio_entry->s.config.pktin.bit.ts_ptp) {
		ts_val = odp_time_global();
		ts = &ts_val;
	}

	for (i = 0; i < nbr; i++) {
		uint32_t pkt_len;

		pkt = packet_from_buf_hdr(hdr_tbl[i]);
		pkt_len = odp_packet_len(pkt);
		pkt_hdr = odp_packet_hdr(pkt);

		packet_parse_reset(pkt_hdr);
		if (pktio_cls_enabled(pktio_entry)) {
			odp_packet_t new_pkt;
			odp_pool_t new_pool;
			uint8_t *pkt_addr;
			uint8_t buf[PACKET_PARSE_SEG_LEN];
			int ret;
			uint32_t seg_len = odp_packet_seg_len(pkt);

			/* Make sure there is enough data for the packet
			 * parser in the case of a segmented packet. */
			if (odp_unlikely(seg_len < PACKET_PARSE_SEG_LEN &&
					 pkt_len > PACKET_PARSE_SEG_LEN)) {
				odp_packet_copy_to_mem(pkt, 0,
						       PACKET_PARSE_SEG_LEN,
						       buf);
				seg_len = PACKET_PARSE_SEG_LEN;
				pkt_addr = buf;
			} else {
				pkt_addr = odp_packet_data(pkt);
			}

			ret = cls_classify_packet(pktio_entry, pkt_addr,
						  pkt_len, seg_len,
						  &new_pool, pkt_hdr);
			if (ret) {
				failed++;
				odp_packet_free(pkt);
				continue;
			}

			if (new_pool != odp_packet_pool(pkt)) {
				new_pkt = odp_packet_copy(pkt, new_pool);

				odp_packet_free(pkt);

				if (new_pkt == ODP_PACKET_INVALID) {
					failed++;
					continue;
				}
				pkt = new_pkt;
			}
		} else {
			packet_parse_layer(pkt_hdr,
					   pktio_entry->s.config.parser.layer);
		}

		packet_set_ts(pkt_hdr, ts);
		pkt_hdr->input = pktio_entry->s.handle;

		/* Try IPsec inline processing */
		if (pktio_entry->s.config.inbound_ipsec &&
		    odp_packet_has_ipsec(pkt))
			_odp_ipsec_try_inline(pkt);

		pktio_entry->s.stats.in_octets += pkt_len;
		pkts[num_rx++] = pkt;
	}

	pktio_entry->s.stats.in_errors += failed;
	pktio_entry->s.stats.in_ucast_pkts += num_rx - failed;

	odp_ticketlock_unlock(&pktio_entry->s.rxl);

	return num_rx;
}

static int loopback_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			 const odp_packet_t pkt_tbl[], int num)
{
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	queue_t queue;
	int i;
	int ret;
	int nb_tx = 0;
	uint32_t bytes = 0;
	uint32_t out_octets_tbl[num];

	if (odp_unlikely(num > QUEUE_MULTI_MAX))
		num = QUEUE_MULTI_MAX;

	for (i = 0; i < num; ++i) {
		uint32_t pkt_len = odp_packet_len(pkt_tbl[i]);

		if (pkt_len > LOOP_MTU) {
			if (nb_tx == 0) {
				__odp_errno = EMSGSIZE;
				return -1;
			}
			break;
		}
		hdr_tbl[i] = packet_to_buf_hdr(pkt_tbl[i]);
		bytes += pkt_len;
		/* Store cumulative byte counts to update 'stats.out_octets'
		 * correctly in case enq_multi() fails to enqueue all packets.
		 */
		out_octets_tbl[i] = bytes;
		nb_tx++;
	}

	for (i = 0; i < nb_tx; ++i) {
		odp_ipsec_packet_result_t result;

		if (packet_subtype(pkt_tbl[i]) ==
				ODP_EVENT_PACKET_IPSEC &&
		    pktio_entry->s.config.outbound_ipsec) {

			/* Possibly postprocessing packet */
			odp_ipsec_result(&result, pkt_tbl[i]);
		}
		packet_subtype_set(pkt_tbl[i], ODP_EVENT_PACKET_BASIC);
	}

	odp_ticketlock_lock(&pktio_entry->s.txl);

	queue = queue_fn->from_ext(pktio_entry->s.pkt_loop.loopq);
	ret = queue_fn->enq_multi(queue, hdr_tbl, nb_tx);

	if (ret > 0) {
		pktio_entry->s.stats.out_ucast_pkts += ret;
		pktio_entry->s.stats.out_octets += out_octets_tbl[ret - 1];
	} else {
		ODP_DBG("queue enqueue failed %i\n", ret);
		ret = -1;
	}

	odp_ticketlock_unlock(&pktio_entry->s.txl);

	return ret;
}

static uint32_t loopback_mtu_get(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return LOOP_MTU;
}

static int loopback_mac_addr_get(pktio_entry_t *pktio_entry ODP_UNUSED,
				 void *mac_addr)
{
	memcpy(mac_addr, pktio_loop_mac, ETH_ALEN);
	((uint8_t *)mac_addr)[ETH_ALEN - 1] += pktio_entry->s.pkt_loop.idx;
	return ETH_ALEN;
}

static int loopback_link_status(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	/* loopback interfaces are always up */
	return 1;
}

static int loopback_capability(pktio_entry_t *pktio_entry ODP_UNUSED,
			       odp_pktio_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues  = 1;
	capa->max_output_queues = 1;
	capa->set_op.op.promisc_mode = 1;

	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;
	capa->config.inbound_ipsec = 1;
	capa->config.outbound_ipsec = 1;

	return 0;
}

static int loopback_promisc_mode_set(pktio_entry_t *pktio_entry,
				     odp_bool_t enable)
{
	pktio_entry->s.pkt_loop.promisc = enable;
	return 0;
}

static int loopback_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return pktio_entry->s.pkt_loop.promisc ? 1 : 0;
}

static int loopback_stats(pktio_entry_t *pktio_entry,
			  odp_pktio_stats_t *stats)
{
	memcpy(stats, &pktio_entry->s.stats, sizeof(odp_pktio_stats_t));
	return 0;
}

static int loopback_stats_reset(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	memset(&pktio_entry->s.stats, 0, sizeof(odp_pktio_stats_t));
	return 0;
}

static int loop_init_global(void)
{
	ODP_PRINT("PKTIO: initialized loop interface.\n");
	return 0;
}

const pktio_if_ops_t loopback_pktio_ops = {
	.name = "loop",
	.print = NULL,
	.init_global = loop_init_global,
	.init_local = NULL,
	.term = NULL,
	.open = loopback_open,
	.close = loopback_close,
	.start = NULL,
	.stop = NULL,
	.stats = loopback_stats,
	.stats_reset = loopback_stats_reset,
	.recv = loopback_recv,
	.send = loopback_send,
	.mtu_get = loopback_mtu_get,
	.promisc_mode_set = loopback_promisc_mode_set,
	.promisc_mode_get = loopback_promisc_mode_get,
	.mac_get = loopback_mac_addr_get,
	.mac_set = NULL,
	.link_status = loopback_link_status,
	.capability = loopback_capability,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL,
};

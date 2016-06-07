/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

#include <errno.h>

/* MAC address for the "loop" interface */
static const char pktio_loop_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x01};

static int loopback_stats_reset(pktio_entry_t *pktio_entry);

static int loopback_open(odp_pktio_t id, pktio_entry_t *pktio_entry,
			 const char *devname, odp_pool_t pool ODP_UNUSED)
{
	if (strcmp(devname, "loop"))
		return -1;

	char loopq_name[ODP_QUEUE_NAME_LEN];

	snprintf(loopq_name, sizeof(loopq_name), "%" PRIu64 "-pktio_loopq",
		 odp_pktio_to_u64(id));
	pktio_entry->s.pkt_loop.loopq =
		odp_queue_create(loopq_name, NULL);

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
			 odp_packet_t pkts[], int len)
{
	int nbr, i;
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	queue_entry_t *qentry;
	odp_packet_hdr_t *pkt_hdr;
	odp_packet_hdr_t parsed_hdr;
	odp_packet_t pkt;
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	int num_rx = 0;
	int failed = 0;

	if (odp_unlikely(len > QUEUE_MULTI_MAX))
		len = QUEUE_MULTI_MAX;

	odp_ticketlock_lock(&pktio_entry->s.rxl);

	qentry = queue_to_qentry(pktio_entry->s.pkt_loop.loopq);
	nbr = queue_deq_multi(qentry, hdr_tbl, len);

	if (pktio_entry->s.config.pktin.bit.ts_all ||
	    pktio_entry->s.config.pktin.bit.ts_ptp) {
		ts_val = odp_time_global();
		ts = &ts_val;
	}

	for (i = 0; i < nbr; i++) {
		pkt = _odp_packet_from_buffer(odp_hdr_to_buf(hdr_tbl[i]));

		if (pktio_cls_enabled(pktio_entry)) {
			odp_packet_t new_pkt;
			odp_pool_t new_pool;
			uint8_t *pkt_addr;
			int ret;

			pkt_addr = odp_packet_data(pkt);
			ret = cls_classify_packet(pktio_entry, pkt_addr,
						  odp_packet_len(pkt),
						  &new_pool, &parsed_hdr);
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
		}
		pkt_hdr = odp_packet_hdr(pkt);

		pkt_hdr->input = pktio_entry->s.handle;

		if (pktio_cls_enabled(pktio_entry))
			copy_packet_parser_metadata(&parsed_hdr, pkt_hdr);
		else
			packet_parse_l2(pkt_hdr);

		packet_set_ts(pkt_hdr, ts);

		pktio_entry->s.stats.in_octets += odp_packet_len(pkt);

		pkts[num_rx++] = pkt;
	}

	pktio_entry->s.stats.in_errors += failed;
	pktio_entry->s.stats.in_ucast_pkts += num_rx - failed;

	odp_ticketlock_unlock(&pktio_entry->s.rxl);

	return num_rx;
}

static int loopback_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			 const odp_packet_t pkt_tbl[], int len)
{
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	queue_entry_t *qentry;
	int i;
	int ret;
	uint32_t bytes = 0;

	if (odp_unlikely(len > QUEUE_MULTI_MAX))
		len = QUEUE_MULTI_MAX;

	for (i = 0; i < len; ++i) {
		hdr_tbl[i] = odp_buf_to_hdr(_odp_packet_to_buffer(pkt_tbl[i]));
		bytes += odp_packet_len(pkt_tbl[i]);
	}

	odp_ticketlock_lock(&pktio_entry->s.txl);

	qentry = queue_to_qentry(pktio_entry->s.pkt_loop.loopq);
	ret = queue_enq_multi(qentry, hdr_tbl, len, 0);
	if (ret > 0) {
		pktio_entry->s.stats.out_ucast_pkts += ret;
		pktio_entry->s.stats.out_octets += bytes;
	}

	odp_ticketlock_unlock(&pktio_entry->s.txl);

	return ret;
}

static uint32_t loopback_mtu_get(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	/* the loopback interface imposes no maximum transmit size limit */
	return INT_MAX;
}

static int loopback_mac_addr_get(pktio_entry_t *pktio_entry ODP_UNUSED,
				 void *mac_addr)
{
	memcpy(mac_addr, pktio_loop_mac, ETH_ALEN);
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

const pktio_if_ops_t loopback_pktio_ops = {
	.name = "loop",
	.print = NULL,
	.init_global = NULL,
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
	.link_status = loopback_link_status,
	.capability = loopback_capability,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL,
};

/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <odp.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_internal.h>
#include <odp_debug_internal.h>
#include <odp/hints.h>

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

#include <errno.h>

/* MAC address for the "loop" interface */
static const char pktio_loop_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x01};

static int loopback_open(odp_pktio_t id, pktio_entry_t *pktio_entry,
			 const char *devname, odp_pool_t pool ODP_UNUSED)
{
	if (strcmp(devname, "loop"))
		return -1;

	char loopq_name[ODP_QUEUE_NAME_LEN];

	snprintf(loopq_name, sizeof(loopq_name), "%" PRIu64 "-pktio_loopq",
		 odp_pktio_to_u64(id));
	pktio_entry->s.pkt_loop.loopq =
		odp_queue_create(loopq_name, ODP_QUEUE_TYPE_POLL, NULL);

	if (pktio_entry->s.pkt_loop.loopq == ODP_QUEUE_INVALID)
		return -1;

	return 0;
}

static int loopback_close(pktio_entry_t *pktio_entry)
{
	return odp_queue_destroy(pktio_entry->s.pkt_loop.loopq);
}

static int loopback_recv(pktio_entry_t *pktio_entry, odp_packet_t pkts[],
			 unsigned len)
{
	int nbr, i, j;
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	queue_entry_t *qentry;
	odp_packet_hdr_t *pkt_hdr;
	odp_packet_t pkt;

	nbr = 0;
	qentry = queue_to_qentry(pktio_entry->s.pkt_loop.loopq);
	nbr = queue_deq_multi(qentry, hdr_tbl, len);

	if (pktio_cls_enabled(pktio_entry)) {
		for (i = 0, j = 0; i < nbr; i++) {
			pkt = _odp_packet_from_buffer(odp_hdr_to_buf
						      (hdr_tbl[i]));
			pkt_hdr = odp_packet_hdr(pkt);
			packet_parse_reset(pkt_hdr);
			packet_parse_l2(pkt_hdr);
			if (0 > _odp_packet_classifier(pktio_entry, pkt))
				pkts[j++] = pkt;
		}
	nbr = j;
	} else {
		for (i = 0; i < nbr; ++i) {
			pkts[i] = _odp_packet_from_buffer(odp_hdr_to_buf
							  (hdr_tbl[i]));
			pkt_hdr = odp_packet_hdr(pkts[i]);
			packet_parse_reset(pkt_hdr);
			packet_parse_l2(pkt_hdr);
		}
	}

	return nbr;
}

static int loopback_send(pktio_entry_t *pktio_entry, odp_packet_t pkt_tbl[],
			 unsigned len)
{
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	queue_entry_t *qentry;
	unsigned i;

	for (i = 0; i < len; ++i)
		hdr_tbl[i] = odp_buf_to_hdr(_odp_packet_to_buffer(pkt_tbl[i]));

	qentry = queue_to_qentry(pktio_entry->s.pkt_loop.loopq);
	return queue_enq_multi(qentry, hdr_tbl, len, 0);
}

static int loopback_mtu_get(pktio_entry_t *pktio_entry ODP_UNUSED)
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

const pktio_if_ops_t loopback_pktio_ops = {
	.init = NULL,
	.term = NULL,
	.open = loopback_open,
	.close = loopback_close,
	.start = NULL,
	.stop = NULL,
	.recv = loopback_recv,
	.send = loopback_send,
	.mtu_get = loopback_mtu_get,
	.promisc_mode_set = loopback_promisc_mode_set,
	.promisc_mode_get = loopback_promisc_mode_get,
	.mac_get = loopback_mac_addr_get
};

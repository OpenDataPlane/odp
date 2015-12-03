/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <odp_packet_io_internal.h>
#include <odp_classification_internal.h>

int _odp_packet_cls_enq(pktio_entry_t *pktio_entry,
			uint8_t *base, uint16_t buf_len,
			odp_packet_t *pkt_ret)
{
	cos_t *cos;
	odp_packet_t pkt;
	odp_packet_hdr_t pkt_hdr;
	int ret;
	odp_pool_t pool;

	packet_parse_reset(&pkt_hdr);

	_odp_cls_parse(&pkt_hdr, base);
	cos = pktio_select_cos(pktio_entry, (uint8_t *)base, &pkt_hdr);
	pool = cos->s.pool->s.pool_hdl;

	/* if No CoS found then drop the packet */
	if (cos == NULL || cos->s.queue == NULL)
		return 0;

	pkt = odp_packet_alloc(pool, buf_len);
	if (odp_unlikely(pkt == ODP_PACKET_INVALID))
		return 0;

	copy_packet_parser_metadata(&pkt_hdr, odp_packet_hdr(pkt));
	odp_packet_hdr(pkt)->input = pktio_entry->s.id;

	if (odp_packet_copydata_in(pkt, 0, buf_len, base) != 0) {
		odp_packet_free(pkt);
		return 0;
	}

	/* Parse and set packet header data */
	odp_packet_pull_tail(pkt, odp_packet_len(pkt) - buf_len);
	ret = queue_enq(cos->s.queue, odp_buf_to_hdr((odp_buffer_t)pkt), 0);
	if (ret < 0) {
		*pkt_ret = pkt;
		return 1;
	}

	return 0;
}

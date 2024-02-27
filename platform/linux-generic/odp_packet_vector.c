/* Copyright (c) 2020-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/align.h>
#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/pool.h>
#include <odp/api/plat/packet_vector_inlines.h>
#include <odp/api/plat/strong_types.h>

#include <odp_debug_internal.h>
#include <odp_event_vector_internal.h>
#include <odp_pool_internal.h>
#include <odp_string_internal.h>

#include <inttypes.h>
#include <stdint.h>

#include <odp/visibility_begin.h>

/* Packet vector header field offsets for inline functions */
const _odp_event_vector_inline_offset_t _odp_event_vector_inline ODP_ALIGNED_CACHE = {
	.packet    = offsetof(odp_event_vector_hdr_t, packet),
	.pool      = offsetof(odp_event_vector_hdr_t, event_hdr.pool),
	.size      = offsetof(odp_event_vector_hdr_t, size),
	.uarea_addr = offsetof(odp_event_vector_hdr_t, uarea_addr),
	.flags     = offsetof(odp_event_vector_hdr_t, flags)
};

#include <odp/visibility_end.h>

static inline odp_event_vector_hdr_t *event_vector_hdr_from_event(odp_event_t event)
{
	return (odp_event_vector_hdr_t *)(uintptr_t)event;
}

odp_packet_vector_t odp_packet_vector_alloc(odp_pool_t pool_hdl)
{
	odp_event_t event;
	pool_t *pool;

	_ODP_ASSERT(pool_hdl != ODP_POOL_INVALID);

	pool = _odp_pool_entry(pool_hdl);

	_ODP_ASSERT(pool->type == ODP_POOL_VECTOR);

	event = _odp_event_alloc(pool);
	if (odp_unlikely(event == ODP_EVENT_INVALID))
		return ODP_PACKET_VECTOR_INVALID;

	_ODP_ASSERT(event_vector_hdr_from_event(event)->size == 0);

	return odp_packet_vector_from_event(event);
}

void odp_packet_vector_free(odp_packet_vector_t pktv)
{
	odp_event_vector_hdr_t *pktv_hdr = _odp_packet_vector_hdr(pktv);

	pktv_hdr->size = 0;
	pktv_hdr->flags.all_flags = 0;

	_odp_event_free(odp_packet_vector_to_event(pktv));
}

int odp_packet_vector_valid(odp_packet_vector_t pktv)
{
	odp_event_vector_hdr_t *pktv_hdr;
	odp_event_t ev;
	pool_t *pool;
	uint32_t i;

	if (odp_unlikely(pktv == ODP_PACKET_VECTOR_INVALID))
		return 0;

	ev = odp_packet_vector_to_event(pktv);

	if (_odp_event_is_valid(ev) == 0)
		return 0;

	if (odp_event_type(ev) != ODP_EVENT_PACKET_VECTOR)
		return 0;

	pktv_hdr = _odp_packet_vector_hdr(pktv);
	pool = _odp_pool_entry(pktv_hdr->event_hdr.pool);

	if (odp_unlikely(pktv_hdr->size > pool->params.vector.max_size))
		return 0;

	for (i = 0; i < pktv_hdr->size; i++) {
		if (pktv_hdr->packet[i] == ODP_PACKET_INVALID)
			return 0;
	}

	return 1;
}

void odp_packet_vector_print(odp_packet_vector_t pktv)
{
	int max_len = 4096;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;
	uint32_t i;
	odp_event_vector_hdr_t *pktv_hdr = _odp_packet_vector_hdr(pktv);

	len += _odp_snprint(&str[len], n - len, "Packet vector info\n");
	len += _odp_snprint(&str[len], n - len, "------------------\n");
	len += _odp_snprint(&str[len], n - len, "  handle         0x%" PRIx64 "\n",
			    odp_packet_vector_to_u64(pktv));
	len += _odp_snprint(&str[len], n - len, "  size           %" PRIu32 "\n", pktv_hdr->size);
	len += _odp_snprint(&str[len], n - len, "  flags          0x%" PRIx32 "\n",
			    pktv_hdr->flags.all_flags);
	len += _odp_snprint(&str[len], n - len, "  user area      %p\n", pktv_hdr->uarea_addr);

	for (i = 0; i < pktv_hdr->size; i++) {
		odp_packet_t pkt = pktv_hdr->packet[i];
		char seg_str[max_len];
		int str_len;

		str_len = _odp_snprint(seg_str, max_len, "    packet     %p  len %" PRIu32 "\n",
				       (void *)pkt, odp_packet_len(pkt));

		/* Prevent print buffer overflow */
		if (n - len - str_len < 10) {
			len += _odp_snprint(&str[len], n - len, "    ...\n");
			break;
		}
		len += _odp_snprint(&str[len], n - len, "%s", seg_str);
	}

	_ODP_PRINT("%s\n", str);
}

uint64_t odp_packet_vector_to_u64(odp_packet_vector_t pktv)
{
	return _odp_pri(pktv);
}

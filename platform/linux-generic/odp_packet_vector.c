/* Copyright (c) 2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/pool.h>
#include <odp/api/plat/packet_vector_inlines.h>
#include <odp/api/plat/strong_types.h>

#include <odp_debug_internal.h>
#include <odp_event_vector_internal.h>
#include <odp_pool_internal.h>

#include <inttypes.h>
#include <stdint.h>

#include <odp/visibility_begin.h>

/* Packet vector header field offsets for inline functions */
const _odp_event_vector_inline_offset_t _odp_event_vector_inline ODP_ALIGNED_CACHE = {
	.packet    = offsetof(odp_event_vector_hdr_t, packet),
	.pool      = offsetof(odp_event_vector_hdr_t, buf_hdr.pool_ptr),
	.size      = offsetof(odp_event_vector_hdr_t, size)
};

#include <odp/visibility_end.h>

static inline odp_event_vector_hdr_t *event_vector_hdr_from_buffer(odp_buffer_t buf)
{
	return (odp_event_vector_hdr_t *)(uintptr_t)buf;
}

odp_packet_vector_t odp_packet_vector_alloc(odp_pool_t pool)
{
	odp_buffer_t buf;

	ODP_ASSERT(pool_entry_from_hdl(pool)->params.type == ODP_POOL_VECTOR);

	buf = odp_buffer_alloc(pool);
	if (odp_unlikely(buf == ODP_BUFFER_INVALID))
		return ODP_PACKET_VECTOR_INVALID;

	ODP_ASSERT(event_vector_hdr_from_buffer(buf)->size == 0);

	return odp_packet_vector_from_event(odp_buffer_to_event(buf));
}

void odp_packet_vector_free(odp_packet_vector_t pktv)
{
	odp_event_vector_hdr_t *pktv_hdr = _odp_packet_vector_hdr(pktv);
	odp_event_t ev = odp_packet_vector_to_event(pktv);

	pktv_hdr->size = 0;

	odp_buffer_free(odp_buffer_from_event(ev));
}

int odp_packet_vector_valid(odp_packet_vector_t pktv)
{
	odp_event_vector_hdr_t *pktv_hdr = _odp_packet_vector_hdr(pktv);
	pool_t *pool = pktv_hdr->buf_hdr.pool_ptr;
	uint32_t i;

	if (odp_unlikely(pktv == ODP_PACKET_VECTOR_INVALID))
		return 0;

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

	len += snprintf(&str[len], n - len, "Packet Vector\n");
	len += snprintf(&str[len], n - len,
			"  handle %p\n", pktv);
	len += snprintf(&str[len], n - len,
			"  size   %" PRIu32 "\n", pktv_hdr->size);

	for (i = 0; i < pktv_hdr->size; i++) {
		odp_packet_t pkt = pktv_hdr->packet[i];
		char seg_str[max_len];
		int str_len;

		str_len = snprintf(seg_str, max_len,
				   "    packet     %p  len %" PRIu32 "\n",
				   pkt, odp_packet_len(pkt));

		/* Prevent print buffer overflow */
		if (n - len - str_len < 10) {
			len += snprintf(&str[len], n - len, "    ...\n");
			break;
		}
		len += snprintf(&str[len], n - len, "%s", seg_str);
	}

	ODP_PRINT("%s\n", str);
}

uint64_t odp_packet_vector_to_u64(odp_packet_vector_t pktv)
{
	return _odp_pri(pktv);
}

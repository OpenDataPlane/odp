/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2025 Nokia
 */

#include <odp/api/align.h>
#include <odp/api/event_types.h>
#include <odp/api/event_vector.h>
#include <odp/api/hints.h>
#include <odp/api/pool.h>
#include <odp/api/plat/strong_types.h>

#include <odp_debug_internal.h>
#include <odp_event_vector_internal.h>
#include <odp_pool_internal.h>
#include <odp_string_internal.h>

#include <inttypes.h>
#include <stdint.h>

#include <odp/visibility_begin.h>

/* Event vector header field offsets for inline functions */
const _odp_event_vector_inline_offset_t _odp_event_vector_inline ODP_ALIGNED_CACHE = {
	.event     = offsetof(odp_event_vector_hdr_t, event),
	.pool      = offsetof(odp_event_vector_hdr_t, event_hdr.pool),
	.size      = offsetof(odp_event_vector_hdr_t, size),
	.event_type = offsetof(odp_event_vector_hdr_t, event_type),
	.uarea_addr = offsetof(odp_event_vector_hdr_t, uarea_addr),
	.flags     = offsetof(odp_event_vector_hdr_t, flags)
};

#include <odp/visibility_end.h>

static inline odp_event_vector_hdr_t *event_vector_hdr_from_event(odp_event_t event)
{
	return (odp_event_vector_hdr_t *)(uintptr_t)event;
}

odp_event_vector_t odp_event_vector_alloc(odp_pool_t pool_hdl)
{
	odp_event_t event;
	pool_t *pool;

	_ODP_ASSERT(pool_hdl != ODP_POOL_INVALID);

	pool = _odp_pool_entry(pool_hdl);

	_ODP_ASSERT(pool->type == ODP_POOL_EVENT_VECTOR);

	event = _odp_event_alloc(pool);
	if (odp_unlikely(event == ODP_EVENT_INVALID))
		return ODP_EVENT_VECTOR_INVALID;

	_ODP_ASSERT(event_vector_hdr_from_event(event)->size == 0);
	_ODP_ASSERT(event_vector_hdr_from_event(event)->event_type == ODP_EVENT_ANY);

	return odp_event_vector_from_event(event);
}

void odp_event_vector_free(odp_event_vector_t evv)
{
	odp_event_vector_hdr_t *evv_hdr = _odp_event_vector_hdr(evv);

	evv_hdr->size = 0;
	evv_hdr->flags.all_flags = 0;
	evv_hdr->event_type = ODP_EVENT_ANY;

	_odp_event_free(odp_event_vector_to_event(evv));
}

void odp_event_vector_print(odp_event_vector_t evv)
{
	int max_len = 4096;
	char str[max_len];
	int len = 0;
	int n = max_len - 1;
	uint32_t i;
	odp_event_vector_hdr_t *evv_hdr;

	len += _odp_snprint(&str[len], n - len, "Event vector info\n");
	len += _odp_snprint(&str[len], n - len, "------------------\n");
	len += _odp_snprint(&str[len], n - len, "  handle         0x%" PRIx64 "\n",
			    odp_event_vector_to_u64(evv));

	if (evv == ODP_EVENT_VECTOR_INVALID) {
		len += _odp_snprint(&str[len], n - len,
				    "  handle         ODP_EVENT_VECTOR_INVALID\n");
		goto out;
	}

	evv_hdr = _odp_event_vector_hdr(evv);

	len += _odp_snprint(&str[len], n - len, "  size           %" PRIu32 "\n", evv_hdr->size);
	len += _odp_snprint(&str[len], n - len, "  flags          0x%" PRIx32 "\n",
			    evv_hdr->flags.all_flags);
	len += _odp_snprint(&str[len], n - len, "  user area      %p\n", evv_hdr->uarea_addr);

	for (i = 0; i < evv_hdr->size; i++) {
		odp_event_t ev = evv_hdr->event[i];
		char seg_str[max_len];
		int str_len;

		str_len = _odp_snprint(seg_str, max_len, "    event     %p  type %d subtype %d\n",
				       ev,
				       odp_event_type(ev),
				       odp_event_subtype(ev));

		/* Prevent print buffer overflow */
		if (n - len - str_len < 10) {
			len += _odp_snprint(&str[len], n - len, "    ...\n");
			break;
		}
		len += _odp_snprint(&str[len], n - len, "%s", seg_str);
	}

out:
	_ODP_PRINT("%s\n", str);
}

uint64_t odp_event_vector_to_u64(odp_event_vector_t evv)
{
	return _odp_pri(evv);
}

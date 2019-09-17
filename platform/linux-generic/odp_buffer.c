/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/buffer.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/plat/buffer_inline_types.h>

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <odp/visibility_begin.h>

/* Fill in buffer header field offsets for inline functions */
const _odp_buffer_inline_offset_t ODP_ALIGNED_CACHE
_odp_buffer_inline_offset = {
	.event_type = offsetof(odp_buffer_hdr_t, event_type)
};

#include <odp/visibility_end.h>

odp_buffer_t odp_buffer_from_event(odp_event_t ev)
{
	return (odp_buffer_t)ev;
}

odp_event_t odp_buffer_to_event(odp_buffer_t buf)
{
	return (odp_event_t)buf;
}

void *odp_buffer_addr(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = buf_hdl_to_hdr(buf);

	return hdr->base_data;
}

uint32_t odp_buffer_size(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = buf_hdl_to_hdr(buf);
	pool_t *pool = hdr->pool_ptr;

	return pool->seg_len;
}

int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	pool_t *pool;
	int len = 0;

	if (!odp_buffer_is_valid(buf)) {
		ODP_PRINT("Buffer is not valid.\n");
		return len;
	}

	hdr = buf_hdl_to_hdr(buf);
	pool = hdr->pool_ptr;

	len += snprintf(&str[len], n - len,
			"Buffer\n");
	len += snprintf(&str[len], n - len,
			"  pool         %" PRIu64 "\n",
			odp_pool_to_u64(pool->pool_hdl));
	len += snprintf(&str[len], n - len,
			"  addr         %p\n",          hdr->base_data);
	len += snprintf(&str[len], n - len,
			"  size         %" PRIu32 "\n", odp_buffer_size(buf));
	len += snprintf(&str[len], n - len,
			"  type         %i\n",          hdr->type);

	return len;
}

void odp_buffer_print(odp_buffer_t buf)
{
	int max_len = 512;
	char str[max_len];
	int len;

	len = odp_buffer_snprint(str, max_len - 1, buf);
	str[len] = 0;

	ODP_PRINT("\n%s\n", str);
}

uint64_t odp_buffer_to_u64(odp_buffer_t hdl)
{
	return _odp_pri(hdl);
}

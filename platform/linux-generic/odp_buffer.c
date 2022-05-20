/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/buffer.h>

#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_debug_internal.h>

#include <string.h>
#include <stdio.h>
#include <inttypes.h>

uint32_t odp_buffer_size(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = _odp_buf_hdr(buf);
	pool_t *pool = hdr->event_hdr.pool_ptr;

	return pool->seg_len;
}

void odp_buffer_print(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	int len = 0;
	int max_len = 512;
	int n = max_len - 1;
	char str[max_len];

	if (!odp_buffer_is_valid(buf)) {
		ODP_ERR("Buffer is not valid.\n");
		return;
	}

	hdr = _odp_buf_hdr(buf);

	len += snprintf(&str[len], n - len, "Buffer\n------\n");
	len += snprintf(&str[len], n - len, "  pool index    %u\n", hdr->event_hdr.index.pool);
	len += snprintf(&str[len], n - len, "  buffer index  %u\n", hdr->event_hdr.index.event);
	len += snprintf(&str[len], n - len, "  addr          %p\n",
			(void *)hdr->event_hdr.base_data);
	len += snprintf(&str[len], n - len, "  size          %u\n", odp_buffer_size(buf));
	str[len] = 0;

	ODP_PRINT("\n%s\n", str);
}

uint64_t odp_buffer_to_u64(odp_buffer_t hdl)
{
	return _odp_pri(hdl);
}

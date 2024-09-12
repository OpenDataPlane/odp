/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2024 Nokia
 */

#include <odp/api/align.h>
#include <odp/api/buffer.h>

#include <odp/api/plat/buffer_inline_types.h>
#include <odp/api/plat/strong_types.h>

#include <odp_buffer_internal.h>
#include <odp_debug_internal.h>
#include <odp_string_internal.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <odp/visibility_begin.h>

/* Buffer header field offsets for inline functions */
const _odp_buffer_inline_offset_t _odp_buffer_inline_offset ODP_ALIGNED_CACHE = {
	.uarea_addr = offsetof(odp_buffer_hdr_t, uarea_addr)
};

#include <odp/visibility_end.h>

void odp_buffer_print(odp_buffer_t buf)
{
	int len = 0;
	int max_len = 512;
	int n = max_len - 1;
	char str[max_len];

	if (!odp_buffer_is_valid(buf)) {
		_ODP_ERR("Buffer is not valid.\n");
		return;
	}

	len += _odp_snprint(&str[len], n - len, "Buffer info\n");
	len += _odp_snprint(&str[len], n - len, "-----------\n");
	len += _odp_snprint(&str[len], n - len, "  handle         0x%" PRIx64 "\n",
			    odp_buffer_to_u64(buf));
	len += _odp_snprint(&str[len], n - len, "  pool index     %u\n",
			    odp_pool_index(odp_buffer_pool(buf)));
	len += _odp_snprint(&str[len], n - len, "  buffer index   %u\n", _odp_buffer_index(buf));
	len += _odp_snprint(&str[len], n - len, "  addr           %p\n", odp_buffer_addr(buf));
	len += _odp_snprint(&str[len], n - len, "  size           %u\n", odp_buffer_size(buf));
	len += _odp_snprint(&str[len], n - len, "  user area      %p\n", odp_buffer_user_area(buf));
	str[len] = 0;

	_ODP_PRINT("%s\n", str);
}

uint64_t odp_buffer_to_u64(odp_buffer_t hdl)
{
	return _odp_pri(hdl);
}

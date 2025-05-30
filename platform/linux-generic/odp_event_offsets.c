/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2020-2025 Nokia
 */

#include <odp_event_internal.h>

#include <odp/api/plat/event_inline_types.h>

#include <odp/visibility_begin.h>

/* Fill in event header field offsets for inline functions */
const _odp_event_inline_offset_t
_odp_event_inline_offset ODP_ALIGNED_CACHE = {
	.event_type = offsetof(_odp_event_hdr_t, event_type),
	.base_data  = offsetof(_odp_event_hdr_t, base_data),
	.user_area  = offsetof(_odp_event_hdr_t, user_area),
	.subtype    = offsetof(_odp_event_hdr_t, subtype),
	.flow_id    = offsetof(_odp_event_hdr_t, flow_id),
	.pool       = offsetof(_odp_event_hdr_t, pool),
};

#include <odp/visibility_end.h>

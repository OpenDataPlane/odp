/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_event.h>
#include <odp_buffer.h>
#include <odp_pool.h>
#include <odp_buffer_internal.h>

int odp_event_type(odp_event_t event)
{
	odp_buffer_t buf;

	buf = odp_buffer_from_event(event);

	switch (_odp_buffer_type(buf)) {
	case ODP_BUFFER_TYPE_RAW:
		return ODP_EVENT_BUFFER;
	case ODP_BUFFER_TYPE_PACKET:
		return ODP_EVENT_PACKET;
	case ODP_BUFFER_TYPE_TIMEOUT:
		return ODP_EVENT_TIMEOUT;
	default:
		return ODP_EVENT_TYPE_INVALID;
	}
}

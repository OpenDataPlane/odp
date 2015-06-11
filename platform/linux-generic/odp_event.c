/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/event.h>
#include <odp/buffer.h>
#include <odp/pool.h>
#include <odp_buffer_internal.h>
#include <odp_buffer_inlines.h>

int odp_event_type(odp_event_t event)
{
	return _odp_buffer_event_type(odp_buffer_from_event(event));
}

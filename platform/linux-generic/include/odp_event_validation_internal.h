/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#ifndef ODP_EVENT_VALIDATION_INTERNAL_H_
#define ODP_EVENT_VALIDATION_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/autoheader_external.h>

#include <odp/api/event.h>
#include <odp/api/hints.h>

#include <odp/api/plat/event_validation_external.h>

#include <odp_event_internal.h>

#include <stdint.h>

#if _ODP_EVENT_VALIDATION

#define _ODP_EV_ENDMARK_VAL  0xDEADBEEFDEADBEEF
#define _ODP_EV_ENDMARK_SIZE (sizeof(uint64_t))

static inline void _odp_event_endmark_set(odp_event_t event)
{
	uint64_t *endmark_ptr;

	endmark_ptr = _odp_event_endmark_get_ptr(event);
	*endmark_ptr = _ODP_EV_ENDMARK_VAL;
}

#else

#define _ODP_EV_ENDMARK_VAL  0
#define _ODP_EV_ENDMARK_SIZE 0

static inline void _odp_event_endmark_set(odp_event_t event ODP_UNUSED)
{
}

#endif

#ifdef __cplusplus
}
#endif
#endif

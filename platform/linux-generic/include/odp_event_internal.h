/* Copyright (c) 2021-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP event descriptor - implementation internal
 */

#ifndef ODP_EVENT_INTERNAL_H_
#define ODP_EVENT_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/debug.h>
#include <odp/api/event.h>
#include <odp/api/pool_types.h>
#include <odp/api/std_types.h>

#include <odp_config_internal.h>

/* Combined pool and event index */
typedef union _odp_event_index_t {
	uint32_t u32;

	struct {
		uint32_t pool   :8;
		uint32_t event  :24;
	};
} _odp_event_index_t;

/* Check that pool index fit into bit field */
ODP_STATIC_ASSERT(ODP_CONFIG_POOLS    <= (0xFF + 1), "TOO_MANY_POOLS");

/* Check that buffer index fit into bit field */
ODP_STATIC_ASSERT(CONFIG_POOL_MAX_NUM <= (0xFFFFFF + 1), "TOO_LARGE_POOL");

/* Type size limits number of flow IDs supported */
#define BUF_HDR_MAX_FLOW_ID 255

/* Common header for all event types without alignment constraints. */
typedef struct _odp_event_hdr_t {
	/* Initial buffer data pointer */
	uint8_t  *base_data;

	/* Pool handle */
	odp_pool_t pool;

	/* --- Mostly read only data --- */

	/* Initial buffer tail pointer and endmark location (if enabled) */
	uint8_t  *buf_end;

	/* Combined pool and event index */
	_odp_event_index_t index;

	/* Pool type */
	int8_t    type;

	/* Event type. Maybe different than pool type (crypto compl event) */
	int8_t    event_type;

	/* Event flow id */
	uint8_t   flow_id;

} _odp_event_hdr_t;

static inline odp_event_t _odp_event_from_hdr(_odp_event_hdr_t *hdr)
{
	return (odp_event_t)hdr;
}

static inline _odp_event_hdr_t *_odp_event_hdr(odp_event_t event)
{
	return (_odp_event_hdr_t *)(uintptr_t)event;
}

static inline void _odp_event_type_set(odp_event_t event, int ev)
{
	_odp_event_hdr(event)->event_type = ev;
}

static inline uint64_t *_odp_event_endmark_get_ptr(odp_event_t event)
{
	return (uint64_t *)(uintptr_t)_odp_event_hdr(event)->buf_end;
}

#ifdef __cplusplus
}
#endif

#endif

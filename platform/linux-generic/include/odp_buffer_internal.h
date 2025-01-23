/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2025 Nokia
 */

/**
 * @file
 *
 * ODP buffer descriptor - implementation internal
 */

#ifndef ODP_BUFFER_INTERNAL_H_
#define ODP_BUFFER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/atomic.h>
#include <odp/api/pool.h>
#include <odp/api/buffer.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp/api/byteorder.h>
#include <odp/api/thread.h>
#include <odp/api/event.h>

#include <odp_config_internal.h>
#include <odp_event_internal.h>
#include <odp_pool_internal.h>

#include <stddef.h>
#include <stdint.h>

/* Internal buffer header */
typedef struct ODP_ALIGNED_CACHE odp_buffer_hdr_t {
	/* Common event header */
	_odp_event_hdr_t event_hdr;

	/* User area pointer */
	void *uarea_addr;

	/* Data */
	uint8_t data[];
} odp_buffer_hdr_t;

/* Buffer header size is critical for performance. Ensure that it does not accidentally
 * grow over cache line size. Note that ODP_ALIGNED_CACHE rounds up struct size to a multiple of
 * ODP_CACHE_LINE_SIZE. */
ODP_STATIC_ASSERT(sizeof(odp_buffer_hdr_t) <= ODP_CACHE_LINE_SIZE, "BUFFER_HDR_SIZE_ERROR");

static inline odp_buffer_hdr_t *_odp_buf_hdr(odp_buffer_t buf)
{
	return (odp_buffer_hdr_t *)(uintptr_t)buf;
}

static inline void _odp_buffer_subtype_set(odp_buffer_t buffer, int subtype)
{
	odp_buffer_hdr_t *buf_hdr = _odp_buf_hdr(buffer);

	buf_hdr->event_hdr.subtype = subtype;
}

static inline uint32_t _odp_buffer_index(odp_buffer_t buf)
{
	return _odp_buf_hdr(buf)->event_hdr.index.event;
}

static inline void _odp_buffer_free_sp(const odp_buffer_t buf[], int num)
{
	_odp_event_free_sp((_odp_event_hdr_t **)(uintptr_t)buf, num);
}

#ifdef __cplusplus
}
#endif

#endif

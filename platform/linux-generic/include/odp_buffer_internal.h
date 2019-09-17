/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
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
#include <odp_align_internal.h>
#include <odp_config_internal.h>
#include <odp/api/byteorder.h>
#include <odp/api/thread.h>
#include <odp/api/event.h>
#include <odp_forward_typedefs_internal.h>
#include <odp_schedule_if.h>
#include <stddef.h>

typedef union buffer_index_t {
	uint32_t u32;

	struct {
		uint32_t pool   :8;
		uint32_t buffer :24;
	};
} buffer_index_t;

/* Check that pool index fit into bit field */
ODP_STATIC_ASSERT(ODP_CONFIG_POOLS    <= (0xFF + 1), "TOO_MANY_POOLS");

/* Check that buffer index fit into bit field */
ODP_STATIC_ASSERT(CONFIG_POOL_MAX_NUM <= (0xFFFFFF + 1), "TOO_LARGE_POOL");

/* Type size limits number of flow IDs supported */
#define BUF_HDR_MAX_FLOW_ID 255

/* Common buffer header */
struct ODP_ALIGNED_CACHE odp_buffer_hdr_t {
	/* Initial buffer data pointer */
	uint8_t  *base_data;

	/* Pool pointer */
	void     *pool_ptr;

	/* --- Mostly read only data --- */
	const void *user_ptr;

	/* Initial buffer tail pointer */
	uint8_t  *buf_end;

	/* User area pointer */
	void    *uarea_addr;

	/* ipc mapped process can not walk over pointers,
	 * offset has to be used */
	uint64_t ipc_data_offset;

	/* Combined pool and buffer index */
	buffer_index_t index;

	/* Reference count */
	odp_atomic_u32_t ref_cnt;

	/* Pool type */
	int8_t    type;

	/* Event type. Maybe different than pool type (crypto compl event) */
	int8_t    event_type;

	/* Event flow id */
	uint8_t   flow_id;

	/* Data or next header */
	uint8_t data[0];
};

odp_event_type_t _odp_buffer_event_type(odp_buffer_t buf);
void _odp_buffer_event_type_set(odp_buffer_t buf, int ev);
int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf);

static inline odp_buffer_t buf_from_buf_hdr(odp_buffer_hdr_t *hdr)
{
	return (odp_buffer_t)hdr;
}

static inline uint32_t event_flow_id(odp_event_t ev)
{
	odp_buffer_hdr_t *buf_hdr = (odp_buffer_hdr_t *)(uintptr_t)ev;

	return buf_hdr->flow_id;
}

static inline void event_flow_id_set(odp_event_t ev, uint32_t flow_id)
{
	odp_buffer_hdr_t *buf_hdr = (odp_buffer_hdr_t *)(uintptr_t)ev;

	buf_hdr->flow_id = flow_id;
}

#ifdef __cplusplus
}
#endif

#endif

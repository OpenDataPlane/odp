/* Copyright (c) 2013-2018, Linaro Limited
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

typedef struct seg_entry_t {
	void     *hdr;
	uint8_t  *data;
	uint32_t  len;
} seg_entry_t;

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

/* Common buffer header */
struct ODP_ALIGNED_CACHE odp_buffer_hdr_t {
	/* Combined pool and buffer index */
	buffer_index_t index;

	/* Total segment count */
	uint16_t  segcount;

	/* Pool type */
	int8_t    type;

	/* Number of seg[] entries used */
	uint8_t   num_seg;

	/* Next header which continues the segment list */
	void *next_seg;

	/* Last header of the segment list */
	void *last_seg;

	/* Initial buffer data pointer */
	uint8_t  *base_data;

	/* Pool pointer */
	void *pool_ptr;

	/* --- 40 bytes --- */

	/* Segments */
	seg_entry_t seg[CONFIG_PACKET_SEGS_PER_HDR];

	/* --- Mostly read only data --- */
	const void *user_ptr;

	/* Reference count */
	odp_atomic_u32_t ref_cnt;

	/* Event type. Maybe different than pool type (crypto compl event) */
	int8_t    event_type;

	/* Initial buffer tail pointer */
	uint8_t  *buf_end;

	/* User area pointer */
	void    *uarea_addr;

	/* ipc mapped process can not walk over pointers,
	 * offset has to be used */
	uint64_t ipc_data_offset;

	/* Data or next header */
	uint8_t data[0];
};

ODP_STATIC_ASSERT(CONFIG_PACKET_SEGS_PER_HDR < 256,
		  "CONFIG_PACKET_SEGS_PER_HDR_TOO_LARGE");

odp_event_type_t _odp_buffer_event_type(odp_buffer_t buf);
void _odp_buffer_event_type_set(odp_buffer_t buf, int ev);
int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf);

static inline odp_buffer_t buf_from_buf_hdr(odp_buffer_hdr_t *hdr)
{
	return (odp_buffer_t)hdr;
}

static inline odp_event_t event_from_buf_hdr(odp_buffer_hdr_t *hdr)
{
	return (odp_event_t)hdr;
}

#ifdef __cplusplus
}
#endif

#endif

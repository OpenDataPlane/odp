/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PACKET_TYPES_H_
#define ODP_PACKET_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 1
#include <odp/api/abi/packet.h>
#else

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>

/** @ingroup odp_packet
 *  @{
 */

typedef ODP_HANDLE_T(odp_packet_t);

#define ODP_PACKET_INVALID _odp_cast_scalar(odp_packet_t, 0)

#define ODP_PACKET_OFFSET_INVALID (0x0fffffff)

typedef uint8_t odp_packet_seg_t;

#define ODP_PACKET_SEG_INVALID ((odp_packet_seg_t)-1)

typedef enum {
	ODP_PACKET_GREEN = 0,
	ODP_PACKET_YELLOW = 1,
	ODP_PACKET_RED = 2,
	ODP_PACKET_ALL_COLORS = 3,
} odp_packet_color_t;

#define ODP_NUM_PACKET_COLORS 3

/**
 * @}
 */

#endif

/** @internal Packet header field offsets for inline functions */
typedef struct _odp_packet_inline_offset_t {
	/** @internal field offset */
	size_t data;
	/** @internal field offset */
	size_t seg_len;
	/** @internal field offset */
	size_t frame_len;
	/** @internal field offset */
	size_t headroom;
	/** @internal field offset */
	size_t tailroom;
	/** @internal field offset */
	size_t pool;
	/** @internal field offset */
	size_t input;
	/** @internal field offset */
	size_t segcount;
	/** @internal field offset */
	size_t user_ptr;
	/** @internal field offset */
	size_t user_area;
	/** @internal field offset */
	size_t user_area_size;
	/** @internal field offset */
	size_t flow_hash;
	/** @internal field offset */
	size_t timestamp;

} _odp_packet_inline_offset_t;

#ifdef __cplusplus
}
#endif

#endif

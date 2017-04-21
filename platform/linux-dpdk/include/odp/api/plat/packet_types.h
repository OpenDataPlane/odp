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

#define ODP_PACKET_INVALID _odp_cast_scalar(odp_packet_t, NULL)

#define ODP_PACKET_OFFSET_INVALID (0x0fffffff)

typedef ODP_HANDLE_T(odp_packet_seg_t);

#define ODP_PACKET_SEG_INVALID _odp_cast_scalar(odp_packet_seg_t, NULL)

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

#ifdef __cplusplus
}
#endif

#endif

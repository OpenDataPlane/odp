/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_PACKET_H_
#define ODP_ABI_PACKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_packet_t;

/** @internal Dummy  type for strong typing */
typedef struct { char dummy; /**< *internal Dummy */ } _odp_abi_packet_seg_t;

/** @ingroup odp_packet
 *  @{
 */

typedef _odp_abi_packet_t *odp_packet_t;
typedef _odp_abi_packet_seg_t *odp_packet_seg_t;

#define ODP_PACKET_INVALID        ((odp_packet_t)0xffffffff)
#define ODP_PACKET_SEG_INVALID    ((odp_packet_seg_t)0xffffffff)
#define ODP_PACKET_OFFSET_INVALID (0x0fffffff)

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

#ifdef __cplusplus
}
#endif

#endif

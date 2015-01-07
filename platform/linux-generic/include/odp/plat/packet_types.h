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


#include <odp/plat/buffer_types.h>

/** @addtogroup odp_packet ODP PACKET
 *  Operations on a packet.
 *  @{
 */

typedef odp_buffer_t odp_packet_t;

#define ODP_PACKET_INVALID ODP_BUFFER_INVALID

#define ODP_PACKET_OFFSET_INVALID (0x0fffffff)

typedef odp_buffer_t odp_packet_seg_t;

#define ODP_PACKET_SEG_INVALID ODP_BUFFER_INVALID

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

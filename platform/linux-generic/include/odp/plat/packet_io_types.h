/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Packet IO
 */

#ifndef ODP_PACKET_IO_TYPES_H_
#define ODP_PACKET_IO_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_packet_io ODP PACKET IO
 *  Operations on a packet.
 *  @{
 */

typedef uint32_t odp_pktio_t;

#define ODP_PKTIO_INVALID 0

#define ODP_PKTIO_ANY ((odp_pktio_t)~0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

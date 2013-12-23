/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PACKET_H_
#define ODP_PACKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_buffer.h>


/**
 * ODP packet descriptor
 */
typedef uint32_t odp_packet_t;

#define ODP_PACKET_INVALID ODP_BUFFER_INVALID


void odp_packet_init(odp_packet_t pkt);

void odp_packet_print(odp_packet_t pkt);

odp_packet_t odp_packet_from_buffer(odp_buffer_t buf);
odp_buffer_t odp_buffer_from_packet(odp_packet_t pkt);

void odp_packet_set_len(odp_packet_t pkt, size_t len);
size_t odp_packet_get_len(odp_packet_t pkt);

uint8_t *odp_packet_payload(odp_packet_t pkt);

#ifdef __cplusplus
}
#endif

#endif








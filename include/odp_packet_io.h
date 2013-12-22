/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Linaro Limited nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIALDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


/**
 * @file
 *
 * ODP buffer descriptor
 */

#ifndef ODP_PACKET_IO_H_
#define ODP_PACKET_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_buffer_pool.h>
#include <odp_packet.h>
#include <odp_queue.h>

/** ODP packet IO handle */
typedef int odp_pktio_t;
#define ODP_PKTIO_INVALID 0

/**
 * Open an ODP packet IO instance
 *
 * @param dev   Packet IO device
 * @param pool  Pool to use for packet IO
 *
 * @return ODP packet IO handle or ODP_PKTIO_INVALID on error
 */
odp_pktio_t odp_pktio_open(char *dev, odp_buffer_pool_t pool);

/**
 * Close an ODP packet IO instance
 *
 * @param id  ODP packet IO handle
 *
 * @return 0 on success or -1 on error
 */
int odp_pktio_close(odp_pktio_t id);

/**
 * Receive packets
 *
 * @param id          ODP packet IO handle
 * @param pkt_table[] Storage for received packets (filled by function)
 * @param len         Length of pkt_table[], i.e. max number of pkts to receive
 *
 * @return Number of packets received or -1 on error
 */
int odp_pktio_recv(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len);

/**
 * Send packets
 *
 * @param id           ODP packet IO handle
 * @param pkt_table[]  Array of packets to send
 * @param len          length of pkt_table[]
 *
 * @return Number of packets sent or -1 on error
 */
int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], unsigned len);

/**
 * Set the default input queue to be associated with a pktio handle
 *
 * @param
 */
int odp_pktio_inq_setdef(odp_pktio_t id, odp_queue_t queue);

/**
 * Get default input queue associated with a pktio handle
 *
 * @param id  ODP packet IO handle
 *
 * @return Default input queue set or ODP_QUEUE_INVALID on error
 */
odp_queue_t odp_pktio_inq_getdef(odp_pktio_t id);

/**
 * Remove default input queue (if set)
 *
 * @param id  ODP packet IO handle
 *
 * @return 0 on success or -1 on error
 */
int odp_pktio_inq_remdef(odp_pktio_t id);

/**
 * Query default output queue
 *
 * @param id ODP packet IO handle
 *
 * @return Default out queue or ODP_QUEUE_INVALID on error
 */
odp_queue_t odp_pktio_outq_getdef(odp_pktio_t id);

/**
 * Store packet input handle into packet
 *
 * @param pkt  ODP packet buffer handle
 * @param id   ODP packet IO handle
 *
 * @return
 */
void odp_pktio_set_input(odp_packet_t pkt, odp_pktio_t id);

/**
 * Get stored packet input handle from packet
 *
 * @param pkt  ODP packet buffer handle
 *
 * @return Packet IO handle
 */
odp_pktio_t odp_pktio_get_input(odp_packet_t pkt);

#ifdef __cplusplus
}
#endif

#endif


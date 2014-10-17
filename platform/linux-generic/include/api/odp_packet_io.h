/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Packet IO
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
typedef uint32_t odp_pktio_t;

/** Invalid packet IO handle */
#define ODP_PKTIO_INVALID 0

/**
 * odp_pktio_t value to indicate any port
 */
#define ODP_PKTIO_ANY ((odp_pktio_t)~0)

/**
 * Open an ODP packet IO instance
 *
 * @param dev    Packet IO device
 * @param pool   Pool to use for packet IO
 *
 * @return ODP packet IO handle or ODP_PKTIO_INVALID on error
 */
odp_pktio_t odp_pktio_open(const char *dev, odp_buffer_pool_t pool);

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
 * @param id	ODP packet IO handle
 * @param queue default input queue set
 * @return  0 on success or -1 on error
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

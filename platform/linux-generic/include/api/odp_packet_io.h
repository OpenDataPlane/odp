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
#include <odp_platform_types.h>
#include <odp_buffer_pool.h>
#include <odp_packet.h>
#include <odp_queue.h>

/** @defgroup odp_packet_io ODP PACKET IO
 *  Operations on a packet.
 *  @{
 */

/**
 * Open an ODP packet IO instance
 *
 * @param dev    Packet IO device
 * @param pool   Pool to use for packet IO
 *
 * @return ODP packet IO handle or ODP_PKTIO_INVALID on error
 *
 * @note dev name loop is specially pktio reserved name for
 *	 device used for testing. Usually it's loop back
 *	 interface.
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

/**
 * Configure the MTU for a packet IO interface.
 *
 * @param[in] id   ODP packet IO handle.
 * @param[in] mtu  The value of MTU that the interface will be configured to
 *		   use.
 *
 * @retval  0 on success.
 * @retval -1 if specified mtu can not be handled.
 * @retval -1 on any other error or illegal input parameters.
 */
int odp_pktio_set_mtu(odp_pktio_t id, int mtu);

/**
 * Return the currently configured MTU value of a packet IO interface.
 *
 * @param[in] id  ODP packet IO handle.
 *
 * @retval MTU value >0 on success.
 * @retval -1 on any error or not existance pktio id.
 */
int odp_pktio_mtu(odp_pktio_t id);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

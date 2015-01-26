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
#include <odp_pool.h>
#include <odp_packet.h>
#include <odp_queue.h>

/** @defgroup odp_packet_io ODP PACKET IO
 *  Operations on a packet.
 *  @{
 */

/**
 * Open an ODP packet IO instance
 *
 * Packet IO handles are single instance per device, attempts to open an already
 * open device will fail, returning ODP_PKTIO_INVALID with errno set to -EEXIST.
 * odp_pktio_lookup() may be used to obtain a handle to an already open device.
 *
 * @param dev    Packet IO device name
 * @param pool   Pool from which to allocate buffers for storing packets
 *               received over this packet IO
 *
 * @return ODP packet IO handle or ODP_PKTIO_INVALID on error
 *
 * @note dev name loop is specially pktio reserved name for
 *	 device used for testing. Usually it's loop back
 *	 interface.
 */
odp_pktio_t odp_pktio_open(const char *dev, odp_pool_t pool);

/**
 * Close an ODP packet IO instance
 *
 * @param id  ODP packet IO handle
 *
 * @return 0 on success or -1 on error
 */
int odp_pktio_close(odp_pktio_t id);

/**
 * Return a packet IO handle for an already open device
 *
 * @param dev Packet IO device name
 *
 * @return ODP packet IO handle or ODP_PKTIO_INVALID
 */
odp_pktio_t odp_pktio_lookup(const char *dev);

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
 * Return the currently configured MTU value of a packet IO interface.
 *
 * @param[in] id  ODP packet IO handle.
 *
 * @retval MTU value >0 on success.
 * @retval -1 on any error or not existance pktio id.
 */
int odp_pktio_mtu(odp_pktio_t id);

/**
 * Enable/Disable promiscuous mode on a packet IO interface.
 *
 * @param[in] id	ODP packet IO handle.
 * @param[in] enable	1 to enable, 0 to disable.
 *
 * @retval 0 on success.
 * @retval non-zero on any error.
 */
int odp_pktio_promisc_mode_set(odp_pktio_t id, odp_bool_t enable);

/**
 * Determine if promiscuous mode is enabled for a packet IO interface.
 *
 * @param[in] id ODP packet IO handle.
 *
 * @retval  1 if promiscuous mode is enabled.
 * @retval  0 if promiscuous mode is disabled.
 * @retval -1 on any error.
*/
int odp_pktio_promisc_mode(odp_pktio_t id);

/**
 * Get the default MAC address of a packet IO interface.
 *
 * @param	id	  ODP packet IO handle.
 * @param[out]	mac_addr  Storage for MAC address of the packet IO interface.
 * @param	addr_size Storage size for the address
 *
 * @retval Number of bytes written on success, 0 on failure.
 */
size_t odp_pktio_mac_addr(odp_pktio_t id, void *mac_addr,
			  size_t addr_size);

/**
 * Setup per-port default class-of-service.
 *
 * @param[in]	pktio_in	Ingress port identifier.
 * @param[in]	default_cos	Class-of-service set to all packets arriving
 *				at the pktio_in ingress port,
 *				unless overridden by subsequent
 *				header-based filters.
 *
 * @return			0 on success, non-zero on error.
 */
int odp_pktio_default_cos_set(odp_pktio_t pktio_in, odp_cos_t default_cos);

/**
 * Setup per-port error class-of-service
 *
 * @param[in]	pktio_in	Ingress port identifier.
 * @param[in]	error_cos	class-of-service set to all packets arriving
 *				at the pktio_in ingress port
 *				that contain an error.
 *
 * @return			0 on success, non-zero on error.
 *
 * @note Optional.
 */
int odp_pktio_error_cos_set(odp_pktio_t pktio_in, odp_cos_t error_cos);

/**
 * Setup per-port header offset
 *
 * @param[in]	pktio_in	Ingress port identifier.
 * @param[in]	offset		Number of bytes the classifier must skip.
 *
 * @return			0 on success, non-zero on error.
 * @note  Optional.
 *
 */
int odp_pktio_skip_set(odp_pktio_t pktio_in, uint32_t offset);

/**
 * Specify per-port buffer headroom
 *
 * @param[in]	pktio_in	Ingress port identifier.
 * @param[in]	headroom	Number of bytes of space preceding
 *				packet data to reserve for use as headroom.
 *				Must not exceed the implementation
 *				defined ODP_PACKET_MAX_HEADROOM.
 *
 * @return			0 on success, non-zero on error.
 *
 * @note Optional.
 */
int odp_pktio_headroom_set(odp_pktio_t pktio_in, uint32_t headroom);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_NETMAP_H
#define ODP_PACKET_NETMAP_H

#include <odp/pool.h>

#include <linux/if_ether.h>

/** Packet socket using netmap mmaped rings for both Rx and Tx */
typedef struct {
	odp_pool_t pool;		/**< pool to alloc packets from */
	size_t max_frame_len;		/**< buf_size - sizeof(pkt_hdr) */
	struct nm_desc *desc;		/**< netmap meta-data for the device */
	uint32_t if_flags;		/**< interface flags */
	int sockfd;			/**< control socket */
	unsigned char if_mac[ETH_ALEN]; /**< eth mac address */
} pkt_netmap_t;

#endif

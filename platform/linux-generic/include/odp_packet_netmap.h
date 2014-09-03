/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_NETMAP_H
#define ODP_PACKET_NETMAP_H

#include <stdint.h>

#include <net/if.h>
#include <net/netmap.h>
#include <net/netmap_user.h>

#include <odp_align.h>
#include <odp_debug.h>
#include <odp_buffer_pool.h>
#include <odp_packet.h>

#include <odp_pktio_netmap.h>

#define ODP_NETMAP_MODE_HW	0
#define ODP_NETMAP_MODE_SW	1

#define NETMAP_BLOCKING_IO

/** Packet socket using netmap mmaped rings for both Rx and Tx */
typedef struct {
	odp_buffer_pool_t pool;
	size_t max_frame_len; /**< max frame len = buf_size - sizeof(pkt_hdr) */
	size_t frame_offset; /**< frame start offset from start of pkt buf */
	size_t buf_size; /**< size of buffer payload in 'pool' */
	int netmap_mode;
	struct nm_desc_t *nm_desc;
	uint32_t begin;
	uint32_t end;
	struct netmap_ring *rxring;
	struct netmap_ring *txring;
	odp_queue_t tx_access; /* Used for exclusive access to send packets */
	uint32_t if_flags;
	char ifname[32];
} pkt_netmap_t;

/**
 * Configure an interface to work in netmap mode
 */
int setup_pkt_netmap(pkt_netmap_t * const pkt_nm, const char *netdev,
		     odp_buffer_pool_t pool, netmap_params_t *nm_params);

/**
 * Switch interface from netmap mode to normal mode
 */
int close_pkt_netmap(pkt_netmap_t * const pkt_nm);

/**
 * Receive packets using netmap
 */
int recv_pkt_netmap(pkt_netmap_t * const pkt_nm, odp_packet_t pkt_table[],
		    unsigned len);

/**
 * Send packets using netmap
 */
int send_pkt_netmap(pkt_netmap_t * const pkt_nm, odp_packet_t pkt_table[],
		    unsigned len);
#endif

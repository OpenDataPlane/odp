/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_SOCKET_H
#define ODP_PACKET_SOCKET_H

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <string.h>

#include <odp/align.h>
#include <odp/buffer.h>
#include <odp/debug.h>
#include <odp/pool.h>
#include <odp/packet.h>

#include <linux/version.h>

/*
 * Packet socket config:
 */

/** Max receive (Rx) burst size*/
#define ODP_PACKET_SOCKET_MAX_BURST_RX 32
/** Max transmit (Tx) burst size*/
#define ODP_PACKET_SOCKET_MAX_BURST_TX 32

/*
 * This makes sure that building for kernels older than 3.1 works
 * and a fanout requests fails (for invalid packet socket option)
 * in runtime if requested
 */
#ifndef PACKET_FANOUT
#define PACKET_FANOUT		18
#define PACKET_FANOUT_HASH	0
#endif /* PACKET_FANOUT */

typedef struct {
	int sockfd; /**< socket descriptor */
	odp_pool_t pool; /**< pool to alloc packets from */
	size_t buf_size; /**< size of buffer payload in 'pool' */
	size_t max_frame_len; /**< max frame len = buf_size - sizeof(pkt_hdr) */
	size_t frame_offset; /**< frame start offset from start of pkt buf */
	unsigned char if_mac[ETH_ALEN];	/**< IF eth mac addr */
} pkt_sock_t;

/** packet mmap ring */
struct ring {
	struct iovec *rd;
	unsigned frame_num;
	int rd_num;

	int sock;
	int type;
	int version;
	uint8_t *mm_space;
	size_t mm_len;
	size_t rd_len;
	int flen;

	struct tpacket_req req;
};
_ODP_STATIC_ASSERT(offsetof(struct ring, mm_space) <= ODP_CACHE_LINE_SIZE,
		   "ERR_STRUCT_RING");

/** Packet socket using mmap rings for both Rx and Tx */
typedef struct {
	/** Packet mmap ring for Rx */
	struct ring rx_ring ODP_ALIGNED_CACHE;
	/** Packet mmap ring for Tx */
	struct ring tx_ring ODP_ALIGNED_CACHE;

	int sockfd ODP_ALIGNED_CACHE;
	odp_pool_t pool;
	size_t frame_offset; /**< frame start offset from start of pkt buf */
	uint8_t *mmap_base;
	unsigned mmap_len;
	unsigned char if_mac[ETH_ALEN];
	struct sockaddr_ll ll;
	int fanout;
} pkt_sock_mmap_t;

static inline void
ethaddr_copy(unsigned char mac_dst[], unsigned char mac_src[])
{
	memcpy(mac_dst, mac_src, ETH_ALEN);
}

static inline int
ethaddrs_equal(unsigned char mac_a[], unsigned char mac_b[])
{
	return !memcmp(mac_a, mac_b, ETH_ALEN);
}

/**
 * Open & configure a raw packet socket
 */
int sock_setup_pkt(pkt_sock_t * const pkt_sock, const char *netdev,
		   odp_pool_t pool);

int sock_mmap_setup_pkt(pkt_sock_mmap_t * const pkt_sock, const char *netdev,
			odp_pool_t pool, int fanout);

/**
 * Close a packet socket
 */
int sock_close_pkt(pkt_sock_t * const pkt_sock);

int sock_mmap_close_pkt(pkt_sock_mmap_t * const pkt_sock);

/**
 * Receive packets from the packet socket
 */
int sock_basic_recv_pkt(pkt_sock_t * const pkt_sock, odp_packet_t pkt_table[],
			unsigned len);

int sock_mmsg_recv_pkt(pkt_sock_t * const pkt_sock, odp_packet_t pkt_table[],
		       unsigned len);

int sock_mmap_recv_pkt(pkt_sock_mmap_t * const pkt_sock,
		       odp_packet_t pkt_table[], unsigned len);
/**
 * Send packets through the packet socket
 */
int sock_basic_send_pkt(pkt_sock_t * const pkt_sock, odp_packet_t pkt_table[],
			unsigned len);

int sock_mmsg_send_pkt(pkt_sock_t * const pkt_sock, odp_packet_t pkt_table[],
		       unsigned len);

int sock_mmap_send_pkt(pkt_sock_mmap_t * const pkt_sock,
		       odp_packet_t pkt_table[], unsigned len);
#endif

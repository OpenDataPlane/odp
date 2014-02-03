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

#include <odp_align.h>
#include <odp_buffer.h>
#include <odp_debug.h>
#include <odp_buffer_pool.h>
#include <odp_packet.h>

#include <linux/version.h>


/*
 * Packet socket config:
 */
#define ODP_PACKET_SOCKET_BASIC 0 /** use recv()/send() */
#define ODP_PACKET_SOCKET_MMSG  1 /** use recvmmsg()/sendmmsg() */
#define ODP_PACKET_SOCKET_MMAP  2 /** use PACKET_MMAP */


#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 1, 0)
/* PACKET_FANOUT feature not supported */
#define ODP_PACKET_SOCKET_FANOUT 0
#define ODP_PACKET_SOCKET_MODE (ODP_PACKET_SOCKET_BASIC)
#else
/** PACKET_FANOUT mode spreads incoming packets over multiple sockets*/
#define ODP_PACKET_SOCKET_FANOUT 1 /* 0=Off, 1=On */
/** Choose one from the alternatives above */
#define ODP_PACKET_SOCKET_MODE (ODP_PACKET_SOCKET_MMAP)
#endif


/** Max receive (Rx) burst size*/
#define ODP_PACKET_SOCKET_MAX_BURST_RX 32
/** Max transmit (Tx) burst size*/
#define ODP_PACKET_SOCKET_MAX_BURST_TX 32



#if (ODP_PACKET_SOCKET_MODE == ODP_PACKET_SOCKET_BASIC) || \
	(ODP_PACKET_SOCKET_MODE == ODP_PACKET_SOCKET_MMSG)

typedef struct {
	int sockfd; /**< socket descriptor */
	odp_buffer_pool_t pool; /**< buffer pool to alloc packets from */
	size_t buf_size; /**< size of buffer payload in 'pool' */
	size_t max_frame_len; /**< max frame len = buf_size - sizeof(pkt_hdr) */
	size_t l2_offset; /**< l2 hdr start offset from start of pkt payload */
	unsigned char if_mac[ETH_ALEN];	/**< IF eth mac addr */
} pkt_sock_t;

#elif ODP_PACKET_SOCKET_MODE == ODP_PACKET_SOCKET_MMAP

#if ODP_PACKET_SOCKET_FANOUT == 0
#error "ODP_PACKET_SOCKET_MMAP requires ODP_PACKET_SOCKET_FANOUT=1"
#endif

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
ODP_ASSERT(offsetof(struct ring, mm_space) <= ODP_CACHE_LINE_SIZE,
	   ERR_STRUCT_RING);

/** Packet socket using mmap rings for both Rx and Tx */
typedef struct {
	/** Packet mmap ring for Rx */
	struct ring rx_ring ODP_ALIGNED_CACHE;
	/** Packet mmap ring for Tx */
	struct ring tx_ring ODP_ALIGNED_CACHE;

	int sockfd ODP_ALIGNED_CACHE;
	odp_buffer_pool_t pool;
	size_t l2_offset; /**< l2 hdr start offset from start of pkt payload */
	uint8_t *mmap_base;
	unsigned mmap_len;
	unsigned char if_mac[ETH_ALEN];
	struct sockaddr_ll ll;
} pkt_sock_t;

#else
#error "Unsupported ODP_PACKET_SOCKET_MODE!"
#endif

/**
 * Open & configure a raw packet socket
 */
int setup_pkt_sock(pkt_sock_t * const pkt_sock, char *netdev,
		   odp_buffer_pool_t pool);
/**
 * Close a packet socket
 */
int close_pkt_sock(pkt_sock_t * const pkt_sock);

/**
 * Receive packets from the packet socket
 */
int recv_pkt_sock(pkt_sock_t * const pkt_sock, odp_packet_t pkt_table[],
		  unsigned len);
/**
 * Send packets through the packet socket
 */
int send_pkt_sock(pkt_sock_t * const pkt_sock, odp_packet_t pkt_table[],
		  unsigned len);

#endif

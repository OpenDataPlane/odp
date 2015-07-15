/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <odp_packet_io_internal.h>

#include <sys/socket.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <bits/wordsize.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <odp.h>
#include <odp_packet_socket.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_debug_internal.h>
#include <odp/hints.h>

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

static int set_pkt_sock_fanout_mmap(pkt_sock_mmap_t *const pkt_sock,
				    int sock_group_idx)
{
	int sockfd = pkt_sock->sockfd;
	int val;
	int err;
	uint16_t fanout_group;

	fanout_group = (uint16_t)(sock_group_idx & 0xffff);
	val = (PACKET_FANOUT_HASH << 16) | fanout_group;

	err = setsockopt(sockfd, SOL_PACKET, PACKET_FANOUT, &val, sizeof(val));
	if (err != 0) {
		__odp_errno = errno;
		ODP_ERR("setsockopt(PACKET_FANOUT): %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

union frame_map {
	struct {
		struct tpacket2_hdr tp_h ODP_ALIGNED(TPACKET_ALIGNMENT);
		struct sockaddr_ll s_ll
		ODP_ALIGNED(TPACKET_ALIGN(sizeof(struct tpacket2_hdr)));
	} *v2;

	void *raw;
};

static int mmap_pkt_socket(void)
{
	int ver = TPACKET_V2;

	int ret, sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sock == -1) {
		__odp_errno = errno;
		ODP_ERR("socket(SOCK_RAW): %s\n", strerror(errno));
		return -1;
	}

	ret = setsockopt(sock, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
	if (ret == -1) {
		__odp_errno = errno;
		ODP_ERR("setsockopt(PACKET_VERSION): %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

static inline int mmap_rx_kernel_ready(struct tpacket2_hdr *hdr)
{
	return ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER);
}

static inline void mmap_rx_user_ready(struct tpacket2_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_KERNEL;
	__sync_synchronize();
}

static inline int mmap_tx_kernel_ready(struct tpacket2_hdr *hdr)
{
	return !(hdr->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING));
}

static inline void mmap_tx_user_ready(struct tpacket2_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_SEND_REQUEST;
	__sync_synchronize();
}

static inline unsigned pkt_mmap_v2_rx(int sock, struct ring *ring,
				      odp_packet_t pkt_table[], unsigned len,
				      odp_pool_t pool,
				      unsigned char if_mac[])
{
	union frame_map ppd;
	unsigned frame_num, next_frame_num;
	uint8_t *pkt_buf;
	int pkt_len;
	struct ethhdr *eth_hdr;
	unsigned i = 0;

	(void)sock;

	frame_num = ring->frame_num;

	while (i < len) {
		if (mmap_rx_kernel_ready(ring->rd[frame_num].iov_base)) {
			ppd.raw = ring->rd[frame_num].iov_base;

			next_frame_num = (frame_num + 1) % ring->rd_num;

			pkt_buf = (uint8_t *)ppd.raw + ppd.v2->tp_h.tp_mac;
			pkt_len = ppd.v2->tp_h.tp_snaplen;

			/* Don't receive packets sent by ourselves */
			eth_hdr = (struct ethhdr *)pkt_buf;
			if (odp_unlikely(ethaddrs_equal(if_mac,
							eth_hdr->h_source))) {
				mmap_rx_user_ready(ppd.raw); /* drop */
				frame_num = next_frame_num;
				continue;
			}

			pkt_table[i] = odp_packet_alloc(pool, pkt_len);
			if (odp_unlikely(pkt_table[i] == ODP_PACKET_INVALID))
				break;

			if (odp_packet_copydata_in(pkt_table[i], 0,
						   pkt_len, pkt_buf) != 0) {
				odp_packet_free(pkt_table[i]);
				break;
			}

			mmap_rx_user_ready(ppd.raw);

			/* Parse and set packet header data */
			_odp_packet_reset_parse(pkt_table[i]);

			frame_num = next_frame_num;
			i++;
		} else {
			break;
		}
	}

	ring->frame_num = frame_num;

	return i;
}

static inline unsigned pkt_mmap_v2_tx(int sock, struct ring *ring,
				      odp_packet_t pkt_table[], unsigned len)
{
	union frame_map ppd;
	uint32_t pkt_len;
	unsigned frame_num, next_frame_num;
	int ret;
	unsigned i = 0;

	frame_num = ring->frame_num;

	while (i < len) {
		if (mmap_tx_kernel_ready(ring->rd[frame_num].iov_base)) {
			ppd.raw = ring->rd[frame_num].iov_base;

			next_frame_num = (frame_num + 1) % ring->rd_num;

			pkt_len = odp_packet_len(pkt_table[i]);
			ppd.v2->tp_h.tp_snaplen = pkt_len;
			ppd.v2->tp_h.tp_len = pkt_len;

			odp_packet_copydata_out(pkt_table[i], 0, pkt_len,
						(uint8_t *)ppd.raw +
						TPACKET2_HDRLEN -
						sizeof(struct sockaddr_ll));

			mmap_tx_user_ready(ppd.raw);

			odp_packet_free(pkt_table[i]);
			frame_num = next_frame_num;
			i++;
		} else {
			break;
		}
	}

	ring->frame_num = frame_num;

	ret = sendto(sock, NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret == -1) {
		if (errno != EAGAIN) {
			__odp_errno = errno;
			ODP_ERR("sendto(pkt mmap): %s\n", strerror(errno));
			return -1;
		}
	}

	return i;
}

static void mmap_fill_ring(struct ring *ring, odp_pool_t pool_hdl, int fanout)
{
	/*@todo add Huge Pages support*/
	int pz = getpagesize();
	uint32_t pool_id;
	pool_entry_t *pool_entry;

	if (pool_hdl == ODP_POOL_INVALID)
		ODP_ABORT("Invalid pool handle\n");

	pool_id = pool_handle_to_index(pool_hdl);
	pool_entry = get_pool_entry(pool_id);

	/* Frame has to capture full packet which can fit to the pool block.*/
	ring->req.tp_frame_size = (pool_entry->s.blk_size +
				   TPACKET_HDRLEN + TPACKET_ALIGNMENT +
				   + (pz - 1)) & (-pz);

	/* Calculate how many pages do we need to hold all pool packets
	*  and align size to page boundary.
	*/
	ring->req.tp_block_size = (ring->req.tp_frame_size *
				   pool_entry->s.buf_num + (pz - 1)) & (-pz);

	if (!fanout) {
		/* Single socket is in use. Use 1 block with buf_num frames. */
		ring->req.tp_block_nr = 1;
	} else {
		/* Fanout is in use, more likely taffic split accodring to
		 * number of cpu threads. Use cpu blocks and buf_num frames. */
		ring->req.tp_block_nr = odp_cpu_count();
	}

	ring->req.tp_frame_nr = ring->req.tp_block_size /
				ring->req.tp_frame_size * ring->req.tp_block_nr;

	ring->mm_len = ring->req.tp_block_size * ring->req.tp_block_nr;
	ring->rd_num = ring->req.tp_frame_nr;
	ring->flen = ring->req.tp_frame_size;
}

static int mmap_set_packet_loss_discard(int sock)
{
	int ret, discard = 1;

	ret = setsockopt(sock, SOL_PACKET, PACKET_LOSS, (void *)&discard,
			 sizeof(discard));
	if (ret == -1) {
		__odp_errno = errno;
		ODP_ERR("setsockopt(PACKET_LOSS): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int mmap_setup_ring(int sock, struct ring *ring, int type,
			   odp_pool_t pool_hdl, int fanout)
{
	int ret = 0;

	ring->sock = sock;
	ring->type = type;
	ring->version = TPACKET_V2;

	if (type == PACKET_TX_RING) {
		ret = mmap_set_packet_loss_discard(sock);
		if (ret != 0)
			return -1;
	}

	mmap_fill_ring(ring, pool_hdl, fanout);

	ret = setsockopt(sock, SOL_PACKET, type, &ring->req, sizeof(ring->req));
	if (ret == -1) {
		__odp_errno = errno;
		ODP_ERR("setsockopt(pkt mmap): %s\n", strerror(errno));
		return -1;
	}

	ring->rd_len = ring->rd_num * sizeof(*ring->rd);
	ring->rd = malloc(ring->rd_len);
	if (!ring->rd) {
		__odp_errno = errno;
		ODP_ERR("malloc(): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int mmap_sock(pkt_sock_mmap_t *pkt_sock)
{
	int i;
	int sock = pkt_sock->sockfd;

	/* map rx + tx buffer to userspace : they are in this order */
	pkt_sock->mmap_len =
		pkt_sock->rx_ring.req.tp_block_size *
		pkt_sock->rx_ring.req.tp_block_nr +
		pkt_sock->tx_ring.req.tp_block_size *
		pkt_sock->tx_ring.req.tp_block_nr;

	pkt_sock->mmap_base =
		mmap(NULL, pkt_sock->mmap_len, PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_LOCKED | MAP_POPULATE, sock, 0);

	if (pkt_sock->mmap_base == MAP_FAILED) {
		__odp_errno = errno;
		ODP_ERR("mmap rx&tx buffer failed: %s\n", strerror(errno));
		return -1;
	}

	pkt_sock->rx_ring.mm_space = pkt_sock->mmap_base;
	memset(pkt_sock->rx_ring.rd, 0, pkt_sock->rx_ring.rd_len);
	for (i = 0; i < pkt_sock->rx_ring.rd_num; ++i) {
		pkt_sock->rx_ring.rd[i].iov_base =
			pkt_sock->rx_ring.mm_space
			+ (i * pkt_sock->rx_ring.flen);
		pkt_sock->rx_ring.rd[i].iov_len = pkt_sock->rx_ring.flen;
	}

	pkt_sock->tx_ring.mm_space =
		pkt_sock->mmap_base + pkt_sock->rx_ring.mm_len;
	memset(pkt_sock->tx_ring.rd, 0, pkt_sock->tx_ring.rd_len);
	for (i = 0; i < pkt_sock->tx_ring.rd_num; ++i) {
		pkt_sock->tx_ring.rd[i].iov_base =
			pkt_sock->tx_ring.mm_space
			+ (i * pkt_sock->tx_ring.flen);
		pkt_sock->tx_ring.rd[i].iov_len = pkt_sock->tx_ring.flen;
	}

	return 0;
}

static void mmap_unmap_sock(pkt_sock_mmap_t *pkt_sock)
{
	munmap(pkt_sock->mmap_base, pkt_sock->mmap_len);
	free(pkt_sock->rx_ring.rd);
	free(pkt_sock->tx_ring.rd);
}

static int mmap_bind_sock(pkt_sock_mmap_t *pkt_sock, const char *netdev)
{
	int ret;

	pkt_sock->ll.sll_family = PF_PACKET;
	pkt_sock->ll.sll_protocol = htons(ETH_P_ALL);
	pkt_sock->ll.sll_ifindex = if_nametoindex(netdev);
	pkt_sock->ll.sll_hatype = 0;
	pkt_sock->ll.sll_pkttype = 0;
	pkt_sock->ll.sll_halen = 0;

	ret = bind(pkt_sock->sockfd, (struct sockaddr *)&pkt_sock->ll,
		   sizeof(pkt_sock->ll));
	if (ret == -1) {
		__odp_errno = errno;
		ODP_ERR("bind(to IF): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int mmap_store_hw_addr(pkt_sock_mmap_t *const pkt_sock,
			      const char *netdev)
{
	struct ifreq ethreq;
	int ret;

	/* get MAC address */
	memset(&ethreq, 0, sizeof(ethreq));
	snprintf(ethreq.ifr_name, IF_NAMESIZE, "%s", netdev);
	ret = ioctl(pkt_sock->sockfd, SIOCGIFHWADDR, &ethreq);
	if (ret != 0) {
		__odp_errno = errno;
		ODP_ERR("ioctl(SIOCGIFHWADDR): %s: \"%s\".\n",
			strerror(errno),
			ethreq.ifr_name);
		return -1;
	}

	ethaddr_copy(pkt_sock->if_mac,
		     (unsigned char *)ethreq.ifr_ifru.ifru_hwaddr.sa_data);

	return 0;
}

static int sock_mmap_close_pkt(pktio_entry_t *entry)
{
	pkt_sock_mmap_t *const pkt_sock = &entry->s.pkt_sock_mmap;

	mmap_unmap_sock(pkt_sock);
	if (pkt_sock->sockfd != -1 && close(pkt_sock->sockfd) != 0) {
		__odp_errno = errno;
		ODP_ERR("close(sockfd): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int sock_mmap_open_pkt(odp_pktio_t id ODP_UNUSED,
			      pktio_entry_t *pktio_entry,
			      const char *netdev, odp_pool_t pool)
{
	int if_idx;
	int ret = 0;

	if (getenv("ODP_PKTIO_DISABLE_SOCKET_MMAP"))
		return -1;

	pkt_sock_mmap_t *const pkt_sock = &pktio_entry->s.pkt_sock_mmap;
	int fanout = 1;

	/* Init pktio entry */
	memset(pkt_sock, 0, sizeof(*pkt_sock));
	/* set sockfd to -1, because a valid socked might be initialized to 0 */
	pkt_sock->sockfd = -1;

	if (pool == ODP_POOL_INVALID)
		return -1;

	/* Store eth buffer offset for pkt buffers from this pool */
	pkt_sock->frame_offset = 0;

	pkt_sock->pool = pool;
	pkt_sock->sockfd = mmap_pkt_socket();
	if (pkt_sock->sockfd == -1)
		goto error;

	ret = mmap_bind_sock(pkt_sock, netdev);
	if (ret != 0)
		goto error;

	ret = mmap_setup_ring(pkt_sock->sockfd, &pkt_sock->tx_ring,
			      PACKET_TX_RING, pool, fanout);
	if (ret != 0)
		goto error;

	ret = mmap_setup_ring(pkt_sock->sockfd, &pkt_sock->rx_ring,
			      PACKET_RX_RING, pool, fanout);
	if (ret != 0)
		goto error;

	ret = mmap_sock(pkt_sock);
	if (ret != 0)
		goto error;

	ret = mmap_store_hw_addr(pkt_sock, netdev);
	if (ret != 0)
		goto error;

	if_idx = if_nametoindex(netdev);
	if (if_idx == 0) {
		__odp_errno = errno;
		ODP_ERR("if_nametoindex(): %s\n", strerror(errno));
		goto error;
	}

	pkt_sock->fanout = fanout;
	if (fanout) {
		ret = set_pkt_sock_fanout_mmap(pkt_sock, if_idx);
		if (ret != 0)
			goto error;
	}

	return 0;

error:
	sock_mmap_close_pkt(pktio_entry);
	return -1;
}

static int sock_mmap_recv_pkt(pktio_entry_t *pktio_entry,
			      odp_packet_t pkt_table[], unsigned len)
{
	pkt_sock_mmap_t *const pkt_sock = &pktio_entry->s.pkt_sock_mmap;
	return pkt_mmap_v2_rx(pkt_sock->rx_ring.sock, &pkt_sock->rx_ring,
			      pkt_table, len, pkt_sock->pool,
			      pkt_sock->if_mac);
}

static int sock_mmap_send_pkt(pktio_entry_t *pktio_entry,
			      odp_packet_t pkt_table[], unsigned len)
{
	pkt_sock_mmap_t *const pkt_sock = &pktio_entry->s.pkt_sock_mmap;
	return pkt_mmap_v2_tx(pkt_sock->tx_ring.sock, &pkt_sock->tx_ring,
			      pkt_table, len);
}

static int sock_mmap_mtu_get(pktio_entry_t *pktio_entry)
{
	return mtu_get_fd(pktio_entry->s.pkt_sock_mmap.sockfd,
			  pktio_entry->s.name);
}

static int sock_mmap_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	memcpy(mac_addr, pktio_entry->s.pkt_sock_mmap.if_mac, ETH_ALEN);
	return ETH_ALEN;
}

static int sock_mmap_promisc_mode_set(pktio_entry_t *pktio_entry,
				      odp_bool_t enable)
{
	return promisc_mode_set_fd(pktio_entry->s.pkt_sock_mmap.sockfd,
				   pktio_entry->s.name, enable);
}

static int sock_mmap_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return promisc_mode_get_fd(pktio_entry->s.pkt_sock_mmap.sockfd,
				   pktio_entry->s.name);
}

const pktio_if_ops_t sock_mmap_pktio_ops = {
	.open = sock_mmap_open_pkt,
	.close = sock_mmap_close_pkt,
	.recv = sock_mmap_recv_pkt,
	.send = sock_mmap_send_pkt,
	.mtu_get = sock_mmap_mtu_get,
	.promisc_mode_set = sock_mmap_promisc_mode_set,
	.promisc_mode_get = sock_mmap_promisc_mode_get,
	.mac_get = sock_mmap_mac_addr_get
};

/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <bits/wordsize.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <inttypes.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/syscall.h>

#include <odp.h>
#include <odp_packet_socket.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_align_internal.h>
#include <odp_debug_internal.h>
#include <odp/hints.h>

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

/** Provide a sendmmsg wrapper for systems with no libc or kernel support.
 *  As it is implemented as a weak symbol, it has zero effect on systems
 *  with both.
 */
int sendmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen,
	     int flags) __attribute__((weak));
int sendmmsg(int fd, struct mmsghdr *vmessages, unsigned int vlen, int flags)
{
#ifdef SYS_sendmmsg
	return syscall(SYS_sendmmsg, fd, vmessages, vlen, flags);
#else
	/* Emulate sendmmsg using sendmsg.
	 * Note: this emulated version does break sendmmsg promise
	 * that for blocking calls all the messages will be handled
	 * so it's not a good general purpose sendmmsg emulator,
	 * but for our purposes it suffices.
	 */
	ssize_t ret;

	if (vlen) {
		ret = sendmsg(fd, &vmessages->msg_hdr, flags);

		if (ret != -1) {
			vmessages->msg_len = ret;
			return 1;
		}
	}

	return -1;

#endif
}

/** Eth buffer start offset from u32-aligned address to make sure the following
 * header (e.g. IP) starts at a 32-bit aligned address.
 */
#define ETHBUF_OFFSET (ODP_ALIGN_ROUNDUP(ODPH_ETHHDR_LEN, sizeof(uint32_t)) \
				- ODPH_ETHHDR_LEN)

/** Round up buffer address to get a properly aliged eth buffer, i.e. aligned
 * so that the next header always starts at a 32bit aligned address.
 */
#define ETHBUF_ALIGN(buf_ptr) ((uint8_t *)ODP_ALIGN_ROUNDUP_PTR((buf_ptr), \
				sizeof(uint32_t)) + ETHBUF_OFFSET)

/*
 * ODP_PACKET_SOCKET_BASIC:
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 */
int mtu_get_fd(int fd, const char *name)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFMTU, &ifr);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFMTU error\n");
		return -1;
	}
	return ifr.ifr_mtu;
}

/*
 * ODP_PACKET_SOCKET_BASIC:
 * ODP_PACKET_SOCKET_MMSG:
 */
int sock_setup_pkt(pkt_sock_t *const pkt_sock, const char *netdev,
		   odp_pool_t pool)
{
	int sockfd;
	int err;
	unsigned int if_idx;
	struct ifreq ethreq;
	struct sockaddr_ll sa_ll;

	if (pool == ODP_POOL_INVALID)
		return -1;
	pkt_sock->pool = pool;

	/* Store eth buffer offset for pkt buffers from this pool */
	pkt_sock->frame_offset = 0;
	/* pkt buffer size */
	pkt_sock->buf_size = odp_buffer_pool_segment_size(pool);
	/* max frame len taking into account the l2-offset */
	pkt_sock->max_frame_len = pkt_sock->buf_size -
		odp_buffer_pool_headroom(pool) -
		odp_buffer_pool_tailroom(pool);

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockfd == -1) {
		ODP_ERR("socket(): %s\n", strerror(errno));
		goto error;
	}
	pkt_sock->sockfd = sockfd;

	/* get if index */
	memset(&ethreq, 0, sizeof(struct ifreq));
	snprintf(ethreq.ifr_name, IF_NAMESIZE, "%s", netdev);
	err = ioctl(sockfd, SIOCGIFINDEX, &ethreq);
	if (err != 0) {
		ODP_ERR("ioctl(SIOCGIFINDEX): %s: \"%s\".\n", strerror(errno),
			ethreq.ifr_name);
		goto error;
	}
	if_idx = ethreq.ifr_ifindex;

	/* get MAC address */
	memset(&ethreq, 0, sizeof(ethreq));
	snprintf(ethreq.ifr_name, IF_NAMESIZE, "%s", netdev);
	err = ioctl(sockfd, SIOCGIFHWADDR, &ethreq);
	if (err != 0) {
		ODP_ERR("ioctl(SIOCGIFHWADDR): %s\n", strerror(errno));
		goto error;
	}
	ethaddr_copy(pkt_sock->if_mac,
		     (unsigned char *)ethreq.ifr_ifru.ifru_hwaddr.sa_data);

	/* bind socket to if */
	memset(&sa_ll, 0, sizeof(sa_ll));
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_ifindex = if_idx;
	sa_ll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sockfd, (struct sockaddr *)&sa_ll, sizeof(sa_ll)) < 0) {
		ODP_ERR("bind(to IF): %s\n", strerror(errno));
		goto error;
	}

	return sockfd;

error:
	__odp_errno = errno;

	return -1;
}

/*
 * ODP_PACKET_SOCKET_BASIC:
 * ODP_PACKET_SOCKET_MMSG:
 */
int sock_close_pkt(pkt_sock_t *const pkt_sock)
{
	if (pkt_sock->sockfd != -1 && close(pkt_sock->sockfd) != 0) {
		__odp_errno = errno;
		ODP_ERR("close(sockfd): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * ODP_PACKET_SOCKET_BASIC:
 */
int sock_basic_recv_pkt(pkt_sock_t *const pkt_sock,
			odp_packet_t pkt_table[], unsigned len)
{
	ssize_t recv_bytes;
	unsigned i;
	struct sockaddr_ll sll;
	socklen_t addrlen = sizeof(sll);
	int const sockfd = pkt_sock->sockfd;
	odp_packet_t pkt = ODP_PACKET_INVALID;
	uint8_t *pkt_buf;
	int nb_rx = 0;

	/*  recvfrom:
	 *  If the address argument is not a null pointer
	 *  and the protocol does not provide the source address of
	 *  messages, the the value stored in the object pointed to
	 *  by address is unspecified.
	 */
	memset(&sll, 0, sizeof(sll));

	for (i = 0; i < len; i++) {
		if (odp_likely(pkt == ODP_PACKET_INVALID)) {
			pkt = odp_packet_alloc(pkt_sock->pool,
					       pkt_sock->max_frame_len);
			if (odp_unlikely(pkt == ODP_PACKET_INVALID))
				break;
		}

		pkt_buf = odp_packet_data(pkt);

		recv_bytes = recvfrom(sockfd, pkt_buf,
				      pkt_sock->max_frame_len, MSG_DONTWAIT,
				      (struct sockaddr *)&sll, &addrlen);
		/* no data or error: free recv buf and break out of loop */
		if (odp_unlikely(recv_bytes < 1))
			break;
		/* frame not explicitly for us, reuse pkt buf for next frame */
		if (odp_unlikely(sll.sll_pkttype == PACKET_OUTGOING))
			continue;

		/* Parse and set packet header data */
		odp_packet_pull_tail(pkt, pkt_sock->max_frame_len - recv_bytes);
		_odp_packet_reset_parse(pkt);

		pkt_table[nb_rx] = pkt;
		pkt = ODP_PACKET_INVALID;
		nb_rx++;
	} /* end for() */

	if (odp_unlikely(pkt != ODP_PACKET_INVALID))
		odp_packet_free(pkt);

	return nb_rx;
}

/*
 * ODP_PACKET_SOCKET_BASIC:
 */
int sock_basic_send_pkt(pkt_sock_t *const pkt_sock,
			odp_packet_t pkt_table[], unsigned len)
{
	odp_packet_t pkt;
	uint8_t *frame;
	uint32_t frame_len;
	unsigned i;
	unsigned flags;
	int sockfd;
	unsigned nb_tx;
	int ret;

	sockfd = pkt_sock->sockfd;
	flags = MSG_DONTWAIT;
	i = 0;
	while (i < len) {
		pkt = pkt_table[i];

		frame = odp_packet_l2_ptr(pkt, &frame_len);

		ret = send(sockfd, frame, frame_len, flags);
		if (odp_unlikely(ret == -1)) {
			if (odp_likely(errno == EAGAIN)) {
				flags = 0;	/* blocking for next rounds */
				continue;	/* resend buffer */
			} else {
				break;
			}
		}

		i++;
	}			/* end while */
	nb_tx = i;

	for (i = 0; i < nb_tx; i++)
		odp_packet_free(pkt_table[i]);

	return nb_tx;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 */
int sock_mmsg_recv_pkt(pkt_sock_t *const pkt_sock,
		       odp_packet_t pkt_table[], unsigned len)
{
	const int sockfd = pkt_sock->sockfd;
	int msgvec_len;
	struct mmsghdr msgvec[ODP_PACKET_SOCKET_MAX_BURST_RX];
	struct iovec iovecs[ODP_PACKET_SOCKET_MAX_BURST_RX];
	uint8_t *pkt_buf;
	uint8_t *l2_hdr;
	int nb_rx = 0;
	int recv_msgs;
	int i;

	if (odp_unlikely(len > ODP_PACKET_SOCKET_MAX_BURST_RX))
		return -1;

	memset(msgvec, 0, sizeof(msgvec));

	for (i = 0; i < (int)len; i++) {
		pkt_table[i] = odp_packet_alloc(pkt_sock->pool,
						pkt_sock->max_frame_len);
		if (odp_unlikely(pkt_table[i] == ODP_PACKET_INVALID))
			break;

		pkt_buf = odp_packet_data(pkt_table[i]);
		l2_hdr = pkt_buf + pkt_sock->frame_offset;
		iovecs[i].iov_base = l2_hdr;
		iovecs[i].iov_len = pkt_sock->max_frame_len;
		msgvec[i].msg_hdr.msg_iov = &iovecs[i];
		msgvec[i].msg_hdr.msg_iovlen = 1;
	}
	msgvec_len = i; /* number of successfully allocated pkt buffers */

	recv_msgs = recvmmsg(sockfd, msgvec, msgvec_len, MSG_DONTWAIT, NULL);

	for (i = 0; i < recv_msgs; i++) {
		void *base = msgvec[i].msg_hdr.msg_iov->iov_base;
		struct ethhdr *eth_hdr = base;

		/* Don't receive packets sent by ourselves */
		if (odp_unlikely(ethaddrs_equal(pkt_sock->if_mac,
						eth_hdr->h_source))) {
			odp_packet_free(pkt_table[i]);
			continue;
		}

		/* Parse and set packet header data */
		odp_packet_pull_tail(pkt_table[i],
				     pkt_sock->max_frame_len -
				     msgvec[i].msg_len);
		_odp_packet_reset_parse(pkt_table[i]);

		pkt_table[nb_rx] = pkt_table[i];
		nb_rx++;
	}

	/* Free unused pkt buffers */
	for (; i < msgvec_len; i++)
		odp_packet_free(pkt_table[i]);

	return nb_rx;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 */
int sock_mmsg_send_pkt(pkt_sock_t *const pkt_sock,
		       odp_packet_t pkt_table[], unsigned len)
{
	struct mmsghdr msgvec[ODP_PACKET_SOCKET_MAX_BURST_TX];
	struct iovec iovecs[ODP_PACKET_SOCKET_MAX_BURST_TX];
	int ret;
	int sockfd;
	unsigned i;
	unsigned sent_msgs = 0;
	unsigned flags;

	if (odp_unlikely(len > ODP_PACKET_SOCKET_MAX_BURST_TX))
		return -1;

	sockfd = pkt_sock->sockfd;
	memset(msgvec, 0, sizeof(msgvec));

	for (i = 0; i < len; i++) {
		uint32_t seglen;

		iovecs[i].iov_base = odp_packet_l2_ptr(pkt_table[i], &seglen);
		iovecs[i].iov_len = seglen;
		msgvec[i].msg_hdr.msg_iov = &iovecs[i];
		msgvec[i].msg_hdr.msg_iovlen = 1;
	}

	flags = MSG_DONTWAIT;
	for (i = 0; i < len; i += sent_msgs) {
		ret = sendmmsg(sockfd, &msgvec[i], len - i, flags);
		sent_msgs = ret > 0 ? (unsigned)ret : 0;
		flags = 0;	/* blocking for next rounds */
	}

	for (i = 0; i < len; i++)
		odp_packet_free(pkt_table[i]);

	return len;
}

/*
 * ODP_PACKET_SOCKET_BASIC:
 * ODP_PACKET_SOCKET_MMSG:
 */
int sock_mtu_get(pktio_entry_t *pktio_entry)
{
	return mtu_get_fd(pktio_entry->s.pkt_sock.sockfd, pktio_entry->s.name);
}

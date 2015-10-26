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

/**
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_NETMAP:
 */
int mac_addr_get_fd(int fd, const char *name, unsigned char mac_dst[])
{
	struct ifreq ethreq;
	int ret;

	memset(&ethreq, 0, sizeof(ethreq));
	snprintf(ethreq.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFHWADDR, &ethreq);
	if (ret != 0) {
		__odp_errno = errno;
		ODP_ERR("ioctl(SIOCGIFHWADDR): %s: \"%s\".\n", strerror(errno),
			ethreq.ifr_name);
		return -1;
	}

	memcpy(mac_dst, (unsigned char *)ethreq.ifr_ifru.ifru_hwaddr.sa_data,
	       ETH_ALEN);
	return 0;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_NETMAP:
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
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_NETMAP:
 */
int promisc_mode_set_fd(int fd, const char *name, int enable)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFFLAGS error\n");
		return -1;
	}

	if (enable)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~(IFF_PROMISC);

	ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCSIFFLAGS error\n");
		return -1;
	}
	return 0;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 * ODP_PACKET_SOCKET_MMAP:
 * ODP_PACKET_NETMAP:
 */
int promisc_mode_get_fd(int fd, const char *name)
{
	struct ifreq ifr;
	int ret;

	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", name);
	ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
	if (ret < 0) {
		ODP_DBG("ioctl SIOCGIFFLAGS error\n");
		return -1;
	}

	return !!(ifr.ifr_flags & IFF_PROMISC);
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 */
static int sock_close(pktio_entry_t *pktio_entry)
{
	pkt_sock_t *pkt_sock = &pktio_entry->s.pkt_sock;
	if (pkt_sock->sockfd != -1 && close(pkt_sock->sockfd) != 0) {
		__odp_errno = errno;
		ODP_ERR("close(sockfd): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 */
static int sock_setup_pkt(pktio_entry_t *pktio_entry, const char *netdev,
			  odp_pool_t pool)
{
	int sockfd;
	int err;
	unsigned int if_idx;
	struct ifreq ethreq;
	struct sockaddr_ll sa_ll;
	pkt_sock_t *pkt_sock = &pktio_entry->s.pkt_sock;

	/* Init pktio entry */
	memset(pkt_sock, 0, sizeof(*pkt_sock));
	/* set sockfd to -1, because a valid socked might be initialized to 0 */
	pkt_sock->sockfd = -1;

	if (pool == ODP_POOL_INVALID)
		return -1;
	pkt_sock->pool = pool;

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockfd == -1) {
		__odp_errno = errno;
		ODP_ERR("socket(): %s\n", strerror(errno));
		goto error;
	}
	pkt_sock->sockfd = sockfd;

	/* get if index */
	memset(&ethreq, 0, sizeof(struct ifreq));
	snprintf(ethreq.ifr_name, IF_NAMESIZE, "%s", netdev);
	err = ioctl(sockfd, SIOCGIFINDEX, &ethreq);
	if (err != 0) {
		__odp_errno = errno;
		ODP_ERR("ioctl(SIOCGIFINDEX): %s: \"%s\".\n", strerror(errno),
			ethreq.ifr_name);
		goto error;
	}
	if_idx = ethreq.ifr_ifindex;

	err = mac_addr_get_fd(sockfd, netdev, pkt_sock->if_mac);
	if (err != 0)
		goto error;

	/* bind socket to if */
	memset(&sa_ll, 0, sizeof(sa_ll));
	sa_ll.sll_family = AF_PACKET;
	sa_ll.sll_ifindex = if_idx;
	sa_ll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sockfd, (struct sockaddr *)&sa_ll, sizeof(sa_ll)) < 0) {
		__odp_errno = errno;
		ODP_ERR("bind(to IF): %s\n", strerror(errno));
		goto error;
	}

	return 0;

error:
	sock_close(pktio_entry);

	return -1;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 */
static int sock_mmsg_open(odp_pktio_t id ODP_UNUSED,
			  pktio_entry_t *pktio_entry,
			  const char *devname, odp_pool_t pool)
{
	if (getenv("ODP_PKTIO_DISABLE_SOCKET_MMSG"))
		return -1;
	return sock_setup_pkt(pktio_entry, devname, pool);
}

static uint32_t _rx_pkt_to_iovec(odp_packet_t pkt,
				 struct iovec iovecs[ODP_BUFFER_MAX_SEG])
{
	odp_packet_seg_t seg = odp_packet_first_seg(pkt);
	uint32_t seg_count = odp_packet_num_segs(pkt);
	uint32_t seg_id = 0;
	uint32_t iov_count = 0;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint8_t *ptr;
	uint32_t seglen;

	for (seg_id = 0; seg_id < seg_count; ++seg_id) {
		ptr = segment_map(&pkt_hdr->buf_hdr, (odp_buffer_seg_t)seg,
				  &seglen, pkt_hdr->frame_len,
				  pkt_hdr->headroom);

		if (ptr) {
			iovecs[iov_count].iov_base = ptr;
			iovecs[iov_count].iov_len = seglen;
			iov_count++;
		}
		seg = odp_packet_next_seg(pkt, seg);
	}

	return iov_count;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 */
static int sock_mmsg_recv(pktio_entry_t *pktio_entry,
			  odp_packet_t pkt_table[], unsigned len)
{
	pkt_sock_t *pkt_sock = &pktio_entry->s.pkt_sock;
	const int sockfd = pkt_sock->sockfd;
	int msgvec_len;
	struct mmsghdr msgvec[ODP_PACKET_SOCKET_MAX_BURST_RX];
	struct iovec iovecs[ODP_PACKET_SOCKET_MAX_BURST_RX][ODP_BUFFER_MAX_SEG];
	int nb_rx = 0;
	int recv_msgs;
	int i;

	if (odp_unlikely(len > ODP_PACKET_SOCKET_MAX_BURST_RX))
		return -1;

	memset(msgvec, 0, sizeof(msgvec));

	for (i = 0; i < (int)len; i++) {
		pkt_table[i] = packet_alloc(pkt_sock->pool, 0 /*default*/, 1);
		if (odp_unlikely(pkt_table[i] == ODP_PACKET_INVALID))
			break;

		msgvec[i].msg_hdr.msg_iovlen =
			_rx_pkt_to_iovec(pkt_table[i], iovecs[i]);

		msgvec[i].msg_hdr.msg_iov = iovecs[i];
	}
	msgvec_len = i; /* number of successfully allocated pkt buffers */

	recv_msgs = recvmmsg(sockfd, msgvec, msgvec_len, MSG_DONTWAIT, NULL);

	for (i = 0; i < recv_msgs; i++) {
		odp_packet_hdr_t *pkt_hdr;
		void *base = msgvec[i].msg_hdr.msg_iov->iov_base;
		struct ethhdr *eth_hdr = base;

		/* Don't receive packets sent by ourselves */
		if (odp_unlikely(ethaddrs_equal(pkt_sock->if_mac,
						eth_hdr->h_source))) {
			odp_packet_free(pkt_table[i]);
			continue;
		}

		pkt_hdr = odp_packet_hdr(pkt_table[i]);

		odp_packet_pull_tail(pkt_table[i],
				     odp_packet_len(pkt_table[i]) -
				     msgvec[i].msg_len);

		packet_parse_l2(pkt_hdr);

		pkt_table[nb_rx] = pkt_table[i];
		nb_rx++;
	}

	/* Free unused pkt buffers */
	for (; i < msgvec_len; i++)
		odp_packet_free(pkt_table[i]);

	return nb_rx;
}

static uint32_t _tx_pkt_to_iovec(odp_packet_t pkt,
				 struct iovec iovecs[ODP_BUFFER_MAX_SEG])
{
	uint32_t pkt_len = odp_packet_len(pkt);
	uint32_t offset = odp_packet_l2_offset(pkt);
	uint32_t iov_count = 0;

	while (offset < pkt_len) {
		uint32_t seglen;

		iovecs[iov_count].iov_base = odp_packet_offset(pkt, offset,
							       &seglen, NULL);
		iovecs[iov_count].iov_len = seglen;
		iov_count++;
		offset += seglen;
	}
	return iov_count;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 */
static int sock_mmsg_send(pktio_entry_t *pktio_entry,
			  odp_packet_t pkt_table[], unsigned len)
{
	pkt_sock_t *pkt_sock = &pktio_entry->s.pkt_sock;
	struct mmsghdr msgvec[ODP_PACKET_SOCKET_MAX_BURST_TX];
	struct iovec iovecs[ODP_PACKET_SOCKET_MAX_BURST_TX][ODP_BUFFER_MAX_SEG];
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
		msgvec[i].msg_hdr.msg_iov = iovecs[i];
		msgvec[i].msg_hdr.msg_iovlen = _tx_pkt_to_iovec(pkt_table[i],
								iovecs[i]);
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
 * ODP_PACKET_SOCKET_MMSG:
 */
static int sock_mtu_get(pktio_entry_t *pktio_entry)
{
	return mtu_get_fd(pktio_entry->s.pkt_sock.sockfd, pktio_entry->s.name);
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 */
static int sock_mac_addr_get(pktio_entry_t *pktio_entry,
			     void *mac_addr)
{
	memcpy(mac_addr, pktio_entry->s.pkt_sock.if_mac, ETH_ALEN);
	return ETH_ALEN;
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 */
static int sock_promisc_mode_set(pktio_entry_t *pktio_entry,
				 odp_bool_t enable)
{
	return promisc_mode_set_fd(pktio_entry->s.pkt_sock.sockfd,
				   pktio_entry->s.name, enable);
}

/*
 * ODP_PACKET_SOCKET_MMSG:
 */
static int sock_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return promisc_mode_get_fd(pktio_entry->s.pkt_sock.sockfd,
				   pktio_entry->s.name);
}

const pktio_if_ops_t sock_mmsg_pktio_ops = {
	.init = NULL,
	.term = NULL,
	.open = sock_mmsg_open,
	.close = sock_close,
	.start = NULL,
	.stop = NULL,
	.recv = sock_mmsg_recv,
	.send = sock_mmsg_send,
	.mtu_get = sock_mtu_get,
	.promisc_mode_set = sock_promisc_mode_set,
	.promisc_mode_get = sock_promisc_mode_get,
	.mac_get = sock_mac_addr_get
};

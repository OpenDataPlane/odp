/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2013-2019, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/syscall.h>

#include <odp_api.h>
#include <odp_socket_common.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_stats.h>
#include <odp_debug_internal.h>
#include <odp_errno_define.h>
#include <odp_classification_internal.h>

typedef struct {
	odp_ticketlock_t ODP_ALIGNED_CACHE rx_lock;
	odp_ticketlock_t ODP_ALIGNED_CACHE tx_lock;
	int sockfd; /**< socket descriptor */
	odp_pool_t pool; /**< pool to alloc packets from */
	uint32_t mtu;    /**< maximum transmission unit */
	unsigned char if_mac[ETH_ALEN];	/**< IF eth mac addr */
} pkt_sock_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_sock_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_sock_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_sock_t *)(uintptr_t)(pktio_entry->s.pkt_priv);
}

static int disable_pktio; /** !0 this pktio disabled, 0 enabled */

static int sock_stats_reset(pktio_entry_t *pktio_entry);

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
static int sock_close(pktio_entry_t *pktio_entry)
{
	pkt_sock_t *pkt_sock = pkt_priv(pktio_entry);

	if (pkt_sock->sockfd != -1 && close(pkt_sock->sockfd) != 0) {
		__odp_errno = errno;
		ODP_ERR("close(sockfd): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int sock_setup_pkt(pktio_entry_t *pktio_entry, const char *netdev,
			  odp_pool_t pool)
{
	int sockfd;
	int err;
	unsigned int if_idx;
	struct ifreq ethreq;
	struct sockaddr_ll sa_ll;
	char shm_name[ODP_SHM_NAME_LEN];
	pkt_sock_t *pkt_sock = pkt_priv(pktio_entry);

	/* Init pktio entry */
	memset(pkt_sock, 0, sizeof(*pkt_sock));
	/* set sockfd to -1, because a valid socked might be initialized to 0 */
	pkt_sock->sockfd = -1;

	if (pool == ODP_POOL_INVALID)
		return -1;
	pkt_sock->pool = pool;
	snprintf(shm_name, ODP_SHM_NAME_LEN, "%s-%s", "pktio", netdev);
	shm_name[ODP_SHM_NAME_LEN - 1] = '\0';

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

	pkt_sock->mtu = mtu_get_fd(sockfd, netdev);
	if (!pkt_sock->mtu)
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

	pktio_entry->s.stats_type = sock_stats_type_fd(pktio_entry,
						       pkt_sock->sockfd);
	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED)
		ODP_DBG("pktio: %s unsupported stats\n", pktio_entry->s.name);

	err = sock_stats_reset(pktio_entry);
	if (err != 0)
		goto error;

	odp_ticketlock_init(&pkt_sock->rx_lock);
	odp_ticketlock_init(&pkt_sock->tx_lock);

	return 0;

error:
	sock_close(pktio_entry);

	return -1;
}

static int sock_mmsg_open(odp_pktio_t id ODP_UNUSED,
			  pktio_entry_t *pktio_entry,
			  const char *devname, odp_pool_t pool)
{
	if (disable_pktio)
		return -1;
	return sock_setup_pkt(pktio_entry, devname, pool);
}

static inline uint32_t _rx_pkt_to_iovec(odp_packet_t pkt, struct iovec *iovecs)
{
	odp_packet_seg_t seg;
	uint32_t seg_count = odp_packet_num_segs(pkt);
	uint32_t i;

	if (odp_likely(seg_count) == 1) {
		iovecs[0].iov_base = odp_packet_data(pkt);
		iovecs[0].iov_len = odp_packet_len(pkt);
		return 1;
	}

	seg = odp_packet_first_seg(pkt);

	for (i = 0; i < seg_count; i++) {
		iovecs[i].iov_base = odp_packet_seg_data(pkt, seg);
		iovecs[i].iov_len = odp_packet_seg_data_len(pkt, seg);
		seg = odp_packet_next_seg(pkt, seg);
	}
	return i;
}

static int sock_mmsg_recv(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			  odp_packet_t pkt_table[], int num)
{
	pkt_sock_t *pkt_sock = pkt_priv(pktio_entry);
	odp_pool_t pool = pkt_sock->pool;
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	const int sockfd = pkt_sock->sockfd;
	struct mmsghdr msgvec[num];
	struct iovec iovecs[num][PKT_MAX_SEGS];
	int nb_rx = 0;
	int nb_pkts;
	int recv_msgs;
	int i;

	memset(msgvec, 0, sizeof(msgvec));

	nb_pkts = packet_alloc_multi(pool, pkt_sock->mtu, pkt_table, num);
	for (i = 0; i < nb_pkts; i++) {
		msgvec[i].msg_hdr.msg_iovlen =
			_rx_pkt_to_iovec(pkt_table[i], iovecs[i]);
		msgvec[i].msg_hdr.msg_iov = iovecs[i];
	}

	odp_ticketlock_lock(&pkt_sock->rx_lock);
	recv_msgs = recvmmsg(sockfd, msgvec, nb_pkts, MSG_DONTWAIT, NULL);
	odp_ticketlock_unlock(&pkt_sock->rx_lock);

	if (pktio_entry->s.config.pktin.bit.ts_all ||
	    pktio_entry->s.config.pktin.bit.ts_ptp) {
		ts_val = odp_time_global();
		ts = &ts_val;
	}

	for (i = 0; i < recv_msgs; i++) {
		void *base = msgvec[i].msg_hdr.msg_iov->iov_base;
		struct ethhdr *eth_hdr = base;
		odp_packet_t pkt = pkt_table[i];
		odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
		uint16_t pkt_len = msgvec[i].msg_len;
		int ret;

		if (odp_unlikely(msgvec[i].msg_hdr.msg_flags & MSG_TRUNC)) {
			odp_packet_free(pkt);
			ODP_DBG("dropped truncated packet\n");
			continue;
		}
		if (pktio_cls_enabled(pktio_entry)) {
			uint16_t seg_len =  pkt_len;

			if (msgvec[i].msg_hdr.msg_iov->iov_len < pkt_len)
				seg_len = msgvec[i].msg_hdr.msg_iov->iov_len;

			if (cls_classify_packet(pktio_entry, base, pkt_len,
						seg_len, &pool, pkt_hdr,
						true)) {
				ODP_ERR("cls_classify_packet failed");
				odp_packet_free(pkt);
				continue;
			}
		}

		/* Don't receive packets sent by ourselves */
		if (odp_unlikely(ethaddrs_equal(pkt_sock->if_mac,
						eth_hdr->h_source))) {
			odp_packet_free(pkt);
			continue;
		}

		ret = odp_packet_trunc_tail(&pkt, odp_packet_len(pkt) - pkt_len,
					    NULL, NULL);
		if (ret < 0) {
			ODP_ERR("trunk_tail failed");
			odp_packet_free(pkt);
			continue;
		}

		pkt_hdr->input = pktio_entry->s.handle;

		if (!pktio_cls_enabled(pktio_entry))
			packet_parse_layer(pkt_hdr,
					   pktio_entry->s.config.parser.layer,
					   pktio_entry->s.in_chksums);

		packet_set_ts(pkt_hdr, ts);

		pkt_table[nb_rx++] = pkt;
	}

	/* Free unused pkt buffers */
	if (i < nb_pkts)
		odp_packet_free_multi(&pkt_table[i], nb_pkts - i);

	return nb_rx;
}

static int sock_fd_set(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
		       fd_set *readfds)
{
	pkt_sock_t *pkt_sock = pkt_priv(pktio_entry);
	const int sockfd = pkt_sock->sockfd;

	FD_SET(sockfd, readfds);
	return sockfd;
}

static int sock_recv_tmo(pktio_entry_t *pktio_entry, int index,
			 odp_packet_t pkt_table[], int num, uint64_t usecs)
{
	struct timeval timeout;
	int ret;
	int maxfd;
	fd_set readfds;

	ret = sock_mmsg_recv(pktio_entry, index, pkt_table, num);
	if (ret != 0)
		return ret;

	timeout.tv_sec = usecs / (1000 * 1000);
	timeout.tv_usec = usecs - timeout.tv_sec * (1000ULL * 1000ULL);

	FD_ZERO(&readfds);
	maxfd = sock_fd_set(pktio_entry, index, &readfds);

	while (1) {
		ret = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
		if (ret <= 0)
			return 0;

		ret = sock_mmsg_recv(pktio_entry, index, pkt_table, num);
		if (odp_likely(ret))
			return ret;

		/* If no packets, continue wait until timeout expires */
	}
}

static int sock_recv_mq_tmo(pktio_entry_t *pktio_entry[], int index[],
			    int num_q, odp_packet_t pkt_table[], int num,
			    unsigned *from, uint64_t usecs)
{
	struct timeval timeout;
	int i;
	int ret;
	int maxfd = -1, maxfd2;
	fd_set readfds;

	for (i = 0; i < num_q; i++) {
		ret = sock_mmsg_recv(pktio_entry[i], index[i], pkt_table, num);

		if (ret > 0 && from)
			*from = i;

		if (ret != 0)
			return ret;
	}

	FD_ZERO(&readfds);

	for (i = 0; i < num_q; i++) {
		maxfd2 = sock_fd_set(pktio_entry[i], index[i], &readfds);
		if (maxfd2 > maxfd)
			maxfd = maxfd2;
	}

	timeout.tv_sec = usecs / (1000 * 1000);
	timeout.tv_usec = usecs - timeout.tv_sec * (1000ULL * 1000ULL);

	while (1) {
		ret = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
		if (ret <= 0)
			return ret;

		for (i = 0; i < num_q; i++) {
			ret = sock_mmsg_recv(pktio_entry[i], index[i],
					     pkt_table, num);

			if (ret > 0 && from)
				*from = i;

			if (ret)
				return ret;
		}

		/* If no packets, continue wait until timeout expires */
	}
}

static inline uint32_t _tx_pkt_to_iovec(odp_packet_t pkt, struct iovec *iovecs)
{
	odp_packet_seg_t seg;
	int seg_count = odp_packet_num_segs(pkt);
	int i;

	if (odp_likely(seg_count == 1)) {
		iovecs[0].iov_base = odp_packet_data(pkt);
		iovecs[0].iov_len = odp_packet_len(pkt);
		return 1;
	}

	seg = odp_packet_first_seg(pkt);
	for (i = 0; i < seg_count; i++) {
		iovecs[i].iov_base = odp_packet_seg_data(pkt, seg);
		iovecs[i].iov_len = odp_packet_seg_data_len(pkt, seg);
		seg = odp_packet_next_seg(pkt, seg);
	}
	return i;
}

static int sock_mmsg_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			  const odp_packet_t pkt_table[], int num)
{
	pkt_sock_t *pkt_sock = pkt_priv(pktio_entry);
	struct mmsghdr msgvec[num];
	struct iovec iovecs[num][PKT_MAX_SEGS];
	int ret;
	int sockfd = pkt_sock->sockfd;
	int i;

	memset(msgvec, 0, sizeof(msgvec));

	for (i = 0; i < num; i++) {
		msgvec[i].msg_hdr.msg_iov = iovecs[i];
		msgvec[i].msg_hdr.msg_iovlen = _tx_pkt_to_iovec(pkt_table[i],
								iovecs[i]);
	}

	odp_ticketlock_lock(&pkt_sock->tx_lock);

	for (i = 0; i < num; ) {
		ret = sendmmsg(sockfd, &msgvec[i], num - i, MSG_DONTWAIT);
		if (odp_unlikely(ret <= -1)) {
			if (i == 0 && SOCK_ERR_REPORT(errno)) {
				__odp_errno = errno;
				ODP_ERR("sendmmsg(): %s\n", strerror(errno));
				odp_ticketlock_unlock(&pkt_sock->tx_lock);
				return -1;
			}
			break;
		}

		i += ret;
	}

	odp_ticketlock_unlock(&pkt_sock->tx_lock);

	odp_packet_free_multi(pkt_table, i);

	return i;
}

static uint32_t sock_mtu_get(pktio_entry_t *pktio_entry)
{
	return pkt_priv(pktio_entry)->mtu;
}

static int sock_mac_addr_get(pktio_entry_t *pktio_entry,
			     void *mac_addr)
{
	memcpy(mac_addr, pkt_priv(pktio_entry)->if_mac, ETH_ALEN);
	return ETH_ALEN;
}

static int sock_promisc_mode_set(pktio_entry_t *pktio_entry,
				 odp_bool_t enable)
{
	return promisc_mode_set_fd(pkt_priv(pktio_entry)->sockfd,
				   pktio_entry->s.name, enable);
}

static int sock_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return promisc_mode_get_fd(pkt_priv(pktio_entry)->sockfd,
				   pktio_entry->s.name);
}

static int sock_link_status(pktio_entry_t *pktio_entry)
{
	return link_status_fd(pkt_priv(pktio_entry)->sockfd,
			      pktio_entry->s.name);
}

static int sock_capability(pktio_entry_t *pktio_entry ODP_UNUSED,
			   odp_pktio_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues  = 1;
	capa->max_output_queues = 1;
	capa->set_op.op.promisc_mode = 1;

	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;
	return 0;
}

static int sock_stats(pktio_entry_t *pktio_entry,
		      odp_pktio_stats_t *stats)
{
	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED) {
		memset(stats, 0, sizeof(*stats));
		return 0;
	}

	return sock_stats_fd(pktio_entry, stats, pkt_priv(pktio_entry)->sockfd);
}

static int sock_stats_reset(pktio_entry_t *pktio_entry)
{
	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED) {
		memset(&pktio_entry->s.stats, 0,
		       sizeof(odp_pktio_stats_t));
		return 0;
	}

	return sock_stats_reset_fd(pktio_entry, pkt_priv(pktio_entry)->sockfd);
}

static int sock_init_global(void)
{
	if (getenv("ODP_PKTIO_DISABLE_SOCKET_MMSG")) {
		ODP_PRINT("PKTIO: socket mmsg skipped,"
			  " enabled export ODP_PKTIO_DISABLE_SOCKET_MMSG=1.\n");
		disable_pktio = 1;
	} else {
		ODP_PRINT("PKTIO: initialized socket mmsg,"
			  "use export ODP_PKTIO_DISABLE_SOCKET_MMSG=1 to disable.\n");
	}
	return 0;
}

const pktio_if_ops_t sock_mmsg_pktio_ops = {
	.name = "socket",
	.print = NULL,
	.init_global = sock_init_global,
	.init_local = NULL,
	.term = NULL,
	.open = sock_mmsg_open,
	.close = sock_close,
	.start = NULL,
	.stop = NULL,
	.stats = sock_stats,
	.stats_reset = sock_stats_reset,
	.recv = sock_mmsg_recv,
	.recv_tmo = sock_recv_tmo,
	.recv_mq_tmo = sock_recv_mq_tmo,
	.fd_set = sock_fd_set,
	.send = sock_mmsg_send,
	.mtu_get = sock_mtu_get,
	.promisc_mode_set = sock_promisc_mode_set,
	.promisc_mode_get = sock_promisc_mode_get,
	.mac_get = sock_mac_addr_get,
	.mac_set = NULL,
	.link_status = sock_link_status,
	.capability = sock_capability,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL,
};

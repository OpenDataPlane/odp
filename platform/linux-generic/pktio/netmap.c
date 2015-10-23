/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifdef ODP_NETMAP

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <odp_packet_netmap.h>
#include <odp_packet_socket.h>
#include <odp_packet_io_internal.h>
#include <odp_debug_internal.h>
#include <odp/helper/eth.h>

#include <sys/ioctl.h>
#include <poll.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

static struct nm_desc mmap_desc;	/** Used to store the mmap address;
					  filled in first time, used for
					  subsequent calls to nm_open */

#define NM_OPEN_RETRIES 5
#define NM_INJECT_RETRIES 10

struct dispatch_args {
	odp_packet_t *pkt_table;
	unsigned nb_rx;
	pktio_entry_t *pktio_entry;
};

static int netmap_do_ioctl(pktio_entry_t *pktio_entry, unsigned long cmd,
			   int subcmd)
{
	pkt_netmap_t *pkt_nm = &pktio_entry->s.pkt_nm;
	struct ethtool_value eval;
	struct ifreq ifr;
	int err;
	int fd = pkt_nm->sockfd;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s",
		 pktio_entry->s.name);

	switch (cmd) {
	case SIOCSIFFLAGS:
		ifr.ifr_flags = pkt_nm->if_flags & 0xffff;
		break;
	case SIOCETHTOOL:
		eval.cmd = subcmd;
		eval.data = 0;
		ifr.ifr_data = (caddr_t)&eval;
		break;
	default:
		break;
	}
	err = ioctl(fd, cmd, &ifr);
	if (err)
		goto done;

	switch (cmd) {
	case SIOCGIFFLAGS:
		pkt_nm->if_flags = (ifr.ifr_flags << 16) |
			(0xffff & ifr.ifr_flags);
		break;
	case SIOCETHTOOL:
		if (subcmd == ETHTOOL_GLINK)
			return !eval.data;
		break;
	default:
		break;
	}
done:
	if (err)
		ODP_ERR("ioctl err %d %lu: %s\n", err, cmd, strerror(errno));

	return err;
}

static int netmap_close(pktio_entry_t *pktio_entry)
{
	pkt_netmap_t *pkt_nm = &pktio_entry->s.pkt_nm;

	if (pkt_nm->desc != NULL) {
		nm_close(pkt_nm->desc);
		mmap_desc.mem = NULL;
	}
	if (pkt_nm->sockfd != -1 && close(pkt_nm->sockfd) != 0) {
		__odp_errno = errno;
		ODP_ERR("close(sockfd): %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int netmap_open(odp_pktio_t id ODP_UNUSED, pktio_entry_t *pktio_entry,
		       const char *netdev, odp_pool_t pool)
{
	char ifname[IFNAMSIZ + 7]; /* netmap:<ifname> */
	int err;
	int sockfd;
	int i;
	pkt_netmap_t *pkt_nm = &pktio_entry->s.pkt_nm;

	if (getenv("ODP_PKTIO_DISABLE_NETMAP"))
		return -1;

	if (pool == ODP_POOL_INVALID)
		return -1;

	/* Init pktio entry */
	memset(pkt_nm, 0, sizeof(*pkt_nm));
	pkt_nm->sockfd = -1;
	pkt_nm->pool = pool;

	/* max frame len taking into account the l2-offset */
	pkt_nm->max_frame_len = ODP_CONFIG_PACKET_BUF_LEN_MAX -
		odp_buffer_pool_headroom(pool) -
		odp_buffer_pool_tailroom(pool);

	snprintf(pktio_entry->s.name, sizeof(pktio_entry->s.name), "%s",
		 netdev);
	snprintf(ifname, sizeof(ifname), "netmap:%s", netdev);

	if (mmap_desc.mem == NULL)
		pkt_nm->desc = nm_open(ifname, NULL, NETMAP_NO_TX_POLL, NULL);
	else
		pkt_nm->desc = nm_open(ifname, NULL, NETMAP_NO_TX_POLL |
				       NM_OPEN_NO_MMAP, &mmap_desc);
	if (pkt_nm->desc == NULL) {
		ODP_ERR("nm_open(%s) failed\n", ifname);
		goto error;
	}

	if (mmap_desc.mem == NULL) {
		mmap_desc.mem = pkt_nm->desc->mem;
		mmap_desc.memsize = pkt_nm->desc->memsize;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		ODP_ERR("Cannot get device control socket\n");
		goto error;
	}
	pkt_nm->sockfd = sockfd;

	err = netmap_do_ioctl(pktio_entry, SIOCGIFFLAGS, 0);
	if (err)
		goto error;
	if ((pkt_nm->if_flags & IFF_UP) == 0)
		ODP_DBG("%s is down\n", pktio_entry->s.name);

	err = mac_addr_get_fd(sockfd, netdev, pkt_nm->if_mac);
	if (err)
		goto error;

	/* Wait for the link to come up */
	for (i = 0; i < NM_OPEN_RETRIES; i++) {
		err = netmap_do_ioctl(pktio_entry, SIOCETHTOOL, ETHTOOL_GLINK);
		/* nm_open() causes the physical link to reset. When using a
		 * direct attached loopback cable there may be a small delay
		 * until the opposing end's interface comes back up again. In
		 * this case without the additional sleep pktio validation
		 * tests fail. */
		sleep(1);
		if (err == 0)
			return 0;
	}
	ODP_ERR("%s didn't come up\n", pktio_entry->s.name);

error:
	netmap_close(pktio_entry);
	return -1;
}

static void netmap_recv_cb(u_char *arg, const struct nm_pkthdr *hdr,
			   const u_char *buf)
{
	struct dispatch_args *args = (struct dispatch_args *)arg;
	pkt_netmap_t *pkt_nm = &args->pktio_entry->s.pkt_nm;
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;
	size_t frame_len = (size_t)hdr->len;

	if (odp_unlikely(frame_len > pkt_nm->max_frame_len)) {
		ODP_ERR("RX: frame too big %u %lu!\n", (unsigned)frame_len,
			pkt_nm->max_frame_len);
		return;
	}

	if (odp_unlikely(frame_len < ODPH_ETH_LEN_MIN)) {
		ODP_ERR("RX: Frame truncated: %u\n", (unsigned)frame_len);
		return;
	}

	pkt = packet_alloc(pkt_nm->pool, frame_len, 1);
	if (pkt == ODP_PACKET_INVALID)
		return;

	pkt_hdr = odp_packet_hdr(pkt);

	/* For now copy the data in the mbuf,
	   worry about zero-copy later */
	if (odp_packet_copydata_in(pkt, 0, frame_len, buf) != 0) {
		odp_packet_free(pkt);
		return;
	}

	packet_parse_l2(pkt_hdr);

	args->pkt_table[args->nb_rx++] = pkt;
}

static int netmap_recv(pktio_entry_t *pktio_entry, odp_packet_t pkt_table[],
		       unsigned num)
{
	struct dispatch_args args;
	struct nm_desc *nm_desc = pktio_entry->s.pkt_nm.desc;
	struct pollfd polld;

	polld.fd = nm_desc->fd;
	polld.events = POLLIN;

	args.pkt_table = pkt_table;
	args.nb_rx = 0;
	args.pktio_entry = pktio_entry;

	nm_dispatch(nm_desc, num, netmap_recv_cb, (u_char *)&args);
	if (args.nb_rx == 0) {
		if (odp_unlikely(poll(&polld, 1, 0) < 0))
			ODP_ERR("RX: poll error\n");
	}
	return args.nb_rx;
}

static int netmap_send(pktio_entry_t *pktio_entry, odp_packet_t pkt_table[],
		       unsigned num)
{
	struct nm_desc *nm_desc = pktio_entry->s.pkt_nm.desc;
	struct pollfd polld;
	unsigned i, nb_tx;
	uint8_t *frame;
	uint32_t frame_len;

	polld.fd = nm_desc->fd;
	polld.events = POLLOUT;

	for (nb_tx = 0; nb_tx < num; nb_tx++) {
		frame_len = 0;
		frame = odp_packet_l2_ptr(pkt_table[nb_tx], &frame_len);
		for (i = 0; i < NM_INJECT_RETRIES; i++) {
			if (nm_inject(nm_desc, frame, frame_len) == 0)
				poll(&polld, 1, 0);
			else
				break;
		}
		if (odp_unlikely(i == NM_INJECT_RETRIES)) {
			ioctl(nm_desc->fd, NIOCTXSYNC, NULL);
			break;
		}
	}
	for (i = 0; i < nb_tx; i++)
		odp_packet_free(pkt_table[i]);

	return nb_tx;
}

static int netmap_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	memcpy(mac_addr, pktio_entry->s.pkt_nm.if_mac, ETH_ALEN);
	return ETH_ALEN;
}

static int netmap_mtu_get(pktio_entry_t *pktio_entry)
{
	return mtu_get_fd(pktio_entry->s.pkt_nm.sockfd, pktio_entry->s.name);
}

static int netmap_promisc_mode_set(pktio_entry_t *pktio_entry,
				   odp_bool_t enable)
{
	return promisc_mode_set_fd(pktio_entry->s.pkt_nm.sockfd,
				   pktio_entry->s.name, enable);
}

static int netmap_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return promisc_mode_get_fd(pktio_entry->s.pkt_nm.sockfd,
				   pktio_entry->s.name);
}

const pktio_if_ops_t netmap_pktio_ops = {
	.init = NULL,
	.term = NULL,
	.open = netmap_open,
	.close = netmap_close,
	.start = NULL,
	.stop = NULL,
	.recv = netmap_recv,
	.send = netmap_send,
	.mtu_get = netmap_mtu_get,
	.promisc_mode_set = netmap_promisc_mode_set,
	.promisc_mode_get = netmap_promisc_mode_get,
	.mac_get = netmap_mac_addr_get
};

#endif /* ODP_NETMAP */

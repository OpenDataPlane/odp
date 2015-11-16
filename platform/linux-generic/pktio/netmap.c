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

	if (pkt_nm->rx_desc != NULL) {
		nm_close(pkt_nm->rx_desc);
		mmap_desc.mem = NULL;
	}
	if (pkt_nm->tx_desc != NULL)
		nm_close(pkt_nm->tx_desc);

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
		pkt_nm->rx_desc = nm_open(ifname, NULL, NETMAP_NO_TX_POLL,
					  NULL);
	else
		pkt_nm->rx_desc = nm_open(ifname, NULL, NETMAP_NO_TX_POLL |
					  NM_OPEN_NO_MMAP, &mmap_desc);
	pkt_nm->tx_desc = nm_open(ifname, NULL, NM_OPEN_NO_MMAP, &mmap_desc);

	if (pkt_nm->rx_desc == NULL || pkt_nm->tx_desc == NULL) {
		ODP_ERR("nm_open(%s) failed\n", ifname);
		goto error;
	}

	if (mmap_desc.mem == NULL) {
		mmap_desc.mem = pkt_nm->rx_desc->mem;
		mmap_desc.memsize = pkt_nm->rx_desc->memsize;
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

/**
 * Create ODP packet from netmap packet
 *
 * @param pktio_entry    Packet IO handle
 * @param pkt_out        Storage for new ODP packet handle
 * @param buf            Netmap buffer address
 * @param len            Netmap buffer length
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
static inline int netmap_pkt_to_odp(pktio_entry_t *pktio_entry,
				    odp_packet_t *pkt_out, const char *buf,
				    uint16_t len)
{
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;

	if (odp_unlikely(len > pktio_entry->s.pkt_nm.max_frame_len)) {
		ODP_ERR("RX: frame too big %" PRIu16 " %zu!\n", len,
			pktio_entry->s.pkt_nm.max_frame_len);
		return -1;
	}

	if (odp_unlikely(len < ODPH_ETH_LEN_MIN)) {
		ODP_ERR("RX: Frame truncated: %" PRIu16 "\n", len);
		return -1;
	}

	pkt = packet_alloc(pktio_entry->s.pkt_nm.pool, len, 1);
	if (pkt == ODP_PACKET_INVALID)
		return -1;

	pkt_hdr = odp_packet_hdr(pkt);

	/* For now copy the data in the mbuf,
	   worry about zero-copy later */
	if (odp_packet_copydata_in(pkt, 0, len, buf) != 0) {
		odp_packet_free(pkt);
		return -1;
	}
	packet_parse_l2(pkt_hdr);

	*pkt_out = pkt;
	return 0;
}

static int netmap_recv(pktio_entry_t *pktio_entry, odp_packet_t pkt_table[],
		       unsigned num)
{
	struct netmap_ring *ring;
	struct nm_desc *desc = pktio_entry->s.pkt_nm.rx_desc;
	struct pollfd polld;
	char *buf;
	int i;
	int num_rings = desc->last_rx_ring - desc->first_rx_ring + 1;
	int ring_id = desc->cur_rx_ring;
	unsigned num_rx = 0;
	uint32_t slot_id;

	polld.fd = desc->fd;
	polld.events = POLLIN;

	for (i = 0; i < num_rings && num_rx != num; i++) {
		ring_id = desc->cur_rx_ring + i;

		if (ring_id > desc->last_rx_ring)
			ring_id = desc->first_rx_ring;

		ring = NETMAP_RXRING(desc->nifp, ring_id);

		while (!nm_ring_empty(ring) && num_rx != num) {
			slot_id = ring->cur;
			buf = NETMAP_BUF(ring, ring->slot[slot_id].buf_idx);

			odp_prefetch(buf);

			if (!netmap_pkt_to_odp(pktio_entry, &pkt_table[num_rx],
					       buf, ring->slot[slot_id].len))
				num_rx++;

			ring->cur = nm_ring_next(ring, slot_id);
			ring->head = ring->cur;
		}
	}
	desc->cur_rx_ring = ring_id;

	if (num_rx == 0) {
		if (odp_unlikely(poll(&polld, 1, 0) < 0))
			ODP_ERR("RX: poll error\n");
	}
	return num_rx;
}

static int netmap_send(pktio_entry_t *pktio_entry, odp_packet_t pkt_table[],
		       unsigned num)
{
	struct pollfd polld;
	struct nm_desc *nm_desc = pktio_entry->s.pkt_nm.tx_desc;
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
	/* Send pending packets */
	poll(&polld, 1, 0);

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
	.name = "netmap",
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

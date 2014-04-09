/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*
 * NETMAP I/O code inspired by the pkt-gen example application in netmap by:
 * Copyright (C) 2011-2014 Matteo Landi, Luigi Rizzo. All rights reserved.
 * Copyright (C) 2013-2014 Universita` di Pisa. All rights reserved.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <odp_packet_internal.h>
#include <odp_hints.h>
#include <odp_thread.h>

#include <helper/odp_eth.h>
#include <helper/odp_ip.h>
#include <helper/odp_packet_helper.h>

#define NETMAP_WITH_LIBS
#include <odp_packet_netmap.h>

/** Eth buffer start offset from u32-aligned address to make sure the following
 * header (e.g. IP) starts at a 32-bit aligned address.
 */
#define ETHBUF_OFFSET (ODP_ALIGN_ROUNDUP(ODP_ETHHDR_LEN, sizeof(uint32_t)) \
				- ODP_ETHHDR_LEN)

/** Round up buffer address to get a properly aliged eth buffer, i.e. aligned
 * so that the next header always starts at a 32bit aligned address.
 */
#define ETHBUF_ALIGN(buf_ptr) ((uint8_t *)ODP_ALIGN_ROUNDUP_PTR((buf_ptr), \
				sizeof(uint32_t)) + ETHBUF_OFFSET)

#define ETH_PROMISC  1 /* TODO: maybe this should be exported to the user */
#define WAITLINK_TMO 2

static int nm_do_ioctl(pkt_netmap_t * const pkt_nm, unsigned long cmd,
		       int subcmd)
{
	struct ethtool_value eval;
	struct ifreq ifr;
	int error;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		ODP_ERR("Error: cannot get device control socket\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, pkt_nm->ifname, sizeof(ifr.ifr_name));

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
	error = ioctl(fd, cmd, &ifr);
	if (error)
		goto done;

	switch (cmd) {
	case SIOCGIFFLAGS:
		pkt_nm->if_flags = (ifr.ifr_flags << 16) |
			(0xffff & ifr.ifr_flags);
		ODP_DBG("flags are 0x%x\n", pkt_nm->if_flags);
		break;
	default:
		break;
	}
done:
	close(fd);
	if (error)
		ODP_ERR("ioctl err %d %lu: %s\n", error, cmd, strerror(errno));

	return error;
}

int setup_pkt_netmap(pkt_netmap_t * const pkt_nm, char *netdev,
		     odp_buffer_pool_t pool, netmap_params_t *nm_params)
{
	char qname[ODP_QUEUE_NAME_LEN];
	char ifname[32];
	odp_packet_t pkt;
	odp_buffer_t token;
	uint8_t *pkt_buf;
	uint16_t ringid;
	uint8_t *l2_hdr;
	int ret;

	if (pool == ODP_BUFFER_POOL_INVALID)
		return -1;
	pkt_nm->pool = pool;

	pkt = odp_packet_alloc(pool);
	if (!odp_packet_is_valid(pkt))
		return -1;

	pkt_buf = odp_packet_buf_addr(pkt);
	l2_hdr = ETHBUF_ALIGN(pkt_buf);
	/* Store eth buffer offset for buffers from this pool */
	pkt_nm->frame_offset = (uintptr_t)l2_hdr - (uintptr_t)pkt_buf;
	/* pkt buffer size */
	pkt_nm->buf_size = odp_packet_buf_size(pkt);
	/* max frame len taking into account the l2-offset */
	pkt_nm->max_frame_len = pkt_nm->buf_size - pkt_nm->frame_offset;
	/* save netmap_mode for later use */
	pkt_nm->netmap_mode = nm_params->netmap_mode;

	odp_packet_free(pkt);

	if (nm_params->netmap_mode == ODP_NETMAP_MODE_SW)
		ringid = NETMAP_SW_RING;
	else
		ringid = nm_params->ringid;

	strncpy(pkt_nm->ifname, netdev, sizeof(pkt_nm->ifname));
	snprintf(ifname, sizeof(ifname), "netmap:%s", netdev);
	pkt_nm->nm_desc = nm_open(ifname, NULL, ringid, 0);

	if (pkt_nm->nm_desc == NULL) {
		ODP_ERR("Error opening nm interface: %s\n", strerror(errno));
		return -1;
	}

	ODP_DBG("thread %d mode %s mmap addr %p\n",
		odp_thread_id(),
		nm_params->netmap_mode == ODP_NETMAP_MODE_SW ? "SW" : "HW",
		pkt_nm->nm_desc->mem);

	if (nm_params->netmap_mode == ODP_NETMAP_MODE_SW) {
		pkt_nm->rxring = NETMAP_RXRING(pkt_nm->nm_desc->nifp,
				    pkt_nm->nm_desc->req.nr_rx_rings);
		pkt_nm->txring = NETMAP_TXRING(pkt_nm->nm_desc->nifp,
				     pkt_nm->nm_desc->req.nr_tx_rings);
	} else {
		pkt_nm->rxring = NETMAP_RXRING(pkt_nm->nm_desc->nifp, 0);
		pkt_nm->txring = NETMAP_TXRING(pkt_nm->nm_desc->nifp, 0);
	}

	/* Set TX checksumming if hardware rings */
	if (nm_params->netmap_mode == ODP_NETMAP_MODE_HW) {
		ret = nm_do_ioctl(pkt_nm, SIOCGIFFLAGS, 0);
		if (ret)
			return ret;
		if ((pkt_nm->if_flags & IFF_UP) == 0) {
			ODP_DBG("%s is down, bringing up...\n", pkt_nm->ifname);
			pkt_nm->if_flags |= IFF_UP;
		}
		if (ETH_PROMISC) {
			pkt_nm->if_flags |= IFF_PROMISC;
			nm_do_ioctl(pkt_nm, SIOCSIFFLAGS, 0);
		}
		ret = nm_do_ioctl(pkt_nm, SIOCETHTOOL, ETHTOOL_SGSO);
		if (ret)
			ODP_DBG("ETHTOOL_SGSO not supported\n");

		ret = nm_do_ioctl(pkt_nm, SIOCETHTOOL, ETHTOOL_STSO);
		if (ret)
			ODP_DBG("ETHTOOL_STSO not supported\n");
		/* TODO: This seems to cause the app to not receive frames
		 * first time it is launched after netmap driver is inserted.
		 * Should be investigated further.
		 */
		/*
		nm_do_ioctl(pkt_nm, SIOCETHTOOL, ETHTOOL_SRXCSUM);
		*/
		ret = nm_do_ioctl(pkt_nm, SIOCETHTOOL, ETHTOOL_STXCSUM);
		if (ret)
			ODP_DBG("ETHTOOL_STXCSUM not supported\n");
	}

	/* Set up the TX access queue */
	snprintf(qname, sizeof(qname), "%s:%s-pktio_tx_access", netdev,
		 nm_params->netmap_mode == ODP_NETMAP_MODE_SW ? "SW" : "HW");
	pkt_nm->tx_access = odp_queue_create(qname, ODP_QUEUE_TYPE_POLL, NULL);
	if (pkt_nm->tx_access == ODP_QUEUE_INVALID) {
		ODP_ERR("Error: pktio queue creation failed\n");
		return -1;
	}
	token = odp_buffer_alloc(pool);
	if (!odp_buffer_is_valid(token)) {
		ODP_ERR("Error: token creation failed\n");
		return -1;
	}

	odp_queue_enq(pkt_nm->tx_access, token);

	ODP_DBG("Wait for link to come up\n");
	sleep(WAITLINK_TMO);
	ODP_DBG("Done\n");

	return 0;
}

int close_pkt_netmap(pkt_netmap_t * const pkt_nm)
{
	if (pkt_nm->nm_desc != NULL) {
		nm_close(pkt_nm->nm_desc);
		pkt_nm->nm_desc = NULL;
	}

	return 0;
}

int recv_pkt_netmap(pkt_netmap_t * const pkt_nm, odp_packet_t pkt_table[],
		    unsigned len)
{
	struct netmap_ring *rxring;
	int fd;
	unsigned nb_rx = 0;
	uint32_t limit, rx;
	odp_packet_t pkt = ODP_PACKET_INVALID;
#ifdef NETMAP_BLOCKING_IO
	struct pollfd fds[1];
	int ret;
#endif

	fd = pkt_nm->nm_desc->fd;
#ifdef NETMAP_BLOCKING_IO
	fds[0].fd = fd;
	fds[0].events = POLLIN;
#endif

	rxring = pkt_nm->rxring;
	while (nb_rx < len) {
#ifdef NETMAP_BLOCKING_IO
		ret = poll(&fds[0], 1, 50);
		if (ret <= 0 || (fds[0].revents & POLLERR))
			break;
#else
		ioctl(fd, NIOCRXSYNC, NULL);
#endif

		if (nm_ring_empty(rxring)) {
			/* No data on the wire, return to scheduler */
			break;
		}

		limit = len - nb_rx;
		if (nm_ring_space(rxring) < limit)
			limit = nm_ring_space(rxring);

		ODP_DBG("receiving %d frames out of %u\n", limit, len);

		for (rx = 0; rx < limit; rx++) {
			struct netmap_slot *rslot;
			char *p;
			uint16_t frame_len;
			uint8_t *pkt_buf;
			uint8_t *l2_hdr;
			uint32_t cur;

			if (odp_likely(pkt == ODP_PACKET_INVALID)) {
				pkt = odp_packet_alloc(pkt_nm->pool);
				if (odp_unlikely(pkt == ODP_PACKET_INVALID))
					break;
			}

			cur = rxring->cur;
			rslot = &rxring->slot[cur];
			p = NETMAP_BUF(rxring, rslot->buf_idx);
			frame_len = rslot->len;

			rxring->head = nm_ring_next(rxring, cur);
			rxring->cur = rxring->head;

			pkt_buf = odp_packet_buf_addr(pkt);
			l2_hdr = pkt_buf + pkt_nm->frame_offset;

			if (frame_len > pkt_nm->max_frame_len) {
				ODP_ERR("RX: frame too big %u %lu!\n",
					frame_len, pkt_nm->max_frame_len);
				/* drop the frame, reuse pkt next interation */
				continue;
			}
			if (odp_unlikely(frame_len < ODP_ETH_LEN_MIN)) {
				if (odp_unlikely(pkt_nm->netmap_mode !=
						 ODP_NETMAP_MODE_SW)) {
					ODP_ERR("RX: Frame truncated: %u\n",
						(unsigned)frame_len);
					continue;
				}
				memset(l2_hdr + frame_len, 0,
				       ODP_ETH_LEN_MIN - frame_len);
				frame_len = ODP_ETH_LEN_MIN;
			}

			/* For now copy the data in the mbuf,
			   worry about zero-copy later */
			memcpy(l2_hdr, p, frame_len);

			/* Initialize, parse and set packet header data */
			odp_packet_init(pkt);
			odp_packet_parse(pkt, frame_len, pkt_nm->frame_offset);

			pkt_table[nb_rx] = pkt;
			pkt = ODP_PACKET_INVALID;
			nb_rx++;
		}

		if (odp_unlikely(pkt == ODP_PACKET_INVALID))
			break;
	}

	if (odp_unlikely(pkt != ODP_PACKET_INVALID))
		odp_buffer_free((odp_buffer_t) pkt);

	if (nb_rx)
		ODP_DBG("<=== rcvd %03u frames from netmap adapter\n", nb_rx);

	return nb_rx;
}

int send_pkt_netmap(pkt_netmap_t * const pkt_nm, odp_packet_t pkt_table[],
		    unsigned len)
{
	int                 fd;
	uint32_t            i;
	uint32_t            limit;
	void               *txbuf;
	struct netmap_ring *txring;
	struct netmap_slot *slot;
	odp_packet_t        pkt;
	odp_buffer_t        token;

	fd = pkt_nm->nm_desc->fd;

	txring = pkt_nm->txring;
	limit = nm_ring_space(txring);
	if (len < limit)
		limit = len;

	ODP_DBG("Sending %d packets out of %d to netmap %p %u\n",
		limit, len, txring, txring->cur);
	token = odp_queue_deq(pkt_nm->tx_access);

	for (i = 0; i < limit; i++) {
		size_t frame_len;
		uint32_t cur;
		uint8_t *frame;

		cur = txring->cur;
		slot = &txring->slot[cur];
		txbuf = NETMAP_BUF(txring, slot->buf_idx);

		pkt = pkt_table[i];
		frame = odp_packet_start(pkt);
		frame_len = odp_packet_get_len(pkt);

		memcpy(txbuf, frame, frame_len);
		slot->len = frame_len;
		txring->head = nm_ring_next(txring, cur);
		txring->cur  = nm_ring_next(txring, cur);
	}

	odp_queue_enq(pkt_nm->tx_access, token);

	/* The netmap examples don't use this anymore, don't know why ... */
	/* ioctl(fd, NIOCTXSYNC, NULL); */
	(void)fd;
	if (limit)
		ODP_DBG("===> sent %03u frames to netmap adapter\n", limit);

	for (i = 0; i < len; i++)
		odp_packet_free(pkt_table[i]);

	return limit;
}

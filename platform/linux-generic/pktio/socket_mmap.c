/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2013-2022, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/api/debug.h>
#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/ticketlock.h>

#include <odp/api/plat/packet_inlines.h>

#include <odp_socket_common.h>
#include <odp_parse_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_stats.h>
#include <odp_debug_internal.h>
#include <odp_errno_define.h>
#include <odp_classification_datamodel.h>
#include <odp_classification_internal.h>
#include <odp_global_data.h>
#include <odp_macros_internal.h>

#include <protocols/eth.h>
#include <protocols/ip.h>

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
#include <time.h>
#include <linux/if_packet.h>

/* VLAN flags in tpacket2_hdr status */
#ifdef TP_STATUS_VLAN_TPID_VALID
#define VLAN_VALID (TP_STATUS_VLAN_VALID | TP_STATUS_VLAN_TPID_VALID)
#else
#define VLAN_VALID (TP_STATUS_VLAN_VALID)
#endif

/* Reserve 4MB memory for frames in a RX/TX ring */
#define FRAME_MEM_SIZE (4 * 1024 * 1024)
#define BLOCK_SIZE     (4 * 1024)

/** packet mmap ring */
struct ring {
	odp_ticketlock_t lock;
	struct iovec *rd;
	unsigned int frame_num;
	int rd_num;

	odp_shm_t shm;
	int sock;
	int type;
	int version;
	uint8_t *mm_space;
	size_t mm_len;
	size_t rd_len;
	int flen;

	struct tpacket_req req;
};

ODP_STATIC_ASSERT(offsetof(struct ring, mm_space) <= ODP_CACHE_LINE_SIZE,
		  "ERR_STRUCT_RING");

/** Packet socket using mmap rings for both Rx and Tx */
typedef struct {
	/** Packet mmap ring for Rx */
	struct ring rx_ring ODP_ALIGNED_CACHE;
	/** Packet mmap ring for Tx */
	struct ring tx_ring ODP_ALIGNED_CACHE;

	int sockfd ODP_ALIGNED_CACHE;
	odp_pool_t pool;
	int mtu; /**< maximum transmission unit */
	uint32_t mtu_max; /**< maximum supported MTU value */
	size_t frame_offset; /**< frame start offset from start of pkt buf */
	uint8_t *mmap_base;
	unsigned int mmap_len;
	unsigned char if_mac[ETH_ALEN];
	struct sockaddr_ll ll;
} pkt_sock_mmap_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_sock_mmap_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_sock_mmap_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_sock_mmap_t *)(uintptr_t)(pktio_entry->s.pkt_priv);
}

static int disable_pktio; /** !0 this pktio disabled, 0 enabled */

static int mmap_pkt_socket(void)
{
	int ver = TPACKET_V2;

	int ret, sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (sock == -1) {
		_odp_errno = errno;
		ODP_ERR("socket(SOCK_RAW): %s\n", strerror(errno));
		return -1;
	}

	ret = setsockopt(sock, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
	if (ret == -1) {
		_odp_errno = errno;
		ODP_ERR("setsockopt(PACKET_VERSION): %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

static inline unsigned next_frame(unsigned cur_frame, unsigned frame_count)
{
	return odp_unlikely(cur_frame + 1 >= frame_count) ? 0 : cur_frame + 1;
}

static inline unsigned pkt_mmap_v2_rx(pktio_entry_t *pktio_entry,
				      pkt_sock_mmap_t *pkt_sock,
				      odp_packet_t pkt_table[], unsigned num,
				      unsigned char if_mac[])
{
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	unsigned frame_num, next_frame_num;
	uint8_t *pkt_buf, *next_ptr;
	int pkt_len;
	uint32_t alloc_len;
	struct ethhdr *eth_hdr;
	unsigned i;
	unsigned nb_rx;
	struct ring *ring;
	odp_pool_t pool = pkt_sock->pool;
	uint16_t frame_offset = pktio_entry->s.pktin_frame_offset;
	uint16_t vlan_len = 0;
	const odp_proto_layer_t layer = pktio_entry->s.parse_layer;
	const odp_pktin_config_opt_t opt = pktio_entry->s.config.pktin;

	if (opt.bit.ts_all || opt.bit.ts_ptp)
		ts = &ts_val;

	ring  = &pkt_sock->rx_ring;
	frame_num = ring->frame_num;
	next_ptr = ring->rd[frame_num].iov_base;

	for (i = 0, nb_rx = 0; i < num; i++) {
		struct tpacket2_hdr *tp_hdr;
		odp_packet_t pkt;
		odp_packet_hdr_t *hdr;
		int ret;

		tp_hdr = (void *)next_ptr;

		if (tp_hdr->tp_status == TP_STATUS_KERNEL)
			break;

		next_frame_num = next_frame(frame_num, ring->rd_num);
		next_ptr = ring->rd[next_frame_num].iov_base;
		odp_prefetch(next_ptr);
		odp_prefetch(next_ptr + ODP_CACHE_LINE_SIZE);

		if (ts != NULL)
			ts_val = odp_time_global();

		pkt_buf = (uint8_t *)(void *)tp_hdr + tp_hdr->tp_mac;
		pkt_len = tp_hdr->tp_snaplen;

		if (odp_unlikely(pkt_len > pkt_sock->mtu)) {
			tp_hdr->tp_status = TP_STATUS_KERNEL;
			frame_num = next_frame_num;
			ODP_DBG("dropped oversized packet\n");
			continue;
		}

		/* Check if packet had a VLAN header */
		if ((tp_hdr->tp_status & VLAN_VALID) == VLAN_VALID)
			vlan_len = 4;

		alloc_len = pkt_len + frame_offset + vlan_len;
		ret = _odp_packet_alloc_multi(pool, alloc_len, &pkt, 1);

		if (odp_unlikely(ret != 1)) {
			/* Stop receiving packets when pool is empty. Leave
			 * the current frame into the ring. */
			break;
		}

		/* Don't receive packets sent by ourselves */
		eth_hdr = (struct ethhdr *)pkt_buf;
		if (odp_unlikely(ethaddrs_equal(if_mac,
						eth_hdr->h_source))) {
			odp_packet_free(pkt);
			tp_hdr->tp_status = TP_STATUS_KERNEL;
			frame_num = next_frame_num;
			continue;
		}

		hdr = packet_hdr(pkt);

		if (frame_offset)
			pull_head(hdr, frame_offset);

		if (vlan_len)
			pull_head(hdr, vlan_len);

		ret = odp_packet_copy_from_mem(pkt, 0, pkt_len, pkt_buf);
		if (ret != 0) {
			odp_packet_free(pkt);
			tp_hdr->tp_status = TP_STATUS_KERNEL;
			frame_num = next_frame_num;
			continue;
		}

		if (vlan_len) {
			/* Recreate VLAN header. Move MAC addresses and
			 * insert a VLAN header in between source MAC address
			 * and Ethernet type. */
			uint8_t *mac;
			uint16_t *type, *tci;

			push_head(hdr, vlan_len);
			mac = packet_data(hdr);
			memmove(mac, mac + vlan_len, 2 * _ODP_ETHADDR_LEN);
			type  = (uint16_t *)(uintptr_t)
				(mac + 2 * _ODP_ETHADDR_LEN);

			#ifdef TP_STATUS_VLAN_TPID_VALID
			*type = odp_cpu_to_be_16(tp_hdr->tp_vlan_tpid);
			#else
			/* Fallback for old kernels (< v3.14) */
			uint16_t *type2;
			static int warning_printed;

			if (warning_printed == 0) {
				ODP_DBG("Original TPID value lost. Using 0x8100 for single tagged and 0x88a8 for double tagged.\n");
				warning_printed = 1;
			}
			type2 = (uint16_t *)(uintptr_t)(mac + (2 * _ODP_ETHADDR_LEN) + vlan_len);
			/* Recreate TPID 0x88a8 for double tagged and 0x8100 for single tagged */
			if (*type2 == odp_cpu_to_be_16(0x8100))
				*type = odp_cpu_to_be_16(0x88a8);
			else
				*type = odp_cpu_to_be_16(0x8100);
			#endif

			tci   = type + 1;
			*tci  = odp_cpu_to_be_16(tp_hdr->tp_vlan_tci);
		}

		if (layer) {
			if (_odp_packet_parse_common(hdr, pkt_buf, pkt_len,
						     pkt_len, layer, opt) < 0) {
				odp_packet_free(pkt);
				tp_hdr->tp_status = TP_STATUS_KERNEL;
				frame_num = next_frame_num;
				continue;
			}

			if (pktio_cls_enabled(pktio_entry)) {
				odp_pool_t new_pool;

				if (_odp_cls_classify_packet(pktio_entry, pkt_buf,
							     &new_pool, hdr)) {
					odp_packet_free(pkt);
					tp_hdr->tp_status = TP_STATUS_KERNEL;
					frame_num = next_frame_num;
					continue;
				}

				if (odp_unlikely(_odp_pktio_packet_to_pool(
					    &pkt, &hdr, new_pool))) {
					odp_packet_free(pkt);
					tp_hdr->tp_status = TP_STATUS_KERNEL;
					frame_num = next_frame_num;
					odp_atomic_inc_u64(
						&pktio_entry->s.stats_extra
							 .in_discards);
					continue;
				}
			}
		}

		hdr->input = pktio_entry->s.handle;
		packet_set_ts(hdr, ts);

		tp_hdr->tp_status = TP_STATUS_KERNEL;
		frame_num = next_frame_num;

		pkt_table[nb_rx] = pkt;
		nb_rx++;
	}

	ring->frame_num = frame_num;
	return nb_rx;
}

static inline int pkt_mmap_v2_tx(pktio_entry_t *pktio_entry, int sock,
				 struct ring *ring,
				 const odp_packet_t pkt_table[], uint32_t num)
{
	uint32_t i, pkt_len, num_tx, tp_status;
	uint32_t first_frame_num, frame_num, next_frame_num, frame_count;
	int ret;
	uint8_t *buf;
	void *next_ptr;
	struct tpacket2_hdr *tp_hdr[num];
	int total_len = 0;
	uint8_t tx_ts_enabled = _odp_pktio_tx_ts_enabled(pktio_entry);
	uint32_t tx_ts_idx = 0;

	frame_num = ring->frame_num;
	first_frame_num = frame_num;
	frame_count = ring->rd_num;
	next_ptr = ring->rd[frame_num].iov_base;

	if (num > frame_count)
		num = frame_count;

	for (i = 0; i < num; i++) {
		tp_hdr[i] = next_ptr;
		tp_status = tp_hdr[i]->tp_status & 0x7;

		if (tp_status != TP_STATUS_AVAILABLE) {
			if (tp_status == TP_STATUS_WRONG_FORMAT) {
				ODP_ERR("Socket mmap: wrong format\n");
				return -1;
			}

			break;
		}

		next_frame_num = next_frame(frame_num, frame_count);
		next_ptr = ring->rd[next_frame_num].iov_base;
		odp_prefetch(next_ptr);

		pkt_len = odp_packet_len(pkt_table[i]);
		tp_hdr[i]->tp_len = pkt_len;
		total_len += pkt_len;

		buf = (uint8_t *)(void *)tp_hdr[i] + TPACKET2_HDRLEN -
		       sizeof(struct sockaddr_ll);
		odp_packet_copy_to_mem(pkt_table[i], 0, pkt_len, buf);

		tp_hdr[i]->tp_status = TP_STATUS_SEND_REQUEST;

		frame_num = next_frame_num;

		if (tx_ts_enabled && tx_ts_idx == 0) {
			if (odp_unlikely(packet_hdr(pkt_table[i])->p.flags.ts_set))
				tx_ts_idx = i + 1;
		}
	}

	num    = i;
	num_tx = num;

	/* Ping kernel to send packets */
	ret = send(sock, NULL, 0, MSG_DONTWAIT);

	ring->frame_num = frame_num;

	if (odp_unlikely(ret != total_len)) {
		uint32_t frame_sum;

		/* Returns -1 when nothing is sent (send() would block) */
		if (ret < 0 && errno != EWOULDBLOCK) {
			ODP_ERR("Socket mmap: send failed, ret %i, errno %i\n",
				ret, errno);
			return -1;
		}

		/* Check how many first packets have been sent
		 * (TP_STATUS_AVAILABLE or TP_STATUS_SENDING). Assuming that
		 * the rest will not be sent. */
		for (i = 0; i < num; i++) {
			tp_status = tp_hdr[i]->tp_status & 0x7;

			if (tp_status == TP_STATUS_SEND_REQUEST)
				break;

			if (tp_status == TP_STATUS_WRONG_FORMAT) {
				ODP_ERR("Socket mmap: wrong format\n");
				break;
			}
		}

		num_tx = i;

		/* Clear status of not sent packets */
		for (i = num_tx; i < num; i++)
			tp_hdr[i]->tp_status = TP_STATUS_AVAILABLE;

		frame_sum       = first_frame_num + num_tx;
		ring->frame_num = frame_sum;

		if (frame_sum >= frame_count)
			ring->frame_num = frame_sum - frame_count;
	}

	if (odp_unlikely(tx_ts_idx && num_tx >= tx_ts_idx))
		_odp_pktio_tx_ts_set(pktio_entry);

	/* Free sent packets */
	odp_packet_free_multi(pkt_table, num_tx);

	return num_tx;
}

static int mmap_setup_ring(pkt_sock_mmap_t *pkt_sock, struct ring *ring,
			   int type)
{
	odp_shm_t shm;
	uint32_t block_size, block_nr, frame_size, frame_nr;
	uint32_t ring_size;
	int flags;
	int sock = pkt_sock->sockfd;
	int mtu = pkt_sock->mtu_max;
	int ret = 0;

	ring->sock = sock;
	ring->type = type;
	ring->version = TPACKET_V2;

	frame_size = _ODP_ROUNDUP_POWER2_U32(mtu + TPACKET_HDRLEN + TPACKET_ALIGNMENT);
	block_size = BLOCK_SIZE;
	if (frame_size > block_size)
		block_size = frame_size;

	block_nr   = FRAME_MEM_SIZE / block_size;
	frame_nr   = (block_size / frame_size) * block_nr;
	ring_size  = frame_nr * sizeof(struct iovec);
	flags      = 0;

	if (odp_global_ro.shm_single_va)
		flags += ODP_SHM_SINGLE_VA;

	shm = odp_shm_reserve(NULL, ring_size, ODP_CACHE_LINE_SIZE, flags);

	if (shm == ODP_SHM_INVALID) {
		ODP_ERR("Reserving shm failed\n");
		return -1;
	}
	ring->shm = shm;

	ring->req.tp_block_size = block_size;
	ring->req.tp_block_nr   = block_nr;
	ring->req.tp_frame_size = frame_size;
	ring->req.tp_frame_nr   = frame_nr;

	ring->mm_len = ring->req.tp_block_size * ring->req.tp_block_nr;
	ring->rd_num = ring->req.tp_frame_nr;
	ring->flen   = ring->req.tp_frame_size;
	ring->rd_len = ring_size;

	ODP_DBG("  tp_block_size %u\n", ring->req.tp_block_size);
	ODP_DBG("  tp_block_nr   %u\n", ring->req.tp_block_nr);
	ODP_DBG("  tp_frame_size %u\n", ring->req.tp_frame_size);
	ODP_DBG("  tp_frame_nr   %u\n", ring->req.tp_frame_nr);

	ret = setsockopt(sock, SOL_PACKET, type, &ring->req, sizeof(ring->req));
	if (ret == -1) {
		_odp_errno = errno;
		ODP_ERR("setsockopt(pkt mmap): %s\n", strerror(errno));
		return -1;
	}

	ring->rd = odp_shm_addr(shm);
	if (!ring->rd) {
		ODP_ERR("Reading shm addr failed\n");
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
		_odp_errno = errno;
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

static int mmap_unmap_sock(pkt_sock_mmap_t *pkt_sock)
{
	int ret = 0;

	if (pkt_sock->rx_ring.shm != ODP_SHM_INVALID)
		odp_shm_free(pkt_sock->rx_ring.shm);
	if (pkt_sock->tx_ring.shm != ODP_SHM_INVALID)
		odp_shm_free(pkt_sock->tx_ring.shm);

	if (pkt_sock->mmap_base != MAP_FAILED)
		ret = munmap(pkt_sock->mmap_base, pkt_sock->mmap_len);

	return ret;
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
		_odp_errno = errno;
		ODP_ERR("bind(to IF): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int sock_mmap_close(pktio_entry_t *entry)
{
	pkt_sock_mmap_t *const pkt_sock = pkt_priv(entry);
	int ret;

	ret = mmap_unmap_sock(pkt_sock);
	if (ret != 0) {
		ODP_ERR("mmap_unmap_sock() %s\n", strerror(errno));
		return -1;
	}

	if (pkt_sock->sockfd != -1 && close(pkt_sock->sockfd) != 0) {
		_odp_errno = errno;
		ODP_ERR("close(sockfd): %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int sock_mmap_open(odp_pktio_t id ODP_UNUSED,
			  pktio_entry_t *pktio_entry,
			  const char *netdev, odp_pool_t pool)
{
	int if_idx;
	int ret = 0;

	if (disable_pktio)
		return -1;

	pkt_sock_mmap_t *const pkt_sock = pkt_priv(pktio_entry);

	/* Init pktio entry */
	memset(pkt_sock, 0, sizeof(*pkt_sock));
	/* set sockfd to -1, because a valid socked might be initialized to 0 */
	pkt_sock->sockfd = -1;
	pkt_sock->mmap_base = MAP_FAILED;

	if (pool == ODP_POOL_INVALID)
		return -1;

	/* Store eth buffer offset for pkt buffers from this pool */
	pkt_sock->frame_offset = 0;

	pkt_sock->pool = pool;
	odp_ticketlock_init(&pkt_sock->rx_ring.lock);
	odp_ticketlock_init(&pkt_sock->tx_ring.lock);
	pkt_sock->rx_ring.shm = ODP_SHM_INVALID;
	pkt_sock->tx_ring.shm = ODP_SHM_INVALID;
	pkt_sock->sockfd = mmap_pkt_socket();
	if (pkt_sock->sockfd == -1)
		goto error;

	ret = mmap_bind_sock(pkt_sock, netdev);
	if (ret != 0)
		goto error;

	pkt_sock->mtu = _odp_mtu_get_fd(pkt_sock->sockfd, netdev);
	if (!pkt_sock->mtu)
		goto error;
	pkt_sock->mtu_max = _ODP_SOCKET_MTU_MAX;
	if (pkt_sock->mtu > _ODP_SOCKET_MTU_MAX)
		pkt_sock->mtu_max =  pkt_sock->mtu;

	ODP_DBG("MTU size: %i\n", pkt_sock->mtu);

	ODP_DBG("TX ring setup:\n");
	ret = mmap_setup_ring(pkt_sock, &pkt_sock->tx_ring, PACKET_TX_RING);
	if (ret != 0)
		goto error;

	ODP_DBG("RX ring setup:\n");
	ret = mmap_setup_ring(pkt_sock, &pkt_sock->rx_ring, PACKET_RX_RING);
	if (ret != 0)
		goto error;

	ret = mmap_sock(pkt_sock);
	if (ret != 0)
		goto error;

	ret = _odp_mac_addr_get_fd(pkt_sock->sockfd, netdev, pkt_sock->if_mac);
	if (ret != 0)
		goto error;

	if_idx = if_nametoindex(netdev);
	if (if_idx == 0) {
		_odp_errno = errno;
		ODP_ERR("if_nametoindex(): %s\n", strerror(errno));
		goto error;
	}

	pktio_entry->s.stats_type = _odp_sock_stats_type_fd(pktio_entry,
							    pkt_sock->sockfd);
	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED)
		ODP_DBG("pktio: %s unsupported stats\n", pktio_entry->s.name);

	ret = _odp_sock_stats_reset_fd(pktio_entry,
				       pkt_priv(pktio_entry)->sockfd);
	if (ret != 0)
		goto error;

	return 0;

error:
	sock_mmap_close(pktio_entry);
	return -1;
}

static int sock_mmap_fd_set(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			    fd_set *readfds)
{
	pkt_sock_mmap_t *const pkt_sock = pkt_priv(pktio_entry);
	int fd;

	odp_ticketlock_lock(&pktio_entry->s.rxl);
	fd = pkt_sock->sockfd;
	FD_SET(fd, readfds);
	odp_ticketlock_unlock(&pktio_entry->s.rxl);

	return fd;
}

static int sock_mmap_recv(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			  odp_packet_t pkt_table[], int num)
{
	pkt_sock_mmap_t *const pkt_sock = pkt_priv(pktio_entry);
	int ret;

	odp_ticketlock_lock(&pkt_sock->rx_ring.lock);
	ret = pkt_mmap_v2_rx(pktio_entry, pkt_sock, pkt_table, num,
			     pkt_sock->if_mac);
	odp_ticketlock_unlock(&pkt_sock->rx_ring.lock);

	return ret;
}

static int sock_mmap_recv_tmo(pktio_entry_t *pktio_entry, int index,
			      odp_packet_t pkt_table[], int num, uint64_t usecs)
{
	struct timeval timeout;
	int ret;
	int maxfd;
	fd_set readfds;

	ret = sock_mmap_recv(pktio_entry, index, pkt_table, num);
	if (ret != 0)
		return ret;

	timeout.tv_sec = usecs / (1000 * 1000);
	timeout.tv_usec = usecs - timeout.tv_sec * (1000ULL * 1000ULL);

	FD_ZERO(&readfds);
	maxfd = sock_mmap_fd_set(pktio_entry, index, &readfds);

	while (1) {
		ret = select(maxfd + 1, &readfds, NULL, NULL, &timeout);

		if (ret <= 0)
			return ret;

		ret = sock_mmap_recv(pktio_entry, index, pkt_table, num);

		if (ret)
			return ret;

		/* If no packets, continue wait until timeout expires */
	}
}

static int sock_mmap_recv_mq_tmo(pktio_entry_t *pktio_entry[], int index[],
				 uint32_t num_q, odp_packet_t pkt_table[], int num,
				 uint32_t *from, uint64_t usecs)
{
	struct timeval timeout;
	uint32_t i;
	int ret;
	int maxfd = -1, maxfd2;
	fd_set readfds;

	for (i = 0; i < num_q; i++) {
		ret = sock_mmap_recv(pktio_entry[i], index[i], pkt_table, num);

		if (ret > 0 && from)
			*from = i;

		if (ret != 0)
			return ret;
	}

	FD_ZERO(&readfds);

	for (i = 0; i < num_q; i++) {
		maxfd2 = sock_mmap_fd_set(pktio_entry[i], index[i], &readfds);
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
			ret = sock_mmap_recv(pktio_entry[i], index[i],
					     pkt_table, num);

			if (ret > 0 && from)
				*from = i;

			if (ret)
				return ret;
		}

		/* If no packets, continue wait until timeout expires */
	}
}

static int sock_mmap_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			  const odp_packet_t pkt_table[], int num)
{
	int ret;
	pkt_sock_mmap_t *const pkt_sock = pkt_priv(pktio_entry);

	odp_ticketlock_lock(&pkt_sock->tx_ring.lock);
	ret = pkt_mmap_v2_tx(pktio_entry, pkt_sock->tx_ring.sock,
			     &pkt_sock->tx_ring, pkt_table, num);
	odp_ticketlock_unlock(&pkt_sock->tx_ring.lock);

	return ret;
}

static uint32_t sock_mmap_mtu_get(pktio_entry_t *pktio_entry)
{
	return _odp_mtu_get_fd(pkt_priv(pktio_entry)->sockfd,
			       pktio_entry->s.name);
}

static int sock_mmap_mtu_set(pktio_entry_t *pktio_entry, uint32_t maxlen_input,
			     uint32_t maxlen_output ODP_UNUSED)
{
	pkt_sock_mmap_t *pkt_sock = pkt_priv(pktio_entry);
	int ret;

	ret = _odp_mtu_set_fd(pkt_sock->sockfd, pktio_entry->s.name, maxlen_input);
	if (ret)
		return ret;

	pkt_sock->mtu = maxlen_input;

	return 0;
}

static int sock_mmap_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	memcpy(mac_addr, pkt_priv(pktio_entry)->if_mac, ETH_ALEN);
	return ETH_ALEN;
}

static int sock_mmap_promisc_mode_set(pktio_entry_t *pktio_entry,
				      odp_bool_t enable)
{
	return _odp_promisc_mode_set_fd(pkt_priv(pktio_entry)->sockfd,
					pktio_entry->s.name, enable);
}

static int sock_mmap_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return _odp_promisc_mode_get_fd(pkt_priv(pktio_entry)->sockfd,
					pktio_entry->s.name);
}

static int sock_mmap_link_status(pktio_entry_t *pktio_entry)
{
	return _odp_link_status_fd(pkt_priv(pktio_entry)->sockfd,
				   pktio_entry->s.name);
}

static int sock_mmap_link_info(pktio_entry_t *pktio_entry, odp_pktio_link_info_t *info)
{
	return _odp_link_info_fd(pkt_priv(pktio_entry)->sockfd, pktio_entry->s.name, info);
}

static int sock_mmap_capability(pktio_entry_t *pktio_entry,
				odp_pktio_capability_t *capa)
{
	pkt_sock_mmap_t *const pkt_sock = pkt_priv(pktio_entry);

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues  = 1;
	capa->max_output_queues = 1;
	capa->set_op.op.promisc_mode = 1;
	capa->set_op.op.maxlen = 1;

	capa->maxlen.equal = true;
	capa->maxlen.min_input = _ODP_SOCKET_MTU_MIN;
	capa->maxlen.max_input = pkt_sock->mtu_max;
	capa->maxlen.min_output = _ODP_SOCKET_MTU_MIN;
	capa->maxlen.max_output = pkt_sock->mtu_max;

	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;

	capa->config.pktout.bit.ts_ena = 1;

	/* Fill statistics capabilities */
	_odp_sock_stats_capa(pktio_entry, capa);

	return 0;
}

static int sock_mmap_stats(pktio_entry_t *pktio_entry,
			   odp_pktio_stats_t *stats)
{
	return _odp_sock_stats_fd(pktio_entry,
				  stats,
				  pkt_priv(pktio_entry)->sockfd);
}

static int sock_mmap_stats_reset(pktio_entry_t *pktio_entry)
{
	if (pktio_entry->s.stats_type == STATS_UNSUPPORTED) {
		memset(&pktio_entry->s.stats, 0,
		       sizeof(odp_pktio_stats_t));
		return 0;
	}

	return _odp_sock_stats_reset_fd(pktio_entry,
					pkt_priv(pktio_entry)->sockfd);
}

static int sock_mmap_extra_stat_info(pktio_entry_t *pktio_entry,
				     odp_pktio_extra_stat_info_t info[],
				     int num)
{
	return _odp_sock_extra_stat_info(pktio_entry, info, num,
					 pkt_priv(pktio_entry)->sockfd);
}

static int sock_mmap_extra_stats(pktio_entry_t *pktio_entry, uint64_t stats[],
				 int num)
{
	return _odp_sock_extra_stats(pktio_entry, stats, num,
				     pkt_priv(pktio_entry)->sockfd);
}

static int sock_mmap_extra_stat_counter(pktio_entry_t *pktio_entry, uint32_t id,
					uint64_t *stat)
{
	return _odp_sock_extra_stat_counter(pktio_entry, id, stat,
					    pkt_priv(pktio_entry)->sockfd);
}

static int sock_mmap_init_global(void)
{
	if (getenv("ODP_PKTIO_DISABLE_SOCKET_MMAP")) {
		ODP_PRINT("PKTIO: socket mmap skipped,"
				" enabled export ODP_PKTIO_DISABLE_SOCKET_MMAP=1.\n");
		disable_pktio = 1;
	} else  {
		ODP_PRINT("PKTIO: initialized socket mmap,"
				" use export ODP_PKTIO_DISABLE_SOCKET_MMAP=1 to disable.\n");
	}
	return 0;
}

const pktio_if_ops_t _odp_sock_mmap_pktio_ops = {
	.name = "socket_mmap",
	.print = NULL,
	.init_global = sock_mmap_init_global,
	.init_local = NULL,
	.term = NULL,
	.open = sock_mmap_open,
	.close = sock_mmap_close,
	.start = NULL,
	.stop = NULL,
	.stats = sock_mmap_stats,
	.stats_reset = sock_mmap_stats_reset,
	.extra_stat_info = sock_mmap_extra_stat_info,
	.extra_stats = sock_mmap_extra_stats,
	.extra_stat_counter = sock_mmap_extra_stat_counter,
	.recv = sock_mmap_recv,
	.recv_tmo = sock_mmap_recv_tmo,
	.recv_mq_tmo = sock_mmap_recv_mq_tmo,
	.send = sock_mmap_send,
	.fd_set = sock_mmap_fd_set,
	.maxlen_get = sock_mmap_mtu_get,
	.maxlen_set = sock_mmap_mtu_set,
	.promisc_mode_set = sock_mmap_promisc_mode_set,
	.promisc_mode_get = sock_mmap_promisc_mode_get,
	.mac_get = sock_mmap_mac_addr_get,
	.mac_set = NULL,
	.link_status = sock_mmap_link_status,
	.link_info = sock_mmap_link_info,
	.capability = sock_mmap_capability,
	.pktio_ts_res = NULL,
	.pktio_ts_from_ns = NULL,
	.pktio_time = NULL,
	.config = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL,
};

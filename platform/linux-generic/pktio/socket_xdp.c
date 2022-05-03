/* Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/autoheader_internal.h>

#ifdef _ODP_PKTIO_XDP

#include <odp_posix_extensions.h>
#include <odp/api/debug.h>
#include <odp/api/hints.h>
#include <odp/api/system_info.h>
#include <odp/api/ticketlock.h>
#include <odp/api/packet_io_stats.h>

#include <odp_debug_internal.h>
#include <odp_macros_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_internal.h>
#include <odp_parse_internal.h>
#include <odp_classification_internal.h>
#include <odp_socket_common.h>

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

#include <xdp/xsk.h>

#define NUM_XDP_DESCS 1024U
#define MIN_FRAME_SIZE 2048U

#define IF_DELIM " "
#define Q_DELIM ':'

enum {
	RX_PKT_ALLOC_ERR,
	RX_DESC_RSV_ERR,
	TX_PKT_ALLOC_ERR,
	TX_DESC_RSV_ERR
};

static const char * const internal_stats_strs[] = {
	"rx_packet_allocation_errors",
	"rx_umem_descriptor_reservation_errors",
	"tx_packet_allocation_errors",
	"tx_umem_descriptor_reservation_errors"
};

#define MAX_INTERNAL_STATS _ODP_ARRAY_SIZE(internal_stats_strs)

typedef struct {
	struct xsk_ring_prod fill_q;
	struct xsk_ring_cons compl_q;
	struct xsk_umem *umem;
	pool_t *pool;
} xdp_umem_info_t;

typedef struct {
	struct xsk_ring_cons rx;
	struct xsk_ring_cons compl_q;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fill_q;
	uint64_t i_stats[MAX_INTERNAL_STATS];
	xdp_umem_info_t *umem_info;
	struct xsk_socket *xsk;
	int pktio_idx;
	int helper_sock;
	uint32_t mtu;
	uint32_t max_mtu;
} xdp_sock_info_t;

typedef struct {
	odp_ticketlock_t rx_lock ODP_ALIGNED_CACHE;
	odp_ticketlock_t tx_lock ODP_ALIGNED_CACHE;
	xdp_sock_info_t sock_info;
} pkt_xdp_t;

typedef struct {
	odp_packet_hdr_t *pkt_hdr;
	odp_packet_t pkt;
	uint8_t *data;
	uint32_t len;
} pkt_data_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_xdp_t),
		  "PKTIO_PRIVATE_SIZE too small");

static odp_bool_t disable_pktio;

static int sock_xdp_init_global(void)
{
	if (getenv("ODP_PKTIO_DISABLE_SOCKET_XDP")) {
		ODP_PRINT("PKTIO: socket xdp skipped,"
			  " enabled export ODP_PKTIO_DISABLE_SOCKET_XDP=1.\n");
		disable_pktio = true;
	} else {
		ODP_PRINT("PKTIO: initialized socket xdp,"
			  " use export ODP_PKTIO_DISABLE_SOCKET_XDP=1 to disable.\n");
	}

	return 0;
}

static inline pkt_xdp_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_xdp_t *)(uintptr_t)(pktio_entry->s.pkt_priv);
}

static void fill_socket_config(struct xsk_socket_config *config)
{
	config->rx_size = NUM_XDP_DESCS;
	config->tx_size = NUM_XDP_DESCS;
	config->libxdp_flags = 0U;
	config->xdp_flags = 0U;
	config->bind_flags = XDP_ZEROCOPY; /* TODO: XDP_COPY */
}

static uint32_t get_bind_queue_index(const char *devname)
{
	const char *param = getenv("ODP_PKTIO_XDP_PARAMS");
	char *tmp_str;
	char *tmp;
	char *if_str;
	int idx = 0;

	if (param == NULL)
		goto out;

	tmp_str = strdup(param);

	if (tmp_str == NULL)
		goto out;

	tmp = strtok(tmp_str, IF_DELIM);

	if (tmp == NULL)
		goto out_str;

	while (tmp) {
		if_str = strchr(tmp, Q_DELIM);

		if (if_str != NULL && if_str != &tmp[strlen(tmp) - 1U]) {
			if (strncmp(devname, tmp, (uint64_t)(uintptr_t)(if_str - tmp)) == 0) {
				idx = _ODP_MAX(atoi(++if_str), 0);
				break;
			}
		}

		tmp = strtok(NULL, IF_DELIM);
	}

out_str:
	free(tmp_str);

out:
	return idx;
}

static odp_bool_t reserve_fill_queue_elements(xdp_sock_info_t *sock_info, int num)
{
	pool_t *pool;
	odp_packet_t packets[num];
	int count;
	struct xsk_ring_prod *fill_q;
	uint32_t start_idx;
	int pktio_idx;
	uint32_t block_size;
	odp_packet_hdr_t *pkt_hdr;

	pool = sock_info->umem_info->pool;
	count = odp_packet_alloc_multi(pool->pool_hdl, sock_info->mtu, packets, num);

	if (count <= 0) {
		++sock_info->i_stats[RX_PKT_ALLOC_ERR];
		return false;
	}

	fill_q = &sock_info->fill_q;

	if (xsk_ring_prod__reserve(fill_q, count, &start_idx) == 0U) {
		odp_packet_free_multi(packets, count);
		++sock_info->i_stats[RX_DESC_RSV_ERR];
		return false;
	}

	pktio_idx = sock_info->pktio_idx;
	block_size = pool->block_size;

	for (int i = 0; i < count; ++i) {
		pkt_hdr = packet_hdr(packets[i]);
		pkt_hdr->ms_pktio_idx = pktio_idx;
		*xsk_ring_prod__fill_addr(fill_q, start_idx++) =
			pkt_hdr->event_hdr.index.event * block_size;
	}

	xsk_ring_prod__submit(&sock_info->fill_q, count);

	return true;
}

static inline void lock_rxtx(pkt_xdp_t *priv)
{
	odp_ticketlock_lock(&priv->rx_lock);
	odp_ticketlock_lock(&priv->tx_lock);
}

static inline void unlock_rxtx(pkt_xdp_t *priv)
{
	odp_ticketlock_unlock(&priv->rx_lock);
	odp_ticketlock_unlock(&priv->tx_lock);
}

static int sock_xdp_stats_reset(pktio_entry_t *pktio_entry)
{
	pkt_xdp_t *priv = pkt_priv(pktio_entry);

	lock_rxtx(priv);
	memset(&pktio_entry->s.stats, 0, sizeof(odp_pktio_stats_t));
	unlock_rxtx(priv);

	return 0;
}

static int sock_xdp_open(odp_pktio_t pktio, pktio_entry_t *pktio_entry, const char *devname,
			 odp_pool_t pool_hdl)
{
	pkt_xdp_t *priv;
	pool_t *pool;
	struct xsk_socket_config config;
	uint32_t bind_q;
	int ret;

	if (disable_pktio)
		return -1;

	priv = pkt_priv(pktio_entry);
	memset(priv, 0, sizeof(pkt_xdp_t));
	pool = pool_entry_from_hdl(pool_hdl);
	priv->sock_info.umem_info = (xdp_umem_info_t *)pool->mem_src_data;
	priv->sock_info.xsk = NULL;
	/* Mark transitory kernel-owned packets with the pktio index, so that they can be freed on
	 * close. */
	priv->sock_info.pktio_idx = 1 + odp_pktio_index(pktio);
	fill_socket_config(&config);
	bind_q = get_bind_queue_index(devname);
	/* With xsk_socket__create_shared(), as only one bind queue index can
	 * be passed, NIC in use needs to be configured accordingly to have
	 * only a single combined TX-RX queue, otherwise traffic may not end up
	 * on the socket. For now, always bind to the first queue (overridable
	 * with environment variable). */
	ret = xsk_socket__create_shared(&priv->sock_info.xsk, devname, bind_q,
					priv->sock_info.umem_info->umem, &priv->sock_info.rx,
					&priv->sock_info.tx, &priv->sock_info.fill_q,
					&priv->sock_info.compl_q, &config);

	if (ret) {
		ODP_ERR("Error creating xdp socket for bind queue %u: %d\n", bind_q, ret);
		goto xsk_err;
	}

	/* Ring setup/clean up routines seem to be asynchronous with some drivers and might not be
	 * ready yet after xsk_socket__create_shared(). */
	sleep(1U);

	/* Querying with ioctl() via AF_XDP socket doesn't seem to work, so
	 * create a helper socket for this. */
	priv->sock_info.helper_sock = -1;
	ret = socket(AF_INET, SOCK_DGRAM, 0);

	if (ret == -1) {
		ODP_ERR("Error creating helper socket for xdp: %s\n", strerror(errno));
		goto sock_err;
	}

	priv->sock_info.helper_sock = ret;
	priv->sock_info.mtu = _odp_mtu_get_fd(priv->sock_info.helper_sock, devname);

	if (priv->sock_info.mtu == 0U)
		goto res_err;

	priv->sock_info.max_mtu = pool->seg_len;

	if (!reserve_fill_queue_elements(&priv->sock_info, config.rx_size)) {
		ODP_ERR("Unable to reserve fill queue descriptors.\n");
		goto res_err;
	}

	odp_ticketlock_init(&priv->rx_lock);
	odp_ticketlock_init(&priv->tx_lock);
	sock_xdp_stats_reset(pktio_entry);

	return 0;

res_err:
	close(priv->sock_info.helper_sock);
	priv->sock_info.helper_sock = -1;

sock_err:
	xsk_socket__delete(priv->sock_info.xsk);
	priv->sock_info.xsk = NULL;

xsk_err:
	return -1;
}

static int sock_xdp_close(pktio_entry_t *pktio_entry)
{
	pkt_xdp_t *priv = pkt_priv(pktio_entry);
	pool_t *pool = priv->sock_info.umem_info->pool;
	odp_packet_hdr_t *pkt_hdr;

	if (priv->sock_info.helper_sock != -1)
		close(priv->sock_info.helper_sock);

	if (priv->sock_info.xsk != NULL)
		xsk_socket__delete(priv->sock_info.xsk);

	/* Ring setup/clean up routines seem to be asynchronous with some drivers and might not be
	 * ready yet after xsk_socket__delete(). */
	sleep(1U);

	/* Free all packets that were in fill or completion queues at the time of closing. */
	for (uint32_t i = 0U; i < pool->num + pool->skipped_blocks; ++i) {
		pkt_hdr = packet_hdr(packet_from_event_hdr(event_hdr_from_index(pool, i)));

		if (pkt_hdr->ms_pktio_idx == priv->sock_info.pktio_idx) {
			pkt_hdr->ms_pktio_idx = 0U;
			odp_packet_free(packet_handle(pkt_hdr));
		}
	}

	return 0;
}

static int sock_xdp_stats(pktio_entry_t *pktio_entry, odp_pktio_stats_t *stats)
{
	pkt_xdp_t *priv = pkt_priv(pktio_entry);

	lock_rxtx(priv);
	memcpy(stats, &pktio_entry->s.stats, sizeof(odp_pktio_stats_t));
	unlock_rxtx(priv);

	return 0;
}

static int sock_xdp_extra_stat_info(pktio_entry_t *pktio_entry ODP_UNUSED,
				    odp_pktio_extra_stat_info_t info[],
				    int num)
{
	if (info != NULL && num > 0) {
		for (int i = 0; i < _ODP_MIN(num, (int)MAX_INTERNAL_STATS); ++i) {
			strncpy(info[i].name, internal_stats_strs[i],
				ODP_PKTIO_STATS_EXTRA_NAME_LEN - 1);
		}
	}

	return MAX_INTERNAL_STATS;
}

static int sock_xdp_extra_stats(pktio_entry_t *pktio_entry, uint64_t stats[], int num)
{
	pkt_xdp_t *priv = pkt_priv(pktio_entry);
	uint64_t *i_stats = priv->sock_info.i_stats;

	if (stats != NULL && num > 0) {
		lock_rxtx(priv);

		for (int i = 0; i < _ODP_MIN(num, (int)MAX_INTERNAL_STATS); ++i)
			stats[i] = i_stats[i];

		unlock_rxtx(priv);
	}

	return MAX_INTERNAL_STATS;
}

static int sock_xdp_extra_stat_counter(pktio_entry_t *pktio_entry, uint32_t id, uint64_t *stat)
{
	pkt_xdp_t *priv = pkt_priv(pktio_entry);

	if (id >= MAX_INTERNAL_STATS) {
		ODP_ERR("Invalid counter id: %u (allowed range: 0-%" PRIu64 ")\n", id,
			MAX_INTERNAL_STATS - 1U);
		return -1;
	}

	lock_rxtx(priv);
	*stat = priv->sock_info.i_stats[id];
	unlock_rxtx(priv);

	return 0;
}

static inline void extract_data(const struct xdp_desc *rx_desc, uint8_t *pool_base_addr,
				pkt_data_t *pkt_data)
{
	uint64_t frame_off;
	uint64_t pkt_off;

	/* UMEM "addresses" are offsets from start of a registered UMEM area.
	 * Additionally, the packet data offset (where received packet data
	 * starts within a UMEM frame) is encoded to the UMEM address with
	 * XSK_UNALIGNED_BUF_OFFSET_SHIFT left bitshift when XDP_ZEROCOPY and
	 * XDP_UMEM_UNALIGNED_CHUNK_FLAG are enabled. */
	frame_off = rx_desc->addr;
	pkt_off = xsk_umem__add_offset_to_addr(frame_off);
	frame_off = xsk_umem__extract_addr(frame_off);
	pkt_data->pkt_hdr = xsk_umem__get_data(pool_base_addr, frame_off);
	pkt_data->pkt = packet_handle(pkt_data->pkt_hdr);
	pkt_data->data = xsk_umem__get_data(pool_base_addr, pkt_off);
	pkt_data->len = rx_desc->len;
}

static uint32_t process_received(pktio_entry_t *pktio_entry, xdp_sock_info_t *sock_info,
				 uint32_t start_idx, odp_packet_t packets[], int num)
{
	pkt_data_t pkt_data;
	struct xsk_ring_cons *rx = &sock_info->rx;
	uint8_t *base_addr = sock_info->umem_info->pool->base_addr;
	const odp_proto_layer_t layer = pktio_entry->s.parse_layer;
	int ret;
	const odp_proto_chksums_t in_chksums = pktio_entry->s.in_chksums;
	const odp_pktin_config_opt_t opt = pktio_entry->s.config.pktin;
	uint64_t l4_part_sum = 0U;
	odp_pool_t *pool_hdl = &sock_info->umem_info->pool->pool_hdl;
	uint64_t errors = 0U, octets = 0U;
	odp_pktio_t pktio_hdl = pktio_entry->s.handle;
	uint32_t num_rx = 0U;

	for (int i = 0; i < num; ++i) {
		extract_data(xsk_ring_cons__rx_desc(rx, start_idx++), base_addr, &pkt_data);
		pkt_data.pkt_hdr->ms_pktio_idx = 0U;
		packet_init(pkt_data.pkt_hdr, pkt_data.len);

		if (layer) {
			ret = _odp_packet_parse_common(&pkt_data.pkt_hdr->p, pkt_data.data,
						       pkt_data.len, pkt_data.len,
						       layer, in_chksums, &l4_part_sum, opt);

			if (ret)
				++errors;

			if (ret < 0) {
				odp_packet_free(pkt_data.pkt);
				continue;
			}

			if (pktio_cls_enabled(pktio_entry) &&
			    _odp_cls_classify_packet(pktio_entry, pkt_data.data, pool_hdl,
						     pkt_data.pkt_hdr)) {
				odp_packet_free(pkt_data.pkt);
				continue;
			}
		}

		pkt_data.pkt_hdr->seg_data = pkt_data.data;
		pkt_data.pkt_hdr->event_hdr.base_data = pkt_data.data;
		pkt_data.pkt_hdr->input = pktio_hdl;
		packets[num_rx++] = pkt_data.pkt;
		octets += pkt_data.len;
	}

	pktio_entry->s.stats.in_octets += octets;
	pktio_entry->s.stats.in_packets += num_rx;
	pktio_entry->s.stats.in_errors += errors;

	return num_rx;
}

static int sock_xdp_recv(pktio_entry_t *pktio_entry, int index ODP_UNUSED, odp_packet_t packets[],
			 int num)
{
	pkt_xdp_t *priv;
	struct pollfd fd;
	uint32_t start_idx = 0U, recvd, procd;

	priv = pkt_priv(pktio_entry);
	odp_ticketlock_lock(&priv->rx_lock);

	if (odp_unlikely(xsk_ring_prod__needs_wakeup(&priv->sock_info.fill_q))) {
		fd.fd = xsk_socket__fd(priv->sock_info.xsk);
		fd.events = POLLIN;
		(void)poll(&fd, 1U, 0);
	}

	recvd = xsk_ring_cons__peek(&priv->sock_info.rx, num, &start_idx);

	if (recvd == 0U) {
		odp_ticketlock_unlock(&priv->rx_lock);
		return 0;
	}

	procd = process_received(pktio_entry, &priv->sock_info, start_idx, packets, recvd);
	xsk_ring_cons__release(&priv->sock_info.rx, recvd);
	(void)reserve_fill_queue_elements(&priv->sock_info, recvd);
	odp_ticketlock_unlock(&priv->rx_lock);

	return procd;
}

static inline void populate_tx_desc(pool_t *pool, odp_packet_hdr_t *pkt_hdr,
				    struct xdp_desc *tx_desc)
{
	uint64_t frame_off;
	uint64_t pkt_off;

	frame_off = pkt_hdr->event_hdr.index.event * pool->block_size;
	pkt_off = (uint64_t)(uintptr_t)pkt_hdr->event_hdr.base_data
		  - (uint64_t)(uintptr_t)pool->base_addr - frame_off;
	pkt_off <<= XSK_UNALIGNED_BUF_OFFSET_SHIFT;
	tx_desc->addr = frame_off | pkt_off;
	tx_desc->len = pkt_hdr->frame_len;
}

static void handle_pending_tx(xdp_sock_info_t *sock_info, int num)
{
	struct xsk_ring_cons *compl_q;
	uint32_t sent;
	uint8_t *base_addr;
	uint32_t start_idx;
	uint64_t frame_off;
	odp_packet_t pkt;

	if (odp_unlikely(xsk_ring_prod__needs_wakeup(&sock_info->tx)))
		(void)sendto(xsk_socket__fd(sock_info->xsk), NULL, 0U, MSG_DONTWAIT, NULL, 0U);

	compl_q = &sock_info->compl_q;
	sent = xsk_ring_cons__peek(compl_q, num, &start_idx);
	base_addr = sock_info->umem_info->pool->base_addr;

	odp_packet_t packets[sent];

	if (sent) {
		for (uint32_t i = 0U; i < sent; ++i) {
			frame_off = *xsk_ring_cons__comp_addr(compl_q, start_idx++);
			frame_off = xsk_umem__extract_addr(frame_off);
			pkt = xsk_umem__get_data(base_addr, frame_off);
			packets[i] = pkt;
			packet_hdr(packets[i])->ms_pktio_idx = 0U;
		}

		odp_packet_free_multi(packets, sent);
		xsk_ring_cons__release(compl_q, sent);
	}
}

static int sock_xdp_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			 const odp_packet_t packets[], int num)
{
	pkt_xdp_t *priv;
	xdp_sock_info_t *sock_info;
	pool_t *pool;
	odp_pool_t pool_hdl;
	int pktio_idx, i;
	struct xsk_ring_prod *tx;
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;
	uint32_t start_idx;
	uint64_t octets = 0U;

	if (odp_unlikely(num == 0))
		return 0;

	priv = pkt_priv(pktio_entry);
	odp_ticketlock_lock(&priv->tx_lock);
	sock_info = &priv->sock_info;
	pool = sock_info->umem_info->pool;
	pool_hdl = pool->pool_hdl;
	pktio_idx = sock_info->pktio_idx;
	tx = &sock_info->tx;

	for (i = 0; i < num; ++i) {
		pkt = ODP_PACKET_INVALID;

		if (odp_unlikely(odp_packet_num_segs(packets[i])) > 1) {
			/* TODO: handle segmented packets */
			ODP_ERR("Only single-segment packets supported\n");
			break;
		}

		pkt_hdr = packet_hdr(packets[i]);

		if (pkt_hdr->event_hdr.pool_ptr != pool) {
			pkt = odp_packet_copy(packets[i], pool_hdl);

			if (odp_unlikely(pkt == ODP_PACKET_INVALID)) {
				++sock_info->i_stats[TX_PKT_ALLOC_ERR];
				break;
			}

			pkt_hdr = packet_hdr(pkt);
		}

		if (xsk_ring_prod__reserve(tx, 1U, &start_idx) == 0U) {
			handle_pending_tx(sock_info, NUM_XDP_DESCS);

			if (xsk_ring_prod__reserve(tx, 1U, &start_idx) == 0U) {
				if (pkt != ODP_PACKET_INVALID)
					odp_packet_free(pkt);

				++sock_info->i_stats[TX_DESC_RSV_ERR];

				break;
			}
		}

		if (pkt != ODP_PACKET_INVALID)
			odp_packet_free(packets[i]);

		pkt_hdr->ms_pktio_idx = pktio_idx;
		populate_tx_desc(pool, pkt_hdr, xsk_ring_prod__tx_desc(tx, start_idx));
		octets += odp_packet_len(packet_handle(pkt_hdr));
	}

	xsk_ring_prod__submit(tx, i);
	handle_pending_tx(sock_info, NUM_XDP_DESCS);
	pktio_entry->s.stats.out_octets += octets;
	pktio_entry->s.stats.out_packets += i;
	odp_ticketlock_unlock(&priv->tx_lock);

	return i;
}

static uint32_t sock_xdp_mtu_get(pktio_entry_t *pktio_entry)
{
	return pkt_priv(pktio_entry)->sock_info.mtu;
}

static int sock_xdp_mtu_set(pktio_entry_t *pktio_entry, uint32_t maxlen_input,
			    uint32_t maxlen_output ODP_UNUSED)
{
	pkt_xdp_t *priv = pkt_priv(pktio_entry);
	int ret;

	ret = _odp_mtu_set_fd(priv->sock_info.helper_sock, pktio_entry->s.name, maxlen_input);
	if (ret)
		return ret;

	priv->sock_info.mtu = maxlen_input;

	return 0;
}

static int sock_xdp_promisc_mode_set(pktio_entry_t *pktio_entry,  int enable)
{
	return _odp_promisc_mode_set_fd(pkt_priv(pktio_entry)->sock_info.helper_sock,
					pktio_entry->s.name, enable);
}

static int sock_xdp_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return _odp_promisc_mode_get_fd(pkt_priv(pktio_entry)->sock_info.helper_sock,
					pktio_entry->s.name);
}

static int sock_xdp_mac_addr_get(pktio_entry_t *pktio_entry ODP_UNUSED, void *mac_addr)
{
	return _odp_mac_addr_get_fd(pkt_priv(pktio_entry)->sock_info.helper_sock,
				    pktio_entry->s.name, mac_addr) ? -1 : ETH_ALEN;
}

static int sock_xdp_link_status(pktio_entry_t *pktio_entry)
{
	return _odp_link_status_fd(pkt_priv(pktio_entry)->sock_info.helper_sock,
				   pktio_entry->s.name);
}

static int sock_xdp_link_info(pktio_entry_t *pktio_entry, odp_pktio_link_info_t *info)
{
	return _odp_link_info_fd(pkt_priv(pktio_entry)->sock_info.helper_sock,
				 pktio_entry->s.name, info);
}

static int sock_xdp_capability(pktio_entry_t *pktio_entry, odp_pktio_capability_t *capa)
{
	pkt_xdp_t *priv = pkt_priv(pktio_entry);

	memset(capa, 0, sizeof(odp_pktio_capability_t));
	capa->max_input_queues  = 1U;
	capa->max_output_queues = 1U;
	capa->set_op.op.promisc_mode = 1U;
	capa->set_op.op.maxlen = 1U;

	capa->maxlen.equal = true;
	capa->maxlen.min_input = _ODP_SOCKET_MTU_MIN;
	capa->maxlen.max_input = priv->sock_info.max_mtu;
	capa->maxlen.min_output = _ODP_SOCKET_MTU_MIN;
	capa->maxlen.max_output = priv->sock_info.max_mtu;

	capa->config.parser.layer = ODP_PROTO_LAYER_ALL;

	capa->stats.pktio.counter.in_octets = 1U;
	capa->stats.pktio.counter.in_packets = 1U;
	capa->stats.pktio.counter.in_errors = 1U;
	capa->stats.pktio.counter.out_octets = 1U;
	capa->stats.pktio.counter.out_packets = 1U;

	capa->stats.pktin_queue.all_counters = 0U;
	capa->stats.pktout_queue.all_counters = 0U;

	return 0;
}

const pktio_if_ops_t _odp_sock_xdp_pktio_ops = {
	.name = "socket_xdp",
	.print = NULL,
	.init_global = sock_xdp_init_global,
	.init_local = NULL,
	.term = NULL,
	.open = sock_xdp_open,
	.close = sock_xdp_close,
	.start = NULL,
	.stop = NULL,
	.stats = sock_xdp_stats,
	.stats_reset = sock_xdp_stats_reset,
	.pktin_queue_stats = NULL,
	.pktout_queue_stats = NULL,
	.extra_stat_info = sock_xdp_extra_stat_info,
	.extra_stats = sock_xdp_extra_stats,
	.extra_stat_counter = sock_xdp_extra_stat_counter,
	.pktio_ts_res = NULL,
	.pktio_ts_from_ns = NULL,
	.pktio_time = NULL,
	.recv = sock_xdp_recv,
	.recv_tmo = NULL,
	.recv_mq_tmo = NULL,
	.fd_set = NULL,
	.send = sock_xdp_send,
	.maxlen_get = sock_xdp_mtu_get,
	.maxlen_set = sock_xdp_mtu_set,
	.promisc_mode_set = sock_xdp_promisc_mode_set,
	.promisc_mode_get = sock_xdp_promisc_mode_get,
	.mac_get = sock_xdp_mac_addr_get,
	.mac_set = NULL,
	.link_status = sock_xdp_link_status,
	.link_info = sock_xdp_link_info,
	.capability = sock_xdp_capability,
	.config = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL
};

static odp_bool_t sock_xdp_is_mem_src_active(void)
{
	return !disable_pktio;
}

static void sock_xdp_force_mem_src_disable(void)
{
	disable_pktio = true;
}

static void sock_xdp_adjust_block_size(uint8_t *data ODP_UNUSED, uint32_t *block_size,
				       uint32_t *block_offset ODP_UNUSED, uint32_t *flags)
{
	const uint32_t size = *block_size + XDP_PACKET_HEADROOM;
	const uint64_t ps = odp_sys_page_size();
	/* AF_XDP requires frames to be between 2kB and page size, so with
	 * XDP_ZEROCOPY, if block size is less than 2kB, adjust it to 2kB, if
	 * it is larger than page size, make pool creation fail. */
	if (disable_pktio)
		return;

	if (size > ps) {
		ODP_ERR("Adjusted pool block size larger than page size: %u > %" PRIu64 "\n",
			size, ps);
		*block_size = 0U;
	}

	*flags |= ODP_SHM_HP;
	*block_size = _ODP_MAX(size, MIN_FRAME_SIZE);
}

static int sock_xdp_umem_create(uint8_t *data, pool_t *pool)
{
	struct xsk_umem_config cfg;
	xdp_umem_info_t *umem_info = (xdp_umem_info_t *)data;

	umem_info->pool = pool;
	/* Fill queue size is recommended to be >= HW RX ring size + AF_XDP RX
	 * ring size, so use size twice the size of AF_XDP RX ring. */
	cfg.fill_size = NUM_XDP_DESCS * 2U; /* TODO: num descs vs pool size */
	cfg.comp_size = NUM_XDP_DESCS;
	cfg.frame_size = pool->block_size;
	cfg.frame_headroom = sizeof(odp_packet_hdr_t) + pool->headroom;
	cfg.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;

	return xsk_umem__create(&umem_info->umem, pool->base_addr, pool->shm_size,
				&umem_info->fill_q, &umem_info->compl_q, &cfg);
}

static void sock_xdp_umem_delete(uint8_t *data)
{
	xdp_umem_info_t *umem_info = (xdp_umem_info_t *)data;

	while (xsk_umem__delete(umem_info->umem) == -EBUSY)
		continue;
}

const _odp_pool_mem_src_ops_t _odp_pool_sock_xdp_mem_src_ops = {
	.name = "xdp_zc",
	.is_active = sock_xdp_is_mem_src_active,
	.force_disable = sock_xdp_force_mem_src_disable,
	.adjust_size = sock_xdp_adjust_block_size,
	.bind = sock_xdp_umem_create,
	.unbind = sock_xdp_umem_delete
};

#else
/* Avoid warning about empty translation unit */
typedef int _odp_dummy;
#endif

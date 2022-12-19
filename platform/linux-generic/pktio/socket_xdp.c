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

#include <odp_classification_internal.h>
#include <odp_debug_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_macros_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_internal.h>
#include <odp_parse_internal.h>
#include <odp_pool_internal.h>
#include <odp_socket_common.h>

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <linux/if_xdp.h>

#include <xdp/xsk.h>

#define NUM_DESCS_DEFAULT 1024U
#define MIN_FRAME_SIZE 2048U

#define IF_DELIM " "
#define Q_DELIM ':'
#define CONF_BASE_STR "pktio_xdp"
#define RX_DESCS_STR "num_rx_desc"
#define TX_DESCS_STR "num_tx_desc"

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
	uint64_t rx_dropped;
	uint64_t rx_inv_descs;
	uint64_t tx_inv_descs;
} xdp_sock_stats_t;

typedef struct {
	odp_ticketlock_t rx_lock ODP_ALIGNED_CACHE;
	odp_ticketlock_t tx_lock ODP_ALIGNED_CACHE;
	struct xsk_ring_cons rx;
	struct xsk_ring_cons compl_q;
	struct xsk_ring_prod tx;
	struct xsk_ring_prod fill_q;
	odp_pktin_queue_stats_t qi_stats;
	odp_pktout_queue_stats_t qo_stats;
	xdp_sock_stats_t xdp_stats;
	struct xsk_socket *xsk;
	uint64_t i_stats[MAX_INTERNAL_STATS];
} xdp_sock_t;

typedef struct {
	struct xsk_ring_prod fill_q;
	struct xsk_ring_cons compl_q;
	struct xsk_umem *umem;
	pool_t *pool;
	int num_rx_desc;
	int num_tx_desc;
	uint32_t ref_cnt;
} xdp_umem_info_t;

typedef struct {
	xdp_sock_t qs[ODP_PKTOUT_MAX_QUEUES];
	xdp_umem_info_t *umem_info;
	uint32_t num_q;
	int pktio_idx;
	int helper_sock;
	uint32_t mtu;
	uint32_t max_mtu;
	uint32_t bind_q;
	odp_bool_t lockless_rx;
	odp_bool_t lockless_tx;
} xdp_sock_info_t;

typedef struct {
	odp_packet_hdr_t *pkt_hdr;
	odp_packet_t pkt;
	uint8_t *data;
	uint32_t len;
} pkt_data_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(xdp_sock_info_t),
		  "PKTIO_PRIVATE_SIZE too small");

static odp_bool_t disable_pktio;

static int sock_xdp_init_global(void)
{
	if (getenv("ODP_PKTIO_DISABLE_SOCKET_XDP")) {
		_ODP_PRINT("PKTIO: socket xdp skipped,"
			  " enabled export ODP_PKTIO_DISABLE_SOCKET_XDP=1.\n");
		disable_pktio = true;
	} else {
		_ODP_PRINT("PKTIO: initialized socket xdp,"
			  " use export ODP_PKTIO_DISABLE_SOCKET_XDP=1 to disable.\n");
	}

	return 0;
}

static inline xdp_sock_info_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (xdp_sock_info_t *)(uintptr_t)(pktio_entry->pkt_priv);
}

static void parse_options(xdp_umem_info_t *umem_info)
{
	if (!_odp_libconfig_lookup_ext_int(CONF_BASE_STR, NULL, RX_DESCS_STR,
					   &umem_info->num_rx_desc) ||
	    !_odp_libconfig_lookup_ext_int(CONF_BASE_STR, NULL, TX_DESCS_STR,
					   &umem_info->num_tx_desc)) {
		_ODP_ERR("Unable to parse xdp descriptor configuration, using defaults (%d).\n",
			 NUM_DESCS_DEFAULT);
		goto defaults;
	}

	if (umem_info->num_rx_desc <= 0 || umem_info->num_tx_desc <= 0 ||
	    !_ODP_CHECK_IS_POWER2(umem_info->num_rx_desc) ||
	    !_ODP_CHECK_IS_POWER2(umem_info->num_tx_desc)) {
		_ODP_ERR("Invalid xdp descriptor configuration, using defaults (%d).\n",
			 NUM_DESCS_DEFAULT);
		goto defaults;
	}

	return;

defaults:
	umem_info->num_rx_desc = NUM_DESCS_DEFAULT;
	umem_info->num_tx_desc = NUM_DESCS_DEFAULT;
}

static int umem_create(xdp_umem_info_t *umem_info, pool_t *pool)
{
	struct xsk_umem_config cfg;

	if (umem_info->ref_cnt++ > 0U)
		return 0;

	parse_options(umem_info);
	umem_info->pool = pool;
	/* Fill queue size is recommended to be >= HW RX ring size + AF_XDP RX
	* ring size, so use size twice the size of AF_XDP RX ring. */
	cfg.fill_size = umem_info->num_rx_desc * 2U;
	cfg.comp_size = umem_info->num_tx_desc;
	cfg.frame_size = pool->block_size;
	cfg.frame_headroom = sizeof(odp_packet_hdr_t) + pool->headroom;
	cfg.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;

	return xsk_umem__create(&umem_info->umem, pool->base_addr, pool->shm_size,
				&umem_info->fill_q, &umem_info->compl_q, &cfg);
}

static void umem_delete(xdp_umem_info_t *umem_info)
{
	if (umem_info->ref_cnt-- != 1U)
		return;

	while (xsk_umem__delete(umem_info->umem) == -EBUSY)
		continue;
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

static int sock_xdp_open(odp_pktio_t pktio, pktio_entry_t *pktio_entry, const char *devname,
			 odp_pool_t pool_hdl)
{
	xdp_sock_info_t *priv;
	pool_t *pool;
	int ret;

	if (disable_pktio)
		return -1;

	priv = pkt_priv(pktio_entry);
	memset(priv, 0, sizeof(xdp_sock_info_t));
	pool = _odp_pool_entry(pool_hdl);
	priv->umem_info = (xdp_umem_info_t *)pool->mem_src_data;
	ret = umem_create(priv->umem_info, pool);

	if (ret) {
		_ODP_ERR("Error creating UMEM pool for xdp: %d\n", ret);
		return -1;
	}

	/* Mark transitory kernel-owned packets with the pktio index, so that they can be freed on
	 * close. */
	priv->pktio_idx = 1 + odp_pktio_index(pktio);
	/* Querying with ioctl() via AF_XDP socket doesn't seem to work, so
	 * create a helper socket for this. */
	ret = socket(AF_INET, SOCK_DGRAM, 0);

	if (ret == -1) {
		_ODP_ERR("Error creating helper socket for xdp: %s\n", strerror(errno));
		goto sock_err;
	}

	priv->helper_sock = ret;
	priv->mtu = _odp_mtu_get_fd(priv->helper_sock, devname);

	if (priv->mtu == 0U)
		goto mtu_err;

	priv->max_mtu = pool->seg_len;

	for (int i = 0; i < ODP_PKTOUT_MAX_QUEUES; ++i) {
		odp_ticketlock_init(&priv->qs[i].rx_lock);
		odp_ticketlock_init(&priv->qs[i].tx_lock);
	}

	priv->bind_q = get_bind_queue_index(pktio_entry->name);

	_ODP_DBG("Socket xdp interface (%s):\n", pktio_entry->name);
	_ODP_DBG("  num_rx_desc: %d\n", priv->umem_info->num_rx_desc);
	_ODP_DBG("  num_tx_desc: %d\n", priv->umem_info->num_tx_desc);
	_ODP_DBG("  starting bind queue: %u\n", priv->bind_q);

	return 0;

mtu_err:
	close(priv->helper_sock);

sock_err:
	umem_delete(priv->umem_info);

	return -1;
}

static int sock_xdp_close(pktio_entry_t *pktio_entry)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);
	pool_t *pool = priv->umem_info->pool;
	odp_packet_hdr_t *pkt_hdr;

	close(priv->helper_sock);

	for (uint32_t i = 0U; i < priv->num_q; ++i) {
		if (priv->qs[i].xsk != NULL) {
			xsk_socket__delete(priv->qs[i].xsk);
			priv->qs[i].xsk = NULL;
		}
	}

	umem_delete(priv->umem_info);
	/* Ring setup/clean up routines seem to be asynchronous with some drivers and might not be
	 * ready yet after xsk_socket__delete(). */
	sleep(1U);

	/* Free all packets that were in fill or completion queues at the time of closing. */
	for (uint32_t i = 0U; i < pool->num + pool->skipped_blocks; ++i) {
		pkt_hdr = packet_hdr(packet_from_event_hdr(event_hdr_from_index(pool, i)));

		if (pkt_hdr->ms_pktio_idx == priv->pktio_idx) {
			pkt_hdr->ms_pktio_idx = 0U;
			odp_packet_free(packet_handle(pkt_hdr));
		}
	}

	return 0;
}

static int sock_xdp_stats(pktio_entry_t *pktio_entry, odp_pktio_stats_t *stats)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);
	xdp_sock_t *sock;
	odp_pktin_queue_stats_t qi_stats;
	odp_pktout_queue_stats_t qo_stats;
	struct xdp_statistics xdp_stats;
	socklen_t optlen = sizeof(struct xdp_statistics);

	memset(stats, 0, sizeof(odp_pktio_stats_t));

	for (uint32_t i = 0U; i < priv->num_q; ++i) {
		sock = &priv->qs[i];
		qi_stats = sock->qi_stats;
		qo_stats = sock->qo_stats;
		stats->in_octets += qi_stats.octets;
		stats->in_packets += qi_stats.packets;
		stats->in_errors += qi_stats.errors;
		stats->out_octets += qo_stats.octets;
		stats->out_packets += qo_stats.packets;

		if (!getsockopt(xsk_socket__fd(sock->xsk), SOL_XDP, XDP_STATISTICS, &xdp_stats,
				&optlen)) {
			stats->in_errors += (xdp_stats.rx_dropped - sock->xdp_stats.rx_dropped);
			stats->in_discards +=
				(xdp_stats.rx_invalid_descs - sock->xdp_stats.rx_inv_descs);
			stats->out_discards +=
				(xdp_stats.tx_invalid_descs - sock->xdp_stats.tx_inv_descs);
		}
	}

	return 0;
}

static int sock_xdp_stats_reset(pktio_entry_t *pktio_entry)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);
	xdp_sock_t *sock;
	struct xdp_statistics xdp_stats;
	socklen_t optlen = sizeof(struct xdp_statistics);

	for (uint32_t i = 0U; i < priv->num_q; ++i) {
		sock = &priv->qs[i];
		memset(&sock->qi_stats, 0, sizeof(odp_pktin_queue_stats_t));
		memset(&sock->qo_stats, 0, sizeof(odp_pktout_queue_stats_t));
		memset(sock->i_stats, 0, sizeof(sock->i_stats));

		if (!getsockopt(xsk_socket__fd(sock->xsk), SOL_XDP, XDP_STATISTICS, &xdp_stats,
				&optlen)) {
			sock->xdp_stats.rx_dropped = xdp_stats.rx_dropped;
			sock->xdp_stats.rx_inv_descs = xdp_stats.rx_invalid_descs;
			sock->xdp_stats.tx_inv_descs = xdp_stats.tx_invalid_descs;
		}
	}

	return 0;
}

static int sock_xdp_pktin_queue_stats(pktio_entry_t *pktio_entry, uint32_t index,
				      odp_pktin_queue_stats_t *pktin_stats)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);
	xdp_sock_t *sock;
	struct xdp_statistics xdp_stats;
	socklen_t optlen = sizeof(struct xdp_statistics);

	sock = &priv->qs[index];
	*pktin_stats = sock->qi_stats;

	if (!getsockopt(xsk_socket__fd(sock->xsk), SOL_XDP, XDP_STATISTICS, &xdp_stats, &optlen)) {
		pktin_stats->errors += (xdp_stats.rx_dropped - sock->xdp_stats.rx_dropped);
		pktin_stats->discards +=
			(xdp_stats.rx_invalid_descs - sock->xdp_stats.rx_inv_descs);
	}

	return 0;
}

static int sock_xdp_pktout_queue_stats(pktio_entry_t *pktio_entry, uint32_t index,
				       odp_pktout_queue_stats_t *pktout_stats)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);
	xdp_sock_t *sock;
	struct xdp_statistics xdp_stats;
	socklen_t optlen = sizeof(struct xdp_statistics);

	sock = &priv->qs[index];
	*pktout_stats = sock->qo_stats;

	if (!getsockopt(xsk_socket__fd(sock->xsk), SOL_XDP, XDP_STATISTICS, &xdp_stats, &optlen))
		pktout_stats->discards +=
			(xdp_stats.tx_invalid_descs - sock->xdp_stats.tx_inv_descs);

	return 0;
}

static int sock_xdp_extra_stat_info(pktio_entry_t *pktio_entry, odp_pktio_extra_stat_info_t info[],
				    int num)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);
	const int total_stats = MAX_INTERNAL_STATS * priv->num_q;

	if (info != NULL && num > 0) {
		for (int i = 0; i < _ODP_MIN(num, total_stats); ++i)
			snprintf(info[i].name, ODP_PKTIO_STATS_EXTRA_NAME_LEN - 1,
				 "q%" PRIu64 "_%s", i / MAX_INTERNAL_STATS,
				 internal_stats_strs[i % MAX_INTERNAL_STATS]);
	}

	return total_stats;
}

static int sock_xdp_extra_stats(pktio_entry_t *pktio_entry, uint64_t stats[], int num)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);
	const int total_stats = MAX_INTERNAL_STATS * priv->num_q;
	uint64_t *i_stats;

	if (stats != NULL && num > 0) {
		for (int i = 0; i < _ODP_MIN(num, total_stats); ++i) {
			i_stats = priv->qs[i / MAX_INTERNAL_STATS].i_stats;
			stats[i] = i_stats[i % MAX_INTERNAL_STATS];
		}
	}

	return total_stats;
}

static int sock_xdp_extra_stat_counter(pktio_entry_t *pktio_entry, uint32_t id, uint64_t *stat)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);
	const uint32_t total_stats = MAX_INTERNAL_STATS * priv->num_q;

	if (id >= total_stats) {
		_ODP_ERR("Invalid counter id: %u (allowed range: 0-%u)\n", id, total_stats - 1U);
		return -1;
	}

	*stat = priv->qs[id / MAX_INTERNAL_STATS].i_stats[id % MAX_INTERNAL_STATS];

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

static uint32_t process_received(pktio_entry_t *pktio_entry, xdp_sock_t *sock, pool_t *pool,
				 uint32_t start_idx, odp_packet_t packets[], int num)
{
	struct xsk_ring_cons *rx = &sock->rx;
	uint8_t *base_addr = pool->base_addr;
	pkt_data_t pkt_data;
	const odp_proto_layer_t layer = pktio_entry->parse_layer;
	int ret;
	const odp_pktin_config_opt_t opt = pktio_entry->config.pktin;
	uint64_t errors = 0U, octets = 0U;
	odp_pktio_t pktio_hdl = pktio_entry->handle;
	uint32_t num_rx = 0U;

	for (int i = 0; i < num; ++i) {
		extract_data(xsk_ring_cons__rx_desc(rx, start_idx++), base_addr, &pkt_data);
		pkt_data.pkt_hdr->ms_pktio_idx = 0U;
		packet_init(pkt_data.pkt_hdr, pkt_data.len);
		pkt_data.pkt_hdr->seg_data = pkt_data.data;
		pkt_data.pkt_hdr->event_hdr.base_data = pkt_data.data;

		if (layer) {
			ret = _odp_packet_parse_common(pkt_data.pkt_hdr, pkt_data.data,
						       pkt_data.len, pkt_data.len,
						       layer, opt);

			if (ret)
				++errors;

			if (ret < 0) {
				odp_packet_free(pkt_data.pkt);
				continue;
			}

			if (pktio_cls_enabled(pktio_entry)) {
				odp_pool_t new_pool;

				ret = _odp_cls_classify_packet(pktio_entry, pkt_data.data,
							       &new_pool, pkt_data.pkt_hdr);
				if (ret) {
					odp_packet_free(pkt_data.pkt);
					continue;
				}

				if (odp_unlikely(_odp_pktio_packet_to_pool(
					    &pkt_data.pkt, &pkt_data.pkt_hdr, new_pool))) {
					odp_packet_free(pkt_data.pkt);
					continue;
				}
			}
		}

		pkt_data.pkt_hdr->input = pktio_hdl;
		packets[num_rx++] = pkt_data.pkt;
		octets += pkt_data.len;
	}

	sock->qi_stats.octets += octets;
	sock->qi_stats.packets += num_rx;
	sock->qi_stats.errors += errors;

	return num_rx;
}

static odp_bool_t reserve_fill_queue_elements(xdp_sock_info_t *sock_info, xdp_sock_t *sock,
					      int num)
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
	count = odp_packet_alloc_multi(_odp_pool_handle(pool), sock_info->mtu, packets, num);

	if (count <= 0) {
		++sock->i_stats[RX_PKT_ALLOC_ERR];
		return false;
	}

	fill_q = &sock->fill_q;

	if (xsk_ring_prod__reserve(fill_q, count, &start_idx) == 0U) {
		odp_packet_free_multi(packets, count);
		++sock->i_stats[RX_DESC_RSV_ERR];
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

	xsk_ring_prod__submit(&sock->fill_q, count);

	return true;
}

static int sock_xdp_recv(pktio_entry_t *pktio_entry, int index, odp_packet_t packets[], int num)
{
	xdp_sock_info_t *priv;
	xdp_sock_t *sock;
	struct pollfd fd;
	uint32_t start_idx = 0U, recvd, procd;

	priv = pkt_priv(pktio_entry);
	sock = &priv->qs[index];

	if (!priv->lockless_rx)
		odp_ticketlock_lock(&sock->rx_lock);

	if (odp_unlikely(xsk_ring_prod__needs_wakeup(&sock->fill_q))) {
		fd.fd = xsk_socket__fd(sock->xsk);
		fd.events = POLLIN;
		(void)poll(&fd, 1U, 0);
	}

	recvd = xsk_ring_cons__peek(&sock->rx, num, &start_idx);

	if (recvd == 0U) {
		if (!priv->lockless_rx)
			odp_ticketlock_unlock(&sock->rx_lock);
		return 0;
	}

	procd = process_received(pktio_entry, sock, priv->umem_info->pool, start_idx, packets,
				 recvd);
	xsk_ring_cons__release(&sock->rx, recvd);
	(void)reserve_fill_queue_elements(priv, sock, recvd);

	if (!priv->lockless_rx)
		odp_ticketlock_unlock(&sock->rx_lock);

	return procd;
}

static void handle_pending_tx(xdp_sock_t *sock, uint8_t *base_addr, int num)
{
	struct xsk_ring_cons *compl_q;
	uint32_t sent;
	uint32_t start_idx;
	uint64_t frame_off;
	odp_packet_t pkt;

	if (odp_unlikely(xsk_ring_prod__needs_wakeup(&sock->tx)))
		(void)sendto(xsk_socket__fd(sock->xsk), NULL, 0U, MSG_DONTWAIT, NULL, 0U);

	compl_q = &sock->compl_q;
	sent = xsk_ring_cons__peek(compl_q, num, &start_idx);

	if (sent) {
		odp_packet_t packets[sent];

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

static inline void populate_tx_desc(odp_packet_hdr_t *pkt_hdr, pool_t *pool,
				    struct xdp_desc *tx_desc, uint32_t len)
{
	uint64_t frame_off;
	uint64_t pkt_off;

	frame_off = pkt_hdr->event_hdr.index.event * pool->block_size;
	pkt_off = (uint64_t)(uintptr_t)pkt_hdr->seg_data - (uint64_t)(uintptr_t)pool->base_addr
		  - frame_off;
	pkt_off <<= XSK_UNALIGNED_BUF_OFFSET_SHIFT;
	tx_desc->addr = frame_off | pkt_off;
	tx_desc->len = len;
}

static inline void populate_tx_descs(odp_packet_hdr_t *pkt_hdr, pool_t *pool,
				     struct xsk_ring_prod *tx, int seg_cnt, uint32_t start_idx,
				     int pktio_idx)
{
	if (odp_likely(seg_cnt == 1)) {
		populate_tx_desc(pkt_hdr, pool, xsk_ring_prod__tx_desc(tx, start_idx),
				 pkt_hdr->frame_len);
		pkt_hdr->ms_pktio_idx = pktio_idx;
	} else {
		for (int i = 0; i < seg_cnt; ++i) {
			populate_tx_desc(pkt_hdr, pool, xsk_ring_prod__tx_desc(tx, start_idx++),
					 pkt_hdr->seg_len);
			pkt_hdr->ms_pktio_idx = pktio_idx;
			pkt_hdr = pkt_hdr->seg_next;
		}
	}
}

static int sock_xdp_send(pktio_entry_t *pktio_entry, int index, const odp_packet_t packets[],
			 int num)
{
	xdp_sock_info_t *priv;
	xdp_sock_t *sock;
	pool_t *pool;
	odp_pool_t pool_hdl;
	int pktio_idx, i, seg_cnt;
	struct xsk_ring_prod *tx;
	uint8_t *base_addr;
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;
	uint32_t tx_descs, start_idx, sent = 0U;
	uint64_t octets = 0U;

	if (odp_unlikely(num == 0))
		return 0;

	priv = pkt_priv(pktio_entry);
	sock = &priv->qs[index];

	if (!priv->lockless_tx)
		odp_ticketlock_lock(&sock->tx_lock);

	pool = priv->umem_info->pool;
	pool_hdl = _odp_pool_handle(pool);
	pktio_idx = priv->pktio_idx;
	tx = &sock->tx;
	base_addr = priv->umem_info->pool->base_addr;
	tx_descs = priv->umem_info->num_tx_desc;

	for (i = 0; i < num; ++i) {
		pkt = ODP_PACKET_INVALID;
		pkt_hdr = packet_hdr(packets[i]);
		seg_cnt = pkt_hdr->seg_count;

		if (_odp_pool_entry(pkt_hdr->event_hdr.pool) != pool) {
			pkt = odp_packet_copy(packets[i], pool_hdl);

			if (odp_unlikely(pkt == ODP_PACKET_INVALID)) {
				++sock->i_stats[TX_PKT_ALLOC_ERR];
				break;
			}

			pkt_hdr = packet_hdr(pkt);
			seg_cnt = pkt_hdr->seg_count;
		}

		if (xsk_ring_prod__reserve(tx, seg_cnt, &start_idx) == 0U) {
			handle_pending_tx(sock, base_addr, tx_descs);

			if (xsk_ring_prod__reserve(tx, seg_cnt, &start_idx) == 0U) {
				if (pkt != ODP_PACKET_INVALID)
					odp_packet_free(pkt);

				++sock->i_stats[TX_DESC_RSV_ERR];

				break;
			}
		}

		if (pkt != ODP_PACKET_INVALID)
			odp_packet_free(packets[i]);

		populate_tx_descs(pkt_hdr, pool, tx, seg_cnt, start_idx, pktio_idx);
		sent += seg_cnt;
		octets += pkt_hdr->frame_len;
	}

	xsk_ring_prod__submit(tx, sent);
	handle_pending_tx(sock, base_addr, tx_descs);
	sock->qo_stats.octets += octets;
	sock->qo_stats.packets += i;

	if (!priv->lockless_tx)
		odp_ticketlock_unlock(&sock->tx_lock);

	return i;
}

static uint32_t sock_xdp_mtu_get(pktio_entry_t *pktio_entry)
{
	return pkt_priv(pktio_entry)->mtu;
}

static int sock_xdp_mtu_set(pktio_entry_t *pktio_entry, uint32_t maxlen_input,
			    uint32_t maxlen_output ODP_UNUSED)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);
	int ret;

	ret = _odp_mtu_set_fd(priv->helper_sock, pktio_entry->name, maxlen_input);
	if (ret)
		return ret;

	priv->mtu = maxlen_input;

	return 0;
}

static int sock_xdp_promisc_mode_set(pktio_entry_t *pktio_entry,  int enable)
{
	return _odp_promisc_mode_set_fd(pkt_priv(pktio_entry)->helper_sock,
					pktio_entry->name, enable);
}

static int sock_xdp_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return _odp_promisc_mode_get_fd(pkt_priv(pktio_entry)->helper_sock,
					pktio_entry->name);
}

static int sock_xdp_mac_addr_get(pktio_entry_t *pktio_entry ODP_UNUSED, void *mac_addr)
{
	return _odp_mac_addr_get_fd(pkt_priv(pktio_entry)->helper_sock,
				    pktio_entry->name, mac_addr) ? -1 : ETH_ALEN;
}

static int sock_xdp_link_status(pktio_entry_t *pktio_entry)
{
	return _odp_link_status_fd(pkt_priv(pktio_entry)->helper_sock,
				   pktio_entry->name);
}

static int sock_xdp_link_info(pktio_entry_t *pktio_entry, odp_pktio_link_info_t *info)
{
	return _odp_link_info_fd(pkt_priv(pktio_entry)->helper_sock,
				 pktio_entry->name, info);
}

static int set_queue_capability(int fd, const char *devname, odp_pktio_capability_t *capa)
{
	struct ifreq ifr;
	struct ethtool_channels channels;
	uint32_t max_channels;
	int ret;

	memset(&channels, 0, sizeof(struct ethtool_channels));
	channels.cmd = ETHTOOL_GCHANNELS;
	snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", devname);
	ifr.ifr_data = (char *)&channels;
	ret = ioctl(fd, SIOCETHTOOL, &ifr);

	if (ret == -1 || channels.max_combined == 0U) {
		if (ret == -1 && errno != EOPNOTSUPP) {
			_ODP_ERR("Unable to query NIC channel capabilities: %s\n", strerror(errno));
			return -1;
		}

		channels.max_combined = 1U;
	}

	max_channels = _ODP_MIN((uint32_t)ODP_PKTIN_MAX_QUEUES,
				_ODP_MIN((uint32_t)ODP_PKTOUT_MAX_QUEUES, channels.max_combined));
	capa->equal_num_queues = true;
	capa->max_input_queues = max_channels;
	capa->max_output_queues = max_channels;

	return 0;
}

static int sock_xdp_capability(pktio_entry_t *pktio_entry, odp_pktio_capability_t *capa)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	if (set_queue_capability(priv->helper_sock, pktio_entry->name, capa))
		return -1;

	capa->set_op.op.promisc_mode = 1U;
	capa->set_op.op.maxlen = 1U;

	capa->maxlen.equal = true;
	capa->maxlen.min_input = _ODP_SOCKET_MTU_MIN;
	capa->maxlen.max_input = priv->max_mtu;
	capa->maxlen.min_output = _ODP_SOCKET_MTU_MIN;
	capa->maxlen.max_output = priv->max_mtu;

	capa->config.parser.layer = ODP_PROTO_LAYER_ALL;

	capa->stats.pktio.counter.in_octets = 1U;
	capa->stats.pktio.counter.in_packets = 1U;
	capa->stats.pktio.counter.in_errors = 1U;
	capa->stats.pktio.counter.in_discards = 1U;
	capa->stats.pktio.counter.out_octets = 1U;
	capa->stats.pktio.counter.out_packets = 1U;
	capa->stats.pktio.counter.out_discards = 1U;

	capa->stats.pktin_queue.counter.octets = 1U;
	capa->stats.pktin_queue.counter.packets = 1U;
	capa->stats.pktin_queue.counter.errors = 1U;
	capa->stats.pktin_queue.counter.discards = 1U;
	capa->stats.pktout_queue.counter.octets = 1U;
	capa->stats.pktout_queue.counter.packets = 1U;
	capa->stats.pktout_queue.counter.discards = 1U;

	return 0;
}

static int sock_xdp_input_queues_config(pktio_entry_t *pktio_entry,
					const odp_pktin_queue_param_t *param)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);

	priv->lockless_rx = pktio_entry->param.in_mode == ODP_PKTIN_MODE_SCHED ||
			    param->op_mode == ODP_PKTIO_OP_MT_UNSAFE;

	return 0;
}

static void fill_socket_config(struct xsk_socket_config *config, xdp_umem_info_t *umem_info)
{
	config->rx_size = umem_info->num_rx_desc;
	config->tx_size = umem_info->num_tx_desc;
	config->libxdp_flags = 0U;
	config->xdp_flags = 0U;
	config->bind_flags = XDP_ZEROCOPY; /* TODO: XDP_COPY */
}

static int sock_xdp_output_queues_config(pktio_entry_t *pktio_entry,
					 const odp_pktout_queue_param_t *param)
{
	xdp_sock_info_t *priv = pkt_priv(pktio_entry);
	struct xsk_socket_config config;
	const char *devname = pktio_entry->name;
	uint32_t bind_q, i;
	struct xsk_umem *umem;
	xdp_sock_t *sock;
	int ret;

	priv->lockless_tx = param->op_mode == ODP_PKTIO_OP_MT_UNSAFE;
	fill_socket_config(&config, priv->umem_info);
	bind_q = priv->bind_q;
	umem = priv->umem_info->umem;

	for (i = 0U; i < param->num_queues;) {
		sock = &priv->qs[i];
		ret = xsk_socket__create_shared(&sock->xsk, devname, bind_q, umem, &sock->rx,
						&sock->tx, &sock->fill_q, &sock->compl_q, &config);

		if (ret) {
			_ODP_ERR("Error creating xdp socket for bind queue %u: %d\n", bind_q, ret);
			goto err;
		}

		++i;

		if (!reserve_fill_queue_elements(priv, sock, config.rx_size)) {
			_ODP_ERR("Unable to reserve fill queue descriptors for queue: %u.\n",
				 bind_q);
			goto err;
		}

		++bind_q;
	}

	priv->num_q = i;
	/* Ring setup/clean up routines seem to be asynchronous with some drivers and might not be
	 * ready yet after xsk_socket__create_shared(). */
	sleep(1U);

	return 0;

err:
	for (uint32_t j = 0U; j < i; ++j) {
		xsk_socket__delete(priv->qs[j].xsk);
		priv->qs[j].xsk = NULL;
	}

	return -1;
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
	.pktin_queue_stats = sock_xdp_pktin_queue_stats,
	.pktout_queue_stats = sock_xdp_pktout_queue_stats,
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
	.input_queues_config = sock_xdp_input_queues_config,
	.output_queues_config = sock_xdp_output_queues_config
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
		_ODP_ERR("Adjusted pool block size larger than page size: %u > %" PRIu64 "\n",
			 size, ps);
		*block_size = 0U;
	}

	*flags |= ODP_SHM_HP;
	*block_size = _ODP_MAX(size, MIN_FRAME_SIZE);
}

const _odp_pool_mem_src_ops_t _odp_pool_sock_xdp_mem_src_ops = {
	.name = "xdp_zc",
	.is_active = sock_xdp_is_mem_src_active,
	.force_disable = sock_xdp_force_mem_src_disable,
	.adjust_size = sock_xdp_adjust_block_size,
	.bind = NULL,
	.unbind = NULL
};

#else
/* Avoid warning about empty translation unit */
typedef int _odp_dummy;
#endif

/* Copyright (c) 2016-2018, Linaro Limited
 * Copyright (c) 2019-2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/autoheader_internal.h>

#ifdef _ODP_PKTIO_DPDK

#include <odp_posix_extensions.h>

#include <sched.h>
#include <ctype.h>
#include <unistd.h>
#include <math.h>

#include <odp/api/cpumask.h>

#include <odp/api/packet.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/time.h>
#include <odp/api/plat/time_inlines.h>

#include <odp_packet_io_internal.h>
#include <odp_pool_internal.h>
#include <odp_classification_internal.h>
#include <odp_socket_common.h>
#include <odp_packet_dpdk.h>
#include <odp_pool_internal.h>
#include <odp_debug_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_errno_define.h>
#include <odp_macros_internal.h>

#include <protocols/eth.h>
#include <protocols/udp.h>

#include <rte_config.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#if __GNUC__ >= 7
#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-Wimplicit-fallthrough=0"
#endif
#include <rte_mbuf.h>
#if __GNUC__ >= 7
#pragma GCC diagnostic pop
#endif
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_log.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_string_fns.h>
#include <rte_version.h>

#if RTE_VERSION < RTE_VERSION_NUM(21, 11, 0, 0)
	#define RTE_MBUF_F_RX_RSS_HASH PKT_RX_RSS_HASH
	#define RTE_MBUF_F_TX_IPV4 PKT_TX_IPV4
	#define RTE_MBUF_F_TX_IPV6 PKT_TX_IPV6
	#define RTE_MBUF_F_TX_IP_CKSUM PKT_TX_IP_CKSUM
	#define RTE_MBUF_F_TX_UDP_CKSUM PKT_TX_UDP_CKSUM
	#define RTE_MBUF_F_TX_TCP_CKSUM PKT_TX_TCP_CKSUM
	#define RTE_MEMPOOL_REGISTER_OPS MEMPOOL_REGISTER_OPS
#endif

/* NUMA is not supported on all platforms */
#ifdef _ODP_HAVE_NUMA_LIBRARY
#include <numa.h>
#else
#define numa_num_configured_nodes() 1
#endif

#define MEMPOOL_FLAGS 0

#if _ODP_DPDK_ZERO_COPY
ODP_STATIC_ASSERT(CONFIG_PACKET_HEADROOM == RTE_PKTMBUF_HEADROOM,
		  "ODP and DPDK headroom sizes not matching!");
#endif

/* DPDK poll mode drivers requiring minimum RX burst size DPDK_MIN_RX_BURST */
#define IXGBE_DRV_NAME "net_ixgbe"
#define I40E_DRV_NAME "net_i40e"

#define DPDK_MEMORY_MB 512
#define DPDK_NB_MBUF 16384
#define DPDK_MBUF_BUF_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define DPDK_MEMPOOL_CACHE_SIZE 64

ODP_STATIC_ASSERT((DPDK_NB_MBUF % DPDK_MEMPOOL_CACHE_SIZE == 0) &&
		  (DPDK_MEMPOOL_CACHE_SIZE <= RTE_MEMPOOL_CACHE_MAX_SIZE) &&
		  (DPDK_MEMPOOL_CACHE_SIZE <= DPDK_MBUF_BUF_SIZE * 10 / 15)
		  , "DPDK mempool cache size failure");

/* Minimum RX burst size */
#define DPDK_MIN_RX_BURST 4

/* Limits for setting link MTU */
#define DPDK_MTU_MIN (RTE_ETHER_MIN_MTU + _ODP_ETHHDR_LEN)
#define DPDK_MTU_MAX (9000 + _ODP_ETHHDR_LEN)

/** DPDK runtime configuration options */
typedef struct {
	int num_rx_desc;
	int num_tx_desc_default;
	uint8_t multicast_en;
	uint8_t rx_drop_en;
	uint8_t set_flow_hash;
} dpdk_opt_t;

typedef struct ODP_ALIGNED_CACHE {
	/** array for storing extra RX packets */
	struct rte_mbuf *pkt[DPDK_MIN_RX_BURST];
	unsigned int idx;			  /**< head of cache */
	unsigned int count;			  /**< packets in cache */
} pkt_cache_t;

/** Packet IO using DPDK interface */
typedef struct ODP_ALIGNED_CACHE {
	odp_pool_t pool;		/**< pool to alloc packets from */
	struct rte_mempool *pkt_pool;	/**< DPDK packet pool */
	uint32_t data_room;		/**< maximum packet length */
	unsigned int min_rx_burst;	/**< minimum RX burst size */
	/** RSS configuration */
	struct rte_eth_rss_conf rss_conf;
	uint16_t mtu;			/**< maximum transmission unit */
	uint32_t mtu_max;		/**< maximum supported MTU value */
	odp_bool_t mtu_set;		/**< DPDK MTU has been modified */
	uint16_t port_id;		/**< DPDK port identifier */
	uint16_t num_tx_desc[PKTIO_MAX_QUEUES]; /**< Number of TX descriptors per queue */
	/** Use system call to get/set vdev promisc mode */
	uint8_t vdev_sysc_promisc;
	uint8_t lockless_rx;		/**< no locking for rx */
	uint8_t lockless_tx;		/**< no locking for tx */
	  /** RX queue locks */
	odp_ticketlock_t rx_lock[PKTIO_MAX_QUEUES] ODP_ALIGNED_CACHE;
	odp_ticketlock_t tx_lock[PKTIO_MAX_QUEUES];  /**< TX queue locks */
	/** cache for storing extra RX packets */
	pkt_cache_t rx_cache[PKTIO_MAX_QUEUES];
	dpdk_opt_t opt;
} pkt_dpdk_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_dpdk_t),
		  "PKTIO_PRIVATE_SIZE too small");

typedef struct {
	uint32_t dpdk_elt_size;
	uint8_t pool_in_use;
	struct rte_mempool *pkt_pool;
} mem_src_data_t;

ODP_STATIC_ASSERT(_ODP_POOL_MEM_SRC_DATA_SIZE >= sizeof(mem_src_data_t),
		  "_ODP_POOL_MEM_SRC_DATA_SIZE too small");

static inline struct rte_mbuf *mbuf_from_pkt_hdr(odp_packet_hdr_t *pkt_hdr)
{
	return ((struct rte_mbuf *)pkt_hdr) - 1;
}

static inline odp_packet_hdr_t *pkt_hdr_from_mbuf(struct rte_mbuf *mbuf)
{
	return (odp_packet_hdr_t *)(mbuf + 1);
}

static inline pkt_dpdk_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_dpdk_t *)(uintptr_t)(pktio_entry->pkt_priv);
}

static inline mem_src_data_t *mem_src_priv(uint8_t *data)
{
	return (mem_src_data_t *)data;
}

static int disable_pktio; /** !0 this pktio disabled, 0 enabled */

static int dpdk_pktio_init(void);

static int lookup_opt(const char *opt_name, const char *drv_name, int *val)
{
	const char *base = "pktio_dpdk";
	int ret;

	ret = _odp_libconfig_lookup_ext_int(base, drv_name, opt_name, val);
	if (ret == 0)
		ODP_ERR("Unable to find DPDK configuration option: %s\n",
			opt_name);

	return ret;
}

static int init_options(pktio_entry_t *pktio_entry,
			const struct rte_eth_dev_info *dev_info)
{
	dpdk_opt_t *opt = &pkt_priv(pktio_entry)->opt;
	int val;

	if (!lookup_opt("num_rx_desc", dev_info->driver_name,
			&opt->num_rx_desc))
		return -1;
	if (opt->num_rx_desc < dev_info->rx_desc_lim.nb_min ||
	    opt->num_rx_desc > dev_info->rx_desc_lim.nb_max ||
	    opt->num_rx_desc % dev_info->rx_desc_lim.nb_align) {
		ODP_ERR("Invalid number of RX descriptors\n");
		return -1;
	}

	if (!lookup_opt("num_tx_desc", dev_info->driver_name,
			&opt->num_tx_desc_default))
		return -1;

	if (!lookup_opt("rx_drop_en", dev_info->driver_name, &val))
		return -1;
	opt->rx_drop_en = !!val;

	if (!lookup_opt("set_flow_hash", NULL, &val))
		return -1;
	opt->set_flow_hash = !!val;

	if (!lookup_opt("multicast_en", NULL, &val))
		return -1;
	opt->multicast_en = !!val;

	ODP_DBG("DPDK interface (%s): %" PRIu16 "\n", dev_info->driver_name,
		pkt_priv(pktio_entry)->port_id);
	ODP_DBG("  multicast_en: %d\n", opt->multicast_en);
	ODP_DBG("  num_rx_desc: %d\n", opt->num_rx_desc);
	ODP_DBG("  num_tx_desc: %d\n", opt->num_tx_desc_default);
	ODP_DBG("  rx_drop_en: %d\n", opt->rx_drop_en);

	return 0;
}

/**
 * Calculate valid cache size for DPDK packet pool
 */
static unsigned cache_size(uint32_t num)
{
	unsigned size = 0;
	unsigned i;

	if (!RTE_MEMPOOL_CACHE_MAX_SIZE)
		return 0;

	i = ceil((double)num / RTE_MEMPOOL_CACHE_MAX_SIZE);
	i = RTE_MAX(i, 2UL);
	for (; i <= (num / 2); ++i)
		if ((num % i) == 0) {
			size = num / i;
			break;
		}
	if (odp_unlikely(size > RTE_MEMPOOL_CACHE_MAX_SIZE ||
			 (uint32_t)size * 1.5 > num)) {
		ODP_ERR("Cache size calc failure: %d\n", size);
		size = 0;
	}

	return size;
}

static inline uint16_t mbuf_data_off(struct rte_mbuf *mbuf,
				     odp_packet_hdr_t *pkt_hdr)
{
	return (uintptr_t)pkt_hdr->seg_data - (uintptr_t)mbuf->buf_addr;
}

/**
 * Update mbuf
 *
 * Called always before rte_mbuf is passed to DPDK.
 */
static inline void mbuf_update(struct rte_mbuf *mbuf, odp_packet_hdr_t *pkt_hdr,
			       uint16_t pkt_len)
{
	mbuf->data_len = pkt_len;
	mbuf->pkt_len = pkt_len;
	mbuf->refcnt = 1;
	mbuf->ol_flags = 0;

	if (odp_unlikely(((uint8_t *)mbuf->buf_addr +  mbuf->data_off) != pkt_hdr->seg_data))
		mbuf->data_off = mbuf_data_off(mbuf, pkt_hdr);
}

/**
 * Initialize packet mbuf. Modified version of standard rte_pktmbuf_init()
 * function.
 */
static void pktmbuf_init(struct rte_mempool *mp, void *opaque_arg ODP_UNUSED,
			 void *_m, unsigned i ODP_UNUSED)
{
	struct rte_mbuf *m = _m;
	uint32_t mbuf_size, buf_len, priv_size;
	odp_packet_hdr_t *pkt_hdr;
	void *buf_addr;

	pkt_hdr = pkt_hdr_from_mbuf(m);
	buf_addr = pkt_hdr->event_hdr.base_data - RTE_PKTMBUF_HEADROOM;

	priv_size = rte_pktmbuf_priv_size(mp);
	mbuf_size = sizeof(struct rte_mbuf);
	buf_len = rte_pktmbuf_data_room_size(mp);

	/* odp_packet_hdr_t stored in private data so don't zero */
	memset(m, 0, mbuf_size);
	m->priv_size = priv_size;
	m->buf_addr = buf_addr;

	m->buf_iova = rte_mem_virt2iova(buf_addr);
	if (odp_unlikely(m->buf_iova == 0))
		ODP_ABORT("Bad IO virtual address\n");

	m->buf_len = (uint16_t)buf_len;
	m->data_off = RTE_PKTMBUF_HEADROOM;

	/* Init some constant fields */
	m->pool = mp;
	m->nb_segs = 1;
	m->port = MBUF_INVALID_PORT;
	rte_mbuf_refcnt_set(m, 1);
	m->next = NULL;
}

/**
 *  Create custom DPDK packet pool
 */
static struct rte_mempool *mbuf_pool_create(const char *name,
					    pool_t *pool_entry,
					    uint32_t dpdk_elt_size)
{
	odp_shm_info_t shm_info;
	struct rte_mempool *mp = NULL;
	struct rte_pktmbuf_pool_private mbp_priv;
	struct rte_mempool_objsz sz;
	unsigned int elt_size = dpdk_elt_size;
	unsigned int num = pool_entry->num, populated = 0;
	uint32_t total_size;
	uint64_t page_size, offset = 0, remainder = 0;
	uint8_t *addr;
	int ret;

	if (!(pool_entry->mem_from_huge_pages)) {
		ODP_ERR("DPDK requires memory is allocated from huge pages\n");
		goto fail;
	}

	if (pool_entry->seg_len < RTE_MBUF_DEFAULT_BUF_SIZE) {
		ODP_ERR("Some NICs need at least %dB buffers to not segment "
			"standard ethernet frames. Increase pool seg_len.\n",
			RTE_MBUF_DEFAULT_BUF_SIZE);
		goto fail;
	}

	if (odp_shm_info(pool_entry->shm, &shm_info)) {
		ODP_ERR("Failed to query SHM info.\n");
		goto fail;
	}

	page_size = shm_info.page_size;
	total_size = rte_mempool_calc_obj_size(elt_size, MEMPOOL_FLAGS, &sz);
	if (total_size != pool_entry->block_size) {
		ODP_ERR("DPDK pool block size not matching to ODP pool: "
			"%" PRIu32 "/%" PRIu32 "\n", total_size,
			pool_entry->block_size);
		goto fail;
	}

	mp = rte_mempool_create_empty(name, num, elt_size, cache_size(num),
				      sizeof(struct rte_pktmbuf_pool_private),
				      rte_socket_id(), MEMPOOL_FLAGS);
	if (mp == NULL) {
		ODP_ERR("Failed to create empty DPDK packet pool\n");
		goto fail;
	}

	mp->pool_data = _odp_pool_handle(pool_entry);

	if (rte_mempool_set_ops_byname(mp, "odp_pool", pool_entry)) {
		ODP_ERR("Failed setting mempool operations\n");
		goto fail;
	}

	mbp_priv.mbuf_data_room_size = pool_entry->headroom +
			pool_entry->seg_len + pool_entry->tailroom;
	mbp_priv.mbuf_priv_size = RTE_ALIGN(sizeof(odp_packet_hdr_t),
					    RTE_MBUF_PRIV_ALIGN);
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	/* DPDK expects buffers that would be crossing a hugepage boundary to be aligned to the
	 * boundary. This isn't the case with ODP pools as boundary-crossing buffers are skipped
	 * and unused but still part of the pool. Thus, populate the mempool with several virtually
	 * and physically contiguous chunks as dictated by the skipped buffers. */
	for (uint64_t i = 0; i < pool_entry->shm_size; i += page_size) {
		remainder = (page_size - offset) % total_size;
		addr = pool_entry->base_addr + i + offset;
		ret = rte_mempool_populate_iova(mp, (char *)addr, rte_mem_virt2iova(addr),
						page_size - remainder - offset,
						NULL, NULL);

		if (ret <= 0) {
			ODP_ERR("Failed to populate mempool: %d\n", ret);
			goto fail;
		}

		populated += ret;
		offset = remainder ? total_size - remainder : 0;
	}

	if (populated != num) {
		ODP_ERR("Failed to populate mempool with all requested blocks, populated: %u, "
			"requested: %u\n", populated, num);
		goto fail;
	}

	rte_mempool_obj_iter(mp, pktmbuf_init, NULL);

	return mp;

fail:
	if (mp)
		rte_mempool_free(mp);
	return NULL;
}

/* DPDK external memory pool operations */

static int pool_enqueue(struct rte_mempool *mp,
			void * const *obj_table, unsigned num)
{
	odp_packet_t pkt_tbl[num];
	pool_t *pool_entry = (pool_t *)mp->pool_config;
	mem_src_data_t *mem_src_data = mem_src_priv(pool_entry->mem_src_data);
	unsigned i;

	if (odp_unlikely(num == 0 || !mem_src_data->pool_in_use))
		return 0;

	for (i = 0; i < num; i++) {
		struct rte_mbuf *mbuf = (struct rte_mbuf *)obj_table[i];
		odp_packet_hdr_t *pkt_hdr = pkt_hdr_from_mbuf(mbuf);

		pkt_tbl[i] = packet_handle(pkt_hdr);
	}

	odp_packet_free_multi(pkt_tbl, num);

	return 0;
}

static int pool_dequeue_bulk(struct rte_mempool *mp, void **obj_table,
			     unsigned num)
{
	odp_pool_t pool = (odp_pool_t)mp->pool_data;
	pool_t *pool_entry = (pool_t *)mp->pool_config;
	odp_packet_t packet_tbl[num];
	int pkts;
	int i;

	pkts = _odp_packet_alloc_multi(pool, pool_entry->seg_len, packet_tbl,
				       num);

	if (odp_unlikely(pkts != (int)num)) {
		if (pkts > 0)
			odp_packet_free_multi(packet_tbl, pkts);
		return -ENOENT;
	}

	for (i = 0; i < pkts; i++) {
		odp_packet_hdr_t *pkt_hdr = packet_hdr(packet_tbl[i]);

		obj_table[i] = mbuf_from_pkt_hdr(pkt_hdr);
	}

	return 0;
}

static int pool_alloc(struct rte_mempool *mp ODP_UNUSED)
{
	return 0;
}

static unsigned pool_get_count(const struct rte_mempool *mp)
{
	odp_pool_t pool = (odp_pool_t)mp->pool_data;
	odp_pool_info_t info;

	if (odp_pool_info(pool, &info)) {
		ODP_ERR("Failed to read pool info\n");
		return 0;
	}
	return info.params.pkt.num;
}

static void pool_free(struct rte_mempool *mp)
{
	unsigned lcore_id;

	RTE_LCORE_FOREACH(lcore_id) {
		struct rte_mempool_cache *cache;

		cache = rte_mempool_default_cache(mp, lcore_id);
		if (cache != NULL)
			rte_mempool_cache_flush(cache, mp);
	}
}

static void pool_destroy(uint8_t *data)
{
	mem_src_data_t *mem_src_data = mem_src_priv(data);

	if (mem_src_data->pkt_pool != NULL) {
		mem_src_data->pool_in_use = 0;
		rte_mempool_free(mem_src_data->pkt_pool);
	}

	mem_src_data->pkt_pool = NULL;
}

static int pool_create(uint8_t *data, pool_t *pool)
{
	struct rte_mempool *pkt_pool;
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	mem_src_data_t *mem_src_data = mem_src_priv(data);

	mem_src_data->pkt_pool = NULL;

	if (!_ODP_DPDK_ZERO_COPY)
		return 0;

	mem_src_data->pool_in_use = 0;
	snprintf(pool_name, sizeof(pool_name),
		 "dpdk_pktpool_%" PRIu32 "_%" PRIu32 "", odp_global_ro.main_pid,
		 pool->pool_idx);
	pkt_pool = mbuf_pool_create(pool_name, pool, mem_src_data->dpdk_elt_size);

	if (pkt_pool == NULL) {
		ODP_ERR("Creating external DPDK pool failed\n");
		return -1;
	}

	mem_src_data->pkt_pool = pkt_pool;
	mem_src_data->pool_in_use = 1;

	return 0;
}

static void pool_obj_size(uint8_t *data, uint32_t *block_size, uint32_t *block_offset,
			  uint32_t *flags)
{
	struct rte_mempool_objsz sz;
	uint32_t size;
	uint32_t total_size;
	mem_src_data_t *mem_src_data = mem_src_priv(data);

	if (!_ODP_DPDK_ZERO_COPY)
		return;

	if (odp_global_rw->dpdk_initialized == 0) {
		if (dpdk_pktio_init()) {
			ODP_ERR("Initializing DPDK failed\n");
			*block_size = 0;
			return;
		}
		odp_global_rw->dpdk_initialized = 1;
	}

	*flags |= ODP_SHM_HP;
	size = *block_size + sizeof(struct rte_mbuf);
	total_size = rte_mempool_calc_obj_size(size, MEMPOOL_FLAGS, &sz);
	mem_src_data->dpdk_elt_size = sz.elt_size;
	*block_size = total_size;
	*block_offset = sz.header_size + sizeof(struct rte_mbuf);
}

static struct rte_mempool_ops odp_pool_ops = {
	.name = "odp_pool",
	.alloc = pool_alloc,
	.free = pool_free,
	.enqueue = pool_enqueue,
	.dequeue = pool_dequeue_bulk,
	.get_count = pool_get_count
};

RTE_MEMPOOL_REGISTER_OPS(odp_pool_ops)

static inline int mbuf_to_pkt(pktio_entry_t *pktio_entry,
			      odp_packet_t pkt_table[],
			      struct rte_mbuf *mbuf_table[],
			      uint16_t mbuf_num, odp_time_t *ts)
{
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;
	uint16_t pkt_len;
	struct rte_mbuf *mbuf;
	void *data;
	int i, j, num;
	uint32_t max_len;
	int nb_pkts = 0;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	odp_pool_t pool = pkt_dpdk->pool;
	odp_pktin_config_opt_t pktin_cfg = pktio_entry->config.pktin;
	odp_pktio_t input = pktio_entry->handle;
	uint16_t frame_offset = pktio_entry->pktin_frame_offset;
	const odp_proto_layer_t layer = pktio_entry->parse_layer;

	/* Allocate maximum sized packets */
	max_len = pkt_dpdk->data_room;

	num = _odp_packet_alloc_multi(pool, max_len + frame_offset,
				      pkt_table, mbuf_num);
	if (num != mbuf_num) {
		ODP_DBG("_odp_packet_alloc_multi() unable to allocate all packets: "
			"%d/%" PRIu16 " allocated\n", num, mbuf_num);
		for (i = num; i < mbuf_num; i++)
			rte_pktmbuf_free(mbuf_table[i]);
	}

	for (i = 0; i < num; i++) {
		mbuf = mbuf_table[i];
		if (odp_unlikely(mbuf->nb_segs != 1)) {
			ODP_ERR("Segmented buffers not supported\n");
			goto fail;
		}

		data = rte_pktmbuf_mtod(mbuf, char *);
		odp_prefetch(data);

		pkt_len = rte_pktmbuf_pkt_len(mbuf);
		pkt     = pkt_table[i];
		pkt_hdr = packet_hdr(pkt);

		if (layer) {
			int ret;

			packet_parse_reset(pkt_hdr, 1);
			ret = _odp_dpdk_packet_parse_common(pkt_hdr, data, pkt_len, pkt_len,
							    mbuf, layer, pktin_cfg);
			if (ret)
				odp_atomic_inc_u64(&pktio_entry->stats_extra.in_errors);

			if (ret < 0) {
				odp_packet_free(pkt);
				rte_pktmbuf_free(mbuf);
				continue;
			}

			if (pktio_cls_enabled(pktio_entry)) {
				odp_pool_t new_pool;

				ret = _odp_cls_classify_packet(pktio_entry, (const uint8_t *)data,
							       &new_pool, pkt_hdr);
				if (ret < 0)
					odp_atomic_inc_u64(&pktio_entry->stats_extra.in_discards);

				if (ret) {
					odp_packet_free(pkt);
					rte_pktmbuf_free(mbuf);
					continue;
				}

				if (odp_unlikely(_odp_pktio_packet_to_pool(
					    &pkt, &pkt_hdr, new_pool))) {
					odp_packet_free(pkt);
					rte_pktmbuf_free(mbuf);
					odp_atomic_inc_u64(&pktio_entry->stats_extra.in_discards);
					continue;
				}
			}
		}

		pull_tail(pkt_hdr, max_len - pkt_len);
		if (frame_offset)
			pull_head(pkt_hdr, frame_offset);

		if (odp_packet_copy_from_mem(pkt, 0, pkt_len, data) != 0)
			goto fail;

		pkt_hdr->input = input;

		if (mbuf->ol_flags & RTE_MBUF_F_RX_RSS_HASH)
			packet_set_flow_hash(pkt_hdr, mbuf->hash.rss);

		packet_set_ts(pkt_hdr, ts);

		pkt_table[nb_pkts++] = pkt;

		rte_pktmbuf_free(mbuf);
	}

	return nb_pkts;

fail:
	odp_packet_free_multi(&pkt_table[i], num - i);

	for (j = i; j < num; j++)
		rte_pktmbuf_free(mbuf_table[j]);

	return (i > 0 ? i : -1);
}

static inline int check_proto(void *l3_hdr, odp_bool_t *l3_proto_v4,
			      uint8_t *l4_proto)
{
	uint8_t l3_proto_ver = _ODP_IPV4HDR_VER(*(uint8_t *)l3_hdr);

	if (l3_proto_ver == _ODP_IPV4) {
		struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)l3_hdr;

		*l3_proto_v4 = 1;
		if (!rte_ipv4_frag_pkt_is_fragmented(ip))
			*l4_proto = ip->next_proto_id;
		else
			*l4_proto = 0;

		return 0;
	} else if (l3_proto_ver == _ODP_IPV6) {
		struct rte_ipv6_hdr *ipv6 = (struct rte_ipv6_hdr *)l3_hdr;

		*l3_proto_v4 = 0;
		*l4_proto = ipv6->proto;
		return 0;
	}

	return -1;
}

static inline uint16_t phdr_csum(odp_bool_t ipv4, void *l3_hdr,
				 uint64_t ol_flags)
{
	if (ipv4)
		return rte_ipv4_phdr_cksum(l3_hdr, ol_flags);
	else /*ipv6*/
		return rte_ipv6_phdr_cksum(l3_hdr, ol_flags);
}

#define OL_TX_CHKSUM_PKT(_cfg, _capa, _proto, _ovr_set, _ovr) \
	(_capa && _proto && (_ovr_set ? _ovr : _cfg))

static inline void pkt_set_ol_tx(odp_pktout_config_opt_t *pktout_cfg,
				 odp_pktout_config_opt_t *pktout_capa,
				 odp_packet_hdr_t *pkt_hdr,
				 struct rte_mbuf *mbuf,
				 char *mbuf_data)
{
	void *l3_hdr, *l4_hdr;
	uint8_t l4_proto;
	odp_bool_t l3_proto_v4;
	odp_bool_t ipv4_chksum_pkt, udp_chksum_pkt, tcp_chksum_pkt;
	packet_parser_t *pkt_p = &pkt_hdr->p;

	if (pkt_p->l3_offset == ODP_PACKET_OFFSET_INVALID)
		return;

	l3_hdr = (void *)(mbuf_data + pkt_p->l3_offset);

	if (check_proto(l3_hdr, &l3_proto_v4, &l4_proto))
		return;

	ipv4_chksum_pkt = OL_TX_CHKSUM_PKT(pktout_cfg->bit.ipv4_chksum,
					   pktout_capa->bit.ipv4_chksum,
					   l3_proto_v4,
					   pkt_p->flags.l3_chksum_set,
					   pkt_p->flags.l3_chksum);
	udp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.udp_chksum,
					   pktout_capa->bit.udp_chksum,
					   (l4_proto == _ODP_IPPROTO_UDP),
					   pkt_p->flags.l4_chksum_set,
					   pkt_p->flags.l4_chksum);
	tcp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.tcp_chksum,
					   pktout_capa->bit.tcp_chksum,
					   (l4_proto == _ODP_IPPROTO_TCP),
					   pkt_p->flags.l4_chksum_set,
					   pkt_p->flags.l4_chksum);

	if (!ipv4_chksum_pkt && !udp_chksum_pkt && !tcp_chksum_pkt)
		return;

	mbuf->l2_len = pkt_p->l3_offset - pkt_p->l2_offset;

	if (l3_proto_v4)
		mbuf->ol_flags = RTE_MBUF_F_TX_IPV4;
	else
		mbuf->ol_flags = RTE_MBUF_F_TX_IPV6;

	if (ipv4_chksum_pkt) {
		mbuf->ol_flags |=  RTE_MBUF_F_TX_IP_CKSUM;

		((struct rte_ipv4_hdr *)l3_hdr)->hdr_checksum = 0;
		mbuf->l3_len = _ODP_IPV4HDR_IHL(*(uint8_t *)l3_hdr) * 4;
	}

	if (pkt_p->l4_offset == ODP_PACKET_OFFSET_INVALID)
		return;

	mbuf->l3_len = pkt_p->l4_offset - pkt_p->l3_offset;

	l4_hdr = (void *)(mbuf_data + pkt_p->l4_offset);

	if (udp_chksum_pkt) {
		mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;

		((struct rte_udp_hdr *)l4_hdr)->dgram_cksum =
			phdr_csum(l3_proto_v4, l3_hdr, mbuf->ol_flags);
	} else if (tcp_chksum_pkt) {
		mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

		((struct rte_tcp_hdr *)l4_hdr)->cksum =
			phdr_csum(l3_proto_v4, l3_hdr, mbuf->ol_flags);
	}
}

static inline int pkt_to_mbuf(pktio_entry_t *pktio_entry,
			      struct rte_mbuf *mbuf_table[],
			      const odp_packet_t pkt_table[], uint16_t num,
			      int *tx_ts_idx)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	int i, j;
	char *data;
	uint16_t pkt_len;
	uint8_t chksum_enabled = pktio_entry->enabled.chksum_insert;
	uint8_t tx_ts_enabled = _odp_pktio_tx_ts_enabled(pktio_entry);
	odp_pktout_config_opt_t *pktout_cfg = &pktio_entry->config.pktout;

	if (odp_unlikely((rte_pktmbuf_alloc_bulk(pkt_dpdk->pkt_pool,
						 mbuf_table, num)))) {
		ODP_ERR("Failed to alloc mbuf\n");
		return 0;
	}
	for (i = 0; i < num; i++) {
		odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt_table[i]);

		pkt_len = packet_len(pkt_hdr);

		if (odp_unlikely(pkt_len > pkt_dpdk->mtu)) {
			if (i == 0)
				_odp_errno = EMSGSIZE;
			goto fail;
		}

		/* Packet always fits in mbuf */
		data = rte_pktmbuf_append(mbuf_table[i], pkt_len);

		odp_packet_copy_to_mem(pkt_table[i], 0, pkt_len, data);

		if (odp_unlikely(chksum_enabled)) {
			odp_pktout_config_opt_t *pktout_capa =
			&pktio_entry->capa.config.pktout;

			pkt_set_ol_tx(pktout_cfg, pktout_capa, pkt_hdr,
				      mbuf_table[i], data);
		}

		if (odp_unlikely(tx_ts_enabled)) {
			if (odp_unlikely(*tx_ts_idx == 0 && pkt_hdr->p.flags.ts_set))
				*tx_ts_idx = i + 1;
		}
	}
	return i;

fail:
	for (j = i; j < num; j++)
		rte_pktmbuf_free(mbuf_table[j]);

	return i;
}

static inline void prefetch_pkt(struct rte_mbuf *mbuf)
{
	odp_packet_hdr_t *pkt_hdr = pkt_hdr_from_mbuf(mbuf);
	void *data = rte_pktmbuf_mtod(mbuf, char *);

	odp_prefetch(pkt_hdr);
	odp_prefetch_store((uint8_t *)pkt_hdr + ODP_CACHE_LINE_SIZE);
	odp_prefetch(data);
}

static inline int mbuf_to_pkt_zero(pktio_entry_t *pktio_entry,
				   odp_packet_t pkt_table[],
				   struct rte_mbuf *mbuf_table[],
				   uint16_t mbuf_num, odp_time_t *ts)
{
	odp_packet_hdr_t *pkt_hdr;
	uint16_t pkt_len;
	uint8_t set_flow_hash;
	struct rte_mbuf *mbuf;
	void *data;
	int i, nb_pkts;
	odp_pktin_config_opt_t pktin_cfg;
	odp_pktio_t input;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	const odp_proto_layer_t layer = pktio_entry->parse_layer;

	prefetch_pkt(mbuf_table[0]);

	nb_pkts = 0;
	set_flow_hash = pkt_dpdk->opt.set_flow_hash;
	pktin_cfg = pktio_entry->config.pktin;
	input = pktio_entry->handle;

	if (odp_likely(mbuf_num > 1))
		prefetch_pkt(mbuf_table[1]);

	for (i = 0; i < mbuf_num; i++) {
		odp_packet_t pkt;

		if (odp_likely((i + 2) < mbuf_num))
			prefetch_pkt(mbuf_table[i + 2]);

		mbuf = mbuf_table[i];
		if (odp_unlikely(mbuf->nb_segs != 1)) {
			ODP_ERR("Segmented buffers not supported\n");
			rte_pktmbuf_free(mbuf);
			continue;
		}

		data = rte_pktmbuf_mtod(mbuf, char *);
		pkt_len = rte_pktmbuf_pkt_len(mbuf);
		pkt_hdr = pkt_hdr_from_mbuf(mbuf);
		pkt = packet_handle(pkt_hdr);
		packet_init(pkt_hdr, pkt_len);

		/* Init buffer segments. Currently, only single segment packets
		 * are supported. */
		pkt_hdr->seg_data = data;

		if (layer) {
			int ret;

			ret = _odp_dpdk_packet_parse_common(pkt_hdr, data, pkt_len, pkt_len,
							    mbuf, layer, pktin_cfg);
			if (ret)
				odp_atomic_inc_u64(&pktio_entry->stats_extra.in_errors);

			if (ret < 0) {
				rte_pktmbuf_free(mbuf);
				continue;
			}

			if (pktio_cls_enabled(pktio_entry)) {
				odp_pool_t new_pool;

				ret = _odp_cls_classify_packet(pktio_entry, (const uint8_t *)data,
							       &new_pool, pkt_hdr);
				if (ret < 0)
					odp_atomic_inc_u64(&pktio_entry->stats_extra.in_discards);

				if (ret) {
					rte_pktmbuf_free(mbuf);
					continue;
				}

				if (odp_unlikely(_odp_pktio_packet_to_pool(
					    &pkt, &pkt_hdr, new_pool))) {
					rte_pktmbuf_free(mbuf);
					odp_atomic_inc_u64(&pktio_entry->stats_extra.in_discards);
					continue;
				}
			}
		}

		pkt_hdr->input = input;

		if (set_flow_hash && (mbuf->ol_flags & RTE_MBUF_F_RX_RSS_HASH))
			packet_set_flow_hash(pkt_hdr, mbuf->hash.rss);

		packet_set_ts(pkt_hdr, ts);

		pkt_table[nb_pkts++] = pkt;
	}

	return nb_pkts;
}

static inline int pkt_to_mbuf_zero(pktio_entry_t *pktio_entry,
				   struct rte_mbuf *mbuf_table[],
				   const odp_packet_t pkt_table[], uint16_t num,
				   uint16_t *copy_count, uint16_t cpy_idx[], int *tx_ts_idx)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	odp_pktout_config_opt_t *pktout_cfg = &pktio_entry->config.pktout;
	odp_pktout_config_opt_t *pktout_capa =
		&pktio_entry->capa.config.pktout;
	uint16_t mtu = pkt_dpdk->mtu;
	uint8_t chksum_enabled = pktio_entry->enabled.chksum_insert;
	uint8_t tx_ts_enabled = _odp_pktio_tx_ts_enabled(pktio_entry);
	int i;
	*copy_count = 0;

	for (i = 0; i < num; i++) {
		odp_packet_t pkt = pkt_table[i];
		odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
		struct rte_mbuf *mbuf = mbuf_from_pkt_hdr(pkt_hdr);
		uint16_t pkt_len = odp_packet_len(pkt);

		if (odp_unlikely(pkt_len > mtu))
			goto fail;

		if (odp_likely(pkt_hdr->seg_count == 1)) {
			mbuf_update(mbuf, pkt_hdr, pkt_len);

			if (odp_unlikely(chksum_enabled))
				pkt_set_ol_tx(pktout_cfg, pktout_capa, pkt_hdr,
					      mbuf, odp_packet_data(pkt));
		} else {
			int dummy_idx = 0;

			/* Fall back to packet copy */
			if (odp_unlikely(pkt_to_mbuf(pktio_entry, &mbuf,
						     &pkt, 1, &dummy_idx) != 1))
				goto fail;
			cpy_idx[(*copy_count)++] = i;
		}
		mbuf_table[i] = mbuf;

		if (odp_unlikely(tx_ts_enabled)) {
			if (odp_unlikely(*tx_ts_idx == 0 && pkt_hdr->p.flags.ts_set))
				*tx_ts_idx = i + 1;
		}
	}
	return i;

fail:
	if (i == 0)
		_odp_errno = EMSGSIZE;
	return i;
}

/* Test if s has only digits or not. Dpdk pktio uses only digits.*/
static int dpdk_netdev_is_valid(const char *s)
{
	while (*s) {
		if (!isdigit(*s))
			return 0;
		s++;
	}
	return 1;
}

static uint32_t dpdk_vdev_mtu_get(uint16_t port_id)
{
	struct rte_eth_dev_info dev_info;
	struct ifreq ifr;
	int sockfd;
	uint32_t mtu;

	memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		ODP_ERR("Failed to create control socket\n");
		return 0;
	}

	mtu = _odp_mtu_get_fd(sockfd, ifr.ifr_name);
	close(sockfd);
	return mtu;
}

static uint32_t dpdk_mtu_get(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint32_t mtu = 0;

	if (rte_eth_dev_get_mtu(pkt_dpdk->port_id, (uint16_t *)&mtu))
		return 0;

	/* Some DPDK PMD virtual devices do not support getting MTU size.
	 * Try to use system call if DPDK cannot get MTU value.
	 */
	if (mtu == 0)
		mtu = dpdk_vdev_mtu_get(pkt_dpdk->port_id);

	/* Mbuf chaining not yet supported */
	if (pkt_dpdk->data_room && pkt_dpdk->data_room < mtu)
		return pkt_dpdk->data_room;

	return mtu;
}

static uint32_t dpdk_maxlen(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);

	return pkt_dpdk->mtu;
}

static int dpdk_maxlen_set(pktio_entry_t *pktio_entry, uint32_t maxlen_input,
			   uint32_t maxlen_output ODP_UNUSED)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t mtu;
	int ret;

	/* DPDK MTU value does not include Ethernet header */
	mtu = maxlen_input - _ODP_ETHHDR_LEN;

	ret = rte_eth_dev_set_mtu(pkt_dpdk->port_id, mtu);
	if (odp_unlikely(ret))
		ODP_ERR("rte_eth_dev_set_mtu() failed: %d\n", ret);

	pkt_dpdk->mtu = maxlen_input;
	pkt_dpdk->mtu_set = true;

	return ret;
}

static int dpdk_vdev_promisc_mode_get(uint16_t port_id)
{
	struct rte_eth_dev_info dev_info;
	struct ifreq ifr;
	int sockfd;
	int mode;

	memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		ODP_ERR("Failed to create control socket\n");
		return -1;
	}

	mode = _odp_promisc_mode_get_fd(sockfd, ifr.ifr_name);
	close(sockfd);
	return mode;
}

static int dpdk_vdev_promisc_mode_set(uint16_t port_id, int enable)
{
	struct rte_eth_dev_info dev_info;
	struct ifreq ifr;
	int sockfd;
	int mode;

	memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));

	rte_eth_dev_info_get(port_id, &dev_info);
	if_indextoname(dev_info.if_index, ifr.ifr_name);

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		ODP_ERR("Failed to create control socket\n");
		return -1;
	}

	mode = _odp_promisc_mode_set_fd(sockfd, ifr.ifr_name, enable);
	close(sockfd);
	return mode;
}

static void hash_proto_to_rss_conf(struct rte_eth_rss_conf *rss_conf,
				   const odp_pktin_hash_proto_t *hash_proto)
{
	if (hash_proto->proto.ipv4_udp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV4_UDP;
	if (hash_proto->proto.ipv4_tcp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV4_TCP;
	if (hash_proto->proto.ipv4)
		rss_conf->rss_hf |= ETH_RSS_IPV4 | ETH_RSS_FRAG_IPV4 |
				    ETH_RSS_NONFRAG_IPV4_OTHER;
	if (hash_proto->proto.ipv6_udp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV6_UDP |
				    ETH_RSS_IPV6_UDP_EX;
	if (hash_proto->proto.ipv6_tcp)
		rss_conf->rss_hf |= ETH_RSS_NONFRAG_IPV6_TCP |
				    ETH_RSS_IPV6_TCP_EX;
	if (hash_proto->proto.ipv6)
		rss_conf->rss_hf |= ETH_RSS_IPV6 | ETH_RSS_FRAG_IPV6 |
				    ETH_RSS_NONFRAG_IPV6_OTHER |
				    ETH_RSS_IPV6_EX;
	rss_conf->rss_key = NULL;
}

static int dpdk_setup_eth_dev(pktio_entry_t *pktio_entry)
{
	int ret;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	struct rte_eth_conf eth_conf;
	uint64_t rx_offloads = 0;
	uint64_t tx_offloads = 0;

	memset(&eth_conf, 0, sizeof(eth_conf));

	eth_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	eth_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
	eth_conf.rx_adv_conf.rss_conf = pkt_dpdk->rss_conf;

	/* Setup RX checksum offloads */
	if (pktio_entry->config.pktin.bit.ipv4_chksum)
		rx_offloads |= DEV_RX_OFFLOAD_IPV4_CKSUM;

	if (pktio_entry->config.pktin.bit.udp_chksum)
		rx_offloads |= DEV_RX_OFFLOAD_UDP_CKSUM;

	if (pktio_entry->config.pktin.bit.tcp_chksum)
		rx_offloads |= DEV_RX_OFFLOAD_TCP_CKSUM;

	eth_conf.rxmode.offloads = rx_offloads;

	/* Setup TX checksum offloads */
	if (pktio_entry->config.pktout.bit.ipv4_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;

	if (pktio_entry->config.pktout.bit.udp_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;

	if (pktio_entry->config.pktout.bit.tcp_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;

	if (pktio_entry->config.pktout.bit.sctp_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_SCTP_CKSUM;

	eth_conf.txmode.offloads = tx_offloads;

	if (tx_offloads)
		pktio_entry->enabled.chksum_insert = 1;

	ret = rte_eth_dev_configure(pkt_dpdk->port_id,
				    pktio_entry->num_in_queue,
				    pktio_entry->num_out_queue, &eth_conf);
	if (ret < 0) {
		ODP_ERR("Failed to setup device: err=%d, port=%" PRIu8 "\n",
			ret, pkt_dpdk->port_id);
		return -1;
	}
	return 0;
}

static int dpdk_close(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	unsigned idx;
	unsigned i, j;

	/* Free cache packets */
	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		idx = pkt_dpdk->rx_cache[i].idx;

		for (j = 0; j < pkt_dpdk->rx_cache[i].count; j++)
			rte_pktmbuf_free(pkt_dpdk->rx_cache[i].pkt[idx++]);
	}

	return 0;
}

static int dpdk_pktio_init(void)
{
	int dpdk_argc;
	int i;
	odp_cpumask_t mask;
	char mask_str[ODP_CPUMASK_STR_SIZE];
	const char *cmdline;
	int32_t masklen;
	int mem_str_len;
	int cmd_len;
	int numa_nodes;
	cpu_set_t original_cpuset;

	/**
	 * DPDK init changes the affinity of the calling thread, so after it
	 * returns the original affinity is restored. Only the first active
	 * core is passed to rte_eal_init(), as the rest would be used for
	 * DPDK's special lcore threads, which are only available through
	 * rte_eal_[mp_]remote_launch(), but not through ODP API's.
	 * Nevertheless, odp_local_init() makes sure for the rest of
	 * the DPDK libraries ODP threads look like proper DPDK threads.
	 */
	CPU_ZERO(&original_cpuset);
	i = pthread_getaffinity_np(pthread_self(),
				   sizeof(original_cpuset), &original_cpuset);
	if (i != 0) {
		ODP_ERR("Failed to read thread affinity: %d\n", i);
		return -1;
	}

	odp_cpumask_zero(&mask);
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &original_cpuset)) {
			odp_cpumask_set(&mask, i);
			break;
		}
	}
	masklen = odp_cpumask_to_str(&mask, mask_str, ODP_CPUMASK_STR_SIZE);

	if (masklen < 0) {
		ODP_ERR("CPU mask error: %" PRId32 "\n", masklen);
		return -1;
	}

	mem_str_len = snprintf(NULL, 0, "%d,", DPDK_MEMORY_MB);

	/* numa_num_configured_nodes() may return 0 on some platforms */
	numa_nodes = numa_num_configured_nodes();
	if (numa_nodes <= 0)
		numa_nodes = 1;

	char mem_str[mem_str_len * numa_nodes];

	for (i = 0; i < numa_nodes; i++)
		sprintf(&mem_str[i * mem_str_len], "%d,", DPDK_MEMORY_MB);
	mem_str[mem_str_len * numa_nodes - 1] = '\0';

	cmdline = getenv("ODP_PKTIO_DPDK_PARAMS");
	if (cmdline == NULL)
		cmdline = "";

	/* masklen includes the terminating null as well */
	cmd_len = snprintf(NULL, 0, "odpdpdk --file-prefix %" PRIu32 "_ "
			   "--proc-type auto -c %s --socket-mem %s %s ",
			   odp_global_ro.main_pid, mask_str, mem_str, cmdline);

	char full_cmd[cmd_len];

	/* first argument is facility log, simply bind it to odpdpdk for now.*/
	cmd_len = snprintf(full_cmd, cmd_len,
			   "odpdpdk --file-prefix %" PRIu32 "_ "
			   "--proc-type auto -c %s --socket-mem %s %s ",
			   odp_global_ro.main_pid, mask_str, mem_str, cmdline);

	for (i = 0, dpdk_argc = 1; i < cmd_len; ++i) {
		if (isspace(full_cmd[i]))
			++dpdk_argc;
	}

	char *dpdk_argv[dpdk_argc];

	dpdk_argc = rte_strsplit(full_cmd, strlen(full_cmd), dpdk_argv,
				 dpdk_argc, ' ');
	for (i = 0; i < dpdk_argc; ++i)
		ODP_DBG("arg[%d]: %s\n", i, dpdk_argv[i]);

	i = rte_eal_init(dpdk_argc, dpdk_argv);

	/* Force getopt() to reset its internal state */
	optind = 0;

	if (i < 0) {
		ODP_ERR("Cannot init the Intel DPDK EAL!\n");
		return -1;
	} else if (i + 1 != dpdk_argc) {
		ODP_DBG("Some DPDK args were not processed!\n");
		ODP_DBG("Passed: %d Consumed %d\n", dpdk_argc, i + 1);
	}
	ODP_DBG("rte_eal_init OK\n");

	rte_log_set_global_level(RTE_LOG_WARNING);

	i = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t),
				   &original_cpuset);
	if (i)
		ODP_ERR("Failed to reset thread affinity: %d\n", i);

	ODP_PRINT("\nDPDK version: %s\n", rte_version());

	return 0;
}

/* Placeholder for DPDK global init */
static int dpdk_pktio_init_global(void)
{
	if (getenv("ODP_PKTIO_DISABLE_DPDK")) {
		ODP_PRINT("PKTIO: dpdk pktio skipped,"
			  " enabled export ODP_PKTIO_DISABLE_DPDK=1.\n");
		disable_pktio = 1;
	} else  {
		ODP_PRINT("PKTIO: initialized dpdk pktio,"
			  " use export ODP_PKTIO_DISABLE_DPDK=1 to disable.\n");
	}
	return 0;
}

static int dpdk_pktio_init_local(void)
{
	int cpu;

	cpu = sched_getcpu();
	if (cpu < 0) {
		ODP_ERR("getcpu failed\n");
		return -1;
	}

	RTE_PER_LCORE(_lcore_id) = cpu;

	return 0;
}

static void dpdk_mempool_free(struct rte_mempool *mp, void *arg ODP_UNUSED)
{
	rte_mempool_free(mp);
}

static int dpdk_pktio_term(void)
{
	uint16_t port_id;

	if (!odp_global_rw->dpdk_initialized)
		return 0;

	RTE_ETH_FOREACH_DEV(port_id) {
		rte_eth_dev_close(port_id);
	}

	if (!_ODP_DPDK_ZERO_COPY)
		rte_mempool_walk(dpdk_mempool_free, NULL);

	return 0;
}

static void prepare_rss_conf(pktio_entry_t *pktio_entry,
			     const odp_pktin_queue_param_t *p)
{
	struct rte_eth_dev_info dev_info;
	uint64_t rss_hf_capa;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t port_id = pkt_dpdk->port_id;

	memset(&pkt_dpdk->rss_conf, 0, sizeof(struct rte_eth_rss_conf));

	if (!p->hash_enable)
		return;

	rte_eth_dev_info_get(port_id, &dev_info);
	rss_hf_capa = dev_info.flow_type_rss_offloads;

	/* Print debug info about unsupported hash protocols */
	if (p->hash_proto.proto.ipv4 &&
	    ((rss_hf_capa & ETH_RSS_IPV4) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv4 not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv4_udp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV4_UDP) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv4_udp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv4_tcp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV4_TCP) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv4_tcp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv6 &&
	    ((rss_hf_capa & ETH_RSS_IPV6) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv6 not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv6_udp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV6_UDP) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv6_udp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	if (p->hash_proto.proto.ipv6_tcp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV6_TCP) == 0))
		ODP_PRINT("DPDK: hash_proto.ipv6_tcp not supported (rss_hf_capa 0x%" PRIx64 ")\n",
			  rss_hf_capa);

	hash_proto_to_rss_conf(&pkt_dpdk->rss_conf, &p->hash_proto);

	/* Filter out unsupported hash functions */
	pkt_dpdk->rss_conf.rss_hf &= rss_hf_capa;
}

static int dpdk_input_queues_config(pktio_entry_t *pktio_entry,
				    const odp_pktin_queue_param_t *p)
{
	odp_pktin_mode_t mode = pktio_entry->param.in_mode;
	uint8_t lockless;

	prepare_rss_conf(pktio_entry, p);

	/**
	 * Scheduler synchronizes input queue polls. Only single thread
	 * at a time polls a queue */
	if (mode == ODP_PKTIN_MODE_SCHED ||
	    p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		lockless = 1;
	else
		lockless = 0;

	pkt_priv(pktio_entry)->lockless_rx = lockless;

	return 0;
}

static int dpdk_output_queues_config(pktio_entry_t *pktio_entry,
				     const odp_pktout_queue_param_t *p)
{
	struct rte_eth_dev_info dev_info;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint8_t lockless;
	int ret;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		lockless = 1;
	else
		lockless = 0;

	pkt_dpdk->lockless_tx = lockless;

	ret  = rte_eth_dev_info_get(pkt_dpdk->port_id, &dev_info);
	if (ret) {
		ODP_ERR("DPDK: rte_eth_dev_info_get() failed: %d\n", ret);
		return -1;
	}

	/* Configure TX descriptors */
	for (uint32_t i = 0; i  < p->num_queues; i++) {
		uint16_t num_tx_desc = pkt_dpdk->opt.num_tx_desc_default;

		if (p->queue_size[i] != 0) {
			num_tx_desc = p->queue_size[i];
			/* Make sure correct alignment is used */
			if (dev_info.tx_desc_lim.nb_align)
				num_tx_desc = RTE_ALIGN_MUL_CEIL(num_tx_desc,
								 dev_info.tx_desc_lim.nb_align);
		}

		if (num_tx_desc < dev_info.tx_desc_lim.nb_min ||
		    num_tx_desc > dev_info.tx_desc_lim.nb_max ||
		    num_tx_desc % dev_info.tx_desc_lim.nb_align) {
			ODP_ERR("DPDK: invalid number of TX descriptors\n");
			return -1;
		}
		pkt_dpdk->num_tx_desc[i] = num_tx_desc;
	}
	return 0;
}

static int dpdk_init_capability(pktio_entry_t *pktio_entry,
				const struct rte_eth_dev_info *dev_info)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	odp_pktio_capability_t *capa = &pktio_entry->capa;
	struct rte_ether_addr mac_addr;
	int ptype_cnt;
	int ptype_l3_ipv4 = 0;
	int ptype_l4_tcp = 0;
	int ptype_l4_udp = 0;
	int ret;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues = RTE_MIN(dev_info->max_rx_queues,
					 PKTIO_MAX_QUEUES);

	/* ixgbe devices support only 16 rx queues in RSS mode */
	if (!strncmp(dev_info->driver_name, IXGBE_DRV_NAME,
		     strlen(IXGBE_DRV_NAME)))
		capa->max_input_queues = RTE_MIN((unsigned)16,
						 capa->max_input_queues);

	capa->max_output_queues = RTE_MIN(dev_info->max_tx_queues,
					  PKTIO_MAX_QUEUES);
	capa->min_output_queue_size = dev_info->tx_desc_lim.nb_min;
	capa->max_output_queue_size = dev_info->tx_desc_lim.nb_max;

	capa->set_op.op.promisc_mode = 1;

	/* Check if setting default MAC address is supporter */
	rte_eth_macaddr_get(pkt_dpdk->port_id, &mac_addr);
	ret = rte_eth_dev_default_mac_addr_set(pkt_dpdk->port_id, &mac_addr);
	if (ret == 0) {
		capa->set_op.op.mac_addr = 1;
	} else if (ret != -ENOTSUP && ret != -EPERM) {
		ODP_ERR("Failed to set interface default MAC: %d\n", ret);
		return -1;
	}

	/* Check if setting MTU is supported */
	ret = rte_eth_dev_set_mtu(pkt_dpdk->port_id, pkt_dpdk->mtu - _ODP_ETHHDR_LEN);
	/* From DPDK 21.11 onwards, calling rte_eth_dev_set_mtu() before device is configured with
	 * rte_eth_dev_configure() will result in failure. The least hacky (unfortunately still
	 * very hacky) way to continue checking the support is to take into account that the
	 * function will fail earlier with -ENOTSUP if MTU setting is not supported by device than
	 * if the device was not yet configured. */
	if (ret != -ENOTSUP) {
		capa->set_op.op.maxlen = 1;
		capa->maxlen.equal = true;
		capa->maxlen.min_input = DPDK_MTU_MIN;
		capa->maxlen.max_input = pkt_dpdk->mtu_max;
		capa->maxlen.min_output = DPDK_MTU_MIN;
		capa->maxlen.max_output = pkt_dpdk->mtu_max;
	}

	ptype_cnt = rte_eth_dev_get_supported_ptypes(pkt_dpdk->port_id,
						     ptype_mask, NULL, 0);
	if (ptype_cnt > 0) {
		uint32_t ptypes[ptype_cnt];
		int i;

		ptype_cnt = rte_eth_dev_get_supported_ptypes(pkt_dpdk->port_id,
							     ptype_mask, ptypes,
							     ptype_cnt);
		for (i = 0; i < ptype_cnt; i++)
			switch (ptypes[i]) {
			case RTE_PTYPE_L3_IPV4:
			/* Fall through */
			case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
			/* Fall through */
			case RTE_PTYPE_L3_IPV4_EXT:
				ptype_l3_ipv4 = 1;
				break;
			case RTE_PTYPE_L4_TCP:
				ptype_l4_tcp = 1;
				break;
			case RTE_PTYPE_L4_UDP:
				ptype_l4_udp = 1;
				break;
			}
	}

	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;

	capa->config.pktin.bit.ipv4_chksum = ptype_l3_ipv4 &&
		(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) ? 1 : 0;
	if (capa->config.pktin.bit.ipv4_chksum)
		capa->config.pktin.bit.drop_ipv4_err = 1;

	capa->config.pktin.bit.udp_chksum = ptype_l4_udp &&
		(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_UDP_CKSUM) ? 1 : 0;
	if (capa->config.pktin.bit.udp_chksum)
		capa->config.pktin.bit.drop_udp_err = 1;

	capa->config.pktin.bit.tcp_chksum = ptype_l4_tcp &&
		(dev_info->rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM) ? 1 : 0;
	if (capa->config.pktin.bit.tcp_chksum)
		capa->config.pktin.bit.drop_tcp_err = 1;

	capa->config.pktout.bit.ipv4_chksum =
		(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) ? 1 : 0;
	capa->config.pktout.bit.udp_chksum =
		(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM) ? 1 : 0;
	capa->config.pktout.bit.tcp_chksum =
		(dev_info->tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) ? 1 : 0;

	capa->config.pktout.bit.ipv4_chksum_ena =
		capa->config.pktout.bit.ipv4_chksum;
	capa->config.pktout.bit.udp_chksum_ena =
		capa->config.pktout.bit.udp_chksum;
	capa->config.pktout.bit.tcp_chksum_ena =
		capa->config.pktout.bit.tcp_chksum;
	capa->config.pktout.bit.ts_ena = 1;

	capa->stats.pktio.counter.in_octets = 1;
	capa->stats.pktio.counter.in_packets = 1;
	capa->stats.pktio.counter.in_discards = 1;
	capa->stats.pktio.counter.in_errors = 1;
	capa->stats.pktio.counter.out_octets = 1;
	capa->stats.pktio.counter.out_packets = 1;
	capa->stats.pktio.counter.out_errors = 1;

	capa->stats.pktin_queue.counter.octets = 1;
	capa->stats.pktin_queue.counter.packets = 1;
	capa->stats.pktin_queue.counter.errors = 1;

	capa->stats.pktout_queue.counter.octets = 1;
	capa->stats.pktout_queue.counter.packets = 1;

	return 0;
}

/* Some DPDK PMD virtual devices, like PCAP, do not support promisc
 * mode change. Use system call for them. */
static void promisc_mode_check(pkt_dpdk_t *pkt_dpdk)
{
	int ret;

	ret = rte_eth_promiscuous_enable(pkt_dpdk->port_id);

	if (!rte_eth_promiscuous_get(pkt_dpdk->port_id))
		pkt_dpdk->vdev_sysc_promisc = 1;

	ret += rte_eth_promiscuous_disable(pkt_dpdk->port_id);

	if (ret)
		pkt_dpdk->vdev_sysc_promisc = 1;
}

static int dpdk_open(odp_pktio_t id ODP_UNUSED,
		     pktio_entry_t *pktio_entry,
		     const char *netdev,
		     odp_pool_t pool)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	struct rte_eth_dev_info dev_info;
	struct rte_mempool *pkt_pool;
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	uint16_t data_room;
	uint32_t mtu;
	int i, ret;
	pool_t *pool_entry;
	uint16_t port_id;

	if (disable_pktio)
		return -1;

	if (pool == ODP_POOL_INVALID)
		return -1;
	pool_entry = _odp_pool_entry(pool);

	/* Init pktio entry */
	memset(pkt_dpdk, 0, sizeof(*pkt_dpdk));

	if (!rte_eth_dev_get_port_by_name(netdev, &port_id))
		pkt_dpdk->port_id = port_id;
	else if (dpdk_netdev_is_valid(netdev))
		pkt_dpdk->port_id = atoi(netdev);
	else {
		ODP_ERR("Invalid DPDK interface name: %s\n", netdev);
		return -1;
	}

	/* Initialize DPDK here instead of odp_init_global() to enable running
	 * 'make check' without root privileges */
	if (odp_global_rw->dpdk_initialized == 0) {
		dpdk_pktio_init();
		odp_global_rw->dpdk_initialized = 1;
	}

	pkt_dpdk->pool = pool;

	if (rte_eth_dev_count_avail() == 0) {
		ODP_ERR("No DPDK ports found\n");
		return -1;
	}

	memset(&dev_info, 0, sizeof(struct rte_eth_dev_info));
	ret = rte_eth_dev_info_get(pkt_dpdk->port_id, &dev_info);
	if (ret) {
		ODP_ERR("Failed to read device info: %d\n", ret);
		return -1;
	}

	/* Initialize runtime options */
	if (init_options(pktio_entry, &dev_info)) {
		ODP_ERR("Initializing runtime options failed\n");
		return -1;
	}

	mtu = dpdk_mtu_get(pktio_entry);
	if (mtu == 0) {
		ODP_ERR("Failed to read interface MTU\n");
		return -1;
	}
	pkt_dpdk->mtu = mtu + _ODP_ETHHDR_LEN;
	pkt_dpdk->mtu_max = RTE_MAX(pkt_dpdk->mtu, DPDK_MTU_MAX);
	pkt_dpdk->mtu_set = false;

	promisc_mode_check(pkt_dpdk);

	if (pkt_dpdk->opt.multicast_en)
		ret = rte_eth_allmulticast_enable(pkt_dpdk->port_id);
	else
		ret = rte_eth_allmulticast_disable(pkt_dpdk->port_id);

	/* Not supported by all PMDs, so ignore the return value */
	if (ret)
		ODP_DBG("Configuring multicast reception not supported by the PMD\n");

	/* Drivers requiring minimum burst size. Supports also *_vf versions
	 * of the drivers. */
	if (!strncmp(dev_info.driver_name, IXGBE_DRV_NAME,
		     strlen(IXGBE_DRV_NAME)) ||
	    !strncmp(dev_info.driver_name, I40E_DRV_NAME,
		     strlen(I40E_DRV_NAME)))
		pkt_dpdk->min_rx_burst = DPDK_MIN_RX_BURST;
	else
		pkt_dpdk->min_rx_burst = 0;

	if (_ODP_DPDK_ZERO_COPY) {
		mem_src_data_t *mem_src_data = mem_src_priv(pool_entry->mem_src_data);

		pkt_pool = mem_src_data->pkt_pool;
	} else {
		snprintf(pool_name, sizeof(pool_name), "pktpool_%s", netdev);
		/* Check if the pool exists already */
		pkt_pool = rte_mempool_lookup(pool_name);
		if (pkt_pool == NULL) {
			unsigned cache_size = DPDK_MEMPOOL_CACHE_SIZE;

			pkt_pool = rte_pktmbuf_pool_create(pool_name,
							   DPDK_NB_MBUF,
							   cache_size, 0,
							   DPDK_MBUF_BUF_SIZE,
							   rte_socket_id());
		}
	}
	if (pkt_pool == NULL) {
		ODP_ERR("Cannot init mbuf packet pool\n");
		return -1;
	}

	pkt_dpdk->pkt_pool = pkt_pool;

	data_room = rte_pktmbuf_data_room_size(pkt_dpdk->pkt_pool) -
			RTE_PKTMBUF_HEADROOM;
	pkt_dpdk->data_room = RTE_MIN(pool_entry->seg_len, data_room);

	/* Reserve room for packet input offset */
	pkt_dpdk->data_room -= pktio_entry->pktin_frame_offset;

	/* Mbuf chaining not yet supported */
	pkt_dpdk->mtu = RTE_MIN(pkt_dpdk->mtu, pkt_dpdk->data_room);
	pkt_dpdk->mtu_max = RTE_MIN(pkt_dpdk->mtu_max, pkt_dpdk->data_room);

	if (dpdk_init_capability(pktio_entry, &dev_info)) {
		ODP_ERR("Failed to initialize capability\n");
		return -1;
	}

	for (i = 0; i < PKTIO_MAX_QUEUES; i++) {
		odp_ticketlock_init(&pkt_dpdk->rx_lock[i]);
		odp_ticketlock_init(&pkt_dpdk->tx_lock[i]);
	}

	rte_eth_stats_reset(pkt_dpdk->port_id);

	return 0;
}

static int dpdk_setup_eth_tx(pktio_entry_t *pktio_entry,
			     const pkt_dpdk_t *pkt_dpdk,
			     const struct rte_eth_dev_info *dev_info)
{
	uint32_t i;
	int ret;
	uint16_t port_id = pkt_dpdk->port_id;

	for (i = 0; i < pktio_entry->num_out_queue; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i,
					     pkt_dpdk->num_tx_desc[i],
					     rte_eth_dev_socket_id(port_id),
					     &dev_info->default_txconf);
		if (ret < 0) {
			ODP_ERR("Queue setup failed: err=%d, port=%" PRIu8 "\n",
				ret, port_id);
			return -1;
		}
	}

	/* Set per queue statistics mappings. Not supported by all PMDs, so
	 * ignore the return value. */
	for (i = 0; i < pktio_entry->num_out_queue && i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		ret = rte_eth_dev_set_tx_queue_stats_mapping(port_id, i, i);
		if (ret) {
			ODP_DBG("Mapping per TX queue statistics not supported: %d\n", ret);
			break;
		}
	}
	ODP_DBG("Mapped %" PRIu32 "/%d TX counters\n", i, RTE_ETHDEV_QUEUE_STAT_CNTRS);

	return 0;
}

static int dpdk_setup_eth_rx(const pktio_entry_t *pktio_entry,
			     const pkt_dpdk_t *pkt_dpdk,
			     const struct rte_eth_dev_info *dev_info)
{
	struct rte_eth_rxconf rxconf;
	uint32_t i;
	int ret;
	uint16_t port_id = pkt_dpdk->port_id;

	rxconf = dev_info->default_rxconf;

	rxconf.rx_drop_en = pkt_dpdk->opt.rx_drop_en;

	for (i = 0; i < pktio_entry->num_in_queue; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i,
					     pkt_dpdk->opt.num_rx_desc,
					     rte_eth_dev_socket_id(port_id),
					     &rxconf, pkt_dpdk->pkt_pool);
		if (ret < 0) {
			ODP_ERR("Queue setup failed: err=%d, port=%" PRIu8 "\n",
				ret, port_id);
			return -1;
		}
	}

	/* Set per queue statistics mappings. Not supported by all PMDs, so
	 * ignore the return value. */
	for (i = 0; i < pktio_entry->num_in_queue && i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		ret = rte_eth_dev_set_rx_queue_stats_mapping(port_id, i, i);
		if (ret) {
			ODP_DBG("Mapping per RX queue statistics not supported: %d\n", ret);
			break;
		}
	}
	ODP_DBG("Mapped %" PRIu32 "/%d RX counters\n", i, RTE_ETHDEV_QUEUE_STAT_CNTRS);

	return 0;
}

static int dpdk_start(pktio_entry_t *pktio_entry)
{
	struct rte_eth_dev_info dev_info;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t port_id = pkt_dpdk->port_id;
	int ret;

	/* DPDK doesn't support nb_rx_q/nb_tx_q being 0 */
	if (!pktio_entry->num_in_queue)
		pktio_entry->num_in_queue = 1;
	if (!pktio_entry->num_out_queue)
		pktio_entry->num_out_queue = 1;

	rte_eth_dev_info_get(port_id, &dev_info);

	/* Setup device */
	if (dpdk_setup_eth_dev(pktio_entry)) {
		ODP_ERR("Failed to configure device\n");
		return -1;
	}

	/* Setup TX queues */
	if (dpdk_setup_eth_tx(pktio_entry, pkt_dpdk, &dev_info))
		return -1;

	/* Setup RX queues */
	if (dpdk_setup_eth_rx(pktio_entry, pkt_dpdk, &dev_info))
		return -1;

	/* Restore MTU value resetted by dpdk_setup_eth_rx() */
	if (pkt_dpdk->mtu_set && pktio_entry->capa.set_op.op.maxlen) {
		ret = dpdk_maxlen_set(pktio_entry, pkt_dpdk->mtu, 0);
		if (ret) {
			ODP_ERR("Restoring device MTU failed: err=%d, port=%" PRIu8 "\n",
				ret, port_id);
			return -1;
		}
	}
	/* Start device */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		ODP_ERR("Device start failed: err=%d, port=%" PRIu8 "\n",
			ret, port_id);
		return -1;
	}

	return 0;
}

static int dpdk_stop(pktio_entry_t *pktio_entry)
{
	rte_eth_dev_stop(pkt_priv(pktio_entry)->port_id);

	return 0;
}

static int dpdk_recv(pktio_entry_t *pktio_entry, int index,
		     odp_packet_t pkt_table[], int num)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	pkt_cache_t *rx_cache = &pkt_dpdk->rx_cache[index];
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	int nb_rx;
	struct rte_mbuf *rx_mbufs[num];
	int i;
	unsigned cache_idx;

	if (!pkt_dpdk->lockless_rx)
		odp_ticketlock_lock(&pkt_dpdk->rx_lock[index]);
	/**
	 * ixgbe and i40e drivers have a minimum supported RX burst size
	 * ('min_rx_burst'). If 'num' < 'min_rx_burst', 'min_rx_burst' is used
	 * as rte_eth_rx_burst() argument and the possibly received extra
	 * packets are cached for the next dpdk_recv_queue() call to use.
	 *
	 * Either use cached packets or receive new ones. Not both during the
	 * same call. */
	if (rx_cache->count > 0) {
		for (i = 0; i < num && rx_cache->count; i++) {
			rx_mbufs[i] = rx_cache->pkt[rx_cache->idx];
			rx_cache->idx++;
			rx_cache->count--;
		}
		nb_rx = i;
	} else if ((unsigned)num < pkt_dpdk->min_rx_burst) {
		struct rte_mbuf *new_mbufs[pkt_dpdk->min_rx_burst];

		nb_rx = rte_eth_rx_burst(pkt_priv(pktio_entry)->port_id, index,
					 new_mbufs, pkt_dpdk->min_rx_burst);
		rx_cache->idx = 0;
		for (i = 0; i < nb_rx; i++) {
			if (i < num) {
				rx_mbufs[i] = new_mbufs[i];
			} else {
				cache_idx = rx_cache->count;
				rx_cache->pkt[cache_idx] = new_mbufs[i];
				rx_cache->count++;
			}
		}
		nb_rx = RTE_MIN(num, nb_rx);

	} else {
		nb_rx = rte_eth_rx_burst(pkt_priv(pktio_entry)->port_id, index,
					 rx_mbufs, num);
	}

	if (!pkt_dpdk->lockless_rx)
		odp_ticketlock_unlock(&pkt_dpdk->rx_lock[index]);

	if (nb_rx > 0) {
		if (pktio_entry->config.pktin.bit.ts_all ||
		    pktio_entry->config.pktin.bit.ts_ptp) {
			ts_val = odp_time_global();
			ts = &ts_val;
		}
		if (_ODP_DPDK_ZERO_COPY)
			nb_rx = mbuf_to_pkt_zero(pktio_entry, pkt_table,
						 rx_mbufs, nb_rx, ts);
		else
			nb_rx = mbuf_to_pkt(pktio_entry, pkt_table, rx_mbufs,
					    nb_rx, ts);
	}

	return nb_rx;
}

static int dpdk_send(pktio_entry_t *pktio_entry, int index,
		     const odp_packet_t pkt_table[], int num)
{
	struct rte_mbuf *tx_mbufs[num];
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t copy_count = 0;
	uint16_t cpy_idx[num];
	int tx_pkts;
	int i;
	int mbufs;
	int tx_ts_idx = 0;

	if (_ODP_DPDK_ZERO_COPY)
		mbufs = pkt_to_mbuf_zero(pktio_entry, tx_mbufs, pkt_table, num,
					 &copy_count, cpy_idx, &tx_ts_idx);
	else
		mbufs = pkt_to_mbuf(pktio_entry, tx_mbufs, pkt_table, num,
				    &tx_ts_idx);

	if (!pkt_dpdk->lockless_tx)
		odp_ticketlock_lock(&pkt_dpdk->tx_lock[index]);

	tx_pkts = rte_eth_tx_burst(pkt_dpdk->port_id, index,
				   tx_mbufs, mbufs);

	if (!pkt_dpdk->lockless_tx)
		odp_ticketlock_unlock(&pkt_dpdk->tx_lock[index]);

	if (odp_unlikely(tx_ts_idx && tx_pkts >= tx_ts_idx))
		_odp_pktio_tx_ts_set(pktio_entry);

	if (_ODP_DPDK_ZERO_COPY) {
		/* Free copied packets */
		if (odp_unlikely(copy_count)) {
			uint16_t idx;

			for (i = 0; i < copy_count; i++) {
				idx = cpy_idx[i];

				if (odp_likely(idx < tx_pkts))
					odp_packet_free(pkt_table[idx]);
				else
					rte_pktmbuf_free(tx_mbufs[idx]);
			}
		}
		if (odp_unlikely(tx_pkts == 0 && _odp_errno != 0))
			return -1;
	} else {
		if (odp_unlikely(tx_pkts < mbufs)) {
			for (i = tx_pkts; i < mbufs; i++)
				rte_pktmbuf_free(tx_mbufs[i]);
		}

		if (odp_unlikely(tx_pkts == 0)) {
			if (_odp_errno != 0)
				return -1;
		} else {
			odp_packet_free_multi(pkt_table, tx_pkts);
		}
	}

	return tx_pkts;
}

static int dpdk_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	rte_eth_macaddr_get(pkt_priv(pktio_entry)->port_id,
			    (struct rte_ether_addr *)mac_addr);
	return ETH_ALEN;
}

static int dpdk_mac_addr_set(pktio_entry_t *pktio_entry, const void *mac_addr)
{
	struct rte_ether_addr addr = *(const struct rte_ether_addr *)mac_addr;

	return rte_eth_dev_default_mac_addr_set(pkt_priv(pktio_entry)->port_id,
						&addr);
}

static int dpdk_promisc_mode_set(pktio_entry_t *pktio_entry, odp_bool_t enable)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;

	if (pkt_priv(pktio_entry)->vdev_sysc_promisc)
		return dpdk_vdev_promisc_mode_set(port_id, enable);

	if (enable)
		rte_eth_promiscuous_enable(port_id);
	else
		rte_eth_promiscuous_disable(port_id);

	return 0;
}

static int dpdk_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;

	if (pkt_priv(pktio_entry)->vdev_sysc_promisc)
		return dpdk_vdev_promisc_mode_get(port_id);
	else
		return rte_eth_promiscuous_get(port_id);
}

static int dpdk_capability(pktio_entry_t *pktio_entry,
			   odp_pktio_capability_t *capa)
{
	*capa = pktio_entry->capa;
	return 0;
}

static int dpdk_link_status(pktio_entry_t *pktio_entry)
{
	struct rte_eth_link link;

	memset(&link, 0, sizeof(struct rte_eth_link));

	rte_eth_link_get_nowait(pkt_priv(pktio_entry)->port_id, &link);
	if (link.link_status)
		return ODP_PKTIO_LINK_STATUS_UP;
	return ODP_PKTIO_LINK_STATUS_DOWN;
}

static int dpdk_link_info(pktio_entry_t *pktio_entry, odp_pktio_link_info_t *info)
{
	struct rte_eth_link link;
	struct rte_eth_fc_conf fc_conf;
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;
	int ret;

	memset(&fc_conf, 0, sizeof(struct rte_eth_fc_conf));
	memset(&link, 0, sizeof(struct rte_eth_link));

	ret = rte_eth_dev_flow_ctrl_get(port_id, &fc_conf);
	if (ret && ret != -ENOTSUP) {
		ODP_ERR("rte_eth_dev_flow_ctrl_get() failed\n");
		return -1;
	}

	memset(info, 0, sizeof(odp_pktio_link_info_t));
	info->pause_rx = ODP_PKTIO_LINK_PAUSE_OFF;
	info->pause_tx = ODP_PKTIO_LINK_PAUSE_OFF;
	if (fc_conf.mode == RTE_FC_RX_PAUSE) {
		info->pause_rx = ODP_PKTIO_LINK_PAUSE_ON;
	} else if (fc_conf.mode == RTE_FC_TX_PAUSE) {
		info->pause_tx = ODP_PKTIO_LINK_PAUSE_ON;
	} else if (fc_conf.mode == RTE_FC_FULL) {
		info->pause_rx = ODP_PKTIO_LINK_PAUSE_ON;
		info->pause_tx = ODP_PKTIO_LINK_PAUSE_ON;
	}

	rte_eth_link_get_nowait(port_id, &link);
	if (link.link_autoneg == ETH_LINK_AUTONEG)
		info->autoneg = ODP_PKTIO_LINK_AUTONEG_ON;
	else
		info->autoneg = ODP_PKTIO_LINK_AUTONEG_OFF;

	if (link.link_duplex == ETH_LINK_FULL_DUPLEX)
		info->duplex = ODP_PKTIO_LINK_DUPLEX_FULL;
	else
		info->duplex = ODP_PKTIO_LINK_DUPLEX_HALF;

	if (link.link_speed == ETH_SPEED_NUM_NONE)
		info->speed = ODP_PKTIO_LINK_SPEED_UNKNOWN;
	else
		info->speed = link.link_speed;

	if (link.link_status == ETH_LINK_UP)
		info->status = ODP_PKTIO_LINK_STATUS_UP;
	else
		info->status = ODP_PKTIO_LINK_STATUS_DOWN;

	info->media = "unknown";

	return 0;
}

static void stats_convert(const struct rte_eth_stats *rte_stats,
			  odp_pktio_stats_t *stats)
{
	memset(stats, 0, sizeof(odp_pktio_stats_t));

	stats->in_octets = rte_stats->ibytes;
	stats->in_packets = rte_stats->ipackets;
	stats->in_discards = rte_stats->imissed;
	stats->in_errors = rte_stats->ierrors;
	stats->out_octets = rte_stats->obytes;
	stats->out_packets = rte_stats->opackets;
	stats->out_errors = rte_stats->oerrors;
}

static int dpdk_stats(pktio_entry_t *pktio_entry, odp_pktio_stats_t *stats)
{
	int ret;
	struct rte_eth_stats rte_stats;

	ret = rte_eth_stats_get(pkt_priv(pktio_entry)->port_id, &rte_stats);

	if (ret == 0) {
		stats_convert(&rte_stats, stats);
		return 0;
	}
	return -1;
}

static int dpdk_stats_reset(pktio_entry_t *pktio_entry)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;

	(void)rte_eth_stats_reset(port_id);
	(void)rte_eth_xstats_reset(port_id);
	return 0;
}

static int dpdk_extra_stat_info(pktio_entry_t *pktio_entry,
				odp_pktio_extra_stat_info_t info[], int num)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;
	int num_stats, ret, i;

	num_stats = rte_eth_xstats_get_names(port_id, NULL, 0);
	if (num_stats < 0) {
		ODP_ERR("rte_eth_xstats_get_names() failed: %d\n", num_stats);
		return num_stats;
	} else if (info == NULL || num == 0 || num_stats == 0) {
		return num_stats;
	}

	struct rte_eth_xstat_name xstats_names[num_stats];

	ret = rte_eth_xstats_get_names(port_id, xstats_names, num_stats);
	if (ret < 0 || ret > num_stats) {
		ODP_ERR("rte_eth_xstats_get_names() failed: %d\n", ret);
		return -1;
	}
	num_stats = ret;

	for (i = 0; i < num && i < num_stats; i++)
		strncpy(info[i].name, xstats_names[i].name,
			ODP_PKTIO_STATS_EXTRA_NAME_LEN - 1);

	return num_stats;
}

static int dpdk_extra_stats(pktio_entry_t *pktio_entry,
			    uint64_t stats[], int num)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;
	int num_stats, ret, i;

	num_stats = rte_eth_xstats_get(port_id, NULL, 0);
	if (num_stats < 0) {
		ODP_ERR("rte_eth_xstats_get() failed: %d\n", num_stats);
		return num_stats;
	} else if (stats == NULL || num == 0 || num_stats == 0) {
		return num_stats;
	}

	struct rte_eth_xstat xstats[num_stats];

	ret = rte_eth_xstats_get(port_id, xstats, num_stats);
	if (ret < 0 || ret > num_stats) {
		ODP_ERR("rte_eth_xstats_get() failed: %d\n", ret);
		return -1;
	}
	num_stats = ret;

	for (i = 0; i < num && i < num_stats; i++)
		stats[i] = xstats[i].value;

	return num_stats;
}

static int dpdk_extra_stat_counter(pktio_entry_t *pktio_entry, uint32_t id,
				   uint64_t *stat)
{
	uint16_t port_id = pkt_priv(pktio_entry)->port_id;
	uint64_t xstat_id = id;
	int ret;

	ret = rte_eth_xstats_get_by_id(port_id, &xstat_id, stat, 1);
	if (ret != 1) {
		ODP_ERR("rte_eth_xstats_get_by_id() failed: %d\n", ret);
		return -1;
	}

	return 0;
}

static int dpdk_pktin_stats(pktio_entry_t *pktio_entry, uint32_t index,
			    odp_pktin_queue_stats_t *pktin_stats)
{
	struct rte_eth_stats rte_stats;
	int ret;

	if (odp_unlikely(index > RTE_ETHDEV_QUEUE_STAT_CNTRS - 1)) {
		ODP_ERR("DPDK supports max %d per queue counters\n",
			RTE_ETHDEV_QUEUE_STAT_CNTRS);
		return -1;
	}

	ret = rte_eth_stats_get(pkt_priv(pktio_entry)->port_id, &rte_stats);
	if (odp_unlikely(ret)) {
		ODP_ERR("Failed to read DPDK pktio stats: %d\n", ret);
		return -1;
	}

	memset(pktin_stats, 0, sizeof(odp_pktin_queue_stats_t));

	pktin_stats->packets = rte_stats.q_ipackets[index];
	pktin_stats->octets = rte_stats.q_ibytes[index];
	pktin_stats->errors = rte_stats.q_errors[index];

	return 0;
}

static int dpdk_pktout_stats(pktio_entry_t *pktio_entry, uint32_t index,
			     odp_pktout_queue_stats_t *pktout_stats)
{
	struct rte_eth_stats rte_stats;
	int ret;

	if (odp_unlikely(index > RTE_ETHDEV_QUEUE_STAT_CNTRS - 1)) {
		ODP_ERR("DPDK supports max %d per queue counters\n",
			RTE_ETHDEV_QUEUE_STAT_CNTRS);
		return -1;
	}

	ret = rte_eth_stats_get(pkt_priv(pktio_entry)->port_id, &rte_stats);
	if (odp_unlikely(ret)) {
		ODP_ERR("Failed to read DPDK pktio stats: %d\n", ret);
		return -1;
	}

	memset(pktout_stats, 0, sizeof(odp_pktout_queue_stats_t));

	pktout_stats->packets = rte_stats.q_opackets[index];
	pktout_stats->octets = rte_stats.q_obytes[index];

	return 0;
}

const pktio_if_ops_t _odp_dpdk_pktio_ops = {
	.name = "dpdk",
	.init_global = dpdk_pktio_init_global,
	.init_local = dpdk_pktio_init_local,
	.term = dpdk_pktio_term,
	.open = dpdk_open,
	.close = dpdk_close,
	.start = dpdk_start,
	.stop = dpdk_stop,
	.stats = dpdk_stats,
	.stats_reset = dpdk_stats_reset,
	.pktin_queue_stats = dpdk_pktin_stats,
	.pktout_queue_stats = dpdk_pktout_stats,
	.extra_stat_info = dpdk_extra_stat_info,
	.extra_stats = dpdk_extra_stats,
	.extra_stat_counter = dpdk_extra_stat_counter,
	.recv = dpdk_recv,
	.send = dpdk_send,
	.link_status = dpdk_link_status,
	.link_info = dpdk_link_info,
	.maxlen_get = dpdk_maxlen,
	.maxlen_set = dpdk_maxlen_set,
	.promisc_mode_set = dpdk_promisc_mode_set,
	.promisc_mode_get = dpdk_promisc_mode_get,
	.mac_get = dpdk_mac_addr_get,
	.mac_set = dpdk_mac_addr_set,
	.capability = dpdk_capability,
	.pktio_ts_res = NULL,
	.pktio_ts_from_ns = NULL,
	.pktio_time = NULL,
	.config = NULL,
	.input_queues_config = dpdk_input_queues_config,
	.output_queues_config = dpdk_output_queues_config
};

static odp_bool_t is_mem_src_active(void)
{
	return !disable_pktio && _ODP_DPDK_ZERO_COPY;
}

static void force_mem_src_disable(void)
{
	if (_ODP_DPDK_ZERO_COPY)
		disable_pktio = 1;
}

const _odp_pool_mem_src_ops_t _odp_pool_dpdk_mem_src_ops = {
	.name = "dpdk_zc",
	.is_active = is_mem_src_active,
	.force_disable = force_mem_src_disable,
	.adjust_size = pool_obj_size,
	.bind = pool_create,
	.unbind = pool_destroy
};

#else
/* Avoid warning about empty translation unit */
typedef int _odp_dummy;
#endif /* _ODP_PKTIO_DPDK */

/* Copyright (c) 2016-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
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
#include <odp_classification_internal.h>
#include <odp_socket_common.h>
#include <odp_packet_dpdk.h>
#include <odp_debug_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_errno_define.h>

#include <protocols/eth.h>
#include <protocols/udp.h>

#include <rte_config.h>
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

/* NUMA is not supported on all platforms */
#ifdef _ODP_HAVE_NUMA_LIBRARY
#include <numa.h>
#else
#define numa_num_configured_nodes() 1
#endif

#if RTE_VERSION < RTE_VERSION_NUM(17, 5, 0, 0)
#define rte_log_set_global_level rte_set_log_level
#endif

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

/** DPDK runtime configuration options */
typedef struct {
	int num_rx_desc;
	int num_tx_desc;
	uint8_t rx_drop_en;
	uint8_t set_flow_hash;
} dpdk_opt_t;

struct pkt_cache_t {
	/** array for storing extra RX packets */
	struct rte_mbuf *pkt[DPDK_MIN_RX_BURST];
	unsigned int idx;			  /**< head of cache */
	unsigned int count;			  /**< packets in cache */
};

typedef union ODP_ALIGNED_CACHE {
	struct pkt_cache_t s;
	uint8_t pad[ROUNDUP_CACHE_LINE(sizeof(struct pkt_cache_t))];
} pkt_cache_t;

/** Packet IO using DPDK interface */
typedef struct ODP_ALIGNED_CACHE {
	odp_pool_t pool;		  /**< pool to alloc packets from */
	struct rte_mempool *pkt_pool;	  /**< DPDK packet pool */
	uint32_t data_room;		  /**< maximum packet length */
	unsigned int min_rx_burst;		  /**< minimum RX burst size */
	odp_pktin_hash_proto_t hash;	  /**< Packet input hash protocol */
	/* Supported RTE_PTYPE_XXX flags in a mask */
	uint32_t supported_ptypes;
	uint16_t mtu;			  /**< maximum transmission unit */
	uint16_t port_id;		  /**< DPDK port identifier */
	/** Use system call to get/set vdev promisc mode */
	uint8_t vdev_sysc_promisc;
	uint8_t lockless_rx;		  /**< no locking for rx */
	uint8_t lockless_tx;		  /**< no locking for tx */
	  /** RX queue locks */
	odp_ticketlock_t ODP_ALIGNED_CACHE rx_lock[PKTIO_MAX_QUEUES];
	odp_ticketlock_t tx_lock[PKTIO_MAX_QUEUES];  /**< TX queue locks */
	/** cache for storing extra RX packets */
	pkt_cache_t rx_cache[PKTIO_MAX_QUEUES];
	dpdk_opt_t opt;
} pkt_dpdk_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_dpdk_t),
		  "PKTIO_PRIVATE_SIZE too small");

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
	return (pkt_dpdk_t *)(uintptr_t)(pktio_entry->s.pkt_priv);
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
			&opt->num_tx_desc))
		return -1;
	if (opt->num_tx_desc < dev_info->tx_desc_lim.nb_min ||
	    opt->num_tx_desc > dev_info->tx_desc_lim.nb_max ||
	    opt->num_tx_desc % dev_info->tx_desc_lim.nb_align) {
		ODP_ERR("Invalid number of TX descriptors\n");
		return -1;
	}

	if (!lookup_opt("rx_drop_en", dev_info->driver_name, &val))
		return -1;
	opt->rx_drop_en = !!val;

	if (!lookup_opt("set_flow_hash", NULL, &val))
		return -1;
	opt->set_flow_hash = !!val;

	ODP_PRINT("DPDK interface (%s): %" PRIu16 "\n", dev_info->driver_name,
		  pkt_priv(pktio_entry)->port_id);
	ODP_PRINT("  num_rx_desc: %d\n", opt->num_rx_desc);
	ODP_PRINT("  num_tx_desc: %d\n", opt->num_tx_desc);
	ODP_PRINT("  rx_drop_en: %d\n", opt->rx_drop_en);

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

	if (odp_unlikely(pkt_hdr->buf_hdr.base_data != pkt_hdr->seg_data))
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
	buf_addr = pkt_hdr->buf_hdr.base_data - RTE_PKTMBUF_HEADROOM;

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
					    pool_t *pool_entry)
{
	struct rte_mempool *mp = NULL;
	struct rte_pktmbuf_pool_private mbp_priv;
	struct rte_mempool_objsz sz;
	unsigned int elt_size = pool_entry->dpdk_elt_size;
	unsigned int num = pool_entry->num;
	uint32_t total_size;

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

	total_size = rte_mempool_calc_obj_size(elt_size, 0, &sz);
	if (total_size != pool_entry->block_size) {
		ODP_ERR("DPDK pool block size not matching to ODP pool: "
			"%" PRIu32 "/%" PRIu32 "\n", total_size,
			pool_entry->block_size);
		goto fail;
	}

	/* Skipped buffers have to be taken into account to populate pool
	 * properly. */
	mp = rte_mempool_create_empty(name, num + pool_entry->skipped_blocks,
				      elt_size, cache_size(num),
				      sizeof(struct rte_pktmbuf_pool_private),
				      rte_socket_id(), 0);
	if (mp == NULL) {
		ODP_ERR("Failed to create empty DPDK packet pool\n");
		goto fail;
	}

	mp->pool_data = pool_entry->pool_hdl;

	if (rte_mempool_set_ops_byname(mp, "odp_pool", pool_entry)) {
		ODP_ERR("Failed setting mempool operations\n");
		goto fail;
	}

	mbp_priv.mbuf_data_room_size = pool_entry->headroom +
			pool_entry->seg_len;
	mbp_priv.mbuf_priv_size = RTE_ALIGN(sizeof(odp_packet_hdr_t),
					    RTE_MBUF_PRIV_ALIGN);
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	num = rte_mempool_populate_iova(mp, (char *)pool_entry->base_addr,
					RTE_BAD_IOVA, pool_entry->shm_size,
					NULL, NULL);
	if (num <= 0) {
		ODP_ERR("Failed to populate mempool: %d\n", num);
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
	unsigned i;

	if (odp_unlikely(num == 0 || !pool_entry->pool_in_use))
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

	pkts = packet_alloc_multi(pool, pool_entry->seg_len, packet_tbl,
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

static void pool_destroy(void *pool)
{
	struct rte_mempool *mp = (struct rte_mempool *)pool;

	if (mp != NULL) {
		pool_t *pool_entry = (pool_t *)mp->pool_config;

		pool_entry->pool_in_use = 0;
		rte_mempool_free(mp);
	}
}

int _odp_dpdk_pool_create(pool_t *pool)
{
	struct rte_mempool *pkt_pool;
	char pool_name[RTE_MEMPOOL_NAMESIZE];

	if (!_ODP_DPDK_ZERO_COPY)
		return 0;

	pool->pool_in_use = 0;

	snprintf(pool_name, sizeof(pool_name),
		 "dpdk_pktpool_%" PRIu32 "_%" PRIu32 "", odp_global_ro.main_pid,
		 pool->pool_idx);
	pkt_pool = mbuf_pool_create(pool_name, pool);

	if (pkt_pool == NULL) {
		ODP_ERR("Creating external DPDK pool failed\n");
		return -1;
	}

	pool->ext_desc = pkt_pool;
	pool->ext_destroy = pool_destroy;
	pool->pool_in_use = 1;

	return 0;
}

uint32_t _odp_dpdk_pool_obj_size(pool_t *pool, uint32_t block_size)
{
	struct rte_mempool_objsz sz;
	uint32_t total_size;

	if (!_ODP_DPDK_ZERO_COPY)
		return block_size;

	if (odp_global_rw->dpdk_initialized == 0) {
		if (dpdk_pktio_init()) {
			ODP_ERR("Initializing DPDK failed\n");
			return 0;
		}
		odp_global_rw->dpdk_initialized = 1;
	}

	block_size += sizeof(struct rte_mbuf);
	total_size = rte_mempool_calc_obj_size(block_size, 0, &sz);
	pool->dpdk_elt_size = sz.elt_size;
	pool->block_offset = sz.header_size + sizeof(struct rte_mbuf);

	return total_size;
}

static struct rte_mempool_ops odp_pool_ops = {
	.name = "odp_pool",
	.alloc = pool_alloc,
	.free = pool_free,
	.enqueue = pool_enqueue,
	.dequeue = pool_dequeue_bulk,
	.get_count = pool_get_count
};

MEMPOOL_REGISTER_OPS(odp_pool_ops);

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
	int i, j;
	int alloc_len, num;
	int nb_pkts = 0;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	odp_pool_t pool = pkt_dpdk->pool;
	odp_pktin_config_opt_t pktin_cfg = pktio_entry->s.config.pktin;
	odp_proto_layer_t parse_layer = pktio_entry->s.config.parser.layer;
	odp_pktio_t input = pktio_entry->s.handle;

	/* Allocate maximum sized packets */
	alloc_len = pkt_dpdk->data_room;

	num = packet_alloc_multi(pool, alloc_len, pkt_table, mbuf_num);
	if (num != mbuf_num) {
		ODP_DBG("packet_alloc_multi() unable to allocate all packets: "
			"%d/%" PRIu16 " allocated\n", num, mbuf_num);
		for (i = num; i < mbuf_num; i++)
			rte_pktmbuf_free(mbuf_table[i]);
	}

	for (i = 0; i < num; i++) {
		odp_packet_hdr_t parsed_hdr;

		mbuf = mbuf_table[i];
		if (odp_unlikely(mbuf->nb_segs != 1)) {
			ODP_ERR("Segmented buffers not supported\n");
			goto fail;
		}

		data = rte_pktmbuf_mtod(mbuf, char *);
		odp_prefetch(data);

		pkt_len = rte_pktmbuf_pkt_len(mbuf);

		if (pktio_cls_enabled(pktio_entry)) {
			uint32_t supported_ptypes = pkt_dpdk->supported_ptypes;

			packet_parse_reset(&parsed_hdr);
			packet_set_len(&parsed_hdr, pkt_len);
			if (_odp_dpdk_packet_parse_common(&parsed_hdr.p, data,
							  pkt_len, pkt_len,
							  mbuf,
							  ODP_PROTO_LAYER_ALL,
							  supported_ptypes,
							  pktin_cfg)) {
				odp_packet_free(pkt_table[i]);
				rte_pktmbuf_free(mbuf);
				continue;
			}
			if (cls_classify_packet(pktio_entry,
						(const uint8_t *)data,
						pkt_len, pkt_len, &pool,
						&parsed_hdr, false))
				goto fail;
		}

		pkt     = pkt_table[i];
		pkt_hdr = packet_hdr(pkt);
		pull_tail(pkt_hdr, alloc_len - pkt_len);

		if (odp_packet_copy_from_mem(pkt, 0, pkt_len, data) != 0)
			goto fail;

		pkt_hdr->input = input;

		if (pktio_cls_enabled(pktio_entry)) {
			copy_packet_cls_metadata(&parsed_hdr, pkt_hdr);
		} else if (parse_layer != ODP_PROTO_LAYER_NONE) {
			uint32_t supported_ptypes = pkt_dpdk->supported_ptypes;

			if (_odp_dpdk_packet_parse_layer(pkt_hdr, mbuf,
							 parse_layer,
							 supported_ptypes,
							 pktin_cfg)) {
				odp_packet_free(pkt);
				rte_pktmbuf_free(mbuf);
				continue;
			}
		}

		if (mbuf->ol_flags & PKT_RX_RSS_HASH)
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
		struct ipv4_hdr *ip = (struct ipv4_hdr *)l3_hdr;

		*l3_proto_v4 = 1;
		if (!rte_ipv4_frag_pkt_is_fragmented(ip))
			*l4_proto = ip->next_proto_id;
		else
			*l4_proto = 0;

		return 0;
	} else if (l3_proto_ver == _ODP_IPV6) {
		struct ipv6_hdr *ipv6 = (struct ipv6_hdr *)l3_hdr;

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
		mbuf->ol_flags = PKT_TX_IPV4;
	else
		mbuf->ol_flags = PKT_TX_IPV6;

	if (ipv4_chksum_pkt) {
		mbuf->ol_flags |=  PKT_TX_IP_CKSUM;

		((struct ipv4_hdr *)l3_hdr)->hdr_checksum = 0;
		mbuf->l3_len = _ODP_IPV4HDR_IHL(*(uint8_t *)l3_hdr) * 4;
	}

	if (pkt_p->l4_offset == ODP_PACKET_OFFSET_INVALID)
		return;

	mbuf->l3_len = pkt_p->l4_offset - pkt_p->l3_offset;

	l4_hdr = (void *)(mbuf_data + pkt_p->l4_offset);

	if (udp_chksum_pkt) {
		mbuf->ol_flags |= PKT_TX_UDP_CKSUM;

		((struct udp_hdr *)l4_hdr)->dgram_cksum =
			phdr_csum(l3_proto_v4, l3_hdr, mbuf->ol_flags);
	} else if (tcp_chksum_pkt) {
		mbuf->ol_flags |= PKT_TX_TCP_CKSUM;

		((struct tcp_hdr *)l4_hdr)->cksum =
			phdr_csum(l3_proto_v4, l3_hdr, mbuf->ol_flags);
	}
}

static inline int pkt_to_mbuf(pktio_entry_t *pktio_entry,
			      struct rte_mbuf *mbuf_table[],
			      const odp_packet_t pkt_table[], uint16_t num)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	int i, j;
	char *data;
	uint16_t pkt_len;
	odp_pktout_config_opt_t *pktout_cfg = &pktio_entry->s.config.pktout;

	if (odp_unlikely((rte_pktmbuf_alloc_bulk(pkt_dpdk->pkt_pool,
						 mbuf_table, num)))) {
		ODP_ERR("Failed to alloc mbuf\n");
		return 0;
	}
	for (i = 0; i < num; i++) {
		odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt_table[i]);

		pkt_len = packet_len(pkt_hdr);

		if (pkt_len > pkt_dpdk->mtu) {
			if (i == 0)
				__odp_errno = EMSGSIZE;
			goto fail;
		}

		/* Packet always fits in mbuf */
		data = rte_pktmbuf_append(mbuf_table[i], pkt_len);

		odp_packet_copy_to_mem(pkt_table[i], 0, pkt_len, data);

		if (odp_unlikely(pktio_entry->s.chksum_insert_ena)) {
			odp_pktout_config_opt_t *pktout_capa =
			&pktio_entry->s.capa.config.pktout;

			pkt_set_ol_tx(pktout_cfg, pktout_capa, pkt_hdr,
				      mbuf_table[i], data);
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
	odp_pool_t pool;
	odp_pktin_config_opt_t pktin_cfg;
	odp_proto_layer_t parse_layer;
	odp_pktio_t input;
	pkt_dpdk_t *pkt_dpdk;

	prefetch_pkt(mbuf_table[0]);

	pkt_dpdk = pkt_priv(pktio_entry);
	nb_pkts = 0;
	pool = pkt_dpdk->pool;
	set_flow_hash = pkt_dpdk->opt.set_flow_hash;
	pktin_cfg = pktio_entry->s.config.pktin;
	parse_layer = pktio_entry->s.config.parser.layer;
	input = pktio_entry->s.handle;

	if (odp_likely(mbuf_num > 1))
		prefetch_pkt(mbuf_table[1]);

	for (i = 0; i < mbuf_num; i++) {
		odp_packet_hdr_t parsed_hdr;

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

		if (pktio_cls_enabled(pktio_entry)) {
			uint32_t supported_ptypes = pkt_dpdk->supported_ptypes;

			packet_parse_reset(&parsed_hdr);
			packet_set_len(&parsed_hdr, pkt_len);
			if (_odp_dpdk_packet_parse_common(&parsed_hdr.p, data,
							  pkt_len, pkt_len,
							  mbuf,
							  ODP_PROTO_LAYER_ALL,
							  supported_ptypes,
							  pktin_cfg)) {
				rte_pktmbuf_free(mbuf);
				continue;
			}
			if (cls_classify_packet(pktio_entry,
						(const uint8_t *)data,
						pkt_len, pkt_len, &pool,
						&parsed_hdr, false)) {
				ODP_ERR("Unable to classify packet\n");
				rte_pktmbuf_free(mbuf);
				continue;
			}
		}

		/* Init buffer segments. Currently, only single segment packets
		 * are supported. */
		pkt_hdr->seg_data = data;

		packet_init(pkt_hdr, pkt_len);
		pkt_hdr->input = input;

		if (pktio_cls_enabled(pktio_entry)) {
			copy_packet_cls_metadata(&parsed_hdr, pkt_hdr);
		} else if (parse_layer != ODP_PROTO_LAYER_NONE) {
			uint32_t supported_ptypes = pkt_dpdk->supported_ptypes;

			if (_odp_dpdk_packet_parse_layer(pkt_hdr, mbuf,
							 parse_layer,
							 supported_ptypes,
							 pktin_cfg)) {
				rte_pktmbuf_free(mbuf);
				continue;
			}
		}
		if (set_flow_hash && (mbuf->ol_flags & PKT_RX_RSS_HASH))
			packet_set_flow_hash(pkt_hdr, mbuf->hash.rss);

		packet_set_ts(pkt_hdr, ts);

		pkt_table[nb_pkts++] = packet_handle(pkt_hdr);
	}

	return nb_pkts;
}

static inline int pkt_to_mbuf_zero(pktio_entry_t *pktio_entry,
				   struct rte_mbuf *mbuf_table[],
				   const odp_packet_t pkt_table[], uint16_t num,
				   uint16_t *copy_count)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	odp_pktout_config_opt_t *pktout_cfg = &pktio_entry->s.config.pktout;
	odp_pktout_config_opt_t *pktout_capa =
		&pktio_entry->s.capa.config.pktout;
	uint16_t mtu = pkt_dpdk->mtu;
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

			if (odp_unlikely(pktio_entry->s.chksum_insert_ena))
				pkt_set_ol_tx(pktout_cfg, pktout_capa, pkt_hdr,
					      mbuf, odp_packet_data(pkt));
		} else {
			/* Fall back to packet copy */
			if (odp_unlikely(pkt_to_mbuf(pktio_entry, &mbuf,
						     &pkt, 1) != 1))
				goto fail;
			(*copy_count)++;
		}
		mbuf_table[i] = mbuf;
	}
	return i;

fail:
	if (i == 0)
		__odp_errno = EMSGSIZE;
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

	mtu = mtu_get_fd(sockfd, ifr.ifr_name);
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

static uint32_t dpdk_frame_maxlen(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);

	return pkt_dpdk->mtu;
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

	mode = promisc_mode_get_fd(sockfd, ifr.ifr_name);
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

	mode = promisc_mode_set_fd(sockfd, ifr.ifr_name, enable);
	close(sockfd);
	return mode;
}

static void rss_conf_to_hash_proto(struct rte_eth_rss_conf *rss_conf,
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

static int dpdk_setup_eth_dev(pktio_entry_t *pktio_entry,
			      const struct rte_eth_dev_info *dev_info)
{
	int ret;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	struct rte_eth_rss_conf rss_conf;
	struct rte_eth_conf eth_conf;
	uint64_t rss_hf_capa = dev_info->flow_type_rss_offloads;

	memset(&rss_conf, 0, sizeof(struct rte_eth_rss_conf));

	/* Always set some hash functions to enable DPDK RSS hash calculation.
	 * Hash capability has been checked in pktin config. */
	if (pkt_dpdk->hash.all_bits == 0)
		rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP;
	else
		rss_conf_to_hash_proto(&rss_conf, &pkt_dpdk->hash);

	/* Filter out unsupported flags */
	rss_conf.rss_hf &= rss_hf_capa;

	memset(&eth_conf, 0, sizeof(eth_conf));

	eth_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
	eth_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
	eth_conf.rx_adv_conf.rss_conf = rss_conf;

	ret = rte_eth_dev_configure(pkt_dpdk->port_id,
				    pktio_entry->s.num_in_queue,
				    pktio_entry->s.num_out_queue, &eth_conf);
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
		idx = pkt_dpdk->rx_cache[i].s.idx;

		for (j = 0; j < pkt_dpdk->rx_cache[i].s.count; j++)
			rte_pktmbuf_free(pkt_dpdk->rx_cache[i].s.pkt[idx++]);
	}

#if RTE_VERSION < RTE_VERSION_NUM(17, 8, 0, 0)
	if (pktio_entry->s.state != PKTIO_STATE_OPENED)
		rte_eth_dev_close(pkt_dpdk->port_id);
#endif

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
	struct rte_config *cfg;

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
		ODP_ERR("CPU mask error: d\n", masklen);
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

	cfg = rte_eal_get_configuration();
	for (i = 0; i < RTE_MAX_LCORE; i++)
		cfg->lcore_role[i] = ROLE_RTE;

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

/* RTE_ETH_FOREACH_DEV was introduced in v17.8, but causes a build error in
 * v18.2 (only a warning, but our build system treats warnings as errors). */
#if (RTE_VERSION >= RTE_VERSION_NUM(18, 2, 0, 0)) && \
	(RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0))
	#define ETH_FOREACH_DEV(p)					\
		for (p = rte_eth_find_next(0);				\
		     (unsigned int)p < (unsigned int)RTE_MAX_ETHPORTS;	\
		     p = rte_eth_find_next(p + 1))
#elif RTE_VERSION >= RTE_VERSION_NUM(17, 8, 0, 0)
	#define ETH_FOREACH_DEV(p) RTE_ETH_FOREACH_DEV(p)
#endif

static int dpdk_pktio_term(void)
{
	uint16_t port_id;

	if (!odp_global_rw->dpdk_initialized)
		return 0;

#if RTE_VERSION >= RTE_VERSION_NUM(17, 8, 0, 0)
	ETH_FOREACH_DEV(port_id) {
		rte_eth_dev_close(port_id);
	}
#endif

	if (!_ODP_DPDK_ZERO_COPY)
		rte_mempool_walk(dpdk_mempool_free, NULL);

	return 0;
}

static int check_hash_proto(pktio_entry_t *pktio_entry,
			    const odp_pktin_queue_param_t *p)
{
	struct rte_eth_dev_info dev_info;
	uint64_t rss_hf_capa;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t port_id = pkt_dpdk->port_id;

	rte_eth_dev_info_get(port_id, &dev_info);
	rss_hf_capa = dev_info.flow_type_rss_offloads;

	if (p->hash_proto.proto.ipv4 &&
	    ((rss_hf_capa & ETH_RSS_IPV4) == 0)) {
		ODP_ERR("hash_proto.ipv4 not supported\n");
		return -1;
	}

	if (p->hash_proto.proto.ipv4_udp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV4_UDP) == 0)) {
		ODP_ERR("hash_proto.ipv4_udp not supported. "
			"rss_hf_capa 0x%" PRIx64 "\n", rss_hf_capa);
		return -1;
	}

	if (p->hash_proto.proto.ipv4_tcp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV4_TCP) == 0)) {
		ODP_ERR("hash_proto.ipv4_tcp not supported. "
			"rss_hf_capa 0x%" PRIx64 "\n", rss_hf_capa);
		return -1;
	}

	if (p->hash_proto.proto.ipv6 &&
	    ((rss_hf_capa & ETH_RSS_IPV6) == 0)) {
		ODP_ERR("hash_proto.ipv6 not supported. "
			"rss_hf_capa 0x%" PRIx64 "\n", rss_hf_capa);
		return -1;
	}

	if (p->hash_proto.proto.ipv6_udp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV6_UDP) == 0)) {
		ODP_ERR("hash_proto.ipv6_udp not supported. "
			"rss_hf_capa 0x%" PRIx64 "\n", rss_hf_capa);
		return -1;
	}

	if (p->hash_proto.proto.ipv6_tcp &&
	    ((rss_hf_capa & ETH_RSS_NONFRAG_IPV6_TCP) == 0)) {
		ODP_ERR("hash_proto.ipv6_tcp not supported. "
			"rss_hf_capa 0x%" PRIx64 "\n", rss_hf_capa);
		return -1;
	}

	return 0;
}

static int dpdk_input_queues_config(pktio_entry_t *pktio_entry,
				    const odp_pktin_queue_param_t *p)
{
	odp_pktin_mode_t mode = pktio_entry->s.param.in_mode;
	uint8_t lockless;

	if (p->hash_enable && check_hash_proto(pktio_entry, p))
		return -1;

	/**
	 * Scheduler synchronizes input queue polls. Only single thread
	 * at a time polls a queue */
	if (mode == ODP_PKTIN_MODE_SCHED ||
	    p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		lockless = 1;
	else
		lockless = 0;

	if (p->hash_enable && p->num_queues > 1)
		pkt_priv(pktio_entry)->hash = p->hash_proto;

	pkt_priv(pktio_entry)->lockless_rx = lockless;

	return 0;
}

static int dpdk_output_queues_config(pktio_entry_t *pktio_entry,
				     const odp_pktout_queue_param_t *p)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint8_t lockless;

	if (p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		lockless = 1;
	else
		lockless = 0;

	pkt_dpdk->lockless_tx = lockless;

	return 0;
}

static void dpdk_init_capability(pktio_entry_t *pktio_entry,
				 struct rte_eth_dev_info *dev_info)
{
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	odp_pktio_capability_t *capa = &pktio_entry->s.capa;
	int ptype_cnt;
	int ptype_l3_ipv4 = 0;
	int ptype_l4_tcp = 0;
	int ptype_l4_udp = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	memset(dev_info, 0, sizeof(struct rte_eth_dev_info));
	memset(capa, 0, sizeof(odp_pktio_capability_t));

	rte_eth_dev_info_get(pkt_dpdk->port_id, dev_info);
	capa->max_input_queues = RTE_MIN(dev_info->max_rx_queues,
					 PKTIO_MAX_QUEUES);

	/* ixgbe devices support only 16 rx queues in RSS mode */
	if (!strncmp(dev_info->driver_name, IXGBE_DRV_NAME,
		     strlen(IXGBE_DRV_NAME)))
		capa->max_input_queues = RTE_MIN((unsigned)16,
						 capa->max_input_queues);

	capa->max_output_queues = RTE_MIN(dev_info->max_tx_queues,
					  PKTIO_MAX_QUEUES);
	capa->set_op.op.promisc_mode = 1;

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
	int i;
	pool_t *pool_entry;

	if (disable_pktio)
		return -1;

	if (pool == ODP_POOL_INVALID)
		return -1;
	pool_entry = pool_entry_from_hdl(pool);

	if (!dpdk_netdev_is_valid(netdev)) {
		ODP_ERR("Invalid dpdk netdev: %s\n", netdev);
		return -1;
	}

	/* Initialize DPDK here instead of odp_init_global() to enable running
	 * 'make check' without root privileges */
	if (odp_global_rw->dpdk_initialized == 0) {
		dpdk_pktio_init();
		odp_global_rw->dpdk_initialized = 1;
	}

	/* Init pktio entry */
	memset(pkt_dpdk, 0, sizeof(*pkt_dpdk));

	pkt_dpdk->pool = pool;
	pkt_dpdk->port_id = atoi(netdev);

	/* rte_eth_dev_count() was removed in v18.05 */
#if RTE_VERSION < RTE_VERSION_NUM(18, 5, 0, 0)
	if (rte_eth_dev_count() == 0) {
#else
	if (rte_eth_dev_count_avail() == 0) {
#endif
		ODP_ERR("No DPDK ports found\n");
		return -1;
	}

	dpdk_init_capability(pktio_entry, &dev_info);

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

	/* Some DPDK PMD virtual devices, like PCAP, do not support promisc
	 * mode change. Use system call for them. */
	rte_eth_promiscuous_enable(pkt_dpdk->port_id);
	if (!rte_eth_promiscuous_get(pkt_dpdk->port_id))
		pkt_dpdk->vdev_sysc_promisc = 1;
	rte_eth_promiscuous_disable(pkt_dpdk->port_id);

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
		pkt_pool = (struct rte_mempool *)pool_entry->ext_desc;
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

	/* Mbuf chaining not yet supported */
	 pkt_dpdk->mtu = RTE_MIN(pkt_dpdk->mtu, pkt_dpdk->data_room);

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
	struct rte_eth_txconf txconf;
	uint64_t tx_offloads;
	uint32_t i;
	int ret;
	uint16_t port_id = pkt_dpdk->port_id;

	txconf = dev_info->default_txconf;

	tx_offloads = 0;
	if (pktio_entry->s.config.pktout.bit.ipv4_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;

	if (pktio_entry->s.config.pktout.bit.udp_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;

	if (pktio_entry->s.config.pktout.bit.tcp_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_TCP_CKSUM;

	if (pktio_entry->s.config.pktout.bit.sctp_chksum_ena)
		tx_offloads |= DEV_TX_OFFLOAD_SCTP_CKSUM;

	txconf.offloads = tx_offloads;

	if (tx_offloads)
		pktio_entry->s.chksum_insert_ena = 1;

	for (i = 0; i < pktio_entry->s.num_out_queue; i++) {

		ret = rte_eth_tx_queue_setup(port_id, i,
					     pkt_dpdk->opt.num_tx_desc,
					     rte_eth_dev_socket_id(port_id),
					     &txconf);
		if (ret < 0) {
			ODP_ERR("Queue setup failed: err=%d, port=%" PRIu8 "\n",
				ret, port_id);
			return -1;
		}
	}

	return 0;
}

static int dpdk_setup_eth_rx(const pktio_entry_t *pktio_entry,
			     const pkt_dpdk_t *pkt_dpdk,
			     const struct rte_eth_dev_info *dev_info)
{
	struct rte_eth_rxconf rxconf;
	uint64_t rx_offloads;
	uint32_t i;
	int ret;
	uint16_t port_id = pkt_dpdk->port_id;

	rxconf = dev_info->default_rxconf;

	rxconf.rx_drop_en = pkt_dpdk->opt.rx_drop_en;

	rx_offloads = 0;
	if (pktio_entry->s.config.pktin.bit.ipv4_chksum)
		rx_offloads |= DEV_RX_OFFLOAD_IPV4_CKSUM;

	if (pktio_entry->s.config.pktin.bit.udp_chksum)
		rx_offloads |= DEV_RX_OFFLOAD_UDP_CKSUM;

	if (pktio_entry->s.config.pktin.bit.tcp_chksum)
		rx_offloads |= DEV_RX_OFFLOAD_TCP_CKSUM;

	rxconf.offloads = rx_offloads;

	for (i = 0; i < pktio_entry->s.num_in_queue; i++) {
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

	return 0;
}

static void dpdk_ptype_support_set(pktio_entry_t *pktio_entry, uint16_t port_id)
{
	int max_num, num, i;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint32_t mask = RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK |
			RTE_PTYPE_L4_MASK;

	pkt_dpdk->supported_ptypes = 0;

	max_num = rte_eth_dev_get_supported_ptypes(port_id, mask, NULL, 0);
	if (max_num <= 0) {
		ODP_ERR("Device does not support any ptype flags\n");
		return;
	}

	uint32_t ptype[max_num];

	num = rte_eth_dev_get_supported_ptypes(port_id, mask, ptype, max_num);
	if (num <= 0) {
		ODP_ERR("Device does not support any ptype flags\n");
		return;
	}

	for (i = 0; i < num; i++) {
		ODP_DBG("  supported ptype: 0x%x\n", ptype[i]);

		if (ptype[i] == RTE_PTYPE_L2_ETHER_VLAN)
			pkt_dpdk->supported_ptypes |= PTYPE_VLAN;
		else if (ptype[i] == RTE_PTYPE_L2_ETHER_QINQ)
			pkt_dpdk->supported_ptypes |= PTYPE_VLAN_QINQ;
		else if (ptype[i] == RTE_PTYPE_L2_ETHER_ARP)
			pkt_dpdk->supported_ptypes |= PTYPE_ARP;
		else if (RTE_ETH_IS_IPV4_HDR(ptype[i]))
			pkt_dpdk->supported_ptypes |= PTYPE_IPV4;
		else if (RTE_ETH_IS_IPV6_HDR(ptype[i]))
			pkt_dpdk->supported_ptypes |= PTYPE_IPV6;
		else if (ptype[i] == RTE_PTYPE_L4_UDP)
			pkt_dpdk->supported_ptypes |= PTYPE_UDP;
		else if (ptype[i] == RTE_PTYPE_L4_TCP)
			pkt_dpdk->supported_ptypes |= PTYPE_TCP;
	}
}

static int dpdk_start(pktio_entry_t *pktio_entry)
{
	struct rte_eth_dev_info dev_info;
	pkt_dpdk_t *pkt_dpdk = pkt_priv(pktio_entry);
	uint16_t port_id = pkt_dpdk->port_id;
	int ret;

	/* DPDK doesn't support nb_rx_q/nb_tx_q being 0 */
	if (!pktio_entry->s.num_in_queue)
		pktio_entry->s.num_in_queue = 1;
	if (!pktio_entry->s.num_out_queue)
		pktio_entry->s.num_out_queue = 1;

	rte_eth_dev_info_get(port_id, &dev_info);

	/* Setup device */
	if (dpdk_setup_eth_dev(pktio_entry, &dev_info)) {
		ODP_ERR("Failed to configure device\n");
		return -1;
	}

	/* Setup TX queues */
	if (dpdk_setup_eth_tx(pktio_entry, pkt_dpdk, &dev_info))
		return -1;

	/* Setup RX queues */
	if (dpdk_setup_eth_rx(pktio_entry, pkt_dpdk, &dev_info))
		return -1;

	/* Start device */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		ODP_ERR("Device start failed: err=%d, port=%" PRIu8 "\n",
			ret, port_id);
		return -1;
	}

	/* Record supported parser ptype flags */
	dpdk_ptype_support_set(pktio_entry, port_id);

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

	if (odp_unlikely(pktio_entry->s.state != PKTIO_STATE_STARTED))
		return 0;

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
	if (rx_cache->s.count > 0) {
		for (i = 0; i < num && rx_cache->s.count; i++) {
			rx_mbufs[i] = rx_cache->s.pkt[rx_cache->s.idx];
			rx_cache->s.idx++;
			rx_cache->s.count--;
		}
		nb_rx = i;
	} else if ((unsigned)num < pkt_dpdk->min_rx_burst) {
		struct rte_mbuf *new_mbufs[pkt_dpdk->min_rx_burst];

		nb_rx = rte_eth_rx_burst(pkt_priv(pktio_entry)->port_id, index,
					 new_mbufs, pkt_dpdk->min_rx_burst);
		rx_cache->s.idx = 0;
		for (i = 0; i < nb_rx; i++) {
			if (i < num) {
				rx_mbufs[i] = new_mbufs[i];
			} else {
				cache_idx = rx_cache->s.count;
				rx_cache->s.pkt[cache_idx] = new_mbufs[i];
				rx_cache->s.count++;
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
		if (pktio_entry->s.config.pktin.bit.ts_all ||
		    pktio_entry->s.config.pktin.bit.ts_ptp) {
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
	int tx_pkts;
	int i;
	int mbufs;

	if (odp_unlikely(pktio_entry->s.state != PKTIO_STATE_STARTED))
		return 0;

	if (_ODP_DPDK_ZERO_COPY)
		mbufs = pkt_to_mbuf_zero(pktio_entry, tx_mbufs, pkt_table, num,
					 &copy_count);
	else
		mbufs = pkt_to_mbuf(pktio_entry, tx_mbufs, pkt_table, num);

	if (!pkt_dpdk->lockless_tx)
		odp_ticketlock_lock(&pkt_dpdk->tx_lock[index]);

	tx_pkts = rte_eth_tx_burst(pkt_dpdk->port_id, index,
				   tx_mbufs, mbufs);

	if (!pkt_dpdk->lockless_tx)
		odp_ticketlock_unlock(&pkt_dpdk->tx_lock[index]);

	if (_ODP_DPDK_ZERO_COPY) {
		/* Free copied packets */
		if (odp_unlikely(copy_count)) {
			uint16_t freed = 0;

			for (i = 0; i < mbufs && freed != copy_count; i++) {
				odp_packet_t pkt = pkt_table[i];
				odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

				if (pkt_hdr->seg_count > 1) {
					if (odp_likely(i < tx_pkts))
						odp_packet_free(pkt);
					else
						rte_pktmbuf_free(tx_mbufs[i]);
					freed++;
				}
			}
		}
		if (odp_unlikely(tx_pkts == 0 && __odp_errno != 0))
				return -1;
	} else {
		if (odp_unlikely(tx_pkts < mbufs)) {
			for (i = tx_pkts; i < mbufs; i++)
				rte_pktmbuf_free(tx_mbufs[i]);
		}

		if (odp_unlikely(tx_pkts == 0)) {
			if (__odp_errno != 0)
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
			    (struct ether_addr *)mac_addr);
	return ETH_ALEN;
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
	*capa = pktio_entry->s.capa;
	return 0;
}

static int dpdk_link_status(pktio_entry_t *pktio_entry)
{
	struct rte_eth_link link;

	memset(&link, 0, sizeof(struct rte_eth_link));

	rte_eth_link_get_nowait(pkt_priv(pktio_entry)->port_id, &link);

	return link.link_status;
}

static void stats_convert(const struct rte_eth_stats *rte_stats,
			  odp_pktio_stats_t *stats)
{
	memset(stats, 0, sizeof(odp_pktio_stats_t));

	stats->in_octets = rte_stats->ibytes;
	stats->in_discards = rte_stats->imissed;
	stats->in_errors = rte_stats->ierrors;
	stats->out_octets = rte_stats->obytes;
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
	rte_eth_stats_reset(pkt_priv(pktio_entry)->port_id);
	return 0;
}

const pktio_if_ops_t dpdk_pktio_ops = {
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
	.recv = dpdk_recv,
	.send = dpdk_send,
	.link_status = dpdk_link_status,
	.mtu_get = dpdk_frame_maxlen,
	.promisc_mode_set = dpdk_promisc_mode_set,
	.promisc_mode_get = dpdk_promisc_mode_get,
	.mac_get = dpdk_mac_addr_get,
	.mac_set = NULL,
	.capability = dpdk_capability,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL,
	.input_queues_config = dpdk_input_queues_config,
	.output_queues_config = dpdk_output_queues_config
};

#else

#include <stdint.h>

#include <odp/api/hints.h>

#include <odp_packet_dpdk.h>
#include <odp_pool_internal.h>

/*
 * Dummy functions for pool_create()
 */

uint32_t _odp_dpdk_pool_obj_size(pool_t *pool ODP_UNUSED, uint32_t block_size)
{
	return block_size;
}

int _odp_dpdk_pool_create(pool_t *pool ODP_UNUSED)
{
	return 0;
}

#endif /* _ODP_PKTIO_DPDK */

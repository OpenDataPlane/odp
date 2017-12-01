/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#ifdef ODP_PKTIO_DPDK

#include <odp_posix_extensions.h>

#include <sched.h>
#include <ctype.h>
#include <unistd.h>
#include <math.h>

#include <odp/api/cpumask.h>

#include <odp/api/plat/packet_inlines.h>
#include <odp/api/packet.h>

#include <odp_packet_io_internal.h>
#include <odp_classification_internal.h>
#include <odp_packet_dpdk.h>
#include <odp_debug_internal.h>

#include <protocols/eth.h>

#include <rte_config.h>
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

#if RTE_VERSION < RTE_VERSION_NUM(17, 5, 0, 0)
#define rte_log_set_global_level rte_set_log_level
#endif

#if ODP_DPDK_ZERO_COPY
ODP_STATIC_ASSERT(CONFIG_PACKET_HEADROOM == RTE_PKTMBUF_HEADROOM,
		  "ODP and DPDK headroom sizes not matching!");
ODP_STATIC_ASSERT(PKT_EXTRA_LEN >= sizeof(struct rte_mbuf),
		  "DPDK rte_mbuf won't fit in odp_packet_hdr_t.extra!");
#endif

/* DPDK poll mode drivers requiring minimum RX burst size DPDK_MIN_RX_BURST */
#define IXGBE_DRV_NAME "net_ixgbe"
#define I40E_DRV_NAME "net_i40e"

static int disable_pktio; /** !0 this pktio disabled, 0 enabled */

/* Has dpdk_pktio_init() been called */
static odp_bool_t dpdk_initialized;

#ifndef RTE_BUILD_SHARED_LIB
#define MEMPOOL_OPS(hdl) \
extern void mp_hdlr_init_##hdl(void)

MEMPOOL_OPS(ops_mp_mc);
MEMPOOL_OPS(ops_sp_sc);
MEMPOOL_OPS(ops_mp_sc);
MEMPOOL_OPS(ops_sp_mc);
MEMPOOL_OPS(ops_stack);

/*
 * This function is not called from anywhere, it's only purpose is to make sure
 * that if ODP and DPDK are statically linked to an application, the GCC
 * constructors of mempool handlers are linked as well. Otherwise the linker
 * would omit them. It's not an issue with dynamic linking. */
void refer_constructors(void);
void refer_constructors(void)
{
	mp_hdlr_init_ops_mp_mc();
	mp_hdlr_init_ops_sp_sc();
	mp_hdlr_init_ops_mp_sc();
	mp_hdlr_init_ops_sp_mc();
	mp_hdlr_init_ops_stack();
}
#endif

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
	return (uint64_t)pkt_hdr->buf_hdr.seg[0].data -
			(uint64_t)mbuf->buf_addr;
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

	if (odp_unlikely(pkt_hdr->buf_hdr.base_data !=
			 pkt_hdr->buf_hdr.seg[0].data))
		mbuf->data_off = mbuf_data_off(mbuf, pkt_hdr);
}

/**
 * Initialize mbuf
 *
 * Called once per ODP packet.
 */
static void mbuf_init(struct rte_mempool *mp, struct rte_mbuf *mbuf,
		      odp_packet_hdr_t *pkt_hdr)
{
	void *buf_addr = pkt_hdr->buf_hdr.base_data - RTE_PKTMBUF_HEADROOM;

	memset(mbuf, 0, sizeof(struct rte_mbuf));

	mbuf->priv_size = 0;
	mbuf->buf_addr = buf_addr;
	mbuf->buf_physaddr = rte_mem_virt2phy(buf_addr);
	if (odp_unlikely(mbuf->buf_physaddr == RTE_BAD_PHYS_ADDR ||
			 mbuf->buf_physaddr == 0))
		ODP_ABORT("Failed to map virt addr to phy");

	mbuf->buf_len = (uint16_t)rte_pktmbuf_data_room_size(mp);
	mbuf->data_off = RTE_PKTMBUF_HEADROOM;
	mbuf->pool = mp;
	mbuf->refcnt = 1;
	mbuf->nb_segs = 1;
	mbuf->port = 0xff;

	/* Store ODP packet handle inside rte_mbuf */
	mbuf->userdata = packet_handle(pkt_hdr);
	pkt_hdr->extra_type = PKT_EXTRA_TYPE_DPDK;
}

/**
 *  Create custom DPDK packet pool
 */
static struct rte_mempool *mbuf_pool_create(const char *name,
					    pool_t *pool_entry)
{
	struct rte_mempool *mp;
	struct rte_pktmbuf_pool_private mbp_priv;
	unsigned elt_size;
	unsigned num;
	uint16_t data_room_size;

	if (!(pool_entry->mem_from_huge_pages)) {
		ODP_ERR("DPDK requires memory is allocated from huge pages\n");
		return NULL;
	}

	num = pool_entry->num;
	data_room_size = pool_entry->seg_len + CONFIG_PACKET_HEADROOM;
	elt_size = sizeof(struct rte_mbuf) + (unsigned)data_room_size;
	mbp_priv.mbuf_data_room_size = data_room_size;
	mbp_priv.mbuf_priv_size = 0;

	mp = rte_mempool_create_empty(name, num, elt_size, cache_size(num),
				      sizeof(struct rte_pktmbuf_pool_private),
				      rte_socket_id(), 0);
	if (mp == NULL) {
		ODP_ERR("Failed to create empty DPDK packet pool\n");
		return NULL;
	}

	if (rte_mempool_set_ops_byname(mp, "odp_pool", pool_entry)) {
		ODP_ERR("Failed setting mempool operations\n");
		return NULL;
	}

	rte_pktmbuf_pool_init(mp, &mbp_priv);

	if (rte_mempool_ops_alloc(mp)) {
		ODP_ERR("Failed allocating mempool\n");
		return NULL;
	}

	return mp;
}

/* DPDK external memory pool operations */

static int pool_enqueue(struct rte_mempool *mp ODP_UNUSED,
			void * const *obj_table, unsigned num)
{
	odp_packet_t pkt_tbl[num];
	unsigned i;

	if (odp_unlikely(num == 0))
		return 0;

	for (i = 0; i < num; i++)
		pkt_tbl[i] = (odp_packet_t)((struct rte_mbuf *)
				obj_table[i])->userdata;

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
		odp_packet_t pkt = packet_tbl[i];
		odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
		struct rte_mbuf *mbuf = (struct rte_mbuf *)
					(uintptr_t)pkt_hdr->extra;
		if (pkt_hdr->extra_type != PKT_EXTRA_TYPE_DPDK)
			mbuf_init(mp, mbuf, pkt_hdr);
		obj_table[i] = mbuf;
	}

	return 0;
}

static int pool_alloc(struct rte_mempool *mp)
{
	pool_t *pool_entry = (pool_t *)mp->pool_config;

	mp->pool_data = pool_entry->pool_hdl;
	mp->flags |= MEMPOOL_F_POOL_CREATED;

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

	if (mp != NULL)
		rte_mempool_free(mp);
}

static struct rte_mempool *pool_create(pool_t *pool)
{
	struct rte_mempool *pkt_pool;
	char pool_name[RTE_MEMPOOL_NAMESIZE];

	odp_ticketlock_lock(&pool->lock);

	if (pool->ext_desc != NULL) {
		odp_ticketlock_unlock(&pool->lock);
		return (struct rte_mempool *)pool->ext_desc;
	}

	snprintf(pool_name, sizeof(pool_name),
		 "dpdk_pktpool_%" PRIu32 "", pool->pool_idx);
	pkt_pool = mbuf_pool_create(pool_name, pool);

	if (pkt_pool == NULL) {
		odp_ticketlock_unlock(&pool->lock);
		ODP_ERR("Creating external DPDK pool failed\n");
		return NULL;
	}

	pool->ext_desc = pkt_pool;
	pool->ext_destroy = pool_destroy;

	odp_ticketlock_unlock(&pool->lock);

	return pkt_pool;
}

static struct rte_mempool_ops ops_stack = {
	.name = "odp_pool",
	.alloc = pool_alloc,
	.free = pool_free,
	.enqueue = pool_enqueue,
	.dequeue = pool_dequeue_bulk,
	.get_count = pool_get_count
};

MEMPOOL_REGISTER_OPS(ops_stack);

#define HAS_IP4_CSUM_FLAG(m, f) ((m->ol_flags & PKT_RX_IP_CKSUM_MASK) == f)
#define HAS_L4_PROTO(m, proto) ((m->packet_type & RTE_PTYPE_L4_MASK) == proto)
#define HAS_L4_CSUM_FLAG(m, f) ((m->ol_flags & PKT_RX_L4_CKSUM_MASK) == f)

#define PKTIN_CSUM_BITS 0x1C

static inline int pkt_set_ol_rx(odp_pktin_config_opt_t *pktin_cfg,
				odp_packet_hdr_t *pkt_hdr,
				struct rte_mbuf *mbuf)
{
	if (pktin_cfg->bit.ipv4_chksum &&
	    RTE_ETH_IS_IPV4_HDR(mbuf->packet_type) &&
	    HAS_IP4_CSUM_FLAG(mbuf, PKT_RX_IP_CKSUM_BAD)) {
		if (pktin_cfg->bit.drop_ipv4_err)
			return -1;

		pkt_hdr->p.error_flags.ip_err = 1;
	}

	if (pktin_cfg->bit.udp_chksum &&
	    HAS_L4_PROTO(mbuf, RTE_PTYPE_L4_UDP) &&
	    HAS_L4_CSUM_FLAG(mbuf, PKT_RX_L4_CKSUM_BAD)) {
		if (pktin_cfg->bit.drop_udp_err)
			return -1;

		pkt_hdr->p.error_flags.udp_err = 1;
	} else if (pktin_cfg->bit.tcp_chksum &&
		   HAS_L4_PROTO(mbuf, RTE_PTYPE_L4_TCP)  &&
		   HAS_L4_CSUM_FLAG(mbuf, PKT_RX_L4_CKSUM_BAD)) {
		if (pktin_cfg->bit.drop_tcp_err)
			return -1;

		pkt_hdr->p.error_flags.tcp_err = 1;
	}

	return 0;
}

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
	int nb_pkts = 0;
	int alloc_len, num;
	odp_pool_t pool = pktio_entry->s.pkt_dpdk.pool;
	odp_pktin_config_opt_t *pktin_cfg = &pktio_entry->s.config.pktin;

	/* Allocate maximum sized packets */
	alloc_len = pktio_entry->s.pkt_dpdk.data_room;

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
			if (cls_classify_packet(pktio_entry,
						(const uint8_t *)data,
						pkt_len, pkt_len, &pool,
						&parsed_hdr))
				goto fail;
		}

		pkt     = pkt_table[i];
		pkt_hdr = odp_packet_hdr(pkt);
		pull_tail(pkt_hdr, alloc_len - pkt_len);

		if (odp_packet_copy_from_mem(pkt, 0, pkt_len, data) != 0)
			goto fail;

		pkt_hdr->input = pktio_entry->s.handle;

		if (pktio_cls_enabled(pktio_entry))
			copy_packet_cls_metadata(&parsed_hdr, pkt_hdr);
		else if (pktio_entry->s.config.parser.layer)
			packet_parse_layer(pkt_hdr,
					   pktio_entry->s.config.parser.layer);

		if (mbuf->ol_flags & PKT_RX_RSS_HASH)
			odp_packet_flow_hash_set(pkt, mbuf->hash.rss);

		packet_set_ts(pkt_hdr, ts);

		if (pktin_cfg->all_bits & PKTIN_CSUM_BITS) {
			if (pkt_set_ol_rx(pktin_cfg, pkt_hdr, mbuf)) {
				odp_packet_free(pkt);
				rte_pktmbuf_free(mbuf);
				continue;
			}
		}

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

static inline void pkt_set_ol_tx(odp_pktout_config_opt_t *pktout_cfg,
				 odp_packet_hdr_t *pkt_hdr,
				 struct rte_mbuf *mbuf,
				 char *mbuf_data)
{
	void *l3_hdr, *l4_hdr;
	uint8_t l4_proto;
	odp_bool_t l3_proto_v4;
	odp_bool_t ipv4_chksum_pkt, udp_chksum_pkt, tcp_chksum_pkt;
	packet_parser_t *pkt_p = &pkt_hdr->p;

	l3_hdr = (void *)(mbuf_data + pkt_p->l3_offset);

	if (check_proto(l3_hdr, &l3_proto_v4, &l4_proto))
		return;

	ipv4_chksum_pkt = pktout_cfg->bit.ipv4_chksum && l3_proto_v4;
	udp_chksum_pkt =  pktout_cfg->bit.udp_chksum &&
		(l4_proto == _ODP_IPPROTO_UDP);
	tcp_chksum_pkt = pktout_cfg->bit.tcp_chksum &&
			(l4_proto == _ODP_IPPROTO_TCP);

	if (!ipv4_chksum_pkt && !udp_chksum_pkt && !tcp_chksum_pkt)
			return;

	mbuf->l2_len = pkt_p->l3_offset - pkt_p->l2_offset;
	mbuf->l3_len = pkt_p->l4_offset - pkt_p->l3_offset;

	if (l3_proto_v4)
		mbuf->ol_flags = PKT_TX_IPV4;
	else
		mbuf->ol_flags = PKT_TX_IPV6;

	if (ipv4_chksum_pkt) {
		mbuf->ol_flags |=  PKT_TX_IP_CKSUM;

		((struct ipv4_hdr *)l3_hdr)->hdr_checksum = 0;
	}

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
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
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
		pkt_len = _odp_packet_len(pkt_table[i]);

		if (pkt_len > pkt_dpdk->mtu) {
			if (i == 0)
				__odp_errno = EMSGSIZE;
			goto fail;
		}

		/* Packet always fits in mbuf */
		data = rte_pktmbuf_append(mbuf_table[i], pkt_len);

		odp_packet_copy_to_mem(pkt_table[i], 0, pkt_len, data);

		if (pktout_cfg->all_bits)
			pkt_set_ol_tx(pktout_cfg,
				      odp_packet_hdr(pkt_table[i]),
				      mbuf_table[i], data);
	}
	return i;

fail:
	for (j = i; j < num; j++)
		rte_pktmbuf_free(mbuf_table[j]);

	return i;
}

static inline int mbuf_to_pkt_zero(pktio_entry_t *pktio_entry,
				   odp_packet_t pkt_table[],
				   struct rte_mbuf *mbuf_table[],
				   uint16_t mbuf_num, odp_time_t *ts)
{
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;
	uint16_t pkt_len;
	struct rte_mbuf *mbuf;
	void *data;
	int i;
	int nb_pkts = 0;
	odp_pool_t pool = pktio_entry->s.pkt_dpdk.pool;
	odp_pktin_config_opt_t *pktin_cfg = &pktio_entry->s.config.pktin;

	for (i = 0; i < mbuf_num; i++) {
		odp_packet_hdr_t parsed_hdr;

		mbuf = mbuf_table[i];
		if (odp_unlikely(mbuf->nb_segs != 1)) {
			ODP_ERR("Segmented buffers not supported\n");
			rte_pktmbuf_free(mbuf);
			continue;
		}

		data = rte_pktmbuf_mtod(mbuf, char *);
		pkt_len = rte_pktmbuf_pkt_len(mbuf);

		pkt = (odp_packet_t)mbuf->userdata;
		pkt_hdr = odp_packet_hdr(pkt);

		if (pktio_cls_enabled(pktio_entry)) {
			if (cls_classify_packet(pktio_entry,
						(const uint8_t *)data,
						pkt_len, pkt_len, &pool,
						&parsed_hdr))
				ODP_ERR("Unable to classify packet\n");
				rte_pktmbuf_free(mbuf);
				continue;
		}

		/* Init buffer segments. Currently, only single segment packets
		 * are supported. */
		pkt_hdr->buf_hdr.seg[0].data = data;

		packet_init(pkt_hdr, pkt_len);
		pkt_hdr->input = pktio_entry->s.handle;

		if (pktio_cls_enabled(pktio_entry))
			copy_packet_cls_metadata(&parsed_hdr, pkt_hdr);
		else if (pktio_entry->s.config.parser.layer)
			packet_parse_layer(pkt_hdr,
					   pktio_entry->s.config.parser.layer);

		if (mbuf->ol_flags & PKT_RX_RSS_HASH)
			odp_packet_flow_hash_set(pkt, mbuf->hash.rss);

		packet_set_ts(pkt_hdr, ts);

		if (pktin_cfg->all_bits & PKTIN_CSUM_BITS) {
			if (pkt_set_ol_rx(pktin_cfg, pkt_hdr, mbuf)) {
				rte_pktmbuf_free(mbuf);
				continue;
			}
		}

		pkt_table[nb_pkts++] = pkt;
	}

	return nb_pkts;
}

static inline int pkt_to_mbuf_zero(pktio_entry_t *pktio_entry,
				   struct rte_mbuf *mbuf_table[],
				   const odp_packet_t pkt_table[], uint16_t num,
				   uint16_t *copy_count)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	odp_pktout_config_opt_t *pktout_cfg = &pktio_entry->s.config.pktout;
	int i;
	*copy_count = 0;

	for (i = 0; i < num; i++) {
		odp_packet_t pkt = pkt_table[i];
		odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
		struct rte_mbuf *mbuf = (struct rte_mbuf *)
					(uintptr_t)pkt_hdr->extra;
		uint16_t pkt_len = odp_packet_len(pkt);

		if (odp_unlikely(pkt_len > pkt_dpdk->mtu))
			goto fail;

		if (odp_likely(pkt_hdr->buf_hdr.segcount == 1 &&
			       pkt_hdr->extra_type == PKT_EXTRA_TYPE_DPDK)) {
			mbuf_update(mbuf, pkt_hdr, pkt_len);

			if (pktout_cfg->all_bits)
				pkt_set_ol_tx(pktout_cfg, pkt_hdr,
					      mbuf, odp_packet_data(pkt));
		} else {
			pool_t *pool_entry = pkt_hdr->buf_hdr.pool_ptr;

			if (odp_unlikely(pool_entry->ext_desc == NULL)) {
				if (pool_create(pool_entry) == NULL)
					ODP_ABORT("Creating DPDK pool failed");
			}

			if (pkt_hdr->buf_hdr.segcount != 1 ||
			    !pool_entry->mem_from_huge_pages) {
				/* Fall back to packet copy */
				if (odp_unlikely(pkt_to_mbuf(pktio_entry, &mbuf,
							     &pkt, 1) != 1))
					goto fail;
				(*copy_count)++;

			} else {
				mbuf_init((struct rte_mempool *)
					  pool_entry->ext_desc, mbuf, pkt_hdr);
				mbuf_update(mbuf, pkt_hdr, pkt_len);
				if (pktout_cfg->all_bits)
					pkt_set_ol_tx(pktout_cfg, pkt_hdr,
						      mbuf,
						      odp_packet_data(pkt));
			}
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

static uint32_t dpdk_vdev_mtu_get(uint8_t port_id)
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
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
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

static int dpdk_vdev_promisc_mode_get(uint8_t port_id)
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

static int dpdk_vdev_promisc_mode_set(uint8_t port_id, int enable)
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
	memset(rss_conf, 0, sizeof(struct rte_eth_rss_conf));

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

static int dpdk_setup_port(pktio_entry_t *pktio_entry)
{
	int ret;
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	struct rte_eth_rss_conf rss_conf;
	uint16_t hw_ip_checksum = 0;

	/* Always set some hash functions to enable DPDK RSS hash calculation */
	if (pkt_dpdk->hash.all_bits == 0) {
		memset(&rss_conf, 0, sizeof(struct rte_eth_rss_conf));
		rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP;
	} else {
		rss_conf_to_hash_proto(&rss_conf, &pkt_dpdk->hash);
	}

	if (pktio_entry->s.config.pktin.bit.ipv4_chksum ||
	    pktio_entry->s.config.pktin.bit.udp_chksum ||
	    pktio_entry->s.config.pktin.bit.tcp_chksum)
		hw_ip_checksum = 1;

	struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = ETH_MQ_RX_RSS,
			.split_hdr_size = 0,
			.header_split   = 0,
			.hw_ip_checksum = hw_ip_checksum,
			.hw_vlan_filter = 0,
			.hw_strip_crc   = 0,
			.enable_scatter = 0,
		},
		.rx_adv_conf = {
			.rss_conf = rss_conf,
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		},
	};

	ret = rte_eth_dev_configure(pkt_dpdk->port_id,
				    pktio_entry->s.num_in_queue,
				    pktio_entry->s.num_out_queue, &port_conf);
	if (ret < 0) {
		ODP_ERR("Failed to setup device: err=%d, port=%" PRIu8 "\n",
			ret, pkt_dpdk->port_id);
		return -1;
	}
	return 0;
}

static int dpdk_close(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
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

	mem_str_len = snprintf(NULL, 0, "%d", DPDK_MEMORY_MB);

	cmdline = getenv("ODP_PKTIO_DPDK_PARAMS");
	if (cmdline == NULL)
		cmdline = "";

	/* masklen includes the terminating null as well */
	cmd_len = strlen("odpdpdk -c -m ") + masklen + mem_str_len +
			strlen(cmdline) + strlen("  ");

	char full_cmd[cmd_len];

	/* first argument is facility log, simply bind it to odpdpdk for now.*/
	cmd_len = snprintf(full_cmd, cmd_len, "odpdpdk -c %s -m %d %s",
			   mask_str, DPDK_MEMORY_MB, cmdline);

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

static int dpdk_pktio_term(void)
{
	if (!dpdk_initialized)
		return 0;

#if RTE_VERSION >= RTE_VERSION_NUM(17, 8, 0, 0)
	uint8_t port_id;

	RTE_ETH_FOREACH_DEV(port_id) {
		rte_eth_dev_close(port_id);
	}
#endif

	if (!ODP_DPDK_ZERO_COPY)
		rte_mempool_walk(dpdk_mempool_free, NULL);

	return 0;
}

static int dpdk_input_queues_config(pktio_entry_t *pktio_entry,
				    const odp_pktin_queue_param_t *p)
{
	odp_pktin_mode_t mode = pktio_entry->s.param.in_mode;
	uint8_t lockless;

	/**
	 * Scheduler synchronizes input queue polls. Only single thread
	 * at a time polls a queue */
	if (mode == ODP_PKTIN_MODE_SCHED ||
	    p->op_mode == ODP_PKTIO_OP_MT_UNSAFE)
		lockless = 1;
	else
		lockless = 0;

	if (p->hash_enable && p->num_queues > 1)
		pktio_entry->s.pkt_dpdk.hash = p->hash_proto;

	pktio_entry->s.pkt_dpdk.lockless_rx = lockless;

	return 0;
}

static int dpdk_output_queues_config(pktio_entry_t *pktio_entry,
				     const odp_pktout_queue_param_t *p)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
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
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
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
}

static int dpdk_open(odp_pktio_t id ODP_UNUSED,
		     pktio_entry_t *pktio_entry,
		     const char *netdev,
		     odp_pool_t pool)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
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
	if (dpdk_initialized == 0) {
		dpdk_pktio_init();
		dpdk_initialized = 1;
	}

	/* Init pktio entry */
	memset(pkt_dpdk, 0, sizeof(*pkt_dpdk));

	pkt_dpdk->pool = pool;
	pkt_dpdk->port_id = atoi(netdev);

	if (rte_eth_dev_count() == 0) {
		ODP_ERR("No DPDK ports found\n");
		return -1;
	}

	dpdk_init_capability(pktio_entry, &dev_info);

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

	if (ODP_DPDK_ZERO_COPY) {
		if (pool_entry->ext_desc != NULL)
			pkt_pool = (struct rte_mempool *)pool_entry->ext_desc;
		else
			pkt_pool = pool_create(pool_entry);
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

static int dpdk_start(pktio_entry_t *pktio_entry)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	uint8_t port_id = pkt_dpdk->port_id;
	int ret;
	unsigned i;

	/* DPDK doesn't support nb_rx_q/nb_tx_q being 0 */
	if (!pktio_entry->s.num_in_queue)
		pktio_entry->s.num_in_queue = 1;
	if (!pktio_entry->s.num_out_queue)
		pktio_entry->s.num_out_queue = 1;

	/* init port */
	if (dpdk_setup_port(pktio_entry)) {
		ODP_ERR("Failed to configure device\n");
		return -1;
	}
	/* Init TX queues */
	for (i = 0; i < pktio_entry->s.num_out_queue; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, DPDK_NM_TX_DESC,
					     rte_eth_dev_socket_id(port_id),
					     NULL);
		if (ret < 0) {
			ODP_ERR("Queue setup failed: err=%d, port=%" PRIu8 "\n",
				ret, port_id);
			return -1;
		}
	}
	/* Init RX queues */
	for (i = 0; i < pktio_entry->s.num_in_queue; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, DPDK_NM_RX_DESC,
					     rte_eth_dev_socket_id(port_id),
					     NULL, pkt_dpdk->pkt_pool);
		if (ret < 0) {
			ODP_ERR("Queue setup failed: err=%d, port=%" PRIu8 "\n",
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
	rte_eth_dev_stop(pktio_entry->s.pkt_dpdk.port_id);

	return 0;
}

static int dpdk_recv(pktio_entry_t *pktio_entry, int index,
		     odp_packet_t pkt_table[], int num)
{
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
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

		nb_rx = rte_eth_rx_burst(pktio_entry->s.pkt_dpdk.port_id, index,
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
		nb_rx = rte_eth_rx_burst(pktio_entry->s.pkt_dpdk.port_id, index,
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
		if (ODP_DPDK_ZERO_COPY)
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
	pkt_dpdk_t *pkt_dpdk = &pktio_entry->s.pkt_dpdk;
	uint16_t copy_count = 0;
	int tx_pkts;
	int i;
	int mbufs;

	if (odp_unlikely(pktio_entry->s.state != PKTIO_STATE_STARTED))
		return 0;

	if (ODP_DPDK_ZERO_COPY)
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

	if (ODP_DPDK_ZERO_COPY) {
		/* Free copied packets */
		if (odp_unlikely(copy_count)) {
			uint16_t freed = 0;

			for (i = 0; i < mbufs && freed != copy_count; i++) {
				odp_packet_t pkt = pkt_table[i];
				odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

				if (pkt_hdr->buf_hdr.segcount > 1) {
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
	rte_eth_macaddr_get(pktio_entry->s.pkt_dpdk.port_id,
			    (struct ether_addr *)mac_addr);
	return ETH_ALEN;
}

static int dpdk_promisc_mode_set(pktio_entry_t *pktio_entry, odp_bool_t enable)
{
	uint8_t port_id = pktio_entry->s.pkt_dpdk.port_id;

	if (pktio_entry->s.pkt_dpdk.vdev_sysc_promisc)
		return dpdk_vdev_promisc_mode_set(port_id, enable);

	if (enable)
		rte_eth_promiscuous_enable(port_id);
	else
		rte_eth_promiscuous_disable(port_id);

	return 0;
}

static int dpdk_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	uint8_t port_id = pktio_entry->s.pkt_dpdk.port_id;

	if (pktio_entry->s.pkt_dpdk.vdev_sysc_promisc)
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

	rte_eth_link_get_nowait(pktio_entry->s.pkt_dpdk.port_id, &link);

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

	ret = rte_eth_stats_get(pktio_entry->s.pkt_dpdk.port_id, &rte_stats);

	if (ret == 0) {
		stats_convert(&rte_stats, stats);
		return 0;
	}
	return -1;
}

static int dpdk_stats_reset(pktio_entry_t *pktio_entry)
{
	rte_eth_stats_reset(pktio_entry->s.pkt_dpdk.port_id);
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
	.mtu_get = dpdk_mtu_get,
	.promisc_mode_set = dpdk_promisc_mode_set,
	.promisc_mode_get = dpdk_promisc_mode_get,
	.mac_get = dpdk_mac_addr_get,
	.capability = dpdk_capability,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL,
	.input_queues_config = dpdk_input_queues_config,
	.output_queues_config = dpdk_output_queues_config
};

#endif /* ODP_PKTIO_DPDK */

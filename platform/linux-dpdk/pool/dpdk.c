/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/std_types.h>
#include <odp/api/pool.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_packet_internal.h>
#include <odp_timer_internal.h>
#include <odp_align_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/align.h>
#include <odp_internal.h>
#include <odp_config_internal.h>
#include <odp/api/hints.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp/api/cpumask.h>

#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <inttypes.h>

/* for DPDK */
#include <odp_packet_dpdk.h>

#ifdef POOL_USE_TICKETLOCK
#include <odp/api/ticketlock.h>
#define LOCK(a)      odp_ticketlock_lock(a)
#define UNLOCK(a)    odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)
#else
#include <odp/api/spinlock.h>
#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a) odp_spinlock_init(a)
#endif

/* Define a practical limit for contiguous memory allocations */
#define MAX_SIZE   (10 * 1024 * 1024)

/* The pool table ptr - resides in shared memory */
pool_table_cp_t *pool_tbl_cp;
pool_table_dp_t *pool_tbl_dp;

static int dpdk_pool_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	shm = odp_shm_reserve("odp_pools_cp",
			      sizeof(pool_table_cp_t),
			      sizeof(pool_entry_cp_t), 0);
	if (shm == ODP_SHM_INVALID)
		return -1;

	pool_tbl_cp = odp_shm_addr(shm);
	if (pool_tbl_cp == NULL)
		return -1;

	memset(pool_tbl_cp, 0, sizeof(pool_table_cp_t));
	pool_tbl_cp->shm_cp = shm;

	shm = odp_shm_reserve("odp_pools_dp",
			      sizeof(pool_table_dp_t),
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID)
		return -1;

	pool_tbl_dp = odp_shm_addr(shm);
	if (pool_tbl_dp == NULL)
		goto dp_tbl_alloc_failed;

	memset(pool_tbl_dp, 0, sizeof(pool_table_dp_t));
	pool_tbl_cp->shm_dp = shm;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		/* init locks */
		pool_entry_cp_t *pool_cp = &pool_tbl_cp->pool[i];

		LOCK_INIT(&pool_cp->lock);
		pool_cp->pool_hdl = pool_index_to_handle(i);
	}

	ODP_DBG("\nPool init global\n");
	ODP_DBG("  pool_entry_cp_t size     %zu\n", sizeof(pool_entry_cp_t));
	ODP_DBG("  pool_entry_dp_t size     %zu\n", sizeof(pool_entry_dp_t));
	ODP_DBG("  pool_table_cp_t size     %zu\n", sizeof(pool_table_cp_t));
	ODP_DBG("  pool_table_dp_t size     %zu\n", sizeof(pool_table_dp_t));
	ODP_DBG("  odp_buffer_hdr_t size %zu\n", sizeof(odp_buffer_hdr_t));
	ODP_DBG("\n");

	return 0;

dp_tbl_alloc_failed:
	odp_shm_free(pool_tbl_cp->shm_cp);
	return -1;
}

static int dpdk_pool_init_local(void)
{
	return 0;
}

static int dpdk_pool_term_global(void)
{
	int ret;

	ret = odp_shm_free(pool_tbl_cp->shm_dp);
	if (ret < 0)
		ODP_ERR("Pool DP shm free failed\n");

	ret = odp_shm_free(pool_tbl_cp->shm_cp);
	if (ret < 0)
		ODP_ERR("Pool CP shm free failed\n");

	return ret;
}

static int dpdk_pool_term_local(void)
{
	return 0;
}

static int dpdk_pool_capability(odp_pool_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pool_capability_t));

	capa->max_pools = ODP_CONFIG_POOLS;

	/* Buffer pools */
	capa->buf.max_pools = ODP_CONFIG_POOLS;
	capa->buf.max_align = ODP_CONFIG_BUFFER_ALIGN_MAX;
	capa->buf.max_size  = MAX_SIZE;
	capa->buf.max_num   = CONFIG_POOL_MAX_NUM;

	/* Packet pools */
	capa->pkt.max_pools        = ODP_CONFIG_POOLS;
	capa->pkt.max_len          = 0;
	capa->pkt.max_num	   = CONFIG_POOL_MAX_NUM;
	capa->pkt.min_headroom     = CONFIG_PACKET_HEADROOM;
	capa->pkt.min_tailroom     = CONFIG_PACKET_TAILROOM;
	capa->pkt.max_segs_per_pkt = CONFIG_PACKET_MAX_SEGS;
	capa->pkt.min_seg_len      = CONFIG_PACKET_SEG_LEN_MIN;
	capa->pkt.max_seg_len      = CONFIG_PACKET_SEG_LEN_MAX;
	capa->pkt.max_uarea_size   = MAX_SIZE;

	/* Timeout pools */
	capa->tmo.max_pools = ODP_CONFIG_POOLS;
	capa->tmo.max_num   = CONFIG_POOL_MAX_NUM;

	return 0;
}

struct mbuf_ctor_arg {
	uint16_t seg_buf_offset; /* To skip the ODP buf/pkt/tmo header */
	uint16_t seg_buf_size;   /* size of user data */
	int type;
	int pkt_uarea_size;      /* size of user area in bytes */
};

struct mbuf_pool_ctor_arg {
	/* This has to be the first member */
	struct rte_pktmbuf_pool_private pkt;
	odp_pool_t	pool_hdl;
};

static void
odp_dpdk_mbuf_pool_ctor(struct rte_mempool *mp,
			void *opaque_arg)
{
	struct mbuf_pool_ctor_arg *mbp_priv;

	if (mp->private_data_size < sizeof(struct mbuf_pool_ctor_arg)) {
		ODP_ERR("(%s) private_data_size %d < %d",
			mp->name, (int)mp->private_data_size,
			(int)sizeof(struct mbuf_pool_ctor_arg));
		return;
	}
	mbp_priv = rte_mempool_get_priv(mp);
	*mbp_priv = *((struct mbuf_pool_ctor_arg *)opaque_arg);
}

/* ODP DPDK mbuf constructor.
 * This is a combination of rte_pktmbuf_init in rte_mbuf.c
 * and testpmd_mbuf_ctor in testpmd.c
 */
static void
odp_dpdk_mbuf_ctor(struct rte_mempool *mp,
		   void *opaque_arg,
		   void *raw_mbuf,
		   unsigned i)
{
	struct mbuf_ctor_arg *mb_ctor_arg;
	struct rte_mbuf *mb = raw_mbuf;
	struct odp_buffer_hdr_t *buf_hdr;
	struct mbuf_pool_ctor_arg *mbp_ctor_arg = rte_mempool_get_priv(mp);

	/* The rte_mbuf is at the begninning in all cases */
	mb_ctor_arg = (struct mbuf_ctor_arg *)opaque_arg;
	mb = (struct rte_mbuf *)raw_mbuf;

	RTE_ASSERT(mp->elt_size >= sizeof(struct rte_mbuf));

	memset(mb, 0, mp->elt_size);

	/* Start of buffer is just after the ODP type specific header
	 * which contains in the very beginning the rte_mbuf struct */
	mb->buf_addr     = (char *)mb + mb_ctor_arg->seg_buf_offset;
	mb->buf_physaddr = rte_mempool_virt2phy(mp, mb) +
			mb_ctor_arg->seg_buf_offset;
	mb->buf_len      = mb_ctor_arg->seg_buf_size;
	mb->priv_size = rte_pktmbuf_priv_size(mp);

	/* keep some headroom between start of buffer and data */
	if (mb_ctor_arg->type == ODP_POOL_PACKET) {
		odp_packet_hdr_t *pkt_hdr;

		mb->data_off = RTE_PKTMBUF_HEADROOM;
		mb->nb_segs = 1;
		mb->port = 0xff;
		mb->vlan_tci = 0;
		pkt_hdr = (odp_packet_hdr_t *)raw_mbuf;
		pkt_hdr->uarea_size = mb_ctor_arg->pkt_uarea_size;
	} else {
		mb->data_off = 0;
	}

	/* init some constant fields */
	mb->pool         = mp;
	mb->ol_flags     = 0;

	/* Save index, might be useful for debugging purposes */
	buf_hdr = (struct odp_buffer_hdr_t *)raw_mbuf;
	buf_hdr->index = i;
	buf_hdr->handle.handle = (odp_buffer_t)buf_hdr;
	buf_hdr->pool_hdl = mbp_ctor_arg->pool_hdl;
	buf_hdr->type = mb_ctor_arg->type;
	buf_hdr->event_type = mb_ctor_arg->type;
	buf_hdr->event_subtype = ODP_EVENT_NO_SUBTYPE;
}

#define CHECK_U16_OVERFLOW(X)	do {			\
	if (odp_unlikely(X > UINT16_MAX)) {		\
		ODP_ERR("Invalid size: %d", X);		\
		UNLOCK(&pool_cp->lock);			\
		return ODP_POOL_INVALID;		\
	}						\
} while (0)

static int check_params(odp_pool_param_t *params)
{
	odp_pool_capability_t capa;

	if (odp_pool_capability(&capa) < 0)
		return -1;

	switch (params->type) {
	case ODP_POOL_BUFFER:
		if (params->buf.num > capa.buf.max_num) {
			printf("buf.num too large %u\n", params->buf.num);
			return -1;
		}

		if (params->buf.size > capa.buf.max_size) {
			printf("buf.size too large %u\n", params->buf.size);
			return -1;
		}

		if (params->buf.align > capa.buf.max_align) {
			printf("buf.align too large %u\n", params->buf.align);
			return -1;
		}

		break;

	case ODP_POOL_PACKET:
		if (params->pkt.num > capa.pkt.max_num) {
			printf("pkt.num too large %u\n", params->pkt.num);

			return -1;
		}

		if (params->pkt.seg_len > capa.pkt.max_seg_len) {
			printf("pkt.seg_len too large %u\n",
			       params->pkt.seg_len);
			return -1;
		}

		if (params->pkt.uarea_size > capa.pkt.max_uarea_size) {
			printf("pkt.uarea_size too large %u\n",
			       params->pkt.uarea_size);
			return -1;
		}

		break;

	case ODP_POOL_TIMEOUT:
		if (params->tmo.num > capa.tmo.max_num) {
			printf("tmo.num too large %u\n", params->tmo.num);
			return -1;
		}
		break;

	default:
		printf("bad pool type %i\n", params->type);
		return -1;
	}

	return 0;
}

static odp_pool_t dpdk_pool_create(const char *name,
				   odp_pool_param_t *params)
{
	struct mbuf_pool_ctor_arg mbp_ctor_arg;
	struct mbuf_ctor_arg mb_ctor_arg;
	odp_pool_t pool_hdl = ODP_POOL_INVALID;
	unsigned mb_size, i, cache_size;
	size_t hdr_size;
	pool_entry_cp_t *pool_cp;
	pool_entry_dp_t *pool_dp;
	uint32_t buf_align, blk_size, headroom, tailroom, min_seg_len;
	uint32_t max_len, min_align;
	char pool_name[ODP_POOL_NAME_LEN];
	char *rte_name = NULL;
#if RTE_MEMPOOL_CACHE_MAX_SIZE > 0
	unsigned j;
#endif

	if (check_params(params))
		return ODP_POOL_INVALID;

	if (name == NULL) {
		pool_name[0] = 0;
	} else {
		strncpy(pool_name, name, ODP_POOL_NAME_LEN - 1);
		pool_name[ODP_POOL_NAME_LEN - 1] = 0;
	}

	/* Find an unused buffer pool slot and initialize it as requested */
	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		uint32_t num;
		struct rte_mempool *mp;

		pool_cp = get_pool_entry_cp(i);
		pool_dp = get_pool_entry_dp(i);

		LOCK(&pool_cp->lock);
		if (pool_dp->rte_mempool != NULL) {
			UNLOCK(&pool_cp->lock);
			continue;
		}

		switch (params->type) {
		case ODP_POOL_BUFFER:
			buf_align = params->buf.align;
			blk_size = params->buf.size;

			/* Validate requested buffer alignment */
			if (buf_align > ODP_CONFIG_BUFFER_ALIGN_MAX ||
			    buf_align !=
			    ROUNDDOWN_POWER2(buf_align, buf_align)) {
				UNLOCK(&pool_cp->lock);
				return ODP_POOL_INVALID;
			}

			/* Set correct alignment based on input request */
			if (buf_align == 0)
				buf_align = ODP_CACHE_LINE_SIZE;
			else if (buf_align < ODP_CONFIG_BUFFER_ALIGN_MIN)
				buf_align = ODP_CONFIG_BUFFER_ALIGN_MIN;

			if (params->buf.align != 0)
				blk_size = ROUNDUP_ALIGN(blk_size,
							 buf_align);

			hdr_size = sizeof(odp_buffer_hdr_t);
			CHECK_U16_OVERFLOW(blk_size);
			mbp_ctor_arg.pkt.mbuf_data_room_size = blk_size;
			num = params->buf.num;
			ODP_DBG("type: buffer name: %s num: "
				"%u size: %u align: %u\n", pool_name, num,
				params->buf.size, params->buf.align);
			break;
		case ODP_POOL_PACKET:
			headroom = CONFIG_PACKET_HEADROOM;
			tailroom = CONFIG_PACKET_TAILROOM;
			min_seg_len = CONFIG_PACKET_SEG_LEN_MIN;
			min_align = ODP_CONFIG_BUFFER_ALIGN_MIN;

			blk_size = min_seg_len;
			if (params->pkt.seg_len > blk_size)
				blk_size = params->pkt.seg_len;
			if (params->pkt.len > blk_size)
				blk_size = params->pkt.len;
			/* Make sure at least one max len packet fits in the
			 * pool.
			 */
			max_len = 0;
			if (params->pkt.max_len != 0)
				max_len = params->pkt.max_len;
			if ((max_len + blk_size) / blk_size > params->pkt.num)
				blk_size = (max_len + params->pkt.num) /
					params->pkt.num;
			blk_size = ROUNDUP_ALIGN(headroom + blk_size +
						 tailroom, min_align);
			/* Segment size minus headroom might be rounded down by
			 * the driver to the nearest multiple of 1024. Round it
			 * up here to make sure the requested size still going
			 * to fit there without segmentation.
			 */
			blk_size = ROUNDUP_ALIGN(blk_size - headroom,
						 min_seg_len) + headroom;

			hdr_size = sizeof(odp_packet_hdr_t) +
				   params->pkt.uarea_size;
			mb_ctor_arg.pkt_uarea_size = params->pkt.uarea_size;
			CHECK_U16_OVERFLOW(blk_size);
			mbp_ctor_arg.pkt.mbuf_data_room_size = blk_size;
			num = params->pkt.num;

			ODP_DBG("type: packet, name: %s, "
				"num: %u, len: %u, blk_size: %u, "
				"uarea_size %d, hdr_size %d\n",
				pool_name, num, params->pkt.len, blk_size,
				params->pkt.uarea_size, hdr_size);
			break;
		case ODP_POOL_TIMEOUT:
			hdr_size = sizeof(odp_timeout_hdr_t);
			mbp_ctor_arg.pkt.mbuf_data_room_size = 0;
			num = params->tmo.num;
			ODP_DBG("type: tmo name: %s num: %u\n",
				pool_name, num);
			break;
		default:
			ODP_ERR("Bad type %i\n",
				params->type);
			UNLOCK(&pool_cp->lock);
			return ODP_POOL_INVALID;
		}

		mb_ctor_arg.seg_buf_offset =
			(uint16_t)ROUNDUP_CACHE_LINE(hdr_size);
		mb_ctor_arg.seg_buf_size = mbp_ctor_arg.pkt.mbuf_data_room_size;
		mb_ctor_arg.type = params->type;
		mb_size = mb_ctor_arg.seg_buf_offset + mb_ctor_arg.seg_buf_size;
		mbp_ctor_arg.pool_hdl = pool_cp->pool_hdl;
		mbp_ctor_arg.pkt.mbuf_priv_size = mb_ctor_arg.seg_buf_offset -
			sizeof(struct rte_mbuf);

		ODP_DBG("Metadata size: %u, mb_size %d\n",
			mb_ctor_arg.seg_buf_offset, mb_size);
		cache_size = 0;
#if RTE_MEMPOOL_CACHE_MAX_SIZE > 0
		j = ceil((double)num / RTE_MEMPOOL_CACHE_MAX_SIZE);
		j = RTE_MAX(j, 2UL);
		for (; j <= (num / 2); ++j)
			if ((num % j) == 0) {
				cache_size = num / j;
				break;
			}
		if (odp_unlikely(cache_size > RTE_MEMPOOL_CACHE_MAX_SIZE ||
				 (uint32_t)cache_size * 1.5 > num)) {
			ODP_ERR("cache_size calc failure: %d\n", cache_size);
			cache_size = 0;
		}
#endif
		ODP_DBG("cache_size %d\n", cache_size);

		if (strlen(pool_name) > RTE_MEMPOOL_NAMESIZE - 1) {
			ODP_ERR("Max pool name size: %u. Trimming %u long, name collision might happen!\n",
				RTE_MEMPOOL_NAMESIZE - 1, strlen(pool_name));
			rte_name = malloc(RTE_MEMPOOL_NAMESIZE);
			snprintf(rte_name, RTE_MEMPOOL_NAMESIZE - 1, "%s",
				 pool_name);
		}

		pool_dp->rte_mempool =
			rte_mempool_create(rte_name ? rte_name : pool_name,
					   num,
					   mb_size,
					   cache_size,
					   sizeof(struct mbuf_pool_ctor_arg),
					   odp_dpdk_mbuf_pool_ctor,
					   &mbp_ctor_arg,
					   odp_dpdk_mbuf_ctor,
					   &mb_ctor_arg,
					   rte_socket_id(),
					   0);
		free(rte_name);
		if (pool_dp->rte_mempool == NULL) {
			ODP_ERR("Cannot init DPDK mbuf pool: %s\n",
				rte_strerror(rte_errno));
			UNLOCK(&pool_cp->lock);
			return ODP_POOL_INVALID;
		}
		/* found free pool */
		if (name == NULL) {
			pool_cp->name[0] = 0;
		} else {
			strncpy(pool_cp->name, name,
				ODP_POOL_NAME_LEN - 1);
			pool_cp->name[ODP_POOL_NAME_LEN - 1] = 0;
		}

		pool_cp->params = *params;
		mp = pool_dp->rte_mempool;
		ODP_DBG("Header/element/trailer size: %u/%u/%u, "
			"total pool size: %lu\n",
			mp->header_size, mp->elt_size, mp->trailer_size,
			(unsigned long)((mp->header_size + mp->elt_size +
			mp->trailer_size) * num));
		UNLOCK(&pool_cp->lock);
		pool_hdl = pool_cp->pool_hdl;
		break;
	}

	return pool_hdl;
}

static odp_pool_t dpdk_pool_lookup(const char *name)
{
	struct rte_mempool *mp = NULL;
	odp_pool_t pool_hdl = ODP_POOL_INVALID;
	int i;

	mp = rte_mempool_lookup(name);
	if (mp == NULL)
		return ODP_POOL_INVALID;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool_entry_cp_t *pool_cp = get_pool_entry_cp(i);
		pool_entry_dp_t *pool_dp = get_pool_entry_dp(i);

		LOCK(&pool_cp->lock);
		if (pool_dp->rte_mempool != mp) {
			UNLOCK(&pool_cp->lock);
			continue;
		}
		UNLOCK(&pool_cp->lock);
		pool_hdl = pool_cp->pool_hdl;
		break;
	}
	return pool_hdl;
}

static odp_buffer_t buffer_alloc(odp_pool_t pool_hdl)
{
	odp_buffer_t buffer;
	pool_entry_cp_t *pool_cp;
	pool_entry_dp_t *pool_dp;

	pool_cp = odp_pool_to_entry_cp(pool_hdl);
	pool_dp = odp_pool_to_entry_dp(pool_hdl);

	ODP_ASSERT(pool_cp->params.type != ODP_POOL_BUFFER &&
		   pool_cp->params.type != ODP_POOL_TIMEOUT);

	buffer = (odp_buffer_t)rte_ctrlmbuf_alloc(pool_dp->rte_mempool);

	if ((struct rte_mbuf *)buffer == NULL) {
		rte_errno = ENOMEM;
		return ODP_BUFFER_INVALID;
	}

	buf_hdl_to_hdr(buffer)->next = NULL;
	return buffer;
}

odp_buffer_t odp_buffer_alloc(odp_pool_t pool_hdl)
{
	ODP_ASSERT(ODP_POOL_INVALID != pool_hdl);

	return buffer_alloc(pool_hdl);
}

int odp_buffer_alloc_multi(odp_pool_t pool_hdl, odp_buffer_t buf[], int num)
{
	int i;

	ODP_ASSERT(ODP_POOL_INVALID != pool_hdl);

	for (i = 0; i < num; i++) {
		buf[i] = buffer_alloc(pool_hdl);
		if (buf[i] == ODP_BUFFER_INVALID)
			return rte_errno == ENOMEM ? i : -EINVAL;
	}
	return i;
}

void odp_buffer_free(odp_buffer_t buf)
{
	struct rte_mbuf *mbuf = (struct rte_mbuf *)buf;

	rte_ctrlmbuf_free(mbuf);
}

void odp_buffer_free_multi(const odp_buffer_t buf[], int num)
{
	int i;

	for (i = 0; i < num; i++) {
		struct rte_mbuf *mbuf = (struct rte_mbuf *)buf[i];

		rte_ctrlmbuf_free(mbuf);
	}
}

static void dpdk_pool_print(odp_pool_t pool_hdl)
{
	pool_entry_dp_t *pool_dp = odp_pool_to_entry_dp(pool_hdl);

	rte_mempool_dump(stdout, pool_dp->rte_mempool);
}

static int dpdk_pool_info(odp_pool_t pool_hdl, odp_pool_info_t *info)
{
	pool_entry_cp_t *pool_cp = odp_pool_to_entry_cp(pool_hdl);

	if (pool_cp == NULL || info == NULL)
		return -1;

	info->name = pool_cp->name;
	info->params = pool_cp->params;

	return 0;
}

/*
 * DPDK doesn't support pool destroy at the moment. Instead we should improve
 * dpdk_pool_create() to try to reuse pools
 */
static int dpdk_pool_destroy(odp_pool_t pool_hdl)
{
	pool_entry_dp_t *pool_dp = odp_pool_to_entry_dp(pool_hdl);

	if (pool_dp->rte_mempool == NULL) {
		ODP_ERR("Can't find pool!\n");
		return -1;
	}

	rte_mempool_free(pool_dp->rte_mempool);
	pool_dp->rte_mempool = NULL;
	/* The pktio supposed to be closed by now */
	return 0;
}

static void dpdk_pool_param_init(odp_pool_param_t *params)
{
	memset(params, 0, sizeof(odp_pool_param_t));
}

static uint64_t dpdk_pool_to_u64(odp_pool_t hdl)
{
	return _odp_pri(hdl);
}

pool_module_t dpdk_pool = {
	.base = {
		.name = "dpdk_pool",
		.init_local = dpdk_pool_init_local,
		.term_local = dpdk_pool_term_local,
		.init_global = dpdk_pool_init_global,
		.term_global = dpdk_pool_term_global,
		},
	.capability = dpdk_pool_capability,
	.create = dpdk_pool_create,
	.destroy = dpdk_pool_destroy,
	.lookup = dpdk_pool_lookup,
	.info = dpdk_pool_info,
	.print = dpdk_pool_print,
	.to_u64 = dpdk_pool_to_u64,
	.param_init = dpdk_pool_param_init,
};

ODP_MODULE_CONSTRUCTOR(dpdk_pool)
{
	odp_module_constructor(&dpdk_pool);
	odp_subsystem_register_module(pool, &dpdk_pool);
}

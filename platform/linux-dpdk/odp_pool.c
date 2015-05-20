/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/std_types.h>
#include <odp/pool.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_packet_internal.h>
#include <odp_timer_internal.h>
#include <odp_align_internal.h>
#include <odp/shared_memory.h>
#include <odp/align.h>
#include <odp_internal.h>
#include <odp/config.h>
#include <odp/hints.h>
#include <odp/debug.h>
#include <odp_debug_internal.h>

#include <string.h>
#include <stdlib.h>

/* for DPDK */
#include <odp_packet_dpdk.h>

#ifdef POOL_USE_TICKETLOCK
#include <odp/ticketlock.h>
#define LOCK(a)      odp_ticketlock_lock(a)
#define UNLOCK(a)    odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)
#else
#include <odp/spinlock.h>
#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a) odp_spinlock_init(a)
#endif

typedef struct pool_table_t {
	pool_entry_t pool[ODP_CONFIG_POOLS];

} pool_table_t;


/* The pool table ptr - resides in shared memory */
static pool_table_t *pool_tbl;

/* Pool entry pointers (for inlining) */
void *pool_entry_ptr[ODP_CONFIG_POOLS];


int odp_pool_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	shm = odp_shm_reserve("odp_pools",
			      sizeof(pool_table_t),
			      sizeof(pool_entry_t), 0);

	pool_tbl = odp_shm_addr(shm);

	if (pool_tbl == NULL)
		return -1;

	memset(pool_tbl, 0, sizeof(pool_table_t));


	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		/* init locks */
		pool_entry_t *pool = &pool_tbl->pool[i];
		LOCK_INIT(&pool->s.lock);
		pool->s.pool_hdl = pool_index_to_handle(i);

		pool_entry_ptr[i] = pool;
	}

	ODP_DBG("\nPool init global\n");
	ODP_DBG("  pool_entry_s size     %zu\n", sizeof(struct pool_entry_s));
	ODP_DBG("  pool_entry_t size     %zu\n", sizeof(pool_entry_t));
	ODP_DBG("  odp_buffer_hdr_t size %zu\n", sizeof(odp_buffer_hdr_t));
	ODP_DBG("\n");

	return 0;
}

struct mbuf_ctor_arg {
	uint16_t seg_buf_offset; /* To skip the ODP buf/pkt/tmo header */
	uint16_t seg_buf_size;   /* size of user data */
	int type;
	int pkt_uarea_size;      /* size of user area in bytes */
};

struct mbuf_pool_ctor_arg {
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
			mp->name, (int) mp->private_data_size,
			(int) sizeof(struct mbuf_pool_ctor_arg));
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

	RTE_MBUF_ASSERT(mp->elt_size >= sizeof(struct rte_mbuf));

	memset(mb, 0, mp->elt_size);

	/* Start of buffer is just after the ODP type specific header
	 * which contains in the very beginning the rte_mbuf struct */
	mb->buf_addr     = (char *)mb + mb_ctor_arg->seg_buf_offset;
	mb->buf_physaddr = rte_mempool_virt2phy(mp, mb) +
			mb_ctor_arg->seg_buf_offset;
	mb->buf_len      = mb_ctor_arg->seg_buf_size;

	/* keep some headroom between start of buffer and data */
	if (mb_ctor_arg->type == ODP_POOL_PACKET) {
		odp_packet_hdr_t *pkt_hdr;

		mb->type = RTE_MBUF_PKT;
		mb->pkt.data = (char *)mb->buf_addr +
				ODP_CONFIG_PACKET_HEADROOM;
		mb->pkt.nb_segs = 1;
		mb->pkt.in_port = 0xff;
		pkt_hdr = (odp_packet_hdr_t *)raw_mbuf;
		pkt_hdr->uarea_size = mb_ctor_arg->pkt_uarea_size;
	} else {
		mb->type = RTE_MBUF_CTRL;
		mb->ctrl.data = mb->buf_addr;
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
}

#define CHECK_U16_OVERFLOW(X)	do {			\
	if (odp_unlikely(X > UINT16_MAX)) {		\
		ODP_ERR("Invalid size: %d", X);		\
		UNLOCK(&pool->s.lock);			\
		return ODP_POOL_INVALID;		\
	}						\
} while (0)

odp_pool_t odp_pool_create(const char *name, odp_shm_t shm,
			   odp_pool_param_t *params)
{
	struct mbuf_pool_ctor_arg mbp_ctor_arg;
	struct mbuf_ctor_arg mb_ctor_arg;
	odp_pool_t pool_hdl = ODP_POOL_INVALID;
	unsigned mb_size, i, j, cache_size;
	size_t hdr_size;
	pool_entry_t *pool;
	uint32_t buf_align, blk_size, headroom, tailroom, seg_len;

	if (shm != ODP_SHM_NULL)
		ODP_DBG("DPDK doesn't support shm parameter. (%l)",
			odp_shm_to_u64(shm));

	/* Find an unused buffer pool slot and initalize it as requested */
	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		uint32_t num;
		pool = get_pool_entry(i);

		LOCK(&pool->s.lock);
		if (pool->s.rte_mempool != NULL) {
			UNLOCK(&pool->s.lock);
			continue;
		}

		switch (params->type) {
		case ODP_POOL_BUFFER:
			buf_align = params->buf.align;
			blk_size = params->buf.size;

			/* Validate requested buffer alignment */
			if (buf_align > ODP_CONFIG_BUFFER_ALIGN_MAX ||
			    buf_align !=
			    ODP_ALIGN_ROUNDDOWN_POWER_2(buf_align, buf_align)) {
				UNLOCK(&pool->s.lock);
				return ODP_POOL_INVALID;
			}

			/* Set correct alignment based on input request */
			if (buf_align == 0)
				buf_align = ODP_CACHE_LINE_SIZE;
			else if (buf_align < ODP_CONFIG_BUFFER_ALIGN_MIN)
				buf_align = ODP_CONFIG_BUFFER_ALIGN_MIN;

			/* Optimize small raw buffers */
			if (blk_size > ODP_MAX_INLINE_BUF ||
			    params->buf.align != 0)
				blk_size = ODP_ALIGN_ROUNDUP(blk_size,
							     buf_align);

			hdr_size = sizeof(odp_buffer_hdr_t);
			CHECK_U16_OVERFLOW(blk_size);
			mbp_ctor_arg.pkt.mbuf_data_room_size = blk_size;
			num = params->buf.num;
			ODP_DBG("type: buffer name: %s num: "
				"%u size: %u align: %u\n", name, num,
				params->buf.size, params->buf.align);
			break;
		case ODP_POOL_PACKET:
			headroom = ODP_CONFIG_PACKET_HEADROOM;
			tailroom = ODP_CONFIG_PACKET_TAILROOM;
			seg_len = params->pkt.seg_len == 0 ?
				ODP_CONFIG_PACKET_SEG_LEN_MIN :
				(params->pkt.seg_len <= ODP_CONFIG_PACKET_SEG_LEN_MAX ?
				 params->pkt.seg_len : ODP_CONFIG_PACKET_SEG_LEN_MAX);

			seg_len = ODP_ALIGN_ROUNDUP(
				headroom + seg_len + tailroom,
				ODP_CONFIG_BUFFER_ALIGN_MIN);
			blk_size = params->pkt.len <= seg_len ? seg_len :
				ODP_ALIGN_ROUNDUP(params->pkt.len, seg_len);

			/* Reject create if pkt.len needs too many segments */
			if (blk_size / seg_len > ODP_BUFFER_MAX_SEG) {
				UNLOCK(&pool->s.lock);
				return ODP_POOL_INVALID;
			}

			hdr_size = sizeof(odp_packet_hdr_t) +
				   params->pkt.uarea_size;
			mb_ctor_arg.pkt_uarea_size = params->pkt.uarea_size;
			CHECK_U16_OVERFLOW(blk_size);
			mbp_ctor_arg.pkt.mbuf_data_room_size = blk_size;
			num = params->pkt.num;
			ODP_DBG("type: packet, name: %s, "
				"num: %u, len: %u, seg_len: %u, blk_size %d, "
				"uarea_size %d, hdr_size %d\n",
				name, num, params->pkt.len,
				params->pkt.seg_len, blk_size,
				params->pkt.uarea_size, hdr_size);
			break;
		case ODP_POOL_TIMEOUT:
			hdr_size = sizeof(odp_timeout_hdr_t);
			mbp_ctor_arg.pkt.mbuf_data_room_size = 0;
			num = params->tmo.num;
			ODP_DBG("type: tmo name: %s num: %u\n",
				name, num);
			break;
		default:
			ODP_ERR("Bad type %i\n",
				params->type);
			UNLOCK(&pool->s.lock);
			return ODP_POOL_INVALID;
			break;
		}

		mb_ctor_arg.seg_buf_offset =
			(uint16_t) ODP_CACHE_LINE_SIZE_ROUNDUP(hdr_size);
		mb_ctor_arg.seg_buf_size = mbp_ctor_arg.pkt.mbuf_data_room_size;
		mb_ctor_arg.type = params->type;
		mb_size = mb_ctor_arg.seg_buf_offset + mb_ctor_arg.seg_buf_size;
		mbp_ctor_arg.pool_hdl = pool->s.pool_hdl;

		cache_size = 0;
		j = RTE_MAX(num / RTE_MEMPOOL_CACHE_MAX_SIZE, 2UL);
		for (; j < (num / 2); ++j)
			if ((num % j) == 0) {
				cache_size = num / j;
				break;
			}
		if (odp_unlikely(cache_size > RTE_MEMPOOL_CACHE_MAX_SIZE ||
				 (uint32_t) cache_size * 1.5 > num)) {
			ODP_ERR("cache_size calc failure: %d\n", cache_size);
			cache_size = 0;
		}

		ODP_DBG("cache_size %d\n", cache_size);

		pool->s.rte_mempool =
			rte_mempool_create(name,
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
		if (pool->s.rte_mempool == NULL) {
			ODP_ERR("Cannot init DPDK mbuf pool: %s\n",
				rte_strerror(rte_errno));
			UNLOCK(&pool->s.lock);
			return ODP_POOL_INVALID;
		}
		/* found free pool */
		if (name == NULL) {
			pool->s.name[0] = 0;
		} else {
			strncpy(pool->s.name, name,
				ODP_POOL_NAME_LEN - 1);
			pool->s.name[ODP_POOL_NAME_LEN - 1] = 0;
		}

		pool->s.params = *params;
		UNLOCK(&pool->s.lock);
		pool_hdl = pool->s.pool_hdl;
		break;
	}

	return pool_hdl;
}


odp_pool_t odp_pool_lookup(const char *name)
{
	struct rte_mempool *mp = NULL;
	odp_pool_t pool_hdl = ODP_POOL_INVALID;
	int i;

	mp = rte_mempool_lookup(name);
	if (mp == NULL)
		return ODP_POOL_INVALID;

	for (i = 0; i < ODP_CONFIG_POOLS; i++) {
		pool_entry_t *pool = get_pool_entry(i);
		LOCK(&pool->s.lock);
		if (pool->s.rte_mempool != mp) {
			UNLOCK(&pool->s.lock);
			continue;
		}
		UNLOCK(&pool->s.lock);
		pool_hdl = pool->s.pool_hdl;
	}
	return pool_hdl;
}


odp_buffer_t odp_buffer_alloc(odp_pool_t pool_hdl)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	odp_buffer_t buffer;
	if (pool->s.params.type == ODP_POOL_PACKET)
		buffer = (odp_buffer_t)rte_pktmbuf_alloc(pool->s.rte_mempool);
	else
		buffer = (odp_buffer_t)rte_ctrlmbuf_alloc(pool->s.rte_mempool);
	if ((struct rte_mbuf *)buffer == NULL)
		return ODP_BUFFER_INVALID;
	else
		return buffer;
}


void odp_buffer_free(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);
	struct rte_mbuf *mbuf = (struct rte_mbuf *)hdr;
	if (mbuf->type == RTE_MBUF_PKT)
		rte_pktmbuf_free(mbuf);
	else
		rte_ctrlmbuf_free(mbuf);
}


void odp_pool_print(odp_pool_t pool_hdl)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	rte_mempool_dump(stdout, pool->s.rte_mempool);
}

int odp_pool_info(odp_pool_t pool_hdl, odp_pool_info_t *info)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);

	if (pool == NULL || info == NULL)
		return -1;

	info->name = pool->s.name;
	info->shm  = ODP_SHM_INVALID;
	info->params = pool->s.params;

	return 0;
}

/*
 * DPDK doesn't support pool destroy at the moment. Instead we should improve
 * odp_pool_create() to try to reuse pools
 */
int odp_pool_destroy(odp_pool_t pool_hdl)
{
	uint32_t pool_id = pool_handle_to_index(pool_hdl);
	pool_entry_t *pool = get_pool_entry(pool_id);
	struct rte_mem_config *mcfg;
	int i;
	char name[RTE_MEMZONE_NAMESIZE];
	char ringname[RTE_MEMZONE_NAMESIZE];
	struct rte_mempool *mp;

	ODP_ERR("WARNING! This function doesn't really delete the pool due to "
		"lack of DPDK support, it only releases its name. The memzone "
		"allocated will be leaked!\n");

	if ((mp = rte_mempool_lookup(pool->s.name)) == NULL) {
		ODP_ERR("Can't find pool with this name!\n");
		return -1;
	}
	mp->name[0] = 0;

	snprintf(name, sizeof(name), RTE_MEMPOOL_MZ_FORMAT, pool->s.name);
	snprintf(ringname, sizeof(ringname), "%s%s", RTE_RING_MZ_PREFIX, name);

	/* This code is based on memzone_lookup_thread_unsafe() from DPDK. We
	 * are deleting the name of the memzones, so at least we can reuse it
	 * next time */
	/* get pointer to global configuration */
	mcfg = rte_eal_get_configuration()->mem_config;
	rte_rwlock_write_lock(&mcfg->mlock);
	/*
	 * the algorithm is not optimal (linear), but there are few
	 * zones and this function should be called at init only
	 */
	for (i = 0; i < RTE_MAX_MEMZONE && mcfg->memzone[i].addr != NULL; i++) {
		if (!strncmp(name, mcfg->memzone[i].name,
			     RTE_MEMZONE_NAMESIZE) ||
		    !strncmp(ringname, mcfg->memzone[i].name,
			     RTE_MEMZONE_NAMESIZE))
			mcfg->memzone[i].name[0] = 0;
	}
	rte_rwlock_write_unlock(&mcfg->mlock);

	pool->s.rte_mempool = NULL;
	/* The pktio supposed to be closed by now */
	return 0;
}

odp_pool_t odp_buffer_pool(odp_buffer_t buf)
{
	return odp_buf_to_hdr(buf)->pool_hdl;
}

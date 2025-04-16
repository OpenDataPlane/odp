/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2025 Nokia
 */

#include <odp/api/dma.h>
#include <odp/api/event.h>
#include <odp/api/shared_memory.h>
#include <odp/api/ticketlock.h>
#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp/api/stash.h>
#include <odp/api/packet.h>
#include <odp/api/pool.h>
#include <odp/api/queue.h>

#include <odp/api/plat/std_inlines.h>
#include <odp/api/plat/strong_types.h>

#include <odp_global_data.h>
#include <odp_debug_internal.h>
#include <odp_init_internal.h>
#include <odp_event_internal.h>
#include <odp_pool_internal.h>
#include <odp_string_internal.h>

#include <string.h>
#include <inttypes.h>

#define MAX_SESSIONS  CONFIG_MAX_DMA_SESSIONS
#define MAX_TRANSFERS 256
#define MAX_SEGS      16
#define MAX_SEG_LEN   (128 * 1024)

ODP_STATIC_ASSERT(MAX_TRANSFERS < UINT32_MAX, "Too many inflight transfers");

typedef struct segment_t {
	void     *addr;
	uint32_t  len;

} segment_t;

typedef struct transfer_t {
	void     *dst;
	void     *src;
	uint32_t  len;

} transfer_t;

typedef struct result_t {
	void *user_ptr;

} result_t;

typedef struct ODP_ALIGNED_CACHE dma_session_t {
	odp_ticketlock_t  lock;
	odp_dma_param_t   dma_param;
	uint8_t           active;
	char              name[ODP_DMA_NAME_LEN];
	odp_stash_t       stash;
	result_t          result[MAX_TRANSFERS];

} dma_session_t;

typedef struct dma_global_t {
	odp_shm_t shm;

	/* Buffer pool capability and default parameters */
	odp_pool_capability_t pool_capa;
	odp_pool_param_t pool_param;

	dma_session_t session[MAX_SESSIONS];

} dma_global_t;

static dma_global_t *_odp_dma_glb;

static inline dma_session_t *dma_session_from_handle(odp_dma_t dma)
{
	return (dma_session_t *)(uintptr_t)dma;
}

int odp_dma_capability(odp_dma_capability_t *capa)
{
	if (odp_global_ro.disable.dma) {
		_ODP_ERR("DMA is disabled\n");
		return -1;
	}

	memset(capa, 0, sizeof(odp_dma_capability_t));

	capa->max_sessions  = MAX_SESSIONS;
	capa->max_transfers = MAX_TRANSFERS;
	capa->max_src_segs  = MAX_SEGS;
	capa->max_dst_segs  = MAX_SEGS;
	capa->max_segs      = 2 * MAX_SEGS;
	capa->max_seg_len   = MAX_SEG_LEN;

	capa->compl_mode_mask = ODP_DMA_COMPL_SYNC  | ODP_DMA_COMPL_NONE |
				ODP_DMA_COMPL_EVENT | ODP_DMA_COMPL_POLL;

	capa->queue_type_sched = 1;
	capa->queue_type_plain = 1;
	capa->src_seg_free     = 1;

	capa->pool.max_pools         = _odp_dma_glb->pool_capa.buf.max_pools;
	capa->pool.max_num           = _odp_dma_glb->pool_capa.buf.max_num;
	capa->pool.max_uarea_size    = _odp_dma_glb->pool_capa.buf.max_uarea_size;
	capa->pool.uarea_persistence = _odp_dma_glb->pool_capa.buf.uarea_persistence;
	capa->pool.min_cache_size    = _odp_dma_glb->pool_capa.buf.min_cache_size;
	capa->pool.max_cache_size    = _odp_dma_glb->pool_capa.buf.max_cache_size;

	return 0;
}

void odp_dma_param_init(odp_dma_param_t *param)
{
	memset(param, 0, sizeof(odp_dma_param_t));

	param->direction = ODP_DMA_MAIN_TO_MAIN;
	param->type      = ODP_DMA_TYPE_COPY;
	param->mt_mode   = ODP_DMA_MT_SAFE;
	param->order     = ODP_DMA_ORDER_NONE;
}

static odp_stash_t create_stash(void)
{
	odp_stash_param_t stash_param;
	odp_stash_t stash;
	uint32_t id, tmp, i;
	int32_t ret = 0;

	odp_stash_param_init(&stash_param);
	stash_param.num_obj    = MAX_TRANSFERS;
	stash_param.obj_size   = sizeof(uint32_t);
	stash_param.cache_size = 0;

	stash = odp_stash_create("_odp_dma_transfer_id", &stash_param);

	if (stash == ODP_STASH_INVALID) {
		_ODP_ERR("Stash create failed\n");
		return ODP_STASH_INVALID;
	}

	/* Zero is invalid ID */
	for (id = 1; id < MAX_TRANSFERS + 1; id++) {
		ret = odp_stash_put_u32(stash, &id, 1);
		if (ret != 1) {
			_ODP_ERR("Stash put failed: %i, %u\n", ret, id);
			break;
		}
	}

	if (ret != 1) {
		for (i = 0; i < id; i++) {
			if (odp_stash_get_u32(stash, &tmp, 1) != 1) {
				_ODP_ERR("Stash get failed: %u\n", i);
				break;
			}
		}

		if (odp_stash_destroy(stash))
			_ODP_ERR("Stash destroy failed\n");

		return ODP_STASH_INVALID;
	}

	return stash;
}

static int destroy_stash(odp_stash_t stash)
{
	uint32_t tmp;
	int32_t num;
	int ret = 0;

	while (1) {
		num = odp_stash_get_u32(stash, &tmp, 1);

		if (num == 1)
			continue;

		if (num == 0)
			break;

		_ODP_ERR("Stash get failed: %i\n", num);
		ret = -1;
		break;
	}

	if (odp_stash_destroy(stash)) {
		_ODP_ERR("Stash destroy failed\n");
		ret = -1;
	}

	return ret;
}

odp_dma_t odp_dma_create(const char *name, const odp_dma_param_t *param)
{
	odp_dma_capability_t dma_capa;
	int i;
	dma_session_t *session = NULL;

	if (odp_global_ro.disable.dma) {
		_ODP_ERR("DMA is disabled\n");
		return ODP_DMA_INVALID;
	}

	if ((param->direction != ODP_DMA_MAIN_TO_MAIN) ||
	    (param->type != ODP_DMA_TYPE_COPY)) {
		_ODP_ERR("Bad DMA parameter\n");
		return ODP_DMA_INVALID;
	}

	if (param->compl_mode_mask == 0) {
		_ODP_ERR("Empty compl mode mask\n");
		return ODP_DMA_INVALID;
	}

	if (odp_dma_capability(&dma_capa)) {
		_ODP_ERR("DMA capa failed\n");
		return ODP_DMA_INVALID;
	}

	if (param->compl_mode_mask & ~dma_capa.compl_mode_mask) {
		_ODP_ERR("Compl mode not supported\n");
		return ODP_DMA_INVALID;
	}

	for (i = 0; i < MAX_SESSIONS; i++) {
		if (_odp_dma_glb->session[i].active)
			continue;

		odp_ticketlock_lock(&_odp_dma_glb->session[i].lock);

		if (_odp_dma_glb->session[i].active) {
			odp_ticketlock_unlock(&_odp_dma_glb->session[i].lock);
			continue;
		}

		session = &_odp_dma_glb->session[i];
		session->active = 1;
		odp_ticketlock_unlock(&_odp_dma_glb->session[i].lock);
		break;
	}

	if (session == NULL) {
		_ODP_DBG("Out of DMA sessions\n");
		return ODP_DMA_INVALID;
	}

	session->stash = ODP_STASH_INVALID;

	/* Create stash for transfer IDs */
	if (param->compl_mode_mask & ODP_DMA_COMPL_POLL) {
		session->stash = create_stash();

		if (session->stash == ODP_STASH_INVALID) {
			session->active = 0;
			return ODP_DMA_INVALID;
		}
	}

	session->name[0] = 0;

	if (name)
		_odp_strcpy(session->name, name, ODP_DMA_NAME_LEN);

	session->dma_param = *param;

	return (odp_dma_t)session;
}

int odp_dma_destroy(odp_dma_t dma)
{
	dma_session_t *session = dma_session_from_handle(dma);
	int ret = 0;

	if (dma == ODP_DMA_INVALID) {
		_ODP_ERR("Bad DMA handle\n");
		return -1;
	}

	if (session->stash != ODP_STASH_INVALID)
		if (destroy_stash(session->stash))
			ret = -1;

	odp_ticketlock_lock(&session->lock);

	if (session->active == 0) {
		_ODP_ERR("Session not created\n");
		odp_ticketlock_unlock(&session->lock);
		return -1;
	}

	session->active = 0;
	odp_ticketlock_unlock(&session->lock);

	return ret;
}

odp_dma_t odp_dma_lookup(const char *name)
{
	dma_session_t *session;
	int i;

	for (i = 0; i < MAX_SESSIONS; i++) {
		session = &_odp_dma_glb->session[i];

		odp_ticketlock_lock(&session->lock);

		if (session->active == 0) {
			odp_ticketlock_unlock(&session->lock);
			continue;
		}

		if (strcmp(session->name, name) == 0) {
			/* found it */
			odp_ticketlock_unlock(&session->lock);
			return (odp_dma_t)session;
		}
		odp_ticketlock_unlock(&session->lock);
	}

	return ODP_DMA_INVALID;
}

static uint32_t transfer_len(const odp_dma_transfer_param_t *trs_param)
{
	uint32_t i;
	uint32_t src_len = 0;
	uint32_t dst_len = 0;

	for (i = 0; i < trs_param->num_src; i++)
		src_len += trs_param->src_seg[i].len;

	for (i = 0; i < trs_param->num_dst; i++)
		dst_len += trs_param->dst_seg[i].len;

	if (src_len != dst_len)
		return 0;

	return src_len;
}

static inline void segment_raw(segment_t seg[], int num, const odp_dma_seg_t *dma_seg)
{
	int i;

	for (i = 0; i < num; i++) {
		seg[i].addr = dma_seg[i].addr;
		seg[i].len  = dma_seg[i].len;
	}
}

static inline int segment_pkt(segment_t seg[], int num_seg, const odp_dma_seg_t *dma_seg)
{
	odp_packet_t pkt;
	uint32_t offset;
	void *addr;
	uint32_t seg_len, tot_len, len;
	int i;
	int num = 0;

	for (i = 0; i < num_seg; i++) {
		pkt     = dma_seg[i].packet;
		offset  = dma_seg[i].offset;
		tot_len = dma_seg[i].len;

		if (odp_unlikely(offset + tot_len > odp_packet_len(pkt))) {
			_ODP_ERR("Bad packet segment len/offset (%u/%u)\n", tot_len, offset);
			return 0;
		}

		while (tot_len) {
			addr = odp_packet_offset(pkt, offset, &seg_len, NULL);

			if (odp_unlikely(addr == NULL)) {
				_ODP_ERR("Bad packet offset %u\n", offset);
				return 0;
			}

			seg[num].addr = addr;
			len = tot_len;
			if (tot_len > seg_len)
				len = seg_len;

			seg[num].len = len;

			tot_len -= len;
			offset  += len;
			num++;

			if (odp_unlikely(num > MAX_SEGS)) {
				_ODP_ERR("Too many packet segments\n");
				return 0;
			}
		}
	}

	return num;
}

static int transfer_table(transfer_t *trs, const segment_t src_seg[], const segment_t dst_seg[],
			  int max_num, uint32_t tot_len)
{
	uint32_t len, src_len, dst_len;
	uint8_t *src_ptr, *dst_ptr;
	int i;
	int src = 0;
	int dst = 0;

	src_ptr = src_seg[0].addr;
	dst_ptr = dst_seg[0].addr;
	src_len = src_seg[0].len;
	dst_len = dst_seg[0].len;

	len = src_len;
	if (dst_len < src_len)
		len = dst_len;

	for (i = 0; i < max_num; i++) {
		trs[i].src = src_ptr;
		trs[i].dst = dst_ptr;
		trs[i].len = len;
		tot_len -= len;

		if (tot_len == 0)
			break;

		if (dst_len < src_len) {
			dst++;
			dst_ptr  = dst_seg[dst].addr;
			dst_len  = dst_seg[dst].len;
			src_ptr += len;
			src_len -= len;
		} else if (src_len < dst_len) {
			src++;
			src_ptr  = src_seg[src].addr;
			src_len  = src_seg[src].len;
			dst_ptr += len;
			dst_len -= len;
		} else { /* equal lengths */
			dst++;
			src++;
			dst_ptr  = dst_seg[dst].addr;
			dst_len  = dst_seg[dst].len;
			src_ptr  = src_seg[src].addr;
			src_len  = src_seg[src].len;
		}

		len = src_len;
		if (dst_len < src_len)
			len = dst_len;
	}

	return i + 1;
}

static uint32_t add_to_free_set(odp_packet_t pkt, odp_packet_t set[], uint32_t num)
{
	odp_bool_t is_found = false;

	for (uint32_t i = 0; i < num; i++)
		if (set[i] == pkt)
			is_found = true;

	if (!is_found)
		set[num++] = pkt;

	return num;
}

static void free_src_segs(const odp_dma_transfer_param_t *transfer)
{
	const uint32_t num_src = transfer->num_src;

	if (transfer->opts.unique_src_segs) {
		for (uint32_t i = 0; i < num_src; i++)
			odp_packet_free(transfer->src_seg[i].packet);
	} else {
		odp_packet_t free_set[num_src];
		uint32_t num = 0;

		for (uint32_t i = 0; i < num_src; i++)
			num = add_to_free_set(transfer->src_seg[i].packet, free_set, num);

		odp_packet_free_multi(free_set, num);
	}
}

int odp_dma_transfer(odp_dma_t dma, const odp_dma_transfer_param_t *transfer,
		     odp_dma_result_t *result)
{
	int num, i;
	uint32_t tot_len;
	dma_session_t *session = dma_session_from_handle(dma);
	int num_src, num_dst;
	const int max_num = 2 * MAX_SEGS;
	transfer_t trs[max_num];
	segment_t src[MAX_SEGS];
	segment_t dst[MAX_SEGS];

	if (odp_unlikely(dma == ODP_DMA_INVALID)) {
		_ODP_ERR("Bad DMA handle\n");
		return -1;
	}

	if (odp_unlikely(session->active == 0)) {
		_ODP_ERR("Session not created\n");
		return -1;
	}

	if (odp_unlikely(transfer->num_src == 0 || transfer->num_src > MAX_SEGS)) {
		_ODP_ERR("Bad number of src segments\n");
		return -1;
	}

	if (odp_unlikely(transfer->num_dst == 0 || transfer->num_dst > MAX_SEGS)) {
		_ODP_ERR("Bad number of dst segments\n");
		return -1;
	}

	if (odp_unlikely(transfer->opts.seg_free &&
			 transfer->src_format != ODP_DMA_FORMAT_PACKET)) {
		_ODP_ERR("Source segment freeing supported only for packets\n");
		return -1;
	}

	tot_len = transfer_len(transfer);

	if (odp_unlikely(tot_len == 0)) {
		_ODP_ERR("Bad transfer length\n");
		return -1;
	}

	if (transfer->src_format == ODP_DMA_FORMAT_ADDR) {
		num_src = transfer->num_src;
		segment_raw(src, num_src, transfer->src_seg);
	} else {
		num_src = segment_pkt(src, transfer->num_src, transfer->src_seg);

		if (odp_unlikely(num_src == 0))
			return -1;
	}

	if (transfer->dst_format == ODP_DMA_FORMAT_ADDR) {
		num_dst = transfer->num_dst;
		segment_raw(dst, num_dst, transfer->dst_seg);
	} else {
		num_dst = segment_pkt(dst, transfer->num_dst, transfer->dst_seg);

		if (odp_unlikely(num_dst == 0))
			return -1;
	}

	num = transfer_table(trs, src, dst, max_num, tot_len);

	if (odp_unlikely(num > max_num)) {
		_ODP_ERR("Segment table error\n");
		return -1;
	}

	for (i = 0; i < num; i++)
		memcpy(trs[i].dst, trs[i].src, trs[i].len);

	if (transfer->opts.seg_free)
		free_src_segs(transfer);

	if (result) {
		memset(result, 0, sizeof(odp_dma_result_t));
		result->success = 1;
	}

	return 1;
}

int odp_dma_transfer_multi(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param[],
			   odp_dma_result_t *result[], int num)
{
	int i;
	odp_dma_result_t *res = NULL;
	int ret = 0;

	if (odp_unlikely(num < 1)) {
		_ODP_ERR("Bad number of transfers\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		if (result)
			res = result[i];

		ret = odp_dma_transfer(dma, trs_param[i], res);

		if (odp_unlikely(ret != 1))
			break;
	}

	if (odp_unlikely(i == 0))
		return ret;

	return i;
}

odp_dma_transfer_id_t odp_dma_transfer_id_alloc(odp_dma_t dma)
{
	int32_t num;
	uint32_t id;
	dma_session_t *session = dma_session_from_handle(dma);

	num = odp_stash_get_u32(session->stash, &id, 1);

	if (odp_unlikely(num != 1))
		return ODP_DMA_TRANSFER_ID_INVALID;

	return id;
}

void odp_dma_transfer_id_free(odp_dma_t dma, odp_dma_transfer_id_t transfer_id)
{
	int32_t num;
	dma_session_t *session = dma_session_from_handle(dma);
	uint32_t id = transfer_id;

	num = odp_stash_put_u32(session->stash, &id, 1);

	if (odp_unlikely(num != 1))
		_ODP_ERR("Stash put failed\n");
}

static inline uint32_t index_from_transfer_id(odp_dma_transfer_id_t transfer_id)
{
	return transfer_id - 1;
}

int odp_dma_transfer_start(odp_dma_t dma, const odp_dma_transfer_param_t *transfer,
			   const odp_dma_compl_param_t *compl)
{
	int ret;
	dma_session_t *session = dma_session_from_handle(dma);
	const uint32_t transfer_id = compl->transfer_id;

	if (odp_unlikely(dma == ODP_DMA_INVALID)) {
		_ODP_ERR("Bad DMA handle\n");
		return -1;
	}

	/* Check completion mode */
	switch (compl->compl_mode) {
	case ODP_DMA_COMPL_NONE:
		break;
	case ODP_DMA_COMPL_POLL:
		if (transfer_id == ODP_DMA_TRANSFER_ID_INVALID || transfer_id > MAX_TRANSFERS) {
			_ODP_ERR("Bad transfer ID: %u\n", transfer_id);
			return -1;
		}
		break;
	case ODP_DMA_COMPL_EVENT:
		if (compl->event == ODP_EVENT_INVALID ||
		    compl->queue == ODP_QUEUE_INVALID) {
			_ODP_ERR("Bad event or queue\n");
			return -1;
		}
		break;
	default:
		_ODP_ERR("Bad completion mode %u\n", compl->compl_mode);
		return -1;
	}

	ret = odp_dma_transfer(dma, transfer, NULL);

	if (odp_unlikely(ret < 1))
		return ret;

	if (compl->compl_mode == ODP_DMA_COMPL_POLL) {
		uint32_t index = index_from_transfer_id(transfer_id);

		session->result[index].user_ptr = compl->user_ptr;

	} else if (compl->compl_mode == ODP_DMA_COMPL_EVENT) {
		odp_dma_result_t *result;
		odp_buffer_t buf = (odp_buffer_t)(uintptr_t)compl->event;

		if (odp_unlikely(odp_event_type(compl->event) != ODP_EVENT_DMA_COMPL)) {
			_ODP_ERR("Bad completion event type\n");
			return -1;
		}

		result = odp_buffer_addr(buf);
		result->success  = 1;
		result->user_ptr = compl->user_ptr;

		if (odp_unlikely(odp_queue_enq(compl->queue, compl->event))) {
			_ODP_ERR("Completion event enqueue failed %" PRIu64 "\n",
				 odp_queue_to_u64(compl->queue));
			return -1;
		}
	}

	return 1;
}

int odp_dma_transfer_start_multi(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param[],
				 const odp_dma_compl_param_t *compl_param[], int num)
{
	int i;
	int ret = 0;

	if (odp_unlikely(num < 1)) {
		_ODP_ERR("Bad number of transfers\n");
		return -1;
	}

	for (i = 0; i < num; i++) {
		ret = odp_dma_transfer_start(dma, trs_param[i], compl_param[i]);

		if (odp_unlikely(ret != 1))
			break;
	}

	if (odp_unlikely(i == 0))
		return ret;

	return i;
}

int odp_dma_transfer_done(odp_dma_t dma, odp_dma_transfer_id_t transfer_id,
			  odp_dma_result_t *result)
{
	dma_session_t *session = dma_session_from_handle(dma);
	const uint32_t id = transfer_id;

	if (odp_unlikely(dma == ODP_DMA_INVALID)) {
		_ODP_ERR("Bad DMA handle\n");
		return -1;
	}

	if (odp_unlikely(id == ODP_DMA_TRANSFER_ID_INVALID || id > MAX_TRANSFERS)) {
		_ODP_ERR("Bad transfer ID: %u\n", id);
		return -1;
	}

	if (result) {
		uint32_t index = index_from_transfer_id(id);

		result->success  = 1;
		result->user_ptr = session->result[index].user_ptr;
	}

	return 1;
}

void odp_dma_pool_param_init(odp_dma_pool_param_t *pool_param)
{
	memset(pool_param, 0, sizeof(odp_dma_pool_param_t));

	pool_param->cache_size = _odp_dma_glb->pool_param.buf.cache_size;
}

odp_pool_t odp_dma_pool_create(const char *name, const odp_dma_pool_param_t *dma_pool_param)
{
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	uint32_t num = dma_pool_param->num;
	uint32_t uarea_size = dma_pool_param->uarea_size;
	uint32_t cache_size = dma_pool_param->cache_size;

	if (num > _odp_dma_glb->pool_capa.buf.max_num) {
		_ODP_ERR("Too many DMA completion events: %u\n", num);
		return ODP_POOL_INVALID;
	}

	if (uarea_size > _odp_dma_glb->pool_capa.buf.max_uarea_size) {
		_ODP_ERR("Bad uarea size: %u\n", uarea_size);
		return ODP_POOL_INVALID;
	}

	if (cache_size < _odp_dma_glb->pool_capa.buf.min_cache_size ||
	    cache_size > _odp_dma_glb->pool_capa.buf.max_cache_size) {
		_ODP_ERR("Bad cache size: %u\n", cache_size);
		return ODP_POOL_INVALID;
	}

	odp_pool_param_init(&pool_param);
	pool_param.type               = ODP_POOL_BUFFER;
	pool_param.uarea_init.init_fn = dma_pool_param->uarea_init.init_fn;
	pool_param.uarea_init.args    = dma_pool_param->uarea_init.args;
	pool_param.buf.num            = num;
	pool_param.buf.uarea_size     = uarea_size;
	pool_param.buf.cache_size     = cache_size;
	pool_param.buf.size           = sizeof(odp_dma_result_t);

	pool = _odp_pool_create(name, &pool_param, ODP_POOL_DMA_COMPL);

	return pool;
}

uint64_t odp_dma_to_u64(odp_dma_t dma)
{
	return _odp_pri(dma);
}

uint64_t odp_dma_compl_to_u64(odp_dma_compl_t dma_compl)
{
	return _odp_pri(dma_compl);
}

uint64_t odp_dma_transfer_id_to_u64(odp_dma_transfer_id_t transfer_id)
{
	return _odp_pri(transfer_id);
}

void odp_dma_print(odp_dma_t dma)
{
	dma_session_t *session = dma_session_from_handle(dma);

	if (dma == ODP_DMA_INVALID) {
		_ODP_ERR("Bad DMA handle\n");
		return;
	}

	_ODP_PRINT("\nDMA info\n");
	_ODP_PRINT("--------\n");
	_ODP_PRINT("  DMA handle      0x%" PRIx64 "\n", odp_dma_to_u64(dma));
	_ODP_PRINT("  name            %s\n", session->name);
	_ODP_PRINT("\n");
}

void odp_dma_compl_print(odp_dma_compl_t dma_compl)
{
	odp_dma_result_t result;
	int ret;

	if (dma_compl == ODP_DMA_COMPL_INVALID) {
		_ODP_ERR("Bad DMA compl handle\n");
		return;
	}

	ret = odp_dma_compl_result(dma_compl, &result);

	_ODP_PRINT("\nDMA completion\n");
	_ODP_PRINT("--------------\n");
	_ODP_PRINT("  Compl event handle: 0x%" PRIx64 "\n", _odp_pri(dma_compl));

	if (ret == 0) {
		_ODP_PRINT("  Result:             %s\n", result.success ? "success" : "fail");
		_ODP_PRINT("  User pointer:       0x%" PRIx64 "\n", _odp_pri(result.user_ptr));
	} else {
		_ODP_PRINT("  No result metadata\n");
	}

	_ODP_PRINT("\n");
}

int _odp_dma_init_global(void)
{
	odp_shm_t shm;
	int i;

	if (odp_global_ro.disable.dma) {
		_ODP_PRINT("DMA is DISABLED\n");
		return 0;
	}

	shm = odp_shm_reserve("_odp_dma_global", sizeof(dma_global_t), ODP_CACHE_LINE_SIZE, 0);
	_odp_dma_glb = odp_shm_addr(shm);

	if (_odp_dma_glb == NULL) {
		_ODP_ERR("SHM reserve failed\n");
		return -1;
	}

	memset(_odp_dma_glb, 0, sizeof(dma_global_t));
	_odp_dma_glb->shm = shm;

	odp_pool_param_init(&_odp_dma_glb->pool_param);

	if (odp_pool_capability(&_odp_dma_glb->pool_capa)) {
		_ODP_ERR("Pool capability failed\n");
		return -1;
	}

	for (i = 0; i < MAX_SESSIONS; i++)
		odp_ticketlock_init(&_odp_dma_glb->session[i].lock);

	return 0;
}

int _odp_dma_term_global(void)
{
	odp_shm_t shm;

	if (odp_global_ro.disable.dma)
		return 0;

	if (_odp_dma_glb == NULL)
		return 0;

	shm = _odp_dma_glb->shm;

	if (odp_shm_free(shm)) {
		_ODP_ERR("SHM free failed\n");
		return -1;
	}

	return 0;
}

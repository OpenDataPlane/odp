/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>

#include <odp/api/comp.h>
#include <odp/api/event.h>
#include <odp/api/packet.h>
#include <odp/api/plat/strong_types.h>
#include <odp_packet_internal.h>

#include <odp_debug_internal.h>
#include <odp_init_internal.h>

#include "miniz/miniz.h"

#define MAX_SESSIONS  16
#define MEM_LEVEL   8

/** Forward declaration of session structure */
typedef struct odp_comp_generic_session odp_comp_generic_session_t;

#define to_gen_session(s) ((odp_comp_generic_session_t *)(intptr_t)(s))

/**
 * Algorithm handler function prototype
 */
typedef
int (*comp_func_t)(odp_packet_t pkt_in,
		   odp_packet_t pkt_out,
		   const odp_comp_packet_op_param_t *params,
		   odp_comp_generic_session_t *session);

/**
 * Per session data structure
 */
struct odp_comp_generic_session {
	struct odp_comp_generic_session *next;
	odp_comp_session_param_t        params;
	struct {
		comp_func_t func;
		mz_stream stream;
		union {
			tdefl_compressor comp;
			inflate_state inflate;
		} data;
	} comp;
};

typedef struct odp_comp_global_s {
	odp_spinlock_t                lock;
	odp_shm_t global_shm;
	odp_comp_generic_session_t *free;
	odp_comp_generic_session_t  sessions[MAX_SESSIONS];
} odp_comp_global_t;

static odp_comp_global_t *global;

static
odp_comp_generic_session_t *alloc_session(void)
{
	odp_comp_generic_session_t *session = NULL;

	odp_spinlock_lock(&global->lock);
	session = global->free;
	if (session) {
		global->free = session->next;
		session->next = NULL;
	}
	odp_spinlock_unlock(&global->lock);

	return session;
}

static
void free_session(odp_comp_generic_session_t *session)
{
	odp_spinlock_lock(&global->lock);
	session->next = global->free;
	global->free = session;
	odp_spinlock_unlock(&global->lock);
}

static int
null_comp_routine(odp_packet_t pkt_in ODP_UNUSED,
		  odp_packet_t pkt_out ODP_UNUSED,
		  const odp_comp_packet_op_param_t *params ODP_UNUSED,
		  odp_comp_generic_session_t *session ODP_UNUSED)
{
	return 0;
}

static
odp_comp_packet_result_t *get_op_result_from_packet(odp_packet_t pkt)
{
	return &(packet_hdr(pkt)->comp_op_result);
}

void odp_comp_session_param_init(odp_comp_session_param_t *param)
{
	memset(param, 0, sizeof(odp_comp_session_param_t));
}

static void process_input(odp_packet_t pkt_out,
			  const odp_comp_packet_op_param_t *params,
			  odp_comp_generic_session_t *session,
			  odp_comp_packet_result_t *result,
			  odp_bool_t sync)
{
	mz_streamp streamp = &session->comp.stream;
	int ret = 0;
	uint8_t *out_data = NULL;
	uint32_t out_len = 0;
	uint32_t written = 0;
	uint32_t start = 0;
	uint32_t output_end = 0;
	uint32_t space_avail = 0;
	odp_packet_seg_t cur_seg = ODP_PACKET_SEG_INVALID;
	odp_packet_data_range_t *res_data_range;
	int finish = 0;

	res_data_range = &result->output_data_range;

	start = res_data_range->offset + res_data_range->length;
	space_avail = params->out_data_range.length -
		     res_data_range->length;
	output_end = space_avail + start;

	do {
		out_data =
		    odp_packet_offset(pkt_out, start, &out_len, &cur_seg);
		ODP_DBG("out_data 0x%x seg_data_ptr 0x%x out_len %d seg 0x%x\n",
			out_data, odp_packet_seg_data(pkt_out, cur_seg),
			out_len, cur_seg);

		if (0 == out_len) {
			/* there are no more segments */
			ODP_DBG("Ran out of space.  (streamp->avail_out) %d\n",
				(streamp->avail_out));
			result->status = ODP_COMP_STATUS_OUT_OF_SPACE_TERM;
			break;
		}

		/* if segment length is greater than user given available
		 * space, then adjust output len
		 */
		if (out_len > space_avail)
			out_len = space_avail;

		streamp->next_out = out_data;
		streamp->avail_out = out_len;

		ODP_DBG("next_in 0x%x, avail_in %d next_out 0x%lx"
			" avail_out %d, sync %d\n",
			streamp->next_in, streamp->avail_in,
			streamp->next_out,
			streamp->avail_out,
			sync);

		if (session->params.op == ODP_COMP_OP_COMPRESS)
			ret = mz_deflate(streamp,
					 sync ? MZ_FINISH : MZ_NO_FLUSH);
		else
			ret = mz_inflate(streamp, MZ_NO_FLUSH);

		ODP_DBG("ret %d streamp->avail_out %d avail_in %d\n",
			ret, streamp->avail_out, streamp->avail_in);

		out_len = out_len - streamp->avail_out;
		written += out_len;

		/* increase next offset by amount of data written into
		 * output buffer and decrease available space by amount
		 * of space consumed.
		 */
		start += out_len;
		space_avail -= out_len;

		ODP_DBG("ret %d,written %d\n", ret, out_len);

		if (ret == MZ_STREAM_END) {
			if (session->params.op == ODP_COMP_OP_COMPRESS) {
				/* required to continue processing of next pkt
				   with same stream */
				mz_deflateReset(streamp);
			} else {
				mz_inflateReset(streamp);
			}
			finish = 1;
			break;
		}
		if ((ret != MZ_BUF_ERROR) && (ret != MZ_OK)) {
			ODP_DBG("deflate failed. Err %s,ret %d"
				"(streamp->avail_out) %d\n",
				streamp->msg, ret, (streamp->avail_out));
			result->status = ODP_COMP_STATUS_FAILURE;
			return;
		}
	} while (!streamp->avail_out && (start < output_end));

	res_data_range->length += written;

	if ((!finish) && !(streamp->avail_out)) {
		/* if write stopped as output exhausted,
		   return OUT_OF_SPACE_ERR
		 */
		ODP_DBG("Ran out of space.  (out avail) %d,"
			"to process %d\n", streamp->avail_out,
			streamp->avail_in);
		result->status = ODP_COMP_STATUS_OUT_OF_SPACE_TERM;
	} else {
		result->status = ODP_COMP_STATUS_SUCCESS;
	}
}

/*
 * Deflate routine to perform deflate based compression/decompression
 *
 * NOTE: Current implementation does not support in-place
 */
static int deflate_comp(odp_packet_t pkt_in,
			odp_packet_t pkt_out,
			const odp_comp_packet_op_param_t *params,
			odp_comp_generic_session_t *session)
{
	mz_streamp streamp;
	uint8_t *data = NULL;
	uint32_t len;
	uint32_t in_len = 0;
	uint32_t read = 0;
	uint32_t consumed = 0;
	odp_bool_t sync = false;
	odp_packet_seg_t in_seg = ODP_PACKET_SEG_INVALID;
	odp_comp_packet_result_t *result = get_op_result_from_packet(pkt_out);

	ODP_ASSERT(session != NULL);
	ODP_ASSERT(params != NULL);
	ODP_ASSERT(pkt_in != ODP_PACKET_INVALID);
	ODP_ASSERT(pkt_out != ODP_PACKET_INVALID);

	streamp = &session->comp.stream;

	/* Adjust pointer for beginning of area to compress.
	   Since we need to pass phys cont area so we need to deal with segments
	   here as packet inherently are segmented and segments may not be
	   contiguous.
	 */

	read = params->in_data_range.offset;
	len = params->in_data_range.length;

	while (read < (len + params->in_data_range.offset)) {
		data = odp_packet_offset(pkt_in,
					 read,
					 &in_len,
					 &in_seg);
		ODP_DBG("data 0x%x in_len %d seg 0x%x len %d\n",
			data, in_len, in_seg, len);

		if (in_len > len)
			in_len = len;

		/* tracker for data consumed from input */
		consumed += in_len;
		streamp->next_in = data;
		streamp->avail_in = in_len;

		if (consumed >= len) {
			ODP_DBG("This is last chunk\n");
			sync = true;
		}

		process_input(pkt_out, params, session, result, sync);

		if (result->status != ODP_COMP_STATUS_SUCCESS)
			return -1;

		read += in_len;
	}

	ODP_DBG("Read %d Written %d\n",
		read,
		result->output_data_range.length);

	return 0;
}

static void *comp_zalloc(void *opaque, size_t items, size_t size)
{
	odp_comp_generic_session_t *session = opaque;

	if (items * size > sizeof(session->comp.data))
		return NULL;
	else
		return &session->comp.data;
}

static void comp_zfree(void *opaque ODP_UNUSED, void *data ODP_UNUSED)
{
	/* Do nothing */
}

static int deflate_init(odp_comp_generic_session_t *session)
{
	mz_streamp streamp = &session->comp.stream;
	uint32_t level;
	uint32_t strategy;
	int32_t window_bits;
	uint32_t cl;
	odp_comp_huffman_code_t cc;

	/* optional check as such may not required */
	ODP_ASSERT(strcmp(mz_version(), MZ_VERSION) == 0);

	memset(&session->comp.stream, 0, sizeof(mz_stream));

	/*  let zlib handles required memory allocations
	   we will identify if there any memory allocations issues that
	   may come b/w odp and zlib allocated memory
	 */
	streamp->zalloc = comp_zalloc;
	streamp->zfree = comp_zfree;
	streamp->opaque = session;

	switch (session->params.comp_algo) {
	case ODP_COMP_ALG_ZLIB:
		cl = session->params.alg_param.zlib.deflate.comp_level;
		cc = session->params.alg_param.zlib.deflate.huffman_code;
		window_bits = MZ_DEFAULT_WINDOW_BITS;
		break;
	case ODP_COMP_ALG_DEFLATE:
		cl = session->params.alg_param.deflate.comp_level;
		cc = session->params.alg_param.deflate.huffman_code;
		window_bits = -MZ_DEFAULT_WINDOW_BITS;
	break;
	default:
		return -1;
	}

	level = MZ_DEFAULT_COMPRESSION; /* Z_BEST_COMPRESSION; */
	if (cl)
		level = cl;

	switch (cc) {
	case ODP_COMP_HUFFMAN_DEFAULT:
	case ODP_COMP_HUFFMAN_DYNAMIC:/*Z_HUFFMAN_ONLY */
		strategy = MZ_DEFAULT_STRATEGY;
		break;
	case ODP_COMP_HUFFMAN_FIXED:
		strategy = MZ_FIXED;
		break;
	default:
		return -1;
	}
	ODP_DBG(" level %d strategy %d window %d\n",
		level, strategy, window_bits);

	if (ODP_COMP_OP_COMPRESS == session->params.op) {
		if (mz_deflateInit2(streamp, level, MZ_DEFLATED, window_bits,
				    MEM_LEVEL, strategy) != MZ_OK) {
			ODP_DBG("Err in Deflate Initialization %s\n",
				streamp->msg);
			return -1;
		}
	} else {
		if (mz_inflateInit2(streamp, window_bits) != MZ_OK) {
			ODP_DBG("Err in Inflate Initialization %s\n",
				streamp->msg);
			return -1;
		}
	}

	session->comp.func = deflate_comp;

	return 0;
}

static int term_def(odp_comp_generic_session_t *session)
{
	int rc = 0;
	mz_streamp streamp = &session->comp.stream;

	if (ODP_COMP_OP_COMPRESS == session->params.op) {
		rc = mz_deflateEnd(streamp);

		if (rc != MZ_OK) {
			ODP_ERR("deflateEnd failed. Err %s,rc %d\n",
				streamp->msg, rc);
			/* we choose to just return 0 with error info */
		}
	} else {
		rc = mz_inflateEnd(streamp);
		if (rc != MZ_OK) {
			ODP_ERR("inflateEnd failed. Err %s\n", streamp->msg);
			/* we choose to just return 0 with error info */
		}
	}

	return 0;
}

odp_comp_session_t
odp_comp_session_create(const odp_comp_session_param_t *params)
{
	odp_comp_generic_session_t *session;
	int rc;

	/* Allocate memory for this session */
	session = alloc_session();
	if (NULL == session)
		return ODP_COMP_SESSION_INVALID;

	/* Copy stuff over */
	memcpy(&session->params, params, sizeof(*params));

	/* Process based on compress */
	switch (params->comp_algo) {
	case ODP_COMP_ALG_NULL:
		session->comp.func = null_comp_routine;
		break;
	case ODP_COMP_ALG_DEFLATE:
	case ODP_COMP_ALG_ZLIB:
		rc = deflate_init(session);
		if (rc < 0)
			goto cleanup;
		break;
	default:
		rc = -1;
		goto cleanup;
	}

	return (odp_comp_session_t)session;

cleanup:
	free_session(session);

	return ODP_COMP_SESSION_INVALID;
}

int odp_comp_session_destroy(odp_comp_session_t session)
{
	odp_comp_generic_session_t *generic;
	int32_t rc = 0;

	generic = (odp_comp_generic_session_t *)(intptr_t)session;

	switch (generic->params.comp_algo) {
	case ODP_COMP_ALG_DEFLATE:
	case ODP_COMP_ALG_ZLIB:
		rc = term_def(generic);
		break;
	default:
		break;
	}
	if (rc < 0) {
		ODP_ERR("Compression Unit could not be terminated\n");
		return -1;
	}

	memset(generic, 0, sizeof(*generic));
	free_session(generic);
	return 0;
}

int odp_comp_capability(odp_comp_capability_t *capa)
{
	if (NULL == capa)
		return -1;

	/* Initialize comp capability structure */
	memset(capa, 0, sizeof(odp_comp_capability_t));

	capa->comp_algos.bit.null = 1;
	capa->comp_algos.bit.deflate = 1;
	capa->comp_algos.bit.zlib = 1;
	capa->hash_algos.bit.none = 1;
	capa->sync = ODP_SUPPORT_YES;
	capa->async = ODP_SUPPORT_YES;
	capa->max_sessions = MAX_SESSIONS;
	return 0;
}

int
odp_comp_alg_capability(odp_comp_alg_t comp,
			odp_comp_alg_capability_t *capa)
{
	switch (comp) {
	case ODP_COMP_ALG_ZLIB:
		capa->hash_algo.all_bits = 0;
		capa->hash_algo.bit.none = 1;
		capa->max_level = MZ_BEST_COMPRESSION;
		capa->compression_ratio = 50;
		return 0;
	case ODP_COMP_ALG_DEFLATE:
		capa->hash_algo.all_bits = 0;
		capa->hash_algo.bit.none = 1;
		capa->max_level = MZ_BEST_COMPRESSION;
		capa->compression_ratio = 50;
		return 0;
	default:
		/* Error unsupported enum */
		return -1;
	}
	return -1;
}

int
odp_comp_hash_alg_capability(odp_comp_hash_alg_t hash,
			     odp_comp_hash_alg_capability_t *capa)
{
	(void)capa;
	switch (hash) {
	case ODP_COMP_HASH_ALG_NONE:
		capa[0].digest_len = 0;
		return 0;
	default:
		return -1;
	}
	return -1;
}

static int _odp_comp_single(odp_packet_t pkt_in, odp_packet_t pkt_out,
			    const odp_comp_packet_op_param_t *param)
{
	odp_comp_generic_session_t *session;
	odp_comp_packet_result_t *result;
	int rc;

	session = to_gen_session(param->session);
	ODP_ASSERT(session);
	ODP_ASSERT(pkt_in != ODP_PACKET_INVALID);
	ODP_ASSERT(pkt_out != ODP_PACKET_INVALID);

	result = get_op_result_from_packet(pkt_out);
	ODP_ASSERT(result);

	result->pkt_in = pkt_in;
	result->output_data_range.offset = param->out_data_range.offset;
	result->output_data_range.length = 0;

	packet_subtype_set(pkt_out, ODP_EVENT_PACKET_COMP);

	rc = session->comp.func(pkt_in, pkt_out, param, session);
	if (rc < 0)
		return rc;

	return 0;
}

int odp_comp_op(const odp_packet_t pkt_in[], odp_packet_t pkt_out[],
		int num_pkt, const odp_comp_packet_op_param_t param[])
{
	int i;
	int rc;

	for (i = 0; i < num_pkt; i++) {
		rc = _odp_comp_single(pkt_in[i], pkt_out[i], &param[i]);
		if (rc < 0)
			break;
	}

	return i;
}

int odp_comp_op_enq(const odp_packet_t pkt_in[], odp_packet_t pkt_out[],
		    int num_pkt, const odp_comp_packet_op_param_t param[])
{
	int i;
	int rc;

	for (i = 0; i < num_pkt; i++) {
		odp_event_t event;
		odp_comp_generic_session_t *session;

		rc = _odp_comp_single(pkt_in[i], pkt_out[i], &param[i]);
		if (rc < 0)
			break;

		event = odp_packet_to_event(pkt_out[i]);
		session = to_gen_session(param[i].session);
		if (odp_queue_enq(session->params.compl_queue, event)) {
			odp_event_free(event);
			break;
		}
	}

	return i;
}

int odp_comp_result(odp_comp_packet_result_t *result,
		    odp_packet_t packet)
{
	odp_comp_packet_result_t *op_result;

	ODP_ASSERT(odp_event_subtype(odp_packet_to_event(packet))
		   == ODP_EVENT_PACKET_COMP);

	op_result = get_op_result_from_packet(packet);
	ODP_DBG("Copy operational result back\n");
	memcpy(result, op_result, sizeof(*result));
	return 0;
}

int _odp_comp_init_global(void)
{
	size_t mem_size;
	odp_shm_t shm;
	int idx;

	/* Calculate the memory size we need */
	mem_size = sizeof(*global);

	/* Allocate our globally shared memory */
	shm = odp_shm_reserve("comp_pool", mem_size, ODP_CACHE_LINE_SIZE, 0);

	global = odp_shm_addr(shm);

	/* Clear it out */
	memset(global, 0, mem_size);
	global->global_shm = shm;

	/* Initialize free list and lock */
	for (idx = 0; idx < MAX_SESSIONS; idx++) {
		global->sessions[idx].next = global->free;
		global->free = &global->sessions[idx];
	}
	odp_spinlock_init(&global->lock);

	return 0;
}

int _odp_comp_term_global(void)
{
	int rc = 0;
	int ret;
	int count = 0;
	odp_comp_generic_session_t *session;

	for (session = global->free; session != NULL; session = session->next)
		count++;

	if (count != MAX_SESSIONS) {
		ODP_ERR("comp sessions still active\n");
		rc = -1;
	}

	ret = odp_shm_free(global->global_shm);
	if (ret < 0) {
		ODP_ERR("shm free failed for comp_pool\n");
		rc = -1;
	}

	return rc;
}

odp_packet_t odp_comp_packet_from_event(odp_event_t ev)
{
	/* This check not mandated by the API specification */
	ODP_ASSERT(odp_event_type(ev) == ODP_EVENT_PACKET);
	ODP_ASSERT(odp_event_subtype(ev) == ODP_EVENT_PACKET_COMP);

	return odp_packet_from_event(ev);
}

odp_event_t odp_comp_packet_to_event(odp_packet_t pkt)
{
	return odp_packet_to_event(pkt);
}

/** Get printable format of odp_comp_session_t */
uint64_t odp_comp_session_to_u64(odp_comp_session_t hdl)
{
	return _odp_pri(hdl);
}

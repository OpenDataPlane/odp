/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "config.h"
#include <stdio.h>
#include <odp_posix_extensions.h>
#include <fcntl.h>
#include <odp/api/comp.h>
#include <odp_internal.h>
#include <odp/api/atomic.h>
#include <odp/api/spinlock.h>
#include <odp/api/sync.h>
#include <odp/api/debug.h>
#include <odp/api/align.h>
#include <odp/api/shared_memory.h>
#include <odp_comp_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/random.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp_packet_internal.h>
#include <openssl/evp.h>
#include <string.h>

#include <zlib.h>

#define MAX_SESSIONS  16
#define WINDOW_BITS 15
#define MEM_LEVEL   8
#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif

#define ODP_COMP_ALG_NUM (ODP_COMP_ALG_LZS + 1)
#define ODP_COMP_MAX_LEVEL 3

/* #define DBG_COMP */

typedef struct comp_ctx_s {
	z_streamp streamp;
	odp_packet_t out_pkt;	/* buffer to hold compression o/p */
	odp_bool_t pending;
	uint32_t read;		/*mount of input data read so far. not
				specifically mean processed */
	uint32_t len;		/*ength of request */
	odp_packet_t in_pkt;
	uint32_t sync;
	uint8_t  *md;
	uint8_t  md_len;
	int      hash_pending;
} comp_ctx_t;

typedef struct odp_comp_global_s odp_comp_global_t;

struct odp_comp_global_s {
	odp_spinlock_t lock;
	odp_comp_capability_t capa;
	odp_comp_alg_capability_t algo_capa[ODP_COMP_ALG_NUM];
	odp_comp_generic_session_t *free;
	odp_comp_generic_session_t sessions[0];
};

static odp_comp_global_t *global;

#ifdef DBG_COMP
static FILE *gdfile;
static void dump(void *data, int len)
{
	if (gdfile == NULL)
		gdfile = fopen("dump", "wb");
		if (gdfile == NULL)
			printf("Couldn't open dump file\n");
	if (gdfile)
		fwrite(data, 1, len, gdfile);
}
#endif

static
odp_comp_generic_op_result_t *get_op_result_from_packet(odp_packet_t pkt)
{
	return &(odp_packet_hdr(pkt)->comp_result);
}

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
null_comp_routine(odp_comp_op_param_t *params ODP_UNUSED,
		  odp_comp_generic_session_t *session ODP_UNUSED,
		  odp_comp_op_result_t *result)
{
	result->err = ODP_COMP_ERR_NONE;
	return 0;
}

static int compute_digest(odp_comp_generic_session_t *session,
			  uint8_t *data,
			  uint32_t len)
{
	if (session->params.hash_algo == ODP_COMP_HASH_ALG_NONE)
		return 0;

	EVP_MD_CTX *mdctx = (EVP_MD_CTX *) session->hash.ctx;

	if (session->hash.init == 0) {
		EVP_DigestInit_ex(mdctx, session->hash.dt, NULL);
		session->hash.init = 1;
	}
	if (!EVP_DigestUpdate(mdctx, (const void *)data, (size_t)len))
		return -1;
	return 0;
}

static
int sha_gen(odp_comp_generic_session_t *session,
	    odp_comp_op_result_t *result)
{
	uint32_t md_len;
	EVP_MD_CTX *mdctx = (EVP_MD_CTX *)session->hash.ctx;
	odp_packet_t out_pkt = result->output.pkt.packet;
	odp_packet_data_range_t *dr = &result->output.pkt.data_range;
	comp_ctx_t *ctxp = session->comp.ctx;
	uint8_t *data;
	int ret;

	ODP_DBG("result->data_range.length %d b\n",
		result->output.pkt.data_range.length);

	if (ctxp->hash_pending) {
		data = ctxp->md;
		md_len = ctxp->md_len;
	} else {
		EVP_DigestFinal_ex(mdctx, session->hash.md, &md_len);
		data = session->hash.md;
		session->hash.init = 0;
	}

	uint32_t avail_inpkt = odp_packet_len(out_pkt) - dr->offset;

	if (avail_inpkt >= md_len)
		avail_inpkt = md_len;

	ret = odp_packet_copy_from_mem(out_pkt,
				       dr->offset + dr->length,
				       avail_inpkt,
				       (const void *)data);
	if (ret < 0)
		ODP_DBG("odp_packet_copy_from_mem() failed\n");

	dr->length += avail_inpkt;
	if (md_len > avail_inpkt) {
		md_len -= avail_inpkt;
		ctxp->md = data + avail_inpkt;
		ctxp->md_len = md_len;
		result->err = ODP_COMP_ERR_OUT_OF_SPACE;
		ctxp->hash_pending = 1;
	} else {
		result->err = ODP_COMP_ERR_NONE;
		ctxp->hash_pending = 0;
	}

	ODP_DBG("result->data_range.length %d\n", dr->length);
	return 0;
}

static
int init_sha(odp_comp_generic_session_t *session)
{
	EVP_MD_CTX *mdctx = NULL;

	/* Convert keys */
	mdctx = EVP_MD_CTX_create();

	switch (session->params.hash_algo) {
	case ODP_COMP_HASH_ALG_SHA256:
		EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
		session->hash.md = malloc(SHA256_DIGEST_LENGTH);
		break;
	case ODP_COMP_HASH_ALG_SHA1:
		EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
		session->hash.md = malloc(SHA_DIGEST_LENGTH);
		break;
	default:
		/*his should never come */
		break;
	}

	if (session->hash.md == NULL)
		return -1;

	session->hash.ctx = (void *)mdctx;

	return 0;
}

static int term_sha(odp_comp_generic_session_t *session)
{
	EVP_MD_CTX_destroy((EVP_MD_CTX *)session->hash.ctx);
	free(session->hash.md);
	session->hash.md = NULL;
	return 0;
}

static void reset_ctx(comp_ctx_t *ctxp)
{
	ctxp->hash_pending = 0;
	ctxp->pending = 0;
	ctxp->out_pkt = ODP_PACKET_INVALID;
	ctxp->in_pkt = ODP_PACKET_INVALID;
	ctxp->len = 0;
	if (ctxp->md != NULL)
		ctxp->md = NULL;
	ctxp->md_len = 0;
	ctxp->read = 0;
	ctxp->sync = 0;
}

static int process_input(odp_comp_op_param_t *params,
			 odp_comp_generic_session_t *session,
			 odp_comp_op_result_t *result)
{
	int ret = 0;
	comp_ctx_t *ctxp = NULL;
	z_streamp strmp;
	uint8_t *out_data = NULL;
	uint32_t out_len = 0;
	uint32_t written = 0;
	uint32_t start = 0;
	uint32_t output_end = 0;
	uint32_t space_avail = 0;
	odp_packet_seg_t cur_seg = ODP_PACKET_SEG_INVALID;
	uint32_t sync;
	odp_packet_data_range_t *res_data_range;
	int finish = 0;

	ctxp = (comp_ctx_t *)(session->comp.ctx);
	strmp = ctxp->streamp;
	sync = ctxp->sync;
	res_data_range = &result->output.pkt.data_range;

	/* start = params->output.pkt.data_range.offset; */
	start = res_data_range->offset + res_data_range->length;
	space_avail = params->output.pkt.data_range.length -
		     res_data_range->length;
	output_end = space_avail + start;

	do {
		out_data =
		    odp_packet_offset(ctxp->out_pkt, start, &out_len, &cur_seg);
		ODP_DBG("out_data 0x%x seg_data_ptr 0x%x out_len %d seg 0x%x\n",
			out_data, odp_packet_seg_data(ctxp->out_pkt, cur_seg),
			out_len, cur_seg);

		if (0 == out_len) {
			/* there are no more segments */
			ODP_DBG("Ran out of space.  (strmp->avail_out) %d\n",
				(strmp->avail_out));
			result->err = ODP_COMP_ERR_OUT_OF_SPACE;
			break;
		}

		if (out_len > space_avail) {
			/* if segment length is greater than
			 * user given available space, then
			 * adjust output len
			 */
			 out_len = space_avail;
		}

		strmp->next_out = out_data;
		strmp->avail_out = out_len;

		ODP_DBG("next_in 0x%x, avail_in %d next_out 0x%lx"
			" avail_out %d, sync %d\n",
			strmp->next_in, strmp->avail_in,
			strmp->next_out,
			strmp->avail_out,
			sync);

		if (session->params.op == ODP_COMP_OP_COMPRESS)
			ret = deflate(strmp, sync);
		else
			ret = inflate(strmp, sync);

		ODP_DBG("ret %d strmp->avail_out %d avail_in %d\n",
			ret, strmp->avail_out, strmp->avail_in);

		out_len = out_len - strmp->avail_out;
		written += out_len;

#ifdef DBG_COMP
		dump(strmp->next_out, out_len);
#endif
		if (session->params.op == ODP_COMP_OP_DECOMPRESS)
			compute_digest(session, out_data, out_len);

		/* increase next offset by amount of data written into
		 * output buffer and decrease available space by amount
		 * of space consumed.
		 */
		start += out_len;
		space_avail -= out_len;

		ODP_DBG("ret %d,written %d\n", ret, out_len);

		if (ret == Z_STREAM_END) {
			if (session->params.op == ODP_COMP_OP_COMPRESS) {
				/* required to continue processing of next pkt
				   with same stream */
				deflateReset(strmp);
			} else {
				inflateReset(strmp);
			}
			finish = 1;
			break;
		}
		if ((ret != Z_BUF_ERROR) && (ret != Z_OK)) {
			ODP_DBG("deflate failed. Err %s,ret %d"
				"(strmp->avail_out) %d\n",
				strmp->msg, ret, (strmp->avail_out));
			result->err = ODP_COMP_ERR_ALGO_FAIL;
			return -1;
		}
	} while (!strmp->avail_out && (start < output_end));

	res_data_range->length = written;
	/* res_data_range->length += written; */
	res_data_range->offset = params->output.pkt.data_range.offset;
	result->output.pkt.packet = ctxp->out_pkt;

	if ((!finish) && !(strmp->avail_out)) {
		/* if write stopped as output exhausted,
		   return OUT_OF_SPACE_ERR
		 */
		ODP_DBG("Ran out of space.  (out avail) %d,"
			"to process %d\n", strmp->avail_out, strmp->avail_in);
		result->err = ODP_COMP_ERR_OUT_OF_SPACE;
	} else if (finish &&
		   (session->params.hash_algo != ODP_COMP_HASH_ALG_NONE)) {
		ret = sha_gen(session, result);
	} else {
		ctxp->pending = 0;
		result->err = ODP_COMP_ERR_NONE;
	}

#ifdef DBG_COMP
	for (uint32_t i = 0; i < written; i++)
		printf("0x%x ", out_data[i]);
	printf("\n");
#endif
	return 0;
}

/*
 * Deflate routine to perform deflate based compression/decompression
 *
 * NOTE: Current implementation does not support in-place
 *
*/
static int do_deflate(odp_comp_op_param_t *params,
		      odp_comp_generic_session_t *session,
		      odp_comp_op_result_t *result)
{
	int32_t ret;
	z_streamp strmp;
	comp_ctx_t *ctxp = NULL;
	uint8_t *data = NULL;
	uint32_t len;
	uint32_t in_len = 0;
	uint32_t read = 0;
	odp_packet_seg_t in_seg = ODP_PACKET_SEG_INVALID;
	odp_packet_t in_pkt;

	ODP_ASSERT(session != NULL);
	ODP_ASSERT(params != NULL);
	ODP_ASSERT(params->output.pkt.packet != ODP_PACKET_INVALID);

	ctxp = (comp_ctx_t *)(session->comp.ctx);
	strmp = ctxp->streamp;
	ctxp->out_pkt = params->output.pkt.packet;

	if (ctxp->pending) {
		ODP_DBG("Resume last pending request\n");
		if (ctxp->hash_pending)
			ret = sha_gen(session, result);
		else
			ret = process_input(params, session, result);

		if (result->err != ODP_COMP_ERR_OUT_OF_SPACE)
				reset_ctx(ctxp);
		return ret;
	}

	/* Adjust pointer for beginning of area to compress.
	   Since we need to pass phys cont area so we need to deal with segments
	   here as packet inherently are segmented and segments may not be
	   contiguous.
	 */

	read = params->input.pkt.data_range.offset;
	len = params->input.pkt.data_range.length;
	in_pkt = params->input.pkt.packet;
	uint32_t consumed = 0;

	while (read < (len + params->input.pkt.data_range.offset)) {
		data = odp_packet_offset(in_pkt,
					 read,
					 &in_len,
					 &in_seg);
		ODP_DBG("data 0x%x in_len %d seg 0x%x len %d\n",
			data, in_len, in_seg, len);

		if (in_len > len)
			in_len = len;

		/* tracker for data consumed from input */
		consumed += in_len;
#ifdef DBG_COMP
		/* dump(data,in_len); */
#endif
		strmp->next_in = data;
		strmp->avail_in = in_len;

		if (params->last && consumed >= len) {
			ODP_DBG("This is last chunk\n");
			ctxp->sync = Z_FINISH;
		} else {
			ctxp->sync = Z_NO_FLUSH;
		}

		if (session->params.op == ODP_COMP_OP_COMPRESS)
			compute_digest(session, data, in_len);

		ret = process_input(params, session, result);

		if (result->err == ODP_COMP_ERR_OUT_OF_SPACE) {
			/* there are no more segments */
			read += in_len;
			ctxp->read = read;
			ctxp->pending = 1;
			ctxp->in_pkt = in_pkt;
			ctxp->len = len;
			return -1;
		}
		if (result->err != ODP_COMP_ERR_NONE) {
			reset_ctx(ctxp);
			return -1;
		}
		read += in_len;
	}

	ODP_DBG("Read %d Written %d\n",
		read,
		(int)result->output.pkt.data_range.length);

	reset_ctx(ctxp);

	return 0;
}

static int init_def(odp_comp_generic_session_t *session,
		    odp_comp_session_param_t *params)
{
	comp_ctx_t *comp_ctxp = NULL;
	z_streamp streamp = NULL;
	uint32_t level;
	uint32_t strategy;
	int32_t window_bits = WINDOW_BITS;
	odp_comp_level_t cl;
	odp_comp_huffman_code_t cc;
	/* look for alignment here */
	int malloc_len = sizeof(z_stream) + sizeof(*comp_ctxp);

	ODP_DBG("%s Enter\n", __func__);
	/* optional check as such may not required */
	ODP_ASSERT(strcmp(zlibVersion(), ZLIB_VERSION) == 0);

	comp_ctxp = (comp_ctx_t *)malloc(sizeof(comp_ctx_t));
	if (comp_ctxp == NULL)
		return ODP_COMP_SES_CREATE_ERR_ENOMEM;

	memset(comp_ctxp, 0, sizeof(comp_ctx_t));

	streamp = (z_streamp)malloc(malloc_len);
	if (streamp == NULL) {
		free(comp_ctxp);
		comp_ctxp = NULL;
		return ODP_COMP_SES_CREATE_ERR_ENOMEM;
	}

	memset(streamp, 0, sizeof(z_stream));

	/*  let zlib handles required memory allocations
	   we will identify if there any memory allocations issues that
	   may come b/w odp and zlib allocated memory
	 */
	streamp->zalloc = NULL;
	streamp->zfree = NULL;

	switch (params->comp_algo) {
	case ODP_COMP_ALG_ZLIB:
		cl = params->algo_param.zlib.def.level;
		cc = params->algo_param.zlib.def.comp_code;
	break;
	case ODP_COMP_ALG_DEFLATE:
		cl = params->algo_param.deflate.level;
		cc = params->algo_param.deflate.comp_code;
		window_bits = -window_bits;
	break;
	default:
		return ODP_COMP_SES_CREATE_ERR_INV_COMP;
	}

	level = Z_DEFAULT_COMPRESSION; /* Z_BEST_COMPRESSION; */
	if (cl != ODP_COMP_LEVEL_DEFAULT) {
			/*
			Current distribution is like:

			if level falls in lower half = set level to
			best speed
			if level falls in middle == set default
			if level falls in upper hald = set level to
			best compression

			please note this is reference distribution.
			this can be tuned to generate more uniform
			distributation by uniformly distributing
			range between speed vs default vs level.
		*/

		odp_comp_level_t mid =
			(global->algo_capa[params->comp_algo].max_level +
			 1) >> 1;

		if (cl == ODP_COMP_LEVEL_MIN ||
		    cl < mid)
			level = Z_BEST_SPEED;
		else if (cl > mid ||
			 cl == ODP_COMP_LEVEL_MAX)
			level = Z_BEST_COMPRESSION;
	}

	switch (cc) {
	case ODP_COMP_HUFFMAN_CODE_DEFAULT:
	case ODP_COMP_HUFFMAN_CODE_DYNAMIC:/*Z_HUFFMAN_ONLY */
		strategy = Z_DEFAULT_STRATEGY;
		break;
	case ODP_COMP_HUFFMAN_CODE_FIXED:
		strategy = Z_FIXED;
		break;
	default:
		return ODP_COMP_SES_CREATE_ERR_NOT_SUPPORTED;
	}
	ODP_DBG(" level %d strategy %d window %d\n",
		level, strategy, window_bits);

	if (ODP_COMP_OP_COMPRESS == params->op) {
		/*  Or use deflateInit2. Using deflateInit2 can produce
		    raw deflate data as well. See cavm_zlib implementation once
		 */
		ODP_DBG("%s:%d\n", __FILE__, __LINE__);
		if (deflateInit2(streamp, level, Z_DEFLATED, window_bits,
				 MEM_LEVEL, strategy) != Z_OK) {
			ODP_DBG("Err in Deflate Initialization %s\n",
				streamp->msg);
			free(streamp);
			free(comp_ctxp);
			streamp = NULL;
			comp_ctxp = NULL;
			return ODP_COMP_SES_CREATE_ERR_ENOMEM;
		}
	} else {
		if (inflateInit2(streamp, window_bits) != Z_OK) {
			ODP_DBG("Err in Inflate Initialization %s\n",
				streamp->msg);
			free(streamp);
			free(comp_ctxp);
			streamp = NULL;
			comp_ctxp = NULL;
			return ODP_COMP_SES_CREATE_ERR_ENOMEM;
		}
	}

	session->comp.func = do_deflate;

	comp_ctxp->streamp = streamp;
	comp_ctxp->out_pkt = ODP_PACKET_INVALID;

	session->comp.ctx = (void *)comp_ctxp;

	return 0;
}

static int term_def(odp_comp_generic_session_t *session)
{
	int rc = 0;
	comp_ctx_t *ctxp = session->comp.ctx;
	z_streamp streamp = ctxp->streamp;

	if (ODP_COMP_OP_COMPRESS == session->params.op) {
		if (ODP_COMP_ALG_DEFLATE == session->params.comp_algo) {
			/*fake end to move state to finish_state
			   zlib issue with raw deflate as deflateReset()/
			   deflateInit() move state to BUSY_STATE for RawDeflate
			   which is equals to INIT_STATE where as for zlib
			   format, marks state to INIT_STATE. And deflateEnd()
			   always assumes BUSY means in the middle of operation.
			   Thus throws error so following works for zlib but
			   not RawDeflate
			   deflateInit2()<== set state to INIT for zlib, BUSY
			   for raw
			   deflateEnd()<==fails for raw as it sees state as
			   BUSY.
			 */
			deflate(streamp, Z_FINISH);
		}
		rc = deflateEnd(streamp);

		if (rc != Z_OK) {
			ODP_ERR("deflateEnd failed. Err %s,rc %d\n",
				streamp->msg, rc);
			/* we choose to just return 0 with error info */
		}
	} else {
		rc = inflateEnd(streamp);
		if (rc != Z_OK) {
			ODP_ERR("inflateEnd failed. Err %s\n", streamp->msg);
			/* we choose to just return 0 with error info */
		}
	}

	free(streamp);
	streamp = NULL;
	free(ctxp);
	ctxp = NULL;
#ifdef ODP_COMP
	if (gdfile != NULL) {
		fclose(gdfile);
		gdfile = NULL;
	}
#endif
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
	capa->hash_algos.bit.sha1 = 1;
	capa->hash_algos.bit.sha256 = 1;
	capa->sync = ODP_SUPPORT_YES;
	capa->async = ODP_SUPPORT_YES;
	capa->max_sessions = MAX_SESSIONS;
	return 0;
}

int
odp_comp_alg_capability(odp_comp_alg_t comp,
			odp_comp_alg_capability_t capa[], int num)
{
	if (num <= 0)
		return -1;

	switch (comp) {
	case ODP_COMP_ALG_ZLIB:
		capa[0].support_dict = 1;
		capa[0].dict_len = 32 * 1024;
		capa[0].hash_algo.all_bits = 1;
		capa[0].support_dict = 0;
		/* sw zlib support 3 - Z_BEST_SPEED, Z_BEST_COMPRESSION
		   and DEFAULT
		*/
		capa[0].max_level = Z_BEST_COMPRESSION;
		return 1;
	case ODP_COMP_ALG_DEFLATE:
		capa[0].hash_algo.all_bits = 1;
		capa[0].support_dict = 0;
		capa[0].max_level = Z_BEST_COMPRESSION;
		return 1;
	default:
		/* Error unsupported enum */
		return -1;
	}
	return -1;
}

int
odp_comp_hash_alg_capability(odp_comp_hash_alg_t hash,
			     odp_comp_hash_alg_capability_t capa[],
			     int num)
{
	if (num <= 0)
		return -1;

	switch (hash) {
	case ODP_COMP_HASH_ALG_SHA1:
		capa[0].digest_len = SHA_DIGEST_LENGTH;
		return 1;
	case ODP_COMP_HASH_ALG_SHA256:
		capa[0].digest_len = SHA256_DIGEST_LENGTH;
		return 1;
	default:
		return -1;
	}
	return -1;
}

void odp_comp_session_param_init(odp_comp_session_param_t *param)
{
	memset(param, 0, sizeof(odp_comp_session_param_t));
}

int odp_comp_set_dict(odp_comp_session_t session,
		      const odp_comp_dict_t *dict)
{
	odp_comp_generic_session_t *gen_session;

	gen_session = (odp_comp_generic_session_t *)(intptr_t)session;
	comp_ctx_t *comp_ctx;
	int ret;

	if (NULL == gen_session) {
		ODP_ERR("Invalid session\n");
		return -1;
	}

	if (!global->algo_capa[gen_session->params.comp_algo].support_dict) {
		ODP_ERR("Algorithm doesn't support dictionary\n");
		return -1;
	}

	comp_ctx = (comp_ctx_t *)(gen_session->comp.ctx);

	if (gen_session->params.op == ODP_COMP_OP_COMPRESS) {
		ret = deflateSetDictionary(comp_ctx->streamp,
					   (const Bytef *)(dict->buf),
					   (uInt)(dict->len));
	} else {
		ret = inflateSetDictionary(comp_ctx->streamp,
					   (const Bytef *)(dict->buf),
					   (uInt)(dict->len));
	}
	return ret;
}

int
odp_comp_session_create(odp_comp_session_param_t *params,
			odp_comp_session_t *session_out,
			odp_comp_ses_create_err_t *status)
{
	odp_comp_generic_session_t *session;
	int rc;
	/* Default to successful result */
	*status = ODP_COMP_SES_CREATE_ERR_NONE;

	/* Allocate memory for this session */
	session = alloc_session();
	if (NULL == session) {
		*status = ODP_COMP_SES_CREATE_ERR_ENOMEM;
		return -1;
	}

	/* Copy stuff over */
	memcpy(&session->params, params, sizeof(*params));

	/* Process based on compress */
	switch (params->comp_algo) {
	case ODP_COMP_ALG_NULL:
		session->comp.func = null_comp_routine;
		break;
	case ODP_COMP_ALG_DEFLATE:
	case ODP_COMP_ALG_ZLIB:
		rc = init_def(session, params);
		if (rc < 0)
			return rc;
		break;
	default:
		*status = ODP_COMP_SES_CREATE_ERR_INV_COMP;
		return -1;
	}

	switch (params->hash_algo) {
	case ODP_COMP_HASH_ALG_SHA256:
	case ODP_COMP_HASH_ALG_SHA1:
		rc = init_sha(session);
		break;
	default:
		break;
	}

	*session_out = (intptr_t)session;
	return 0;
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

	switch (generic->params.hash_algo) {
	case ODP_COMP_HASH_ALG_SHA256:
	case ODP_COMP_HASH_ALG_SHA1:
		rc = term_sha(generic);
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

int
odp_comp_compress(odp_comp_op_param_t *params, odp_comp_op_result_t *result)
{
	odp_comp_generic_session_t *session;
	odp_comp_generic_op_result_t *op_result;
	int rc;

	session = (odp_comp_generic_session_t *)(intptr_t)params->session;
	if (NULL == session) {
		ODP_ERR("Invalid session\n");
		return -1;
	}
	/* Resolve output buffer */
	if (ODP_PACKET_INVALID == params->output.pkt.packet)
		ODP_ABORT();

	/* Fill in result */
	result->ctx = params->ctx;
	result->output.pkt.packet = params->output.pkt.packet;
	result->output.pkt.data_range.offset =
		params->output.pkt.data_range.offset;
	result->output.pkt.data_range.length = 0;

	/* Invoke the functions */
	rc = session->comp.func(params, session, result);
	if (rc < 0 && result->err != ODP_COMP_ERR_OUT_OF_SPACE)
		return rc;

	_odp_buffer_event_subtype_set(packet_to_buffer
				      (params->output.pkt.packet),
				      ODP_EVENT_PACKET_COMP);

	op_result = get_op_result_from_packet(params->output.pkt.packet);

	/* Mark queued result as complete */
	memcpy(&op_result->result, result, sizeof(*op_result));

	/* If specified during creation post event to completion queue */
	if (ODP_COMP_ASYNC == session->params.mode) {
		odp_event_t completion_event;

		/* Linux generic will always use packet for completion event */
		completion_event = odp_packet_to_event
					(params->output.pkt.packet);

		ODP_DBG("Enqueue Event\n");
		if (odp_queue_enq(session->params.compl_queue,
				  completion_event)) {
			odp_event_free(completion_event);
			return -1;
		}
	}
	return 0;
}

int
odp_comp_compress_enq(odp_comp_op_param_t *params)
{
	odp_comp_op_result_t result;
	int ret;

	ret = odp_comp_compress(params, &result);
	return ret;
}

int
odp_comp_decomp(odp_comp_op_param_t *params, odp_comp_op_result_t *result)
{
	odp_comp_generic_session_t *session;

	session = (odp_comp_generic_session_t *)(intptr_t)params->session;
	if (NULL == session) {
		ODP_ERR("Invalid session\n");
		return -1;
	}
	/* Resolve output buffer */
	if (ODP_PACKET_INVALID == params->output.pkt.packet)
		ODP_ABORT();

	/* Fill in result */
	result->ctx = params->ctx;
	result->output.pkt.packet = params->output.pkt.packet;
	result->output.pkt.data_range.offset =
		params->output.pkt.data_range.offset;
	result->output.pkt.data_range.length = 0;

	return session->comp.func(params, session, result);
}

int
odp_comp_decomp_enq(odp_comp_op_param_t *params)
{
	int ret;
	odp_event_t completion_event;
	odp_comp_generic_op_result_t *op_result;
	struct odp_comp_generic_session *session;

	session = (struct odp_comp_generic_session *)(intptr_t)params->session;

	/* Linux generic will always use packet for completion event */
	completion_event = odp_packet_to_event
				(params->output.pkt.packet);

	op_result = get_op_result_from_packet(params->output.pkt.packet);

	ret = odp_comp_decomp(params, &op_result->result);
	if (ret < 0 && op_result->result.err != ODP_COMP_ERR_OUT_OF_SPACE)
		return -1;

	/* Asynchronous, build result (no HW so no errors) and send
	   it */
	_odp_buffer_event_subtype_set(packet_to_buffer
				     (params->output.pkt.packet),
				     ODP_EVENT_PACKET_COMP);

	/* Mark queued result as complete */
	ODP_DBG("Enqueue Event\n");
	if (odp_queue_enq(session->params.compl_queue,
			  completion_event)) {
		odp_event_free(completion_event);
		return -1;
	}
	return 0;
}

int odp_comp_init_global(void)
{
	size_t mem_size;
	odp_shm_t shm;
	int idx;

	/* Calculate the memory size we need */
	mem_size = sizeof(*global);
	mem_size += (MAX_SESSIONS * sizeof(odp_comp_generic_session_t));

	/* Allocate our globally shared memory */
	shm = odp_shm_reserve("comp_pool", mem_size, ODP_CACHE_LINE_SIZE, 0);

	global = odp_shm_addr(shm);

	/* Clear it out */
	memset(global, 0, mem_size);

	/* Initialize free list and lock */
	for (idx = 0; idx < MAX_SESSIONS; idx++) {
		global->sessions[idx].next = global->free;
		global->free = &global->sessions[idx];
	}
	odp_spinlock_init(&global->lock);
	global->capa.async = ODP_SUPPORT_NO;
	global->capa.sync = ODP_SUPPORT_YES;
	global->capa.comp_algos.bit.deflate = 1;
	global->capa.hash_algos.all_bits = 0;
	global->capa.max_sessions = MAX_SESSIONS;
	memset(global->algo_capa, 0, sizeof(global->algo_capa));
	global->algo_capa[ODP_COMP_ALG_DEFLATE].max_level = Z_BEST_COMPRESSION;
	global->algo_capa[ODP_COMP_ALG_ZLIB].max_level = Z_BEST_COMPRESSION;
	return 0;
}

int odp_comp_term_global(void)
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

	ret = odp_shm_free(odp_shm_lookup("comp_pool"));
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

int odp_comp_result(odp_packet_t packet,
		    odp_comp_op_result_t *result)
{
	odp_comp_generic_op_result_t *op_result;

	ODP_ASSERT(odp_event_subtype(odp_packet_to_event(packet))
					== ODP_EVENT_PACKET_COMP);

	ODP_DBG("\n");

	op_result = get_op_result_from_packet(packet);
	ODP_DBG("Copy operational result back\n");
	memcpy(result, &op_result->result, sizeof(*result));
	return 0;
}

/** Get printable format of odp_comp_session_t */
uint64_t odp_comp_session_to_u64(odp_comp_session_t hdl)
{
	return (uint64_t)hdl;
}


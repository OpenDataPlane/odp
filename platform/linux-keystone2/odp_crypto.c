/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_crypto.h>
#include <odp_internal.h>
#include <odp_atomic.h>
#include <odp_spinlock.h>
#include <odp_sync.h>
#include <odp_debug.h>
#include <odp_align.h>
#include <odp_hints.h>
#include <odp_shared_memory.h>
#include <odp_crypto_internal.h>
#include <odp_packet_internal.h>
#include <odp_queue_internal.h>
#include <odp_byteorder.h>

#include <string.h>
#include <odp_ti_mcsdk.h>

#define MAX_SESSIONS 32

typedef struct {
	odp_atomic_u32_t next;
	uint32_t         max;
	struct odp_crypto_session_s sessions[0];
} odp_crypto_global_t;

static odp_crypto_global_t *global;

static struct odp_crypto_session_s *alloc_session(void)
{
	uint32_t idx;
	struct odp_crypto_session_s *session = NULL;

	idx = odp_atomic_fetch_inc_u32(&global->next);
	if (idx < global->max) {
		session = &global->sessions[idx];
		session->index = idx;
	}
	return session;
}

static void _print_nwalCreateDmSAParams(nwalCreateDmSAParams_t *dmSaParam)
{
	odp_pr_dbg("dmSaParam.dmChnType = %u\n",
		   dmSaParam->dmSaParam.dmChnType);
	odp_pr_dbg("dmSaParam.authMode = %u\n", dmSaParam->dmSaParam.authMode);
	odp_pr_dbg("dmSaParam.cipherMode = %u\n",
		   dmSaParam->dmSaParam.cipherMode);
	odp_pr_dbg("dmSaParam.enc1st = %u\n", dmSaParam->dmSaParam.enc1st);
	odp_pr_dbg("dmSaParam.macSize = %u\n", dmSaParam->dmSaParam.macSize);
	odp_pr_dbg("dmSaParam.aadSize = %u\n", dmSaParam->dmSaParam.aadSize);
	odp_pr_dbg("dmSaParam.replayWindow = %u\n",
		   dmSaParam->dmSaParam.replayWindow);

	if (dmSaParam->dmSaParam.cipherMode != NWAL_SA_EALG_NULL)
		odp_pr_dbg_mem(dmSaParam->keyParam.pEncKey,
			       dmSaParam->keyParam.encKeySize,
			       "keyParam.pEncKey");
	if (dmSaParam->dmSaParam.authMode != NWAL_SA_AALG_NULL)
		odp_pr_dbg_mem(dmSaParam->keyParam.pAuthKey,
			       dmSaParam->keyParam.macKeySize,
			       "keyParam.pAuthKey");
}

int odp_crypto_session_create(odp_crypto_session_params_t *params,
			      odp_crypto_session_t *session_out,
			      enum odp_crypto_ses_create_err *status)
{
	nwal_RetValue nwal_ret;
	nwalCreateDmSAParams_t sa_params;
	nwalMbufPool_t rx_pool;
	Cppi_FlowHnd out_flow;
	struct odp_crypto_session_s *session;

	ODP_ASSERT((params->cipher_alg != ODP_CIPHER_ALG_NULL ||
		    params->auth_alg != ODP_AUTH_ALG_NULL),
		   "Both algorithms are NULL");

	if (params->cipher_alg == ODP_CIPHER_ALG_NULL) {
		params->cipher_key.data   = NULL;
		params->cipher_key.length = 0;
	}

	if (params->auth_alg == ODP_AUTH_ALG_NULL &&
	    params->cipher_alg != ODP_CIPHER_ALG_AES_GCM &&
	    params->cipher_alg != ODP_CIPHER_ALG_AES_CCM) {
		params->auth_key.data   = NULL;
		params->auth_key.length = 0;
	}

	/* Default to failure result */
	*status  = ODP_CRYPTO_SES_CREATE_ERR_NONE;
	*session_out = ODP_CRYPTO_SESSION_INVALID;


	/* Allocate memory for this session */
	session = alloc_session();
	if (!session) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
		return -1;
	}

	/* Copy stuff over */
	session->op = params->op;
	session->cipher.alg = params->cipher_alg;
	session->auth.alg = params->auth_alg;
	if (sizeof(session->cipher.iv.data) < params->iv.length) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER;
		return -1;
	}
	memcpy(session->cipher.iv.data, params->iv.data, params->iv.length);
	/** @todo: need separate IV for Auth */
	memcpy(session->auth.iv.data, params->iv.data, params->iv.length);

	session->compl_queue = params->compl_queue;
	session->out_pool = params->output_pool;

	rx_pool.numBufPools = 1;
	rx_pool.bufPool[0].heapHandle = session->out_pool;
	rx_pool.bufPool[0].bufSize =
			Pktlib_getMaxBufferSize(session->out_pool);
	rx_pool.bufPool[0].descSize = TUNE_NETAPI_DESC_SIZE;

	nwal_ret = nwal_SetupFlow(odp_global->nwal.handle,
			&rx_pool,
			0, /* buffer header travels via SA, so no offset */
			odp_local.nwal.cfg.rxPktTailRoomSz,
			&out_flow,
			nwal_FALSE);

	if (nwal_ret != nwal_OK) {
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
		return -1;
	}

	session->out_flow_id = Cppi_getFlowId(out_flow);

	memset(&sa_params, 0, sizeof(nwalCreateDmSAParams_t));
	sa_params.dmSaParam.dmChnType =
			(params->op == ODP_CRYPTO_OP_DECODE) ?
					NWAL_DM_CHAN_DECRYPT :
					NWAL_DM_CHAN_ENCRYPT;
	sa_params.dmSaParam.replayWindow = 64; /** @todo: always 64? */
	sa_params.dmSaParam.authMode = params->auth_alg;
	sa_params.dmSaParam.cipherMode = params->cipher_alg;

	sa_params.dmSaParam.enc1st = (params->op == ODP_CRYPTO_OP_ENCODE) ?
			params->auth_cipher_text : !params->auth_cipher_text;

	if ((sa_params.dmSaParam.cipherMode == NWAL_SA_EALG_AES_GCM) ||
	    (sa_params.dmSaParam.cipherMode	== NWAL_SA_EALG_AES_CCM) ||
	    (sa_params.dmSaParam.authMode == NWAL_SA_AALG_GMAC)) {
		sa_params.dmSaParam.macSize = 16;
		sa_params.dmSaParam.aadSize = 8;
		/* Enc1st needs to always be true for combined algorithms */
		sa_params.dmSaParam.enc1st = nwal_TRUE;
	} else if (sa_params.dmSaParam.authMode != NWAL_SA_AALG_NULL) {
		sa_params.dmSaParam.macSize = 12;
		sa_params.dmSaParam.aadSize = 0;
	} else {
		sa_params.dmSaParam.enc1st = nwal_TRUE;
		sa_params.dmSaParam.macSize = 0;
	}

	sa_params.keyParam.pEncKey = params->cipher_key.data;
	sa_params.keyParam.encKeySize = params->cipher_key.length;
	sa_params.keyParam.pAuthKey = params->auth_key.data;
	sa_params.keyParam.macKeySize = params->auth_key.length;

	session->auth.tag_len = sa_params.dmSaParam.macSize;

	ODP_ASSERT(session->auth.tag_len <=
		   ODP_FIELD_SIZEOF(struct odp_pkthdr, crypto.dec.hash_tag),
		   "Auth tag length is bigger than hash_tag array");

	_print_nwalCreateDmSAParams(&sa_params);
	odp_pr_dbg("Session addr: %p\n", session);
	nwal_ret = nwal_setDMSecAssoc(odp_global->nwal.handle,
					(nwal_AppId) session,
					&sa_params,
					&session->dm_handle);
	if (nwal_ret != nwal_OK) {
		odp_pr_err("nwal_setDMSecAssoc() returned Error Code %d\n",
			   nwal_ret);
		*status = ODP_CRYPTO_SES_CREATE_ERR_ENOMEM;
		return -1;
	}

	nwal_ret = nwal_initDMPSCmdInfo(odp_global->nwal.handle,
			session->dm_handle,
			&session->dm_ps_cmdinfo);

	*status = ODP_CRYPTO_SES_CREATE_ERR_NONE;
	*session_out = session;

	return 0;
}

int odp_crypto_session_destroy(odp_crypto_session_t ses)
{
	struct odp_crypto_session_s *session = ses;
	nwal_RetValue nwal_ret;
	nwal_ret = nwal_delDMSecAssoc(odp_global->nwal.handle,
				      session->dm_handle);
	return (nwal_ret == nwal_OK) ? 0 : -1;
}

#define ODP_CRYPTO_BUFFER_PROCESSED_OFFSET (-1)

static inline void hash_copy_be32(uint8_t *dest, const uint32be_t *sa, size_t n)
{
	union hash_u {
		uint32_t hash32;
		uint8_t hash[4];
	} hash;

	n /= 4;
	while (n--) {
		unsigned int i;
		hash.hash32 = odp_be_to_cpu_32(*sa++);
		for (i = 0; i < sizeof(hash.hash); i++)
			*dest++ = hash.hash[i];
	};
}

static inline int hash_compare_be32(const uint32_t *orig, const uint32be_t *sa,
				    size_t n)
{
	n /= 4;
	while (n--) {
		if (*orig++ != odp_be_to_cpu_32(*sa++))
			return 1;
	};
	return 0;
}

/**
 *  Set bufPtr to origBuffPtr to pass buffer header via SA
 *
 *  @return offset value
 */
static inline int16_t odp_crypto_buffer_preprocess(odp_buffer_t buf)
{
	struct odp_pkthdr *hdr;
	int16_t offset;
	Cppi_HostDesc *desc;
	uint32_t packet_length;

	desc = _odp_buf_to_cppi_desc(buf);
	hdr = odp_packet_hdr(odp_packet_from_buffer(buf));
	offset = desc->buffPtr - desc->origBuffPtr;
	hdr->crypto.saved_buf_offset = offset;
	odp_pr_dbg("buffPtr: 0x%08x, buffLen: 0x%x, offset: %x\n",
		   desc->buffPtr, desc->buffLen, offset);
	desc->buffPtr -= offset;
	desc->buffLen += offset;
	packet_length = odp_packet_get_len(odp_packet_from_buffer(buf));
	odp_packet_set_len(odp_packet_from_buffer(buf),
			   packet_length + offset);
	odp_pr_vdbg_packet(odp_packet_from_buffer(buf));
	return offset;
}

/**
 *  Restore bufPtr after SA operation
 *
 *  @return offset value
 */
static inline void odp_crypto_buffer_postprocess(odp_buffer_t buf,
						 enum crypto_alg_err *alg_err)
{
	Cppi_HostDesc *desc;
	int16_t offset;
	uint8_t *auth_tag = NULL;
	uint32_t auth_tag_len = 0;
	struct odp_pkthdr *hdr;
	struct odp_crypto_session_s *session;
	Ti_Pkt *pkt;
	uint32_t packet_length;
	nwal_Bool_t result;
	enum crypto_alg_err auth_err = ODP_CRYPTO_ALG_ERR_NONE;

	odp_pr_vdbg_packet(odp_packet_from_buffer(buf));
	hdr  = odp_packet_hdr(odp_packet_from_buffer(buf));
	offset = hdr->crypto.saved_buf_offset;
	if (offset == ODP_CRYPTO_BUFFER_PROCESSED_OFFSET) {
		/* Buffer already post-processed */
		return;
	}
	ODP_ASSERT(offset >= 0, "Wrong saved buffer offset\n");

	hdr->crypto.saved_buf_offset = ODP_CRYPTO_BUFFER_PROCESSED_OFFSET;
	pkt  = _odp_buf_to_ti_pkt(buf);
	desc = _odp_buf_to_cppi_desc(buf);

	odp_pr_dbg("buffPtr: 0x%08x, buffLen: 0x%x, offset: %x\n",
		   desc->buffPtr, desc->buffLen, offset);
	desc->buffPtr += offset;
	desc->buffLen -= offset;
	packet_length = odp_packet_get_len(odp_packet_from_buffer(buf));
	odp_packet_set_len(odp_packet_from_buffer(buf),
			   packet_length - offset);

	result = nwal_mGetAppidFmPkt(pkt, (nwal_AppId *)&session);
	ODP_ASSERT(result == nwal_TRUE, "Can't get crypto session context\n");
	odp_pr_dbg("Session addr: %p\n", session);

	nwal_mmGetDmAuthTag(pkt, &auth_tag, &auth_tag_len);

	ODP_ASSERT(session->auth.tag_len <= auth_tag_len,
		   "Auth tag length from SA is bigger than ICV length");
	ODP_ASSERT(!((uintptr_t)auth_tag & 0x3),
		   "Auth tag is not 4 bytes aligned");

	if (session->op == ODP_CRYPTO_OP_ENCODE) {
		/* Copy hash to packet */
		uint8_t *data = odp_buffer_addr(buf);
		data += hdr->crypto.hash_offset;
		hash_copy_be32(data, (uint32be_t *)(void *)auth_tag,
			       session->auth.tag_len);
	} else if (hash_compare_be32(hdr->crypto.dec.hash_tag,
				     (uint32be_t *)(void *)auth_tag,
				     session->auth.tag_len)) {
		odp_pr_dbg("ICV is wrong\n");
		odp_pr_dbg_mem(hdr->crypto.dec.hash_tag, session->auth.tag_len,
			       "Saved auth tag");
		odp_pr_dbg_mem(auth_tag, session->auth.tag_len,
			       "Decoded auth tag");
		auth_err = ODP_CRYPTO_ALG_ERR_ICV_CHECK;
	}

	if (alg_err)
		*alg_err = auth_err;
	return;
}

int odp_crypto_operation(odp_crypto_op_params_t *params,
			 bool *posted,
			 odp_buffer_t completion_event ODP_UNUSED)
{
	nwalTxDmPSCmdInfo_t *dm_cmd_info;
	Cppi_HostDesc       *desc;
	struct odp_crypto_session_s *session;
	odp_buffer_t buf = odp_buffer_from_packet(params->pkt);
	struct odp_pkthdr *hdr = odp_packet_hdr(params->pkt);
	uint32_t offset;
	uint8_t *data;

	session = (struct odp_crypto_session_s *)(intptr_t)params->session;

	/* Out packet is allocated from out poll and can't be specified */
	if (params->out_pkt != ODP_PACKET_INVALID)
		return -1;

	dm_cmd_info = &session->dm_ps_cmdinfo;
	dm_cmd_info->rxSbSaQ = _odp_queue_to_qmss_queue(session->compl_queue);
	dm_cmd_info->rxPktFlowId = session->out_flow_id;

	/* Save hash tag for decode operation and fill hash result with 0's*/
	data  = odp_packet_buf_addr(params->pkt);
	data += params->hash_result_offset;
	hdr->crypto.hash_offset = params->hash_result_offset;
	if (session->op == ODP_CRYPTO_OP_DECODE)
		memcpy(hdr->crypto.dec.hash_tag, data, session->auth.tag_len);
	memset(data, 0, session->auth.tag_len);

	offset = odp_crypto_buffer_preprocess(buf);

	nwal_mCmdDMUpdate(_odp_buf_to_ti_pkt(buf),
			  dm_cmd_info,
			  nwal_HANDLE_INVALID,
			  params->cipher_range.offset + offset,
			  params->cipher_range.length,
			  (params->override_iv_ptr) ?
					params->override_iv_ptr :
					session->cipher.iv.data,
			  params->auth_range.offset + offset,
			  params->auth_range.length,
			  NULL,
			  0, /** @todo: Should be aadSize from session? */
			  NULL);

	desc = _odp_buf_to_cppi_desc(buf);
	desc = Osal_qmssConvertDescVirtToPhy(0, desc);

	Qmss_queuePushDescSizeRaw(dm_cmd_info->txQueue,
				  desc,
				  NWAL_DESC_SIZE);

	*posted = 1;
	return 0;
}


int odp_crypto_init_global(void)
{
	size_t mem_size;

	/* Calculate the memory size we need */
	mem_size  = sizeof(*global);
	mem_size += (MAX_SESSIONS * sizeof(struct odp_crypto_session_s));

	/* Allocate our globally shared memory */
	global = odp_shm_reserve("crypto_pool", mem_size, ODP_CACHE_LINE_SIZE);

	/* Clear it out */
	memset(global, 0, mem_size);

	/* Initialize it */
	global->max = MAX_SESSIONS;

	return 0;
}

int odp_hw_random_get(uint8_t *buf, uint32_t *len, bool use_entropy ODP_UNUSED)
{
	Sa_RngData_t random;
	uint8_t *random_buf;
	uint32_t length = *len;
	uint32_t i;
	nwal_RetValue ret;

	ret = nwal_getSARandomNum(odp_global->nwal.handle, &random);
	if (ret != nwal_OK) {
		*len = 0;
		return -1;
	}
	random_buf = (uint8_t *)&random;
	if (length > sizeof(Sa_RngData_t))
		length = sizeof(Sa_RngData_t);

	for (i = 0; i < length; i++)
		*buf++ = *random_buf++;
	*len = length;

	return 0;
}
void
odp_crypto_get_operation_compl_status(odp_buffer_t completion_event,
				      struct odp_crypto_compl_status *auth,
				      struct odp_crypto_compl_status *cipher)
{
	auth->hw_err = ODP_CRYPTO_HW_ERR_NONE;
	auth->alg_err = ODP_CRYPTO_ALG_ERR_NONE;
	cipher->hw_err = ODP_CRYPTO_HW_ERR_NONE;
	cipher->alg_err = ODP_CRYPTO_ALG_ERR_NONE;

	odp_crypto_buffer_postprocess(completion_event, &auth->alg_err);

	return;
}

odp_packet_t
odp_crypto_get_operation_compl_packet(odp_buffer_t completion_event)
{
	odp_crypto_buffer_postprocess(completion_event, NULL);
	return odp_packet_from_buffer(completion_event);
}


void *odp_crypto_get_operation_compl_ctx(odp_buffer_t completion ODP_UNUSED)
{
	/* Not supported */
	return NULL;
}

void odp_crypto_get_ses_create_compl_status(odp_buffer_t completion_event,
				       enum odp_crypto_ses_create_err *status)
{
	struct odp_session_result_s *result;

	result = odp_buffer_addr(completion_event);
	*status = result->rc;
}

void odp_crypto_get_ses_create_compl_session(odp_buffer_t completion_event,
					odp_crypto_session_t *session)
{
	struct odp_session_result_s *result;

	result = odp_buffer_addr(completion_event);
	*session = result->session;
}

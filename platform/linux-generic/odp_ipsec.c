/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/atomic.h>
#include <odp/api/ipsec.h>
#include <odp/api/packet.h>
#include <odp/api/shared_memory.h>

#include <odp_buffer_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_debug_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_packet_internal.h>
#include <odp_pool_internal.h>

#include <protocols/ip.h>
#include <protocols/ipsec.h>

typedef void (*ipsec_postprocess_t)(ipsec_ctx_t *ctx);

/**
 * Per packet IPsec processing context
 */
struct ipsec_ctx_s {
	odp_buffer_t buffer;     /**< Buffer for context */
	ipsec_ctx_t *next;       /**< Next context in event */

	ipsec_postprocess_t postprocess;
	ipsec_sa_t *ipsec_sa;
	odp_crypto_op_result_t crypto;
	odp_ipsec_op_status_t status;

	uint8_t  ip_tos;         /**< Saved IP TOS value */
	uint8_t  ip_ttl;         /**< Saved IP TTL value */
	uint16_t ip_frag_offset; /**< Saved IP flags value */
	unsigned hdr_len;        /**< Length of IPsec headers */
	unsigned trl_len;        /**< Length of IPsec trailers */

	uint32_t src_ip;         /**< SA source IP address */
	uint32_t dst_ip;         /**< SA dest IP address */
	uint16_t ipsec_offset;   /**< Offset of IPsec header from
				      buffer start */
	uint8_t	iv[MAX_IV_LEN];  /**< ESP IV storage */

	unsigned pkt_out : 1;    /**< Packet was output to application */
};

static odp_pool_t ipsec_ctx_pool = ODP_POOL_INVALID;

#define IPSEC_CTX_POOL_BUF_COUNT 1024

int _odp_ipsec_init_global(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	/* Create context buffer pool */
	param.buf.size  = sizeof(ipsec_ctx_t);
	param.buf.align = 0;
	param.buf.num   = IPSEC_CTX_POOL_BUF_COUNT;
	param.type      = ODP_POOL_BUFFER;

	ipsec_ctx_pool = odp_pool_create("ipsec_ctx_pool", &param);
	if (ODP_POOL_INVALID == ipsec_ctx_pool) {
		ODP_ERR("Error: context pool create failed.\n");
		return -1;
	}

	return 0;
}

int _odp_ipsec_term_global(void)
{
	int ret;
	int rc = 0;

	ret = odp_pool_destroy(ipsec_ctx_pool);
	if (ret < 0) {
		ODP_ERR("ctx pool destroy failed");
		rc = -1;
	}

	return rc;
}

int odp_ipsec_capability(odp_ipsec_capability_t *capa)
{
	int rc;
	odp_crypto_capability_t crypto_capa;

	memset(capa, 0, sizeof(odp_ipsec_capability_t));

	capa->op_mode_sync = ODP_SUPPORT_PREFERRED;
	capa->op_mode_async = ODP_SUPPORT_PREFERRED;
	capa->op_mode_inline_out = ODP_SUPPORT_YES;

	capa->proto_ah = ODP_SUPPORT_YES;

	capa->max_num_sa = ODP_CONFIG_IPSEC_SAS;

	rc = odp_crypto_capability(&crypto_capa);
	if (rc < 0)
		return rc;

	capa->ciphers = crypto_capa.ciphers;
	capa->auths = crypto_capa.auths;

	return 0;
}

int odp_ipsec_cipher_capability(odp_cipher_alg_t cipher,
				odp_crypto_cipher_capability_t capa[], int num)
{
	return odp_crypto_cipher_capability(cipher, capa, num);
}

int odp_ipsec_auth_capability(odp_auth_alg_t auth,
			      odp_crypto_auth_capability_t capa[], int num)
{
	return odp_crypto_auth_capability(auth, capa, num);
}

void odp_ipsec_config_init(odp_ipsec_config_t *config)
{
	memset(config, 0, sizeof(odp_ipsec_config_t));
	config->inbound_mode = ODP_IPSEC_OP_MODE_SYNC;
	config->outbound_mode = ODP_IPSEC_OP_MODE_SYNC;
	config->max_num_sa = ODP_CONFIG_IPSEC_SAS;
	config->inbound.default_queue = ODP_QUEUE_INVALID;
	config->inbound.lookup.min_spi = 0;
	config->inbound.lookup.max_spi = UINT32_MAX;
}

static odp_ipsec_config_t ipsec_config;

int odp_ipsec_config(const odp_ipsec_config_t *config)
{
	/* FIXME: unsupported for now */
	if (ODP_IPSEC_OP_MODE_INLINE == config->inbound_mode)
		return -1;

	if (ODP_CONFIG_IPSEC_SAS > config->max_num_sa)
		return -1;

	ipsec_config = *config;

	return 0;
}

static
void ipsec_ctx_init(ipsec_ctx_t *ctx, odp_buffer_t buf)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->buffer = buf;

	ctx->crypto.pkt = ODP_PACKET_INVALID;
	ctx->crypto.ok = true;
}

/**
 * Allocate per packet processing context.
 *
 * @return pointer to context area
 */
static
ipsec_ctx_t *ipsec_ctx_alloc(void)
{
	odp_buffer_t ctx_buf = odp_buffer_alloc(ipsec_ctx_pool);
	ipsec_ctx_t *ctx;

	if (odp_unlikely(ODP_BUFFER_INVALID == ctx_buf))
		return NULL;

	ctx = odp_buffer_addr(ctx_buf);
	ipsec_ctx_init(ctx, ctx_buf);

	return ctx;
}

void _odp_ipsec_ctx_free(ipsec_ctx_t *ctx)
{
	while (NULL != ctx) {
		ipsec_ctx_t *next = ctx->next;

		if (!ctx->pkt_out && ODP_PACKET_INVALID != ctx->crypto.pkt)
			odp_packet_free(ctx->crypto.pkt);

		odp_buffer_free(ctx->buffer);

		ctx = next;
	}
}

/**
 * Checksum
 *
 * @param buffer calculate chksum for buffer
 * @param len    buffer length
 *
 * @return checksum value in host cpu order
 */
static inline
odp_u16sum_t _odp_chksum(void *buffer, int len)
{
	uint16_t *buf = (uint16_t *)buffer;
	uint32_t sum = 0;
	uint16_t result;

	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;

	if (len == 1)
		sum += *(unsigned char *)buf;

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;

	return  (__odp_force odp_u16sum_t) result;
}

/**
 * Calculate and fill in IPv4 checksum
 *
 * @note when using this api to populate data destined for the wire
 * odp_cpu_to_be_16() can be used to remove sparse warnings
 *
 * @param pkt  ODP packet
 *
 * @return IPv4 checksum in host cpu order, or 0 on failure
 */
static inline odp_u16sum_t
_odp_ipv4_csum_update(odp_packet_t pkt)
{
	uint16_t *w;
	_odp_ipv4hdr_t *ip;
	int nleft = sizeof(_odp_ipv4hdr_t);

	ip = (_odp_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	if (ip == NULL)
		return 0;

	ip->chksum = 0;
	w = (uint16_t *)(void *)ip;
	ip->chksum = _odp_chksum(w, nleft);
	return ip->chksum;
}

#define ipv4_hdr_len(ip) (_ODP_IPV4HDR_IHL(ip->ver_ihl) * 4)
static inline
void ipv4_adjust_len(_odp_ipv4hdr_t *ip, int adj)
{
	ip->tot_len = odp_cpu_to_be_16(odp_be_to_cpu_16(ip->tot_len) + adj);
}

static
void ipsec_finish(ipsec_ctx_t *ctx,
		  odp_ipsec_packet_result_t *res,
		  odp_packet_t *pkt)
{
	res->status = ctx->status;

	/* Check crypto result */
	if (!ctx->crypto.ok) {
		if ((ctx->crypto.cipher_status.alg_err !=
		    ODP_CRYPTO_ALG_ERR_NONE) ||
		    (ctx->crypto.cipher_status.hw_err !=
		     ODP_CRYPTO_HW_ERR_NONE))
			res->status.error.alg = 1;

		if ((ctx->crypto.auth_status.alg_err !=
		    ODP_CRYPTO_ALG_ERR_NONE) ||
		    (ctx->crypto.auth_status.hw_err !=
		     ODP_CRYPTO_HW_ERR_NONE))
			res->status.error.auth = 1;
	} else {
		if (ctx->postprocess)
			ctx->postprocess(ctx);
	}

	*pkt = ctx->crypto.pkt;
	ctx->pkt_out = 1;

	if (NULL != ctx->ipsec_sa) {
		res->sa = ctx->ipsec_sa->ipsec_sa_hdl;
		_odp_ipsec_sa_unuse(ctx->ipsec_sa);
	} else {
		res->sa = ODP_IPSEC_SA_INVALID;
	}
}

static
int ipsec_in_check_sa(ipsec_ctx_t *ctx, odp_ipsec_protocol_t proto,
		      uint32_t spi, void *dst_addr)
{
	if (NULL == ctx->ipsec_sa) {
		ipsec_sa_lookup_t lookup;

		lookup.proto = proto;
		lookup.spi = spi;
		lookup.dst_addr = dst_addr;

		ctx->ipsec_sa = _odp_ipsec_sa_lookup(&lookup);
		if (NULL == ctx->ipsec_sa) {
			ctx->status.error.sa_lookup = 1;
			return -1;
		}
	} else if (ctx->ipsec_sa->spi != spi ||
		   ctx->ipsec_sa->proto != proto) {
		ctx->status.error.proto = 1;
		return -1;
	}

	return 0;
}

static const uint8_t ipsec_padding[255] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
	0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
	0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
	0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
	0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
	0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
	0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
	0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80,
	0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
	0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
	0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
	0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0,
	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
	0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
	0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
	0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
	0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
	0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
	0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
	0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
	0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
	0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

static void ipsec_in_postprocess(ipsec_ctx_t *ctx);

static
void ipsec_in_single(ipsec_ctx_t *ctx)
{
	odp_packet_t pkt = ctx->crypto.pkt;
	uint32_t ip_offset = odp_packet_l3_offset(pkt);
	_odp_ipv4hdr_t *ip = odp_packet_l3_ptr(pkt, NULL);
	uint16_t ip_hdr_len = ipv4_hdr_len(ip);
	odp_crypto_op_param_t param;
	odp_bool_t posted = 0;
	int rc = -1;
	unsigned stats_length;

	ODP_ASSERT(ODP_PACKET_OFFSET_INVALID != ip_offset);
	ODP_ASSERT(NULL != ip);

	/* Initialize parameters block */
	memset(&param, 0, sizeof(param));
	param.ctx = ctx;

	ctx->postprocess = ipsec_in_postprocess;
	ctx->ipsec_offset = ip_offset + ip_hdr_len;

	if (ODP_IPSEC_MODE_TRANSPORT == ctx->ipsec_sa->mode &&
	    _ODP_IPV4HDR_IS_FRAGMENT(ip->frag_offset)) {
		ctx->status.error.alg = 1;
		return;
	}

	/* Check IP header for IPSec protocols and look it up */
	if (_ODP_IPPROTO_ESP == ip->proto) {
		_odp_esphdr_t esp;

		if (odp_packet_copy_to_mem(pkt, ctx->ipsec_offset,
					   sizeof(esp), &esp) < 0) {
			ctx->status.error.alg = 1;
			return;
		}

		if (ipsec_in_check_sa(ctx, ODP_IPSEC_ESP,
				      odp_be_to_cpu_32(esp.spi),
				      &ip->dst_addr) < 0)
			return;

		if (odp_packet_copy_to_mem(pkt,
					   ctx->ipsec_offset + _ODP_ESPHDR_LEN,
					   ctx->ipsec_sa->esp_iv_len,
					   ctx->iv) < 0) {
			ctx->status.error.alg = 1;
			return;
		}

		ctx->hdr_len = _ODP_ESPHDR_LEN + ctx->ipsec_sa->esp_iv_len;
		ctx->trl_len = _ODP_ESPTRL_LEN + ctx->ipsec_sa->icv_len;

		param.cipher_range.offset = ctx->ipsec_offset + ctx->hdr_len;
		param.cipher_range.length = odp_be_to_cpu_16(ip->tot_len) -
					    ip_hdr_len -
					    ctx->hdr_len -
					    ctx->ipsec_sa->icv_len;
		param.override_iv_ptr = ctx->iv;

		param.auth_range.offset = ctx->ipsec_offset;
		param.auth_range.length = odp_be_to_cpu_16(ip->tot_len) -
					  ip_hdr_len -
					  ctx->ipsec_sa->icv_len;
		param.hash_result_offset = ip_offset +
					   odp_be_to_cpu_16(ip->tot_len) -
					   ctx->ipsec_sa->icv_len;

		stats_length = param.cipher_range.length;
	} else if (_ODP_IPPROTO_AH == ip->proto) {
		_odp_ahhdr_t ah;

		if (odp_packet_copy_to_mem(pkt, ctx->ipsec_offset,
					   sizeof(ah), &ah) < 0) {
			ctx->status.error.alg = 1;
			return;
		}

		if (ipsec_in_check_sa(ctx, ODP_IPSEC_AH,
				      odp_be_to_cpu_32(ah.spi),
				      &ip->dst_addr) < 0)
			return;

		ctx->hdr_len = (ah.ah_len + 2) * 4;
		ctx->trl_len = 0;

		/* Save everything to context */
		ctx->ip_tos = ip->tos;
		ctx->ip_frag_offset = odp_be_to_cpu_16(ip->frag_offset);
		ctx->ip_ttl = ip->ttl;

		/*
		 * If authenticating, zero the mutable fields build the request
		 */
		ip->chksum = 0;
		ip->tos = 0;
		ip->frag_offset = 0;
		ip->ttl = 0;

		param.auth_range.offset = ip_offset;
		param.auth_range.length = odp_be_to_cpu_16(ip->tot_len);
		param.hash_result_offset = ctx->ipsec_offset + _ODP_AHHDR_LEN;

		stats_length = param.auth_range.length;
	} else {
		ctx->status.error.proto = 1;
		return;
	}

	if (_odp_ipsec_sa_update_stats(ctx->ipsec_sa,
				       stats_length,
				       &ctx->status) < 0)
		return;

	param.session = ctx->ipsec_sa->session;
	param.pkt = pkt;
	/* Create new packet after all length extensions */
	if (ctx->ipsec_sa->in_place) {
		param.out_pkt = pkt;
	} else {
		param.out_pkt = odp_packet_alloc(odp_packet_pool(pkt),
						  odp_packet_len(pkt));
		/* uarea will be copied by odp_crypto_operation */
		odp_packet_user_ptr_set(param.out_pkt,
					odp_packet_user_ptr(param.pkt));
	}

	rc = odp_crypto_operation(&param, &posted, &ctx->crypto);
	if (rc < 0) {
		ODP_DBG("Crypto failed\n");
		ctx->status.error.alg = 1;
		return;
	}

	ODP_ASSERT(!posted);
}

static
void ipsec_in_postprocess(ipsec_ctx_t *ctx)
{
	odp_packet_t pkt = ctx->crypto.pkt;
	uint32_t ip_offset = odp_packet_l3_offset(pkt);
	_odp_ipv4hdr_t *ip = odp_packet_l3_ptr(pkt, NULL);
	uint16_t ip_hdr_len = ipv4_hdr_len(ip);

	if (_ODP_IPPROTO_ESP == ip->proto) {
		/*
		 * Finish cipher by finding ESP trailer and processing
		 */
		_odp_esptrl_t esptrl;
		uint32_t esptrl_offset = ip_offset +
					 odp_be_to_cpu_16(ip->tot_len) -
					 ctx->trl_len;

		if (odp_packet_copy_to_mem(pkt, esptrl_offset,
					   sizeof(esptrl), &esptrl) < 0) {
			ctx->status.error.proto = 1;
			return;
		}

		if (ip_offset + esptrl.pad_len > esptrl_offset) {
			ctx->status.error.proto = 1;
			return;
		}

		if (_odp_packet_cmp_data(pkt, esptrl_offset - esptrl.pad_len,
					 ipsec_padding, esptrl.pad_len) != 0) {
			ctx->status.error.proto = 1;
			return;
		}

		ip->proto = esptrl.next_header;
		ctx->trl_len += esptrl.pad_len;
	} else if (_ODP_IPPROTO_AH == ip->proto) {
		/*
		 * Finish auth
		 */
		_odp_ahhdr_t ah;

		if (odp_packet_copy_to_mem(pkt, ctx->ipsec_offset,
					   sizeof(ah), &ah) < 0) {
			ctx->status.error.alg = 1;
			return;
		}

		ip->proto = ah.next_header;

		/* Restore mutable fields */
		ip->ttl = ctx->ip_ttl;
		ip->tos = ctx->ip_tos;
		ip->frag_offset = odp_cpu_to_be_16(ctx->ip_frag_offset);
	} else {
		ctx->status.error.proto = 1;
		return;
	}

	if (ODP_IPSEC_MODE_TUNNEL == ctx->ipsec_sa->mode) {
		/* We have a tunneled IPv4 packet, strip outer and IPsec
		 * headers */
		odp_packet_move_data(pkt, ip_hdr_len + ctx->hdr_len, 0,
				     ip_offset);
		if (odp_packet_trunc_head(&pkt, ip_hdr_len + ctx->hdr_len,
					  NULL, NULL) < 0) {
			ctx->status.error.alg = 1;
			return;
		}

		ip = odp_packet_l3_ptr(pkt, NULL);
		ip->ttl -= ctx->ipsec_sa->dec_ttl;
		_odp_ipv4_csum_update(pkt);

	} else {
		/* Finalize the IPv4 header */
		ipv4_adjust_len(ip, -(ctx->hdr_len + ctx->trl_len));

		_odp_ipv4_csum_update(pkt);

		odp_packet_move_data(pkt, ctx->hdr_len, 0,
				     ip_offset + ip_hdr_len);
		if (odp_packet_trunc_head(&pkt, ctx->hdr_len,
					  NULL, NULL) < 0) {
			ctx->status.error.alg = 1;
			return;
		}
	}

	if (odp_packet_trunc_tail(&pkt, ctx->trl_len, NULL, NULL) < 0)
		ctx->status.error.alg = 1;

	ctx->crypto.pkt = pkt;
}

/* Helper for calculating encode length using data length and block size */
#define ESP_ENCODE_LEN(x, b) ((((x) + ((b) - 1)) / (b)) * (b))

static
int ipsec_out_extend_packet(ipsec_ctx_t *ctx, odp_packet_t *pkt)
{
	if (odp_packet_extend_tail(pkt, ctx->trl_len, NULL, NULL) < 0) {
		ctx->status.error.alg = 1;
		return -1;
	}

	if (odp_packet_extend_head(pkt, ctx->hdr_len, NULL, NULL) < 0) {
		ctx->status.error.alg = 1;
		ctx->crypto.pkt = *pkt;
		return -1;
	}

	odp_packet_move_data(*pkt, 0, ctx->hdr_len, ctx->ipsec_offset);

	ctx->crypto.pkt = *pkt;

	return 0;
}

static void ipsec_out_postprocess(ipsec_ctx_t *ctx);

static
void ipsec_out_single(ipsec_ctx_t *ctx)
{
	odp_packet_t pkt = ctx->crypto.pkt;
	uint32_t ip_offset = odp_packet_l3_offset(pkt);
	_odp_ipv4hdr_t *ip = odp_packet_l3_ptr(pkt, NULL);
	uint16_t ip_hdr_len = ipv4_hdr_len(ip);
	odp_crypto_op_param_t param;
	odp_bool_t posted = 0;
	unsigned stats_length;
	int rc = -1;

	ODP_ASSERT(ODP_PACKET_OFFSET_INVALID != ip_offset);
	ODP_ASSERT(NULL != ip);
	ODP_ASSERT(NULL != ctx->ipsec_sa);

	/* Initialize parameters block */
	memset(&param, 0, sizeof(param));
	param.ctx = ctx;

	if (ODP_IPSEC_MODE_TRANSPORT == ctx->ipsec_sa->mode &&
	    _ODP_IPV4HDR_IS_FRAGMENT(ip->frag_offset)) {
		ctx->status.error.alg = 1;
		return;
	}

	if (ODP_IPSEC_MODE_TUNNEL == ctx->ipsec_sa->mode) {
		_odp_ipv4hdr_t out_ip;

		ip->ttl -= ctx->ipsec_sa->dec_ttl;

		out_ip.ver_ihl = 0x45;
		if (ctx->ipsec_sa->copy_dscp)
			out_ip.tos = ip->tos;
		else
			out_ip.tos = (ip->tos & ~_ODP_IP_TOS_DSCP_MASK) |
				     (ctx->ipsec_sa->tun_dscp <<
				      _ODP_IP_TOS_DSCP_SHIFT);
		out_ip.tot_len = odp_cpu_to_be_16(odp_be_to_cpu_16(ip->tot_len) + _ODP_IPV4HDR_LEN);
		/* No need to convert to BE: ID just should not be duplicated */
		out_ip.id = odp_atomic_fetch_add_u32(&ctx->ipsec_sa->tun_hdr_id, 1) & 0xffff;
		out_ip.frag_offset = 0;
		if (ctx->ipsec_sa->copy_df)
			out_ip.frag_offset = ip->frag_offset;
		else
			out_ip.frag_offset = (ip->frag_offset & ~0x4000) |
					     (ctx->ipsec_sa->tun_df << 14);
		out_ip.ttl = ctx->ipsec_sa->tun_ttl;
		out_ip.proto = _ODP_IPV4;
		out_ip.src_addr = ctx->ipsec_sa->tun_src_ip;
		out_ip.dst_addr = ctx->ipsec_sa->tun_dst_ip;

		if (odp_packet_extend_head(&pkt, _ODP_IPV4HDR_LEN,
					   NULL, NULL) < 0) {
			ctx->status.error.alg = 1;
			return;
		}
		ctx->crypto.pkt = pkt;

		odp_packet_move_data(pkt, 0, _ODP_IPV4HDR_LEN, ip_offset);

		odp_packet_copy_from_mem(pkt, ip_offset,
					 _ODP_IPV4HDR_LEN, &out_ip);

		odp_packet_l4_offset_set(pkt, ip_offset + _ODP_IPV4HDR_LEN);

		ip = odp_packet_l3_ptr(pkt, NULL);
		ip_hdr_len = _ODP_IPV4HDR_LEN;
	}

	ctx->postprocess = ipsec_out_postprocess;

	ctx->ipsec_offset = ip_offset + ip_hdr_len;

	if (ctx->ipsec_sa->proto == ODP_IPSEC_ESP) {
		_odp_esphdr_t esp;
		_odp_esptrl_t esptrl;
		uint32_t encrypt_len;
		uint16_t ip_data_len = odp_be_to_cpu_16(ip->tot_len) -
				       ip_hdr_len;
		uint32_t pad_block = ctx->ipsec_sa->esp_block_len;

		/* ESP trailer should be 32-bit right aligned */
		if (pad_block < 4)
			pad_block = 4;

		encrypt_len = ESP_ENCODE_LEN(ip_data_len + _ODP_ESPTRL_LEN,
					     pad_block);

		ctx->hdr_len += _ODP_ESPHDR_LEN + ctx->ipsec_sa->esp_iv_len;
		ctx->trl_len = encrypt_len -
			       ip_data_len +
			       ctx->ipsec_sa->icv_len;

		if (ctx->ipsec_sa->esp_iv_len) {
			/* FIXME: this is correct only for CBC ciphers ! */
			uint32_t len = odp_random_data(ctx->iv,
						       ctx->ipsec_sa->esp_iv_len,
						       ODP_RANDOM_CRYPTO);

			if (len != ctx->ipsec_sa->esp_iv_len) {
				ctx->status.error.alg = 1;
				return;
			}

			param.override_iv_ptr = ctx->iv;
		}

		if (ipsec_out_extend_packet(ctx, &pkt) < 0)
			return;

		ip = odp_packet_l3_ptr(pkt, NULL);

		/* Set IPv4 length before authentication */
		ipv4_adjust_len(ip, ctx->hdr_len + ctx->trl_len);

		uint32_t esptrl_offset = ip_offset +
					 ip_hdr_len +
					 ctx->hdr_len +
					 encrypt_len -
					 _ODP_ESPTRL_LEN;

		memset(&esp, 0, sizeof(esp));
		esp.spi = odp_cpu_to_be_32(ctx->ipsec_sa->spi);
		esp.seq_no = odp_cpu_to_be_32(odp_atomic_fetch_add_u32(&ctx->ipsec_sa->seq, 1) + 1);

		memset(&esptrl, 0, sizeof(esptrl));
		esptrl.pad_len = encrypt_len - ip_data_len - _ODP_ESPTRL_LEN;
		esptrl.next_header = ip->proto;
		ip->proto = _ODP_IPPROTO_ESP;

		odp_packet_copy_from_mem(pkt,
					 ctx->ipsec_offset, _ODP_ESPHDR_LEN,
					 &esp);
		/* FIXME: this is correct only for CBC ciphers ! */
		odp_packet_copy_from_mem(pkt,
					 ctx->ipsec_offset + _ODP_ESPHDR_LEN,
					 ctx->ipsec_sa->esp_iv_len, ctx->iv);
		odp_packet_copy_from_mem(pkt,
					 esptrl_offset - esptrl.pad_len,
					 esptrl.pad_len, ipsec_padding);
		odp_packet_copy_from_mem(pkt,
					 esptrl_offset, _ODP_ESPTRL_LEN,
					 &esptrl);

		param.cipher_range.offset = ctx->ipsec_offset + ctx->hdr_len;
		param.cipher_range.length = odp_be_to_cpu_16(ip->tot_len) -
					    ip_hdr_len -
					    ctx->hdr_len -
					    ctx->ipsec_sa->icv_len;

		param.auth_range.offset = ctx->ipsec_offset;
		param.auth_range.length = odp_be_to_cpu_16(ip->tot_len) -
					  ip_hdr_len -
					  ctx->ipsec_sa->icv_len;
		param.hash_result_offset = ip_offset +
					   odp_be_to_cpu_16(ip->tot_len) -
					   ctx->ipsec_sa->icv_len;

		stats_length = param.cipher_range.length;
	} else if (ctx->ipsec_sa->proto == ODP_IPSEC_AH) {
		_odp_ahhdr_t ah;

		ctx->hdr_len = _ODP_AHHDR_LEN + ctx->ipsec_sa->icv_len;
		ctx->trl_len = 0;

		/* Save IPv4 stuff */
		ctx->ip_tos = ip->tos;
		ctx->ip_frag_offset = odp_be_to_cpu_16(ip->frag_offset);
		ctx->ip_ttl = ip->ttl;

		if (ipsec_out_extend_packet(ctx, &pkt) < 0)
			return;

		ip = odp_packet_l3_ptr(pkt, NULL);

		/* Set IPv4 length before authentication */
		ipv4_adjust_len(ip, ctx->hdr_len + ctx->trl_len);

		memset(&ah, 0, sizeof(ah));
		ah.spi = odp_cpu_to_be_32(ctx->ipsec_sa->spi);
		ah.ah_len = 1 + (ctx->ipsec_sa->icv_len / 4);
		ah.seq_no = odp_cpu_to_be_32(odp_atomic_fetch_add_u32(&ctx->ipsec_sa->seq, 1) + 1);
		ah.next_header = ip->proto;
		ip->proto = _ODP_IPPROTO_AH;

		odp_packet_copy_from_mem(pkt,
					 ctx->ipsec_offset, _ODP_AHHDR_LEN,
					 &ah);
		_odp_packet_set_data(pkt,
				     ctx->ipsec_offset + _ODP_AHHDR_LEN,
				     0, ctx->ipsec_sa->icv_len);

		ip->chksum = 0;
		ip->tos = 0;
		ip->frag_offset = 0;
		ip->ttl = 0;

		param.auth_range.offset = ip_offset;
		param.auth_range.length = odp_be_to_cpu_16(ip->tot_len);
		param.hash_result_offset = ctx->ipsec_offset + _ODP_AHHDR_LEN;

		stats_length = param.auth_range.length;
	} else {
		ctx->status.error.alg = 1;
		return;
	}

	if (_odp_ipsec_sa_update_stats(ctx->ipsec_sa,
				       stats_length,
				       &ctx->status) < 0)
		return;

	param.session = ctx->ipsec_sa->session;
	param.pkt = pkt;
	/* Create new packet after all length extensions */
	if (ctx->ipsec_sa->in_place) {
		param.out_pkt = pkt;
	} else {
		param.out_pkt = odp_packet_alloc(odp_packet_pool(pkt),
						  odp_packet_len(pkt));
		if (odp_unlikely(ODP_PACKET_INVALID == param.out_pkt)) {
			ctx->status.error.alg = 1;
			return;
		}
		odp_packet_user_ptr_set(param.out_pkt,
					odp_packet_user_ptr(param.pkt));
	}

	rc = odp_crypto_operation(&param, &posted, &ctx->crypto);
	if (rc < 0) {
		ODP_DBG("Crypto failed\n");
		ctx->status.error.alg = 1;
		return;
	}

	ODP_ASSERT(!posted);
}

static
void ipsec_out_postprocess(ipsec_ctx_t *ctx)
{
	odp_packet_t pkt = ctx->crypto.pkt;
	_odp_ipv4hdr_t *ip = odp_packet_l3_ptr(pkt, NULL);

	/* Finalize the IPv4 header */
	if (ip->proto == _ODP_IPPROTO_AH) {
		ip->ttl = ctx->ip_ttl;
		ip->tos = ctx->ip_tos;
		ip->frag_offset = odp_cpu_to_be_16(ctx->ip_frag_offset);
	}

	_odp_ipv4_csum_update(pkt);
}

#if 0
static odp_ipsec_op_opt_t default_opt = {
	.mode = ODP_IPSEC_FRAG_DISABLED,
};
#endif

int odp_ipsec_in(const odp_ipsec_op_param_t *input,
		 odp_ipsec_op_result_t *output)
{
	int in_pkt = 0;
	int out_pkt = 0;
	unsigned sa_idx = 0;
	unsigned opt_idx = 0;
	unsigned sa_inc = (input->num_sa > 1) ? 1 : 0;
	unsigned opt_inc = (input->num_opt > 1) ? 1 : 0;

	while (in_pkt < input->num_pkt && out_pkt < output->num_pkt) {
		ipsec_ctx_t ctx;

		ipsec_ctx_init(&ctx, ODP_BUFFER_INVALID);

#if 0
		odp_ipsec_op_opt_t *opt;

		if (0 == input->num_opt)
			opt = &default_opt;
		else
			opt = &input->opt[opt_idx];
#endif

		ctx.crypto.pkt = input->pkt[in_pkt];

		if (0 == input->num_sa) {
			ctx.ipsec_sa = NULL;
		} else {
			ctx.ipsec_sa = _odp_ipsec_sa_use(input->sa[sa_idx]);
			ODP_ASSERT(NULL != ctx.ipsec_sa);
		}

		ipsec_in_single(&ctx);

		ipsec_finish(&ctx,
			     &output->res[out_pkt],
			     &output->pkt[out_pkt]);

		in_pkt++;
		out_pkt++;
		sa_idx += sa_inc;
		opt_idx += opt_inc;
	}

	return in_pkt;
}

int odp_ipsec_out(const odp_ipsec_op_param_t *input,
		 odp_ipsec_op_result_t *output)
{
	int in_pkt = 0;
	int out_pkt = 0;
	unsigned sa_idx = 0;
	unsigned opt_idx = 0;
	unsigned sa_inc = (input->num_sa > 1) ? 1 : 0;
	unsigned opt_inc = (input->num_opt > 1) ? 1 : 0;

	ODP_ASSERT(input->num_sa != 0);

	while (in_pkt < input->num_pkt && out_pkt < output->num_pkt) {
		odp_ipsec_sa_t sa;
		ipsec_ctx_t ctx;

		ipsec_ctx_init(&ctx, ODP_BUFFER_INVALID);

		sa = input->sa[sa_idx];

		ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);

#if 0
		odp_ipsec_op_opt_t *opt;

		if (0 == input->num_opt)
			opt = &default_opt;
		else
			opt = &input->opt[opt_idx];
#endif

		ctx.crypto.pkt = input->pkt[in_pkt];
		ctx.ipsec_sa = _odp_ipsec_sa_use(sa);

		ipsec_out_single(&ctx);

		ipsec_finish(&ctx,
			     &output->res[out_pkt],
			     &output->pkt[out_pkt]);

		in_pkt++;
		out_pkt++;
		sa_idx += sa_inc;
		opt_idx += opt_inc;
	}

	return in_pkt;
}

int odp_ipsec_in_enq(const odp_ipsec_op_param_t *input)
{
	int in_pkt = 0;
	unsigned sa_idx = 0;
	unsigned opt_idx = 0;
	unsigned sa_inc = (input->num_sa > 1) ? 1 : 0;
	unsigned opt_inc = (input->num_opt > 1) ? 1 : 0;

	while (in_pkt < input->num_pkt) {
		ipsec_ctx_t *ctx;
		odp_queue_t queue;

		ctx = ipsec_ctx_alloc();
		if (NULL == ctx)
			break;

#if 0
		odp_ipsec_op_opt_t *opt;

		if (0 == input->num_opt)
			opt = &default_opt;
		else
			opt = &input->opt[opt_idx];
#endif

		ctx->crypto.pkt = input->pkt[in_pkt];

		if (0 == input->num_sa) {
			ctx->ipsec_sa = NULL;
		} else {
			ctx->ipsec_sa = _odp_ipsec_sa_use(input->sa[sa_idx]);
			ODP_ASSERT(NULL != ctx->ipsec_sa);
		}

		ipsec_in_single(ctx);

		in_pkt++;
		sa_idx += sa_inc;
		opt_idx += opt_inc;

		/* IN might have looked up SA for the packet */
		if (NULL == ctx->ipsec_sa)
			queue = ipsec_config.inbound.default_queue;
		else
			queue = ctx->ipsec_sa->queue;
		if (odp_unlikely(_odp_ipsec_result_send(queue, ctx) < 0))
			break;
	}

	return in_pkt;
}

int odp_ipsec_out_enq(const odp_ipsec_op_param_t *input)
{
	int in_pkt = 0;
	unsigned sa_idx = 0;
	unsigned opt_idx = 0;
	unsigned sa_inc = (input->num_sa > 1) ? 1 : 0;
	unsigned opt_inc = (input->num_opt > 1) ? 1 : 0;

	ODP_ASSERT(input->num_sa != 0);

	while (in_pkt < input->num_pkt) {
		odp_ipsec_sa_t sa;
		ipsec_ctx_t *ctx;

		ctx = ipsec_ctx_alloc();
		if (NULL == ctx)
			break;

		sa = input->sa[sa_idx];

		ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);

#if 0
		odp_ipsec_op_opt_t *opt;

		if (0 == input->num_opt)
			opt = &default_opt;
		else
			opt = &input->opt[opt_idx];
#endif

		ctx->crypto.pkt = input->pkt[in_pkt];
		ctx->ipsec_sa = _odp_ipsec_sa_use(sa);

		ipsec_out_single(ctx);

		in_pkt++;
		sa_idx += sa_inc;
		opt_idx += opt_inc;

		if (odp_unlikely(_odp_ipsec_result_send(ctx->ipsec_sa->queue,
							ctx) < 0))
			break;
	}

	return in_pkt;
}

static
void _odp_ipsec_out_inline_send(ipsec_ctx_t *ctx,
				const odp_ipsec_inline_op_param_t *inline_param)
{
	while (ctx) {
		ipsec_ctx_t *next = ctx->next;
		odp_ipsec_packet_result_t dummy;
		odp_packet_t pkt;
		uint32_t offset;
		odp_pktout_queue_t queue;
		uint32_t hdr_len = inline_param->outer_hdr.len;

		ctx->next = NULL;

		ipsec_finish(ctx, &dummy, &pkt);
		if (ctx->status.all_error)
			goto err;

		offset = odp_packet_l3_offset(pkt);

		if (offset >= hdr_len) {
			if (odp_packet_trunc_head(&pkt, offset - hdr_len,
						  NULL, NULL) < 0) {
				ctx->status.error.alg = 1;
				goto err;
			}

		} else {
			if (odp_packet_extend_head(&pkt, hdr_len - offset,
						   NULL, NULL) < 0) {
				ctx->status.error.alg = 1;
				goto err;
			}
		}

		odp_packet_l3_offset_set(pkt, hdr_len);

		if (odp_packet_copy_from_mem(pkt, 0,
					     hdr_len,
					     inline_param->outer_hdr.ptr) < 0) {
			ctx->status.error.alg = 1;
			goto err;
		}

		if (odp_pktout_queue(inline_param->pktio, &queue, 1) < 0) {
			ctx->status.error.alg = 1;
			goto err;
		}

		if (odp_pktout_send(queue, &pkt, 1) < 0) {
			ctx->status.error.alg = 1;
			goto err;
		}

		if (ctx->status.all_error) {
err:
			_odp_ipsec_result_send(ctx->ipsec_sa->queue, ctx);
		} else {
			_odp_ipsec_ctx_free(ctx);
		}
		ctx = next;
	}

}

int odp_ipsec_out_inline(const odp_ipsec_op_param_t *input,
			 const odp_ipsec_inline_op_param_t *inline_param)
{
	int in_pkt = 0;
	unsigned sa_idx = 0;
	unsigned opt_idx = 0;
	unsigned sa_inc = (input->num_sa > 1) ? 1 : 0;
	unsigned opt_inc = (input->num_opt > 1) ? 1 : 0;

	ODP_ASSERT(input->num_sa != 0);

	while (in_pkt < input->num_pkt) {
		odp_ipsec_sa_t sa;
		ipsec_ctx_t *ctx;

		ctx = ipsec_ctx_alloc();
		if (NULL == ctx)
			break;

		sa = input->sa[sa_idx];

		ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);

#if 0
		odp_ipsec_op_opt_t *opt;

		if (0 == input->num_opt)
			opt = &default_opt;
		else
			opt = &input->opt[opt_idx];
#endif

		ctx->crypto.pkt = input->pkt[in_pkt];
		ctx->ipsec_sa = _odp_ipsec_sa_use(sa);

		ipsec_out_single(ctx);

		in_pkt++;
		sa_idx += sa_inc;
		opt_idx += opt_inc;

		/* FIXME: inline_param should have been put into context */
		_odp_ipsec_out_inline_send(ctx, &inline_param[in_pkt - 1]);
	}

	return in_pkt;
}

int _odp_ipsec_ctx_result(ipsec_ctx_t *ctx, odp_ipsec_op_result_t *result)
{
	int out_pkt = 0;

	if (NULL == result)
		goto count;

	while (NULL != ctx && out_pkt < result->num_pkt) {
		ipsec_finish(ctx, &result->res[out_pkt], &result->pkt[out_pkt]);
		out_pkt++;
		ctx = ctx->next;
	}

	result->num_pkt = out_pkt;

count:
	while (NULL != ctx) {
		out_pkt++;
		ctx = ctx->next;
	}

	return out_pkt;
}

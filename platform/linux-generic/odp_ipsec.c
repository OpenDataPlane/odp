/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp/api/ipsec.h>

#include <odp/api/plat/packet_inlines.h>

#include <odp_debug_internal.h>
#include <odp_packet_internal.h>
#include <odp_ipsec_internal.h>

#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/ipsec.h>

#include <string.h>

typedef struct ODP_PACKED {
	odp_u32be_t spi;     /**< Security Parameter Index */
	odp_u32be_t seq_no;  /**< Sequence Number */
} ipsec_aad_t;

int odp_ipsec_capability(odp_ipsec_capability_t *capa)
{
	int rc;
	odp_crypto_capability_t crypto_capa;
	odp_queue_capability_t queue_capa;

	memset(capa, 0, sizeof(odp_ipsec_capability_t));

	capa->op_mode_sync = ODP_SUPPORT_PREFERRED;
	capa->op_mode_async = ODP_SUPPORT_PREFERRED;
	capa->op_mode_inline_in = ODP_SUPPORT_PREFERRED;
	capa->op_mode_inline_out = ODP_SUPPORT_PREFERRED;

	capa->proto_ah = ODP_SUPPORT_YES;

	capa->max_num_sa = ODP_CONFIG_IPSEC_SAS;

	capa->max_antireplay_ws = IPSEC_ANTIREPLAY_WS;

	rc = odp_crypto_capability(&crypto_capa);
	if (rc < 0)
		return rc;

	capa->ciphers = crypto_capa.ciphers;
	capa->auths = crypto_capa.auths;

	rc = odp_queue_capability(&queue_capa);
	if (rc < 0)
		return rc;

	capa->max_queues = queue_capa.max_queues;

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
	if (ODP_CONFIG_IPSEC_SAS > config->max_num_sa)
		return -1;

	ipsec_config = *config;

	return 0;
}

odp_ipsec_packet_result_t *_odp_ipsec_pkt_result(odp_packet_t packet)
{
	ODP_ASSERT(ODP_EVENT_PACKET_IPSEC ==
		   odp_event_subtype(odp_packet_to_event(packet)));

	return &odp_packet_hdr(packet)->ipsec_ctx;
}

/**
 * Checksum
 *
 * @param buffer calculate chksum for buffer
 * @param len    buffer length
 *
 * @return checksum value in network order
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

static inline int _odp_ipv4_csum(odp_packet_t pkt,
				 uint32_t offset,
				 _odp_ipv4hdr_t *ip,
				 odp_u16sum_t *chksum)
{
	unsigned nleft = _ODP_IPV4HDR_IHL(ip->ver_ihl) * 4;
	uint16_t buf[nleft / 2];
	int res;

	if (odp_unlikely(nleft < sizeof(*ip)))
		return -1;
	ip->chksum = 0;
	memcpy(buf, ip, sizeof(*ip));
	res = odp_packet_copy_to_mem(pkt, offset + sizeof(*ip),
				     nleft - sizeof(*ip),
				     buf + sizeof(*ip) / 2);
	if (odp_unlikely(res < 0))
		return res;

	*chksum = _odp_chksum(buf, nleft);

	return 0;
}

/** @internal Checksum offset in IPv4 header */
#define _ODP_IPV4HDR_CSUM_OFFSET	10

/**
 * Calculate and fill in IPv4 checksum
 *
 * @param pkt  ODP packet
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
static inline int _odp_ipv4_csum_update(odp_packet_t pkt)
{
	uint32_t offset;
	_odp_ipv4hdr_t ip;
	odp_u16sum_t chksum;
	int res;

	offset = odp_packet_l3_offset(pkt);
	if (offset == ODP_PACKET_OFFSET_INVALID)
		return -1;

	res = odp_packet_copy_to_mem(pkt, offset, sizeof(ip), &ip);
	if (odp_unlikely(res < 0))
		return res;

	res = _odp_ipv4_csum(pkt, offset, &ip, &chksum);
	if (odp_unlikely(res < 0))
		return res;

	return odp_packet_copy_from_mem(pkt,
					offset + _ODP_IPV4HDR_CSUM_OFFSET,
					2, &chksum);
}

#define ipv4_hdr_len(ip) (_ODP_IPV4HDR_IHL(ip->ver_ihl) * 4)
static inline
void ipv4_adjust_len(_odp_ipv4hdr_t *ip, int adj)
{
	ip->tot_len = odp_cpu_to_be_16(odp_be_to_cpu_16(ip->tot_len) + adj);
}

static const uint8_t ipsec_padding[255] = {
	      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
	0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

static inline odp_pktio_parser_layer_t parse_layer(odp_ipsec_proto_layer_t l)
{
	switch (l) {
	case ODP_IPSEC_LAYER_NONE:
		return ODP_PKTIO_PARSER_LAYER_NONE;
	case ODP_IPSEC_LAYER_L2:
		return ODP_PKTIO_PARSER_LAYER_L2;
	case ODP_IPSEC_LAYER_L3:
		return ODP_PKTIO_PARSER_LAYER_L3;
	case ODP_IPSEC_LAYER_L4:
		return ODP_PKTIO_PARSER_LAYER_L4;
	case ODP_IPSEC_LAYER_ALL:
		return ODP_PKTIO_PARSER_LAYER_ALL;
	}

	return ODP_PKTIO_PARSER_LAYER_NONE;
}

static ipsec_sa_t *ipsec_in_single(odp_packet_t pkt,
				   odp_ipsec_sa_t sa,
				   odp_packet_t *pkt_out,
				   odp_ipsec_op_status_t *status)
{
	ipsec_sa_t *ipsec_sa = NULL;
	uint32_t ip_offset = odp_packet_l3_offset(pkt);
	_odp_ipv4hdr_t *ip = odp_packet_l3_ptr(pkt, NULL);
	uint16_t ip_hdr_len = ipv4_hdr_len(ip);
	odp_crypto_packet_op_param_t param;
	int rc;
	unsigned stats_length;
	uint16_t ipsec_offset;   /**< Offset of IPsec header from
				      buffer start */
	uint8_t	iv[IPSEC_MAX_IV_LEN];  /**< ESP IV storage */
	ipsec_aad_t aad;         /**< AAD, note ESN is not fully supported */
	unsigned hdr_len;        /**< Length of IPsec headers */
	unsigned trl_len;        /**< Length of IPsec trailers */
	uint8_t  ip_tos;         /**< Saved IP TOS value */
	uint8_t  ip_ttl;         /**< Saved IP TTL value */
	uint16_t ip_frag_offset; /**< Saved IP flags value */
	odp_crypto_packet_result_t crypto; /**< Crypto operation result */
	odp_packet_hdr_t *pkt_hdr;

	ODP_ASSERT(ODP_PACKET_OFFSET_INVALID != ip_offset);
	ODP_ASSERT(NULL != ip);

	ip_tos = 0;
	ip_ttl = 0;
	ip_frag_offset = 0;

	/* Initialize parameters block */
	memset(&param, 0, sizeof(param));

	ipsec_offset = ip_offset + ip_hdr_len;

	if (odp_be_to_cpu_16(ip->tot_len) + ip_offset > odp_packet_len(pkt)) {
		status->error.alg = 1;
		goto err;
	}

	if (_ODP_IPV4HDR_IS_FRAGMENT(odp_be_to_cpu_16(ip->frag_offset))) {
		status->error.proto = 1;
		goto err;
	}

	/* Check IP header for IPSec protocols and look it up */
	if (_ODP_IPPROTO_ESP == ip->proto) {
		_odp_esphdr_t esp;

		if (odp_packet_copy_to_mem(pkt, ipsec_offset,
					   sizeof(esp), &esp) < 0) {
			status->error.alg = 1;
			goto err;
		}

		if (ODP_IPSEC_SA_INVALID == sa) {
			ipsec_sa_lookup_t lookup;

			lookup.proto = ODP_IPSEC_ESP;
			lookup.spi = odp_be_to_cpu_32(esp.spi);
			lookup.dst_addr = &ip->dst_addr;

			ipsec_sa = _odp_ipsec_sa_lookup(&lookup);
			if (NULL == ipsec_sa) {
				status->error.sa_lookup = 1;
				goto err;
			}
		} else {
			ipsec_sa = _odp_ipsec_sa_use(sa);
			ODP_ASSERT(NULL != ipsec_sa);
			if (ipsec_sa->proto != ODP_IPSEC_ESP ||
			    ipsec_sa->spi != odp_be_to_cpu_32(esp.spi)) {
				status->error.proto = 1;
				goto err;
			}
		}

		memcpy(iv, ipsec_sa->salt, ipsec_sa->salt_length);
		if (odp_packet_copy_to_mem(pkt,
					   ipsec_offset + _ODP_ESPHDR_LEN,
					   ipsec_sa->esp_iv_len,
					   iv + ipsec_sa->salt_length) < 0) {
			status->error.alg = 1;
			goto err;
		}

		if (ipsec_sa->aes_ctr_iv) {
			iv[12] = 0;
			iv[13] = 0;
			iv[14] = 0;
			iv[15] = 1;
		}

		hdr_len = _ODP_ESPHDR_LEN + ipsec_sa->esp_iv_len;
		trl_len = _ODP_ESPTRL_LEN + ipsec_sa->icv_len;

		param.cipher_range.offset = ipsec_offset + hdr_len;
		param.cipher_range.length = odp_be_to_cpu_16(ip->tot_len) -
					    ip_hdr_len -
					    hdr_len -
					    ipsec_sa->icv_len;
		param.override_iv_ptr = iv;

		aad.spi = esp.spi;
		aad.seq_no = esp.seq_no;

		param.aad.ptr = (uint8_t *)&aad;
		param.aad.length = sizeof(aad);

		param.auth_range.offset = ipsec_offset;
		param.auth_range.length = odp_be_to_cpu_16(ip->tot_len) -
					  ip_hdr_len -
					  ipsec_sa->icv_len;
		param.hash_result_offset = ip_offset +
					   odp_be_to_cpu_16(ip->tot_len) -
					   ipsec_sa->icv_len;

		stats_length = param.cipher_range.length;
	} else if (_ODP_IPPROTO_AH == ip->proto) {
		_odp_ahhdr_t ah;

		if (odp_packet_copy_to_mem(pkt, ipsec_offset,
					   sizeof(ah), &ah) < 0) {
			status->error.alg = 1;
			goto err;
		}

		if (ODP_IPSEC_SA_INVALID == sa) {
			ipsec_sa_lookup_t lookup;

			lookup.proto = ODP_IPSEC_AH;
			lookup.spi = odp_be_to_cpu_32(ah.spi);
			lookup.dst_addr = &ip->dst_addr;

			ipsec_sa = _odp_ipsec_sa_lookup(&lookup);
			if (NULL == ipsec_sa) {
				status->error.sa_lookup = 1;
				goto err;
			}
		} else {
			ipsec_sa = _odp_ipsec_sa_use(sa);
			ODP_ASSERT(NULL != ipsec_sa);
			if (ipsec_sa->proto != ODP_IPSEC_AH ||
			    ipsec_sa->spi != odp_be_to_cpu_32(ah.spi)) {
				status->error.proto = 1;
				goto err;
			}
		}

		memcpy(iv, ipsec_sa->salt, ipsec_sa->salt_length);
		if (odp_packet_copy_to_mem(pkt,
					   ipsec_offset + _ODP_AHHDR_LEN,
					   ipsec_sa->esp_iv_len,
					   iv + ipsec_sa->salt_length) < 0) {
			status->error.alg = 1;
			goto err;
		}
		param.override_iv_ptr = iv;

		hdr_len = (ah.ah_len + 2) * 4;
		trl_len = 0;

		/* Save everything to context */
		ip_tos = ip->tos;
		ip_frag_offset = odp_be_to_cpu_16(ip->frag_offset);
		ip_ttl = ip->ttl;

		/* FIXME: zero copy of header, passing it to crypto! */
		/*
		 * If authenticating, zero the mutable fields build the request
		 */
		ip->chksum = 0;
		ip->tos = 0;
		ip->frag_offset = 0;
		ip->ttl = 0;

		aad.spi = ah.spi;
		aad.seq_no = ah.seq_no;

		param.aad.ptr = (uint8_t *)&aad;
		param.aad.length = sizeof(aad);

		param.auth_range.offset = ip_offset;
		param.auth_range.length = odp_be_to_cpu_16(ip->tot_len);
		param.hash_result_offset = ipsec_offset + _ODP_AHHDR_LEN +
					ipsec_sa->esp_iv_len;

		stats_length = param.auth_range.length;
	} else {
		status->error.proto = 1;
		goto err;
	}

	if (_odp_ipsec_sa_replay_precheck(ipsec_sa,
					  odp_be_to_cpu_32(aad.seq_no),
					  status) < 0)
		goto err;

	if (_odp_ipsec_sa_stats_precheck(ipsec_sa, status) < 0)
		goto err;

	param.session = ipsec_sa->session;

	rc = odp_crypto_op(&pkt, &pkt, &param, 1);
	if (rc < 0) {
		ODP_DBG("Crypto failed\n");
		status->error.alg = 1;
		goto err;
	}

	rc = odp_crypto_result(&crypto, pkt);
	if (rc < 0) {
		ODP_DBG("Crypto failed\n");
		status->error.alg = 1;
		goto err;
	}

	if (!crypto.ok) {
		if ((crypto.cipher_status.alg_err !=
		     ODP_CRYPTO_ALG_ERR_NONE) ||
		    (crypto.cipher_status.hw_err !=
		     ODP_CRYPTO_HW_ERR_NONE))
			status->error.alg = 1;

		if ((crypto.auth_status.alg_err !=
		     ODP_CRYPTO_ALG_ERR_NONE) ||
		    (crypto.auth_status.hw_err !=
		     ODP_CRYPTO_HW_ERR_NONE))
			status->error.auth = 1;

		goto err;
	}

	if (_odp_ipsec_sa_stats_update(ipsec_sa, stats_length, status) < 0)
		goto err;

	if (_odp_ipsec_sa_replay_update(ipsec_sa,
					odp_be_to_cpu_32(aad.seq_no),
					status) < 0)
		goto err;

	ip_offset = odp_packet_l3_offset(pkt);
	ip = odp_packet_l3_ptr(pkt, NULL);
	ip_hdr_len = ipv4_hdr_len(ip);

	if (_ODP_IPPROTO_ESP == ip->proto) {
		/*
		 * Finish cipher by finding ESP trailer and processing
		 */
		_odp_esptrl_t esptrl;
		uint32_t esptrl_offset = ip_offset +
					 odp_be_to_cpu_16(ip->tot_len) -
					 trl_len;

		if (odp_packet_copy_to_mem(pkt, esptrl_offset,
					   sizeof(esptrl), &esptrl) < 0) {
			status->error.proto = 1;
			goto err;
		}

		if (ip_offset + esptrl.pad_len > esptrl_offset) {
			status->error.proto = 1;
			goto err;
		}

		if (_odp_packet_cmp_data(pkt, esptrl_offset - esptrl.pad_len,
					 ipsec_padding, esptrl.pad_len) != 0) {
			status->error.proto = 1;
			goto err;
		}

		ip->proto = esptrl.next_header;
		trl_len += esptrl.pad_len;
	} else if (_ODP_IPPROTO_AH == ip->proto) {
		/*
		 * Finish auth
		 */
		_odp_ahhdr_t ah;

		if (odp_packet_copy_to_mem(pkt, ipsec_offset,
					   sizeof(ah), &ah) < 0) {
			status->error.alg = 1;
			goto err;
		}

		ip->proto = ah.next_header;

		/* Restore mutable fields */
		ip->ttl = ip_ttl;
		ip->tos = ip_tos;
		ip->frag_offset = odp_cpu_to_be_16(ip_frag_offset);
	} else {
		status->error.proto = 1;
		goto err;
	}

	if (odp_packet_trunc_tail(&pkt, trl_len, NULL, NULL) < 0) {
		status->error.alg = 1;
		goto err;
	}

	if (ODP_IPSEC_MODE_TUNNEL == ipsec_sa->mode) {
		/* We have a tunneled IPv4 packet, strip outer and IPsec
		 * headers */
		odp_packet_move_data(pkt, ip_hdr_len + hdr_len, 0,
				     ip_offset);
		if (odp_packet_trunc_head(&pkt, ip_hdr_len + hdr_len,
					  NULL, NULL) < 0) {
			status->error.alg = 1;
			goto err;
		}
	} else {
		odp_packet_move_data(pkt, hdr_len, 0,
				     ip_offset + ip_hdr_len);
		if (odp_packet_trunc_head(&pkt, hdr_len,
					  NULL, NULL) < 0) {
			status->error.alg = 1;
			goto err;
		}
	}

	/* Finalize the IPv4 header */
	if (odp_packet_len(pkt) > sizeof(*ip)) {
		ip = odp_packet_l3_ptr(pkt, NULL);

		if (ODP_IPSEC_MODE_TRANSPORT == ipsec_sa->mode)
			ipv4_adjust_len(ip, -(hdr_len + trl_len));

		ip->ttl -= ipsec_sa->dec_ttl;
		_odp_ipv4_csum_update(pkt);
	}

	pkt_hdr = odp_packet_hdr(pkt);

	packet_parse_reset(pkt_hdr);

	packet_parse_l3_l4(pkt_hdr, parse_layer(ipsec_config.inbound.parse),
			   ip_offset, _ODP_ETHTYPE_IPV4);

	*pkt_out = pkt;

	return ipsec_sa;

err:
	pkt_hdr = odp_packet_hdr(pkt);
	pkt_hdr->p.error_flags.ipsec_err = 1;

	*pkt_out = pkt;

	return ipsec_sa;
}

/* Generate sequence number */
static inline
uint32_t ipsec_seq_no(ipsec_sa_t *ipsec_sa)
{
	return odp_atomic_fetch_add_u32(&ipsec_sa->out.seq, 1);
}

/* Helper for calculating encode length using data length and block size */
#define ESP_ENCODE_LEN(x, b) ((((x) + ((b) - 1)) / (b)) * (b))

static ipsec_sa_t *ipsec_out_single(odp_packet_t pkt,
				    odp_ipsec_sa_t sa,
				    odp_packet_t *pkt_out,
				    odp_ipsec_out_opt_t *opt ODP_UNUSED,
				    odp_ipsec_op_status_t *status)
{
	ipsec_sa_t *ipsec_sa = NULL;
	uint32_t ip_offset = odp_packet_l3_offset(pkt);
	_odp_ipv4hdr_t *ip = odp_packet_l3_ptr(pkt, NULL);
	uint16_t ip_hdr_len = ipv4_hdr_len(ip);
	odp_crypto_packet_op_param_t param;
	unsigned stats_length;
	int rc;
	uint16_t ipsec_offset;   /**< Offset of IPsec header from
				      buffer start */
	uint8_t	iv[IPSEC_MAX_IV_LEN];  /**< ESP IV storage */
	ipsec_aad_t aad;         /**< AAD, note ESN is not fully supported */
	unsigned hdr_len;        /**< Length of IPsec headers */
	unsigned trl_len;        /**< Length of IPsec trailers */
	uint8_t  ip_tos;         /**< Saved IP TOS value */
	uint8_t  ip_ttl;         /**< Saved IP TTL value */
	uint16_t ip_frag_offset; /**< Saved IP flags value */
	odp_crypto_packet_result_t crypto; /**< Crypto operation result */
	odp_packet_hdr_t *pkt_hdr;

	ODP_ASSERT(ODP_PACKET_OFFSET_INVALID != ip_offset);
	ODP_ASSERT(NULL != ip);

	ip_tos = 0;
	ip_ttl = 0;
	ip_frag_offset = 0;

	ipsec_sa = _odp_ipsec_sa_use(sa);
	ODP_ASSERT(NULL != ipsec_sa);

	/* Initialize parameters block */
	memset(&param, 0, sizeof(param));

	if (ODP_IPSEC_MODE_TRANSPORT == ipsec_sa->mode &&
	    _ODP_IPV4HDR_IS_FRAGMENT(odp_be_to_cpu_16(ip->frag_offset))) {
		status->error.alg = 1;
		goto err;
	}

	if (odp_be_to_cpu_16(ip->tot_len) + ip_offset > odp_packet_len(pkt)) {
		status->error.alg = 1;
		goto err;
	}

	if (ODP_IPSEC_MODE_TUNNEL == ipsec_sa->mode) {
		_odp_ipv4hdr_t out_ip;
		uint16_t tot_len;

		ip->ttl -= ipsec_sa->dec_ttl;

		out_ip.ver_ihl = 0x45;
		if (ipsec_sa->copy_dscp)
			out_ip.tos = ip->tos;
		else
			out_ip.tos = (ip->tos & ~_ODP_IP_TOS_DSCP_MASK) |
				     (ipsec_sa->out.tun_dscp <<
				      _ODP_IP_TOS_DSCP_SHIFT);
		tot_len = odp_be_to_cpu_16(ip->tot_len) + _ODP_IPV4HDR_LEN;
		out_ip.tot_len = odp_cpu_to_be_16(tot_len);
		/* No need to convert to BE: ID just should not be duplicated */
		out_ip.id = odp_atomic_fetch_add_u32(&ipsec_sa->out.tun_hdr_id,
						     1);
		if (ipsec_sa->copy_df)
			out_ip.frag_offset = ip->frag_offset & 0x4000;
		else
			out_ip.frag_offset =
				((uint16_t)ipsec_sa->out.tun_df) << 14;
		out_ip.ttl = ipsec_sa->out.tun_ttl;
		out_ip.proto = _ODP_IPV4;
		/* Will be filled later by packet checksum update */
		out_ip.chksum = 0;
		out_ip.src_addr = ipsec_sa->out.tun_src_ip;
		out_ip.dst_addr = ipsec_sa->out.tun_dst_ip;

		if (odp_packet_extend_head(&pkt, _ODP_IPV4HDR_LEN,
					   NULL, NULL) < 0) {
			status->error.alg = 1;
			goto err;
		}

		odp_packet_move_data(pkt, 0, _ODP_IPV4HDR_LEN, ip_offset);

		odp_packet_copy_from_mem(pkt, ip_offset,
					 _ODP_IPV4HDR_LEN, &out_ip);

		odp_packet_l4_offset_set(pkt, ip_offset + _ODP_IPV4HDR_LEN);

		ip = odp_packet_l3_ptr(pkt, NULL);
		ip_hdr_len = _ODP_IPV4HDR_LEN;
	}

	ipsec_offset = ip_offset + ip_hdr_len;

	if (ipsec_sa->proto == ODP_IPSEC_ESP) {
		_odp_esphdr_t esp;
		_odp_esptrl_t esptrl;
		uint32_t encrypt_len;
		uint16_t ip_data_len = odp_be_to_cpu_16(ip->tot_len) -
				       ip_hdr_len;
		uint32_t pad_block = ipsec_sa->esp_block_len;

		/* ESP trailer should be 32-bit right aligned */
		if (pad_block < 4)
			pad_block = 4;

		encrypt_len = ESP_ENCODE_LEN(ip_data_len + _ODP_ESPTRL_LEN,
					     pad_block);

		hdr_len = _ODP_ESPHDR_LEN + ipsec_sa->esp_iv_len;
		trl_len = encrypt_len -
			       ip_data_len +
			       ipsec_sa->icv_len;

		if (ipsec_sa->use_counter_iv) {
			uint64_t ctr;

			/* Both GCM and CTR use 8-bit counters */
			ODP_ASSERT(sizeof(ctr) == ipsec_sa->esp_iv_len);

			ctr = odp_atomic_fetch_add_u64(&ipsec_sa->out.counter,
						       1);
			/* Check for overrun */
			if (ctr == 0)
				goto err;

			memcpy(iv, ipsec_sa->salt, ipsec_sa->salt_length);
			memcpy(iv + ipsec_sa->salt_length, &ctr,
			       ipsec_sa->esp_iv_len);

			if (ipsec_sa->aes_ctr_iv) {
				iv[12] = 0;
				iv[13] = 0;
				iv[14] = 0;
				iv[15] = 1;
			}
		} else if (ipsec_sa->esp_iv_len) {
			uint32_t len;

			len = odp_random_data(iv, ipsec_sa->esp_iv_len,
					      ODP_RANDOM_CRYPTO);

			if (len != ipsec_sa->esp_iv_len) {
				status->error.alg = 1;
				goto err;
			}
		}

		param.override_iv_ptr = iv;

		if (odp_packet_extend_tail(&pkt, trl_len, NULL, NULL) < 0) {
			status->error.alg = 1;
			goto err;
		}

		if (odp_packet_extend_head(&pkt, hdr_len, NULL, NULL) < 0) {
			status->error.alg = 1;
			goto err;
		}

		odp_packet_move_data(pkt, 0, hdr_len, ipsec_offset);

		ip = odp_packet_l3_ptr(pkt, NULL);

		/* Set IPv4 length before authentication */
		ipv4_adjust_len(ip, hdr_len + trl_len);

		uint32_t esptrl_offset = ip_offset +
					 ip_hdr_len +
					 hdr_len +
					 encrypt_len -
					 _ODP_ESPTRL_LEN;

		memset(&esp, 0, sizeof(esp));
		esp.spi = odp_cpu_to_be_32(ipsec_sa->spi);
		esp.seq_no = odp_cpu_to_be_32(ipsec_seq_no(ipsec_sa));

		aad.spi = esp.spi;
		aad.seq_no = esp.seq_no;

		param.aad.ptr = (uint8_t *)&aad;
		param.aad.length = sizeof(aad);

		memset(&esptrl, 0, sizeof(esptrl));
		esptrl.pad_len = encrypt_len - ip_data_len - _ODP_ESPTRL_LEN;
		esptrl.next_header = ip->proto;
		ip->proto = _ODP_IPPROTO_ESP;

		odp_packet_copy_from_mem(pkt,
					 ipsec_offset, _ODP_ESPHDR_LEN,
					 &esp);
		odp_packet_copy_from_mem(pkt,
					 ipsec_offset + _ODP_ESPHDR_LEN,
					 ipsec_sa->esp_iv_len,
					 iv + ipsec_sa->salt_length);
		odp_packet_copy_from_mem(pkt,
					 esptrl_offset - esptrl.pad_len,
					 esptrl.pad_len, ipsec_padding);
		odp_packet_copy_from_mem(pkt,
					 esptrl_offset, _ODP_ESPTRL_LEN,
					 &esptrl);

		param.cipher_range.offset = ipsec_offset + hdr_len;
		param.cipher_range.length = odp_be_to_cpu_16(ip->tot_len) -
					    ip_hdr_len -
					    hdr_len -
					    ipsec_sa->icv_len;

		param.auth_range.offset = ipsec_offset;
		param.auth_range.length = odp_be_to_cpu_16(ip->tot_len) -
					  ip_hdr_len -
					  ipsec_sa->icv_len;
		param.hash_result_offset = ip_offset +
					   odp_be_to_cpu_16(ip->tot_len) -
					   ipsec_sa->icv_len;

		stats_length = param.cipher_range.length;
	} else if (ipsec_sa->proto == ODP_IPSEC_AH) {
		_odp_ahhdr_t ah;

		hdr_len = _ODP_AHHDR_LEN + ipsec_sa->esp_iv_len +
			ipsec_sa->icv_len;
		trl_len = 0;

		/* Save IPv4 stuff */
		ip_tos = ip->tos;
		ip_frag_offset = odp_be_to_cpu_16(ip->frag_offset);
		ip_ttl = ip->ttl;

		if (odp_packet_extend_tail(&pkt, trl_len, NULL, NULL) < 0) {
			status->error.alg = 1;
			goto err;
		}

		if (odp_packet_extend_head(&pkt, hdr_len, NULL, NULL) < 0) {
			status->error.alg = 1;
			goto err;
		}

		odp_packet_move_data(pkt, 0, hdr_len, ipsec_offset);

		ip = odp_packet_l3_ptr(pkt, NULL);

		/* Set IPv4 length before authentication */
		ipv4_adjust_len(ip, hdr_len + trl_len);

		memset(&ah, 0, sizeof(ah));
		ah.spi = odp_cpu_to_be_32(ipsec_sa->spi);
		ah.ah_len = 1 + (ipsec_sa->esp_iv_len + ipsec_sa->icv_len) / 4;
		ah.seq_no = odp_cpu_to_be_32(ipsec_seq_no(ipsec_sa));
		ah.next_header = ip->proto;
		ip->proto = _ODP_IPPROTO_AH;

		aad.spi = ah.spi;
		aad.seq_no = ah.seq_no;

		param.aad.ptr = (uint8_t *)&aad;
		param.aad.length = sizeof(aad);

		/* For GMAC */
		if (ipsec_sa->use_counter_iv) {
			uint64_t ctr;

			ODP_ASSERT(sizeof(ctr) == ipsec_sa->esp_iv_len);

			ctr = odp_atomic_fetch_add_u64(&ipsec_sa->out.counter,
						       1);
			/* Check for overrun */
			if (ctr == 0)
				goto err;

			memcpy(iv, ipsec_sa->salt, ipsec_sa->salt_length);
			memcpy(iv + ipsec_sa->salt_length, &ctr,
			       ipsec_sa->esp_iv_len);
			param.override_iv_ptr = iv;
		}

		odp_packet_copy_from_mem(pkt,
					 ipsec_offset, _ODP_AHHDR_LEN,
					 &ah);
		odp_packet_copy_from_mem(pkt,
					 ipsec_offset + _ODP_AHHDR_LEN,
					 ipsec_sa->esp_iv_len,
					 iv + ipsec_sa->salt_length);
		_odp_packet_set_data(pkt,
				     ipsec_offset + _ODP_AHHDR_LEN +
				       ipsec_sa->esp_iv_len,
				     0, ipsec_sa->icv_len);

		ip->chksum = 0;
		ip->tos = 0;
		ip->frag_offset = 0;
		ip->ttl = 0;

		param.auth_range.offset = ip_offset;
		param.auth_range.length = odp_be_to_cpu_16(ip->tot_len);
		param.hash_result_offset = ipsec_offset + _ODP_AHHDR_LEN +
					ipsec_sa->esp_iv_len;

		stats_length = param.auth_range.length;
	} else {
		status->error.alg = 1;
		goto err;
	}

	/* No need to run precheck here, we know that packet is authentic */
	if (_odp_ipsec_sa_stats_update(ipsec_sa, stats_length, status) < 0)
		goto err;

	param.session = ipsec_sa->session;

	rc = odp_crypto_op(&pkt, &pkt, &param, 1);
	if (rc < 0) {
		ODP_DBG("Crypto failed\n");
		status->error.alg = 1;
		goto err;
	}

	rc = odp_crypto_result(&crypto, pkt);
	if (rc < 0) {
		ODP_DBG("Crypto failed\n");
		status->error.alg = 1;
		goto err;
	}

	if (!crypto.ok) {
		if ((crypto.cipher_status.alg_err !=
		     ODP_CRYPTO_ALG_ERR_NONE) ||
		    (crypto.cipher_status.hw_err !=
		     ODP_CRYPTO_HW_ERR_NONE))
			status->error.alg = 1;

		if ((crypto.auth_status.alg_err !=
		     ODP_CRYPTO_ALG_ERR_NONE) ||
		    (crypto.auth_status.hw_err !=
		     ODP_CRYPTO_HW_ERR_NONE))
			status->error.auth = 1;

		goto err;
	}

	ip = odp_packet_l3_ptr(pkt, NULL);

	/* Finalize the IPv4 header */
	if (ip->proto == _ODP_IPPROTO_AH) {
		ip->ttl = ip_ttl;
		ip->tos = ip_tos;
		ip->frag_offset = odp_cpu_to_be_16(ip_frag_offset);
	}

	_odp_ipv4_csum_update(pkt);

	*pkt_out = pkt;
	return ipsec_sa;

err:
	pkt_hdr = odp_packet_hdr(pkt);

	pkt_hdr->p.error_flags.ipsec_err = 1;

	*pkt_out = pkt;
	return ipsec_sa;
}

int odp_ipsec_in(const odp_packet_t pkt_in[], int num_in,
		 odp_packet_t pkt_out[], int *num_out,
		 const odp_ipsec_in_param_t *param)
{
	int in_pkt = 0;
	int out_pkt = 0;
	int max_out = *num_out;
	unsigned sa_idx = 0;
	unsigned sa_inc = (param->num_sa > 1) ? 1 : 0;

	while (in_pkt < num_in && out_pkt < max_out) {
		odp_packet_t pkt = pkt_in[in_pkt];
		odp_ipsec_op_status_t status;
		odp_ipsec_sa_t sa;
		ipsec_sa_t *ipsec_sa;
		odp_ipsec_packet_result_t *result;

		memset(&status, 0, sizeof(status));

		if (0 == param->num_sa) {
			sa = ODP_IPSEC_SA_INVALID;
		} else {
			sa = param->sa[sa_idx++];
			ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);
		}

		ipsec_sa = ipsec_in_single(pkt, sa, &pkt, &status);

		_odp_buffer_event_subtype_set(packet_to_buffer(pkt),
					      ODP_EVENT_PACKET_IPSEC);
		result = _odp_ipsec_pkt_result(pkt);
		memset(result, 0, sizeof(*result));
		result->status = status;
		if (NULL != ipsec_sa)
			result->sa = ipsec_sa->ipsec_sa_hdl;
		else
			result->sa = ODP_IPSEC_SA_INVALID;

		pkt_out[out_pkt] = pkt;
		in_pkt++;
		out_pkt++;
		sa_idx += sa_inc;

		/* Last thing */
		if (NULL != ipsec_sa)
			_odp_ipsec_sa_unuse(ipsec_sa);
	}

	*num_out = out_pkt;

	return in_pkt;
}

static odp_ipsec_out_opt_t default_opt = {
	.mode = ODP_IPSEC_FRAG_DISABLED,
};

int odp_ipsec_out(const odp_packet_t pkt_in[], int num_in,
		  odp_packet_t pkt_out[], int *num_out,
		  const odp_ipsec_out_param_t *param)
{
	int in_pkt = 0;
	int out_pkt = 0;
	int max_out = *num_out;
	unsigned sa_idx = 0;
	unsigned opt_idx = 0;
	unsigned sa_inc = (param->num_sa > 1) ? 1 : 0;
	unsigned opt_inc = (param->num_opt > 1) ? 1 : 0;

	ODP_ASSERT(param->num_sa != 0);

	while (in_pkt < num_in && out_pkt < max_out) {
		odp_packet_t pkt = pkt_in[in_pkt];
		odp_ipsec_op_status_t status;
		odp_ipsec_sa_t sa;
		ipsec_sa_t *ipsec_sa;
		odp_ipsec_packet_result_t *result;
		odp_ipsec_out_opt_t *opt;

		memset(&status, 0, sizeof(status));

		sa = param->sa[sa_idx++];
		ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);

		if (0 == param->num_opt)
			opt = &default_opt;
		else
			opt = &param->opt[opt_idx];

		ipsec_sa = ipsec_out_single(pkt, sa, &pkt, opt, &status);
		ODP_ASSERT(NULL != ipsec_sa);

		_odp_buffer_event_subtype_set(packet_to_buffer(pkt),
					      ODP_EVENT_PACKET_IPSEC);
		result = _odp_ipsec_pkt_result(pkt);
		memset(result, 0, sizeof(*result));
		result->status = status;
		result->sa = ipsec_sa->ipsec_sa_hdl;

		pkt_out[out_pkt] = pkt;
		in_pkt++;
		out_pkt++;
		sa_idx += sa_inc;
		opt_idx += opt_inc;

		/* Last thing */
		_odp_ipsec_sa_unuse(ipsec_sa);
	}

	*num_out = out_pkt;

	return in_pkt;
}

int odp_ipsec_in_enq(const odp_packet_t pkt_in[], int num_in,
		     const odp_ipsec_in_param_t *param)
{
	int in_pkt = 0;
	unsigned sa_idx = 0;
	unsigned sa_inc = (param->num_sa > 1) ? 1 : 0;

	while (in_pkt < num_in) {
		odp_packet_t pkt = pkt_in[in_pkt];
		odp_ipsec_op_status_t status;
		odp_ipsec_sa_t sa;
		ipsec_sa_t *ipsec_sa;
		odp_ipsec_packet_result_t *result;
		odp_queue_t queue;

		memset(&status, 0, sizeof(status));

		if (0 == param->num_sa) {
			sa = ODP_IPSEC_SA_INVALID;
		} else {
			sa = param->sa[sa_idx++];
			ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);
		}

		ipsec_sa = ipsec_in_single(pkt, sa, &pkt, &status);

		_odp_buffer_event_subtype_set(packet_to_buffer(pkt),
					      ODP_EVENT_PACKET_IPSEC);
		result = _odp_ipsec_pkt_result(pkt);
		memset(result, 0, sizeof(*result));
		result->status = status;
		if (NULL != ipsec_sa) {
			result->sa = ipsec_sa->ipsec_sa_hdl;
			queue = ipsec_sa->queue;
		} else {
			result->sa = ODP_IPSEC_SA_INVALID;
			queue = ipsec_config.inbound.default_queue;
		}

		if (odp_queue_enq(queue, odp_ipsec_packet_to_event(pkt))) {
			odp_packet_free(pkt);
			break;
		}
		in_pkt++;
		sa_idx += sa_inc;

		/* Last thing */
		if (NULL != ipsec_sa)
			_odp_ipsec_sa_unuse(ipsec_sa);
	}

	return in_pkt;
}

int odp_ipsec_out_enq(const odp_packet_t pkt_in[], int num_in,
		      const odp_ipsec_out_param_t *param)
{
	int in_pkt = 0;
	unsigned sa_idx = 0;
	unsigned opt_idx = 0;
	unsigned sa_inc = (param->num_sa > 1) ? 1 : 0;
	unsigned opt_inc = (param->num_opt > 1) ? 1 : 0;

	ODP_ASSERT(param->num_sa != 0);

	while (in_pkt < num_in) {
		odp_packet_t pkt = pkt_in[in_pkt];
		odp_ipsec_op_status_t status;
		odp_ipsec_sa_t sa;
		ipsec_sa_t *ipsec_sa;
		odp_ipsec_packet_result_t *result;
		odp_ipsec_out_opt_t *opt;
		odp_queue_t queue;

		memset(&status, 0, sizeof(status));

		sa = param->sa[sa_idx++];
		ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);

		if (0 == param->num_opt)
			opt = &default_opt;
		else
			opt = &param->opt[opt_idx];

		ipsec_sa = ipsec_out_single(pkt, sa, &pkt, opt, &status);
		ODP_ASSERT(NULL != ipsec_sa);

		_odp_buffer_event_subtype_set(packet_to_buffer(pkt),
					      ODP_EVENT_PACKET_IPSEC);
		result = _odp_ipsec_pkt_result(pkt);
		memset(result, 0, sizeof(*result));
		result->status = status;
		result->sa = ipsec_sa->ipsec_sa_hdl;
		queue = ipsec_sa->queue;

		if (odp_queue_enq(queue, odp_ipsec_packet_to_event(pkt))) {
			odp_packet_free(pkt);
			break;
		}
		in_pkt++;
		sa_idx += sa_inc;
		opt_idx += opt_inc;

		/* Last thing */
		_odp_ipsec_sa_unuse(ipsec_sa);
	}

	return in_pkt;
}

int _odp_ipsec_try_inline(odp_packet_t pkt)
{
	odp_ipsec_op_status_t status;
	ipsec_sa_t *ipsec_sa;
	odp_ipsec_packet_result_t *result;
	odp_packet_hdr_t *pkt_hdr;

	memset(&status, 0, sizeof(status));

	ipsec_sa = ipsec_in_single(pkt, ODP_IPSEC_SA_INVALID, &pkt, &status);
	/*
	 * Route packet back in case of lookup failure or early error before
	 * lookup
	 */
	if (NULL == ipsec_sa)
		return -1;

	_odp_buffer_event_subtype_set(packet_to_buffer(pkt),
				      ODP_EVENT_PACKET_IPSEC);
	result = _odp_ipsec_pkt_result(pkt);
	memset(result, 0, sizeof(*result));
	result->status = status;
	result->sa = ipsec_sa->ipsec_sa_hdl;
	result->flag.inline_mode = 1;

	pkt_hdr = odp_packet_hdr(pkt);
	pkt_hdr->p.input_flags.dst_queue = 1;
	pkt_hdr->dst_queue = queue_fn->from_ext(ipsec_sa->queue);

	/* Last thing */
	_odp_ipsec_sa_unuse(ipsec_sa);

	return 0;
}

int odp_ipsec_out_inline(const odp_packet_t pkt_in[], int num_in,
			 const odp_ipsec_out_param_t *param,
			 const odp_ipsec_out_inline_param_t *inline_param)
{
	int in_pkt = 0;
	unsigned sa_idx = 0;
	unsigned opt_idx = 0;
	unsigned sa_inc = (param->num_sa > 1) ? 1 : 0;
	unsigned opt_inc = (param->num_opt > 1) ? 1 : 0;

	ODP_ASSERT(param->num_sa != 0);

	while (in_pkt < num_in) {
		odp_packet_t pkt = pkt_in[in_pkt];
		odp_ipsec_op_status_t status;
		odp_ipsec_sa_t sa;
		ipsec_sa_t *ipsec_sa;
		odp_ipsec_packet_result_t *result;
		odp_ipsec_out_opt_t *opt;
		uint32_t hdr_len, offset;
		const void *ptr;

		memset(&status, 0, sizeof(status));

		if (0 == param->num_sa) {
			sa = ODP_IPSEC_SA_INVALID;
		} else {
			sa = param->sa[sa_idx++];
			ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);
		}

		if (0 == param->num_opt)
			opt = &default_opt;
		else
			opt = &param->opt[opt_idx];

		hdr_len = inline_param[in_pkt].outer_hdr.len;
		ptr = inline_param[in_pkt].outer_hdr.ptr;
		offset = odp_packet_l3_offset(pkt);
		if (offset >= hdr_len) {
			if (odp_packet_trunc_head(&pkt, offset - hdr_len,
						  NULL, NULL) < 0)
				status.error.alg = 1;

		} else {
			if (odp_packet_extend_head(&pkt, hdr_len - offset,
						   NULL, NULL) < 0)
				status.error.alg = 1;
		}

		odp_packet_l3_offset_set(pkt, hdr_len);

		if (odp_packet_copy_from_mem(pkt, 0,
					     hdr_len,
					     ptr) < 0)
			status.error.alg = 1;

		ipsec_sa = ipsec_out_single(pkt, sa, &pkt, opt, &status);
		ODP_ASSERT(NULL != ipsec_sa);

		_odp_buffer_event_subtype_set(packet_to_buffer(pkt),
					      ODP_EVENT_PACKET_IPSEC);
		result = _odp_ipsec_pkt_result(pkt);
		memset(result, 0, sizeof(*result));
		result->sa = ipsec_sa->ipsec_sa_hdl;
		result->status = status;

		if (!status.error.all) {
			odp_pktout_queue_t pkqueue;

			if (odp_pktout_queue(inline_param[in_pkt].pktio,
					     &pkqueue, 1) < 0) {
				status.error.alg = 1;
				goto err;
			}

			if (odp_pktout_send(pkqueue, &pkt, 1) < 0) {
				status.error.alg = 1;
				goto err;
			}
		} else {
			odp_queue_t queue;
			odp_buffer_t buf;
err:
			buf = packet_to_buffer(pkt);
			_odp_buffer_event_subtype_set(buf,
						      ODP_EVENT_PACKET_IPSEC);
			result = _odp_ipsec_pkt_result(pkt);
			memset(result, 0, sizeof(*result));
			result->sa = ipsec_sa->ipsec_sa_hdl;
			result->status = status;
			queue = ipsec_sa->queue;

			if (odp_queue_enq(queue,
					  odp_ipsec_packet_to_event(pkt))) {
				odp_packet_free(pkt);
				break;
			}
		}
		in_pkt++;
		sa_idx += sa_inc;
		opt_idx += opt_inc;

		/* Last thing */
		_odp_ipsec_sa_unuse(ipsec_sa);
	}

	return in_pkt;
}

int odp_ipsec_result(odp_ipsec_packet_result_t *result, odp_packet_t packet)
{
	odp_ipsec_packet_result_t *res;

	ODP_ASSERT(result != NULL);

	res = _odp_ipsec_pkt_result(packet);

	/* FIXME: maybe postprocess here, setting alg error in case of crypto
	 * error instead of processing packet fully in ipsec_in/out_single */

	*result = *res;

	return 0;
}

odp_packet_t odp_ipsec_packet_from_event(odp_event_t ev)
{
	return odp_packet_from_event(ev);
}

odp_event_t odp_ipsec_packet_to_event(odp_packet_t pkt)
{
	return odp_packet_to_event(pkt);
}

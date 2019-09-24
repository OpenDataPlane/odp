/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/ipsec.h>
#include <odp/api/chksum.h>

#include <odp/api/plat/packet_inlines.h>
#include <odp/api/byteorder.h>
#include <odp/api/plat/byteorder_inlines.h>

#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_internal.h>
#include <odp_ipsec_internal.h>
#include <odp/api/plat/queue_inlines.h>

#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/ipsec.h>
#include <protocols/udp.h>

#include <string.h>

static odp_ipsec_config_t *ipsec_config;

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

/* This should be enough for all ciphers and auths. Currently used maximum is 3
 * capabilities */
#define MAX_CAPS 10

int odp_ipsec_cipher_capability(odp_cipher_alg_t cipher,
				odp_ipsec_cipher_capability_t capa[], int num)
{
	odp_crypto_cipher_capability_t crypto_capa[MAX_CAPS];
	uint32_t req_iv_len;
	int rc, i, out;

	rc = odp_crypto_cipher_capability(cipher, crypto_capa, MAX_CAPS);
	if (rc <= 0)
		return rc;

	ODP_ASSERT(rc <= MAX_CAPS);
	if (rc > MAX_CAPS)
		rc = MAX_CAPS;

	req_iv_len = _odp_ipsec_cipher_iv_len(cipher);
	for (i = 0, out = 0; i < rc; i++) {
		if (crypto_capa[i].iv_len != req_iv_len)
			continue;

		if (out < num)
			capa[out].key_len = crypto_capa[i].key_len;
		out++;
	}

	return out;
}

int odp_ipsec_auth_capability(odp_auth_alg_t auth,
			      odp_ipsec_auth_capability_t capa[], int num)
{
	odp_crypto_auth_capability_t crypto_capa[MAX_CAPS];
	uint32_t req_digest_len;
	int rc, i, out;

	rc = odp_crypto_auth_capability(auth, crypto_capa, MAX_CAPS);
	if (rc <= 0)
		return rc;

	ODP_ASSERT(rc <= MAX_CAPS);
	if (rc > MAX_CAPS)
		rc = MAX_CAPS;

	req_digest_len = _odp_ipsec_auth_digest_len(auth);
	for (i = 0, out = 0; i < rc; i++) {
		if (crypto_capa[i].digest_len != req_digest_len)
			continue;

		if (ODP_AUTH_ALG_AES_GCM == auth ||
		    ODP_AUTH_ALG_CHACHA20_POLY1305 == auth ||
		    ODP_DEPRECATE(ODP_AUTH_ALG_AES128_GCM) == auth) {
			uint8_t aad_len = 12;

			if (aad_len < crypto_capa[i].aad_len.min ||
			    aad_len > crypto_capa[i].aad_len.max ||
			    0 != (aad_len - crypto_capa[i].aad_len.min) %
				  crypto_capa[i].aad_len.inc)
				continue;
		}

		if (out < num)
			capa[out].key_len = crypto_capa[i].key_len;
		out++;
	}

	return out;
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

int odp_ipsec_config(const odp_ipsec_config_t *config)
{
	if (ODP_CONFIG_IPSEC_SAS > config->max_num_sa)
		return -1;

	*ipsec_config = *config;

	return 0;
}

static odp_ipsec_packet_result_t *ipsec_pkt_result(odp_packet_t packet)
{
	ODP_ASSERT(ODP_EVENT_PACKET_IPSEC ==
		   odp_event_subtype(odp_packet_to_event(packet)));

	return &packet_hdr(packet)->ipsec_ctx;
}

#define _ODP_IPV4HDR_PROTO_OFFSET ODP_OFFSETOF(_odp_ipv4hdr_t, proto)
#define _ODP_IPV6HDR_NHDR_OFFSET ODP_OFFSETOF(_odp_ipv6hdr_t, next_hdr)
#define _ODP_IPV6HDREXT_NHDR_OFFSET ODP_OFFSETOF(_odp_ipv6hdr_ext_t, next_hdr)

#define ipv4_hdr_len(ip) (_ODP_IPV4HDR_IHL((ip)->ver_ihl) * 4)

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

typedef struct {
	void *ip;
	unsigned stats_length;
	uint16_t ip_offset;
	uint16_t ip_hdr_len;
	uint16_t ip_tot_len;
	uint16_t ip_next_hdr_offset;
	uint8_t  ip_next_hdr;
	unsigned is_ipv4 : 1;
	unsigned is_ipv6 : 1;
	union {
		struct {
			uint32_t ip_flabel;
			uint16_t ip_df;
			uint8_t  ip_tos;
		} out_tunnel;
		struct {
			uint16_t hdr_len;
			uint16_t trl_len;
			odp_u32be_t seq_no;
		} in;
		odp_u32be_t ipv4_addr;
		uint8_t ipv6_addr[_ODP_IPV6ADDR_LEN];
	};
	union {
		struct {
			uint8_t  tos;
			uint8_t  ttl;
			odp_u16be_t frag_offset;
		} ah_ipv4;
		struct {
			odp_u32be_t ver_tc_flow;
			uint8_t hop_limit;
		} ah_ipv6;
		struct {
			ipsec_aad_t aad;
		} esp;
	};
	uint8_t	iv[IPSEC_MAX_IV_LEN];
} ipsec_state_t;

static int ipsec_parse_ipv4(ipsec_state_t *state, odp_packet_t pkt)
{
	_odp_ipv4hdr_t ipv4hdr;

	odp_packet_copy_to_mem(pkt, state->ip_offset,
			       _ODP_IPV4HDR_LEN, &ipv4hdr);

	if (_ODP_IPV4HDR_IS_FRAGMENT(odp_be_to_cpu_16(ipv4hdr.frag_offset)))
		return -1;

	state->ip_hdr_len = ipv4_hdr_len(&ipv4hdr);
	state->ip_tot_len = odp_be_to_cpu_16(ipv4hdr.tot_len);
	state->ip_next_hdr = ipv4hdr.proto;
	state->ip_next_hdr_offset = state->ip_offset +
		_ODP_IPV4HDR_PROTO_OFFSET;
	state->ipv4_addr = ipv4hdr.dst_addr;

	return 0;
}

static int ipsec_parse_ipv6(ipsec_state_t *state, odp_packet_t pkt)
{
	_odp_ipv6hdr_t ipv6hdr;
	_odp_ipv6hdr_ext_t ipv6hdrext;

	odp_packet_copy_to_mem(pkt, state->ip_offset,
			       _ODP_IPV6HDR_LEN, &ipv6hdr);

	state->ip_hdr_len = _ODP_IPV6HDR_LEN;
	state->ip_next_hdr = ipv6hdr.next_hdr;
	state->ip_next_hdr_offset = state->ip_offset + _ODP_IPV6HDR_NHDR_OFFSET;
	/* FIXME: Jumbo frames */
	state->ip_tot_len = odp_be_to_cpu_16(ipv6hdr.payload_len) +
			    _ODP_IPV6HDR_LEN;
	memcpy(state->ipv6_addr, &ipv6hdr.dst_addr, _ODP_IPV6ADDR_LEN);

	while (state->ip_next_hdr == _ODP_IPPROTO_HOPOPTS ||
	       state->ip_next_hdr == _ODP_IPPROTO_DEST ||
	       state->ip_next_hdr == _ODP_IPPROTO_ROUTE) {
		odp_packet_copy_to_mem(pkt,
				       state->ip_offset + state->ip_hdr_len,
				       sizeof(ipv6hdrext),
				       &ipv6hdrext);
		state->ip_next_hdr = ipv6hdrext.next_hdr;
		state->ip_next_hdr_offset = state->ip_offset +
			state->ip_hdr_len +
			_ODP_IPV6HDREXT_NHDR_OFFSET;
		state->ip_hdr_len += (ipv6hdrext.ext_len + 1) * 8;
	}

	if (_ODP_IPPROTO_FRAG == state->ip_next_hdr)
		return -1;

	return 0;
}

static inline ipsec_sa_t *ipsec_get_sa(odp_ipsec_sa_t sa,
				       odp_ipsec_protocol_t proto,
				       uint32_t spi,
				       odp_ipsec_ip_version_t ver,
				       void *dst_addr,
				       odp_ipsec_op_status_t *status)
{
	ipsec_sa_t *ipsec_sa;

	if (ODP_IPSEC_SA_INVALID == sa) {
		ipsec_sa_lookup_t lookup;

		lookup.proto = proto;
		lookup.spi = spi;
		lookup.ver = ver;
		lookup.dst_addr = dst_addr;

		ipsec_sa = _odp_ipsec_sa_lookup(&lookup);
		if (NULL == ipsec_sa) {
			status->error.sa_lookup = 1;
			return NULL;
		}
	} else {
		ipsec_sa = _odp_ipsec_sa_use(sa);
		ODP_ASSERT(NULL != ipsec_sa);
		if (ipsec_sa->proto != proto ||
		    ipsec_sa->spi != spi) {
			status->error.proto = 1;
			return ipsec_sa;
		}
	}

	return ipsec_sa;
}

static int ipsec_in_iv(odp_packet_t pkt,
		       ipsec_state_t *state,
		       ipsec_sa_t *ipsec_sa,
		       uint16_t iv_offset)
{
	memcpy(state->iv, ipsec_sa->salt, ipsec_sa->salt_length);
	if (odp_packet_copy_to_mem(pkt,
				   iv_offset,
				   ipsec_sa->esp_iv_len,
				   state->iv + ipsec_sa->salt_length) < 0)
		return -1;

	if (ipsec_sa->aes_ctr_iv) {
		state->iv[12] = 0;
		state->iv[13] = 0;
		state->iv[14] = 0;
		state->iv[15] = 1;
	}

	return 0;
}

static int ipsec_in_esp(odp_packet_t *pkt,
			ipsec_state_t *state,
			ipsec_sa_t **_ipsec_sa,
			odp_ipsec_sa_t sa,
			odp_crypto_packet_op_param_t *param,
			odp_ipsec_op_status_t *status)
{
	_odp_esphdr_t esp;
	uint16_t ipsec_offset;
	ipsec_sa_t *ipsec_sa;
	odp_bool_t udp_encap = false;

	ipsec_offset = state->ip_offset + state->ip_hdr_len;

	if (_ODP_IPPROTO_UDP == state->ip_next_hdr) {
		_odp_udphdr_t udp;
		uint16_t ip_data_len = state->ip_tot_len -
				       state->ip_hdr_len;

		odp_packet_copy_to_mem(*pkt, ipsec_offset,
				       _ODP_UDPHDR_LEN, &udp);

		if (udp.dst_port != odp_cpu_to_be_16(_ODP_UDP_IPSEC_PORT) ||
		    udp.length != odp_cpu_to_be_16(ip_data_len)) {
			status->error.proto = 1;
			return -1;
		}

		ipsec_offset += _ODP_UDPHDR_LEN;
		state->ip_hdr_len += _ODP_UDPHDR_LEN;
		udp_encap = true;
	}

	if (odp_packet_copy_to_mem(*pkt, ipsec_offset,
				   sizeof(esp), &esp) < 0) {
		status->error.alg = 1;
		return -1;
	}

	ipsec_sa = ipsec_get_sa(sa, ODP_IPSEC_ESP,
				odp_be_to_cpu_32(esp.spi),
				state->is_ipv4 ? ODP_IPSEC_IPV4 :
						ODP_IPSEC_IPV6,
				&state->ipv4_addr, status);
	*_ipsec_sa = ipsec_sa;
	if (status->error.all)
		return -1;

	if (!!ipsec_sa->udp_encap != udp_encap) {
		status->error.proto = 1;
		return -1;
	}

	if (ipsec_in_iv(*pkt, state, ipsec_sa,
			ipsec_offset + _ODP_ESPHDR_LEN) < 0) {
		status->error.alg = 1;
		return -1;
	}

	state->in.hdr_len = _ODP_ESPHDR_LEN + ipsec_sa->esp_iv_len;
	state->in.trl_len = _ODP_ESPTRL_LEN + ipsec_sa->icv_len;

	if (odp_unlikely(state->ip_tot_len <
			 state->ip_hdr_len + state->in.hdr_len + ipsec_sa->icv_len)) {
		status->error.proto = 1;
		return -1;
	}

	param->cipher_range.offset = ipsec_offset + state->in.hdr_len;
	param->cipher_range.length = state->ip_tot_len -
				    state->ip_hdr_len -
				    state->in.hdr_len -
				    ipsec_sa->icv_len;
	param->cipher_iv_ptr = state->iv;
	param->auth_iv_ptr = state->iv;

	state->esp.aad.spi = esp.spi;
	state->esp.aad.seq_no = esp.seq_no;
	state->in.seq_no = odp_be_to_cpu_32(esp.seq_no);

	param->aad_ptr = (uint8_t *)&state->esp.aad;

	param->auth_range.offset = ipsec_offset;
	param->auth_range.length = state->ip_tot_len -
				  state->ip_hdr_len -
				  ipsec_sa->icv_len;
	param->hash_result_offset = state->ip_offset +
				   state->ip_tot_len -
				   ipsec_sa->icv_len;

	state->stats_length = param->cipher_range.length;

	return 0;
}

static int ipsec_in_esp_post(odp_packet_t pkt,
			     ipsec_state_t *state)
{
	_odp_esptrl_t esptrl;
	uint32_t esptrl_offset = state->ip_offset +
				 state->ip_tot_len -
				 state->in.trl_len;

	if (odp_packet_copy_to_mem(pkt, esptrl_offset,
				   sizeof(esptrl), &esptrl) < 0 ||
	    state->ip_offset + esptrl.pad_len > esptrl_offset ||
	    _odp_packet_cmp_data(pkt, esptrl_offset - esptrl.pad_len,
				 ipsec_padding, esptrl.pad_len) != 0)
		return -1;

	if (_ODP_IPPROTO_UDP == state->ip_next_hdr) {
		state->ip_hdr_len -= _ODP_UDPHDR_LEN;
		state->in.hdr_len += _ODP_UDPHDR_LEN;
	}

	odp_packet_copy_from_mem(pkt, state->ip_next_hdr_offset,
				 1, &esptrl.next_header);
	state->in.trl_len += esptrl.pad_len;
	state->ip_next_hdr = esptrl.next_header;

	return 0;
}

static int ipsec_in_ah(odp_packet_t *pkt,
		       ipsec_state_t *state,
		       ipsec_sa_t **_ipsec_sa,
		       odp_ipsec_sa_t sa,
		       odp_crypto_packet_op_param_t *param,
		       odp_ipsec_op_status_t *status)
{
	_odp_ahhdr_t ah;
	uint16_t ipsec_offset;
	ipsec_sa_t *ipsec_sa;

	ipsec_offset = state->ip_offset + state->ip_hdr_len;

	if (odp_packet_copy_to_mem(*pkt, ipsec_offset,
				   sizeof(ah), &ah) < 0) {
		status->error.alg = 1;
		return -1;
	}

	ipsec_sa = ipsec_get_sa(sa, ODP_IPSEC_AH,
				odp_be_to_cpu_32(ah.spi),
				state->is_ipv4 ? ODP_IPSEC_IPV4 :
						ODP_IPSEC_IPV6,
				&state->ipv4_addr, status);
	*_ipsec_sa = ipsec_sa;
	if (status->error.all)
		return -1;

	if (ipsec_in_iv(*pkt, state, ipsec_sa,
			ipsec_offset + _ODP_AHHDR_LEN) < 0) {
		status->error.alg = 1;
		return -1;
	}

	param->auth_iv_ptr = state->iv;

	state->in.hdr_len = (ah.ah_len + 2) * 4;
	state->in.trl_len = 0;

	if (state->is_ipv4) {
		_odp_ipv4hdr_t *ipv4hdr = state->ip;

		/* Save everything to context */
		state->ah_ipv4.tos = ipv4hdr->tos;
		state->ah_ipv4.frag_offset = ipv4hdr->frag_offset;
		state->ah_ipv4.ttl = ipv4hdr->ttl;

		/* FIXME: zero copy of header, passing it to crypto! */
		/*
		 * If authenticating, zero the mutable fields build the request
		 */
		ipv4hdr->chksum = 0;
		ipv4hdr->tos = 0;
		ipv4hdr->frag_offset = 0;
		ipv4hdr->ttl = 0;
	} else {
		_odp_ipv6hdr_t *ipv6hdr = state->ip;

		state->ah_ipv6.ver_tc_flow = ipv6hdr->ver_tc_flow;
		state->ah_ipv6.hop_limit = ipv6hdr->hop_limit;
		ipv6hdr->ver_tc_flow =
			odp_cpu_to_be_32(6 << _ODP_IPV6HDR_VERSION_SHIFT);
		ipv6hdr->hop_limit = 0;
	}

	state->in.seq_no = odp_be_to_cpu_32(ah.seq_no);

	param->auth_range.offset = state->ip_offset;
	param->auth_range.length = state->ip_tot_len;
	param->hash_result_offset = ipsec_offset + _ODP_AHHDR_LEN +
				ipsec_sa->esp_iv_len;

	state->stats_length = param->auth_range.length;

	return 0;
}

static int ipsec_in_ah_post(odp_packet_t pkt,
			    ipsec_state_t *state)
{
	_odp_ahhdr_t ah;
	uint16_t ipsec_offset;

	ipsec_offset = state->ip_offset + state->ip_hdr_len;

	if (odp_packet_copy_to_mem(pkt, ipsec_offset,
				   sizeof(ah), &ah) < 0)
		return -1;

	odp_packet_copy_from_mem(pkt, state->ip_next_hdr_offset,
				 1, &ah.next_header);

	/* Restore mutable fields */
	if (state->is_ipv4) {
		_odp_ipv4hdr_t *ipv4hdr = state->ip;

		ipv4hdr->ttl = state->ah_ipv4.ttl;
		ipv4hdr->tos = state->ah_ipv4.tos;
		ipv4hdr->frag_offset = state->ah_ipv4.frag_offset;
	} else {
		_odp_ipv6hdr_t *ipv6hdr = odp_packet_l3_ptr(pkt, NULL);

		ipv6hdr->ver_tc_flow = state->ah_ipv6.ver_tc_flow;
		ipv6hdr->hop_limit = state->ah_ipv6.hop_limit;
	}
	state->ip_next_hdr = ah.next_header;

	return 0;
}

static ipsec_sa_t *ipsec_in_single(odp_packet_t pkt,
				   odp_ipsec_sa_t sa,
				   odp_packet_t *pkt_out,
				   odp_ipsec_op_status_t *status)
{
	ipsec_state_t state;
	ipsec_sa_t *ipsec_sa = NULL;
	odp_crypto_packet_op_param_t param;
	int rc;
	odp_crypto_packet_result_t crypto; /**< Crypto operation result */
	odp_packet_hdr_t *pkt_hdr;

	state.ip_offset = odp_packet_l3_offset(pkt);
	ODP_ASSERT(ODP_PACKET_OFFSET_INVALID != state.ip_offset);

	state.ip = odp_packet_l3_ptr(pkt, NULL);
	ODP_ASSERT(NULL != state.ip);

	/* Initialize parameters block */
	memset(&param, 0, sizeof(param));

	/*
	 * FIXME: maybe use packet flag as below ???
	 * This adds requirement that input packets contain not only valid
	 * l3/l4 offsets, but also valid packet flags
	 * state.is_ipv4 = odp_packet_has_ipv4(pkt);
	 */
	state.is_ipv4 = (((uint8_t *)state.ip)[0] >> 4) == 0x4;
	state.is_ipv6 = (((uint8_t *)state.ip)[0] >> 4) == 0x6;
	if (state.is_ipv4)
		rc = ipsec_parse_ipv4(&state, pkt);
	else if (state.is_ipv6)
		rc = ipsec_parse_ipv6(&state, pkt);
	else
		rc = -1;
	if (rc < 0 ||
	    state.ip_tot_len + state.ip_offset > odp_packet_len(pkt)) {
		status->error.alg = 1;
		goto err;
	}

	/* Check IP header for IPSec protocols and look it up */
	if (_ODP_IPPROTO_ESP == state.ip_next_hdr ||
	    _ODP_IPPROTO_UDP == state.ip_next_hdr) {
		rc = ipsec_in_esp(&pkt, &state, &ipsec_sa, sa, &param, status);
	} else if (_ODP_IPPROTO_AH == state.ip_next_hdr) {
		rc = ipsec_in_ah(&pkt, &state, &ipsec_sa, sa, &param, status);
	} else {
		status->error.proto = 1;
		goto err;
	}
	if (rc < 0)
		goto err;

	if (_odp_ipsec_sa_replay_precheck(ipsec_sa,
					  state.in.seq_no,
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

	if (_odp_ipsec_sa_stats_update(ipsec_sa,
				       state.stats_length,
				       status) < 0)
		goto err;

	if (_odp_ipsec_sa_replay_update(ipsec_sa,
					state.in.seq_no,
					status) < 0)
		goto err;

	state.ip = odp_packet_l3_ptr(pkt, NULL);

	if (ODP_IPSEC_ESP == ipsec_sa->proto)
		rc = ipsec_in_esp_post(pkt, &state);
	else if (ODP_IPSEC_AH == ipsec_sa->proto)
		rc = ipsec_in_ah_post(pkt, &state);
	else
		rc = -1;
	if (rc < 0) {
		status->error.proto = 1;
		goto err;
	}

	if (odp_packet_trunc_tail(&pkt, state.in.trl_len, NULL, NULL) < 0) {
		status->error.alg = 1;
		goto err;
	}
	state.ip_tot_len -= state.in.trl_len;

	if (ODP_IPSEC_MODE_TUNNEL == ipsec_sa->mode) {
		/* We have a tunneled IPv4 packet, strip outer and IPsec
		 * headers */
		odp_packet_move_data(pkt, state.ip_hdr_len + state.in.hdr_len,
				     0,
				     state.ip_offset);
		if (odp_packet_trunc_head(&pkt, state.ip_hdr_len +
					  state.in.hdr_len,
					  NULL, NULL) < 0) {
			status->error.alg = 1;
			goto err;
		}
		state.ip_tot_len -= state.ip_hdr_len + state.in.hdr_len;
		if (_ODP_IPPROTO_IPIP == state.ip_next_hdr) {
			state.is_ipv4 = 1;
			state.is_ipv6 = 0;
		} else if (_ODP_IPPROTO_IPV6 == state.ip_next_hdr) {
			state.is_ipv4 = 0;
			state.is_ipv6 = 1;
		} else if (_ODP_IPPROTO_NO_NEXT == state.ip_next_hdr) {
			state.is_ipv4 = 0;
			state.is_ipv6 = 0;
		} else {
			status->error.proto = 1;
			goto err;
		}
	} else {
		odp_packet_move_data(pkt, state.in.hdr_len, 0,
				     state.ip_offset + state.ip_hdr_len);
		if (odp_packet_trunc_head(&pkt, state.in.hdr_len,
					  NULL, NULL) < 0) {
			status->error.alg = 1;
			goto err;
		}
		state.ip_tot_len -= state.in.hdr_len;
	}

	/* Finalize the IPv4 header */
	if (state.is_ipv4 && odp_packet_len(pkt) > _ODP_IPV4HDR_LEN) {
		_odp_ipv4hdr_t *ipv4hdr = odp_packet_l3_ptr(pkt, NULL);

		if (ODP_IPSEC_MODE_TRANSPORT == ipsec_sa->mode)
			ipv4hdr->tot_len = odp_cpu_to_be_16(state.ip_tot_len);
		else
			ipv4hdr->ttl -= ipsec_sa->dec_ttl;
		_odp_packet_ipv4_chksum_insert(pkt);
	} else if (state.is_ipv6 && odp_packet_len(pkt) > _ODP_IPV6HDR_LEN) {
		_odp_ipv6hdr_t *ipv6hdr = odp_packet_l3_ptr(pkt, NULL);

		if (ODP_IPSEC_MODE_TRANSPORT == ipsec_sa->mode)
			ipv6hdr->payload_len =
				odp_cpu_to_be_16(state.ip_tot_len -
						  _ODP_IPV6HDR_LEN);
		else
			ipv6hdr->hop_limit -= ipsec_sa->dec_ttl;
	} else if (state.ip_next_hdr != _ODP_IPPROTO_NO_NEXT) {
		status->error.proto = 1;
		goto err;
	}

	if (_ODP_IPPROTO_NO_NEXT == state.ip_next_hdr &&
	    ODP_IPSEC_MODE_TUNNEL == ipsec_sa->mode) {
		odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

		packet_parse_reset(pkt_hdr);
		pkt_hdr->p.l3_offset = state.ip_offset;
	} else {
		odp_packet_parse_param_t parse_param;

		parse_param.proto = state.is_ipv4 ? ODP_PROTO_IPV4 :
			state.is_ipv6 ? ODP_PROTO_IPV6 :
			ODP_PROTO_NONE;
		parse_param.last_layer = ipsec_config->inbound.parse_level;
		parse_param.chksums = ipsec_config->inbound.chksums;

		/* We do not care about return code here.
		 * Parsing error should not result in IPsec error. */
		odp_packet_parse(pkt, state.ip_offset, &parse_param);
	}

	*pkt_out = pkt;

	return ipsec_sa;

err:
	pkt_hdr = packet_hdr(pkt);
	pkt_hdr->p.flags.ipsec_err = 1;

	*pkt_out = pkt;

	return ipsec_sa;
}

/* Generate sequence number */
static inline
uint64_t ipsec_seq_no(ipsec_sa_t *ipsec_sa)
{
	return odp_atomic_fetch_add_u64(&ipsec_sa->hot.out.seq, 1);
}

/* Helper for calculating encode length using data length and block size */
#define IPSEC_PAD_LEN(x, b) ((((x) + ((b) - 1)) / (b)) * (b))

static int ipsec_out_tunnel_parse_ipv4(ipsec_state_t *state,
				       ipsec_sa_t *ipsec_sa)
{
	_odp_ipv4hdr_t *ipv4hdr = state->ip;
	uint16_t flags = odp_be_to_cpu_16(ipv4hdr->frag_offset);

	ipv4hdr->ttl -= ipsec_sa->dec_ttl;
	state->out_tunnel.ip_tos = ipv4hdr->tos;
	state->out_tunnel.ip_df = _ODP_IPV4HDR_FLAGS_DONT_FRAG(flags);
	state->out_tunnel.ip_flabel = 0;
	state->ip_next_hdr = ipv4hdr->proto;

	return 0;
}

static int ipsec_out_tunnel_parse_ipv6(ipsec_state_t *state,
				       ipsec_sa_t *ipsec_sa)
{
	_odp_ipv6hdr_t *ipv6hdr = state->ip;

	ipv6hdr->hop_limit -= ipsec_sa->dec_ttl;
	state->out_tunnel.ip_tos = (ipv6hdr->ver_tc_flow &
				    _ODP_IPV6HDR_TC_MASK) >>
		_ODP_IPV6HDR_TC_SHIFT;
	state->out_tunnel.ip_df = 0;
	state->out_tunnel.ip_flabel = (ipv6hdr->ver_tc_flow &
				       _ODP_IPV6HDR_FLOW_LABEL_MASK) >>
		_ODP_IPV6HDR_FLOW_LABEL_SHIFT;
	state->ip_next_hdr = ipv6hdr->next_hdr;

	return 0;
}

static int ipsec_out_tunnel_ipv4(odp_packet_t *pkt,
				 ipsec_state_t *state,
				 ipsec_sa_t *ipsec_sa,
				 const odp_ipsec_ipv4_param_t *ipv4_param)
{
	_odp_ipv4hdr_t out_ip;
	uint16_t flags;

	out_ip.ver_ihl = 0x45;
	if (ipsec_sa->copy_dscp)
		out_ip.tos = state->out_tunnel.ip_tos;
	else
		out_ip.tos = (state->out_tunnel.ip_tos &
			      ~_ODP_IP_TOS_DSCP_MASK) |
			     (ipv4_param->dscp <<
			      _ODP_IP_TOS_DSCP_SHIFT);
	state->ip_tot_len = odp_packet_len(*pkt) - state->ip_offset;
	state->ip_tot_len += _ODP_IPV4HDR_LEN;

	out_ip.tot_len = odp_cpu_to_be_16(state->ip_tot_len);
	if (ipsec_sa->copy_df)
		flags = state->out_tunnel.ip_df;
	else
		flags = ((uint16_t)ipv4_param->df) << 14;
	out_ip.frag_offset = odp_cpu_to_be_16(flags);

	/* Allocate unique IP ID only for non-atomic datagrams */
	if (out_ip.frag_offset == 0)
		out_ip.id = _odp_ipsec_sa_alloc_ipv4_id(ipsec_sa);
	else
		out_ip.id = 0;

	out_ip.ttl = ipv4_param->ttl;
	/* Will be filled later by packet checksum update */
	out_ip.chksum = 0;
	memcpy(&out_ip.src_addr, ipv4_param->src_addr,
	       _ODP_IPV4ADDR_LEN);
	memcpy(&out_ip.dst_addr, ipv4_param->dst_addr,
	       _ODP_IPV4ADDR_LEN);

	if (odp_packet_extend_head(pkt, _ODP_IPV4HDR_LEN,
				   NULL, NULL) < 0)
		return -1;

	odp_packet_move_data(*pkt, 0, _ODP_IPV4HDR_LEN, state->ip_offset);

	odp_packet_copy_from_mem(*pkt, state->ip_offset,
				 _ODP_IPV4HDR_LEN, &out_ip);

	odp_packet_l4_offset_set(*pkt, state->ip_offset + _ODP_IPV4HDR_LEN);

	state->ip = odp_packet_l3_ptr(*pkt, NULL);
	state->ip_hdr_len = _ODP_IPV4HDR_LEN;
	if (state->is_ipv4)
		state->ip_next_hdr = _ODP_IPPROTO_IPIP;
	else if (state->is_ipv6)
		state->ip_next_hdr = _ODP_IPPROTO_IPV6;
	else
		state->ip_next_hdr = _ODP_IPPROTO_NO_NEXT;
	state->ip_next_hdr_offset = state->ip_offset +
		_ODP_IPV4HDR_PROTO_OFFSET;

	state->is_ipv4 = 1;
	state->is_ipv6 = 0;

	return 0;
}

static int ipsec_out_tunnel_ipv6(odp_packet_t *pkt,
				 ipsec_state_t *state,
				 ipsec_sa_t *ipsec_sa,
				 const odp_ipsec_ipv6_param_t *ipv6_param)
{
	_odp_ipv6hdr_t out_ip;
	uint32_t ver;

	ver = 6 << _ODP_IPV6HDR_VERSION_SHIFT;
	if (ipsec_sa->copy_dscp)
		ver |= state->out_tunnel.ip_tos << _ODP_IPV6HDR_TC_SHIFT;
	else
		ver |= ((state->out_tunnel.ip_tos &
			 ~_ODP_IP_TOS_DSCP_MASK) |
			(ipv6_param->dscp <<
			 _ODP_IP_TOS_DSCP_SHIFT)) <<
			_ODP_IPV6HDR_TC_SHIFT;
	if (ipsec_sa->copy_flabel)
		ver |= state->out_tunnel.ip_flabel;
	else
		ver |= ipv6_param->flabel;
	out_ip.ver_tc_flow = odp_cpu_to_be_32(ver);

	state->ip_tot_len = odp_packet_len(*pkt) - state->ip_offset;
	out_ip.payload_len = odp_cpu_to_be_16(state->ip_tot_len);
	state->ip_tot_len += _ODP_IPV6HDR_LEN;

	out_ip.hop_limit = ipv6_param->hlimit;
	memcpy(&out_ip.src_addr, ipv6_param->src_addr,
	       _ODP_IPV6ADDR_LEN);
	memcpy(&out_ip.dst_addr, ipv6_param->dst_addr,
	       _ODP_IPV6ADDR_LEN);

	if (odp_packet_extend_head(pkt, _ODP_IPV6HDR_LEN,
				   NULL, NULL) < 0)
		return -1;

	odp_packet_move_data(*pkt, 0, _ODP_IPV6HDR_LEN, state->ip_offset);

	odp_packet_copy_from_mem(*pkt, state->ip_offset,
				 sizeof(out_ip), &out_ip);

	odp_packet_l4_offset_set(*pkt, state->ip_offset + _ODP_IPV6HDR_LEN);

	state->ip = odp_packet_l3_ptr(*pkt, NULL);
	state->ip_hdr_len = _ODP_IPV6HDR_LEN;
	if (state->is_ipv4)
		state->ip_next_hdr = _ODP_IPPROTO_IPIP;
	else if (state->is_ipv6)
		state->ip_next_hdr = _ODP_IPPROTO_IPV6;
	else
		state->ip_next_hdr = _ODP_IPPROTO_NO_NEXT;
	state->ip_next_hdr_offset = state->ip_offset + _ODP_IPV6HDR_NHDR_OFFSET;

	state->is_ipv4 = 0;
	state->is_ipv6 = 1;

	return 0;
}

#define IPSEC_RANDOM_BUF_SIZE 256

static int ipsec_random_data(uint8_t *data, uint32_t len)
{
	static __thread uint8_t buffer[IPSEC_RANDOM_BUF_SIZE];
	static __thread uint32_t buffer_used = IPSEC_RANDOM_BUF_SIZE;

	if (odp_likely(buffer_used + len <= IPSEC_RANDOM_BUF_SIZE)) {
		memcpy(data, &buffer[buffer_used], len);
		buffer_used += len;
	} else if (odp_likely(len <= IPSEC_RANDOM_BUF_SIZE)) {
		uint32_t rnd_len;

		rnd_len = odp_random_data(buffer, IPSEC_RANDOM_BUF_SIZE,
					  odp_global_ro.ipsec_rand_kind);
		if (odp_unlikely(rnd_len != IPSEC_RANDOM_BUF_SIZE))
			return -1;
		memcpy(data, &buffer[0], len);
		buffer_used = len;
	} else {
		return -1;
	}
	return 0;
}

static int ipsec_out_iv(ipsec_state_t *state,
			ipsec_sa_t *ipsec_sa,
			uint64_t seq_no)
{
	if (ipsec_sa->use_counter_iv) {
		/* Both GCM and CTR use 8-bit counters */
		ODP_ASSERT(sizeof(seq_no) == ipsec_sa->esp_iv_len);

		/* Check for overrun */
		if (seq_no == 0)
			return -1;

		memcpy(state->iv, ipsec_sa->salt, ipsec_sa->salt_length);
		memcpy(state->iv + ipsec_sa->salt_length, &seq_no,
		       ipsec_sa->esp_iv_len);

		if (ipsec_sa->aes_ctr_iv) {
			state->iv[12] = 0;
			state->iv[13] = 0;
			state->iv[14] = 0;
			state->iv[15] = 1;
		}
	} else if (ipsec_sa->esp_iv_len) {
		if (ipsec_random_data(state->iv, ipsec_sa->esp_iv_len))
			return -1;
	}

	return 0;
}

static int ipsec_out_esp(odp_packet_t *pkt,
			 ipsec_state_t *state,
			 ipsec_sa_t *ipsec_sa,
			 odp_crypto_packet_op_param_t *param,
			 odp_ipsec_op_status_t *status,
			 uint32_t mtu,
			 const odp_ipsec_out_opt_t *opt)
{
	_odp_esphdr_t esp;
	_odp_esptrl_t esptrl;
	_odp_udphdr_t udphdr;
	uint32_t encrypt_len;
	uint16_t ip_data_len = state->ip_tot_len -
			       state->ip_hdr_len;
	uint16_t tfc_len = (opt->flag.tfc_pad || opt->flag.tfc_dummy) ?
		opt->tfc_pad_len : 0;
	uint32_t pad_block = ipsec_sa->esp_block_len;
	uint16_t ipsec_offset = state->ip_offset + state->ip_hdr_len;
	unsigned hdr_len;
	unsigned trl_len;
	unsigned pkt_len, new_len;
	uint8_t proto = _ODP_IPPROTO_ESP;
	uint64_t seq_no;

	if (odp_unlikely(opt->flag.tfc_dummy)) {
		ip_data_len = 0;
		state->ip_tot_len = state->ip_offset + state->ip_hdr_len;
	}

	/* ESP trailer should be 32-bit right aligned */
	if (pad_block < 4)
		pad_block = 4;

	encrypt_len = IPSEC_PAD_LEN(ip_data_len + tfc_len + _ODP_ESPTRL_LEN,
				    pad_block);

	hdr_len = _ODP_ESPHDR_LEN + ipsec_sa->esp_iv_len;
	trl_len = encrypt_len -
		       ip_data_len +
		       ipsec_sa->icv_len;

	if (ipsec_sa->udp_encap) {
		hdr_len += _ODP_UDPHDR_LEN;
		proto = _ODP_IPPROTO_UDP;
		udphdr.src_port = odp_cpu_to_be_16(_ODP_UDP_IPSEC_PORT);
		udphdr.dst_port = odp_cpu_to_be_16(_ODP_UDP_IPSEC_PORT);
		udphdr.length = odp_cpu_to_be_16(ip_data_len +
						  hdr_len + trl_len);
		udphdr.chksum = 0; /* should be 0 by RFC */
	}

	if (state->ip_tot_len + hdr_len + trl_len > mtu) {
		status->error.mtu = 1;
		return -1;
	}

	seq_no = ipsec_seq_no(ipsec_sa);

	if (ipsec_out_iv(state, ipsec_sa, seq_no) < 0) {
		status->error.alg = 1;
		return -1;
	}

	param->cipher_iv_ptr = state->iv;
	param->auth_iv_ptr = state->iv;

	memset(&esp, 0, sizeof(esp));
	esp.spi = odp_cpu_to_be_32(ipsec_sa->spi);
	esp.seq_no = odp_cpu_to_be_32(seq_no & 0xffffffff);

	state->esp.aad.spi = esp.spi;
	state->esp.aad.seq_no = esp.seq_no;

	param->aad_ptr = (uint8_t *)&state->esp.aad;

	memset(&esptrl, 0, sizeof(esptrl));
	esptrl.pad_len = encrypt_len - ip_data_len - tfc_len - _ODP_ESPTRL_LEN;
	esptrl.next_header = state->ip_next_hdr;

	odp_packet_copy_from_mem(*pkt, state->ip_next_hdr_offset, 1, &proto);
	state->ip_tot_len += hdr_len + trl_len;
	if (state->is_ipv4) {
		_odp_ipv4hdr_t *ipv4hdr = state->ip;

		ipv4hdr->tot_len = odp_cpu_to_be_16(state->ip_tot_len);
	} else if (state->is_ipv6) {
		_odp_ipv6hdr_t *ipv6hdr = state->ip;

		ipv6hdr->payload_len = odp_cpu_to_be_16(state->ip_tot_len -
							 _ODP_IPV6HDR_LEN);
	}

	if (odp_packet_extend_head(pkt, hdr_len, NULL, NULL) < 0) {
		status->error.alg = 1;
		return -1;
	}

	pkt_len = odp_packet_len(*pkt);
	new_len = state->ip_offset + state->ip_tot_len;
	if (pkt_len >= new_len) {
		if (odp_packet_trunc_tail(pkt, pkt_len - new_len,
					  NULL, NULL) < 0) {
			status->error.alg = 1;
			return -1;
		}
	} else {
		if (odp_packet_extend_tail(pkt, new_len - pkt_len,
					   NULL, NULL) < 0) {
			status->error.alg = 1;
			return -1;
		}
	}

	odp_packet_move_data(*pkt, 0, hdr_len, ipsec_offset);

	uint32_t esptrl_offset = state->ip_offset +
				 state->ip_hdr_len +
				 hdr_len +
				 encrypt_len -
				 _ODP_ESPTRL_LEN;

	if (ipsec_sa->udp_encap) {
		odp_packet_copy_from_mem(*pkt, ipsec_offset, _ODP_UDPHDR_LEN,
					 &udphdr);
		ipsec_offset += _ODP_UDPHDR_LEN;
		hdr_len -= _ODP_UDPHDR_LEN;
		state->ip_hdr_len += _ODP_UDPHDR_LEN;
	}

	odp_packet_copy_from_mem(*pkt,
				 ipsec_offset, _ODP_ESPHDR_LEN,
				 &esp);
	odp_packet_copy_from_mem(*pkt,
				 ipsec_offset + _ODP_ESPHDR_LEN,
				 ipsec_sa->esp_iv_len,
				 state->iv + ipsec_sa->salt_length);
	/* 0xa5 is a good value to fill data instead of generating random data
	 * to create TFC padding */
	_odp_packet_set_data(*pkt, esptrl_offset - esptrl.pad_len - tfc_len,
			     0xa5, tfc_len);
	odp_packet_copy_from_mem(*pkt,
				 esptrl_offset - esptrl.pad_len,
				 esptrl.pad_len, ipsec_padding);
	odp_packet_copy_from_mem(*pkt,
				 esptrl_offset, _ODP_ESPTRL_LEN,
				 &esptrl);

	if (odp_unlikely(state->ip_tot_len <
			 state->ip_hdr_len + hdr_len + ipsec_sa->icv_len)) {
		status->error.proto = 1;
		return -1;
	}

	param->cipher_range.offset = ipsec_offset + hdr_len;
	param->cipher_range.length = state->ip_tot_len -
				    state->ip_hdr_len -
				    hdr_len -
				    ipsec_sa->icv_len;

	param->auth_range.offset = ipsec_offset;
	param->auth_range.length = state->ip_tot_len -
				  state->ip_hdr_len -
				  ipsec_sa->icv_len;
	param->hash_result_offset = state->ip_offset +
				   state->ip_tot_len -
				   ipsec_sa->icv_len;

	state->stats_length = param->cipher_range.length;

	return 0;
}

static void ipsec_out_esp_post(ipsec_state_t *state, odp_packet_t pkt)
{
	if (state->is_ipv4)
		_odp_packet_ipv4_chksum_insert(pkt);
}

static int ipsec_out_ah(odp_packet_t *pkt,
			ipsec_state_t *state,
			ipsec_sa_t *ipsec_sa,
			odp_crypto_packet_op_param_t *param,
			odp_ipsec_op_status_t *status,
			uint32_t mtu)
{
	_odp_ahhdr_t ah;
	unsigned hdr_len = _ODP_AHHDR_LEN + ipsec_sa->esp_iv_len +
		ipsec_sa->icv_len;
	uint16_t ipsec_offset = state->ip_offset + state->ip_hdr_len;
	uint8_t proto = _ODP_IPPROTO_AH;
	uint64_t seq_no;

	if (state->ip_tot_len + hdr_len > mtu) {
		status->error.mtu = 1;
		return -1;
	}

	seq_no = ipsec_seq_no(ipsec_sa);

	memset(&ah, 0, sizeof(ah));
	ah.spi = odp_cpu_to_be_32(ipsec_sa->spi);
	ah.seq_no = odp_cpu_to_be_32(seq_no & 0xffffffff);
	ah.next_header = state->ip_next_hdr;

	odp_packet_copy_from_mem(*pkt, state->ip_next_hdr_offset, 1, &proto);
	/* Save IP stuff */
	if (state->is_ipv4) {
		_odp_ipv4hdr_t *ipv4hdr = state->ip;

		state->ah_ipv4.tos = ipv4hdr->tos;
		state->ah_ipv4.frag_offset = ipv4hdr->frag_offset;
		state->ah_ipv4.ttl = ipv4hdr->ttl;
		ipv4hdr->chksum = 0;
		ipv4hdr->tos = 0;
		ipv4hdr->frag_offset = 0;
		ipv4hdr->ttl = 0;
		hdr_len = IPSEC_PAD_LEN(hdr_len, 4);
		state->ip_tot_len += hdr_len;
		ipv4hdr->tot_len = odp_cpu_to_be_16(state->ip_tot_len);
	} else {
		_odp_ipv6hdr_t *ipv6hdr = state->ip;

		state->ah_ipv6.ver_tc_flow = ipv6hdr->ver_tc_flow;
		state->ah_ipv6.hop_limit = ipv6hdr->hop_limit;
		ipv6hdr->ver_tc_flow =
			odp_cpu_to_be_32(6 << _ODP_IPV6HDR_VERSION_SHIFT);
		ipv6hdr->hop_limit = 0;

		hdr_len = IPSEC_PAD_LEN(hdr_len, 8);
		state->ip_tot_len += hdr_len;
		ipv6hdr->payload_len = odp_cpu_to_be_16(state->ip_tot_len -
							 _ODP_IPV6HDR_LEN);
	}

	ah.ah_len = hdr_len / 4 - 2;

	/* For GMAC */
	if (ipsec_out_iv(state, ipsec_sa, seq_no) < 0) {
		status->error.alg = 1;
		return -1;
	}

	param->auth_iv_ptr = state->iv;

	if (odp_packet_extend_head(pkt, hdr_len, NULL, NULL) < 0) {
		status->error.alg = 1;
		return -1;
	}

	odp_packet_move_data(*pkt, 0, hdr_len, ipsec_offset);

	odp_packet_copy_from_mem(*pkt,
				 ipsec_offset, _ODP_AHHDR_LEN,
				 &ah);
	odp_packet_copy_from_mem(*pkt,
				 ipsec_offset + _ODP_AHHDR_LEN,
				 ipsec_sa->esp_iv_len,
				 state->iv + ipsec_sa->salt_length);
	_odp_packet_set_data(*pkt,
			     ipsec_offset + _ODP_AHHDR_LEN +
			       ipsec_sa->esp_iv_len,
			     0,
			     hdr_len - _ODP_AHHDR_LEN - ipsec_sa->esp_iv_len);

	param->auth_range.offset = state->ip_offset;
	param->auth_range.length = state->ip_tot_len;
	param->hash_result_offset = ipsec_offset + _ODP_AHHDR_LEN +
				ipsec_sa->esp_iv_len;

	state->stats_length = param->auth_range.length;

	return 0;
}

static void ipsec_out_ah_post(ipsec_state_t *state, odp_packet_t pkt)
{
	if (state->is_ipv4) {
		_odp_ipv4hdr_t *ipv4hdr = odp_packet_l3_ptr(pkt, NULL);

		ipv4hdr->ttl = state->ah_ipv4.ttl;
		ipv4hdr->tos = state->ah_ipv4.tos;
		ipv4hdr->frag_offset = state->ah_ipv4.frag_offset;

		_odp_packet_ipv4_chksum_insert(pkt);
	} else {
		_odp_ipv6hdr_t *ipv6hdr = odp_packet_l3_ptr(pkt, NULL);

		ipv6hdr->ver_tc_flow = state->ah_ipv6.ver_tc_flow;
		ipv6hdr->hop_limit = state->ah_ipv6.hop_limit;
	}
}

#define OL_TX_CHKSUM_PKT(_cfg, _proto, _ovr_set, _ovr) \
	(_proto && (_ovr_set ? _ovr : _cfg))

static void ipsec_out_checksums(odp_packet_t pkt,
				ipsec_state_t *state)
{
	odp_bool_t ipv4_chksum_pkt, udp_chksum_pkt, tcp_chksum_pkt,
		   sctp_chksum_pkt;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);
	odp_ipsec_outbound_config_t outbound = ipsec_config->outbound;

	ipv4_chksum_pkt = OL_TX_CHKSUM_PKT(outbound.chksum.inner_ipv4,
					   state->is_ipv4,
					   pkt_hdr->p.flags.l3_chksum_set,
					   pkt_hdr->p.flags.l3_chksum);
	udp_chksum_pkt =  OL_TX_CHKSUM_PKT(outbound.chksum.inner_udp,
					   state->ip_next_hdr ==
					   _ODP_IPPROTO_UDP,
					   pkt_hdr->p.flags.l4_chksum_set,
					   pkt_hdr->p.flags.l4_chksum);
	tcp_chksum_pkt =  OL_TX_CHKSUM_PKT(outbound.chksum.inner_tcp,
					   state->ip_next_hdr ==
					   _ODP_IPPROTO_TCP,
					   pkt_hdr->p.flags.l4_chksum_set,
					   pkt_hdr->p.flags.l4_chksum);

	sctp_chksum_pkt =  OL_TX_CHKSUM_PKT(outbound.chksum.inner_sctp,
					    state->ip_next_hdr ==
					    _ODP_IPPROTO_SCTP,
					    pkt_hdr->p.flags.l4_chksum_set,
					    pkt_hdr->p.flags.l4_chksum);

	if (ipv4_chksum_pkt)
		_odp_packet_ipv4_chksum_insert(pkt);

	if (tcp_chksum_pkt)
		_odp_packet_tcp_chksum_insert(pkt);

	if (udp_chksum_pkt)
		_odp_packet_udp_chksum_insert(pkt);

	if (sctp_chksum_pkt)
		_odp_packet_sctp_chksum_insert(pkt);
}

static ipsec_sa_t *ipsec_out_single(odp_packet_t pkt,
				    odp_ipsec_sa_t sa,
				    odp_packet_t *pkt_out,
				    const odp_ipsec_out_opt_t *opt,
				    odp_ipsec_op_status_t *status)
{
	ipsec_state_t state;
	ipsec_sa_t *ipsec_sa;
	odp_crypto_packet_op_param_t param;
	int rc;
	odp_crypto_packet_result_t crypto; /**< Crypto operation result */
	odp_packet_hdr_t *pkt_hdr;
	odp_ipsec_frag_mode_t frag_mode;
	uint32_t mtu;

	/*
	 * No need to do _odp_ipsec_sa_use() here since an ODP application
	 * is not allowed to do call IPsec output before SA creation has
	 * completed nor call odp_ipsec_sa_disable() before IPsec output
	 * has completed. IOW, the needed sychronization between threads
	 * is done by the application.
	 */
	ipsec_sa = _odp_ipsec_sa_entry_from_hdl(sa);
	ODP_ASSERT(NULL != ipsec_sa);

	if (opt->flag.tfc_dummy) {
		odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

		ODP_ASSERT(ODP_IPSEC_MODE_TUNNEL == ipsec_sa->mode);
		pkt_hdr->p.l2_offset = ODP_PACKET_OFFSET_INVALID;
		pkt_hdr->p.l3_offset = 0;
		state.ip_offset = 0;
		state.ip = NULL;
		state.is_ipv4 = 0;
		state.is_ipv6 = 0;
	} else {
		state.ip_offset = odp_packet_l3_offset(pkt);
		ODP_ASSERT(ODP_PACKET_OFFSET_INVALID != state.ip_offset);

		state.ip = odp_packet_l3_ptr(pkt, NULL);
		ODP_ASSERT(NULL != state.ip);

		state.is_ipv4 = (((uint8_t *)state.ip)[0] >> 4) == 0x4;
		state.is_ipv6 = (((uint8_t *)state.ip)[0] >> 4) == 0x6;
	}

	frag_mode = opt->flag.frag_mode ? opt->frag_mode :
					  ipsec_sa->out.frag_mode;
	if (frag_mode == ODP_IPSEC_FRAG_CHECK)
		mtu = ipsec_sa->out.mtu;
	else
		mtu = UINT32_MAX;

	/* Initialize parameters block */
	memset(&param, 0, sizeof(param));

	if (ODP_IPSEC_MODE_TRANSPORT == ipsec_sa->mode) {
		if (state.is_ipv4)
			rc = ipsec_parse_ipv4(&state, pkt);
		else if (state.is_ipv6)
			rc = ipsec_parse_ipv6(&state, pkt);
		else
			rc = -1;

		if (state.ip_tot_len + state.ip_offset != odp_packet_len(pkt))
			rc = -1;

		if (rc == 0)
			ipsec_out_checksums(pkt, &state);
	} else {
		if (state.is_ipv4)
			rc = ipsec_out_tunnel_parse_ipv4(&state, ipsec_sa);
		else if (state.is_ipv6)
			rc = ipsec_out_tunnel_parse_ipv6(&state, ipsec_sa);
		else if (opt->flag.tfc_dummy) {
			state.out_tunnel.ip_tos = 0;
			state.out_tunnel.ip_df = 0;
			state.out_tunnel.ip_flabel = 0;
			rc = 0;
		} else
			rc = -1;
		if (rc < 0) {
			status->error.alg = 1;
			goto err;
		}

		ipsec_out_checksums(pkt, &state);

		if (ipsec_sa->tun_ipv4)
			rc = ipsec_out_tunnel_ipv4(&pkt, &state, ipsec_sa,
						   opt->flag.ip_param ?
						   &opt->ipv4 :
						   &ipsec_sa->out.tun_ipv4.param);
		else
			rc = ipsec_out_tunnel_ipv6(&pkt, &state, ipsec_sa,
						   opt->flag.ip_param ?
						   &opt->ipv6 :
						   &ipsec_sa->out.tun_ipv6.param);
	}
	if (rc < 0) {
		status->error.alg = 1;
		goto err;
	}

	if (ODP_IPSEC_ESP == ipsec_sa->proto) {
		rc = ipsec_out_esp(&pkt, &state, ipsec_sa, &param, status, mtu,
				   opt);
	} else if (ODP_IPSEC_AH == ipsec_sa->proto) {
		rc = ipsec_out_ah(&pkt, &state, ipsec_sa, &param, status, mtu);
	} else {
		status->error.alg = 1;
		goto err;
	}
	if (rc < 0)
		goto err;

	/* No need to run precheck here, we know that packet is authentic */
	if (_odp_ipsec_sa_stats_update(ipsec_sa,
				       state.stats_length,
				       status) < 0)
		goto err;

	param.session = ipsec_sa->session;

	/*
	 * NOTE: Do not change to an asynchronous design without thinking
	 * concurrency and what changes are required to guarantee that
	 * used SAs are not destroyed when asynchronous operations are in
	 * progress.
	 *
	 * The containing code does not hold a reference to the SA but
	 * completes outbound processing synchronously and makes use of
	 * the fact that the application may not disable (and then destroy)
	 * the SA before this output routine returns (and all its side
	 * effects are visible to the disabling thread).
	 */
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

	/* Finalize the IPv4 header */
	if (ODP_IPSEC_ESP == ipsec_sa->proto)
		ipsec_out_esp_post(&state, pkt);
	else if (ODP_IPSEC_AH == ipsec_sa->proto)
		ipsec_out_ah_post(&state, pkt);

	_odp_packet_ipv4_chksum_insert(pkt);

	*pkt_out = pkt;
	return ipsec_sa;

err:
	pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.ipsec_err = 1;

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

		packet_subtype_set(pkt, ODP_EVENT_PACKET_IPSEC);
		result = ipsec_pkt_result(pkt);
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

static odp_ipsec_out_opt_t default_out_opt;

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
		const odp_ipsec_out_opt_t *opt;

		memset(&status, 0, sizeof(status));

		sa = param->sa[sa_idx++];
		ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);

		if (0 == param->num_opt)
			opt = &default_out_opt;
		else
			opt = &param->opt[opt_idx];

		ipsec_sa = ipsec_out_single(pkt, sa, &pkt, opt, &status);
		ODP_ASSERT(NULL != ipsec_sa);

		packet_subtype_set(pkt, ODP_EVENT_PACKET_IPSEC);
		result = ipsec_pkt_result(pkt);
		memset(result, 0, sizeof(*result));
		result->status = status;
		result->sa = ipsec_sa->ipsec_sa_hdl;

		pkt_out[out_pkt] = pkt;
		in_pkt++;
		out_pkt++;
		sa_idx += sa_inc;
		opt_idx += opt_inc;
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

		packet_subtype_set(pkt, ODP_EVENT_PACKET_IPSEC);
		result = ipsec_pkt_result(pkt);
		memset(result, 0, sizeof(*result));
		result->status = status;
		if (NULL != ipsec_sa) {
			result->sa = ipsec_sa->ipsec_sa_hdl;
			queue = ipsec_sa->queue;
		} else {
			result->sa = ODP_IPSEC_SA_INVALID;
			queue = ipsec_config->inbound.default_queue;
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
		const odp_ipsec_out_opt_t *opt;
		odp_queue_t queue;

		memset(&status, 0, sizeof(status));

		sa = param->sa[sa_idx++];
		ODP_ASSERT(ODP_IPSEC_SA_INVALID != sa);

		if (0 == param->num_opt)
			opt = &default_out_opt;
		else
			opt = &param->opt[opt_idx];

		ipsec_sa = ipsec_out_single(pkt, sa, &pkt, opt, &status);
		ODP_ASSERT(NULL != ipsec_sa);

		packet_subtype_set(pkt, ODP_EVENT_PACKET_IPSEC);
		result = ipsec_pkt_result(pkt);
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
	}

	return in_pkt;
}

int _odp_ipsec_try_inline(odp_packet_t *pkt)
{
	odp_ipsec_op_status_t status;
	ipsec_sa_t *ipsec_sa;
	odp_ipsec_packet_result_t *result;
	odp_packet_hdr_t *pkt_hdr;

	memset(&status, 0, sizeof(status));

	ipsec_sa = ipsec_in_single(*pkt, ODP_IPSEC_SA_INVALID, pkt, &status);
	/*
	 * Route packet back in case of lookup failure or early error before
	 * lookup
	 */
	if (NULL == ipsec_sa)
		return -1;

	packet_subtype_set(*pkt, ODP_EVENT_PACKET_IPSEC);
	result = ipsec_pkt_result(*pkt);
	memset(result, 0, sizeof(*result));
	result->status = status;
	result->sa = ipsec_sa->ipsec_sa_hdl;
	result->flag.inline_mode = 1;

	pkt_hdr = packet_hdr(*pkt);
	pkt_hdr->p.input_flags.dst_queue = 1;
	pkt_hdr->dst_queue = ipsec_sa->queue;

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
		const odp_ipsec_out_opt_t *opt;
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
			opt = &default_out_opt;
		else
			opt = &param->opt[opt_idx];

		ipsec_sa = ipsec_out_single(pkt, sa, &pkt, opt, &status);
		ODP_ASSERT(NULL != ipsec_sa);

		hdr_len = inline_param[in_pkt].outer_hdr.len;
		ptr = inline_param[in_pkt].outer_hdr.ptr;
		offset = odp_packet_l3_offset(pkt);
		if (odp_unlikely(offset == ODP_PACKET_OFFSET_INVALID))
			offset = 0;
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

		packet_subtype_set(pkt, ODP_EVENT_PACKET_IPSEC);
		result = ipsec_pkt_result(pkt);
		memset(result, 0, sizeof(*result));
		result->sa = ipsec_sa->ipsec_sa_hdl;
		result->status = status;

		if (!status.error.all) {
			odp_pktout_queue_t pkqueue;

			if (odp_pktout_queue(inline_param[in_pkt].pktio,
					     &pkqueue, 1) <= 0) {
				status.error.alg = 1;
				goto err;
			}

			if (odp_pktout_send(pkqueue, &pkt, 1) < 0) {
				status.error.alg = 1;
				goto err;
			}
		} else {
			odp_queue_t queue;
err:
			packet_subtype_set(pkt, ODP_EVENT_PACKET_IPSEC);
			result = ipsec_pkt_result(pkt);
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
	}

	return in_pkt;
}

int odp_ipsec_result(odp_ipsec_packet_result_t *result, odp_packet_t packet)
{
	odp_ipsec_packet_result_t *res;

	ODP_ASSERT(result != NULL);

	res = ipsec_pkt_result(packet);

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

int _odp_ipsec_init_global(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("_odp_ipsec", sizeof(odp_ipsec_config_t),
			      ODP_CACHE_LINE_SIZE, 0);

	ipsec_config = odp_shm_addr(shm);

	if (ipsec_config == NULL) {
		ODP_ERR("Shm reserve failed for odp_ipsec\n");
		return -1;
	}

	odp_ipsec_config_init(ipsec_config);

	memset(&default_out_opt, 0, sizeof(default_out_opt));

	odp_global_ro.ipsec_rand_kind = ODP_RANDOM_CRYPTO;
	if (odp_global_ro.ipsec_rand_kind > odp_random_max_kind())
		odp_global_ro.ipsec_rand_kind = odp_random_max_kind();

	return 0;
}

int _odp_ipsec_term_global(void)
{
	odp_shm_t shm = odp_shm_lookup("_odp_ipsec");

	if (shm == ODP_SHM_INVALID || odp_shm_free(shm)) {
		ODP_ERR("Shm free failed for odp_ipsec");
		return -1;
	}

	return 0;
}

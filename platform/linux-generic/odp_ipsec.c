/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2018-2022 Nokia
 */

#include <odp/api/byteorder.h>
#include <odp/api/ipsec.h>
#include <odp/api/chksum.h>

#include <odp/api/plat/byteorder_inlines.h>
#include <odp/api/plat/ipsec_inlines.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/queue_inlines.h>

#include <odp_global_data.h>
#include <odp_init_internal.h>
#include <odp_debug_internal.h>
#include <odp_macros_internal.h>
#include <odp_packet_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_classification_internal.h>
#include <odp_libconfig_internal.h>
#include <odp_schedule_if.h>

#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/ipsec.h>
#include <protocols/udp.h>

#include <errno.h>
#include <string.h>

typedef enum {
	IPSEC_ORDERING_NONE = 0,
	IPSEC_ORDERING_SIMPLE,
} ordering_mode_t;

typedef struct {
	ordering_mode_t inbound_ordering_mode;
	ordering_mode_t outbound_ordering_mode;
	odp_ipsec_config_t ipsec_config;
} ipsec_global_t;

static ipsec_global_t *ipsec_global;

static odp_ipsec_config_t *ipsec_config;

/*
 * Wait until the ordered scheduling context of this thread corresponds
 * to the head of its input queue. Do nothing if ordering is not requested
 * or if not holding an ordered context.
 */
static void wait_for_order(ordering_mode_t mode)
{
	if (mode == IPSEC_ORDERING_NONE)
		return;
	_odp_sched_fn->order_lock();
	/*
	 * We rely on the unlock being no-op, so let's not even bother
	 * calling it. Unlock cannot really be anything but a no-op since
	 * the scheduler cannot let other threads to continue until at
	 * scheduling context release time.
	 *
	 * _odp_sched_fn->order_unlock();
	 */
}

/*
 * Set cabability bits for algorithms that are defined for use with IPsec
 * and for which the IPsec crypto or auth capability function returns
 * at least one supported instance.
 */
static int set_ipsec_crypto_capa(odp_ipsec_capability_t *capa)
{
	odp_crypto_capability_t crypto_capa;

	crypto_capa.ciphers.all_bits = 0;
	crypto_capa.auths.all_bits = 0;

	if (odp_crypto_capability(&crypto_capa))
		return -1;

#define CHECK_CIPHER(field, alg) do {				\
	if (crypto_capa.ciphers.bit.field &&			\
	    odp_ipsec_cipher_capability(alg, NULL, 0) > 0)	\
		capa->ciphers.bit.field = 1;			\
} while (0)

	CHECK_CIPHER(null,		ODP_CIPHER_ALG_NULL);
	CHECK_CIPHER(des,		ODP_CIPHER_ALG_DES);
	CHECK_CIPHER(trides_cbc,	ODP_CIPHER_ALG_3DES_CBC);
	CHECK_CIPHER(aes_cbc,		ODP_CIPHER_ALG_AES_CBC);
	CHECK_CIPHER(aes_ctr,		ODP_CIPHER_ALG_AES_CTR);
	CHECK_CIPHER(aes_gcm,		ODP_CIPHER_ALG_AES_GCM);
	CHECK_CIPHER(aes_ccm,		ODP_CIPHER_ALG_AES_CCM);
	CHECK_CIPHER(chacha20_poly1305,	ODP_CIPHER_ALG_CHACHA20_POLY1305);

#define CHECK_AUTH(field, alg) do {				\
	if (crypto_capa.auths.bit.field &&			\
	    odp_ipsec_auth_capability(alg, NULL, 0) > 0)	\
		capa->auths.bit.field = 1;			\
} while (0)

	CHECK_AUTH(null,		ODP_AUTH_ALG_NULL);
	CHECK_AUTH(md5_hmac,		ODP_AUTH_ALG_MD5_HMAC);
	CHECK_AUTH(sha1_hmac,		ODP_AUTH_ALG_SHA1_HMAC);
	CHECK_AUTH(sha256_hmac,		ODP_AUTH_ALG_SHA256_HMAC);
	CHECK_AUTH(sha384_hmac,		ODP_AUTH_ALG_SHA384_HMAC);
	CHECK_AUTH(sha512_hmac,		ODP_AUTH_ALG_SHA512_HMAC);
	CHECK_AUTH(aes_gcm,		ODP_AUTH_ALG_AES_GCM);
	CHECK_AUTH(aes_gmac,		ODP_AUTH_ALG_AES_GMAC);
	CHECK_AUTH(aes_ccm,		ODP_AUTH_ALG_AES_CCM);
	CHECK_AUTH(aes_cmac,		ODP_AUTH_ALG_AES_CMAC);
	CHECK_AUTH(aes_xcbc_mac,	ODP_AUTH_ALG_AES_XCBC_MAC);
	CHECK_AUTH(chacha20_poly1305,	ODP_AUTH_ALG_CHACHA20_POLY1305);

	/*
	 * Certain combined mode algorithms are configured by setting
	 * both cipher and auth to the corresponding algorithm when
	 * creating an SA. Since such algorithms cannot be combined
	 * with anything else, clear both capability fields if the
	 * cipher and auth check did not both succeed.
	 *
	 * Although AES-GMAC is a combined mode algorithm, it does
	 * not appear here because it is configured by setting cipher
	 * to null.
	 */
#define REQUIRE_BOTH(field) do {		\
	if (!capa->ciphers.bit.field)		\
		capa->auths.bit.field = 0;	\
	if (!capa->auths.bit.field)		\
		capa->ciphers.bit.field = 0;	\
	} while (0)

	REQUIRE_BOTH(aes_gcm);
	REQUIRE_BOTH(aes_ccm);
	REQUIRE_BOTH(chacha20_poly1305);

	return 0;
}

int odp_ipsec_capability(odp_ipsec_capability_t *capa)
{
	int rc;
	odp_queue_capability_t queue_capa;

	if (odp_global_ro.disable.ipsec) {
		_ODP_ERR("IPSec is disabled\n");
		return -1;
	}

	memset(capa, 0, sizeof(odp_ipsec_capability_t));

	capa->op_mode_sync = ODP_SUPPORT_PREFERRED;
	capa->op_mode_async = ODP_SUPPORT_PREFERRED;
	capa->op_mode_inline_in = ODP_SUPPORT_PREFERRED;
	capa->op_mode_inline_out = ODP_SUPPORT_PREFERRED;

	capa->proto_ah = ODP_SUPPORT_YES;

	capa->max_num_sa = _odp_ipsec_max_num_sa();

	capa->max_antireplay_ws = IPSEC_AR_WIN_SIZE_MAX;

	rc = set_ipsec_crypto_capa(capa);
	if (rc < 0)
		return rc;

	capa->queue_type_plain = true;
	capa->queue_type_sched = true;

	rc = odp_queue_capability(&queue_capa);
	if (rc < 0)
		return rc;

	capa->max_queues = queue_capa.max_queues;
	capa->inline_ipsec_tm = ODP_SUPPORT_NO;

	capa->test.sa_operations.seq_num = 1;

	capa->reassembly.ip = false;
	capa->reassembly.ipv4 = false;
	capa->reassembly.ipv6 = false;
	capa->reass_async = false;
	capa->reass_inline = false;

	return 0;
}

static int cipher_requires_randomness(odp_cipher_alg_t cipher)
{
	int ret;

	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
	case ODP_CIPHER_ALG_AES_CTR:
	case ODP_CIPHER_ALG_AES_GCM:
	case ODP_CIPHER_ALG_AES_CCM:
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		ret = 0;
		break;
	default:
		ret = 1;
		break;
	}
	return ret;
}

int odp_ipsec_cipher_capability(odp_cipher_alg_t cipher,
				odp_ipsec_cipher_capability_t capa[], int num)
{
	uint32_t req_iv_len;
	int rc, i, out, max_capa;

	if (odp_random_max_kind() < ODP_RANDOM_CRYPTO &&
	    cipher_requires_randomness(cipher))
		return 0;

	max_capa = odp_crypto_cipher_capability(cipher, NULL, 0);
	if (max_capa <= 0)
		return max_capa;

	odp_crypto_cipher_capability_t crypto_capa[max_capa];

	rc = odp_crypto_cipher_capability(cipher, crypto_capa, max_capa);
	if (rc <= 0)
		return rc;

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
	uint32_t req_digest_len;
	int rc, i, out, max_capa;

	max_capa = odp_crypto_auth_capability(auth, NULL, 0);
	if (max_capa <= 0)
		return max_capa;

	odp_crypto_auth_capability_t crypto_capa[max_capa];

	rc = odp_crypto_auth_capability(auth, crypto_capa, max_capa);
	if (rc <= 0)
		return rc;

	req_digest_len = _odp_ipsec_auth_digest_len(auth);
	for (i = 0, out = 0; i < rc; i++) {
		if (crypto_capa[i].digest_len != req_digest_len)
			continue;

		if (ODP_AUTH_ALG_AES_GCM == auth ||
		    ODP_AUTH_ALG_CHACHA20_POLY1305 == auth) {
			uint8_t aad_len = 12;

			if (aad_len < crypto_capa[i].aad_len.min ||
			    aad_len > crypto_capa[i].aad_len.max ||
			    0 != (aad_len - crypto_capa[i].aad_len.min) %
				  crypto_capa[i].aad_len.inc)
				continue;
		}

		if (out < num) {
			capa[out].key_len = crypto_capa[i].key_len;
			capa[out].icv_len = crypto_capa[i].digest_len;
		}
		out++;
	}

	return out;
}

void odp_ipsec_config_init(odp_ipsec_config_t *config)
{
	memset(config, 0, sizeof(odp_ipsec_config_t));
	config->inbound_mode = ODP_IPSEC_OP_MODE_SYNC;
	config->outbound_mode = ODP_IPSEC_OP_MODE_SYNC;
	config->max_num_sa = _odp_ipsec_max_num_sa();
	config->inbound.default_queue = ODP_QUEUE_INVALID;
	config->inbound.lookup.min_spi = 0;
	config->inbound.lookup.max_spi = UINT32_MAX;
	config->inbound.reassembly.max_num_frags = 2;
	config->stats_en = false;
}

int odp_ipsec_config(const odp_ipsec_config_t *config)
{
	if (config->max_num_sa > _odp_ipsec_max_num_sa())
		return -1;

	*ipsec_config = *config;

	return 0;
}

odp_bool_t _odp_ipsec_is_sync_mode(odp_ipsec_dir_t dir)
{
	return ((dir == ODP_IPSEC_DIR_INBOUND &&
		 ipsec_config->inbound_mode == ODP_IPSEC_OP_MODE_SYNC) ||
		(dir == ODP_IPSEC_DIR_OUTBOUND &&
		 ipsec_config->outbound_mode == ODP_IPSEC_OP_MODE_SYNC));
}

static odp_ipsec_packet_result_t *ipsec_pkt_result(odp_packet_t packet)
{
	_ODP_ASSERT(ODP_EVENT_PACKET_IPSEC ==
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
			uint64_t seq_no;
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

#define MAX_BURST 32

typedef struct {
	ipsec_state_t state;
	odp_ipsec_op_status_t status;
	ipsec_sa_t *sa;
	odp_ipsec_sa_t sa_hdl;
	uint32_t orig_ip_len;
} ipsec_op_t;

#define MAX_HDR_LEN 100 /* Enough for VxLAN over IPv6 */

typedef struct {
	ipsec_op_t op;
	uint8_t hdr_buf[MAX_HDR_LEN];
} ipsec_inline_op_t;

/*
 * Computes 64-bit seq number according to RFC4303 A2
 */
static inline uint64_t ipsec_compute_esn(ipsec_sa_t *ipsec_sa, uint32_t seq)
{
	uint32_t wintop_h, wintop_l, winbot_l, ws;
	uint64_t seq64 = 0, wintop = 0;

	wintop = odp_atomic_load_u64(&ipsec_sa->hot.in.wintop_seq);
	wintop_l = wintop & 0xffffffff;
	wintop_h = wintop >> 32;

	ws = ipsec_sa->in.ar.win_size;
	winbot_l = wintop_l - ws + 1;

	/* case A: window is within one sequence number subspace */
	if (wintop_l >= (ws - 1)) {
		if (seq < winbot_l)
			wintop_h++;
	/* case B: window spans two sequence number subspaces */
	} else {
		if (seq >= winbot_l)
			wintop_h--;
	}

	seq64 = ((uint64_t)wintop_h << 32) | seq;
	return seq64;
}

static inline uint32_t ipsec_get_seqh_len(ipsec_sa_t *ipsec_sa)
{
	return ipsec_sa->insert_seq_hi * IPSEC_SEQ_HI_LEN;
}

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
		ipsec_sa = _odp_ipsec_sa_entry_from_hdl(sa);
		_ODP_ASSERT(NULL != ipsec_sa);
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
	if (ipsec_sa->salt_length > 0) {
		/* It is faster to just copy MAX_SALT_LEN bytes than the exact length */
		ODP_STATIC_ASSERT(IPSEC_MAX_SALT_LEN <= IPSEC_MAX_IV_LEN,
				  "IPSEC_MAX_SALT_LEN too large");
		memcpy(state->iv, ipsec_sa->salt, IPSEC_MAX_SALT_LEN);
	}
	_ODP_ASSERT(ipsec_sa->salt_length + ipsec_sa->esp_iv_len <= IPSEC_MAX_IV_LEN);
	if (odp_packet_copy_to_mem(pkt,
				   iv_offset,
				   ipsec_sa->esp_iv_len,
				   state->iv + ipsec_sa->salt_length) < 0)
		return -1;

	if (ipsec_sa->aes_ctr_iv) {
		ODP_STATIC_ASSERT(IPSEC_MAX_IV_LEN >= 16, "IPSEC_MAX_IV_LEN too small");
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
	state->in.seq_no = odp_be_to_cpu_32(esp.seq_no);

	if (ipsec_sa->esn) {
		state->in.seq_no = ipsec_compute_esn(ipsec_sa, state->in.seq_no);
		state->esp.aad.seq_no64 = odp_cpu_to_be_64(state->in.seq_no);
	} else {
		state->esp.aad.seq_no = esp.seq_no;
	}
	param->aad_ptr = (uint8_t *)&state->esp.aad;

	/* Insert high-order bits of ESN before the ICV for ICV check
	 * with non-combined mode algorithms.
	 */
	if (ipsec_sa->insert_seq_hi) {
		uint32_t inb_seqh = odp_cpu_to_be_32(state->in.seq_no >> 32);
		uint32_t icv_offset =  odp_packet_len(*pkt) - ipsec_sa->icv_len;

		if (odp_packet_extend_tail(pkt, IPSEC_SEQ_HI_LEN, NULL, NULL) < 0) {
			status->error.alg = 1;
			_ODP_ERR("odp_packet_extend_tail failed\n");
			return -1;
		}
		odp_packet_move_data(*pkt, icv_offset + IPSEC_SEQ_HI_LEN, icv_offset,
				     ipsec_sa->icv_len);
		odp_packet_copy_from_mem(*pkt, icv_offset, IPSEC_SEQ_HI_LEN, &inb_seqh);
	}

	param->auth_range.offset = ipsec_offset;
	param->auth_range.length = state->ip_tot_len -
				  state->ip_hdr_len +
				  ipsec_get_seqh_len(ipsec_sa) -
				  ipsec_sa->icv_len;
	param->hash_result_offset = state->ip_offset +
				   state->ip_tot_len +
				   ipsec_get_seqh_len(ipsec_sa) -
				   ipsec_sa->icv_len;

	state->stats_length = param->cipher_range.length;
	param->session = ipsec_sa->session;

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
	if (ipsec_sa->esn)
		state->in.seq_no = ipsec_compute_esn(ipsec_sa, state->in.seq_no);

	/* ESN higher 32 bits are included at the end of the packet data
	 * for inbound ICV computation.
	 */
	if (ipsec_sa->insert_seq_hi) {
		uint32_t inb_seqh = odp_cpu_to_be_32(state->in.seq_no >> 32);
		uint32_t seqh_offset =  odp_packet_len(*pkt);

		if (odp_packet_extend_tail(pkt, IPSEC_SEQ_HI_LEN, NULL, NULL) < 0) {
			status->error.alg = 1;
			_ODP_ERR("odp_packet_extend_tail failed\n");
			return -1;
		}
		odp_packet_copy_from_mem(*pkt, seqh_offset, IPSEC_SEQ_HI_LEN, &inb_seqh);
	}

	param->auth_range.offset = state->ip_offset;
	param->auth_range.length = state->ip_tot_len;
	param->hash_result_offset = ipsec_offset + _ODP_AHHDR_LEN +
				ipsec_sa->esp_iv_len;

	state->stats_length = param->auth_range.length;
	param->auth_range.length += ipsec_get_seqh_len(ipsec_sa);
	param->session = ipsec_sa->session;

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

static void
ipsec_sa_err_stats_update(ipsec_sa_t *sa, odp_ipsec_op_status_t *status)
{
	odp_ipsec_op_status_t err_status;

	if (odp_likely(ODP_IPSEC_OK == status->error.all))
		return;

	if (NULL == sa)
		return;

	err_status = *status;

	if (err_status.error.proto)
		odp_atomic_inc_u64(&sa->stats.proto_err);

	if (err_status.error.auth)
		odp_atomic_inc_u64(&sa->stats.auth_err);

	if (err_status.error.antireplay)
		odp_atomic_inc_u64(&sa->stats.antireplay_err);

	if (err_status.error.alg)
		odp_atomic_inc_u64(&sa->stats.alg_err);

	if (err_status.error.mtu)
		odp_atomic_inc_u64(&sa->stats.mtu_err);

	if (err_status.error.hard_exp_bytes)
		odp_atomic_inc_u64(&sa->stats.hard_exp_bytes_err);

	if (err_status.error.hard_exp_packets)
		odp_atomic_inc_u64(&sa->stats.hard_exp_pkts_err);
}

static int ipsec_in_parse_encap_packet(odp_packet_t pkt, ipsec_state_t *state,
				       odp_ipsec_op_status_t *status, uint32_t *orig_ip_len)
{
	int (*op)(ipsec_state_t *state, odp_packet_t pkt);

	state->ip_offset = odp_packet_l3_offset(pkt);
	_ODP_ASSERT(ODP_PACKET_OFFSET_INVALID != state->ip_offset);
	state->ip = odp_packet_l3_ptr(pkt, NULL);
	_ODP_ASSERT(NULL != state->ip);
	state->is_ipv4 = (((uint8_t *)state->ip)[0] >> 4) == 0x4;
	state->is_ipv6 = (((uint8_t *)state->ip)[0] >> 4) == 0x6;

	if (odp_unlikely(!(state->is_ipv4 || state->is_ipv6)))
		goto err;

	op = state->is_ipv4 ? ipsec_parse_ipv4 : ipsec_parse_ipv6;

	if (odp_unlikely(op(state, pkt) ||
			 state->ip_tot_len + state->ip_offset > odp_packet_len(pkt)))
		goto err;

	*orig_ip_len = state->ip_tot_len;

	return 0;

err:
	status->error.alg = 1;

	return -1;
}

static int ipsec_in_prepare_op(odp_packet_t *pkt, ipsec_state_t *state, ipsec_sa_t **ipsec_sa,
			       odp_ipsec_sa_t sa, odp_crypto_packet_op_param_t *param,
			       odp_ipsec_op_status_t *status)
{
	int (*op)(odp_packet_t *pkt, ipsec_state_t *state, ipsec_sa_t **ipsec_sa,
		  odp_ipsec_sa_t sa, odp_crypto_packet_op_param_t *param,
		  odp_ipsec_op_status_t *status);

	memset(param, 0, sizeof(*param));

	if (odp_unlikely(!(_ODP_IPPROTO_ESP == state->ip_next_hdr ||
			   _ODP_IPPROTO_UDP == state->ip_next_hdr ||
			   _ODP_IPPROTO_AH == state->ip_next_hdr))) {
		status->error.proto = 1;

		return -1;
	}

	op = _ODP_IPPROTO_ESP == state->ip_next_hdr || _ODP_IPPROTO_UDP == state->ip_next_hdr ?
	     ipsec_in_esp : ipsec_in_ah;

	return op(pkt, state, ipsec_sa, sa, param, status);
}

static int ipsec_in_prepare_packet(odp_packet_t *pkt, ipsec_state_t *state, ipsec_sa_t **ipsec_sa,
				   odp_ipsec_sa_t sa, odp_crypto_packet_op_param_t *param,
				   odp_ipsec_op_status_t *status, uint32_t *orig_ip_len)
{
	return ipsec_in_parse_encap_packet(*pkt, state, status, orig_ip_len) ||
	       ipsec_in_prepare_op(pkt, state, ipsec_sa, sa, param, status) ||
	       _odp_ipsec_sa_replay_precheck(*ipsec_sa, state->in.seq_no, status) < 0 ||
	       _odp_ipsec_sa_stats_precheck(*ipsec_sa, status) < 0;
}

static int ipsec_in_do_crypto(odp_packet_t *pkt, odp_crypto_packet_op_param_t *param,
			      odp_ipsec_op_status_t *status)
{
	odp_crypto_packet_result_t result;
	int rc;

	if (odp_unlikely(odp_crypto_op(pkt, pkt, param, 1) < 0)) {
		_ODP_DBG("Crypto failed\n");
		goto alg_err;
	}

	rc = odp_crypto_result(&result, *pkt);

	if (odp_likely(rc == 0))
		return 0;

	if (odp_unlikely(rc < -1)) {
		_ODP_DBG("Crypto failed\n");
		goto alg_err;
	}

	if (result.cipher_status.alg_err == ODP_CRYPTO_ALG_ERR_ICV_CHECK ||
	    result.auth_status.alg_err == ODP_CRYPTO_ALG_ERR_ICV_CHECK)
		goto auth_err;

alg_err:
	status->error.alg = 1;

	return -1;

auth_err:
	status->error.auth = 1;

	return -1;
}

static int ipsec_in_finalize_op(odp_packet_t *pkt, ipsec_state_t *state, ipsec_sa_t *ipsec_sa,
				odp_ipsec_op_status_t *status)
{
	int (*op)(odp_packet_t pkt, ipsec_state_t *state);

	state->ip = odp_packet_l3_ptr(*pkt, NULL);

	if (odp_unlikely(!(ODP_IPSEC_ESP == ipsec_sa->proto || ODP_IPSEC_AH == ipsec_sa->proto)))
		goto proto_err;

	op = ODP_IPSEC_ESP == ipsec_sa->proto ? ipsec_in_esp_post : ipsec_in_ah_post;

	if (odp_unlikely(op(*pkt, state)))
		goto proto_err;

	if (odp_unlikely(odp_packet_trunc_tail(pkt,
					       state->in.trl_len + ipsec_get_seqh_len(ipsec_sa),
					       NULL, NULL) < 0))
		goto alg_err;

	state->ip_tot_len -= state->in.trl_len;

	return 0;

proto_err:
	status->error.proto = 1;

	return -1;

alg_err:
	status->error.alg = 1;

	return -1;
}

static int ipsec_in_strip_tunnel(odp_packet_t *pkt, ipsec_state_t *state,
				 odp_ipsec_op_status_t *status)
{
	odp_packet_move_data(*pkt, state->ip_hdr_len + state->in.hdr_len, 0, state->ip_offset);

	if (odp_unlikely(odp_packet_trunc_head(pkt, state->ip_hdr_len + state->in.hdr_len, NULL,
					       NULL) < 0)) {
		status->error.alg = 1;

		return -1;
	}

	state->ip_tot_len -= state->ip_hdr_len + state->in.hdr_len;

	if (odp_unlikely(!(_ODP_IPPROTO_IPIP == state->ip_next_hdr ||
			   _ODP_IPPROTO_IPV6 == state->ip_next_hdr ||
			   _ODP_IPPROTO_NO_NEXT == state->ip_next_hdr))) {
		status->error.proto = 1;

		return -1;
	}

	state->is_ipv4 = _ODP_IPPROTO_IPIP == state->ip_next_hdr;
	state->is_ipv6 = _ODP_IPPROTO_IPV6 == state->ip_next_hdr;

	return 0;
}

static int ipsec_in_strip_tp(odp_packet_t *pkt, ipsec_state_t *state,
			     odp_ipsec_op_status_t *status)
{
	odp_packet_move_data(*pkt, state->in.hdr_len, 0, state->ip_offset + state->ip_hdr_len);

	if (odp_unlikely(odp_packet_trunc_head(pkt, state->in.hdr_len, NULL, NULL) < 0)) {
		status->error.alg = 1;

		return -1;
	}

	state->ip_tot_len -= state->in.hdr_len;

	return 0;
}

static int ipsec_in_strip_headers(odp_packet_t *pkt, ipsec_state_t *state, ipsec_sa_t *ipsec_sa,
				  odp_ipsec_op_status_t *status)
{
	int (*op)(odp_packet_t *pkt, ipsec_state_t *state, odp_ipsec_op_status_t *status);

	op = ODP_IPSEC_MODE_TUNNEL == ipsec_sa->mode ? ipsec_in_strip_tunnel : ipsec_in_strip_tp;

	return op(pkt, state, status);
}

static int ipsec_in_finalize_decap_header(odp_packet_t pkt, ipsec_state_t *state,
					  ipsec_sa_t *ipsec_sa, odp_ipsec_op_status_t *status)
{
	_odp_ipv4hdr_t *ipv4hdr;
	_odp_ipv6hdr_t *ipv6hdr;

	if (state->is_ipv4 && odp_packet_len(pkt) > _ODP_IPV4HDR_LEN) {
		ipv4hdr = odp_packet_l3_ptr(pkt, NULL);

		if (ODP_IPSEC_MODE_TRANSPORT == ipsec_sa->mode)
			ipv4hdr->tot_len = odp_cpu_to_be_16(state->ip_tot_len);
		else
			ipv4hdr->ttl -= ipsec_sa->dec_ttl;

		_odp_packet_ipv4_chksum_insert(pkt);
	} else if (state->is_ipv6 && odp_packet_len(pkt) > _ODP_IPV6HDR_LEN) {
		ipv6hdr = odp_packet_l3_ptr(pkt, NULL);

		if (ODP_IPSEC_MODE_TRANSPORT == ipsec_sa->mode)
			ipv6hdr->payload_len = odp_cpu_to_be_16(state->ip_tot_len -
								_ODP_IPV6HDR_LEN);
		else
			ipv6hdr->hop_limit -= ipsec_sa->dec_ttl;
	} else if (state->ip_next_hdr != _ODP_IPPROTO_NO_NEXT) {
		status->error.proto = 1;

		return -1;
	}

	return 0;
}

static int ipsec_in_finalize_packet(odp_packet_t *pkt, ipsec_state_t *state, ipsec_sa_t *ipsec_sa,
				    odp_ipsec_op_status_t *status)
{
	return _odp_ipsec_sa_lifetime_update(ipsec_sa, state->stats_length, status) < 0 ||
	       ipsec_in_finalize_op(pkt, state, ipsec_sa, status) ||
	       ipsec_in_strip_headers(pkt, state, ipsec_sa, status) ||
	       ipsec_in_finalize_decap_header(*pkt, state, ipsec_sa, status);
}

static void ipsec_in_reset_parse_data(odp_packet_t pkt, ipsec_state_t *state)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	packet_parse_reset(pkt_hdr, 0);
	pkt_hdr->p.l3_offset = state->ip_offset;
}

static void ipsec_in_parse_packet(odp_packet_t pkt, ipsec_state_t *state)
{
	odp_packet_parse_param_t parse_param;

	parse_param.proto = state->is_ipv4 ? ODP_PROTO_IPV4 :
		state->is_ipv6 ? ODP_PROTO_IPV6 :
		ODP_PROTO_NONE;
	parse_param.last_layer = ipsec_config->inbound.parse_level;
	parse_param.chksums = ipsec_config->inbound.chksums;
	/* We do not care about return code here. Parsing error should not result in IPsec
	 * error. */
	odp_packet_parse(pkt, state->ip_offset, &parse_param);
}

static void ipsec_in_parse_decap_packet(odp_packet_t pkt, ipsec_state_t *state,
					ipsec_sa_t *ipsec_sa)
{
	void (*op)(odp_packet_t pkt, ipsec_state_t *state);

	op = _ODP_IPPROTO_NO_NEXT == state->ip_next_hdr &&
	     ODP_IPSEC_MODE_TUNNEL == ipsec_sa->mode ? ipsec_in_reset_parse_data :
						       ipsec_in_parse_packet;

	op(pkt, state);
}

static ipsec_sa_t *ipsec_in_single(odp_packet_t pkt,
				   odp_ipsec_sa_t sa,
				   odp_packet_t *pkt_out,
				   odp_bool_t enqueue_op,
				   odp_ipsec_op_status_t *status,
				   uint32_t *orig_ip_len)
{
	ipsec_state_t state;
	ipsec_sa_t *ipsec_sa = NULL;
	odp_crypto_packet_op_param_t param;

	if (odp_unlikely(ipsec_in_prepare_packet(&pkt, &state, &ipsec_sa, sa, &param, status,
						 orig_ip_len)))
		goto exit;

	if (ipsec_in_do_crypto(&pkt, &param, status))
		goto exit;

	if (ipsec_sa->antireplay) {
		if (enqueue_op)
			wait_for_order(ipsec_global->inbound_ordering_mode);

		if (_odp_ipsec_sa_replay_update(ipsec_sa, state.in.seq_no, status) < 0)
			goto exit;
	}

	if (odp_unlikely(ipsec_in_finalize_packet(&pkt, &state, ipsec_sa, status)))
		goto post_lifetime_err_cnt_update;

	ipsec_in_parse_decap_packet(pkt, &state, ipsec_sa);

	goto exit;

post_lifetime_err_cnt_update:
	if (ipsec_config->stats_en) {
		odp_atomic_inc_u64(&ipsec_sa->stats.post_lifetime_err_pkts);
		odp_atomic_add_u64(&ipsec_sa->stats.post_lifetime_err_bytes, state.stats_length);
	}

exit:
	*pkt_out = pkt;

	if (ipsec_config->stats_en)
		ipsec_sa_err_stats_update(ipsec_sa, status);

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

/*
 * Round len up to next multiple of pad_mask + 1.
 * pad_mask + 1 must be a power of 2.
 */
static inline uint32_t ipsec_padded_len(uint32_t len, uint32_t pad_mask)
{
	_ODP_ASSERT(_ODP_CHECK_IS_POWER2(pad_mask + 1));

	return (len + pad_mask) & ~pad_mask;
}

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
	uint32_t ver_tc_flow = odp_be_to_cpu_32(ipv6hdr->ver_tc_flow);

	ipv6hdr->hop_limit -= ipsec_sa->dec_ttl;
	state->out_tunnel.ip_tos = (ver_tc_flow &
				    _ODP_IPV6HDR_TC_MASK) >>
		_ODP_IPV6HDR_TC_SHIFT;
	state->out_tunnel.ip_df = 0;
	state->out_tunnel.ip_flabel = (ver_tc_flow &
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
					  ODP_RANDOM_CRYPTO);
		if (odp_unlikely(rnd_len != IPSEC_RANDOM_BUF_SIZE))
			return -1;
		memcpy(data, &buffer[0], len);
		buffer_used = len;
	} else {
		return -1;
	}
	return 0;
}

/*
 * Generate cipher IV for outbound processing.
 */
static int ipsec_out_iv(ipsec_state_t *state,
			ipsec_sa_t *ipsec_sa,
			uint64_t seq_no)
{
	if (ipsec_sa->use_counter_iv) {
		/* Both GCM and CTR use 8-bit counters */
		_ODP_ASSERT(sizeof(seq_no) == ipsec_sa->esp_iv_len);

		/* It is faster to just copy MAX_SALT_LEN bytes than the exact length */
		ODP_STATIC_ASSERT(IPSEC_MAX_SALT_LEN <= IPSEC_MAX_IV_LEN,
				  "IPSEC_MAX_SALT_LEN too large");
		memcpy(state->iv, ipsec_sa->salt, IPSEC_MAX_SALT_LEN);

		_ODP_ASSERT(ipsec_sa->salt_length + sizeof(seq_no) <= IPSEC_MAX_IV_LEN);
		memcpy(state->iv + ipsec_sa->salt_length, &seq_no, sizeof(seq_no));

		if (ipsec_sa->aes_ctr_iv) {
			ODP_STATIC_ASSERT(IPSEC_MAX_IV_LEN >= 16, "IPSEC_MAX_IV_LEN too small");
			state->iv[12] = 0;
			state->iv[13] = 0;
			state->iv[14] = 0;
			state->iv[15] = 1;
		}
	} else if (ipsec_sa->use_cbc_iv) {
		/*
		 * For CBC mode ciphers with 16 byte IV we generate the cipher
		 * IV by concatenating a per-session random salt value and
		 * 64-bit sequence number. The ESP IV will be generated at
		 * ciphering time by CBC-encrypting a zero block using the
		 * cipher IV.
		 *
		 * This way each packet of an SA will have an unpredictable
		 * IV and different SAs (e.g. manually keyed SAs across
		 * restarts) will have different IV sequences (so one cannot
		 * predict IVs of an SA by observing the IVs of another SA
		 * with the same key).
		 */
		_ODP_ASSERT(CBC_SALT_LEN + sizeof(seq_no) == ipsec_sa->esp_iv_len);
		ODP_STATIC_ASSERT(CBC_SALT_LEN + sizeof(seq_no) <= IPSEC_MAX_IV_LEN,
				  "IPSEC_MAX_IV_LEN too small for CBC IV construction");
		memcpy(state->iv, ipsec_sa->cbc_salt, CBC_SALT_LEN);
		memcpy(state->iv + CBC_SALT_LEN, &seq_no, sizeof(seq_no));
	} else if (odp_unlikely(ipsec_sa->esp_iv_len)) {
		_ODP_ASSERT(ipsec_sa->esp_iv_len <= IPSEC_MAX_IV_LEN);
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
			 odp_bool_t enqueue_op,
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

	encrypt_len = ipsec_padded_len(ip_data_len + tfc_len + _ODP_ESPTRL_LEN,
				       ipsec_sa->esp_pad_mask);

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

	if (enqueue_op)
		wait_for_order(ipsec_global->outbound_ordering_mode);
	seq_no = ipsec_seq_no(ipsec_sa);

	if (ipsec_out_iv(state, ipsec_sa, seq_no) < 0) {
		status->error.alg = 1;
		return -1;
	}

	param->cipher_iv_ptr = state->iv;
	param->auth_iv_ptr = state->iv;

	memset(&esp, 0, sizeof(esp));
	esp.spi = odp_cpu_to_be_32(ipsec_sa->spi);
	state->esp.aad.spi = esp.spi;
	esp.seq_no = odp_cpu_to_be_32(seq_no & 0xffffffff);

	if (ipsec_sa->esn)
		state->esp.aad.seq_no64 = odp_cpu_to_be_64(seq_no);
	else
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
	if (!ipsec_sa->use_cbc_iv) {
		/* copy the relevant part of cipher IV to ESP IV */
		odp_packet_copy_from_mem(*pkt,
					 ipsec_offset + _ODP_ESPHDR_LEN,
					 ipsec_sa->esp_iv_len,
					 state->iv + ipsec_sa->salt_length);
	}
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

	/* Outbound ICV computation includes ESN higher 32 bits as part of ESP
	 * implicit trailer for individual algo's.
	 */
	if (ipsec_sa->insert_seq_hi) {
		uint32_t outb_seqh = odp_cpu_to_be_32(seq_no >> 32);

		if (odp_packet_extend_tail(pkt, IPSEC_SEQ_HI_LEN, NULL, NULL) < 0) {
			status->error.alg = 1;
			_ODP_ERR("odp_packet_extend_tail failed\n");
			return -1;
		}
		odp_packet_copy_from_mem(*pkt,
					 esptrl_offset + _ODP_ESPTRL_LEN,
					 IPSEC_SEQ_HI_LEN, &outb_seqh);
	}

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
				  state->ip_hdr_len +
				  ipsec_get_seqh_len(ipsec_sa) -
				  ipsec_sa->icv_len;
	param->hash_result_offset = state->ip_offset +
				   state->ip_tot_len +
				   ipsec_get_seqh_len(ipsec_sa) -
				   ipsec_sa->icv_len;

	state->stats_length = param->cipher_range.length;

	if (ipsec_sa->use_cbc_iv) {
		/*
		 * Encrypt zeroed ESP IV field using the special cipher IV
		 * to create the final unpredictable ESP IV
		 */
		_ODP_ASSERT(ipsec_sa->esp_iv_len == CBC_IV_LEN);
		param->cipher_range.offset -= CBC_IV_LEN;
		param->cipher_range.length += CBC_IV_LEN;
		_odp_packet_set_data(*pkt,
				     ipsec_offset + _ODP_ESPHDR_LEN,
				     0,
				     CBC_IV_LEN);
	}

	param->session = ipsec_sa->session;

	return 0;
}

static int ipsec_out_esp_post(ipsec_state_t *state, odp_packet_t *pkt,
			      ipsec_sa_t *ipsec_sa)
{
	if (state->is_ipv4)
		_odp_packet_ipv4_chksum_insert(*pkt);

	/* Remove the high order ESN bits that were added in the packet for ICV
	 * computation.
	 */
	if (ipsec_sa->insert_seq_hi) {
		uint32_t icv_offset =  odp_packet_len(*pkt) - ipsec_sa->icv_len;

		odp_packet_move_data(*pkt, icv_offset - IPSEC_SEQ_HI_LEN, icv_offset,
				     ipsec_sa->icv_len);
		if (odp_packet_trunc_tail(pkt, IPSEC_SEQ_HI_LEN, NULL, NULL) < 0) {
			_ODP_ERR("odp_packet_trunc_tail failed\n");
			return -1;
		}
	}

	return 0;
}

static int ipsec_out_ah(odp_packet_t *pkt,
			ipsec_state_t *state,
			ipsec_sa_t *ipsec_sa,
			odp_crypto_packet_op_param_t *param,
			odp_ipsec_op_status_t *status,
			uint32_t mtu,
			odp_bool_t enqueue_op)
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

	if (enqueue_op)
		wait_for_order(ipsec_global->outbound_ordering_mode);
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

	/* ESN higher 32 bits are included at the end of the packet data
	 * for outbound ICV computation.
	 */
	if (ipsec_sa->insert_seq_hi) {
		uint32_t outb_seqh = odp_cpu_to_be_32(seq_no >> 32);
		uint32_t seqh_offset = odp_packet_len(*pkt);

		if (odp_packet_extend_tail(pkt, IPSEC_SEQ_HI_LEN, NULL, NULL) < 0) {
			status->error.alg = 1;
			_ODP_ERR("odp_packet_extend_tail failed\n");
			return -1;
		}
		odp_packet_copy_from_mem(*pkt,
					 seqh_offset, IPSEC_SEQ_HI_LEN, &outb_seqh);
	}

	param->auth_range.offset = state->ip_offset;
	param->auth_range.length = state->ip_tot_len;
	param->hash_result_offset = ipsec_offset + _ODP_AHHDR_LEN +
				ipsec_sa->esp_iv_len;

	state->stats_length = param->auth_range.length;
	param->auth_range.length += ipsec_get_seqh_len(ipsec_sa);
	param->session = ipsec_sa->session;

	return 0;
}

static int ipsec_out_ah_post(ipsec_state_t *state, odp_packet_t *pkt,
			     ipsec_sa_t *ipsec_sa)
{
	if (state->is_ipv4) {
		_odp_ipv4hdr_t *ipv4hdr = odp_packet_l3_ptr(*pkt, NULL);

		ipv4hdr->ttl = state->ah_ipv4.ttl;
		ipv4hdr->tos = state->ah_ipv4.tos;
		ipv4hdr->frag_offset = state->ah_ipv4.frag_offset;

		_odp_packet_ipv4_chksum_insert(*pkt);
	} else {
		_odp_ipv6hdr_t *ipv6hdr = odp_packet_l3_ptr(*pkt, NULL);

		ipv6hdr->ver_tc_flow = state->ah_ipv6.ver_tc_flow;
		ipv6hdr->hop_limit = state->ah_ipv6.hop_limit;
	}

	/* Remove the high order ESN bits that were added in the packet for ICV
	 * computation.
	 */
	if (ipsec_sa->insert_seq_hi) {
		if (odp_packet_trunc_tail(pkt, IPSEC_SEQ_HI_LEN, NULL, NULL) < 0) {
			_ODP_ERR("odp_packet_trunc_tail failed\n");
			return -1;
		}
	}

	return 0;
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

static int ipsec_out_tp_encap(odp_packet_t pkt, ipsec_state_t *state)
{
	int (*op)(ipsec_state_t *state, odp_packet_t pkt);

	if (odp_unlikely(!(state->is_ipv4 || state->is_ipv6)))
		return -1;

	op = state->is_ipv4 ? ipsec_parse_ipv4 : ipsec_parse_ipv6;

	if (odp_unlikely(op(state, pkt) ||
			 state->ip_tot_len + state->ip_offset != odp_packet_len(pkt)))
		return -1;

	ipsec_out_checksums(pkt, state);

	return 0;
}

static int ipsec_out_tunnel_encap(odp_packet_t *pkt, ipsec_state_t *state, ipsec_sa_t *ipsec_sa,
				  const odp_ipsec_out_opt_t *opt)
{
	int ret;

	if (odp_unlikely(!(state->is_ipv4 || state->is_ipv6 || opt->flag.tfc_dummy)))
		return -1;

	if (state->is_ipv4) {
		if (odp_unlikely(ipsec_out_tunnel_parse_ipv4(state, ipsec_sa)))
			return -1;
	} else if (state->is_ipv6) {
		if (odp_unlikely(ipsec_out_tunnel_parse_ipv6(state, ipsec_sa)))
			return -1;
	} else {
		state->out_tunnel.ip_tos = 0;
		state->out_tunnel.ip_df = 0;
		state->out_tunnel.ip_flabel = 0;
		state->ip_next_hdr = _ODP_IPPROTO_NO_NEXT;
	}

	ipsec_out_checksums(*pkt, state);

	if (ipsec_sa->tun_ipv4)
		ret = ipsec_out_tunnel_ipv4(pkt, state, ipsec_sa,
					    opt->flag.ip_param ? &opt->ipv4 :
								 &ipsec_sa->out.tun_ipv4.param);
	else
		ret = ipsec_out_tunnel_ipv6(pkt, state, ipsec_sa,
					    opt->flag.ip_param ? &opt->ipv6 :
								 &ipsec_sa->out.tun_ipv6.param);

	return ret;
}

static int ipsec_out_parse_encap_packet(odp_packet_t *pkt, ipsec_state_t *state,
					ipsec_sa_t *ipsec_sa, const odp_ipsec_out_opt_t *opt,
					odp_ipsec_op_status_t *status)
{
	odp_packet_hdr_t *pkt_hdr;
	int ret;

	if (opt->flag.tfc_dummy) {
		pkt_hdr = packet_hdr(*pkt);
		_ODP_ASSERT(ODP_IPSEC_MODE_TUNNEL == ipsec_sa->mode);
		pkt_hdr->p.l2_offset = ODP_PACKET_OFFSET_INVALID;
		pkt_hdr->p.l3_offset = 0;
		state->ip_offset = 0;
		state->ip = NULL;
		state->is_ipv4 = 0;
		state->is_ipv6 = 0;
	} else {
		state->ip_offset = odp_packet_l3_offset(*pkt);
		_ODP_ASSERT(ODP_PACKET_OFFSET_INVALID != state->ip_offset);
		state->ip = odp_packet_l3_ptr(*pkt, NULL);
		_ODP_ASSERT(NULL != state->ip);
		state->is_ipv4 = (((uint8_t *)state->ip)[0] >> 4) == 0x4;
		state->is_ipv6 = (((uint8_t *)state->ip)[0] >> 4) == 0x6;
	}

	if (ODP_IPSEC_MODE_TRANSPORT == ipsec_sa->mode)
		ret = ipsec_out_tp_encap(*pkt, state);
	else
		ret = ipsec_out_tunnel_encap(pkt, state, ipsec_sa, opt);

	if (odp_unlikely(ret))
		status->error.alg = 1;

	return ret;
}

static int ipsec_out_prepare_op(odp_packet_t *pkt, ipsec_state_t *state, ipsec_sa_t *ipsec_sa,
				const odp_ipsec_out_opt_t *opt, odp_bool_t is_enqueue_op,
				odp_crypto_packet_op_param_t *param, odp_ipsec_op_status_t *status)
{
	odp_ipsec_frag_mode_t frag_mode;
	uint32_t mtu;
	int ret;

	memset(param, 0, sizeof(*param));

	frag_mode = opt->flag.frag_mode ? opt->frag_mode : ipsec_sa->out.frag_mode;
	mtu = frag_mode == ODP_IPSEC_FRAG_CHECK ? odp_atomic_load_u32(&ipsec_sa->out.mtu) :
						  UINT32_MAX;

	if (odp_unlikely(!(ODP_IPSEC_ESP == ipsec_sa->proto || ODP_IPSEC_AH == ipsec_sa->proto))) {
		status->error.alg = 1;

		return -1;
	}

	if (ODP_IPSEC_ESP == ipsec_sa->proto)
		ret = ipsec_out_esp(pkt, state, ipsec_sa, param, status, mtu, is_enqueue_op, opt);
	else
		ret = ipsec_out_ah(pkt, state, ipsec_sa, param, status, mtu, is_enqueue_op);

	return ret;
}

static int ipsec_out_prepare_packet(odp_packet_t *pkt, ipsec_state_t *state, ipsec_sa_t *ipsec_sa,
				    const odp_ipsec_out_opt_t *opt, odp_bool_t is_enqueue_op,
				    odp_crypto_packet_op_param_t *param,
				    odp_ipsec_op_status_t *status)
{
	return ipsec_out_parse_encap_packet(pkt, state, ipsec_sa, opt, status) ||
	       ipsec_out_prepare_op(pkt, state, ipsec_sa, opt, is_enqueue_op, param, status);
}

static int ipsec_out_finalize_packet(odp_packet_t *pkt, ipsec_state_t *state, ipsec_sa_t *ipsec_sa,
				     odp_ipsec_op_status_t *status)
{
	int (*op)(ipsec_state_t *state, odp_packet_t *pkt, ipsec_sa_t *ipsec_sa);

	op = ODP_IPSEC_ESP == ipsec_sa->proto ? ipsec_out_esp_post :
		ODP_IPSEC_AH == ipsec_sa->proto ? ipsec_out_ah_post : NULL;

	if (odp_unlikely(op && op(state, pkt, ipsec_sa))) {
		status->error.alg = 1;

		return -1;
	}

	return 0;
}

static void ipsec_in_prepare(const odp_packet_t pkt_in[], odp_packet_t pkt_out[], int num_in,
			     const odp_ipsec_in_param_t *param, ipsec_op_t ops[],
			     odp_packet_t crypto_pkts[],
			     odp_crypto_packet_op_param_t crypto_param[], ipsec_op_t *crypto_ops[],
			     int *num_crypto)
{
	unsigned int sa_idx = 0, sa_inc = (param->num_sa > 1) ? 1 : 0;

	*num_crypto = 0;

	for (int i = 0; i < num_in; i++) {
		pkt_out[i] = pkt_in[i];
		ipsec_op_t *op = &ops[i];
		odp_packet_t *pkt = &pkt_out[i];
		odp_crypto_packet_op_param_t c_p;

		memset(op, 0, sizeof(*op));

		if (0 == param->num_sa) {
			op->sa_hdl = ODP_IPSEC_SA_INVALID;
		} else {
			op->sa_hdl = param->sa[sa_idx];
			_ODP_ASSERT(ODP_IPSEC_SA_INVALID != op->sa_hdl);
		}

		sa_idx += sa_inc;

		if (odp_likely(ipsec_in_prepare_packet(pkt, &op->state, &op->sa, op->sa_hdl, &c_p,
						       &op->status, &op->orig_ip_len) == 0)) {
			crypto_pkts[*num_crypto] = *pkt;
			crypto_param[*num_crypto] = c_p;
			crypto_ops[*num_crypto] = op;
			(*num_crypto)++;
		}
	}
}

static void ipsec_do_crypto_burst(odp_packet_t pkts[], odp_crypto_packet_op_param_t param[],
				  ipsec_op_t *ops[], int num)
{
	int num_procd = 0;

	while (num_procd < num) {
		int ret = odp_crypto_op(&pkts[num_procd], &pkts[num_procd], &param[num_procd],
					num - num_procd);

		if (odp_unlikely(ret <= 0))
			break;

		num_procd += ret;
	}

	for (int i = num_procd; i < num; i++)
		ops[i]->status.error.alg = 1;
}

static int ipsec_in_check_crypto_result(odp_packet_t pkt, odp_ipsec_op_status_t *status)
{
	odp_crypto_packet_result_t result;
	int rc = odp_crypto_result(&result, pkt);

	if (odp_likely(rc == 0))
		return 0;

	if (odp_unlikely(rc < -1)) {
		_ODP_DBG("Crypto failed\n");
		status->error.alg = 1;
		return -1;
	}

	if (result.cipher_status.alg_err == ODP_CRYPTO_ALG_ERR_ICV_CHECK ||
	    result.auth_status.alg_err == ODP_CRYPTO_ALG_ERR_ICV_CHECK)
		status->error.auth = 1;
	else
		status->error.alg = 1;

	return -1;
}

static inline void update_post_lifetime_stats(ipsec_sa_t *sa, ipsec_state_t *state)
{
	if (ipsec_config->stats_en) {
		odp_atomic_inc_u64(&sa->stats.post_lifetime_err_pkts);
		odp_atomic_add_u64(&sa->stats.post_lifetime_err_bytes, state->stats_length);
	}
}

static inline void finish_packet_proc(odp_packet_t pkt, ipsec_op_t *op, odp_queue_t queue)
{
	odp_ipsec_packet_result_t *res;

	if (ipsec_config->stats_en)
		ipsec_sa_err_stats_update(op->sa, &op->status);

	packet_subtype_set(pkt, ODP_EVENT_PACKET_IPSEC);
	res = ipsec_pkt_result(pkt);
	memset(res, 0, sizeof(*res));
	res->status = op->status;
	res->sa = NULL != op->sa ? op->sa->ipsec_sa_hdl : ODP_IPSEC_SA_INVALID;
	/* We need to decrease SA use count only if the SA was not provided to us by the caller but
	 * was found through our own SA lookup that increased the use count. */
	if (op->sa_hdl == ODP_IPSEC_SA_INVALID && op->sa)
		_odp_ipsec_sa_unuse(op->sa);

	if (queue != ODP_QUEUE_INVALID) {
		res->orig_ip_len = op->orig_ip_len;
		/* What should be done if enqueue fails? */
		if (odp_unlikely(odp_queue_enq(queue, odp_ipsec_packet_to_event(pkt)) < 0))
			odp_packet_free(pkt);
	}
}

static void ipsec_in_finalize(odp_packet_t pkt_in[], ipsec_op_t ops[], int num, odp_bool_t is_enq)
{
	for (int i = 0; i < num; i++) {
		ipsec_op_t *op = &ops[i];
		odp_packet_t *pkt = &pkt_in[i];
		odp_queue_t q = ODP_QUEUE_INVALID;

		if (odp_unlikely(op->status.error.all))
			goto finish;

		if (odp_unlikely(ipsec_in_check_crypto_result(*pkt, &op->status)))
			goto finish;

		if (op->sa->antireplay) {
			if (is_enq)
				wait_for_order(ipsec_global->inbound_ordering_mode);

			if (odp_unlikely(_odp_ipsec_sa_replay_update(op->sa, op->state.in.seq_no,
								     &op->status) < 0))
				goto finish;
		}

		if (odp_unlikely(ipsec_in_finalize_packet(pkt, &op->state, op->sa,
							  &op->status))) {
			update_post_lifetime_stats(op->sa, &op->state);
			goto finish;
		}

		ipsec_in_parse_decap_packet(*pkt, &op->state, op->sa);

finish:
		if (is_enq)
			q = NULL != op->sa ? op->sa->queue : ipsec_config->inbound.default_queue;

		finish_packet_proc(*pkt, op, q);
	}
}

int odp_ipsec_in(const odp_packet_t pkt_in[], int num_in, odp_packet_t pkt_out[], int *num_out,
		 const odp_ipsec_in_param_t *param)
{
	int max_out = _ODP_MIN3(num_in, *num_out, MAX_BURST), num_crypto;
	odp_packet_t crypto_pkts[MAX_BURST];
	odp_crypto_packet_op_param_t crypto_param[MAX_BURST];
	ipsec_op_t ops[MAX_BURST], *crypto_ops[MAX_BURST];

	ipsec_in_prepare(pkt_in, pkt_out, max_out, param, ops, crypto_pkts, crypto_param,
			 crypto_ops, &num_crypto);
	ipsec_do_crypto_burst(crypto_pkts, crypto_param, crypto_ops, num_crypto);
	ipsec_in_finalize(pkt_out, ops, max_out, false);
	*num_out = max_out;

	return max_out;
}

static odp_ipsec_out_opt_t default_out_opt;

static void ipsec_out_prepare(const odp_packet_t pkt_in[], odp_packet_t pkt_out[], int num_in,
			      const odp_ipsec_out_param_t *param, ipsec_op_t ops[],
			      odp_packet_t crypto_pkts[],
			      odp_crypto_packet_op_param_t crypto_param[],
			      ipsec_op_t *crypto_ops[], int *num_crypto, odp_bool_t is_enq)
{
	unsigned int sa_idx = 0, opt_idx = 0, sa_inc = (param->num_sa > 1) ? 1 : 0,
	opt_inc = (param->num_opt > 1) ? 1 : 0;
	/* No need to do _odp_ipsec_sa_use() here since an ODP application is not allowed to do
	 * call IPsec output before SA creation has completed nor call odp_ipsec_sa_disable()
	 * before IPsec output has completed. IOW, the needed synchronization between threads is
	 * done by the application. */
	*num_crypto = 0;

	for (int i = 0; i < num_in; i++) {
		pkt_out[i] = pkt_in[i];
		ipsec_op_t *op = &ops[i];
		const odp_ipsec_out_opt_t *opt;
		odp_packet_t *pkt = &pkt_out[i];
		odp_crypto_packet_op_param_t c_p;

		memset(op, 0, sizeof(*op));
		op->sa_hdl = param->sa[sa_idx];
		_ODP_ASSERT(ODP_IPSEC_SA_INVALID != op->sa_hdl);
		op->sa = _odp_ipsec_sa_entry_from_hdl(op->sa_hdl);
		_ODP_ASSERT(NULL != op->sa);

		if (0 == param->num_opt)
			opt = &default_out_opt;
		else
			opt = &param->opt[opt_idx];

		sa_idx += sa_inc;
		opt_idx += opt_inc;

		if (odp_unlikely(ipsec_out_prepare_packet(pkt, &op->state, op->sa, opt, is_enq,
							  &c_p, &op->status)))
			continue;

		if (odp_unlikely(_odp_ipsec_sa_lifetime_update(op->sa, op->state.stats_length,
							       &op->status))) {
			update_post_lifetime_stats(op->sa, &op->state);
			continue;
		}

		crypto_pkts[*num_crypto] = *pkt;
		crypto_param[*num_crypto] = c_p;
		crypto_ops[*num_crypto] = op;
		(*num_crypto)++;
	}
}

static int ipsec_out_check_crypto_result(odp_packet_t pkt, odp_ipsec_op_status_t *status)
{
	if (odp_unlikely(odp_crypto_result(NULL, pkt) != 0)) {
		_ODP_DBG("Crypto failed\n");
		status->error.alg = 1;
		return -1;
	}

	return 0;
}

static void ipsec_out_finalize(odp_packet_t pkt_in[], ipsec_op_t ops[], int num, odp_bool_t is_enq)
{
	for (int i = 0; i < num; i++) {
		ipsec_op_t *op = &ops[i];
		odp_packet_t *pkt = &pkt_in[i];
		odp_queue_t q = ODP_QUEUE_INVALID;

		if (odp_unlikely(op->status.error.all))
			goto finish;

		if (odp_unlikely(ipsec_out_check_crypto_result(*pkt, &op->status))) {
			update_post_lifetime_stats(op->sa, &op->state);
			goto finish;
		}

		if (odp_unlikely(ipsec_out_finalize_packet(pkt, &op->state, op->sa, &op->status)))
			update_post_lifetime_stats(op->sa, &op->state);

finish:
		if (is_enq)
			q = NULL != op->sa ? op->sa->queue : ipsec_config->inbound.default_queue;

		finish_packet_proc(*pkt, op, q);
	}
}

int odp_ipsec_out(const odp_packet_t pkt_in[], int num_in, odp_packet_t pkt_out[], int *num_out,
		  const odp_ipsec_out_param_t *param)
{
	int max_out = _ODP_MIN3(num_in, *num_out, MAX_BURST), num_crypto;
	odp_packet_t crypto_pkts[MAX_BURST];
	odp_crypto_packet_op_param_t crypto_param[MAX_BURST];
	ipsec_op_t ops[MAX_BURST], *crypto_ops[MAX_BURST];

	ipsec_out_prepare(pkt_in, pkt_out, max_out, param, ops, crypto_pkts, crypto_param,
			  crypto_ops, &num_crypto, false);
	ipsec_do_crypto_burst(crypto_pkts, crypto_param, crypto_ops, num_crypto);
	ipsec_out_finalize(pkt_out, ops, max_out, false);
	*num_out = max_out;

	return max_out;
}

/* Do not change to an asynchronous design without thinking concurrency and what changes are
 * required to guarantee that used SAs are not destroyed when asynchronous operations are in
 * progress.
 *
 * The containing code does not hold a reference to the SA but completes processing synchronously
 * and makes use of the fact that the application may not disable (and then destroy) the SA before
 * these routines return (and all side effects are visible to the disabling thread). */
int odp_ipsec_in_enq(const odp_packet_t pkt_in[], int num_in, const odp_ipsec_in_param_t *param)
{
	int max_out = _ODP_MIN(num_in, MAX_BURST), num_crypto;
	odp_packet_t pkt_out[MAX_BURST], crypto_pkts[MAX_BURST];
	odp_crypto_packet_op_param_t crypto_param[MAX_BURST];
	ipsec_op_t ops[MAX_BURST], *crypto_ops[MAX_BURST];

	ipsec_in_prepare(pkt_in, pkt_out, max_out, param, ops, crypto_pkts, crypto_param,
			 crypto_ops, &num_crypto);
	ipsec_do_crypto_burst(crypto_pkts, crypto_param, crypto_ops, num_crypto);
	ipsec_in_finalize(pkt_out, ops, max_out, true);

	return max_out;
}

int odp_ipsec_out_enq(const odp_packet_t pkt_in[], int num_in, const odp_ipsec_out_param_t *param)
{
	int max_out = _ODP_MIN(num_in, MAX_BURST), num_crypto;
	odp_packet_t pkt_out[MAX_BURST], crypto_pkts[MAX_BURST];
	odp_crypto_packet_op_param_t crypto_param[MAX_BURST];
	ipsec_op_t ops[MAX_BURST], *crypto_ops[MAX_BURST];

	ipsec_out_prepare(pkt_in, pkt_out, max_out, param, ops, crypto_pkts, crypto_param,
			  crypto_ops, &num_crypto, true);
	ipsec_do_crypto_burst(crypto_pkts, crypto_param, crypto_ops, num_crypto);
	ipsec_out_finalize(pkt_out, ops, max_out, true);

	return max_out;
}

int _odp_ipsec_try_inline(odp_packet_t *pkt)
{
	odp_ipsec_op_status_t status;
	ipsec_sa_t *ipsec_sa;
	uint32_t orig_ip_len = 0;
	odp_ipsec_packet_result_t *result;
	odp_packet_hdr_t *pkt_hdr;

	if (odp_global_ro.disable.ipsec)
		return -1;

	memset(&status, 0, sizeof(status));

	ipsec_sa = ipsec_in_single(*pkt, ODP_IPSEC_SA_INVALID, pkt, false,
				   &status, &orig_ip_len);
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
	result->orig_ip_len = orig_ip_len;
	result->sa = ipsec_sa->ipsec_sa_hdl;
	result->flag.inline_mode = 1;

	pkt_hdr = packet_hdr(*pkt);
	pkt_hdr->p.input_flags.dst_queue = 1;
	pkt_hdr->dst_queue = ipsec_sa->queue;
	/* Distinguish inline IPsec packets from classifier packets */
	pkt_hdr->cos = CLS_COS_IDX_NONE;

	/* Last thing */
	_odp_ipsec_sa_unuse(ipsec_sa);

	return 0;
}

static inline int ipsec_out_inline_check_out_hdrs(odp_packet_t pkt,
						  const odp_ipsec_out_inline_param_t *param,
						  ipsec_inline_op_t *op)
{
	uint32_t l2_offset, hdr_len = param->outer_hdr.len;

	if (!param->outer_hdr.ptr) {
		l2_offset = odp_packet_l2_offset(pkt);
		_ODP_ASSERT(hdr_len == odp_packet_l3_offset(pkt) - l2_offset);

		if (odp_unlikely(hdr_len > MAX_HDR_LEN ||
				 odp_packet_copy_to_mem(pkt, l2_offset, hdr_len, op->hdr_buf)
				 < 0)) {
			op->op.status.error.proto = 1;

			return -1;
		}
	}

	return 0;
}

static void ipsec_out_inline_prepare(const odp_packet_t pkt_in[], odp_packet_t pkt_out[],
				     int num_in, const odp_ipsec_out_param_t *param,
				     const odp_ipsec_out_inline_param_t *inline_param,
				     ipsec_inline_op_t ops[], odp_packet_t crypto_pkts[],
				     odp_crypto_packet_op_param_t crypto_param[],
				     ipsec_op_t *crypto_ops[], int *num_crypto)
{
	unsigned int sa_idx = 0, opt_idx = 0, sa_inc = (param->num_sa > 1) ? 1 : 0,
	opt_inc = (param->num_opt > 1) ? 1 : 0;

	*num_crypto = 0;

	for (int i = 0; i < num_in; i++) {
		pkt_out[i] = pkt_in[i];
		ipsec_inline_op_t *op = &ops[i];
		const odp_ipsec_out_opt_t *opt;
		odp_packet_t *pkt = &pkt_out[i];
		odp_crypto_packet_op_param_t c_p;

		memset(op, 0, sizeof(*op));
		op->op.sa_hdl = param->sa[sa_idx];
		_ODP_ASSERT(ODP_IPSEC_SA_INVALID != op->op.sa_hdl);
		op->op.sa = _odp_ipsec_sa_entry_from_hdl(op->op.sa_hdl);
		_ODP_ASSERT(NULL != op->op.sa);

		if (0 == param->num_opt)
			opt = &default_out_opt;
		else
			opt = &param->opt[opt_idx];

		sa_idx += sa_inc;
		opt_idx += opt_inc;

		if (odp_unlikely(ipsec_out_inline_check_out_hdrs(*pkt, &inline_param[i], op) ||
				 ipsec_out_prepare_packet(pkt, &op->op.state, op->op.sa, opt,
							  true, &c_p, &op->op.status)))
			continue;

		if (odp_unlikely(_odp_ipsec_sa_lifetime_update(op->op.sa,
							       op->op.state.stats_length,
							       &op->op.status))) {
			update_post_lifetime_stats(op->op.sa, &op->op.state);
			continue;
		}

		crypto_pkts[*num_crypto] = *pkt;
		crypto_param[*num_crypto] = c_p;
		crypto_ops[*num_crypto] = &op->op;
		(*num_crypto)++;
	}
}

static void ipsec_out_inline_finish_packet_proc(odp_packet_t *pkt,
						const odp_ipsec_out_inline_param_t *param,
						ipsec_inline_op_t *op)
{
	uint32_t offset = odp_packet_l3_offset(*pkt), hdr_len = param->outer_hdr.len;
	odp_pktout_queue_t pkqueue;

	_ODP_ASSERT(NULL != op->op.sa);

	if (odp_unlikely(offset == ODP_PACKET_OFFSET_INVALID))
		offset = 0;

	if (offset >= hdr_len) {
		if (odp_packet_trunc_head(pkt, offset - hdr_len, NULL, NULL) < 0)
			op->op.status.error.alg = 1;
	} else {
		if (odp_packet_extend_head(pkt, hdr_len - offset, NULL, NULL) < 0)
			op->op.status.error.alg = 1;
	}

	odp_packet_l3_offset_set(*pkt, hdr_len);

	if (odp_packet_copy_from_mem(*pkt, 0, hdr_len,
				     param->outer_hdr.ptr ? param->outer_hdr.ptr : op->hdr_buf)
	    < 0)
		op->op.status.error.alg = 1;

	if (!op->op.status.error.all) {
		if (odp_pktout_queue(param->pktio, &pkqueue, 1) <= 0)
			op->op.status.error.alg = 1;

		if (odp_pktout_send(pkqueue, pkt, 1) < 0)
			op->op.status.error.alg = 1;
	}
}

static void ipsec_out_inline_handle_err(odp_packet_t pkt, ipsec_inline_op_t *op)
{
	odp_ipsec_packet_result_t *res;

	if (odp_likely(!op->op.status.error.all))
		return;

	if (ipsec_config->stats_en)
		ipsec_sa_err_stats_update(op->op.sa, &op->op.status);

	packet_subtype_set(pkt, ODP_EVENT_PACKET_IPSEC);
	res = ipsec_pkt_result(pkt);
	memset(res, 0, sizeof(*res));
	res->sa = op->op.sa_hdl;
	res->status = op->op.status;

	if (odp_unlikely(odp_queue_enq(op->op.sa->queue, odp_ipsec_packet_to_event(pkt)) < 0))
		odp_packet_free(pkt);
}

static void ipsec_out_inline_finalize(odp_packet_t pkt_in[],
				      const odp_ipsec_out_inline_param_t *inline_param,
				      ipsec_inline_op_t ops[], int num)
{
	for (int i = 0; i < num; i++) {
		ipsec_inline_op_t *op = &ops[i];
		odp_packet_t *pkt = &pkt_in[i];

		if (op->op.status.warn.soft_exp_packets || op->op.status.warn.soft_exp_bytes) {
			if (!odp_atomic_load_u32(&op->op.sa->soft_expiry_notified)) {
				int rc;

				/*
				 * Another thread may have sent the notification by now but we do
				 * not care since sending duplicate expiry notifications is allowed.
				 */
				rc = _odp_ipsec_status_send(op->op.sa->queue,
							    ODP_IPSEC_STATUS_WARN,
							    op->op.sa->ipsec_sa_hdl,
							    0, op->op.status.warn);
				if (rc == 0)
					odp_atomic_store_u32(&op->op.sa->soft_expiry_notified, 1);
				else
					_ODP_DBG("IPsec status event submission failed\n");
			}
		}

		if (odp_unlikely(op->op.status.error.all))
			goto handle_err;

		if (odp_unlikely(ipsec_out_check_crypto_result(*pkt, &op->op.status))) {
			update_post_lifetime_stats(op->op.sa, &op->op.state);
			goto finish;
		}

		if (odp_unlikely(ipsec_out_finalize_packet(pkt, &op->op.state, op->op.sa,
							   &op->op.status)))
			update_post_lifetime_stats(op->op.sa, &op->op.state);

finish:
		ipsec_out_inline_finish_packet_proc(pkt, &inline_param[i], op);

handle_err:
		ipsec_out_inline_handle_err(*pkt, op);
	}
}

int odp_ipsec_out_inline(const odp_packet_t pkt_in[], int num_in,
			 const odp_ipsec_out_param_t *param,
			 const odp_ipsec_out_inline_param_t *inline_param)
{
	int max_out = _ODP_MIN(num_in, MAX_BURST), num_crypto;
	odp_packet_t pkt_out[MAX_BURST], crypto_pkts[MAX_BURST];
	odp_crypto_packet_op_param_t crypto_param[MAX_BURST];
	ipsec_inline_op_t ops[MAX_BURST];
	ipsec_op_t *crypto_ops[MAX_BURST];

	ipsec_out_inline_prepare(pkt_in, pkt_out, max_out, param, inline_param, ops, crypto_pkts,
				 crypto_param, crypto_ops, &num_crypto);
	ipsec_do_crypto_burst(crypto_pkts, crypto_param, crypto_ops, num_crypto);
	ipsec_out_inline_finalize(pkt_out, inline_param, ops, max_out);

	return max_out;
}

int odp_ipsec_test_sa_update(odp_ipsec_sa_t sa,
			     odp_ipsec_test_sa_operation_t sa_op,
			     const odp_ipsec_test_sa_param_t *sa_param)
{
	ipsec_sa_t *ipsec_sa;

	ipsec_sa = _odp_ipsec_sa_entry_from_hdl(sa);
	_ODP_ASSERT(NULL != ipsec_sa);

	switch (sa_op) {
	case ODP_IPSEC_TEST_SA_UPDATE_SEQ_NUM:
		odp_atomic_store_u64(&ipsec_sa->hot.out.seq, sa_param->seq_num);
		break;
	default:
		return -1;
	}

	return 0;
}

int odp_ipsec_stats(odp_ipsec_sa_t sa, odp_ipsec_stats_t *stats)
{
	ipsec_sa_t *ipsec_sa;

	if (ODP_IPSEC_SA_INVALID == sa)
		return -EINVAL;

	if (!ipsec_config->stats_en)
		return -ENOTSUP;

	_ODP_ASSERT(NULL != stats);

	ipsec_sa = _odp_ipsec_sa_entry_from_hdl(sa);
	_ODP_ASSERT(NULL != ipsec_sa);

	_odp_ipsec_sa_stats_pkts(ipsec_sa, stats);
	stats->proto_err = odp_atomic_load_u64(&ipsec_sa->stats.proto_err);
	stats->auth_err = odp_atomic_load_u64(&ipsec_sa->stats.auth_err);
	stats->antireplay_err = odp_atomic_load_u64(&ipsec_sa->stats.antireplay_err);
	stats->alg_err = odp_atomic_load_u64(&ipsec_sa->stats.alg_err);
	stats->mtu_err = odp_atomic_load_u64(&ipsec_sa->stats.mtu_err);
	stats->hard_exp_bytes_err = odp_atomic_load_u64(&ipsec_sa->stats.hard_exp_bytes_err);
	stats->hard_exp_pkts_err = odp_atomic_load_u64(&ipsec_sa->stats.hard_exp_pkts_err);

	return 0;
}

int odp_ipsec_stats_multi(odp_ipsec_sa_t sa[], odp_ipsec_stats_t stats[], int num)
{
	int ret, i;

	_ODP_ASSERT(NULL != stats);

	for (i = 0; i < num; i++) {
		ret = odp_ipsec_stats(sa[i], &stats[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static int read_config_file(ipsec_global_t *global)
{
	const char *str_i = "ipsec.ordering.async_inbound";
	const char *str_o = "ipsec.ordering.async_outbound";
	int val;

	if (!_odp_libconfig_lookup_int(str_i, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str_i);
		return -1;
	}
	global->inbound_ordering_mode = val;

	if (!_odp_libconfig_lookup_int(str_o, &val)) {
		_ODP_ERR("Config option '%s' not found.\n", str_o);
		return -1;
	}
	global->outbound_ordering_mode = val;

	return 0;
}

int _odp_ipsec_init_global(void)
{
	odp_shm_t shm;

	if (odp_global_ro.disable.ipsec)
		return 0;

	shm = odp_shm_reserve("_odp_ipsec_global", sizeof(*ipsec_global),
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		_ODP_ERR("Shm reserve failed for odp_ipsec\n");
		return -1;
	}
	ipsec_global = odp_shm_addr(shm);
	if (ipsec_global == NULL) {
		_ODP_ERR("ipsec: odp_shm_addr() failed\n");
		odp_shm_free(shm);
		return -1;
	}
	memset(ipsec_global, 0, sizeof(*ipsec_global));
	ipsec_config = &ipsec_global->ipsec_config;

	if (read_config_file(ipsec_global)) {
		odp_shm_free(shm);
		return -1;
	}

	memset(&default_out_opt, 0, sizeof(default_out_opt));

	return 0;
}

int _odp_ipsec_term_global(void)
{
	odp_shm_t shm;

	if (odp_global_ro.disable.ipsec)
		return 0;

	shm = odp_shm_lookup("_odp_ipsec_global");

	if (shm == ODP_SHM_INVALID || odp_shm_free(shm)) {
		_ODP_ERR("Shm free failed for odp_ipsec");
		return -1;
	}

	return 0;
}

void odp_ipsec_print(void)
{
	_ODP_PRINT("\nIPSEC print\n");
	_ODP_PRINT("-----------\n");
	_ODP_PRINT("  max number of SA %u\n\n", ipsec_config->max_num_sa);
}

void odp_ipsec_sa_print(odp_ipsec_sa_t sa)
{
	ipsec_sa_t *ipsec_sa = _odp_ipsec_sa_entry_from_hdl(sa);

	_ODP_PRINT("\nIPSEC SA print\n");
	_ODP_PRINT("--------------\n");
	_ODP_PRINT("  SPI              %u\n\n", ipsec_sa->spi);
}

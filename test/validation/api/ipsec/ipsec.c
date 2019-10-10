/* Copyright (c) 2017-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include <unistd.h>
#include <odp/helper/odph_api.h>

#include "ipsec.h"

#include "test_vectors.h"

struct suite_context_s suite_context;

#define PKT_POOL_NUM  64
#define PKT_POOL_LEN  (1 * 1024)

#define PACKET_USER_PTR	((void *)0x1212fefe)
#define IPSEC_SA_CTX	((void *)0xfefefafa)

static odp_pktio_t pktio_create(odp_pool_t pool)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktio_capability_t capa;

	int ret;

	if (pool == ODP_POOL_INVALID)
		return ODP_PKTIO_INVALID;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_QUEUE;

	pktio = odp_pktio_open("loop", pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		ret = odp_pool_destroy(pool);
		if (ret)
			fprintf(stderr, "unable to destroy pool.\n");
		return ODP_PKTIO_INVALID;
	}

	if (odp_pktio_capability(pktio, &capa)) {
		fprintf(stderr, "pktio capabilities failed.\n");
		return ODP_PKTIO_INVALID;
	}

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

	if (odp_pktin_queue_config(pktio, &pktin_param)) {
		fprintf(stderr, "pktin queue config failed.\n");
		return ODP_PKTIO_INVALID;
	}

	if (odp_pktout_queue_config(pktio, NULL)) {
		fprintf(stderr, "pktout queue config failed.\n");
		return ODP_PKTIO_INVALID;
	}

	return pktio;
}

static int pktio_start(odp_pktio_t pktio, odp_bool_t in, odp_bool_t out)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	if (ODP_PKTIO_INVALID == pktio)
		return -1;

	if (odp_pktio_capability(pktio, &capa))
		return -1;
	/* If inline is not supported, return here. Tests will be marked as
	 * inactive when testing for IPsec capabilities. */
	if (in && !capa.config.inbound_ipsec)
		return 0;
	if (out && !capa.config.outbound_ipsec)
		return 0;

	odp_pktio_config_init(&config);
	config.parser.layer = ODP_PROTO_LAYER_ALL;
	config.inbound_ipsec = in;
	config.outbound_ipsec = out;

	if (odp_pktio_config(pktio, &config))
		return -1;
	if (odp_pktio_start(pktio))
		return -1;

	suite_context.pktio = pktio;

	return 1;
}

static void pktio_stop(odp_pktio_t pktio)
{
	odp_queue_t queue = ODP_QUEUE_INVALID;

	odp_pktin_event_queue(pktio, &queue, 1);

	if (odp_pktio_stop(pktio))
		fprintf(stderr, "IPsec pktio stop failed.\n");

	while (1) {
		odp_event_t ev = odp_queue_deq(queue);

		if (ev != ODP_EVENT_INVALID)
			odp_event_free(ev);
		else
			break;
	}
}

#define MAX_ALG_CAPA 32

int ipsec_check(odp_bool_t ah,
		odp_cipher_alg_t cipher,
		uint32_t cipher_bits,
		odp_auth_alg_t auth,
		uint32_t auth_bits)
{
	odp_ipsec_capability_t capa;
	odp_ipsec_cipher_capability_t cipher_capa[MAX_ALG_CAPA];
	odp_ipsec_auth_capability_t   auth_capa[MAX_ALG_CAPA];
	int i, num;
	odp_bool_t found;

	if (odp_ipsec_capability(&capa) < 0)
		return ODP_TEST_INACTIVE;

	if ((ODP_IPSEC_OP_MODE_SYNC == suite_context.inbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_sync) ||
	    (ODP_IPSEC_OP_MODE_SYNC == suite_context.outbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_sync) ||
	    (ODP_IPSEC_OP_MODE_ASYNC == suite_context.inbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_async) ||
	    (ODP_IPSEC_OP_MODE_ASYNC == suite_context.outbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_async) ||
	    (ODP_IPSEC_OP_MODE_INLINE == suite_context.inbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_inline_in) ||
	    (ODP_IPSEC_OP_MODE_INLINE == suite_context.outbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_inline_out))
		return ODP_TEST_INACTIVE;

	/* suite_context.pktio is set to ODP_PKTIO_INVALID in ipsec_suite_init()
	 * if the pktio device doesn't support inline IPsec processing. */
	if (suite_context.pktio == ODP_PKTIO_INVALID &&
	    (ODP_IPSEC_OP_MODE_INLINE == suite_context.inbound_op_mode ||
	     ODP_IPSEC_OP_MODE_INLINE == suite_context.outbound_op_mode))
		return ODP_TEST_INACTIVE;

	if (ah && (ODP_SUPPORT_NO == capa.proto_ah))
		return ODP_TEST_INACTIVE;

	/* Cipher algorithms */
	switch (cipher) {
	case ODP_CIPHER_ALG_NULL:
		if (!capa.ciphers.bit.null)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_DES:
		if (!capa.ciphers.bit.des)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_3DES_CBC:
		if (!capa.ciphers.bit.trides_cbc)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_CBC:
		if (!capa.ciphers.bit.aes_cbc)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_CTR:
		if (!capa.ciphers.bit.aes_ctr)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_AES_GCM:
		if (!capa.ciphers.bit.aes_gcm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_CIPHER_ALG_CHACHA20_POLY1305:
		if (!capa.ciphers.bit.chacha20_poly1305)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported cipher algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	/* Authentication algorithms */
	switch (auth) {
	case ODP_AUTH_ALG_NULL:
		if (!capa.auths.bit.null)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_MD5_HMAC:
		if (!capa.auths.bit.md5_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA1_HMAC:
		if (!capa.auths.bit.sha1_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA256_HMAC:
		if (!capa.auths.bit.sha256_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA384_HMAC:
		if (!capa.auths.bit.sha384_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_SHA512_HMAC:
		if (!capa.auths.bit.sha512_hmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_XCBC_MAC:
		if (!capa.auths.bit.aes_xcbc_mac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_GCM:
		if (!capa.auths.bit.aes_gcm)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_AES_GMAC:
		if (!capa.auths.bit.aes_gmac)
			return ODP_TEST_INACTIVE;
		break;
	case ODP_AUTH_ALG_CHACHA20_POLY1305:
		if (!capa.auths.bit.chacha20_poly1305)
			return ODP_TEST_INACTIVE;
		break;
	default:
		fprintf(stderr, "Unsupported authentication algorithm\n");
		return ODP_TEST_INACTIVE;
	}

	num = odp_ipsec_cipher_capability(cipher, cipher_capa, MAX_ALG_CAPA);
	if (num <= 0) {
		fprintf(stderr, "Wrong cipher capabilities\n");
		return ODP_TEST_INACTIVE;
	}

	/* Search for the test case */
	found = false;
	for (i = 0; i < num; i++) {
		if (cipher_capa[i].key_len == cipher_bits / 8) {
			found = 1;
			break;
		}
	}

	if (!found) {
		fprintf(stderr, "Unsupported key length\n");
		return ODP_TEST_INACTIVE;
	}

	num = odp_ipsec_auth_capability(auth, auth_capa, MAX_ALG_CAPA);
	if (num <= 0) {
		fprintf(stderr, "Wrong auth capabilities\n");
		return ODP_TEST_INACTIVE;
	}

	/* Search for the test case */
	found = false;
	for (i = 0; i < num; i++) {
		if (auth_capa[i].key_len == auth_bits / 8) {
			found = 1;
			break;
		}
	}

	if (!found) {
		fprintf(stderr, "Unsupported auth key length\n");
		return ODP_TEST_INACTIVE;
	}

	return ODP_TEST_ACTIVE;
}

int ipsec_check_ah_sha256(void)
{
	return ipsec_check_ah(ODP_AUTH_ALG_SHA256_HMAC, 256);
}

int ipsec_check_esp_null_sha256(void)
{
	return  ipsec_check_esp(ODP_CIPHER_ALG_NULL, 0,
				ODP_AUTH_ALG_SHA256_HMAC, 256);
}

int ipsec_check_esp_aes_cbc_128_null(void)
{
	return  ipsec_check_esp(ODP_CIPHER_ALG_AES_CBC, 128,
				ODP_AUTH_ALG_NULL, 0);
}

int ipsec_check_esp_aes_cbc_128_sha256(void)
{
	return  ipsec_check_esp(ODP_CIPHER_ALG_AES_CBC, 128,
				ODP_AUTH_ALG_SHA256_HMAC, 256);
}

int ipsec_check_esp_aes_ctr_128_null(void)
{
	return  ipsec_check_esp(ODP_CIPHER_ALG_AES_CTR, 128,
				ODP_AUTH_ALG_NULL, 0);
}

int ipsec_check_esp_aes_gcm_128(void)
{
	return  ipsec_check_esp(ODP_CIPHER_ALG_AES_GCM, 128,
				ODP_AUTH_ALG_AES_GCM, 0);
}

int ipsec_check_esp_aes_gcm_256(void)
{
	return  ipsec_check_esp(ODP_CIPHER_ALG_AES_GCM, 256,
				ODP_AUTH_ALG_AES_GCM, 0);
}

int ipsec_check_ah_aes_gmac_128(void)
{
	return  ipsec_check_esp(ODP_CIPHER_ALG_NULL, 0,
				ODP_AUTH_ALG_AES_GMAC, 128);
}

int ipsec_check_esp_null_aes_gmac_128(void)
{
	return  ipsec_check_esp(ODP_CIPHER_ALG_NULL, 0,
				ODP_AUTH_ALG_AES_GMAC, 128);
}

int ipsec_check_esp_chacha20_poly1305(void)
{
	return  ipsec_check_esp(ODP_CIPHER_ALG_CHACHA20_POLY1305, 256,
				ODP_AUTH_ALG_CHACHA20_POLY1305, 0);
}

void ipsec_sa_param_fill(odp_ipsec_sa_param_t *param,
			 odp_bool_t in,
			 odp_bool_t ah,
			 uint32_t spi,
			 odp_ipsec_tunnel_param_t *tun,
			 odp_cipher_alg_t cipher_alg,
			 const odp_crypto_key_t *cipher_key,
			 odp_auth_alg_t auth_alg,
			 const odp_crypto_key_t *auth_key,
			 const odp_crypto_key_t *cipher_key_extra,
			 const odp_crypto_key_t *auth_key_extra)
{
	odp_ipsec_sa_param_init(param);
	param->dir = in ? ODP_IPSEC_DIR_INBOUND :
			  ODP_IPSEC_DIR_OUTBOUND;
	if (in)
		param->inbound.lookup_mode = ODP_IPSEC_LOOKUP_SPI;

	param->proto = ah ? ODP_IPSEC_AH :
			    ODP_IPSEC_ESP;

	if (tun) {
		param->mode = ODP_IPSEC_MODE_TUNNEL;
		if (!in)
			param->outbound.tunnel = *tun;
	} else {
		param->mode = ODP_IPSEC_MODE_TRANSPORT;
	}

	param->spi = spi;

	param->dest_queue = suite_context.queue;

	param->context = IPSEC_SA_CTX;

	param->crypto.cipher_alg = cipher_alg;
	if (cipher_key)
		param->crypto.cipher_key = *cipher_key;

	param->crypto.auth_alg = auth_alg;
	if (auth_key)
		param->crypto.auth_key = *auth_key;

	if (cipher_key_extra)
		param->crypto.cipher_key_extra = *cipher_key_extra;

	if (auth_key_extra)
		param->crypto.auth_key_extra = *auth_key_extra;
}

void ipsec_sa_destroy(odp_ipsec_sa_t sa)
{
	odp_event_t event;
	odp_ipsec_status_t status;
	int ret;

	CU_ASSERT_EQUAL(IPSEC_SA_CTX, odp_ipsec_sa_context(sa));

	CU_ASSERT_EQUAL(ODP_IPSEC_OK, odp_ipsec_sa_disable(sa));

	if (ODP_QUEUE_INVALID != suite_context.queue) {
		do {
			event = odp_queue_deq(suite_context.queue);
		} while (event == ODP_EVENT_INVALID);

		CU_ASSERT_EQUAL(ODP_EVENT_IPSEC_STATUS, odp_event_type(event));

		ret = odp_ipsec_status(&status, event);
		CU_ASSERT(ret == 0);

		if (ret == 0) {
			CU_ASSERT_EQUAL(ODP_IPSEC_STATUS_SA_DISABLE, status.id);
			CU_ASSERT_EQUAL(sa, status.sa);
			CU_ASSERT_EQUAL(0, status.result);
			CU_ASSERT_EQUAL(0, status.warn.all);
		}

		odp_event_free(event);
	}

	CU_ASSERT_EQUAL(ODP_IPSEC_OK, odp_ipsec_sa_destroy(sa));
}

odp_packet_t ipsec_packet(const ipsec_test_packet *itp)
{
	odp_packet_t pkt = odp_packet_alloc(suite_context.pool, itp->len);

	CU_ASSERT_NOT_EQUAL(ODP_PACKET_INVALID, pkt);
	if (ODP_PACKET_INVALID == pkt)
		return pkt;

	CU_ASSERT_EQUAL(0, odp_packet_copy_from_mem(pkt, 0, itp->len,
						    itp->data));
	if (itp->l2_offset != ODP_PACKET_OFFSET_INVALID)
		CU_ASSERT_EQUAL(0, odp_packet_l2_offset_set(pkt,
							    itp->l2_offset));
	if (itp->l3_offset != ODP_PACKET_OFFSET_INVALID)
		CU_ASSERT_EQUAL(0, odp_packet_l3_offset_set(pkt,
							    itp->l3_offset));
	if (itp->l4_offset != ODP_PACKET_OFFSET_INVALID)
		CU_ASSERT_EQUAL(0, odp_packet_l4_offset_set(pkt,
							    itp->l4_offset));

	odp_packet_user_ptr_set(pkt, PACKET_USER_PTR);

	return pkt;
}

/*
 * Compare packages ignoring everything before L3 header
 */
static void ipsec_check_packet(const ipsec_test_packet *itp, odp_packet_t pkt,
			       odp_bool_t is_outbound)
{
	uint32_t len = (ODP_PACKET_INVALID == pkt) ? 1 : odp_packet_len(pkt);
	uint32_t l3, l4;
	uint8_t data[len];
	const odph_ipv4hdr_t *itp_ip;
	odph_ipv4hdr_t *ip;

	if (NULL == itp)
		return;

	CU_ASSERT_NOT_EQUAL(ODP_PACKET_INVALID, pkt);
	if (ODP_PACKET_INVALID == pkt)
		return;

	CU_ASSERT_EQUAL(PACKET_USER_PTR, odp_packet_user_ptr(pkt));

	l3 = odp_packet_l3_offset(pkt);
	l4 = odp_packet_l4_offset(pkt);
	odp_packet_copy_to_mem(pkt, 0, len, data);

	if (l3 == ODP_PACKET_OFFSET_INVALID) {
		CU_ASSERT_EQUAL(itp->l3_offset, ODP_PACKET_OFFSET_INVALID);
		CU_ASSERT_EQUAL(l4, ODP_PACKET_OFFSET_INVALID);

		return;
	}

	CU_ASSERT_EQUAL(len - l3, itp->len - itp->l3_offset);
	if (len - l3 != itp->len - itp->l3_offset)
		return;

	CU_ASSERT_EQUAL(l4 - l3, itp->l4_offset - itp->l3_offset);
	if (l4 - l3 != itp->l4_offset - itp->l3_offset)
		return;

	ip = (odph_ipv4hdr_t *) &data[l3];
	itp_ip = (const odph_ipv4hdr_t *) &itp->data[itp->l3_offset];
	if (ODPH_IPV4HDR_VER(ip->ver_ihl) == ODPH_IPV4 &&
	    is_outbound &&
	    ip->id != itp_ip->id) {
		/*
		 * IP ID value chosen by the implementation differs
		 * from the IP value in our test vector. This requires
		 * special handling in outbound checks.
		 */
		/*
		 * Let's change IP ID and header checksum to same values
		 * as in the test vector to facilitate packet comparison.
		 */
		CU_ASSERT(odph_ipv4_csum_valid(pkt));
		ip->id = itp_ip->id;
		ip->chksum = itp_ip->chksum;

		if (ip->proto == ODPH_IPPROTO_AH) {
			/*
			 * ID field is included in the authentication so
			 * we cannot check ICV against our test vector.
			 * Check packet data before the first possible
			 * location of the AH ICV field.
			 */
			CU_ASSERT_EQUAL(0, memcmp(data + l3,
						  itp->data + itp->l3_offset,
						  ODPH_IPV4HDR_LEN + 12));
			return;
		}
	}

	CU_ASSERT_EQUAL(0, memcmp(data + l3,
				  itp->data + itp->l3_offset,
				  len - l3));
}

static int ipsec_send_in_one(const ipsec_test_part *part,
			     odp_ipsec_sa_t sa,
			     odp_packet_t *pkto)
{
	odp_ipsec_in_param_t param;
	int num_out = part->out_pkt;
	odp_packet_t pkt;
	int i;

	pkt = ipsec_packet(part->pkt_in);

	memset(&param, 0, sizeof(param));
	if (!part->lookup) {
		param.num_sa = 1;
		param.sa = &sa;
	} else {
		param.num_sa = 0;
		param.sa = NULL;
	}

	if (ODP_IPSEC_OP_MODE_SYNC == suite_context.inbound_op_mode) {
		CU_ASSERT_EQUAL(part->out_pkt, odp_ipsec_in(&pkt, 1,
							    pkto, &num_out,
							    &param));
		CU_ASSERT_EQUAL(num_out, part->out_pkt);
		CU_ASSERT(odp_packet_subtype(*pkto) == ODP_EVENT_PACKET_IPSEC);
	} else if (ODP_IPSEC_OP_MODE_ASYNC == suite_context.inbound_op_mode) {
		CU_ASSERT_EQUAL(1, odp_ipsec_in_enq(&pkt, 1, &param));

		for (i = 0; i < num_out; i++) {
			odp_event_t event;
			odp_event_subtype_t subtype;

			do {
				event = odp_queue_deq(suite_context.queue);
			} while (event == ODP_EVENT_INVALID);

			CU_ASSERT_EQUAL(ODP_EVENT_PACKET,
					odp_event_types(event, &subtype));
			CU_ASSERT_EQUAL(ODP_EVENT_PACKET_IPSEC, subtype);
			pkto[i] = odp_ipsec_packet_from_event(event);
			CU_ASSERT(odp_packet_subtype(pkto[i]) ==
				  ODP_EVENT_PACKET_IPSEC);
		}
	} else {
		odp_pktout_queue_t pktout;
		odp_queue_t queue = ODP_QUEUE_INVALID;

		if (odp_pktout_queue(suite_context.pktio, &pktout, 1) != 1) {
			CU_FAIL_FATAL("No pktout queue");
			return 0;
		}

		CU_ASSERT_EQUAL(1, odp_pktout_send(pktout, &pkt, 1));
		CU_ASSERT_EQUAL_FATAL(1,
				      odp_pktin_event_queue(suite_context.
							    pktio,
							    &queue, 1));

		for (i = 0; i < num_out;) {
			odp_event_t ev;
			odp_event_subtype_t subtype;

			ev = odp_queue_deq(queue);
			if (ODP_EVENT_INVALID != ev) {
				CU_ASSERT_EQUAL(ODP_EVENT_PACKET,
						odp_event_types(ev, &subtype));
				CU_ASSERT_EQUAL(ODP_EVENT_PACKET_BASIC,
						subtype);
				CU_ASSERT(part->out[i].status.error.sa_lookup);

				pkto[i++] = odp_ipsec_packet_from_event(ev);
				continue;
			}

			ev = odp_queue_deq(suite_context.queue);
			if (ODP_EVENT_INVALID != ev) {
				CU_ASSERT_EQUAL(ODP_EVENT_PACKET,
						odp_event_types(ev, &subtype));
				CU_ASSERT_EQUAL(ODP_EVENT_PACKET_IPSEC,
						subtype);
				CU_ASSERT(!part->out[i].status.error.sa_lookup);

				pkto[i] = odp_ipsec_packet_from_event(ev);
				CU_ASSERT(odp_packet_subtype(pkto[i]) ==
					  ODP_EVENT_PACKET_IPSEC);
				i++;
				continue;
			}
		}
	}

	return num_out;
}

static int ipsec_send_out_one(const ipsec_test_part *part,
			      odp_ipsec_sa_t sa,
			      odp_packet_t *pkto)
{
	odp_ipsec_out_param_t param;
	int num_out = part->out_pkt;
	odp_packet_t pkt;
	int i;

	pkt = ipsec_packet(part->pkt_in);

	memset(&param, 0, sizeof(param));
	param.num_sa = 1;
	param.sa = &sa;
	param.num_opt = part->num_opt;
	param.opt = &part->opt;

	if (ODP_IPSEC_OP_MODE_SYNC == suite_context.outbound_op_mode) {
		CU_ASSERT_EQUAL(part->out_pkt, odp_ipsec_out(&pkt, 1,
							     pkto, &num_out,
							     &param));
		CU_ASSERT_EQUAL(num_out, part->out_pkt);
		CU_ASSERT(odp_packet_subtype(*pkto) ==
			  ODP_EVENT_PACKET_IPSEC);
	} else if (ODP_IPSEC_OP_MODE_ASYNC == suite_context.outbound_op_mode) {
		CU_ASSERT_EQUAL(1, odp_ipsec_out_enq(&pkt, 1, &param));

		for (i = 0; i < num_out; i++) {
			odp_event_t event;
			odp_event_subtype_t subtype;

			do {
				event = odp_queue_deq(suite_context.queue);
			} while (event == ODP_EVENT_INVALID);

			CU_ASSERT_EQUAL(ODP_EVENT_PACKET,
					odp_event_types(event, &subtype));
			CU_ASSERT_EQUAL(ODP_EVENT_PACKET_IPSEC, subtype);
			pkto[i] = odp_ipsec_packet_from_event(event);
			CU_ASSERT(odp_packet_subtype(pkto[i]) ==
				  ODP_EVENT_PACKET_IPSEC);
		}
	} else {
		struct odp_ipsec_out_inline_param_t inline_param;
		uint32_t hdr_len;
		uint8_t hdr[32];
		odp_queue_t queue = ODP_QUEUE_INVALID;

		if (NULL != part->out[0].pkt_out) {
			hdr_len = part->out[0].pkt_out->l3_offset;
			CU_ASSERT_FATAL(hdr_len <= sizeof(hdr));
			memcpy(hdr, part->out[0].pkt_out->data, hdr_len);
		} else if (part->pkt_in->l3_offset !=
			   ODP_PACKET_OFFSET_INVALID) {
			hdr_len = part->pkt_in->l3_offset;
			CU_ASSERT_FATAL(hdr_len <= sizeof(hdr));
			memcpy(hdr, part->pkt_in->data, hdr_len);
		} else {
			/* Dummy header */
			hdr_len = 14;
			memset(hdr, 0xff, hdr_len);
		}
		inline_param.pktio = suite_context.pktio;
		inline_param.outer_hdr.ptr = hdr;
		inline_param.outer_hdr.len = hdr_len;

		CU_ASSERT_EQUAL(1, odp_ipsec_out_inline(&pkt, 1, &param,
							&inline_param));
		CU_ASSERT_EQUAL_FATAL(1,
				      odp_pktin_event_queue(suite_context.
							    pktio,
							    &queue, 1));

		for (i = 0; i < num_out;) {
			odp_event_t ev;
			odp_event_subtype_t subtype;

			ev = odp_queue_deq(queue);
			if (ODP_EVENT_INVALID != ev) {
				CU_ASSERT_EQUAL(ODP_EVENT_PACKET,
						odp_event_types(ev, &subtype));
				CU_ASSERT_EQUAL(ODP_EVENT_PACKET_BASIC,
						subtype);
				CU_ASSERT(!part->out[i].status.error.all);

				pkto[i++] = odp_ipsec_packet_from_event(ev);
				continue;
			}

			ev = odp_queue_deq(suite_context.queue);
			if (ODP_EVENT_INVALID != ev) {
				CU_ASSERT_EQUAL(ODP_EVENT_PACKET,
						odp_event_types(ev, &subtype));
				CU_ASSERT_EQUAL(ODP_EVENT_PACKET_IPSEC,
						subtype);
				CU_ASSERT(part->out[i].status.error.all);

				pkto[i] = odp_ipsec_packet_from_event(ev);
				CU_ASSERT(odp_packet_subtype(pkto[i]) ==
					  ODP_EVENT_PACKET_IPSEC);
				i++;
				continue;
			}
		}
	}

	return num_out;
}

void ipsec_check_in_one(const ipsec_test_part *part, odp_ipsec_sa_t sa)
{
	int num_out = part->out_pkt;
	odp_packet_t pkto[num_out];
	int i;

	num_out = ipsec_send_in_one(part, sa, pkto);

	for (i = 0; i < num_out; i++) {
		odp_ipsec_packet_result_t result;

		if (ODP_PACKET_INVALID == pkto[i]) {
			CU_FAIL("ODP_PACKET_INVALID received");
			continue;
		}

		if (ODP_EVENT_PACKET_IPSEC !=
		    odp_event_subtype(odp_packet_to_event(pkto[i]))) {
			/* Inline packet went through loop */
			CU_ASSERT_EQUAL(1, part->out[i].status.error.sa_lookup);
		} else {
			CU_ASSERT_EQUAL(0, odp_ipsec_result(&result, pkto[i]));
			CU_ASSERT_EQUAL(part->out[i].status.error.all,
					result.status.error.all);
			CU_ASSERT(!result.status.error.all ==
				  !odp_packet_has_error(pkto[i]));
			CU_ASSERT_EQUAL(suite_context.inbound_op_mode ==
					ODP_IPSEC_OP_MODE_INLINE,
					result.flag.inline_mode);
			CU_ASSERT_EQUAL(sa, result.sa);
			if (ODP_IPSEC_SA_INVALID != sa)
				CU_ASSERT_EQUAL(IPSEC_SA_CTX,
						odp_ipsec_sa_context(sa));
		}
		ipsec_check_packet(part->out[i].pkt_out,
				   pkto[i],
				   false);
		if (part->out[i].pkt_out != NULL &&
		    part->out[i].l3_type != _ODP_PROTO_L3_TYPE_UNDEF)
			CU_ASSERT_EQUAL(part->out[i].l3_type,
					odp_packet_l3_type(pkto[i]));
		if (part->out[i].pkt_out != NULL &&
		    part->out[i].l4_type != _ODP_PROTO_L4_TYPE_UNDEF)
			CU_ASSERT_EQUAL(part->out[i].l4_type,
					odp_packet_l4_type(pkto[i]));
		odp_packet_free(pkto[i]);
	}
}

void ipsec_check_out_one(const ipsec_test_part *part, odp_ipsec_sa_t sa)
{
	int num_out = part->out_pkt;
	odp_packet_t pkto[num_out];
	int i;

	num_out = ipsec_send_out_one(part, sa, pkto);

	for (i = 0; i < num_out; i++) {
		odp_ipsec_packet_result_t result;

		if (ODP_PACKET_INVALID == pkto[i]) {
			CU_FAIL("ODP_PACKET_INVALID received");
			continue;
		}

		if (ODP_EVENT_PACKET_IPSEC !=
		    odp_event_subtype(odp_packet_to_event(pkto[i]))) {
			/* Inline packet went through loop */
			CU_ASSERT_EQUAL(0, part->out[i].status.error.all);
		} else {
			/* IPsec packet */
			CU_ASSERT_EQUAL(0, odp_ipsec_result(&result, pkto[i]));
			CU_ASSERT_EQUAL(part->out[i].status.error.all,
					result.status.error.all);
			CU_ASSERT(!result.status.error.all ==
				  !odp_packet_has_error(pkto[i]));
			CU_ASSERT_EQUAL(sa, result.sa);
			CU_ASSERT_EQUAL(IPSEC_SA_CTX,
					odp_ipsec_sa_context(sa));
		}
		ipsec_check_packet(part->out[i].pkt_out,
				   pkto[i],
				   true);
		odp_packet_free(pkto[i]);
	}
}

void ipsec_check_out_in_one(const ipsec_test_part *part,
			    odp_ipsec_sa_t sa,
			    odp_ipsec_sa_t sa_in)
{
	int num_out = part->out_pkt;
	odp_packet_t pkto[num_out];
	int i;

	num_out = ipsec_send_out_one(part, sa, pkto);

	for (i = 0; i < num_out; i++) {
		ipsec_test_part part_in = *part;
		ipsec_test_packet pkt_in;
		odp_ipsec_packet_result_t result;

		if (ODP_PACKET_INVALID == pkto[i]) {
			CU_FAIL("ODP_PACKET_INVALID received");
			continue;
		}

		if (ODP_EVENT_PACKET_IPSEC !=
		    odp_event_subtype(odp_packet_to_event(pkto[i]))) {
			/* Inline packet went through loop */
			CU_ASSERT_EQUAL(0, part->out[i].status.error.all);
		} else {
			/* IPsec packet */
			CU_ASSERT_EQUAL(0, odp_ipsec_result(&result, pkto[i]));
			CU_ASSERT_EQUAL(part->out[i].status.error.all,
					result.status.error.all);
			CU_ASSERT_EQUAL(sa, result.sa);
			CU_ASSERT_EQUAL(IPSEC_SA_CTX,
					odp_ipsec_sa_context(sa));
		}
		CU_ASSERT_FATAL(odp_packet_len(pkto[i]) <=
				sizeof(pkt_in.data));

		pkt_in.len = odp_packet_len(pkto[i]);
		pkt_in.l2_offset = odp_packet_l2_offset(pkto[i]);
		pkt_in.l3_offset = odp_packet_l3_offset(pkto[i]);
		pkt_in.l4_offset = odp_packet_l4_offset(pkto[i]);
		odp_packet_copy_to_mem(pkto[i], 0,
				       pkt_in.len,
				       pkt_in.data);
		part_in.pkt_in = &pkt_in;
		ipsec_check_in_one(&part_in, sa_in);
		odp_packet_free(pkto[i]);
	}
}

int ipsec_suite_init(void)
{
	int rc = 0;

	if (suite_context.pktio != ODP_PKTIO_INVALID)
		rc = pktio_start(suite_context.pktio,
				 suite_context.inbound_op_mode ==
				 ODP_IPSEC_OP_MODE_INLINE,
				 suite_context.outbound_op_mode ==
				 ODP_IPSEC_OP_MODE_INLINE);
	if (rc == 0)
		suite_context.pktio = ODP_PKTIO_INVALID;

	return rc < 0 ? -1 : 0;
}

static int ipsec_suite_term(void)
{
	if (suite_context.pktio != ODP_PKTIO_INVALID)
		pktio_stop(suite_context.pktio);

	if (odp_cunit_print_inactive())
		return -1;

	return 0;
}

int ipsec_in_term(void)
{
	return ipsec_suite_term();
}

int ipsec_out_term(void)
{
	return ipsec_suite_term();
}

int ipsec_init(odp_instance_t *inst)
{
	odp_pool_param_t params;
	odp_pool_t pool;
	odp_queue_t out_queue;
	odp_pool_capability_t pool_capa;
	odp_pktio_t pktio;
	odp_init_t init_param;
	odph_helper_options_t helper_options;

	if (odph_options(&helper_options)) {
		fprintf(stderr, "error: odph_options() failed.\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (0 != odp_init_global(inst, &init_param, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}

	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa) < 0) {
		fprintf(stderr, "error: odp_pool_capability() failed.\n");
		return -1;
	}

	odp_pool_param_init(&params);
	params.pkt.seg_len = PKT_POOL_LEN;
	params.pkt.len     = PKT_POOL_LEN;
	params.pkt.num     = PKT_POOL_NUM;
	params.type        = ODP_POOL_PACKET;

	if (pool_capa.pkt.max_seg_len &&
	    PKT_POOL_LEN > pool_capa.pkt.max_seg_len) {
		fprintf(stderr, "Warning: small packet segment length\n");
		params.pkt.seg_len = pool_capa.pkt.max_seg_len;
	}

	if (pool_capa.pkt.max_len &&
	    PKT_POOL_LEN > pool_capa.pkt.max_len) {
		fprintf(stderr, "Pool max packet length too small\n");
		return -1;
	}

	pool = odp_pool_create("packet_pool", &params);

	if (ODP_POOL_INVALID == pool) {
		fprintf(stderr, "Packet pool creation failed.\n");
		return -1;
	}
	out_queue = odp_queue_create("ipsec-out", NULL);
	if (ODP_QUEUE_INVALID == out_queue) {
		fprintf(stderr, "IPsec outq creation failed.\n");
		return -1;
	}

	pktio = pktio_create(pool);
	if (ODP_PKTIO_INVALID == pktio) {
		fprintf(stderr, "IPsec pktio creation failed.\n");
		return -1;
	}

	return 0;
}

int ipsec_config(odp_instance_t ODP_UNUSED inst)
{
	odp_ipsec_capability_t capa;
	odp_ipsec_config_t ipsec_config;

	if (odp_ipsec_capability(&capa) < 0)
		return -1;

	/* If we can not setup IPsec due to mode being unsupported, don't
	 * return an error here. It is easier (and more correct) to filter that
	 * in test checking function and just say that the test is inactive. */
	if ((ODP_IPSEC_OP_MODE_SYNC == suite_context.inbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_sync) ||
	    (ODP_IPSEC_OP_MODE_SYNC == suite_context.outbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_sync) ||
	    (ODP_IPSEC_OP_MODE_ASYNC == suite_context.inbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_async) ||
	    (ODP_IPSEC_OP_MODE_ASYNC == suite_context.outbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_async) ||
	    (ODP_IPSEC_OP_MODE_INLINE == suite_context.inbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_inline_in) ||
	    (ODP_IPSEC_OP_MODE_INLINE == suite_context.outbound_op_mode &&
	     ODP_SUPPORT_NO == capa.op_mode_inline_out))
		return 0;

	odp_ipsec_config_init(&ipsec_config);
	ipsec_config.inbound_mode = suite_context.inbound_op_mode;
	ipsec_config.outbound_mode = suite_context.outbound_op_mode;
	ipsec_config.outbound.all_chksum = ~0;
	ipsec_config.inbound.default_queue = suite_context.queue;
	ipsec_config.inbound.parse_level = ODP_PROTO_LAYER_ALL;
	ipsec_config.inbound.chksums.all_chksum = ~0;

	if (ODP_IPSEC_OK != odp_ipsec_config(&ipsec_config))
		return -1;

	return 0;
}

int ipsec_term(odp_instance_t inst)
{
	odp_pool_t pool;
	odp_queue_t out_queue;
	odp_pktio_t pktio;

	pktio = odp_pktio_lookup("loop");
	if (ODP_PKTIO_INVALID != pktio) {
		if (odp_pktio_close(pktio))
			fprintf(stderr, "IPsec pktio close failed.\n");
	} else {
		fprintf(stderr, "IPsec pktio not found.\n");
	}

	out_queue = odp_queue_lookup("ipsec-out");
	if (ODP_QUEUE_INVALID != out_queue) {
		if (odp_queue_destroy(out_queue))
			fprintf(stderr, "IPsec outq destroy failed.\n");
	} else {
		fprintf(stderr, "IPsec outq not found.\n");
	}

	pool = odp_pool_lookup("packet_pool");
	if (ODP_POOL_INVALID != pool) {
		if (odp_pool_destroy(pool))
			fprintf(stderr, "Packet pool destroy failed.\n");
	} else {
		fprintf(stderr, "Packet pool not found.\n");
	}

	if (0 != odp_term_local()) {
		fprintf(stderr, "error: odp_term_local() failed.\n");
		return -1;
	}

	if (0 != odp_term_global(inst)) {
		fprintf(stderr, "error: odp_term_global() failed.\n");
		return -1;
	}

	return 0;
}

/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/ipsec.h>

#include <odp_ipsec_internal.h>

#include <string.h>

int odp_ipsec_capability(odp_ipsec_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_ipsec_capability_t));

	return 0;
}

int odp_ipsec_cipher_capability(odp_cipher_alg_t cipher,
				odp_crypto_cipher_capability_t capa[], int num)
{
	(void)cipher;
	(void)capa;
	(void)num;

	return -1;
}

int odp_ipsec_auth_capability(odp_auth_alg_t auth,
			      odp_crypto_auth_capability_t capa[], int num)
{
	(void)auth;
	(void)capa;
	(void)num;

	return -1;
}

void odp_ipsec_config_init(odp_ipsec_config_t *config)
{
	memset(config, 0, sizeof(odp_ipsec_config_t));
}

int odp_ipsec_config(const odp_ipsec_config_t *config)
{
	(void)config;

	return -1;
}

void odp_ipsec_sa_param_init(odp_ipsec_sa_param_t *param)
{
	memset(param, 0, sizeof(odp_ipsec_sa_param_t));
}

odp_ipsec_sa_t odp_ipsec_sa_create(const odp_ipsec_sa_param_t *param)
{
	(void)param;

	return ODP_IPSEC_SA_INVALID;
}

int odp_ipsec_sa_disable(odp_ipsec_sa_t sa)
{
	(void)sa;

	return -1;
}

int odp_ipsec_sa_destroy(odp_ipsec_sa_t sa)
{
	(void)sa;

	return -1;
}

int odp_ipsec_in(const odp_packet_t pkt_in[], int num_in,
		 odp_packet_t pkt_out[], int *num_out,
		 const odp_ipsec_in_param_t *param)
{
	(void)pkt_in;
	(void)num_in;
	(void)pkt_out;
	(void)num_out;
	(void)param;

	return -1;
}

int odp_ipsec_out(const odp_packet_t pkt_in[], int num_in,
		  odp_packet_t pkt_out[], int *num_out,
		  const odp_ipsec_out_param_t *param)
{
	(void)pkt_in;
	(void)num_in;
	(void)pkt_out;
	(void)num_out;
	(void)param;

	return -1;
}

int odp_ipsec_in_enq(const odp_packet_t pkt[], int num,
		     const odp_ipsec_in_param_t *param)
{
	(void)pkt;
	(void)num;
	(void)param;

	return -1;
}

int odp_ipsec_out_enq(const odp_packet_t pkt[], int num,
		      const odp_ipsec_out_param_t *param)
{
	(void)pkt;
	(void)num;
	(void)param;

	return -1;
}

int odp_ipsec_out_inline(const odp_packet_t pkt[], int num,
			 const odp_ipsec_out_param_t *param,
			 const odp_ipsec_out_inline_param_t *inline_param)
{
	(void)pkt;
	(void)num;
	(void)param;
	(void)inline_param;

	return -1;
}

int odp_ipsec_result(odp_ipsec_packet_result_t *result, odp_packet_t packet)
{
	(void)result;
	(void)packet;

	return -1;
}

int odp_ipsec_sa_mtu_update(odp_ipsec_sa_t sa, uint32_t mtu)
{
	(void)sa;
	(void)mtu;

	return -1;
}

void *odp_ipsec_sa_context(odp_ipsec_sa_t sa)
{
	(void)sa;

	return NULL;
}

odp_packet_t odp_ipsec_packet_from_event(odp_event_t ev)
{
	(void)ev;

	return ODP_PACKET_INVALID;
}

odp_event_t odp_ipsec_packet_to_event(odp_packet_t pkt)
{
	(void)pkt;

	return ODP_EVENT_INVALID;
}

uint64_t odp_ipsec_sa_to_u64(odp_ipsec_sa_t sa)
{
	return _odp_pri(sa);
}

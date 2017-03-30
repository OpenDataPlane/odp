/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/ipsec.h>

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

odp_ipsec_sa_t odp_ipsec_sa_create(odp_ipsec_sa_param_t *param)
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

int odp_ipsec_in(const odp_ipsec_op_param_t *input,
		 odp_ipsec_op_result_t *output)
{
	(void)input;
	(void)output;

	return -1;
}

int odp_ipsec_out(const odp_ipsec_op_param_t *input,
		  odp_ipsec_op_result_t *output)
{
	(void)input;
	(void)output;

	return -1;
}

int odp_ipsec_in_enq(const odp_ipsec_op_param_t *input)
{
	(void)input;

	return -1;
}

int odp_ipsec_out_enq(const odp_ipsec_op_param_t *input)
{
	(void)input;

	return -1;
}

int odp_ipsec_out_inline(const odp_ipsec_op_param_t *op_param,
			 const odp_ipsec_inline_op_param_t *inline_param)
{
	(void)op_param;
	(void)inline_param;

	return -1;
}

int odp_ipsec_result(odp_ipsec_op_result_t *result, odp_event_t event)
{
	(void)result;
	(void)event;

	return -1;
}

int odp_ipsec_status(odp_ipsec_status_t *status, odp_event_t event)
{
	(void)status;
	(void)event;

	return -1;
}

int odp_ipsec_mtu_update(odp_ipsec_sa_t sa, uint32_t mtu)
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

uint64_t odp_ipsec_sa_to_u64(odp_ipsec_sa_t sa)
{
	return _odp_pri(sa);
}

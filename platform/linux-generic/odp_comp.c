/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include "config.h"

#include <string.h>

#include <odp/api/comp.h>
#include <odp/api/event.h>
#include <odp/api/packet.h>
#include <odp/api/plat/strong_types.h>

#include <odp_debug_internal.h>

void odp_comp_session_param_init(odp_comp_session_param_t *param)
{
	memset(param, 0, sizeof(odp_comp_session_param_t));
}

odp_comp_session_t
odp_comp_session_create(const odp_comp_session_param_t *params)
{
	(void)params;
	return ODP_COMP_SESSION_INVALID;
}

int odp_comp_session_destroy(odp_comp_session_t session)
{
	(void)session;
	return 0;
}

int odp_comp_capability(odp_comp_capability_t *capa)
{
	if (NULL == capa)
		return -1;

	/* Initialize comp capability structure */
	memset(capa, 0, sizeof(odp_comp_capability_t));

	capa->comp_algos.bit.null = 0;
	capa->hash_algos.bit.none = 0;
	capa->sync = ODP_SUPPORT_NO;
	capa->async = ODP_SUPPORT_NO;
	capa->max_sessions = 0;

	return 0;
}

int
odp_comp_alg_capability(odp_comp_alg_t comp,
			odp_comp_alg_capability_t *capa)
{
	(void)capa;
	switch (comp) {
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
	default:
		return -1;
	}
	return -1;
}

int odp_comp_op(const odp_packet_t pkt_in[], odp_packet_t pkt_out[],
		int num_pkt, const odp_comp_packet_op_param_t param[])
{
	(void)pkt_in;
	(void)pkt_out;
	(void)num_pkt;
	(void)param;

	return -1;
}

int odp_comp_op_enq(const odp_packet_t pkt_in[], odp_packet_t pkt_out[],
		    int num_pkt, const odp_comp_packet_op_param_t param[])
{
	(void)pkt_in;
	(void)pkt_out;
	(void)num_pkt;
	(void)param;

	return -1;
}

int odp_comp_result(odp_comp_packet_result_t *result,
		    odp_packet_t packet)
{
	(void)result;
	(void)packet;
	return 0;
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

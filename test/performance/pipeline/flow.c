/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <odp/helper/odph_api.h>

#include "flow.h"

typedef struct {
	work_t *work;
	uint32_t num;
	odp_bool_t is_set;
} flow_sub_t;

typedef struct ODP_ALIGNED_CACHE {
	char *queue;
	flow_sub_t sub[2U];
} flow_priv_t;

flow_t flow_create_flow(char *queue)
{
	flow_priv_t *flow = calloc(1U, sizeof(*flow));

	if (flow == NULL)
		ODPH_ABORT("Error allocating memory, aborting\n");

	flow->queue = queue;

	return (flow_t)flow;
}

odp_bool_t flow_add_input(flow_t flow,  work_t *work, uint32_t num)
{
	flow_sub_t *sub = &((flow_priv_t *)flow)->sub[F_IN];

	if (sub->is_set)
		return false;

	sub->work = work;
	sub->num = num;
	sub->is_set = true;

	return true;
}

odp_bool_t flow_add_output(flow_t flow,  work_t *work, uint32_t num)
{
	flow_sub_t *sub = &((flow_priv_t *)flow)->sub[F_OUT];

	if (sub->is_set)
		return false;

	sub->work = work;
	sub->num = num;
	sub->is_set = true;

	return true;
}

int flow_issue(flow_type_t type, flow_t flow, odp_event_t ev[], int num)
{
	flow_sub_t *sub = &((flow_priv_t *)flow)->sub[type];
	int num_procd = 0;

	for (uint32_t i = 0U; i < sub->num; ++i) {
		num_procd += work_issue(sub->work[i], &ev[num_procd], num - num_procd);

		if (num_procd == num)
			break;
	}

	return num_procd;
}

void flow_destroy_flow(flow_t flow)
{
	flow_priv_t *priv = (flow_priv_t *)flow;
	work_t work;

	if (priv == NULL)
		return;

	for (uint32_t i = 0U; i < priv->sub[F_IN].num; ++i) {
		work = priv->sub[F_IN].work[i];
		work_print_work(work, priv->queue);
		work_destroy_work(work);
	}

	for (uint32_t i = 0U; i < priv->sub[F_OUT].num; ++i) {
		work = priv->sub[F_OUT].work[i];
		work_print_work(work, priv->queue);
		work_destroy_work(work);
	}

	free(priv->queue);
}

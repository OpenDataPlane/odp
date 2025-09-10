/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2023-2025 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include <odp_cunit_common.h>

#include "event_vector.h"

#define NUM_EVENTS  100
#define EVENT_SIZE  100
#define EVENT_BURST 10
#define MAX_EVENT_TYPES 7

typedef struct {
	struct {
		odp_event_type_t event_type;
		odp_pool_type_t pool_type;
		odp_pool_t pool;
		odp_event_t events[EVENT_BURST];
	} type[MAX_EVENT_TYPES];
	int num_types;
	uint32_t max_flow_id;
	odp_queue_t queue;
} event_type_ctx_t;

static event_type_ctx_t g_type_ctx;

static int pool_index_of(odp_pool_type_t type)
{
	event_type_ctx_t *ctx = &g_type_ctx;

	for (int i = 0; i < ctx->num_types; i++) {
		if (ctx->type[i].pool_type == type)
			return i;
	}

	return -1;
}

static odp_event_t event_types_alloc_event(odp_pool_type_t pool_type)
{
	event_type_ctx_t *ctx = &g_type_ctx;
	int idx = pool_index_of(pool_type);
	odp_buffer_t buf;
	odp_packet_t pkt;
	odp_timeout_t tmo;
	odp_event_vector_t evv;
	odp_packet_vector_t pv;
	odp_dma_compl_t dma_compl;
	odp_ml_compl_t ml_compl;

	if (idx < 0)
		return ODP_EVENT_INVALID;

	switch (pool_type) {
	case ODP_POOL_BUFFER:
		buf = odp_buffer_alloc(ctx->type[idx].pool);
		if (buf == ODP_BUFFER_INVALID)
			return ODP_EVENT_INVALID;
		return odp_buffer_to_event(buf);
	case ODP_POOL_PACKET:
		pkt = odp_packet_alloc(ctx->type[idx].pool, EVENT_SIZE);
		if (pkt == ODP_PACKET_INVALID)
			return ODP_EVENT_INVALID;
		return odp_packet_to_event(pkt);
	case ODP_POOL_TIMEOUT:
		tmo = odp_timeout_alloc(ctx->type[idx].pool);
		if (tmo == ODP_TIMEOUT_INVALID)
			return ODP_EVENT_INVALID;
		return odp_timeout_to_event(tmo);
	case ODP_POOL_EVENT_VECTOR:
		evv = odp_event_vector_alloc(ctx->type[idx].pool);
		if (evv == ODP_EVENT_VECTOR_INVALID)
			return ODP_EVENT_INVALID;
		return odp_event_vector_to_event(evv);
	case ODP_POOL_VECTOR:
		pv = odp_packet_vector_alloc(ctx->type[idx].pool);
		if (pv == ODP_PACKET_VECTOR_INVALID)
			return ODP_EVENT_INVALID;
		return odp_packet_vector_to_event(pv);
	case ODP_POOL_DMA_COMPL:
		dma_compl = odp_dma_compl_alloc(ctx->type[idx].pool);
		if (dma_compl == ODP_DMA_COMPL_INVALID)
			return ODP_EVENT_INVALID;
		return odp_dma_compl_to_event(dma_compl);
	case ODP_POOL_ML_COMPL:
		ml_compl = odp_ml_compl_alloc(ctx->type[idx].pool);
		if (ml_compl == ODP_ML_COMPL_INVALID)
			return ODP_EVENT_INVALID;
		return odp_ml_compl_to_event(ml_compl);
	default:
		return ODP_EVENT_INVALID;
	}
}

static int event_init_global(odp_instance_t *inst)
{
	odp_init_t init_param;
	odph_helper_options_t helper_options;
	odp_schedule_capability_t sched_capa;
	odp_schedule_config_t sched_conf;

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

	if (0 != odp_init_local(*inst, ODP_THREAD_WORKER)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	if (0 != odp_schedule_capability(&sched_capa))
		return -1;

	odp_schedule_config_init(&sched_conf);
	sched_conf.max_flow_id = ODPH_MIN(1U, sched_capa.max_flow_id);

	if (0 != odp_schedule_config(&sched_conf)) {
		fprintf(stderr, "error: odp_schedule_config() failed.\n");
		return -1;
	}

	g_type_ctx.max_flow_id = sched_conf.max_flow_id;

	return 0;
}

static int event_types_suite_init(void)
{
	event_type_ctx_t *ctx = &g_type_ctx;
	int i, j, n = 0;
	char name[ODP_POOL_NAME_LEN];
	odp_queue_capability_t queue_capa;
	odp_queue_param_t queue_prm;
	odp_pool_capability_t p_capa;
	odp_dma_capability_t dma_capa;
	odp_ml_capability_t ml_capa;

	if (odp_queue_capability(&queue_capa) != 0)
		return -1;

	if (queue_capa.plain.max_size < MAX_EVENT_TYPES * EVENT_BURST)
		return -1;

	odp_queue_param_init(&queue_prm);
	queue_prm.type = ODP_QUEUE_TYPE_PLAIN;
	queue_prm.size = MAX_EVENT_TYPES * EVENT_BURST;

	ctx->queue = odp_queue_create("event_types_queue", &queue_prm);
	if (ctx->queue == ODP_QUEUE_INVALID)
		return -1;

	if (odp_pool_capability(&p_capa) != 0)
		return -1;

	if (odp_dma_capability(&dma_capa) != 0)
		return -1;

	if (odp_ml_capability(&ml_capa) != 0)
		return -1;

	ctx->type[n].event_type = ODP_EVENT_BUFFER;
	ctx->type[n++].pool_type = ODP_POOL_BUFFER;

	ctx->type[n].event_type = ODP_EVENT_PACKET;
	ctx->type[n++].pool_type = ODP_POOL_PACKET;

	ctx->type[n].event_type = ODP_EVENT_TIMEOUT;
	ctx->type[n++].pool_type = ODP_POOL_TIMEOUT;

	if (p_capa.event_vector.max_num > 0) {
		ctx->type[n].event_type = ODP_EVENT_VECTOR;
		ctx->type[n++].pool_type = ODP_POOL_EVENT_VECTOR;
	}

	if (p_capa.vector.max_num > 0) {
		ctx->type[n].event_type = ODP_EVENT_PACKET_VECTOR;
		ctx->type[n++].pool_type = ODP_POOL_VECTOR;
	}

	if (dma_capa.max_sessions && (dma_capa.compl_mode_mask & ODP_DMA_COMPL_EVENT) &&
	    dma_capa.pool.max_num > 0) {
		ctx->type[n].event_type = ODP_EVENT_DMA_COMPL;
		ctx->type[n++].pool_type = ODP_POOL_DMA_COMPL;
	}

	if (ml_capa.max_models &&
	    ((ml_capa.load.compl_mode_mask | ml_capa.run.compl_mode_mask) &
	    ODP_ML_COMPL_MODE_EVENT) && ml_capa.pool.max_num > 0) {
		ctx->type[n].event_type = ODP_EVENT_ML_COMPL;
		ctx->type[n++].pool_type = ODP_POOL_ML_COMPL;
	}

	ctx->num_types = n;

	for (i = 0; i < ctx->num_types; i++) {
		odp_pool_param_t prm;
		odp_dma_pool_param_t dma_prm;
		odp_ml_compl_pool_param_t ml_prm;

		odp_pool_param_init(&prm);

		prm.type = ctx->type[i].pool_type;
		switch (ctx->type[i].pool_type) {
		case ODP_POOL_BUFFER:
			prm.buf.num = NUM_EVENTS;
			prm.buf.size = EVENT_SIZE;
			prm.buf.uarea_size = ODPH_MIN(sizeof(uint64_t), p_capa.buf.max_uarea_size);
		break;
		case ODP_POOL_PACKET:
			prm.pkt.num = NUM_EVENTS;
			prm.pkt.len = EVENT_SIZE;
			prm.pkt.uarea_size = ODPH_MIN(sizeof(uint64_t), p_capa.pkt.max_uarea_size);
		break;
		case ODP_POOL_TIMEOUT:
			prm.tmo.num = NUM_EVENTS;
			prm.tmo.uarea_size = ODPH_MIN(sizeof(uint64_t), p_capa.tmo.max_uarea_size);
		break;
		case ODP_POOL_EVENT_VECTOR:
			prm.event_vector.num = NUM_EVENTS;
			prm.event_vector.max_size = 1;
			prm.event_vector.uarea_size = ODPH_MIN(sizeof(uint64_t),
							       p_capa.event_vector.max_uarea_size);
		break;
		case ODP_POOL_VECTOR:
			prm.vector.num = NUM_EVENTS;
			prm.vector.max_size = 1;
			prm.vector.uarea_size = ODPH_MIN(sizeof(uint64_t),
							 p_capa.vector.max_uarea_size);
		break;
		case ODP_POOL_DMA_COMPL:
			odp_dma_pool_param_init(&dma_prm);
			dma_prm.num = NUM_EVENTS;
			dma_prm.uarea_size = ODPH_MIN(sizeof(uint64_t),
						      dma_capa.pool.max_uarea_size);
		break;
		case ODP_POOL_ML_COMPL:
			odp_ml_compl_pool_param_init(&ml_prm);
			ml_prm.num = NUM_EVENTS;
			ml_prm.uarea_size = ODPH_MIN(sizeof(uint64_t),
						     ml_capa.pool.max_uarea_size);
		break;
		}

		snprintf(name, ODP_POOL_NAME_LEN, "event_type_compliance_%d", i);

		if (ctx->type[i].pool_type == ODP_POOL_DMA_COMPL)
			ctx->type[i].pool = odp_dma_pool_create(name, &dma_prm);
		else if (ctx->type[i].pool_type == ODP_POOL_ML_COMPL)
			ctx->type[i].pool = odp_ml_compl_pool_create(name, &ml_prm);
		else
			ctx->type[i].pool = odp_pool_create(name, &prm);

		if (ctx->type[i].pool == ODP_POOL_INVALID)
			return -1;

		for (j = 0; j < EVENT_BURST; j++) {
			ctx->type[i].events[j] = event_types_alloc_event(ctx->type[i].pool_type);
			if (ctx->type[i].events[j] == ODP_EVENT_INVALID)
				return -1;
		}
	}

	return 0;
}

static int event_types_suite_term(void)
{
	event_type_ctx_t *ctx = &g_type_ctx;
	int i, ret = 0;

	if (odp_queue_destroy(ctx->queue))
		ret = -1;

	for (i = 0; i < ctx->num_types; i++) {
		odp_event_free_multi(ctx->type[i].events, EVENT_BURST);
		if (odp_pool_destroy(ctx->type[i].pool))
			ret = -1;
		ctx->type[i].pool = ODP_POOL_INVALID;
	}

	return ret;
}

static void event_test_types_and_subtypes(void)
{
	event_type_ctx_t *ctx = &g_type_ctx;
	odp_event_type_t exp_type;
	odp_event_type_t type;
	odp_event_type_t types_out[EVENT_BURST];
	odp_event_subtype_t exp_sub;
	odp_event_subtype_t sub;
	odp_event_subtype_t subs_out[EVENT_BURST];
	odp_event_t ev;
	odp_event_t events[MAX_EVENT_TYPES];
	int i, j, idx;

	for (i = 0; i < ctx->num_types; i++) {
		exp_type = ctx->type[i].event_type;
		exp_sub = (exp_type == ODP_EVENT_PACKET) ? ODP_EVENT_PACKET_BASIC
							 : ODP_EVENT_NO_SUBTYPE;

		for (j = 0; j < EVENT_BURST; j++) {
			ev = ctx->type[i].events[j];

			CU_ASSERT(odp_event_type(ev) == exp_type);
			CU_ASSERT(odp_event_subtype(ev) == exp_sub);

			CU_ASSERT(odp_event_types(ev, &sub) == exp_type);
			CU_ASSERT(sub == exp_sub);
		}

		odp_event_types_multi(ctx->type[i].events, types_out, subs_out, EVENT_BURST);
		for (j = 0; j < EVENT_BURST; j++) {
			CU_ASSERT(types_out[j] == exp_type);
			CU_ASSERT(subs_out[j] == exp_sub);
		}

		for (j = 0; j < EVENT_BURST; j++)
			types_out[j] = ODP_EVENT_ANY;

		odp_event_types_multi(ctx->type[i].events, types_out, NULL, EVENT_BURST);
		for (j = 0; j < EVENT_BURST; j++)
			CU_ASSERT(types_out[j] == exp_type);

		CU_ASSERT(odp_event_type_multi(ctx->type[i].events, EVENT_BURST, &type)
			  == EVENT_BURST);
		CU_ASSERT(type == exp_type);

		/* Fill array with another event type */
		idx = (i + 1) % ctx->num_types;
		for (j = 0; j < ctx->num_types; j++)
			events[j] = ctx->type[idx].events[j];

		/* Increment the number of same type events at the beginning of the array by one */
		for (j = 0; j < ctx->num_types; j++) {
			events[j] = ctx->type[i].events[j];
			CU_ASSERT(odp_event_type_multi(events, ctx->num_types, &type) == j + 1);
			CU_ASSERT(type == ctx->type[i].event_type);
		}
	}
}

static void event_test_pool(void)
{
	event_type_ctx_t *ctx = &g_type_ctx;
	odp_event_t ev;
	odp_event_type_t exp_type;
	odp_pool_t ev_pool;
	int i, j;

	for (i = 0; i < ctx->num_types; i++) {
		for (j = 0; j < EVENT_BURST; j++) {
			ev = ctx->type[i].events[j];
			exp_type = ctx->type[i].event_type;
			ev_pool = odp_event_pool(ev);

			if (exp_type == ODP_EVENT_TIMEOUT ||
			    exp_type == ODP_EVENT_DMA_COMPL ||
			    exp_type == ODP_EVENT_ML_COMPL)
				CU_ASSERT(ev_pool == ODP_POOL_INVALID);
			else
				CU_ASSERT(ev_pool == ctx->type[i].pool);
		}
	}
}

static void event_test_user_area_flag(void)
{
	event_type_ctx_t *ctx = &g_type_ctx;
	odp_event_t ev;
	int i, j, flag;
	void *user_area;

	for (i = 0; i < ctx->num_types; i++) {
		for (j = 0; j < EVENT_BURST; j++) {
			ev = ctx->type[i].events[j];
			user_area = odp_event_user_area(ev);

			CU_ASSERT(user_area != NULL);

			flag = 0;
			odp_event_user_flag_set(ev, 1);
			user_area = odp_event_user_area_and_flag(ev, &flag);

			CU_ASSERT(user_area != NULL);

			switch (ctx->type[i].event_type) {
			case ODP_EVENT_BUFFER:
			case ODP_EVENT_TIMEOUT:
			case ODP_EVENT_DMA_COMPL:
			case ODP_EVENT_ML_COMPL:
				CU_ASSERT(flag < 0);
				break;
			case ODP_EVENT_PACKET:
			case ODP_EVENT_VECTOR:
			case ODP_EVENT_PACKET_VECTOR:
				CU_ASSERT(flag > 0);
				break;
			default:
				CU_ASSERT(flag != 0);
			}
		}
	}
}

static void event_test_debug(void)
{
	event_type_ctx_t *ctx = &g_type_ctx;
	odp_event_t ev;
	int i, j, k, idx;
	uint64_t event_ids[MAX_EVENT_TYPES * EVENT_BURST];
	uint64_t event_id;

	for (i = 0; i < ctx->num_types; i++) {
		for (j = 0; j < EVENT_BURST; j++) {
			ev = ctx->type[i].events[j];
			CU_ASSERT(odp_event_is_valid(ev) == 1);

			/* Individual events should return unique u64 values */
			idx = i * EVENT_BURST + j;
			event_id = odp_event_to_u64(ev);

			for (k = 0; k < idx; k++)
				CU_ASSERT(event_ids[k] != event_id);

			event_ids[idx] = event_id;
		}
	}
}

static void event_test_flow_id(void)
{
	event_type_ctx_t *ctx = &g_type_ctx;
	odp_event_t ev;
	int i, j;

	for (i = 0; i < ctx->num_types; i++) {
		for (j = 0; j < EVENT_BURST; j++) {
			ev = ctx->type[i].events[j];
			CU_ASSERT(odp_event_flow_id(ev) == 0);

			if (ctx->max_flow_id > 0) {
				odp_event_flow_id_set(ev, 1);
				CU_ASSERT(odp_event_flow_id(ev) == 1);
			}
		}
	}
}

static void event_test_types_filter_packets(void)
{
	event_type_ctx_t *ctx = &g_type_ctx;

	odp_event_t mixed[MAX_EVENT_TYPES * EVENT_BURST];
	odp_packet_t packets[MAX_EVENT_TYPES * EVENT_BURST];
	odp_event_t remain[MAX_EVENT_TYPES * EVENT_BURST];
	odp_event_t expected[MAX_EVENT_TYPES * EVENT_BURST];
	uint64_t event_u64_1;
	uint64_t event_u64_2;

	int num_pkt, num_rem, idx = 0, exp_idx = 0;
	int pkt_idx = pool_index_of(ODP_POOL_PACKET);

	CU_ASSERT_FATAL(pkt_idx >= 0);

	/* Build mixed array and non-packet array */
	for (int i = 0; i < EVENT_BURST; i++) {
		for (int j = 0; j < ctx->num_types; j++) {
			mixed[idx++] = ctx->type[j].events[i];

			if (j != pkt_idx)
				expected[exp_idx++] = ctx->type[j].events[i];
		}
	}

	num_pkt = odp_event_filter_packet(mixed, packets, remain, idx);
	num_rem = idx - num_pkt;

	/* Verify packet count and order */
	CU_ASSERT(num_pkt == EVENT_BURST);
	for (int i = 0; i < num_pkt; i++) {
		CU_ASSERT_FATAL(packets[i] != ODP_PACKET_INVALID);

		event_u64_1 = odp_event_to_u64(odp_packet_to_event(packets[i]));
		event_u64_2 = odp_event_to_u64(ctx->type[pkt_idx].events[i]);
		CU_ASSERT(event_u64_1 == event_u64_2);
	}

	/* Verify remaining events count and order */
	CU_ASSERT(num_rem == exp_idx);
	for (int i = 0; i < num_rem; i++) {
		event_u64_1 = odp_event_to_u64(remain[i]);
		event_u64_2 = odp_event_to_u64(expected[i]);
		CU_ASSERT(event_u64_1 == event_u64_2);
	}
}

static void event_test_event_frees(void)
{
	event_type_ctx_t *ctx = &g_type_ctx;
	odp_event_t sorted_events_multi[EVENT_BURST];
	odp_event_t mixed_events_single[MAX_EVENT_TYPES];
	odp_event_t mixed_events_multi[MAX_EVENT_TYPES];
	int i, j;

	for (i = 0; i < ctx->num_types; i++) {
		for (j = 0; j < EVENT_BURST; j++) {
			sorted_events_multi[j] = event_types_alloc_event(ctx->type[i].pool_type);
			CU_ASSERT_FATAL(sorted_events_multi[j] != ODP_EVENT_INVALID);
		}

		odp_event_free_sp(sorted_events_multi, EVENT_BURST);
	}

	for (i = 0; i < ctx->num_types; i++) {
		mixed_events_single[i] = event_types_alloc_event(ctx->type[i].pool_type);
		mixed_events_multi[i] = event_types_alloc_event(ctx->type[i].pool_type);
		CU_ASSERT_FATAL(mixed_events_single[i] != ODP_EVENT_INVALID);
		CU_ASSERT_FATAL(mixed_events_multi[i] != ODP_EVENT_INVALID);
	}

	for (i = 0; i < ctx->num_types; i++)
		odp_event_free(mixed_events_single[i]);

	odp_event_free_multi(mixed_events_multi, ctx->num_types);
}

static void event_test_queue_enq_deq(void)
{
	event_type_ctx_t *ctx = &g_type_ctx;
	odp_event_t ev;
	odp_event_t ev_tbl[MAX_EVENT_TYPES];
	odp_event_type_t types_seen[MAX_EVENT_TYPES] = {0};
	odp_event_type_t ev_type;
	int i, num, total = 0;

	for (i = 0; i < ctx->num_types; i++) {
		ev = ctx->type[i].events[0];
		CU_ASSERT(odp_queue_enq(ctx->queue, ev) == 0);
	}

	while (1) {
		ev = odp_queue_deq(ctx->queue);
		if (ev == ODP_EVENT_INVALID)
			break;

		ev_type = odp_event_type(ev);
		for (i = 0; i < ctx->num_types; i++)
			if (ctx->type[i].event_type == ev_type)
				types_seen[i]++;
		total++;
	}

	CU_ASSERT(total == ctx->num_types);
	for (i = 0; i < ctx->num_types; i++)
		CU_ASSERT(types_seen[i] == 1);

	for (i = 0; i < ctx->num_types; i++)
		ev_tbl[i] = ctx->type[i].events[1];

	num = 1;
	total = 0;
	while (num > 0 && total < ctx->num_types) {
		num = odp_queue_enq_multi(ctx->queue, &ev_tbl[total], ctx->num_types - total);
		CU_ASSERT_FATAL(num >= 0);
		total += num;
	}

	CU_ASSERT(total == ctx->num_types);

	memset(types_seen, 0, sizeof(types_seen));
	total = 0;
	while (1) {
		num = odp_queue_deq_multi(ctx->queue, ev_tbl, ctx->num_types);
		if (num <= 0)
			break;

		for (i = 0; i < num; i++) {
			ev_type = odp_event_type(ev_tbl[i]);
			for (int j = 0; j < ctx->num_types; j++)
				if (ctx->type[j].event_type == ev_type)
					types_seen[j]++;
			total++;
		}
	}

	CU_ASSERT(total == ctx->num_types);
	for (i = 0; i < ctx->num_types; i++)
		CU_ASSERT(types_seen[i] == 1);
}

static void event_test_free(void)
{
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	int i;
	odp_buffer_t buf;
	odp_packet_t pkt;
	odp_timeout_t tmo;
	odp_event_subtype_t subtype = ODP_EVENT_PACKET_BASIC;
	odp_event_t event[EVENT_BURST];

	/* Buffer events */
	odp_pool_param_init(&pool_param);
	pool_param.buf.num  = NUM_EVENTS;
	pool_param.buf.size = EVENT_SIZE;
	pool_param.type     = ODP_POOL_BUFFER;

	pool = odp_pool_create("event_free", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < EVENT_BURST; i++) {
		buf = odp_buffer_alloc(pool);
		CU_ASSERT(odp_event_is_valid(odp_buffer_to_event(buf)) == 1);
		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
		event[i] = odp_buffer_to_event(buf);
		CU_ASSERT(odp_event_type(event[i]) == ODP_EVENT_BUFFER);
		CU_ASSERT(odp_event_subtype(event[i]) == ODP_EVENT_NO_SUBTYPE);
		CU_ASSERT(odp_event_types(event[i], &subtype) ==
			  ODP_EVENT_BUFFER);
		CU_ASSERT(subtype == ODP_EVENT_NO_SUBTYPE);
	}

	for (i = 0; i < EVENT_BURST; i++)
		odp_event_free(event[i]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);

	/* Packet events */
	odp_pool_param_init(&pool_param);
	pool_param.pkt.num = NUM_EVENTS;
	pool_param.pkt.len = EVENT_SIZE;
	pool_param.type    = ODP_POOL_PACKET;

	pool = odp_pool_create("event_free", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < EVENT_BURST; i++) {
		pkt = odp_packet_alloc(pool, EVENT_SIZE);
		CU_ASSERT(odp_event_is_valid(odp_packet_to_event(pkt)) == 1);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		event[i] = odp_packet_to_event(pkt);
		CU_ASSERT(odp_event_type(event[i]) == ODP_EVENT_PACKET);
		CU_ASSERT(odp_event_subtype(event[i]) ==
			  ODP_EVENT_PACKET_BASIC);
		CU_ASSERT(odp_event_types(event[i], &subtype) ==
			  ODP_EVENT_PACKET);
		CU_ASSERT(subtype == ODP_EVENT_PACKET_BASIC);
	}

	for (i = 0; i < EVENT_BURST; i++)
		odp_event_free(event[i]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);

	/* Timeout events */
	odp_pool_param_init(&pool_param);
	pool_param.tmo.num = NUM_EVENTS;
	pool_param.type    = ODP_POOL_TIMEOUT;

	pool = odp_pool_create("event_free", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < EVENT_BURST; i++) {
		tmo = odp_timeout_alloc(pool);
		CU_ASSERT(odp_event_is_valid(odp_timeout_to_event(tmo)) == 1);
		CU_ASSERT_FATAL(tmo != ODP_TIMEOUT_INVALID);
		event[i] = odp_timeout_to_event(tmo);
		CU_ASSERT(odp_event_type(event[i]) == ODP_EVENT_TIMEOUT);
		CU_ASSERT(odp_event_subtype(event[i]) == ODP_EVENT_NO_SUBTYPE);
		CU_ASSERT(odp_event_types(event[i], &subtype) ==
			  ODP_EVENT_TIMEOUT);
		CU_ASSERT(subtype == ODP_EVENT_NO_SUBTYPE);
	}

	for (i = 0; i < EVENT_BURST; i++)
		odp_event_free(event[i]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void event_test_free_multi(void)
{
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	int i, j;
	odp_buffer_t buf;
	odp_packet_t pkt;
	odp_timeout_t tmo;
	odp_event_t event[EVENT_BURST];

	/* Buffer events */
	odp_pool_param_init(&pool_param);
	pool_param.buf.num  = NUM_EVENTS;
	pool_param.buf.size = EVENT_SIZE;
	pool_param.type     = ODP_POOL_BUFFER;

	pool = odp_pool_create("event_free", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (j = 0; j < 2; j++) {
		for (i = 0; i < EVENT_BURST; i++) {
			buf = odp_buffer_alloc(pool);
			CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
			event[i] = odp_buffer_to_event(buf);
		}

		if (j == 0)
			odp_event_free_multi(event, EVENT_BURST);
		else
			odp_event_free_sp(event, EVENT_BURST);
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);

	/* Packet events */
	odp_pool_param_init(&pool_param);
	pool_param.pkt.num = NUM_EVENTS;
	pool_param.pkt.len = EVENT_SIZE;
	pool_param.type    = ODP_POOL_PACKET;

	pool = odp_pool_create("event_free", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (j = 0; j < 2; j++) {
		for (i = 0; i < EVENT_BURST; i++) {
			pkt = odp_packet_alloc(pool, EVENT_SIZE);
			CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
			event[i] = odp_packet_to_event(pkt);
		}

		if (j == 0)
			odp_event_free_multi(event, EVENT_BURST);
		else
			odp_event_free_sp(event, EVENT_BURST);
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);

	/* Timeout events */
	odp_pool_param_init(&pool_param);
	pool_param.tmo.num = NUM_EVENTS;
	pool_param.type    = ODP_POOL_TIMEOUT;

	pool = odp_pool_create("event_free", &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (j = 0; j < 2; j++) {
		for (i = 0; i < EVENT_BURST; i++) {
			tmo = odp_timeout_alloc(pool);
			CU_ASSERT_FATAL(tmo != ODP_TIMEOUT_INVALID);
			event[i] = odp_timeout_to_event(tmo);
		}

		if (j == 0)
			odp_event_free_multi(event, EVENT_BURST);
		else
			odp_event_free_sp(event, EVENT_BURST);
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void event_test_free_multi_mixed(void)
{
	odp_pool_t pool1, pool2, pool3;
	odp_pool_param_t pool_param;
	int i, j;
	odp_buffer_t buf;
	odp_packet_t pkt;
	odp_timeout_t tmo;
	odp_event_t event[3 * EVENT_BURST];

	/* Buffer events */
	odp_pool_param_init(&pool_param);
	pool_param.buf.num  = NUM_EVENTS;
	pool_param.buf.size = EVENT_SIZE;
	pool_param.type     = ODP_POOL_BUFFER;

	pool1 = odp_pool_create("event_free1", &pool_param);
	CU_ASSERT_FATAL(pool1 != ODP_POOL_INVALID);

	/* Packet events */
	odp_pool_param_init(&pool_param);
	pool_param.pkt.num = NUM_EVENTS;
	pool_param.pkt.len = EVENT_SIZE;
	pool_param.type    = ODP_POOL_PACKET;

	pool2 = odp_pool_create("event_free2", &pool_param);
	CU_ASSERT_FATAL(pool2 != ODP_POOL_INVALID);

	/* Timeout events */
	odp_pool_param_init(&pool_param);
	pool_param.tmo.num = NUM_EVENTS;
	pool_param.type    = ODP_POOL_TIMEOUT;

	pool3 = odp_pool_create("event_free3", &pool_param);
	CU_ASSERT_FATAL(pool3 != ODP_POOL_INVALID);

	for (j = 0; j < 2; j++) {
		for (i = 0; i < 3 * EVENT_BURST;) {
			buf = odp_buffer_alloc(pool1);
			CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
			event[i] = odp_buffer_to_event(buf);
			i++;
			pkt = odp_packet_alloc(pool2, EVENT_SIZE);
			CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
			event[i] = odp_packet_to_event(pkt);
			i++;
			tmo = odp_timeout_alloc(pool3);
			CU_ASSERT_FATAL(tmo != ODP_TIMEOUT_INVALID);
			event[i] = odp_timeout_to_event(tmo);
			i++;
		}
		odp_event_free_multi(event, 3 * EVENT_BURST);
	}

	CU_ASSERT(odp_pool_destroy(pool1) == 0);
	CU_ASSERT(odp_pool_destroy(pool2) == 0);
	CU_ASSERT(odp_pool_destroy(pool3) == 0);
}

#define NUM_TYPE_TEST 6

static void type_test_init(odp_pool_t *buf_pool, odp_pool_t *pkt_pool,
			   odp_event_t buf_event[],
			   odp_event_t pkt_event[],
			   odp_event_t event[])
{
	odp_pool_t pool1, pool2;
	odp_pool_param_t pool_param;
	int i;
	odp_buffer_t buf;
	odp_packet_t pkt;

	/* Buffer events */
	odp_pool_param_init(&pool_param);
	pool_param.buf.num  = NUM_EVENTS;
	pool_param.buf.size = EVENT_SIZE;
	pool_param.type     = ODP_POOL_BUFFER;

	pool1 = odp_pool_create("event_type_buf", &pool_param);
	CU_ASSERT_FATAL(pool1 != ODP_POOL_INVALID);

	for (i = 0; i < NUM_TYPE_TEST; i++) {
		buf = odp_buffer_alloc(pool1);
		CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
		buf_event[i] = odp_buffer_to_event(buf);
	}

	/* Packet events */
	odp_pool_param_init(&pool_param);
	pool_param.pkt.num = NUM_EVENTS;
	pool_param.pkt.len = EVENT_SIZE;
	pool_param.type    = ODP_POOL_PACKET;

	pool2 = odp_pool_create("event_type_pkt", &pool_param);
	CU_ASSERT_FATAL(pool2 != ODP_POOL_INVALID);

	for (i = 0; i < NUM_TYPE_TEST; i++) {
		pkt = odp_packet_alloc(pool2, EVENT_SIZE);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		pkt_event[i] = odp_packet_to_event(pkt);
	}

	/* 1 buf, 1 pkt, 2 buf, 2 pkt, 3 buf, 3 pkt */
	event[0]  = buf_event[0];
	event[1]  = pkt_event[0];
	event[2]  = buf_event[1];
	event[3]  = buf_event[2];
	event[4]  = pkt_event[1];
	event[5]  = pkt_event[2];
	event[6]  = buf_event[3];
	event[7]  = buf_event[4];
	event[8]  = buf_event[5];
	event[9]  = pkt_event[3];
	event[10] = pkt_event[4];
	event[11] = pkt_event[5];

	*buf_pool = pool1;
	*pkt_pool = pool2;
}

static void event_test_type_multi(void)
{
	odp_pool_t buf_pool, pkt_pool;
	odp_event_type_t type = ODP_EVENT_PACKET;
	int num;
	odp_event_t buf_event[NUM_TYPE_TEST];
	odp_event_t pkt_event[NUM_TYPE_TEST];
	odp_event_t event[2 * NUM_TYPE_TEST];

	type_test_init(&buf_pool, &pkt_pool, buf_event, pkt_event, event);

	num = odp_event_type_multi(&event[0], 12, &type);
	CU_ASSERT(num == 1);
	CU_ASSERT(type == ODP_EVENT_BUFFER);

	num = odp_event_type_multi(&event[1], 11, &type);
	CU_ASSERT(num == 1);
	CU_ASSERT(type == ODP_EVENT_PACKET);

	num = odp_event_type_multi(&event[2], 10, &type);
	CU_ASSERT(num == 2);
	CU_ASSERT(type == ODP_EVENT_BUFFER);

	num = odp_event_type_multi(&event[4], 8, &type);
	CU_ASSERT(num == 2);
	CU_ASSERT(type == ODP_EVENT_PACKET);

	num = odp_event_type_multi(&event[6], 6, &type);
	CU_ASSERT(num == 3);
	CU_ASSERT(type == ODP_EVENT_BUFFER);

	num = odp_event_type_multi(&event[9], 3, &type);
	CU_ASSERT(num == 3);
	CU_ASSERT(type == ODP_EVENT_PACKET);

	odp_event_free_multi(buf_event, NUM_TYPE_TEST);
	odp_event_free_multi(pkt_event, NUM_TYPE_TEST);

	CU_ASSERT(odp_pool_destroy(buf_pool) == 0);
	CU_ASSERT(odp_pool_destroy(pkt_pool) == 0);
}

static void event_test_types_multi(void)
{
	odp_pool_t buf_pool, pkt_pool;
	odp_event_t buf_event[NUM_TYPE_TEST];
	odp_event_t pkt_event[NUM_TYPE_TEST];
	odp_event_t event[2 * NUM_TYPE_TEST];
	odp_event_type_t event_types[2 * NUM_TYPE_TEST] = {ODP_EVENT_PACKET};
	odp_event_subtype_t event_subtypes[2 * NUM_TYPE_TEST];
	int i;

	type_test_init(&buf_pool, &pkt_pool, buf_event, pkt_event, event);

	/* Only buffers */
	odp_event_types_multi(buf_event, event_types, event_subtypes, NUM_TYPE_TEST);
	for (i = 0; i < NUM_TYPE_TEST; i++) {
		CU_ASSERT(event_types[i] == ODP_EVENT_BUFFER);
		CU_ASSERT(event_subtypes[i] == ODP_EVENT_NO_SUBTYPE);
	}

	/* Only packets */
	odp_event_types_multi(pkt_event, event_types, event_subtypes, NUM_TYPE_TEST);
	for (i = 0; i < NUM_TYPE_TEST; i++) {
		CU_ASSERT(event_types[i] == ODP_EVENT_PACKET);
		CU_ASSERT(event_subtypes[i] == ODP_EVENT_PACKET_BASIC);
	}

	/* Mixed events: B P BB PP BBB PPP */
	odp_event_types_multi(event, event_types, NULL, 2 * NUM_TYPE_TEST);
	for (i = 0; i < 2 * NUM_TYPE_TEST; i++) {
		if (i == 0 || i == 2 || i == 3 || i == 6 || i == 7 || i == 8) {
			CU_ASSERT(event_types[i] == ODP_EVENT_BUFFER);
		} else {
			CU_ASSERT(event_types[i] == ODP_EVENT_PACKET);
		}
	}

	odp_event_free_multi(buf_event, NUM_TYPE_TEST);
	odp_event_free_multi(pkt_event, NUM_TYPE_TEST);

	CU_ASSERT(odp_pool_destroy(buf_pool) == 0);
	CU_ASSERT(odp_pool_destroy(pkt_pool) == 0);
}

static void event_test_filter_packet(void)
{
	odp_pool_t buf_pool, pkt_pool;
	int i, num_pkt, num_rem;
	int num = 2 * NUM_TYPE_TEST;
	odp_event_t buf_event[NUM_TYPE_TEST];
	odp_event_t pkt_event[NUM_TYPE_TEST];
	odp_event_t event[num];
	odp_packet_t packet[num];
	odp_event_t remain[num];

	type_test_init(&buf_pool, &pkt_pool, buf_event, pkt_event, event);

	for (i = 0; i < num; i++) {
		packet[i] = ODP_PACKET_INVALID;
		remain[i] = ODP_EVENT_INVALID;
	}

	num_pkt = odp_event_filter_packet(event, packet, remain, num);
	CU_ASSERT(num_pkt == NUM_TYPE_TEST);

	for (i = 0; i < num_pkt; i++)
		CU_ASSERT(packet[i] != ODP_PACKET_INVALID);

	num_rem = num - num_pkt;
	CU_ASSERT(num_rem == NUM_TYPE_TEST);

	for (i = 0; i < num_rem; i++) {
		CU_ASSERT(remain[i] != ODP_EVENT_INVALID);
		CU_ASSERT(odp_event_type(remain[i]) == ODP_EVENT_BUFFER);
	}

	odp_event_free_multi(event, num);

	CU_ASSERT(odp_pool_destroy(buf_pool) == 0);
	CU_ASSERT(odp_pool_destroy(pkt_pool) == 0);
}

static void event_test_is_valid(void)
{
	CU_ASSERT(odp_event_is_valid(ODP_EVENT_INVALID) == 0);
	CU_ASSERT(odp_buffer_is_valid(ODP_BUFFER_INVALID) == 0);
	CU_ASSERT(odp_packet_is_valid(ODP_PACKET_INVALID) == 0);
	CU_ASSERT(odp_packet_vector_valid(ODP_PACKET_VECTOR_INVALID) == 0);
}

odp_testinfo_t event_suite[] = {
	ODP_TEST_INFO(event_test_free),
	ODP_TEST_INFO(event_test_free_multi),
	ODP_TEST_INFO(event_test_free_multi_mixed),
	ODP_TEST_INFO(event_test_type_multi),
	ODP_TEST_INFO(event_test_types_multi),
	ODP_TEST_INFO(event_test_filter_packet),
	ODP_TEST_INFO(event_test_is_valid),
	ODP_TEST_INFO_NULL,
};

/* Tests for event type compliancy of function that operate with odp_event_t handles */
static odp_testinfo_t event_types_suite[] = {
	ODP_TEST_INFO(event_test_types_and_subtypes),
	ODP_TEST_INFO(event_test_pool),
	ODP_TEST_INFO(event_test_user_area_flag),
	ODP_TEST_INFO(event_test_debug),
	ODP_TEST_INFO(event_test_flow_id),
	ODP_TEST_INFO(event_test_types_filter_packets),
	ODP_TEST_INFO(event_test_event_frees),
	ODP_TEST_INFO(event_test_queue_enq_deq),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t event_suites[] = {
	{"Event", NULL, NULL, event_suite},
	{"EventTypes", event_types_suite_init, event_types_suite_term, event_types_suite},
	{"EventVector", evv_suite_init, evv_suite_term, evv_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	odp_cunit_register_global_init(event_init_global);

	ret = odp_cunit_register(event_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include <odp/helper/odph_api.h>

#include "event_vector.h"

#define PKT_LEN 1
#define BUF_SIZE 1
#define NUM_VECTORS 2

static uint32_t max_vector_size = 100;
static uint32_t uarea_size = 1;
static odp_pool_t evv_pool = ODP_POOL_INVALID;

static odp_pool_t create_packet_pool(uint32_t num_items)
{
	odp_pool_param_t param;
	odp_pool_t pool;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_PACKET;
	param.pkt.num = num_items;
	param.pkt.max_num = num_items;
	param.pkt.len = PKT_LEN;
	param.pkt.max_len = PKT_LEN;
	param.pkt.align = 0;
	param.pkt.seg_len = 0;
	param.pkt.headroom = 0;

	pool = odp_pool_create("packet pool", &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	return pool;
}

static odp_pool_t create_buffer_pool(uint32_t num_items)
{
	odp_pool_param_t param;
	odp_pool_t pool;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_BUFFER;
	param.buf.num = num_items;
	param.buf.size = BUF_SIZE;
	param.buf.align = 0;

	pool = odp_pool_create("buffer pool", &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	return pool;
}

static odp_event_vector_t event_vector_alloc(void)
{
	odp_event_vector_t evv;
	odp_event_t *ev_tbl = NULL;
	uint32_t size;

	evv = odp_event_vector_alloc(evv_pool);
	CU_ASSERT_FATAL(evv != ODP_EVENT_VECTOR_INVALID);

	CU_ASSERT(odp_event_vector_pool(evv) == evv_pool);
	CU_ASSERT(odp_event_vector_size(evv) == 0);
	CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_ANY);
	CU_ASSERT(odp_event_vector_user_flag(evv) == 0);
	size = odp_event_vector_tbl(evv, &ev_tbl);
	CU_ASSERT(size == 0);
	CU_ASSERT(ev_tbl != NULL);

	return evv;
}

/*
 * Test the various event vector handle conversion functions
 */
static void test_handle_conversions(void)
{
	odp_event_vector_t evv, evv2;
	odp_event_t ev;

	evv = event_vector_alloc();

	CU_ASSERT(odp_event_vector_to_u64(evv) !=
		  odp_event_vector_to_u64(ODP_EVENT_VECTOR_INVALID));

	ev = odp_event_vector_to_event(evv);
	CU_ASSERT(ev != ODP_EVENT_INVALID);
	evv2 = odp_event_vector_from_event(ev);
	CU_ASSERT(evv2 == evv);

	odp_event_vector_free(evv);
}

/*
 * Test that user flag can be set and read. Check also that
 * the user flag is reset after alloc by allocating a vector
 * event so many times that vector event reuse must occur.
 */
static void test_user_flag(void)
{
	odp_event_vector_t evv;

	for (uint32_t i = 0; i < 2 * NUM_VECTORS; i++) {
		evv = event_vector_alloc();

		CU_ASSERT(odp_event_vector_user_flag(evv) == 0);
		odp_event_vector_user_flag_set(evv, 1);
		CU_ASSERT(odp_event_vector_user_flag(evv) == 1);

		odp_event_vector_free(evv);
	}
}

/*
 * Test that odp_event_vector_print() does not crash when printing
 * ODP_EVENT_VECTOR_INVALID, an empty vector or a non-empty vector
 */
static void test_event_vector_print(void)
{
	odp_pool_t buf_pool, pkt_pool;
	odp_buffer_t buf;
	odp_packet_t pkt;
	odp_event_vector_t evv;
	odp_event_t *ev_tbl;
	uint32_t size;

	odp_event_vector_print(ODP_EVENT_VECTOR_INVALID);

	buf_pool = create_buffer_pool(1);
	pkt_pool = create_packet_pool(1);
	buf = odp_buffer_alloc(buf_pool);
	pkt = odp_packet_alloc(pkt_pool, PKT_LEN);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	evv = event_vector_alloc();
	size = odp_event_vector_tbl(evv, &ev_tbl);
	CU_ASSERT(size == 0);

	ev_tbl[0] = odp_buffer_to_event(buf);
	ev_tbl[1] = odp_packet_to_event(pkt);

	odp_event_vector_print(evv);
	odp_event_vector_size_set(evv, 2);
	CU_ASSERT(odp_event_vector_size(evv) == 2);
	odp_event_vector_print(evv);

	odp_event_vector_free(evv);
	odp_packet_free(pkt);
	odp_buffer_free(buf);

	CU_ASSERT(odp_pool_destroy(pkt_pool) == 0);
	CU_ASSERT(odp_pool_destroy(buf_pool) == 0);
}

/*
 * Test odp_event_vector_size{_set}(), odp_event_vector_tbl() and
 * odp_event_vector_type[_set}() in several ways.
 */
static void test_table_ops(void)
{
	odp_pool_t pkt_pool;
	odp_pool_t buf_pool;
	odp_packet_t pkt;
	odp_buffer_t buf;
	odp_event_vector_t evv;
	odp_event_t *ev_tbl, *ev_tbl2;
	uint32_t size;

	pkt_pool = create_packet_pool(1);
	pkt = odp_packet_alloc(pkt_pool, PKT_LEN);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	buf_pool = create_buffer_pool(1);
	buf = odp_buffer_alloc(buf_pool);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

	evv = event_vector_alloc();

	/* initially the vector should be empty */
	CU_ASSERT(odp_event_vector_size(evv) == 0);
	CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_ANY);
	size = odp_event_vector_tbl(evv, &ev_tbl);
	CU_ASSERT(size == 0);
	CU_ASSERT(ev_tbl != NULL);

	/* must be able to set event type of an empty vector */
	odp_event_vector_type_set(evv, ODP_EVENT_BUFFER);
	CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_BUFFER);

	/* put packet handle in the vector */
	ev_tbl[0] = odp_packet_to_event(pkt);
	odp_event_vector_size_set(evv, 1);
	CU_ASSERT(odp_event_vector_size(evv) == 1);
	size = odp_event_vector_tbl(evv, &ev_tbl2);
	CU_ASSERT(size == 1);
	CU_ASSERT(ev_tbl == ev_tbl2);
	CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_BUFFER);
	odp_event_vector_type_set(evv, ODP_EVENT_PACKET);
	CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_PACKET);

	/* add a buffer in the vector */
	ev_tbl[1] = odp_buffer_to_event(buf);
	odp_event_vector_size_set(evv, 2);
	size = odp_event_vector_tbl(evv, &ev_tbl2);
	CU_ASSERT(size == 2);
	CU_ASSERT(ev_tbl == ev_tbl2);
	CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_PACKET);
	odp_event_vector_type_set(evv, ODP_EVENT_ANY);
	CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_ANY);

	/* truncate to zero length */
	odp_event_vector_type_set(evv, ODP_EVENT_PACKET);
	odp_event_vector_size_set(evv, 0);
	CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_PACKET);
	size = odp_event_vector_tbl(evv, &ev_tbl2);
	CU_ASSERT(size == 0);
	CU_ASSERT(ev_tbl == ev_tbl2);
	odp_event_vector_free(evv);
	odp_packet_free(pkt);
	odp_buffer_free(buf);

	CU_ASSERT(odp_pool_destroy(pkt_pool) == 0);
	CU_ASSERT(odp_pool_destroy(buf_pool) == 0);
}

static void alloc_all_bufs(odp_pool_t pool, odp_buffer_t buf[], uint32_t num)
{
	for (uint32_t i = 0; i < num; i++) {
		buf[i] = odp_buffer_alloc(pool);
		CU_ASSERT_FATAL(buf[i] != ODP_BUFFER_INVALID);
	}
	CU_ASSERT(odp_buffer_alloc(pool) == ODP_BUFFER_INVALID);
}

static void alloc_all_pkts(odp_pool_t pool, odp_packet_t pkt[], uint32_t num)
{
	for (uint32_t i = 0; i < num; i++) {
		pkt[i] = odp_packet_alloc(pool, PKT_LEN);
		CU_ASSERT_FATAL(pkt[i] != ODP_PACKET_INVALID);
	}
	CU_ASSERT(odp_packet_alloc(pool, PKT_LEN) == ODP_PACKET_INVALID);
}

static odp_event_vector_t alloc_and_fill_vector(odp_event_t ev[], uint32_t num)
{
	odp_event_vector_t evv;
	odp_event_t *ev_tbl;
	uint32_t size;

	evv = event_vector_alloc();
	size = odp_event_vector_tbl(evv, &ev_tbl);
	CU_ASSERT(size == 0);

	for (uint32_t i = 0; i < num; i++)
		ev_tbl[i] = ev[i];
	odp_event_vector_size_set(evv, num);

	return evv;
}

/*
 * Test that odp_event_free() frees the events contained in a vector
 * and that odp_event_vector_free() does not.
 */
static void test_content_freeing(void)
{
	odp_pool_t pkt_pool;
	odp_pool_t buf_pool;
	uint32_t num_bufs = max_vector_size - 1;
	odp_buffer_t buf[num_bufs];
	odp_event_t ev[max_vector_size];
	odp_packet_t pkt;
	odp_event_vector_t evv;
	odp_event_t *ev_tbl;
	uint32_t size;

	buf_pool = create_buffer_pool(num_bufs);
	pkt_pool = create_packet_pool(1);

	alloc_all_bufs(buf_pool, buf, num_bufs);
	for (uint32_t i = 0; i < num_bufs; i++)
		ev[i] = odp_buffer_to_event(buf[i]);

	alloc_all_pkts(pkt_pool, &pkt, 1);
	ev[num_bufs] = odp_packet_to_event(pkt);

	/* test that odp_event_vector_free() does not free the contained events */

	evv = alloc_and_fill_vector(ev, num_bufs);
	size = odp_event_vector_tbl(evv, &ev_tbl);
	CU_ASSERT(size == num_bufs);
	ev_tbl[num_bufs] = odp_packet_to_event(pkt);
	odp_event_vector_size_set(evv, num_bufs + 1);
	CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_ANY);

	odp_event_vector_free(evv);

	for (uint32_t i = 0; i < num_bufs; i++)
		CU_ASSERT(odp_buffer_is_valid(buf[i]));
	CU_ASSERT(odp_packet_is_valid(pkt));
	CU_ASSERT(odp_buffer_alloc(buf_pool) == ODP_BUFFER_INVALID);
	CU_ASSERT(odp_packet_alloc(pkt_pool, PKT_LEN) == ODP_PACKET_INVALID);

	/* test that odp_event_free() frees all contained events */
	evv = alloc_and_fill_vector(ev, num_bufs + 1);
	CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_ANY);
	odp_event_free(odp_event_vector_to_event(evv));
	alloc_all_bufs(buf_pool, buf, num_bufs);
	alloc_all_pkts(pkt_pool, &pkt, 1);

	/* check that the evv was freed too so allocation succeeds */
	evv = alloc_and_fill_vector(NULL, 0);
	odp_event_vector_free(evv);

	odp_packet_free(pkt);
	for (uint32_t i = 0; i < num_bufs; i++)
		odp_buffer_free(buf[i]);

	CU_ASSERT(odp_pool_destroy(pkt_pool) == 0);
	CU_ASSERT(odp_pool_destroy(buf_pool) == 0);
}

/*
 * Test that odp_event_free() and odp_event_vector_free() return the event
 * vector back to the pool so that it becomes allocatable again.
 */
static void test_vector_freeing(void)
{
	odp_event_vector_t evv[NUM_VECTORS];
	odp_event_vector_t extra;

	for (uint32_t i = 0; i < NUM_VECTORS; i++)
		evv[i] = event_vector_alloc();
	extra = odp_event_vector_alloc(evv_pool);
	CU_ASSERT(extra == ODP_EVENT_VECTOR_INVALID);

	odp_event_vector_free(evv[0]);
	evv[0] = event_vector_alloc();
	extra = odp_event_vector_alloc(evv_pool);
	CU_ASSERT(extra == ODP_EVENT_VECTOR_INVALID);

	odp_event_free(odp_event_vector_to_event(evv[0]));
	evv[0] = event_vector_alloc();
	extra = odp_event_vector_alloc(evv_pool);
	CU_ASSERT(extra == ODP_EVENT_VECTOR_INVALID);

	for (uint32_t i = 0; i < NUM_VECTORS; i++)
		odp_event_vector_free(evv[i]);
}

/*
 * Test that two event vectors allocated from the same pool have
 * different handles, user areas (if supported) and metadata.
 */
static void test_uniqueness(void)
{
	odp_event_vector_t evv1, evv2;
	odp_event_t *ev_tbl1, *ev_tbl2;

	ODP_STATIC_ASSERT(NUM_VECTORS >= 2, "vector pool is too small");
	evv1 = event_vector_alloc();
	evv2 = event_vector_alloc();

	CU_ASSERT(evv1 != evv2);
	CU_ASSERT(uarea_size == 0 || (odp_event_vector_user_area(evv1) !=
				      odp_event_vector_user_area(evv2)));
	CU_ASSERT(odp_event_vector_to_u64(evv1) !=
		  odp_event_vector_to_u64(evv2));

	CU_ASSERT(odp_event_vector_tbl(evv1, &ev_tbl1) == 0);
	CU_ASSERT(odp_event_vector_tbl(evv2, &ev_tbl2) == 0);
	CU_ASSERT(ev_tbl1 != ev_tbl2);

	CU_ASSERT(odp_event_vector_user_flag(evv1) == 0);
	CU_ASSERT(odp_event_vector_user_flag(evv2) == 0);
	odp_event_vector_user_flag_set(evv1, 1);
	CU_ASSERT(odp_event_vector_user_flag(evv1) == 1);
	CU_ASSERT(odp_event_vector_user_flag(evv2) == 0);

	CU_ASSERT(odp_event_vector_size(evv1) == 0);
	CU_ASSERT(odp_event_vector_size(evv2) == 0);
	odp_event_vector_size_set(evv1, 1);
	CU_ASSERT(odp_event_vector_size(evv1) == 1);
	CU_ASSERT(odp_event_vector_size(evv2) == 0);
	odp_event_vector_size_set(evv1, 0);

	CU_ASSERT(odp_event_vector_type(evv1) == ODP_EVENT_ANY);
	CU_ASSERT(odp_event_vector_type(evv2) == ODP_EVENT_ANY);
	odp_event_vector_type_set(evv1, ODP_EVENT_PACKET);
	CU_ASSERT(odp_event_vector_type(evv1) == ODP_EVENT_PACKET);
	CU_ASSERT(odp_event_vector_type(evv2) == ODP_EVENT_ANY);

	odp_event_vector_free(evv1);
	odp_event_vector_free(evv2);
}

int evv_suite_init(void)
{
	odp_pool_capability_t capa;
	static odp_pool_param_t param; /* keep around until tests finished */

	if (odp_pool_capability(&capa) != 0) {
		ODPH_ERR("\nodp_pool_capability() failed\n");
		return 1;
	}
	if (capa.event_vector.max_pools == 0) {
		odp_cunit_set_inactive(); /* skip this test suite */
		return 0;
	}
	if (capa.max_pools < 3) {
		ODPH_ERR("\nnot enough pools (packet, buffer and event vector pools needed)\n");
		return 1;
	}
	if (capa.event_vector.max_num != 0 &&
	    capa.event_vector.max_num < NUM_VECTORS) {
		ODPH_ERR("\ncapa.event_vector.max_num is too small\n");
		return 1; /* intentionally fail instead of skip */
	}
	if (capa.event_vector.max_size < max_vector_size)
		max_vector_size = capa.event_vector.max_size;
	if (max_vector_size < 2) {
		ODPH_ERR("\nevent_vector.max_size pool capability is too low\n");
		return 1;
	}
	if (capa.buf.max_num < max_vector_size) {
		ODPH_ERR("\nbuffer.max_size pool capability is too low\n");
		return 1;
	}
	if (capa.event_vector.max_uarea_size < uarea_size)
		uarea_size = capa.event_vector.max_uarea_size;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_EVENT_VECTOR;
	param.event_vector.num = NUM_VECTORS;
	param.event_vector.max_size = max_vector_size;
	param.event_vector.uarea_size = uarea_size;
	evv_pool = odp_pool_create(NULL, &param);
	if (evv_pool == ODP_POOL_INVALID) {
		ODPH_ERR("\nodp_pool_create() failed\n");
		return 1;
	}
	memset(&param, 0, sizeof(param));

	return 0;
}

int evv_suite_term(void)
{
	odp_cunit_print_inactive();

	if (evv_pool != ODP_POOL_INVALID)
		odp_pool_destroy(evv_pool);

	return 0;
}

odp_testinfo_t evv_suite[] = {
	ODP_TEST_INFO(test_handle_conversions),
	ODP_TEST_INFO(test_user_flag),
	ODP_TEST_INFO(test_event_vector_print),
	ODP_TEST_INFO(test_table_ops),
	ODP_TEST_INFO(test_content_freeing),
	ODP_TEST_INFO(test_vector_freeing),
	ODP_TEST_INFO(test_uniqueness),
	ODP_TEST_INFO_NULL,
};

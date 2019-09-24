/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>

#define NUM_EVENTS  100
#define EVENT_SIZE  100
#define EVENT_BURST 10

static void event_test_free(void)
{
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	int i;
	odp_buffer_t buf;
	odp_packet_t pkt;
	odp_timeout_t tmo;
	odp_event_subtype_t subtype;
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

		if (j == 0)
			odp_event_free_multi(event, 3 * EVENT_BURST);
		else
			odp_event_free_sp(event, 3 * EVENT_BURST);
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
	odp_event_type_t type;
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

odp_testinfo_t event_suite[] = {
	ODP_TEST_INFO(event_test_free),
	ODP_TEST_INFO(event_test_free_multi),
	ODP_TEST_INFO(event_test_free_multi_mixed),
	ODP_TEST_INFO(event_test_type_multi),
	ODP_TEST_INFO(event_test_filter_packet),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t event_suites[] = {
	{"Event", NULL, NULL, event_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(event_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

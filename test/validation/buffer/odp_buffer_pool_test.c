/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp_buffer_tests.h"

static int pool_name_number = 1;
static const int default_buffer_size = 1500;
static const int default_buffer_num = 1000;

odp_pool_t pool_create(int buf_num, int buf_size, int buf_type)
{
	odp_pool_t pool;
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_param_t params = {
			.buf = {
				.size  = buf_size,
				.align = ODP_CACHE_LINE_SIZE,
				.num   = buf_num,
			},
			.type = buf_type,
	};

	snprintf(pool_name, sizeof(pool_name),
		 "test_buffer_pool-%d", pool_name_number++);

	pool = odp_pool_create(pool_name, ODP_SHM_INVALID, &params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	return pool;
}

static void pool_create_destroy_type(int type)
{
	odp_pool_t pool;
	pool = pool_create(default_buffer_num, default_buffer_size, type);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_create_destroy_raw(void)
{
	pool_create_destroy_type(ODP_POOL_BUFFER);
}

static void pool_create_destroy_packet(void)
{
	pool_create_destroy_type(ODP_POOL_PACKET);
}

static void pool_create_destroy_timeout(void)
{
	pool_create_destroy_type(ODP_POOL_TIMEOUT);
}

static void pool_create_destroy_raw_shm(void)
{
	odp_pool_t pool;
	odp_shm_t test_shm;
	odp_pool_param_t params = {
			.buf = {
				.size  = 1500,
				.align = ODP_CACHE_LINE_SIZE,
				.num   = 10,
			},
			.type  = ODP_POOL_BUFFER,
	};

	test_shm = odp_shm_reserve("test_shm",
				   params.buf.size * params.buf.num * 2,
				   ODP_CACHE_LINE_SIZE,
				   0);
	CU_ASSERT_FATAL(test_shm != ODP_SHM_INVALID);

	pool = odp_pool_create("test_shm_pool", test_shm, &params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
	CU_ASSERT(odp_shm_free(test_shm) == 0);
}

static void pool_lookup_info_print(void)
{
	odp_pool_t pool;
	const char pool_name[] = "pool_for_lookup_test";
	odp_pool_info_t info;
	odp_pool_param_t params = {
			.buf = {
				.size  = default_buffer_size,
				.align = ODP_CACHE_LINE_SIZE,
				.num  = default_buffer_num,
			},
			.type  = ODP_POOL_BUFFER,
	};

	pool = odp_pool_create(pool_name, ODP_SHM_INVALID, &params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	pool = odp_pool_lookup(pool_name);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	CU_ASSERT_FATAL(odp_pool_info(pool, &info) == 0);
	CU_ASSERT(strncmp(pool_name, info.name, sizeof(pool_name)) == 0);
	CU_ASSERT(info.shm == ODP_SHM_INVALID);
	CU_ASSERT(params.buf.size <= info.params.buf.size);
	CU_ASSERT(params.buf.align <= info.params.buf.align);
	CU_ASSERT(params.buf.num <= info.params.buf.num);
	CU_ASSERT(params.type == info.params.type);

	odp_pool_print(pool);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_alloc_type(int type)
{
	odp_pool_t pool;
	const int num = 3;
	const size_t size = 1500;
	odp_buffer_t buffer[num];
	odp_packet_t packet[num];
	odp_timeout_t tmo[num];
	odp_event_t ev;
	int index;
	char wrong_type = 0, wrong_size = 0;

	pool = pool_create(num, size, type);
	odp_pool_print(pool);

	/* Try to allocate num items from the pool */
	for (index = 0; index < num; index++) {
		switch (type) {
		case ODP_POOL_BUFFER:
			buffer[index] = odp_buffer_alloc(pool);

			if (buffer[index] == ODP_BUFFER_INVALID)
				break;

			ev = odp_buffer_to_event(buffer[index]);
			if (odp_event_type(ev) != ODP_EVENT_BUFFER)
				wrong_type = 1;
			if (odp_buffer_size(buffer[index]) < size)
				wrong_size = 1;
			if (wrong_type || wrong_size)
				odp_buffer_print(buffer[index]);
			break;
		case ODP_POOL_PACKET:
			packet[index] = odp_packet_alloc(pool, size);

			if (packet[index] == ODP_PACKET_INVALID)
				break;

			ev = odp_packet_to_event(packet[index]);
			if (odp_event_type(ev) != ODP_EVENT_PACKET)
				wrong_type = 1;
			break;
		case ODP_POOL_TIMEOUT:
			tmo[index] = odp_timeout_alloc(pool);

			if (tmo[index] == ODP_TIMEOUT_INVALID)
				break;

			ev = odp_timeout_to_event(tmo[index]);
			if (odp_event_type(ev) != ODP_EVENT_TIMEOUT)
				wrong_type = 1;
			break;
		default:
			break;
		}

	}

	/* Check that the pool had at least num items */
	CU_ASSERT(index == num);
	/* index points out of buffer[] or it point to an invalid buffer */
	index--;

	/* Check that the pool had correct buffers */
	CU_ASSERT(wrong_type == 0);
	CU_ASSERT(wrong_size == 0);

	switch (type) {
	case ODP_POOL_BUFFER:
		for (; index >= 0; index--)
			odp_buffer_free(buffer[index]);
		break;
	case ODP_POOL_PACKET:
		for (; index >= 0; index--)
			odp_packet_free(packet[index]);
		break;
	case ODP_POOL_TIMEOUT:
		for (; index >= 0; index--)
			odp_timeout_free(tmo[index]);
		break;
	default:
		break;
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_alloc_buffer_raw(void)
{
	pool_alloc_type(ODP_POOL_BUFFER);
}

static void pool_alloc_buffer_packet(void)
{
	pool_alloc_type(ODP_POOL_PACKET);
}

static void pool_alloc_buffer_timeout(void)
{
	pool_alloc_type(ODP_POOL_TIMEOUT);
}

static void pool_free_buffer(void)
{
	odp_pool_t pool;
	odp_buffer_t buffer;
	pool = pool_create(1, 64, ODP_POOL_BUFFER);

	/* Allocate the only buffer from the pool */
	buffer = odp_buffer_alloc(pool);
	CU_ASSERT_FATAL(buffer != ODP_BUFFER_INVALID);

	/** @todo: is it correct to assume the pool had only one buffer? */
	CU_ASSERT_FATAL(odp_buffer_alloc(pool) == ODP_BUFFER_INVALID)

	odp_buffer_free(buffer);

	/* Check that the buffer was returned back to the pool */
	buffer = odp_buffer_alloc(pool);
	CU_ASSERT_FATAL(buffer != ODP_BUFFER_INVALID);

	odp_buffer_free(buffer);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

CU_TestInfo buffer_pool_tests[] = {
	_CU_TEST_INFO(pool_create_destroy_raw),
	_CU_TEST_INFO(pool_create_destroy_packet),
	_CU_TEST_INFO(pool_create_destroy_timeout),
	_CU_TEST_INFO(pool_create_destroy_raw_shm),
	_CU_TEST_INFO(pool_lookup_info_print),
	_CU_TEST_INFO(pool_alloc_buffer_raw),
	_CU_TEST_INFO(pool_alloc_buffer_packet),
	_CU_TEST_INFO(pool_alloc_buffer_timeout),
	_CU_TEST_INFO(pool_free_buffer),
	CU_TEST_INFO_NULL,
};

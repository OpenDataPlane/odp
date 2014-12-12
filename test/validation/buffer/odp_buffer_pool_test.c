/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp_buffer_tests.h"

static int pool_name_number = 1;
static const int default_buffer_size = 1500;
static const int default_buffer_num = 1000;

odp_buffer_pool_t pool_create(int buf_num, int buf_size, int buf_type)
{
	odp_buffer_pool_t pool;
	char pool_name[ODP_BUFFER_POOL_NAME_LEN];
	odp_buffer_pool_param_t params = {
			.buf_size  = buf_size,
			.buf_align = ODP_CACHE_LINE_SIZE,
			.num_bufs  = buf_num,
			.buf_type  = buf_type,
	};

	snprintf(pool_name, sizeof(pool_name),
		 "test_buffer_pool-%d", pool_name_number++);

	pool = odp_buffer_pool_create(pool_name, ODP_SHM_INVALID, &params);
	CU_ASSERT_FATAL(pool != ODP_BUFFER_POOL_INVALID);

	return pool;
}

static void pool_create_destroy_type(int type)
{
	odp_buffer_pool_t pool;
	pool = pool_create(default_buffer_num, default_buffer_size, type);

	CU_ASSERT(odp_buffer_pool_destroy(pool) == 0);
}

static void pool_create_destroy_raw(void)
{
	pool_create_destroy_type(ODP_BUFFER_TYPE_RAW);
}

static void pool_create_destroy_packet(void)
{
	pool_create_destroy_type(ODP_BUFFER_TYPE_PACKET);
}

static void pool_create_destroy_timeout(void)
{
	pool_create_destroy_type(ODP_BUFFER_TYPE_TIMEOUT);
}

static void pool_create_destroy_any(void)
{
	pool_create_destroy_type(ODP_BUFFER_TYPE_ANY);
}

static void pool_create_destroy_raw_shm(void)
{
	odp_buffer_pool_t pool;
	odp_shm_t test_shm;
	odp_buffer_pool_param_t params = {
			.buf_size  = 1500,
			.buf_align = ODP_CACHE_LINE_SIZE,
			.num_bufs  = 10,
			.buf_type  = ODP_BUFFER_TYPE_RAW,
	};

	test_shm = odp_shm_reserve("test_shm",
				   params.buf_size * params.num_bufs * 2,
				   ODP_CACHE_LINE_SIZE,
				   0);
	CU_ASSERT_FATAL(test_shm != ODP_SHM_INVALID);

	pool = odp_buffer_pool_create("test_shm_pool", test_shm, &params);
	CU_ASSERT_FATAL(pool != ODP_BUFFER_POOL_INVALID);

	CU_ASSERT(odp_buffer_pool_destroy(pool) == 0);
	CU_ASSERT(odp_shm_free(test_shm) == 0);
}

static void pool_lookup_info_print(void)
{
	odp_buffer_pool_t pool;
	const char pool_name[] = "pool_for_lookup_test";
	odp_buffer_pool_info_t info;
	odp_buffer_pool_param_t params = {
			.buf_size  = default_buffer_size,
			.buf_align = ODP_CACHE_LINE_SIZE,
			.num_bufs  = default_buffer_num,
			.buf_type  = ODP_BUFFER_TYPE_RAW,
	};

	pool = odp_buffer_pool_create(pool_name, ODP_SHM_INVALID, &params);
	CU_ASSERT_FATAL(pool != ODP_BUFFER_POOL_INVALID);

	pool = odp_buffer_pool_lookup(pool_name);
	CU_ASSERT_FATAL(pool != ODP_BUFFER_POOL_INVALID);

	CU_ASSERT_FATAL(odp_buffer_pool_info(pool, &info) == 0);
	CU_ASSERT(strncmp(pool_name, info.name, sizeof(pool_name)) == 0);
	CU_ASSERT(info.shm == ODP_SHM_INVALID);
	CU_ASSERT(params.buf_size <= info.params.buf_size);
	CU_ASSERT(params.buf_align <= info.params.buf_align);
	CU_ASSERT(params.num_bufs <= info.params.num_bufs);
	CU_ASSERT(params.buf_type == info.params.buf_type);

	odp_buffer_pool_print(pool);

	CU_ASSERT(odp_buffer_pool_destroy(pool) == 0);
}

static void pool_alloc_buffer_type(int type)
{
	odp_buffer_pool_t pool;
	const int buf_num = 3;
	const size_t buf_size = 1500;
	odp_buffer_t buffer[buf_num];
	int buf_index;
	char wrong_type = 0, wrong_size = 0;

	pool = pool_create(buf_num, buf_size, type);
	odp_buffer_pool_print(pool);

	/* Try to allocate buf_num buffers from the pool */
	for (buf_index = 0; buf_index < buf_num; buf_index++) {
		buffer[buf_index] = odp_buffer_alloc(pool);
		if (buffer[buf_index] == ODP_BUFFER_INVALID)
			break;
		if (odp_buffer_type(buffer[buf_index]) != type)
			wrong_type = 1;
		if (odp_buffer_size(buffer[buf_index]) < buf_size)
			wrong_size = 1;
		if (wrong_type || wrong_size)
			odp_buffer_print(buffer[buf_index]);
	}

	/* Check that the pool had at least buf_num buffers */
	CU_ASSERT(buf_index == buf_num);
	/* buf_index points out of buffer[] or it point to an invalid buffer */
	buf_index--;

	/* Check that the pool had correct buffers */
	CU_ASSERT(wrong_type == 0);
	CU_ASSERT(wrong_size == 0);

	for (; buf_index >= 0; buf_index--)
		odp_buffer_free(buffer[buf_index]);

	CU_ASSERT(odp_buffer_pool_destroy(pool) == 0);
}

static void pool_alloc_buffer_raw(void)
{
	pool_alloc_buffer_type(ODP_BUFFER_TYPE_RAW);
}

static void pool_alloc_buffer_packet(void)
{
	pool_alloc_buffer_type(ODP_BUFFER_TYPE_PACKET);
}

static void pool_alloc_buffer_timeout(void)
{
	pool_alloc_buffer_type(ODP_BUFFER_TYPE_TIMEOUT);
}

static void pool_alloc_buffer_any(void)
{
	pool_alloc_buffer_type(ODP_BUFFER_TYPE_ANY);
}

static void pool_free_buffer(void)
{
	odp_buffer_pool_t pool;
	odp_buffer_t buffer;
	pool = pool_create(1, 64, ODP_BUFFER_TYPE_RAW);

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
	CU_ASSERT(odp_buffer_pool_destroy(pool) == 0);
}

CU_TestInfo buffer_pool_tests[] = {
	_CU_TEST_INFO(pool_create_destroy_raw),
	_CU_TEST_INFO(pool_create_destroy_packet),
	_CU_TEST_INFO(pool_create_destroy_timeout),
	_CU_TEST_INFO(pool_create_destroy_any),
	_CU_TEST_INFO(pool_create_destroy_raw_shm),
	_CU_TEST_INFO(pool_lookup_info_print),
	_CU_TEST_INFO(pool_alloc_buffer_raw),
	_CU_TEST_INFO(pool_alloc_buffer_packet),
	_CU_TEST_INFO(pool_alloc_buffer_timeout),
	_CU_TEST_INFO(pool_alloc_buffer_any),
	_CU_TEST_INFO(pool_free_buffer),
	CU_TEST_INFO_NULL,
};

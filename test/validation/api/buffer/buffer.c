/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2019-2022, Nokia
 * Copyright (c) 2022, Marvell
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp_api.h>
#include <odp/helper/odph_debug.h>
#include "odp_cunit_common.h"

#define BUF_ALIGN  ODP_CACHE_LINE_SIZE
#define BUF_SIZE   1500
#define BUF_NUM    100
#define BURST      8

static odp_pool_capability_t pool_capa;
static odp_pool_param_t default_param;

static int buffer_suite_init(void)
{
	uint32_t size, num, align;

	if (odp_pool_capability(&pool_capa)) {
		printf("pool capability failed\n");
		return -1;
	}

	size = BUF_SIZE;
	if (pool_capa.buf.max_size && size > pool_capa.buf.max_size)
		size = pool_capa.buf.max_size;

	num = BUF_NUM;
	if (pool_capa.buf.max_num && num > pool_capa.buf.max_num)
		num = pool_capa.buf.max_num;

	align = BUF_ALIGN;
	if (align > pool_capa.buf.max_align)
		align = pool_capa.buf.max_align;

	odp_pool_param_init(&default_param);
	default_param.type      = ODP_POOL_BUFFER;
	default_param.buf.size  = size;
	default_param.buf.num   = num;
	default_param.buf.align = align;

	printf("Default buffer pool\n");
	printf("  size  %u\n", size);
	printf("  num   %u\n", num);
	printf("  align %u\n\n", align);

	return 0;
}

static void test_pool_alloc_free(const odp_pool_param_t *param)
{
	odp_pool_t pool;
	odp_event_t ev;
	uint32_t i;
	uint32_t num_buf = 0;
	void *addr;
	odp_event_subtype_t subtype;
	uint32_t num = param->buf.num;
	uint32_t size = param->buf.size;
	uint32_t align = param->buf.align;

	odp_buffer_t buffer[num];
	odp_bool_t wrong_type = false, wrong_subtype = false;
	odp_bool_t wrong_size = false, wrong_align = false;

	pool = odp_pool_create("default pool", param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	odp_pool_print(pool);

	for (i = 0; i < num; i++) {
		odp_buffer_t buf;

		buffer[i] = odp_buffer_alloc(pool);

		if (buffer[i] == ODP_BUFFER_INVALID)
			break;
		num_buf++;

		CU_ASSERT(odp_buffer_is_valid(buffer[i]) == 1)

		CU_ASSERT(odp_buffer_pool(buffer[i]) == pool);

		ev = odp_buffer_to_event(buffer[i]);
		CU_ASSERT(odp_buffer_from_event(ev) == buffer[i]);

		odp_buffer_to_event_multi(&buffer[i], &ev, 1);
		odp_buffer_from_event_multi(&buf, &ev, 1);
		CU_ASSERT(buf == buffer[i]);

		if (odp_event_type(ev) != ODP_EVENT_BUFFER)
			wrong_type = true;
		if (odp_event_subtype(ev) != ODP_EVENT_NO_SUBTYPE)
			wrong_subtype = true;
		if (odp_event_types(ev, &subtype) != ODP_EVENT_BUFFER)
			wrong_type = true;
		if (subtype != ODP_EVENT_NO_SUBTYPE)
			wrong_subtype = true;
		if (odp_buffer_size(buffer[i]) < size)
			wrong_size = true;

		addr = odp_buffer_addr(buffer[i]);

		if (((uintptr_t)addr % align) != 0)
			wrong_align = true;

		if (wrong_type || wrong_subtype || wrong_size || wrong_align) {
			printf("Buffer has error\n");
			odp_buffer_print(buffer[i]);
			break;
		}

		/* Write buffer data */
		memset(addr, 0, size);
	}

	CU_ASSERT(i == num);
	CU_ASSERT(!wrong_type);
	CU_ASSERT(!wrong_subtype);
	CU_ASSERT(!wrong_size);
	CU_ASSERT(!wrong_align);

	for (i = 0; i < num_buf; i++)
		odp_buffer_free(buffer[i]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void test_pool_alloc_free_multi(const odp_pool_param_t *param)
{
	odp_pool_t pool;
	uint32_t i, num_buf;
	int ret;
	odp_event_t ev;
	void *addr;
	odp_event_subtype_t subtype;
	uint32_t num = param->buf.num;
	uint32_t size = param->buf.size;
	uint32_t align = param->buf.align;

	odp_buffer_t buffer[num + BURST];
	odp_bool_t wrong_type = false, wrong_subtype = false;
	odp_bool_t wrong_size = false, wrong_align = false;

	pool = odp_pool_create("default pool", param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	ret = 0;
	for (i = 0; i < num; i += ret) {
		odp_buffer_t buf[BURST];
		odp_event_t event[BURST];

		ret = odp_buffer_alloc_multi(pool, &buffer[i], BURST);
		CU_ASSERT(ret >= 0);
		CU_ASSERT(ret <= BURST);

		if (ret <= 0)
			break;

		odp_buffer_to_event_multi(&buffer[i], event, ret);
		odp_buffer_from_event_multi(buf, event, ret);
		for (int j = 0; j < ret; j++)
			CU_ASSERT(buf[j] == buffer[i + j]);
	}

	num_buf = i;
	CU_ASSERT(num_buf == num);

	for (i = 0; i < num_buf; i++) {
		if (buffer[i] == ODP_BUFFER_INVALID)
			break;

		CU_ASSERT(odp_buffer_is_valid(buffer[i]) == 1)

		CU_ASSERT(odp_buffer_pool(buffer[i]) == pool);

		ev = odp_buffer_to_event(buffer[i]);
		CU_ASSERT(odp_buffer_from_event(ev) == buffer[i]);

		if (odp_event_type(ev) != ODP_EVENT_BUFFER)
			wrong_type = true;
		if (odp_event_subtype(ev) != ODP_EVENT_NO_SUBTYPE)
			wrong_subtype = true;
		if (odp_event_types(ev, &subtype) != ODP_EVENT_BUFFER)
			wrong_type = true;
		if (subtype != ODP_EVENT_NO_SUBTYPE)
			wrong_subtype = true;
		if (odp_buffer_size(buffer[i]) < size)
			wrong_size = true;

		addr = odp_buffer_addr(buffer[i]);

		if (((uintptr_t)addr % align) != 0)
			wrong_align = true;

		if (wrong_type || wrong_subtype || wrong_size || wrong_align) {
			printf("Buffer has error\n");
			odp_buffer_print(buffer[i]);
			break;
		}

		/* Write buffer data */
		memset(addr, 0, size);
	}

	CU_ASSERT(i == num_buf);
	CU_ASSERT(!wrong_type);
	CU_ASSERT(!wrong_subtype);
	CU_ASSERT(!wrong_size);
	CU_ASSERT(!wrong_align);

	if (num_buf)
		odp_buffer_free_multi(buffer, num_buf);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void test_pool_single_pool(odp_pool_param_t *param)
{
	odp_pool_t pool;
	odp_buffer_t buffer;

	param->buf.num = 1;

	pool = odp_pool_create("pool 0", param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	odp_pool_print(pool);

	/* Allocate the only buffer from the pool */
	buffer = odp_buffer_alloc(pool);
	CU_ASSERT(buffer != ODP_BUFFER_INVALID);

	/* Pool should be empty */
	CU_ASSERT(odp_buffer_alloc(pool) == ODP_BUFFER_INVALID)

	if (buffer != ODP_BUFFER_INVALID) {
		odp_event_t ev = odp_buffer_to_event(buffer);

		CU_ASSERT(odp_buffer_to_u64(buffer) !=
			  odp_buffer_to_u64(ODP_BUFFER_INVALID));
		CU_ASSERT(odp_event_to_u64(ev) !=
			  odp_event_to_u64(ODP_EVENT_INVALID));
		CU_ASSERT(odp_buffer_pool(buffer) == pool);
		odp_buffer_print(buffer);
		odp_buffer_free(buffer);
	}

	/* Check that the buffer was returned back to the pool */
	buffer = odp_buffer_alloc(pool);
	CU_ASSERT(buffer != ODP_BUFFER_INVALID);

	if (buffer != ODP_BUFFER_INVALID)
		odp_buffer_free(buffer);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void test_pool_two_pools(odp_pool_param_t *param)
{
	odp_pool_t pool0, pool1;
	odp_buffer_t buf, buffer[2];
	int num = 0;

	if (pool_capa.buf.max_pools < 2)
		return;

	param->buf.num = 1;

	pool0 = odp_pool_create("pool 0", param);
	CU_ASSERT_FATAL(pool0 != ODP_POOL_INVALID);

	pool1 = odp_pool_create("pool 1", param);
	CU_ASSERT_FATAL(pool1 != ODP_POOL_INVALID);

	buffer[0] = odp_buffer_alloc(pool0);
	CU_ASSERT(buffer[0] != ODP_BUFFER_INVALID);

	buffer[1] = odp_buffer_alloc(pool1);
	CU_ASSERT(buffer[1] != ODP_BUFFER_INVALID);

	if (buffer[0] != ODP_BUFFER_INVALID) {
		CU_ASSERT(odp_buffer_pool(buffer[0]) == pool0);
		num++;
	}
	if (buffer[1] != ODP_BUFFER_INVALID) {
		CU_ASSERT(odp_buffer_pool(buffer[1]) == pool1);
		num++;
	}

	CU_ASSERT(odp_buffer_alloc(pool0) == ODP_BUFFER_INVALID);
	CU_ASSERT(odp_buffer_alloc(pool1) == ODP_BUFFER_INVALID);

	/* free buffers from two different pools */
	if (num)
		odp_buffer_free_multi(buffer, num);

	/* Check that buffers were returned back into pools */
	buf = odp_buffer_alloc(pool0);
	CU_ASSERT(buf != ODP_BUFFER_INVALID);

	if (buf != ODP_BUFFER_INVALID) {
		CU_ASSERT(odp_buffer_pool(buf) == pool0);
		odp_buffer_free(buf);
	}

	CU_ASSERT(odp_pool_destroy(pool0) == 0);

	buf = odp_buffer_alloc(pool1);
	CU_ASSERT(buf != ODP_BUFFER_INVALID);

	if (buf != ODP_BUFFER_INVALID) {
		CU_ASSERT(odp_buffer_pool(buf) == pool1);
		odp_buffer_free(buf);
	}

	CU_ASSERT(odp_pool_destroy(pool1) == 0);
}

static void test_pool_max_pools(odp_pool_param_t *param)
{
	uint32_t i, num_pool, num_buf;
	void *addr;
	odp_event_t ev;
	uint32_t max_pools = pool_capa.buf.max_pools;
	uint32_t size = param->buf.size;
	uint32_t align = param->buf.align;
	odp_pool_t pool[max_pools];
	odp_buffer_t buffer[max_pools];

	CU_ASSERT_FATAL(max_pools != 0);

	printf("\n  Creating %u pools\n", max_pools);

	param->buf.num = 1;

	for (i = 0; i < max_pools; i++) {
		pool[i] = odp_pool_create(NULL, param);

		if (pool[i] == ODP_POOL_INVALID)
			break;
	}

	num_pool = i;

	CU_ASSERT(num_pool == max_pools);
	if (num_pool != max_pools)
		printf("Error: created only %u pools\n", num_pool);

	for (i = 0; i < num_pool; i++) {
		buffer[i] = odp_buffer_alloc(pool[i]);

		if (buffer[i] == ODP_BUFFER_INVALID)
			break;

		CU_ASSERT_FATAL(odp_buffer_pool(buffer[i]) == pool[i]);

		ev = odp_buffer_to_event(buffer[i]);
		CU_ASSERT(odp_buffer_from_event(ev) == buffer[i]);
		CU_ASSERT(odp_event_type(ev) == ODP_EVENT_BUFFER);

		addr = odp_buffer_addr(buffer[i]);
		CU_ASSERT(((uintptr_t)addr % align) == 0);

		/* Write buffer data */
		memset(addr, 0, size);
	}

	num_buf = i;
	CU_ASSERT(num_buf == num_pool);

	if (num_buf)
		odp_buffer_free_multi(buffer, num_buf);

	for (i = 0; i < num_pool; i++)
		CU_ASSERT(odp_pool_destroy(pool[i]) == 0);
}

static void buffer_test_pool_alloc_free(void)
{
	test_pool_alloc_free(&default_param);
}

static void buffer_test_pool_alloc_free_min_cache(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.cache_size = pool_capa.buf.min_cache_size;
	test_pool_alloc_free(&param);
}

static void buffer_test_pool_alloc_free_max_cache(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.cache_size = pool_capa.buf.max_cache_size;
	test_pool_alloc_free(&param);
}

static void buffer_test_pool_alloc_free_multi(void)
{
	test_pool_alloc_free_multi(&default_param);
}

static void buffer_test_pool_alloc_free_multi_min_cache(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.cache_size = pool_capa.buf.min_cache_size;
	test_pool_alloc_free_multi(&param);
}

static void buffer_test_pool_alloc_free_multi_max_cache(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.cache_size = pool_capa.buf.max_cache_size;
	test_pool_alloc_free_multi(&param);
}

static void buffer_test_pool_single_pool(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	test_pool_single_pool(&param);
}

static void buffer_test_pool_single_pool_min_cache(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.cache_size = pool_capa.buf.min_cache_size;
	test_pool_single_pool(&param);
}

static void buffer_test_pool_single_pool_max_cache(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.cache_size = pool_capa.buf.max_cache_size;
	test_pool_single_pool(&param);
}

static void buffer_test_pool_two_pools(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	test_pool_two_pools(&param);
}

static void buffer_test_pool_two_pools_min_cache(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.cache_size = pool_capa.buf.min_cache_size;
	test_pool_two_pools(&param);
}

static void buffer_test_pool_two_pools_max_cache(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.cache_size = pool_capa.buf.max_cache_size;
	test_pool_two_pools(&param);
}

static void buffer_test_pool_max_pools(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	test_pool_max_pools(&param);
}

static void buffer_test_pool_max_pools_min_cache(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.cache_size = pool_capa.buf.min_cache_size;
	test_pool_max_pools(&param);
}

static void buffer_test_pool_max_pools_max_cache(void)
{
	odp_pool_param_t param;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.cache_size = pool_capa.buf.max_cache_size;
	test_pool_max_pools(&param);
}

static void buffer_test_user_area(void)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	uint32_t i, num;
	void *addr;
	void *prev = NULL;
	uint32_t num_alloc = 0;
	uint32_t size = 1024;
	const uint32_t max_size = pool_capa.buf.max_uarea_size;

	if (max_size == 0) {
		ODPH_DBG("Buffer user area not supported\n");
		return;
	}

	if (size > max_size)
		size = max_size;

	memcpy(&param, &default_param, sizeof(odp_pool_param_t));
	param.buf.uarea_size = size;

	num = param.buf.num;

	odp_buffer_t buffer[num];

	pool = odp_pool_create("test_user_area", &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < num; i++) {
		buffer[i] = odp_buffer_alloc(pool);

		if (buffer[i] == ODP_BUFFER_INVALID)
			break;
		num_alloc++;

		addr = odp_buffer_user_area(buffer[i]);
		CU_ASSERT_FATAL(addr != NULL);
		CU_ASSERT(prev != addr);

		prev = addr;
		memset(addr, 0, size);
	}

	CU_ASSERT(i == num);

	if (num_alloc)
		odp_buffer_free_multi(buffer, num_alloc);

	CU_ASSERT_FATAL(odp_pool_destroy(pool) == 0);
}

odp_testinfo_t buffer_suite[] = {
	ODP_TEST_INFO(buffer_test_pool_alloc_free),
	ODP_TEST_INFO(buffer_test_pool_alloc_free_min_cache),
	ODP_TEST_INFO(buffer_test_pool_alloc_free_max_cache),
	ODP_TEST_INFO(buffer_test_pool_alloc_free_multi),
	ODP_TEST_INFO(buffer_test_pool_alloc_free_multi_min_cache),
	ODP_TEST_INFO(buffer_test_pool_alloc_free_multi_max_cache),
	ODP_TEST_INFO(buffer_test_pool_single_pool),
	ODP_TEST_INFO(buffer_test_pool_single_pool_min_cache),
	ODP_TEST_INFO(buffer_test_pool_single_pool_max_cache),
	ODP_TEST_INFO(buffer_test_pool_two_pools),
	ODP_TEST_INFO(buffer_test_pool_two_pools_min_cache),
	ODP_TEST_INFO(buffer_test_pool_two_pools_max_cache),
	ODP_TEST_INFO(buffer_test_pool_max_pools),
	ODP_TEST_INFO(buffer_test_pool_max_pools_min_cache),
	ODP_TEST_INFO(buffer_test_pool_max_pools_max_cache),
	ODP_TEST_INFO(buffer_test_user_area),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t buffer_suites[] = {
	{"buffer tests", buffer_suite_init, NULL, buffer_suite},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(buffer_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp.h>
#include "odp_cunit_common.h"

/* Helper macro for CU_TestInfo initialization */
#define _CU_TEST_INFO(test_func) {#test_func, test_func}

static odp_pool_t raw_pool;
static odp_buffer_t raw_buffer = ODP_BUFFER_INVALID;
static const size_t raw_buffer_size = 1500;

static int buffer_suite_init(void)
{
	odp_pool_param_t params = {
			.buf = {
				.size  = raw_buffer_size,
				.align = ODP_CACHE_LINE_SIZE,
				.num   = 100,
			},
			.type  = ODP_POOL_BUFFER,
	};

	raw_pool = odp_pool_create("raw_pool", ODP_SHM_INVALID, &params);
	if (raw_pool == ODP_POOL_INVALID)
		return -1;
	raw_buffer = odp_buffer_alloc(raw_pool);
	if (raw_buffer == ODP_BUFFER_INVALID)
		return -1;
	return 0;
}

static int buffer_suite_term(void)
{
	odp_buffer_free(raw_buffer);
	if (odp_pool_destroy(raw_pool) != 0)
		return -1;
	return 0;
}

static void buffer_test_pool_alloc(void)
{
	odp_pool_t pool;
	const int num = 3;
	const size_t size = 1500;
	odp_buffer_t buffer[num];
	odp_event_t ev;
	int index;
	char wrong_type = 0, wrong_size = 0;
	odp_pool_param_t params = {
			.buf = {
				.size  = size,
				.align = ODP_CACHE_LINE_SIZE,
				.num   = num,
			},
			.type  = ODP_POOL_BUFFER,
	};

	pool = odp_pool_create("buffer_pool_alloc", ODP_SHM_INVALID, &params);
	odp_pool_print(pool);

	/* Try to allocate num items from the pool */
	for (index = 0; index < num; index++) {
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
	}

	/* Check that the pool had at least num items */
	CU_ASSERT(index == num);
	/* index points out of buffer[] or it point to an invalid buffer */
	index--;

	/* Check that the pool had correct buffers */
	CU_ASSERT(wrong_type == 0);
	CU_ASSERT(wrong_size == 0);

	for (; index >= 0; index--)
		odp_buffer_free(buffer[index]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void buffer_test_pool_free(void)
{
	odp_pool_t pool;
	odp_buffer_t buffer;
	odp_pool_param_t params = {
			.buf = {
				.size  = 64,
				.align = ODP_CACHE_LINE_SIZE,
				.num   = 1,
			},
			.type  = ODP_POOL_BUFFER,
	};

	pool = odp_pool_create("buffer_pool_free", ODP_SHM_INVALID, &params);

	/* Allocate the only buffer from the pool */
	buffer = odp_buffer_alloc(pool);
	CU_ASSERT_FATAL(buffer != ODP_BUFFER_INVALID);

	/* Pool should have only one buffer */
	CU_ASSERT_FATAL(odp_buffer_alloc(pool) == ODP_BUFFER_INVALID)

	odp_buffer_free(buffer);

	/* Check that the buffer was returned back to the pool */
	buffer = odp_buffer_alloc(pool);
	CU_ASSERT_FATAL(buffer != ODP_BUFFER_INVALID);

	odp_buffer_free(buffer);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void buffer_test_management_basic(void)
{
	odp_event_t ev = odp_buffer_to_event(raw_buffer);

	CU_ASSERT(odp_buffer_is_valid(raw_buffer) == 1);
	CU_ASSERT(odp_buffer_pool(raw_buffer) != ODP_POOL_INVALID);
	CU_ASSERT(odp_event_type(ev) == ODP_EVENT_BUFFER);
	CU_ASSERT(odp_buffer_size(raw_buffer) >= raw_buffer_size);
	CU_ASSERT(odp_buffer_addr(raw_buffer) != NULL);
	odp_buffer_print(raw_buffer);
	CU_ASSERT(odp_buffer_to_u64(raw_buffer) !=
		  odp_buffer_to_u64(ODP_BUFFER_INVALID));
	CU_ASSERT(odp_event_to_u64(ev) != odp_event_to_u64(ODP_EVENT_INVALID));
}

static CU_TestInfo buffer_suite[] = {
	_CU_TEST_INFO(buffer_test_pool_alloc),
	_CU_TEST_INFO(buffer_test_pool_free),
	_CU_TEST_INFO(buffer_test_management_basic),
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo buffer_suites[] = {
	{ .pName = "buffer tests",
			.pTests = buffer_suite,
			.pInitFunc = buffer_suite_init,
			.pCleanupFunc = buffer_suite_term,
	},
	CU_SUITE_INFO_NULL,
};

static int buffer_main(void)
{
	return odp_cunit_run(buffer_suites);
}

/* the following main function will be separated when lib is created */
int main(void)
{
	return buffer_main();
}

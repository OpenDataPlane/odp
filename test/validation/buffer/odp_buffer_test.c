/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp_buffer_tests.h"

static odp_buffer_pool_t raw_pool;
static odp_buffer_t raw_buffer = ODP_BUFFER_INVALID;
static const size_t raw_buffer_size = 1500;

int buffer_testsuite_init(void)
{
	odp_buffer_pool_param_t params = {
			.buf_size  = raw_buffer_size,
			.buf_align = ODP_CACHE_LINE_SIZE,
			.num_bufs  = 100,
			.buf_type  = ODP_BUFFER_TYPE_RAW,
	};

	raw_pool = odp_buffer_pool_create("raw_pool", ODP_SHM_INVALID, &params);
	if (raw_pool == ODP_BUFFER_POOL_INVALID)
		return -1;
	raw_buffer = odp_buffer_alloc(raw_pool);
	if (raw_buffer == ODP_BUFFER_INVALID)
		return -1;
	return 0;
}

int buffer_testsuite_finalize(void)
{
	odp_buffer_free(raw_buffer);
	if (odp_buffer_pool_destroy(raw_pool) != 0)
		return -1;
	return 0;
}

static void buffer_management_basic(void)
{
	odp_event_t ev = odp_buffer_to_event(raw_buffer);

	CU_ASSERT(odp_buffer_is_valid(raw_buffer) == 1);
	CU_ASSERT(odp_buffer_pool(raw_buffer) != ODP_BUFFER_POOL_INVALID);
	CU_ASSERT(odp_event_type(ev) == ODP_EVENT_BUFFER);
	CU_ASSERT(odp_buffer_size(raw_buffer) >= raw_buffer_size);
	CU_ASSERT(odp_buffer_addr(raw_buffer) != NULL);
	odp_buffer_print(raw_buffer);
}

CU_TestInfo buffer_tests[] = {
	_CU_TEST_INFO(buffer_management_basic),
	CU_TEST_INFO_NULL,
};

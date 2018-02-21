/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "config.h"

#include <odp_api.h>
#include "odp_cunit_common.h"
#include "pool.h"

#define PKT_LEN 400
#define PKT_NUM 500

static const int default_buffer_size = 1500;
static const int default_buffer_num = 1000;

static void pool_create_destroy(odp_pool_param_t *param)
{
	odp_pool_t pool;

	pool = odp_pool_create(NULL, param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	CU_ASSERT(odp_pool_to_u64(pool) !=
		  odp_pool_to_u64(ODP_POOL_INVALID));
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

void pool_test_create_destroy_buffer(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type      = ODP_POOL_BUFFER,
	param.buf.size  = default_buffer_size;
	param.buf.align = ODP_CACHE_LINE_SIZE;
	param.buf.num   = default_buffer_num;

	pool_create_destroy(&param);
}

void pool_test_create_destroy_packet(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_PACKET;
	param.pkt.len = default_buffer_size;
	param.pkt.num = default_buffer_num;

	pool_create_destroy(&param);
}

void pool_test_create_destroy_timeout(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_TIMEOUT;
	param.tmo.num = default_buffer_num;

	pool_create_destroy(&param);
}

void pool_test_lookup_info_print(void)
{
	odp_pool_t pool;
	const char pool_name[] = "pool_for_lookup_test";
	odp_pool_info_t info;
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type      = ODP_POOL_BUFFER;
	param.buf.size  = default_buffer_size;
	param.buf.align = ODP_CACHE_LINE_SIZE;
	param.buf.num   = default_buffer_num;

	pool = odp_pool_create(pool_name, &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	pool = odp_pool_lookup(pool_name);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	CU_ASSERT_FATAL(odp_pool_info(pool, &info) == 0);
	CU_ASSERT(strncmp(pool_name, info.name, sizeof(pool_name)) == 0);
	CU_ASSERT(param.buf.size <= info.params.buf.size);
	CU_ASSERT(param.buf.align <= info.params.buf.align);
	CU_ASSERT(param.buf.num <= info.params.buf.num);
	CU_ASSERT(param.type == info.params.type);

	odp_pool_print(pool);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

void pool_test_alloc_packet(void)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	uint32_t i, num;
	odp_packet_t pkt[PKT_NUM];

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_PACKET,
	param.pkt.num = PKT_NUM;
	param.pkt.len = PKT_LEN;

	pool = odp_pool_create(NULL, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	num = 0;

	for (i = 0; i < PKT_NUM; i++) {
		pkt[num] = odp_packet_alloc(pool, PKT_LEN);
		CU_ASSERT(pkt[num] != ODP_PACKET_INVALID);

		if (pkt[num] != ODP_PACKET_INVALID)
			num++;
	}

	for (i = 0; i < num; i++)
		odp_packet_free(pkt[i]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

void pool_test_alloc_packet_subparam(void)
{
	odp_pool_t pool;
	odp_pool_capability_t capa;
	odp_pool_param_t param;
	uint32_t i, j, num, num_sub;
	odp_packet_t pkt[PKT_NUM];

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);
	num_sub = capa.pkt.max_num_subparam;

	CU_ASSERT_FATAL(num_sub <= ODP_POOL_MAX_SUBPARAMS);

	odp_pool_param_init(&param);

	param.type             = ODP_POOL_PACKET,
	param.pkt.num          = PKT_NUM;
	param.pkt.len          = PKT_LEN;
	param.pkt.num_subparam = num_sub;

	for (i = 0; i < num_sub; i++) {
		param.pkt.sub[i].num = PKT_NUM;
		param.pkt.sub[i].len = PKT_LEN + (i * 100);
	}

	pool = odp_pool_create(NULL, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	num = 0;

	for (i = 0; i < PKT_NUM; i++) {
		pkt[num] = odp_packet_alloc(pool, PKT_LEN);
		CU_ASSERT(pkt[num] != ODP_PACKET_INVALID);

		if (pkt[num] != ODP_PACKET_INVALID)
			num++;
	}

	for (i = 0; i < num; i++)
		odp_packet_free(pkt[i]);

	for (j = 0; j < num_sub; j++) {
		num = 0;

		for (i = 0; i < param.pkt.sub[j].num; i++) {
			pkt[num] = odp_packet_alloc(pool, param.pkt.sub[j].len);
			CU_ASSERT(pkt[num] != ODP_PACKET_INVALID);

			if (pkt[num] != ODP_PACKET_INVALID)
				num++;
		}

		for (i = 0; i < num; i++)
			odp_packet_free(pkt[i]);
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

void pool_test_info_packet(void)
{
	odp_pool_t pool;
	odp_pool_info_t info;
	odp_pool_param_t param;
	const char pool_name[] = "test_pool_name";

	odp_pool_param_init(&param);

	param.type     = ODP_POOL_PACKET;
	param.pkt.num  = PKT_NUM;
	param.pkt.len  = PKT_LEN;

	pool = odp_pool_create(pool_name, &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	CU_ASSERT_FATAL(odp_pool_info(pool, &info) == 0);

	CU_ASSERT(strncmp(pool_name, info.name, sizeof(pool_name)) == 0);
	CU_ASSERT(info.params.type    == ODP_POOL_PACKET);
	CU_ASSERT(info.params.pkt.num == param.pkt.num);
	CU_ASSERT(info.params.pkt.len == param.pkt.len);
	CU_ASSERT(info.pkt.max_num    >= param.pkt.num);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_test_info_data_range(void)
{
	odp_pool_t pool;
	odp_pool_info_t info;
	odp_pool_param_t param;
	odp_packet_t pkt[PKT_NUM];
	uint32_t i, num;
	uintptr_t pool_len;

	odp_pool_param_init(&param);

	param.type     = ODP_POOL_PACKET;
	param.pkt.num  = PKT_NUM;
	param.pkt.len  = PKT_LEN;

	pool = odp_pool_create(NULL, &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	CU_ASSERT_FATAL(odp_pool_info(pool, &info) == 0);

	pool_len = info.max_data_addr - info.min_data_addr + 1;
	CU_ASSERT(pool_len >= PKT_NUM * PKT_LEN);

	num = 0;

	for (i = 0; i < PKT_NUM; i++) {
		pkt[num] = odp_packet_alloc(pool, PKT_LEN);
		CU_ASSERT(pkt[num] != ODP_PACKET_INVALID);

		if (pkt[num] != ODP_PACKET_INVALID)
			num++;
	}

	for (i = 0; i < num; i++) {
		uintptr_t pkt_data, pkt_data_end;
		uint32_t offset = 0, seg_len;
		uint32_t pkt_len = odp_packet_len(pkt[i]);

		while (offset < pkt_len) {
			pkt_data = (uintptr_t)odp_packet_offset(pkt[i], offset,
								&seg_len, NULL);
			pkt_data_end = pkt_data + seg_len - 1;
			CU_ASSERT((pkt_data >= info.min_data_addr) &&
				  (pkt_data_end <= info.max_data_addr));
			offset += seg_len;
		}

		odp_packet_free(pkt[i]);
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

odp_testinfo_t pool_suite[] = {
	ODP_TEST_INFO(pool_test_create_destroy_buffer),
	ODP_TEST_INFO(pool_test_create_destroy_packet),
	ODP_TEST_INFO(pool_test_create_destroy_timeout),
	ODP_TEST_INFO(pool_test_alloc_packet),
	ODP_TEST_INFO(pool_test_alloc_packet_subparam),
	ODP_TEST_INFO(pool_test_info_packet),
	ODP_TEST_INFO(pool_test_lookup_info_print),
	ODP_TEST_INFO(pool_test_info_data_range),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t pool_suites[] = {
	{ .pName = "Pool tests",
			.pTests = pool_suite,
	},
	ODP_SUITE_INFO_NULL,
};

int pool_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(pool_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

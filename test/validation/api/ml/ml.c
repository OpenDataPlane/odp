/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include "odp_cunit_common.h"

#define UAREA     0xaa
#define NUM_COMPL 10u
#define COMPL_POOL_NAME "ML compl pool"

typedef struct global_t {
	int disabled;
	uint32_t num_compl;
	odp_ml_capability_t ml_capa;
} global_t;

typedef struct {
	uint32_t count;
	uint8_t mark[NUM_COMPL];
} uarea_init_t;

static global_t global;

static int ml_suite_init(void)
{
	memset(&global, 0, sizeof(global_t));

	if (odp_ml_capability(&global.ml_capa)) {
		ODPH_ERR("ML capability failed\n");
		return -1;
	}

	if (global.ml_capa.max_models == 0) {
		global.disabled = 1;
		ODPH_DBG("ML test disabled\n");
		return 0;
	}

	global.num_compl = ODPH_MIN(NUM_COMPL, global.ml_capa.pool.max_num);

	return 0;
}

static int check_ml_support(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void test_ml_capability(void)
{
	odp_ml_capability_t ml_capa;

	memset(&ml_capa, 0, sizeof(odp_ml_capability_t));
	CU_ASSERT(odp_ml_capability(&ml_capa) == 0);

	if (ml_capa.max_models == 0)
		return;

	CU_ASSERT(ml_capa.max_model_size > 0);
	CU_ASSERT(ml_capa.max_models_loaded > 0);
	CU_ASSERT(ml_capa.max_inputs > 0);
	CU_ASSERT(ml_capa.max_outputs > 0);
	CU_ASSERT(ml_capa.max_segs_per_input > 0);
	CU_ASSERT(ml_capa.max_segs_per_output > 0);
	CU_ASSERT(ml_capa.min_input_align > 0);
	CU_ASSERT(ml_capa.min_output_align > 0);

	if ((ml_capa.load.compl_mode_mask | ml_capa.run.compl_mode_mask) &
	    ODP_ML_COMPL_MODE_EVENT) {
		odp_pool_capability_t pool_capa;

		CU_ASSERT_FATAL(odp_pool_capability(&pool_capa) == 0);

		CU_ASSERT(ml_capa.pool.max_pools > 0);
		CU_ASSERT(ml_capa.pool.max_pools <= pool_capa.max_pools);
		CU_ASSERT(ml_capa.pool.max_num > 0);
		CU_ASSERT(ml_capa.pool.max_cache_size >= ml_capa.pool.min_cache_size);
	}

	CU_ASSERT(ml_capa.load.compl_mode_mask);
	CU_ASSERT(ml_capa.run.compl_mode_mask);

	if (ml_capa.load.compl_mode_mask & ODP_ML_COMPL_MODE_EVENT)
		CU_ASSERT(ml_capa.load.compl_queue_plain || ml_capa.load.compl_queue_sched);

	if (ml_capa.run.compl_mode_mask & ODP_ML_COMPL_MODE_EVENT)
		CU_ASSERT(ml_capa.run.compl_queue_plain || ml_capa.run.compl_queue_sched);
}

static void test_ml_param(uint8_t fill)
{
	odp_ml_config_t config;
	odp_ml_model_param_t model_param;
	odp_ml_compl_pool_param_t pool_param;
	odp_ml_compl_param_t compl_param;
	odp_ml_run_param_t run_param;

	memset(&config, fill, sizeof(config));
	odp_ml_config_init(&config);
	CU_ASSERT(config.max_models_created == 1);
	CU_ASSERT(config.max_models_loaded == 1);
	CU_ASSERT(config.load_mode_mask == 0);
	CU_ASSERT(config.run_mode_mask == 0);

	memset(&model_param, fill, sizeof(model_param));
	odp_ml_model_param_init(&model_param);
	CU_ASSERT(model_param.max_compl_id == 0);
	CU_ASSERT(!model_param.extra_stat_enable);
	CU_ASSERT(model_param.extra_param == NULL);
	CU_ASSERT(model_param.extra_info.num_inputs == 0);
	CU_ASSERT(model_param.extra_info.num_outputs == 0);
	CU_ASSERT(model_param.extra_info.input_format == NULL);
	CU_ASSERT(model_param.extra_info.output_format == NULL);

	memset(&pool_param, fill, sizeof(pool_param));
	odp_ml_compl_pool_param_init(&pool_param);
	CU_ASSERT(pool_param.uarea_size == 0);
	CU_ASSERT(pool_param.uarea_init.args == NULL);
	CU_ASSERT(pool_param.uarea_init.init_fn == NULL);
	CU_ASSERT(pool_param.cache_size <= global.ml_capa.pool.max_cache_size);
	CU_ASSERT(pool_param.cache_size >= global.ml_capa.pool.min_cache_size);

	memset(&compl_param, fill, sizeof(compl_param));
	odp_ml_compl_param_init(&compl_param);
	CU_ASSERT(compl_param.user_ptr == NULL);

	memset(&run_param, fill, sizeof(run_param));
	odp_ml_run_param_init(&run_param);
	CU_ASSERT(run_param.batch_size == 0);
	CU_ASSERT(run_param.result == NULL);
}

static void test_ml_param_init(void)
{
	test_ml_param(0x00);
	test_ml_param(0xff);
}

static void test_ml_debug(void)
{
	odp_ml_print();
}

static void ml_compl_pool_create_max_pools(void)
{
	int ret;
	uint32_t i, j;
	odp_ml_compl_pool_param_t ml_pool_param;
	uint32_t max_pools = global.ml_capa.pool.max_pools;
	odp_pool_t compl_pools[max_pools];

	odp_ml_compl_pool_param_init(&ml_pool_param);
	ml_pool_param.num = global.num_compl;
	for (i = 0; i < max_pools; i++) {
		compl_pools[i] = odp_ml_compl_pool_create(NULL, &ml_pool_param);

		if (compl_pools[i] == ODP_POOL_INVALID)
			break;
	}

	CU_ASSERT(i == max_pools);

	/* Destroy the created valid pools */
	for (j = 0; j < i; j++) {
		ret = odp_pool_destroy(compl_pools[j]);
		CU_ASSERT(ret == 0);

		if (ret == -1)
			ODPH_ERR("ML completion pool destroy failed: %u / %u\n", j, i);
	}
}

static void compl_pool_info(void)
{
	odp_pool_t pool;
	odp_pool_t compl_pool;
	odp_pool_info_t pool_info;
	odp_ml_compl_pool_param_t pool_param;

	/* Create an ML job completion pool */
	odp_ml_compl_pool_param_init(&pool_param);
	pool_param.num = global.num_compl;

	compl_pool = odp_ml_compl_pool_create(COMPL_POOL_NAME, &pool_param);
	CU_ASSERT_FATAL(compl_pool != ODP_POOL_INVALID);

	/* Verify info about the created ML completion pool compl_pool */
	pool = odp_pool_lookup(COMPL_POOL_NAME);
	CU_ASSERT(pool == compl_pool);

	memset(&pool_info, 0x66, sizeof(odp_pool_info_t));
	CU_ASSERT_FATAL(odp_pool_info(compl_pool, &pool_info) == 0);

	CU_ASSERT(!strcmp(pool_info.name, COMPL_POOL_NAME));
	CU_ASSERT(pool_info.pool_ext == 0);
	CU_ASSERT(pool_info.type == ODP_POOL_ML_COMPL);
	CU_ASSERT(pool_info.ml_pool_param.num == NUM_COMPL);
	CU_ASSERT(pool_info.ml_pool_param.uarea_size == 0);
	CU_ASSERT(pool_info.ml_pool_param.cache_size == pool_param.cache_size);

	CU_ASSERT_FATAL(odp_pool_destroy(compl_pool) == 0);
}

static void compl_alloc_max(void)
{
	uint64_t u64;
	odp_event_t event;
	odp_pool_t compl_pool;
	odp_ml_compl_pool_param_t pool_param;
	const int num = ODPH_MIN(global.ml_capa.pool.max_num, 1000000u);
	odp_ml_compl_t *compl = malloc(num * sizeof(odp_ml_compl_t));

	CU_ASSERT_FATAL(compl != NULL);

	/* Create an ML job completion pool */
	odp_ml_compl_pool_param_init(&pool_param);
	pool_param.num = num;

	compl_pool = odp_ml_compl_pool_create(COMPL_POOL_NAME, &pool_param);
	CU_ASSERT_FATAL(compl_pool != ODP_POOL_INVALID);

	for (int i = 0; i < num; i++) {
		compl[i] = odp_ml_compl_alloc(compl_pool);
		CU_ASSERT_FATAL(compl[i] != ODP_ML_COMPL_INVALID);

		u64 = odp_ml_compl_to_u64(compl[i]);
		CU_ASSERT(u64 != odp_ml_compl_to_u64(ODP_ML_COMPL_INVALID));

		event = odp_ml_compl_to_event(compl[i]);
		CU_ASSERT(odp_event_type(event) == ODP_EVENT_ML_COMPL);
	}

	for (int i = 0; i < num; i++)
		odp_ml_compl_free(compl[i]);

	free(compl);

	CU_ASSERT_FATAL(odp_pool_destroy(compl_pool) == 0);
}

static void compl_pool_lookup(void)
{
	odp_pool_t pool, pool_a, pool_b;
	odp_ml_compl_pool_param_t pool_param;

	/* Create an ML job completion pool */
	odp_ml_compl_pool_param_init(&pool_param);
	pool_param.num = global.num_compl;

	pool_a = odp_ml_compl_pool_create(COMPL_POOL_NAME, &pool_param);
	CU_ASSERT_FATAL(pool_a != ODP_POOL_INVALID);

	pool = odp_pool_lookup(COMPL_POOL_NAME);
	CU_ASSERT(pool == pool_a);

	/* Second pool with the same name */
	pool_b = odp_ml_compl_pool_create(COMPL_POOL_NAME, &pool_param);
	CU_ASSERT_FATAL(pool_b != ODP_POOL_INVALID);

	pool = odp_pool_lookup(COMPL_POOL_NAME);
	CU_ASSERT(pool == pool_a || pool == pool_b);

	CU_ASSERT(odp_pool_destroy(pool_a) == 0);
	CU_ASSERT(odp_pool_destroy(pool_b) == 0);
}

static int check_event_user_area(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (((global.ml_capa.load.compl_mode_mask | global.ml_capa.run.compl_mode_mask) &
	     ODP_ML_COMPL_MODE_EVENT) &&
	    (global.ml_capa.pool.max_uarea_size > 0))
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static void test_ml_compl_user_area(void)
{
	uint32_t i;
	void *addr;
	void *prev;
	odp_pool_t pool;
	odp_ml_compl_pool_param_t pool_param;
	uint32_t size = global.ml_capa.pool.max_uarea_size;
	uint32_t num = global.num_compl;
	odp_ml_compl_t compl_evs[num];

	odp_ml_compl_pool_param_init(&pool_param);
	pool_param.num = num;
	pool_param.uarea_size = size;
	pool = odp_ml_compl_pool_create(NULL, &pool_param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	prev = NULL;
	for (i = 0; i < num; i++) {
		odp_event_t ev;
		int flag = 0;

		compl_evs[i] = odp_ml_compl_alloc(pool);

		if (compl_evs[i] == ODP_ML_COMPL_INVALID)
			break;

		addr = odp_ml_compl_user_area(compl_evs[i]);

		CU_ASSERT_FATAL(addr != NULL);
		CU_ASSERT(prev != addr);

		memset(addr, 0, size);

		ev = odp_ml_compl_to_event(compl_evs[i]);
		odp_event_user_flag_set(ev, 1);
		CU_ASSERT(odp_event_user_area(ev) == addr);
		CU_ASSERT(odp_event_user_area_and_flag(ev, &flag) == addr);
		CU_ASSERT(flag < 0);

		prev = addr;
	}
	CU_ASSERT(i == num);

	for (uint32_t j = 0; j < i; j++)
		odp_ml_compl_free(compl_evs[j]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static int check_event_user_area_init(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.ml_capa.pool.max_uarea_size > 0 && global.ml_capa.pool.uarea_persistence)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static void init_event_uarea(void *uarea, uint32_t size, void *args, uint32_t index)
{
	uarea_init_t *data = args;

	data->count++;
	data->mark[index] = 1;
	memset(uarea, UAREA, size);
}

static void test_ml_compl_user_area_init(void)
{
	odp_ml_compl_pool_param_t pool_param;
	uint32_t num = global.num_compl, i;
	odp_pool_t pool;
	uarea_init_t data;
	odp_ml_compl_t compl_evs[num];
	uint8_t *uarea;

	memset(&data, 0, sizeof(uarea_init_t));
	odp_ml_compl_pool_param_init(&pool_param);
	pool_param.uarea_init.init_fn = init_event_uarea;
	pool_param.uarea_init.args = &data;
	pool_param.num = num;
	pool_param.uarea_size = 1;
	pool = odp_ml_compl_pool_create(NULL, &pool_param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	CU_ASSERT(data.count == num);

	for (i = 0; i < num; i++) {
		CU_ASSERT(data.mark[i] == 1);

		compl_evs[i] = odp_ml_compl_alloc(pool);

		CU_ASSERT(compl_evs[i] != ODP_ML_COMPL_INVALID);

		if (compl_evs[i] == ODP_ML_COMPL_INVALID)
			break;

		uarea = odp_ml_compl_user_area(compl_evs[i]);

		CU_ASSERT(*uarea == UAREA);
	}

	for (uint32_t j = 0; j < i; j++)
		odp_ml_compl_free(compl_evs[j]);

	odp_pool_destroy(pool);
}

static void test_ml_fp32_to_uint8(void)
{
	uint8_t u8[8];
	float fp[8] = {-20.f, -16.4f, -14.6f, -12.5f, 0, 31.4f, 80.f, 96.3f};
	uint8_t expected[8] = {0, 0, 4, 10, 43, 127, 255, 255};
	float scale = 0.3746f;
	uint8_t zero_point = 43;

	odp_ml_fp32_to_uint8(u8, fp, 8, scale, zero_point);
	for (uint32_t i = 0; i < 8; i++)
		CU_ASSERT(u8[i] == expected[i]);
}

static void test_ml_fp32_from_uint8(void)
{
	float fp[4];
	float scale = 0.4f;
	uint8_t zero_point = 43;
	uint8_t u8[4] = {0, 43, 145, 255};
	float expected[4] = {-17.2f, 0.0f, 40.8f, 84.8f};

	odp_ml_fp32_from_uint8(fp, u8, 4, scale, zero_point);
	for (uint32_t i = 0; i < 4; i++)
		CU_ASSERT(fp[i] == expected[i]);
}

static void test_ml_fp32_to_int8(void)
{
	int8_t i8[5];
	float scale = 0.0223f;
	int8_t zero_point = 0;
	float fp32[5] = {-3.4f, -2.5f, 0, 1.4f, 2.9f};
	int8_t i8_expected[5] = {-127, -112, 0, 63, 127};

	odp_ml_fp32_to_int8(i8, fp32, 5, scale, zero_point);

	for (uint32_t i = 0; i < 5; i++)
		CU_ASSERT(i8[i] == i8_expected[i]);
}

static void test_ml_fp32_to_int8_positive_zp(void)
{
	int8_t i8[6];
	float scale = 0.0223f;
	int8_t zero_point = 56;
	float fp32[6] = {-4.1f, -3.4f, -2.5f, 0, 1.4f, 2.9f};
	int8_t i8_expected[6] = {-127, -96, -56, 56, 119, 127};

	odp_ml_fp32_to_int8(i8, fp32, 6, scale, zero_point);

	for (uint32_t i = 0; i < 6; i++)
		CU_ASSERT(i8[i] == i8_expected[i]);
}

static void test_ml_fp32_to_int8_negative_zp(void)
{
	int8_t i8[6];
	float scale = 0.0223f;
	int8_t zero_point = -56;
	float fp32[6] = {-3.4f, -2.5f, 0, 1.4f, 2.9f, 4.1f};
	int8_t i8_expected[6] = {-127, -127, -56, 7, 74, 127};

	odp_ml_fp32_to_int8(i8, fp32, 6, scale, zero_point);

	for (uint32_t i = 0; i < 6; i++)
		CU_ASSERT(i8[i] == i8_expected[i]);
}

static void test_ml_fp32_from_int8(void)
{
	float fp32[6];
	float scale = 0.05f;
	int8_t zero_point = 56;
	int8_t i8[6] = {-128, 46, 0, 56, 85, 127};
	float fp32_expected[6] = {-9.2f, -0.5f, -2.8f, 0.0f, 1.45f, 3.55f};

	odp_ml_fp32_from_int8(fp32, i8, 6, scale, zero_point);

	for (uint32_t i = 0; i < 6; i++)
		CU_ASSERT(fp32[i] == fp32_expected[i]);
}

static int approx_equal(double a, double b)
{
	const double tolerance = .01;

	if (a < 0 && b < 0) {
		a = -a;
		b = -b;
	}

	if (a < b) {
		double tmp = a;

		a = b;
		b = tmp;
	}

	return (a * (1 - tolerance) < b && a * (1 + tolerance) > b);
}

static void test_ml_fp32_fp16(void)
{
	float fp32[4];
	uint16_t fp16[4];
	float big = 1, small = 1;
	const float phi = 1.618033988749;

	fp32[0] = 0.0;
	fp32[1] = -0.0;
	memset(fp16, 1, sizeof(fp16));
	odp_ml_fp32_to_fp16(fp16, fp32, 2);
	memset(fp32, 1, sizeof(fp32));
	odp_ml_fp32_from_fp16(fp32, fp16, 2);
	CU_ASSERT(fp32[0] == 0);
	CU_ASSERT(fp32[1] == 0);

	/*
	 * 65504 is the largest normal number for fp16 with 5 exponent bits (IEEE 754-2008).
	 */
	while (big < 65504 / 2) {
		fp32[0] = big;
		fp32[1] = -big;
		fp32[2] = small;
		fp32[3] = -small;
		memset(fp16, 0, sizeof(fp16));
		odp_ml_fp32_to_fp16(fp16, fp32, 4);
		memset(fp32, 0, sizeof(fp32));
		odp_ml_fp32_from_fp16(fp32, fp16, 4);
		CU_ASSERT(approx_equal(fp32[0], big));
		CU_ASSERT(approx_equal(fp32[1], -big));
		CU_ASSERT(approx_equal(fp32[2], small));
		CU_ASSERT(approx_equal(fp32[3], -small));
		big *= phi;
		small /= phi;
	}
}

odp_testinfo_t ml_suite[] = {
	ODP_TEST_INFO(test_ml_capability),
	ODP_TEST_INFO_CONDITIONAL(test_ml_param_init, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_debug, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(ml_compl_pool_create_max_pools, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(compl_pool_info, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(compl_alloc_max, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(compl_pool_lookup, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_compl_user_area, check_event_user_area),
	ODP_TEST_INFO_CONDITIONAL(test_ml_compl_user_area_init, check_event_user_area_init),
	ODP_TEST_INFO_CONDITIONAL(test_ml_fp32_to_uint8, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_fp32_from_uint8, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_fp32_to_int8, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_fp32_to_int8_positive_zp, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_fp32_to_int8_negative_zp, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_fp32_from_int8, check_ml_support),
	ODP_TEST_INFO_CONDITIONAL(test_ml_fp32_fp16, check_ml_support),
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t ml_suites[] = {
	{"ML", ml_suite_init, NULL, ml_suite},
	ODP_SUITE_INFO_NULL
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(ml_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

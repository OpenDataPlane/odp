/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2020, Marvell
 * Copyright (c) 2020-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp_api.h>
#include "odp_cunit_common.h"
#include "test_common_macros.h"
#include <odp/helper/odph_api.h>

#define MAX_WORKERS 32

#define BUF_SIZE 1500
#define BUF_NUM  1000
#define TMO_NUM  1000
#define VEC_NUM  1000
#define VEC_LEN  32
#define PKT_LEN  400
#define PKT_NUM  500
#define ELEM_NUM 10
#define ELEM_SIZE 128
#define CACHE_SIZE 32
#define MAX_NUM_DEFAULT (10 * 1024 * 1024)
#define UAREA    0xaa

#define EXT_NUM_BUF        10
#define EXT_BUF_SIZE       2048
#define EXT_BUF_ALIGN      64
#define EXT_APP_HDR_SIZE   128
#define EXT_UAREA_SIZE     32
#define EXT_HEADROOM       16
#define MAGIC_U8           0x7a

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

typedef struct {
	odp_barrier_t init_barrier;
	odp_atomic_u32_t index;
	uint32_t nb_threads;
	odp_pool_t pool;
} global_shared_mem_t;

typedef struct {
	uint32_t count;
	uint8_t mark[ELEM_NUM];
} uarea_init_t;

static global_shared_mem_t *global_mem;

static odp_pool_capability_t global_pool_capa;
static odp_pool_param_t default_pool_param;
static odp_pool_ext_capability_t global_pool_ext_capa;

static void test_param_init(uint8_t fill)
{
	odp_pool_param_t param;

	memset(&param, fill, sizeof(param));
	odp_pool_param_init(&param);

	CU_ASSERT(param.uarea_init.init_fn == NULL);
	CU_ASSERT(param.uarea_init.args == NULL);

	CU_ASSERT(param.buf.uarea_size == 0);
	CU_ASSERT(param.buf.cache_size >= global_pool_capa.buf.min_cache_size &&
		  param.buf.cache_size <= global_pool_capa.buf.max_cache_size);

	CU_ASSERT(param.pkt.max_num == 0);
	CU_ASSERT(param.pkt.num_subparam == 0);
	CU_ASSERT(param.pkt.uarea_size == 0);
	CU_ASSERT(param.pkt.cache_size >= global_pool_capa.pkt.min_cache_size &&
		  param.pkt.cache_size <= global_pool_capa.pkt.max_cache_size);

	CU_ASSERT(param.tmo.uarea_size == 0);
	CU_ASSERT(param.tmo.cache_size >= global_pool_capa.tmo.min_cache_size &&
		  param.tmo.cache_size <= global_pool_capa.tmo.max_cache_size);

	CU_ASSERT(param.vector.uarea_size == 0);
	CU_ASSERT(param.vector.cache_size >= global_pool_capa.vector.min_cache_size &&
		  param.vector.cache_size <= global_pool_capa.vector.max_cache_size);
}

static void pool_test_param_init(void)
{
	test_param_init(0);
	test_param_init(0xff);
}

static void pool_create_destroy(odp_pool_param_t *param)
{
	odp_pool_t pool;

	pool = odp_pool_create(NULL, param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	CU_ASSERT(odp_pool_to_u64(pool) !=
		  odp_pool_to_u64(ODP_POOL_INVALID));
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_test_create_destroy_buffer(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type      = ODP_POOL_BUFFER;
	param.buf.size  = BUF_SIZE;
	param.buf.num   = BUF_NUM;

	pool_create_destroy(&param);
}

static void pool_test_create_destroy_packet(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_PACKET;
	param.pkt.len = PKT_LEN;
	param.pkt.num = PKT_NUM;

	pool_create_destroy(&param);
}

static void pool_test_create_destroy_timeout(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_TIMEOUT;
	param.tmo.num = TMO_NUM;

	pool_create_destroy(&param);
}

static void pool_test_create_destroy_vector(void)
{
	odp_pool_param_t param;
	odp_pool_capability_t capa;
	uint32_t max_num = VEC_NUM;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	CU_ASSERT_FATAL(capa.vector.max_pools > 0);

	if (capa.vector.max_num && capa.vector.max_num < max_num)
		max_num = capa.vector.max_num;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_VECTOR;
	param.vector.num = max_num;
	param.vector.max_size = capa.vector.max_size  < VEC_LEN ? capa.vector.max_size : VEC_LEN;

	pool_create_destroy(&param);
}

static int pool_check_buffer_uarea_init(void)
{
	if (global_pool_capa.buf.max_uarea_size == 0 || !global_pool_capa.buf.uarea_persistence)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pool_check_packet_uarea_init(void)
{
	if (global_pool_capa.pkt.max_uarea_size == 0 || !global_pool_capa.pkt.uarea_persistence)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pool_check_vector_uarea_init(void)
{
	if (global_pool_capa.vector.max_uarea_size == 0 ||
	    !global_pool_capa.vector.uarea_persistence)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pool_check_timeout_uarea_init(void)
{
	if (global_pool_capa.tmo.max_uarea_size == 0 || !global_pool_capa.tmo.uarea_persistence)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void init_event_uarea(void *uarea, uint32_t size, void *args, uint32_t index)
{
	uarea_init_t *data = args;

	data->count++;
	data->mark[index] = 1;
	memset(uarea, UAREA, size);
}

static void pool_test_buffer_uarea_init(void)
{
	odp_pool_param_t param;
	uint32_t num = MIN(global_pool_capa.buf.max_num, ELEM_NUM),
	size = MIN(global_pool_capa.buf.max_size, ELEM_SIZE), i;
	odp_pool_t pool;
	uarea_init_t data;
	odp_buffer_t bufs[num];
	uint8_t *uarea;

	memset(&data, 0, sizeof(uarea_init_t));
	odp_pool_param_init(&param);
	param.type = ODP_POOL_BUFFER;
	param.uarea_init.init_fn = init_event_uarea;
	param.uarea_init.args = &data;
	param.buf.num = num;
	param.buf.size = size;
	param.buf.uarea_size = 1;
	pool = odp_pool_create(NULL, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	CU_ASSERT(data.count == num);

	for (i = 0; i < num; i++) {
		CU_ASSERT(data.mark[i] == 1);

		bufs[i] = odp_buffer_alloc(pool);

		CU_ASSERT(bufs[i] != ODP_BUFFER_INVALID);

		if (bufs[i] == ODP_BUFFER_INVALID)
			break;

		uarea = odp_buffer_user_area(bufs[i]);

		CU_ASSERT(*uarea == UAREA);
	}

	odp_buffer_free_multi(bufs, i);
	odp_pool_destroy(pool);
}

static void pool_test_packet_uarea_init(void)
{
	odp_pool_param_t param;
	uint32_t num = MIN(global_pool_capa.pkt.max_num, ELEM_NUM),
	size = MIN(global_pool_capa.pkt.max_len, ELEM_SIZE), i;
	odp_pool_t pool;
	uarea_init_t data;
	odp_packet_t pkts[num];
	uint8_t *uarea;

	memset(&data, 0, sizeof(uarea_init_t));
	odp_pool_param_init(&param);
	param.type = ODP_POOL_PACKET;
	param.uarea_init.init_fn = init_event_uarea;
	param.uarea_init.args = &data;
	param.pkt.num = num;
	param.pkt.len = size;
	param.pkt.uarea_size = 1;
	pool = odp_pool_create(NULL, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	CU_ASSERT(data.count == num);

	for (i = 0; i < num; i++) {
		CU_ASSERT(data.mark[i] == 1);

		pkts[i] = odp_packet_alloc(pool, ELEM_SIZE);

		CU_ASSERT(pkts[i] != ODP_PACKET_INVALID);

		if (pkts[i] == ODP_PACKET_INVALID)
			break;

		uarea = odp_packet_user_area(pkts[i]);

		CU_ASSERT(*uarea == UAREA);
	}

	odp_packet_free_multi(pkts, i);
	odp_pool_destroy(pool);
}

static void pool_test_vector_uarea_init(void)
{
	odp_pool_param_t param;
	uint32_t num = MIN(global_pool_capa.vector.max_num, ELEM_NUM),
	size = MIN(global_pool_capa.vector.max_size, ELEM_NUM), i;
	odp_pool_t pool;
	uarea_init_t data;
	odp_packet_vector_t vecs[num];
	uint8_t *uarea;

	memset(&data, 0, sizeof(uarea_init_t));
	odp_pool_param_init(&param);
	param.type = ODP_POOL_VECTOR;
	param.uarea_init.init_fn = init_event_uarea;
	param.uarea_init.args = &data;
	param.vector.num = num;
	param.vector.max_size = size;
	param.vector.uarea_size = 1;
	pool = odp_pool_create(NULL, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	CU_ASSERT(data.count == num);

	for (i = 0; i < num; i++) {
		CU_ASSERT(data.mark[i] == 1);

		vecs[i] = odp_packet_vector_alloc(pool);

		CU_ASSERT(vecs[i] != ODP_PACKET_VECTOR_INVALID);

		if (vecs[i] == ODP_PACKET_VECTOR_INVALID)
			break;

		uarea = odp_packet_vector_user_area(vecs[i]);

		CU_ASSERT(*uarea == UAREA);
	}

	for (uint32_t j = 0; j < i; j++)
		odp_packet_vector_free(vecs[j]);

	odp_pool_destroy(pool);
}

static void pool_test_timeout_uarea_init(void)
{
	odp_pool_param_t param;
	uint32_t num = MIN(global_pool_capa.tmo.max_num, ELEM_NUM), i;
	odp_pool_t pool;
	uarea_init_t data;
	odp_timeout_t tmos[num];
	uint8_t *uarea;

	memset(&data, 0, sizeof(uarea_init_t));
	odp_pool_param_init(&param);
	param.type = ODP_POOL_TIMEOUT;
	param.uarea_init.init_fn = init_event_uarea;
	param.uarea_init.args = &data;
	param.tmo.num = num;
	param.tmo.uarea_size = 1;
	pool = odp_pool_create(NULL, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	CU_ASSERT(data.count == num);

	for (i = 0; i < num; i++) {
		CU_ASSERT(data.mark[i] == 1);

		tmos[i] = odp_timeout_alloc(pool);

		CU_ASSERT(tmos[i] != ODP_TIMEOUT_INVALID);

		if (tmos[i] == ODP_TIMEOUT_INVALID)
			break;

		uarea = odp_timeout_user_area(tmos[i]);

		CU_ASSERT(*uarea == UAREA);
	}

	for (uint32_t j = 0; j < i; j++)
		odp_timeout_free(tmos[j]);

	odp_pool_destroy(pool);
}

static void pool_test_lookup_info_print(void)
{
	odp_pool_t pool;
	const char pool_name[] = "pool_for_lookup_test";
	odp_pool_info_t info;
	odp_pool_param_t param;

	memset(&info, 0, sizeof(info));
	odp_pool_param_init(&param);

	param.type      = ODP_POOL_BUFFER;
	param.buf.size  = BUF_SIZE;
	param.buf.num   = BUF_NUM;

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
	odp_pool_print_all();

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_test_same_name(const odp_pool_param_t *param)
{
	odp_pool_t pool, pool_a, pool_b;
	const char *name = "same_name";

	pool_a = odp_pool_create(name, param);
	CU_ASSERT_FATAL(pool_a != ODP_POOL_INVALID);

	pool = odp_pool_lookup(name);
	CU_ASSERT(pool == pool_a);

	/* Second pool with the same name */
	pool_b = odp_pool_create(name, param);
	CU_ASSERT_FATAL(pool_b != ODP_POOL_INVALID);

	pool = odp_pool_lookup(name);
	CU_ASSERT(pool == pool_a || pool == pool_b);

	CU_ASSERT(odp_pool_destroy(pool_a) == 0);
	CU_ASSERT(odp_pool_destroy(pool_b) == 0);
}

static void pool_test_same_name_buf(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type     = ODP_POOL_BUFFER;
	param.buf.size = BUF_SIZE;
	param.buf.num  = BUF_NUM;

	pool_test_same_name(&param);
}

static void pool_test_same_name_pkt(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_PACKET;
	param.pkt.len = PKT_LEN;
	param.pkt.num = PKT_NUM;

	pool_test_same_name(&param);
}

static void pool_test_same_name_tmo(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_TIMEOUT;
	param.tmo.num = TMO_NUM;

	pool_test_same_name(&param);
}

static void pool_test_same_name_vec(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type            = ODP_POOL_VECTOR;
	param.vector.num      = 10;
	param.vector.max_size = 2;

	pool_test_same_name(&param);
}

static void alloc_buffer(uint32_t cache_size)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	uint32_t i, num;
	odp_buffer_t buf[BUF_NUM];

	odp_pool_param_init(&param);

	param.type     = ODP_POOL_BUFFER;
	param.buf.num  = BUF_NUM;
	param.buf.size = BUF_SIZE;
	param.pkt.cache_size = cache_size;

	pool = odp_pool_create(NULL, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	num = 0;

	for (i = 0; i < PKT_NUM; i++) {
		buf[num] = odp_buffer_alloc(pool);
		CU_ASSERT(buf[num] != ODP_BUFFER_INVALID);

		if (buf[num] != ODP_BUFFER_INVALID)
			num++;
	}

	for (i = 0; i < num; i++)
		odp_buffer_free(buf[i]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_test_alloc_buffer(void)
{
	alloc_buffer(default_pool_param.buf.cache_size);
}

static void pool_test_alloc_buffer_min_cache(void)
{
	alloc_buffer(global_pool_capa.buf.min_cache_size);
}

static void pool_test_alloc_buffer_max_cache(void)
{
	alloc_buffer(global_pool_capa.buf.max_cache_size);
}

static void alloc_packet_vector(uint32_t cache_size)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_pool_capability_t capa;
	uint32_t i, num;
	odp_packet_vector_t pkt_vec[VEC_NUM];
	uint32_t max_num = VEC_NUM;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	if (capa.vector.max_num && capa.vector.max_num < max_num)
		max_num = capa.vector.max_num;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_VECTOR;
	param.vector.num = max_num;
	param.vector.max_size = capa.vector.max_size  < VEC_LEN ? capa.vector.max_size : VEC_LEN;
	param.vector.cache_size = cache_size;

	pool = odp_pool_create(NULL, &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	num = 0;
	for (i = 0; i < max_num; i++) {
		odp_packet_vector_t pktv = odp_packet_vector_alloc(pool);

		CU_ASSERT(pktv != ODP_PACKET_VECTOR_INVALID);

		if (pktv == ODP_PACKET_VECTOR_INVALID)
			continue;

		CU_ASSERT(odp_packet_vector_valid(pktv) == 1);
		CU_ASSERT(odp_event_is_valid(odp_packet_vector_to_event(pktv)) == 1);
		CU_ASSERT(odp_packet_vector_size(pktv) == 0);

		pkt_vec[num] = pktv;
		num++;
	}

	for (i = 0; i < num; i++)
		odp_packet_vector_free(pkt_vec[i]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_test_alloc_packet_vector(void)
{
	alloc_packet_vector(default_pool_param.vector.cache_size);
}

static void pool_test_alloc_packet_vector_min_cache(void)
{
	alloc_packet_vector(global_pool_capa.vector.min_cache_size);
}

static void pool_test_alloc_packet_vector_max_cache(void)
{
	alloc_packet_vector(global_pool_capa.vector.max_cache_size);
}

static void alloc_packet(uint32_t cache_size)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	uint32_t i, num;
	odp_packet_t pkt[PKT_NUM];

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_PACKET;
	param.pkt.num = PKT_NUM;
	param.pkt.len = PKT_LEN;
	param.pkt.cache_size = cache_size;

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

static void pool_test_alloc_packet(void)
{
	alloc_packet(default_pool_param.pkt.cache_size);
}

static void pool_test_alloc_packet_min_cache(void)
{
	alloc_packet(global_pool_capa.pkt.min_cache_size);
}

static void pool_test_alloc_packet_max_cache(void)
{
	alloc_packet(global_pool_capa.pkt.max_cache_size);
}

static void pool_test_alloc_packet_subparam(void)
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

	param.type             = ODP_POOL_PACKET;
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

static void alloc_timeout(uint32_t cache_size)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	uint32_t i, num;
	odp_timeout_t tmo[TMO_NUM];

	odp_pool_param_init(&param);

	param.type     = ODP_POOL_TIMEOUT;
	param.tmo.num  = TMO_NUM;
	param.tmo.cache_size = cache_size;

	pool = odp_pool_create(NULL, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	num = 0;

	for (i = 0; i < PKT_NUM; i++) {
		tmo[num] = odp_timeout_alloc(pool);
		CU_ASSERT(tmo[num] != ODP_TIMEOUT_INVALID);

		if (tmo[num] != ODP_TIMEOUT_INVALID)
			num++;
	}

	for (i = 0; i < num; i++)
		odp_timeout_free(tmo[i]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_test_alloc_timeout(void)
{
	alloc_timeout(default_pool_param.tmo.cache_size);
}

static void pool_test_alloc_timeout_min_cache(void)
{
	alloc_timeout(global_pool_capa.tmo.min_cache_size);
}

static void pool_test_alloc_timeout_max_cache(void)
{
	alloc_timeout(global_pool_capa.tmo.max_cache_size);
}

static void pool_test_info_packet(void)
{
	odp_pool_t pool;
	odp_pool_info_t info;
	odp_pool_param_t param;
	const char pool_name[] = "test_pool_name";

	memset(&info, 0, sizeof(info));
	odp_pool_param_init(&param);

	param.type     = ODP_POOL_PACKET;
	param.pkt.num  = PKT_NUM;
	param.pkt.len  = PKT_LEN;

	pool = odp_pool_create(pool_name, &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	memset(&info, 0, sizeof(odp_pool_info_t));
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

	memset(&info, 0, sizeof(info));
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
		uint32_t offset = 0;
		uint32_t seg_len = 0;
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

static void pool_test_buf_max_num(void)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_pool_capability_t capa;
	uint32_t max_num, num, i;
	odp_shm_t shm;
	odp_buffer_t *buf;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	max_num = MAX_NUM_DEFAULT;
	if (capa.buf.max_num)
		max_num = capa.buf.max_num;

	odp_pool_param_init(&param);

	param.type     = ODP_POOL_BUFFER;
	param.buf.num  = max_num;
	param.buf.size = 10;

	pool = odp_pool_create("test_buf_max_num", &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	shm = odp_shm_reserve("test_max_num_shm",
			      max_num * sizeof(odp_buffer_t),
			      sizeof(odp_buffer_t), 0);

	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);

	buf = odp_shm_addr(shm);

	num = 0;
	for (i = 0; i < max_num; i++) {
		buf[num] = odp_buffer_alloc(pool);

		if (buf[num] != ODP_BUFFER_INVALID) {
			CU_ASSERT(odp_buffer_is_valid(buf[num]) == 1);
			CU_ASSERT(odp_event_is_valid(odp_buffer_to_event(buf[num])) == 1);
			num++;
		}
	}

	CU_ASSERT(num == max_num);

	for (i = 0; i < num; i++)
		odp_buffer_free(buf[i]);

	CU_ASSERT(odp_shm_free(shm) == 0);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_test_pkt_max_num(void)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_pool_capability_t capa;
	uint32_t max_num, num, i;
	odp_shm_t shm;
	odp_packet_t *pkt;
	uint32_t len = 10;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	max_num = MAX_NUM_DEFAULT;
	if (capa.pkt.max_num)
		max_num = capa.pkt.max_num;

	odp_pool_param_init(&param);

	param.type         = ODP_POOL_PACKET;
	param.pkt.num      = max_num;
	param.pkt.max_num  = max_num;
	param.pkt.len      = len;
	param.pkt.max_len  = len;
	param.pkt.headroom = 0;

	pool = odp_pool_create("test_packet_max_num", &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	shm = odp_shm_reserve("test_max_num_shm",
			      max_num * sizeof(odp_packet_t),
			      sizeof(odp_packet_t), 0);

	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);

	pkt = odp_shm_addr(shm);

	num = 0;
	for (i = 0; i < max_num; i++) {
		pkt[num] = odp_packet_alloc(pool, len);

		if (pkt[num] != ODP_PACKET_INVALID) {
			CU_ASSERT(odp_packet_is_valid(pkt[num]) == 1);
			CU_ASSERT(odp_event_is_valid(odp_packet_to_event(pkt[num])) == 1);
			num++;
		}
	}

	CU_ASSERT(num == max_num);

	for (i = 0; i < num; i++)
		odp_packet_free(pkt[i]);

	CU_ASSERT(odp_shm_free(shm) == 0);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_test_packet_vector_max_num(void)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_pool_capability_t capa;
	uint32_t num, i;
	odp_shm_t shm;
	odp_packet_vector_t *pktv;
	uint32_t max_num = VEC_NUM;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	if (capa.vector.max_num)
		max_num = capa.vector.max_num;

	odp_pool_param_init(&param);

	param.type = ODP_POOL_VECTOR;
	param.vector.num = max_num;
	param.vector.max_size = 1;

	pool = odp_pool_create("test_packet_vector_max_num", &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	shm = odp_shm_reserve("test_max_num_shm", max_num * sizeof(odp_packet_vector_t),
			      sizeof(odp_packet_vector_t), 0);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);

	pktv = odp_shm_addr(shm);
	CU_ASSERT_FATAL(pktv != NULL);

	num = 0;
	for (i = 0; i < max_num; i++) {
		pktv[num] = odp_packet_vector_alloc(pool);

		if (pktv[num] != ODP_PACKET_VECTOR_INVALID)
			num++;
	}

	CU_ASSERT(num == max_num);

	for (i = 0; i < num; i++)
		odp_packet_vector_free(pktv[i]);

	CU_ASSERT(odp_shm_free(shm) == 0);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_test_pkt_seg_len(void)
{
	uint32_t len = 1500;
	uint32_t min_seg_len = 42;
	uint32_t max_num = 10;
	uint32_t num = 0;
	uint32_t i;
	odp_packet_t pkt_tbl[max_num];
	odp_pool_t pool;
	odp_pool_param_t param;

	odp_pool_param_init(&param);

	param.type         = ODP_POOL_PACKET;
	param.pkt.num      = max_num;
	param.pkt.len      = len;
	param.pkt.max_len  = len;
	param.pkt.seg_len =  min_seg_len;

	pool = odp_pool_create("test_packet_seg_len", &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < max_num; i++) {
		pkt_tbl[i] = odp_packet_alloc(pool, len);

		if (pkt_tbl[i] != ODP_PACKET_INVALID)
			num++;
	}

	CU_ASSERT(num == max_num);

	for (i = 0; i < num; i++) {
		CU_ASSERT(odp_packet_seg_len(pkt_tbl[i]) >= min_seg_len);
		odp_packet_free(pkt_tbl[i]);
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void pool_test_tmo_max_num(void)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_pool_capability_t capa;
	uint32_t max_num, num, i;
	odp_shm_t shm;
	odp_timeout_t *tmo;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	max_num = MAX_NUM_DEFAULT;
	if (capa.tmo.max_num)
		max_num = capa.tmo.max_num;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_TIMEOUT;
	param.tmo.num = max_num;

	pool = odp_pool_create("test_tmo_max_num", &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	shm = odp_shm_reserve("test_max_num_shm",
			      max_num * sizeof(odp_packet_t),
			      sizeof(odp_packet_t), 0);

	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);

	tmo = odp_shm_addr(shm);

	num = 0;
	for (i = 0; i < max_num; i++) {
		tmo[num] = odp_timeout_alloc(pool);

		if (tmo[num] != ODP_TIMEOUT_INVALID) {
			CU_ASSERT(odp_event_is_valid(odp_timeout_to_event(tmo[num])) == 1);
			num++;
		}
	}

	CU_ASSERT(num == max_num);

	for (i = 0; i < num; i++)
		odp_timeout_free(tmo[i]);

	CU_ASSERT(odp_shm_free(shm) == 0);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void buffer_alloc_loop(odp_pool_t pool, int num, int buffer_size)
{
	int allocs;

	/* Allocate, modify, and free buffers */
	for (allocs = 0; allocs < num;) {
		odp_buffer_t buf;
		uint8_t *data;
		int i;

		buf = odp_buffer_alloc(pool);
		if (buf == ODP_BUFFER_INVALID)
			continue;

		data = odp_buffer_addr(buf);

		for (i = 0; i < buffer_size; i++)
			data[i] = i;

		odp_buffer_free(buf);
		allocs++;
	}
}

static int run_pool_test_create_after_fork(void *arg ODP_UNUSED)
{
	int thr_index;

	thr_index = odp_atomic_fetch_inc_u32(&global_mem->index);

	/* Thread 0 allocates the shared pool */
	if (thr_index == 0) {
		odp_pool_t pool;
		odp_pool_param_t param;

		odp_pool_param_init(&param);

		param.type      = ODP_POOL_BUFFER;
		param.buf.size  = BUF_SIZE;
		param.buf.num   = BUF_NUM;

		pool = odp_pool_create(NULL, &param);
		CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
		global_mem->pool = pool;
	}

	odp_barrier_wait(&global_mem->init_barrier);

	buffer_alloc_loop(global_mem->pool, BUF_NUM, BUF_SIZE);

	return CU_get_number_of_failures();
}

static void pool_test_create_after_fork(void)
{
	odp_shm_t shm;
	int num;

	/* No single VA required since reserve is done before fork */
	shm = odp_shm_reserve(NULL, sizeof(global_shared_mem_t), 0, 0);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	global_mem = odp_shm_addr(shm);
	CU_ASSERT_PTR_NOT_NULL_FATAL(global_mem);

	num = odp_cpumask_default_worker(NULL, 0);
	if (num > MAX_WORKERS)
		num = MAX_WORKERS;

	global_mem->nb_threads = num;
	global_mem->pool = ODP_POOL_INVALID;
	odp_barrier_init(&global_mem->init_barrier, num + 1);
	odp_atomic_init_u32(&global_mem->index, 0);

	/* Fork here */
	odp_cunit_thread_create(num, run_pool_test_create_after_fork, NULL, 0, 0);

	/* Wait until thread 0 has created the test pool */
	odp_barrier_wait(&global_mem->init_barrier);

	buffer_alloc_loop(global_mem->pool, BUF_NUM, BUF_SIZE);

	/* Wait for all thread endings */
	CU_ASSERT(odp_cunit_thread_join(num) >= 0);

	CU_ASSERT(!odp_pool_destroy(global_mem->pool));

	CU_ASSERT(!odp_shm_free(shm));
}

static void pool_test_pool_index(void)
{
	uint32_t max_pools = global_pool_capa.pkt.max_pools;
	uint32_t i, num_pools;
	unsigned int max_index = odp_pool_max_index();
	odp_packet_t pool_lookup[max_index + 1];
	odp_packet_t pkt;
	odp_pool_t pool[max_pools];
	odp_pool_param_t param;
	int pool_index;

	CU_ASSERT_FATAL(max_pools > 0);

	/* Pool max index should match to pool capability */
	CU_ASSERT_FATAL(max_index >= global_pool_capa.max_pools - 1);
	CU_ASSERT_FATAL(max_index >= global_pool_capa.pkt.max_pools - 1);

	odp_pool_param_init(&param);
	param.type    = ODP_POOL_PACKET;
	param.pkt.len = PKT_LEN;
	param.pkt.num = 1;
	param.pkt.max_num = 1;

	for (i = 0; i < max_pools; i++) {
		pool[i] = odp_pool_create(NULL, &param);

		if (pool[i] == ODP_POOL_INVALID)
			break;
	}

	/* Ensuring max possible pools are created */
	num_pools = i;
	CU_ASSERT(num_pools == max_pools);

	for (i = 0; i < num_pools; i++) {
		pkt = odp_packet_alloc(pool[i], PKT_LEN);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

		/* Only one packet should be possible from each pool */
		CU_ASSERT_FATAL(odp_packet_alloc(pool[i], PKT_LEN) == ODP_PACKET_INVALID);

		/* Check pool index validity */
		pool_index = odp_pool_index(pool[i]);
		CU_ASSERT_FATAL(pool_index >= 0);
		CU_ASSERT_FATAL((unsigned int)pool_index <= odp_pool_max_index());

		/* Store packet handle in pool lookup table */
		pool_lookup[pool_index] = pkt;
	}

	for (i = 0; i < num_pools; i++) {
		pool_index = odp_pool_index(pool[i]);

		/* Free the packet using pool lookup */
		odp_packet_free(pool_lookup[pool_index]);

		/* Now packet allocation from the pool should be possible */
		pkt = odp_packet_alloc(pool[i], PKT_LEN);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		odp_packet_free(pkt);

		/* Destroy the pool */
		CU_ASSERT(odp_pool_destroy(pool[i]) == 0);
	}
}

static void pool_test_create_max_pkt_pools(void)
{
	uint32_t max_pools = global_pool_capa.pkt.max_pools;
	uint32_t i, num_pools, num_shm;
	odp_pool_t pool[max_pools];
	odp_pool_param_t param;
	odp_shm_capability_t shm_capa;
	uint32_t shm_size = 32;
	uint32_t uarea_size = 32;

	CU_ASSERT_FATAL(max_pools > 0);

	/* Reserve maximum number of SHM blocks */
	CU_ASSERT_FATAL(odp_shm_capability(&shm_capa) == 0);
	CU_ASSERT_FATAL(shm_capa.max_blocks > 0);

	odp_shm_t shm[shm_capa.max_blocks];

	if (shm_capa.max_size && shm_capa.max_size < shm_size)
		shm_size = shm_capa.max_size;

	for (i = 0; i < shm_capa.max_blocks; i++) {
		shm[i] = odp_shm_reserve(NULL, shm_size, 0, 0);

		if (shm[i] == ODP_SHM_INVALID)
			break;
	}
	num_shm = i;
	CU_ASSERT(num_shm == shm_capa.max_blocks);

	/* Create maximum number of packet pools */
	if (uarea_size > global_pool_capa.pkt.max_uarea_size)
		uarea_size = global_pool_capa.pkt.max_uarea_size;

	odp_pool_param_init(&param);
	param.type    = ODP_POOL_PACKET;
	param.pkt.len = PKT_LEN;
	param.pkt.num = 1;
	param.pkt.max_num = 1;
	param.pkt.uarea_size = uarea_size;

	for (i = 0; i < max_pools; i++) {
		pool[i] = odp_pool_create(NULL, &param);

		if (pool[i] == ODP_POOL_INVALID)
			break;
	}
	num_pools = i;
	CU_ASSERT(num_pools == max_pools);

	for (i = 0; i < num_pools; i++)
		CU_ASSERT(odp_pool_destroy(pool[i]) == 0);

	for (i = 0; i < num_shm; i++)
		CU_ASSERT(odp_shm_free(shm[i]) == 0);
}

static int pool_check_buffer_pool_statistics(void)
{
	if (global_pool_capa.buf.stats.all == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pool_check_packet_pool_statistics(void)
{
	if (global_pool_capa.pkt.stats.all == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pool_check_packet_vector_pool_statistics(void)
{
	if (global_pool_capa.vector.stats.all == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pool_check_timeout_pool_statistics(void)
{
	if (global_pool_capa.tmo.stats.all == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pool_test_pool_statistics(odp_pool_type_t pool_type)
{
	odp_pool_stats_t stats;
	odp_pool_stats_selected_t selected;
	odp_pool_param_t param;
	odp_pool_stats_opt_t supported;
	uint32_t i, j, num_pool, num_obj, cache_size;
	uint32_t max_pools = 2;
	uint16_t first = 0;
	uint16_t last = ODP_POOL_MAX_THREAD_STATS - 1;

	if (last > odp_thread_count_max() - 1)
		last = odp_thread_count_max() - 1;

	odp_pool_param_init(&param);

	if (pool_type == ODP_POOL_BUFFER) {
		max_pools = global_pool_capa.buf.max_pools < max_pools ?
				global_pool_capa.buf.max_pools : max_pools;
		num_obj = BUF_NUM;
		supported.all = global_pool_capa.buf.stats.all;
		param.type = ODP_POOL_BUFFER;
		cache_size = CACHE_SIZE > global_pool_capa.buf.max_cache_size ?
				global_pool_capa.buf.max_cache_size : CACHE_SIZE;
		param.buf.cache_size = cache_size;
		param.buf.size = BUF_SIZE;
		param.buf.num = num_obj;
	} else if (pool_type == ODP_POOL_PACKET) {
		max_pools = global_pool_capa.pkt.max_pools < max_pools ?
				global_pool_capa.pkt.max_pools : max_pools;
		num_obj = PKT_NUM;
		supported.all = global_pool_capa.pkt.stats.all;
		param.type = ODP_POOL_PACKET;
		cache_size = CACHE_SIZE > global_pool_capa.pkt.max_cache_size ?
				global_pool_capa.pkt.max_cache_size : CACHE_SIZE;
		param.pkt.cache_size = cache_size;
		param.pkt.len = PKT_LEN;
		param.pkt.num = num_obj;
		param.pkt.max_num = num_obj;
	} else if (pool_type == ODP_POOL_VECTOR) {
		max_pools = global_pool_capa.vector.max_pools < max_pools ?
				global_pool_capa.vector.max_pools : max_pools;
		num_obj = VEC_NUM;
		if (global_pool_capa.vector.max_num && global_pool_capa.vector.max_num < num_obj)
			num_obj = global_pool_capa.vector.max_num;
		supported.all = global_pool_capa.vector.stats.all;
		param.type = ODP_POOL_VECTOR;
		cache_size = CACHE_SIZE > global_pool_capa.vector.max_cache_size ?
				global_pool_capa.vector.max_cache_size : CACHE_SIZE;
		param.vector.cache_size = cache_size;
		param.vector.num = num_obj;
		param.vector.max_size = global_pool_capa.vector.max_size  < VEC_LEN ?
						global_pool_capa.vector.max_size : VEC_LEN;
	} else {
		max_pools = global_pool_capa.tmo.max_pools < max_pools ?
				global_pool_capa.tmo.max_pools : max_pools;
		num_obj = TMO_NUM;
		supported.all = global_pool_capa.tmo.stats.all;
		param.type = ODP_POOL_TIMEOUT;
		cache_size = CACHE_SIZE > global_pool_capa.tmo.max_cache_size ?
				global_pool_capa.tmo.max_cache_size : CACHE_SIZE;
		param.tmo.cache_size = cache_size;
		param.tmo.num = num_obj;
	}

	param.stats.all = supported.all;

	CU_ASSERT_FATAL(max_pools != 0);

	/* Extra alloc rounds for testing odp_pool_stats_t.alloc_fails */
	uint32_t num_allocs = num_obj + 100;
	odp_event_t event[max_pools][num_allocs];
	uint32_t num_event[max_pools];
	odp_pool_t pool[max_pools];

	for (i = 0; i < max_pools; i++) {
		pool[i] = odp_pool_create(NULL, &param);

		if (pool[i] == ODP_POOL_INVALID)
			break;
	}

	num_pool = i;
	CU_ASSERT(num_pool == max_pools);

	for (i = 0; i < num_pool; i++) {
		uint32_t num_events = 0;
		uint32_t num_fails = 0;

		CU_ASSERT_FATAL(odp_pool_stats_reset(pool[i]) == 0);
		stats.thread.first = first;
		stats.thread.last = last;
		CU_ASSERT_FATAL(odp_pool_stats(pool[i], &stats) == 0);
		CU_ASSERT_FATAL(odp_pool_stats_selected(pool[i], &selected, &supported) == 0);

		CU_ASSERT(stats.available <= num_obj);
		if (supported.bit.available)
			CU_ASSERT(selected.available <= num_obj);
		CU_ASSERT(stats.alloc_ops == 0);
		if (supported.bit.alloc_ops)
			CU_ASSERT(selected.alloc_ops == 0);
		CU_ASSERT(stats.alloc_fails == 0);
		if (supported.bit.alloc_fails)
			CU_ASSERT(selected.alloc_fails == 0);
		CU_ASSERT(stats.free_ops == 0);
		if (supported.bit.free_ops)
			CU_ASSERT(selected.free_ops == 0);
		CU_ASSERT(stats.total_ops == 0);
		if (supported.bit.total_ops)
			CU_ASSERT(selected.total_ops == 0);
		CU_ASSERT(stats.cache_available <= num_obj);
		if (supported.bit.cache_available)
			CU_ASSERT(selected.cache_available <= num_obj);
		CU_ASSERT(stats.cache_alloc_ops == 0);
		if (supported.bit.cache_alloc_ops)
			CU_ASSERT(selected.cache_alloc_ops == 0);
		CU_ASSERT(stats.cache_free_ops == 0);
		if (supported.bit.cache_free_ops)
			CU_ASSERT(selected.cache_free_ops == 0);

		CU_ASSERT(stats.thread.first == first);
		CU_ASSERT(stats.thread.last == last);
		for (j = 0; j < ODP_POOL_MAX_THREAD_STATS; j++)
			CU_ASSERT(stats.thread.cache_available[j] <= stats.cache_available);

		/* Allocate the events */
		for (j = 0; j < num_allocs; j++) {
			odp_event_t new_event = ODP_EVENT_INVALID;
			uint64_t total_cached = 0;
			uint16_t first_id = 0;
			uint16_t last_id = last;

			if (pool_type == ODP_POOL_BUFFER) {
				odp_buffer_t buf = odp_buffer_alloc(pool[i]);

				if (buf != ODP_BUFFER_INVALID)
					new_event = odp_buffer_to_event(buf);
			} else if (pool_type == ODP_POOL_PACKET) {
				odp_packet_t pkt = odp_packet_alloc(pool[i], PKT_LEN);

				if (pkt != ODP_PACKET_INVALID)
					new_event = odp_packet_to_event(pkt);
			} else if (pool_type == ODP_POOL_VECTOR) {
				odp_packet_vector_t pktv = odp_packet_vector_alloc(pool[i]);

				if (pktv != ODP_PACKET_VECTOR_INVALID)
					new_event = odp_packet_vector_to_event(pktv);
			} else {
				odp_timeout_t tmo = odp_timeout_alloc(pool[i]);

				if (tmo != ODP_TIMEOUT_INVALID)
					new_event = odp_timeout_to_event(tmo);
			}

			if (new_event != ODP_EVENT_INVALID)
				event[i][num_events++] = new_event;
			else
				num_fails++;

			CU_ASSERT_FATAL(odp_pool_stats(pool[i], &stats) == 0);
			CU_ASSERT_FATAL(odp_pool_stats_selected(pool[i], &selected,
								&supported) == 0);
			CU_ASSERT(stats.available <= num_obj - num_events);
			if (supported.bit.available)
				CU_ASSERT(selected.available <= num_obj - num_events);
			CU_ASSERT(stats.cache_available <= num_obj - num_events);
			if (supported.bit.cache_available)
				CU_ASSERT(selected.cache_available <= num_obj - num_events);

			while (first_id < odp_thread_count_max()) {
				stats.thread.first = first_id;
				stats.thread.last = last_id;
				CU_ASSERT_FATAL(odp_pool_stats(pool[i], &stats) == 0);

				for (int i = 0; i < ODP_POOL_MAX_THREAD_STATS; i++) {
					uint64_t cached = stats.thread.cache_available[i];

					CU_ASSERT(cached <= num_obj - num_events);
					total_cached += cached;
				}
				first_id = last_id + 1;
				last_id += ODP_POOL_MAX_THREAD_STATS;
				if (last_id >= odp_thread_count_max())
					last_id = odp_thread_count_max() - 1;
			};

			if (supported.bit.cache_available && supported.bit.thread_cache_available &&
			    ODP_POOL_MAX_THREAD_STATS >= odp_thread_count_max())
				CU_ASSERT(stats.cache_available == total_cached);
		}

		CU_ASSERT(num_events == num_obj);
		num_event[i] = num_events;

		/* Allow implementation some time to update counters */
		odp_time_wait_ns(ODP_TIME_MSEC_IN_NS);

		stats.thread.first = first;
		stats.thread.last = last;
		CU_ASSERT_FATAL(odp_pool_stats(pool[i], &stats) == 0);
		CU_ASSERT_FATAL(odp_pool_stats_selected(pool[i], &selected, &supported) == 0);

		/* All events are allocated, available count in pool and pool
		 * local caches should be zero. */
		CU_ASSERT(stats.available == 0);
		if (supported.bit.available)
			CU_ASSERT(selected.available == 0);
		CU_ASSERT(stats.cache_available == 0);
		if (supported.bit.cache_available)
			CU_ASSERT(selected.cache_available == 0);
		for (j = 0; j < ODP_POOL_MAX_THREAD_STATS; j++)
			CU_ASSERT(stats.thread.cache_available[j] == 0);
		if (supported.bit.alloc_ops) {
			CU_ASSERT(stats.alloc_ops > 0 && stats.alloc_ops <= num_allocs);
			CU_ASSERT(selected.alloc_ops > 0 && selected.alloc_ops <= num_allocs);
		}
		if (supported.bit.alloc_fails) {
			CU_ASSERT(stats.alloc_fails == num_fails);
			CU_ASSERT(selected.alloc_fails == num_fails);
		}
		if (supported.bit.total_ops) {
			CU_ASSERT(stats.total_ops > 0 && stats.total_ops <= num_allocs);
			CU_ASSERT(selected.total_ops > 0 && selected.total_ops <= num_allocs);
		}
		CU_ASSERT(stats.free_ops == 0);
		if (supported.bit.free_ops)
			CU_ASSERT(selected.free_ops == 0);
		CU_ASSERT(stats.cache_alloc_ops <= num_allocs);
		if (supported.bit.cache_alloc_ops)
			CU_ASSERT(selected.cache_alloc_ops <= num_allocs);
		CU_ASSERT(stats.cache_free_ops == 0);
		if (supported.bit.cache_free_ops)
			CU_ASSERT(selected.cache_free_ops == 0);
	}

	for (i = 0; i < num_pool; i++) {
		odp_event_free_multi(event[i], num_event[i]);

		/* Allow implementation some time to update counters */
		odp_time_wait_ns(ODP_TIME_MSEC_IN_NS);

		stats.thread.first = odp_thread_id();
		stats.thread.last = odp_thread_id();
		CU_ASSERT_FATAL(odp_pool_stats(pool[i], &stats) == 0);
		CU_ASSERT_FATAL(odp_pool_stats_selected(pool[i], &selected, &supported) == 0);

		if (supported.bit.available && supported.bit.cache_available) {
			CU_ASSERT(stats.available + stats.cache_available == num_obj);
			CU_ASSERT(selected.available + selected.cache_available == num_obj);
		}
		if (supported.bit.free_ops) {
			CU_ASSERT(stats.free_ops > 0);
			CU_ASSERT(selected.free_ops > 0);
		}
		if (supported.bit.total_ops) {
			CU_ASSERT(stats.total_ops > 0);
			CU_ASSERT(selected.total_ops > 0);
		}

		if (i == 0) {
			printf("\nPool Statistics\n---------------\n");
			printf("  available:       %" PRIu64 "\n", stats.available);
			printf("  alloc_ops:       %" PRIu64 "\n", stats.alloc_ops);
			printf("  alloc_fails:     %" PRIu64 "\n", stats.alloc_fails);
			printf("  free_ops:        %" PRIu64 "\n", stats.free_ops);
			printf("  total_ops:       %" PRIu64 "\n", stats.total_ops);
			printf("  cache_available: %" PRIu64 "\n", stats.cache_available);
			printf("  cache_alloc_ops: %" PRIu64 "\n", stats.cache_alloc_ops);
			printf("  cache_free_ops:  %" PRIu64 "\n", stats.cache_free_ops);
			printf("  thread.cache_available[0]: %" PRIu64 "\n",
			       stats.thread.cache_available[0]);
		}

		CU_ASSERT_FATAL(odp_pool_stats_reset(pool[i]) == 0);
		CU_ASSERT_FATAL(odp_pool_stats(pool[i], &stats) == 0);
		CU_ASSERT_FATAL(odp_pool_stats_selected(pool[i], &selected, &supported) == 0);

		CU_ASSERT(stats.alloc_ops == 0);
		if (supported.bit.alloc_ops)
			CU_ASSERT(selected.alloc_ops == 0);
		CU_ASSERT(stats.alloc_fails == 0);
		if (supported.bit.alloc_fails)
			CU_ASSERT(selected.alloc_fails == 0);
		CU_ASSERT(stats.free_ops == 0);
		if (supported.bit.free_ops)
			CU_ASSERT(selected.free_ops == 0);
		CU_ASSERT(stats.total_ops == 0);
		if (supported.bit.total_ops)
			CU_ASSERT(selected.total_ops == 0);
		CU_ASSERT(stats.cache_alloc_ops == 0);
		if (supported.bit.cache_alloc_ops)
			CU_ASSERT(selected.cache_alloc_ops == 0);
		CU_ASSERT(stats.cache_free_ops == 0);
		if (supported.bit.cache_free_ops)
			CU_ASSERT(selected.cache_free_ops == 0);

		CU_ASSERT(odp_pool_destroy(pool[i]) == 0);
	}
}

static void pool_test_buffer_pool_statistics(void)
{
	pool_test_pool_statistics(ODP_POOL_BUFFER);
}

static void pool_test_packet_pool_statistics(void)
{
	pool_test_pool_statistics(ODP_POOL_PACKET);
}

static void pool_test_packet_vector_pool_statistics(void)
{
	pool_test_pool_statistics(ODP_POOL_VECTOR);
}

static void pool_test_timeout_pool_statistics(void)
{
	pool_test_pool_statistics(ODP_POOL_TIMEOUT);
}

static void pool_ext_init_packet_pool_param(odp_pool_ext_param_t *param)
{
	odp_pool_ext_capability_t capa;
	uint32_t head_offset, head_align, trailer_size;
	odp_pool_type_t type = ODP_POOL_PACKET;
	uint32_t num_buf = EXT_NUM_BUF;
	uint32_t buf_size = EXT_BUF_SIZE;
	uint32_t uarea_size = EXT_UAREA_SIZE;
	uint32_t headroom = EXT_HEADROOM;
	uint32_t app_hdr_size = EXT_APP_HDR_SIZE;

	CU_ASSERT_FATAL(odp_pool_ext_capability(type, &capa) == 0);

	odp_pool_ext_param_init(type, param);

	if (num_buf > capa.pkt.max_num_buf)
		num_buf = capa.pkt.max_num_buf;

	if (buf_size > capa.pkt.max_buf_size)
		buf_size = capa.pkt.max_buf_size;

	if (uarea_size > capa.pkt.max_uarea_size)
		uarea_size = capa.pkt.max_uarea_size;

	if (headroom > capa.pkt.max_headroom)
		headroom = capa.pkt.max_headroom;

	head_align = capa.pkt.min_head_align;
	head_offset = capa.pkt.odp_header_size + app_hdr_size;
	trailer_size = capa.pkt.odp_trailer_size;

	CU_ASSERT_FATAL(head_offset < buf_size);
	CU_ASSERT_FATAL((head_offset + trailer_size)  < buf_size);

	while (head_offset % head_align) {
		app_hdr_size++;
		head_offset = capa.pkt.odp_header_size + app_hdr_size;

		if (head_offset >= buf_size) {
			ODPH_ERR("Head align too large (%u). No room for data.\n", head_align);
			break;
		}
	}

	CU_ASSERT_FATAL(head_offset < buf_size);
	CU_ASSERT_FATAL((head_offset + trailer_size)  < buf_size);
	CU_ASSERT_FATAL((head_offset % head_align) == 0);

	param->pkt.num_buf         = num_buf;
	param->pkt.buf_size        = buf_size;
	param->pkt.app_header_size = app_hdr_size;
	param->pkt.uarea_size      = uarea_size;
	param->pkt.headroom        = headroom;
}

static void test_packet_pool_ext_capa(void)
{
	odp_pool_ext_capability_t capa;
	odp_pool_type_t type;
	const odp_pool_type_t unsupported_types[] = {ODP_POOL_BUFFER, ODP_POOL_TIMEOUT,
						     ODP_POOL_VECTOR, ODP_POOL_DMA_COMPL};
	const int num_types = sizeof(unsupported_types) / sizeof(unsupported_types[0]);

	/* Verify operation for unsupported pool types */
	for (int i = 0; i < num_types; i++) {
		type = unsupported_types[i];
		CU_ASSERT_FATAL(odp_pool_ext_capability(type, &capa) == 0);
		CU_ASSERT(capa.max_pools == 0);
	}

	type = ODP_POOL_PACKET;

	CU_ASSERT_FATAL(odp_pool_ext_capability(type, &capa) == 0);

	CU_ASSERT(capa.type == type);

	/* External memory pools not supported */
	if (capa.max_pools == 0)
		return;

	CU_ASSERT(capa.max_pools > 0);
	CU_ASSERT(capa.min_cache_size <= capa.max_cache_size);
	CU_ASSERT(capa.pkt.max_num_buf > 0);
	CU_ASSERT(capa.pkt.max_buf_size > 0);
	CU_ASSERT(capa.pkt.min_mem_align > 0);
	CU_ASSERT(TEST_CHECK_POW2(capa.pkt.min_mem_align));
	CU_ASSERT(capa.pkt.min_buf_align > 0);
	CU_ASSERT(capa.pkt.min_head_align > 0);
	CU_ASSERT(capa.pkt.max_headroom > 0);
	CU_ASSERT(capa.pkt.max_headroom_size > 0);
	CU_ASSERT(capa.pkt.max_headroom_size >= capa.pkt.max_headroom);
	CU_ASSERT(capa.pkt.max_segs_per_pkt > 0);
}

static void test_ext_param_init(uint8_t fill)
{
	odp_pool_ext_param_t param;

	memset(&param, fill, sizeof(param));
	odp_pool_ext_param_init(ODP_POOL_PACKET, &param);

	CU_ASSERT(param.type == ODP_POOL_PACKET);
	CU_ASSERT(param.uarea_init.init_fn == NULL);
	CU_ASSERT(param.uarea_init.args == NULL);
	CU_ASSERT(param.cache_size >= global_pool_ext_capa.min_cache_size &&
		  param.cache_size <= global_pool_ext_capa.max_cache_size);
	CU_ASSERT(param.stats.all == 0);
	CU_ASSERT(param.pkt.app_header_size == 0);
	CU_ASSERT(param.pkt.uarea_size == 0);
}

static void test_packet_pool_ext_param_init(void)
{
	test_ext_param_init(0);
	test_ext_param_init(0xff);
}

static void test_packet_pool_ext_create(void)
{
	odp_pool_t pool;
	odp_pool_ext_param_t param;

	pool_ext_init_packet_pool_param(&param);

	pool = odp_pool_ext_create("pool_ext_0", &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void test_packet_pool_ext_lookup(void)
{
	odp_pool_t pool, pool_1;
	odp_pool_ext_param_t param;
	const char *name = "pool_ext_0";

	pool_ext_init_packet_pool_param(&param);

	pool = odp_pool_ext_create(name, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	pool_1 = odp_pool_lookup(name);

	CU_ASSERT_FATAL(pool_1 != ODP_POOL_INVALID);
	CU_ASSERT(pool == pool_1);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void test_packet_pool_ext_info(void)
{
	odp_pool_t pool;
	odp_pool_ext_param_t param;
	odp_pool_info_t info;
	const char *name = "pool_ext_0";

	pool_ext_init_packet_pool_param(&param);

	pool = odp_pool_ext_create(name, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	memset(&info, 0, sizeof(odp_pool_info_t));
	CU_ASSERT_FATAL(odp_pool_info(pool, &info) == 0);

	CU_ASSERT(info.pool_ext);
	CU_ASSERT(strncmp(name, info.name, strlen(name)) == 0);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static odp_shm_t populate_pool(odp_pool_t pool, odp_pool_ext_capability_t *capa,
			       void *buf[], uint32_t num, uint32_t buf_size)
{
	odp_shm_t shm;
	uint8_t *buf_ptr;
	uint32_t i;
	uint32_t shm_size, mem_align;
	uint32_t flags = 0;
	uint32_t buf_align = EXT_BUF_ALIGN;
	uint32_t min_align = capa->pkt.min_buf_align;

	CU_ASSERT_FATAL(min_align > 0);

	if (min_align > buf_align)
		buf_align = min_align;

	if (capa->pkt.buf_size_aligned) {
		buf_align = buf_size;
		CU_ASSERT_FATAL((buf_size % min_align) == 0);
	}

	mem_align = buf_align;
	if (capa->pkt.min_mem_align > mem_align)
		mem_align = capa->pkt.min_mem_align;

	/* Prepare to align every buffer */
	shm_size = (num + 1) * (buf_size + buf_align);

	shm = odp_shm_reserve("test_pool_ext_populate", shm_size, mem_align, 0);
	if (shm == ODP_SHM_INVALID)
		return ODP_SHM_INVALID;

	buf_ptr = odp_shm_addr(shm);
	CU_ASSERT_FATAL((uintptr_t)buf_ptr % mem_align == 0);

	/* initialize entire pool memory with a pattern */
	memset(buf_ptr, MAGIC_U8, shm_size);

	/* Move from mem_align to buf_align */
	while ((uintptr_t)buf_ptr % buf_align)
		buf_ptr++;

	for (i = 0; i < num; i++) {
		if (i == num - 1)
			flags = ODP_POOL_POPULATE_DONE;

		buf[i] = buf_ptr;
		CU_ASSERT_FATAL(odp_pool_ext_populate(pool, &buf[i], buf_size, 1, flags) == 0);

		buf_ptr += buf_size;
		while ((uintptr_t)buf_ptr % buf_align)
			buf_ptr++;
	}

	return shm;
}

static void test_packet_pool_ext_populate(void)
{
	odp_shm_t shm;
	odp_pool_t pool;
	odp_pool_ext_param_t param;
	odp_pool_ext_capability_t capa;
	uint32_t buf_size, num_buf;
	void *buf[EXT_NUM_BUF];

	CU_ASSERT_FATAL(odp_pool_ext_capability(ODP_POOL_PACKET, &capa) == 0);

	pool_ext_init_packet_pool_param(&param);
	num_buf  = param.pkt.num_buf;
	buf_size = param.pkt.buf_size;

	CU_ASSERT_FATAL(capa.pkt.min_head_align > 0);

	pool = odp_pool_ext_create("pool_ext_0", &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	shm = populate_pool(pool, &capa, buf, num_buf, buf_size);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
	CU_ASSERT(odp_shm_free(shm) == 0);
}

static uint32_t find_buf(odp_packet_t pkt, void *buf[], uint32_t num, uint32_t head_offset)
{
	uint32_t i;
	uint8_t *ptr;
	uint8_t *head = odp_packet_head(pkt);

	for (i = 0; i < num; i++) {
		ptr  = buf[i];
		ptr += head_offset;

		if (head == ptr)
			break;
	}

	return i;
}

#define PKT_LEN_NORMAL    0
#define PKT_LEN_MAX       1
#define PKT_LEN_SEGMENTED 2

static void packet_pool_ext_alloc(int len_test)
{
	odp_shm_t shm;
	odp_pool_t pool;
	odp_pool_ext_param_t param;
	odp_pool_ext_capability_t capa;
	uint32_t i, j, buf_size, num_buf, num_pkt, num_alloc, buf_index;
	uint32_t pkt_len, head_offset, trailer_size, headroom, max_headroom;
	uint32_t hr, tr, uarea_size, max_payload, buf_data_size, app_hdr_size;
	int num_seg;
	uint8_t *app_hdr;
	void *buf[EXT_NUM_BUF];
	odp_packet_t pkt[EXT_NUM_BUF];
	uint32_t seg_len = 0;

	CU_ASSERT_FATAL(odp_pool_ext_capability(ODP_POOL_PACKET, &capa) == 0);

	pool_ext_init_packet_pool_param(&param);
	num_buf    = param.pkt.num_buf;
	buf_size   = param.pkt.buf_size;
	uarea_size = param.pkt.uarea_size;

	pool = odp_pool_ext_create("pool_ext_0", &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	shm = populate_pool(pool, &capa, buf, num_buf, buf_size);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);

	app_hdr_size = param.pkt.app_header_size;
	head_offset  = capa.pkt.odp_header_size + app_hdr_size;
	max_headroom = capa.pkt.max_headroom_size;
	headroom = param.pkt.headroom;
	trailer_size = capa.pkt.odp_trailer_size;
	buf_data_size = buf_size - head_offset - trailer_size;
	max_payload = buf_data_size - max_headroom;
	num_pkt = num_buf;
	num_seg = 1;

	if (len_test == PKT_LEN_NORMAL) {
		pkt_len = (buf_data_size - headroom) / 2;
	} else if (len_test == PKT_LEN_MAX) {
		pkt_len = max_payload;
	} else {
		CU_ASSERT_FATAL(capa.pkt.max_segs_per_pkt > 1);
		 /* length that results 2 segments */
		pkt_len = max_payload + (buf_size / 2);
		num_seg = 2;
		num_pkt = num_buf / num_seg;
	}

	for (i = 0; i < num_pkt; i++) {
		pkt[i] = odp_packet_alloc(pool, pkt_len);
		CU_ASSERT(pkt[i] != ODP_PACKET_INVALID);
		if (pkt[i] == ODP_PACKET_INVALID)
			break;

		CU_ASSERT(odp_packet_is_valid(pkt[i]) == 1);
		CU_ASSERT(odp_event_is_valid(odp_packet_to_event(pkt[i])) == 1);
		CU_ASSERT(odp_packet_len(pkt[i]) == pkt_len);
		CU_ASSERT(odp_packet_headroom(pkt[i]) >= headroom);
		buf_index = find_buf(pkt[i], buf, num_buf, head_offset);
		CU_ASSERT(buf_index < num_buf);
		hr = (uintptr_t)odp_packet_data(pkt[i]) - (uintptr_t)odp_packet_head(pkt[i]);
		CU_ASSERT(hr == odp_packet_headroom(pkt[i]));
		CU_ASSERT(num_seg == odp_packet_num_segs(pkt[i]));
		CU_ASSERT(odp_packet_data(pkt[i]) == odp_packet_data_seg_len(pkt[i], &seg_len));
		CU_ASSERT(odp_packet_seg_len(pkt[i]) == seg_len);

		if (num_seg == 1) {
			tr = buf_data_size - hr - pkt_len;
			CU_ASSERT(tr == odp_packet_tailroom(pkt[i]));
			CU_ASSERT(odp_packet_seg_len(pkt[i]) == pkt_len);
		} else {
			odp_packet_seg_t seg = odp_packet_last_seg(pkt[i]);
			uint32_t last_seg_len = odp_packet_seg_data_len(pkt[i], seg);
			uint32_t max_tr = buf_data_size - last_seg_len;

			CU_ASSERT(odp_packet_tailroom(pkt[i]) <= max_tr);
			CU_ASSERT(pkt_len == (odp_packet_seg_len(pkt[i]) + last_seg_len));
		}

		CU_ASSERT(odp_packet_buf_len(pkt[i]) == num_seg * buf_data_size);

		if (uarea_size) {
			CU_ASSERT(odp_packet_user_area(pkt[i]) != NULL);
			CU_ASSERT(odp_packet_user_area_size(pkt[i]) >= uarea_size);
		}

		/* Check that application header content has not changed */
		app_hdr = (uint8_t *)odp_packet_head(pkt[i]) - app_hdr_size;
		for (j = 0; j < app_hdr_size; j++)
			CU_ASSERT(app_hdr[j] == MAGIC_U8);
	}

	num_alloc = i;
	CU_ASSERT(num_alloc == num_pkt);

	/* Pool is now empty */
	CU_ASSERT(odp_packet_alloc(pool, pkt_len) == ODP_PACKET_INVALID);

	for (i = 0; i < num_alloc; i++)
		odp_packet_free(pkt[i]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
	CU_ASSERT(odp_shm_free(shm) == 0);
}

static void test_packet_pool_ext_alloc(void)
{
	packet_pool_ext_alloc(PKT_LEN_NORMAL);
}

static void test_packet_pool_ext_uarea_init(void)
{
	odp_pool_ext_capability_t capa;
	odp_pool_ext_param_t param;
	uint32_t num = ELEM_NUM, i;
	odp_pool_t pool;
	uarea_init_t data;
	odp_shm_t shm;
	uint8_t *uarea;

	CU_ASSERT_FATAL(odp_pool_ext_capability(ODP_POOL_PACKET, &capa) == 0);

	memset(&data, 0, sizeof(uarea_init_t));
	pool_ext_init_packet_pool_param(&param);
	param.uarea_init.init_fn = init_event_uarea;
	param.uarea_init.args = &data;
	num = MIN(num, param.pkt.num_buf);
	param.pkt.num_buf = num;
	param.pkt.uarea_size = 1;
	pool = odp_pool_ext_create(NULL, &param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	void *buf[num];
	odp_packet_t pkts[num];

	shm = populate_pool(pool, &capa, buf, num, param.pkt.buf_size);

	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);
	CU_ASSERT(data.count == num);

	for (i = 0; i < num; i++) {
		CU_ASSERT(data.mark[i] == 1);

		pkts[i] = odp_packet_alloc(pool, (param.pkt.buf_size - param.pkt.headroom) / 2);

		CU_ASSERT(pkts[i] != ODP_PACKET_INVALID);

		if (pkts[i] == ODP_PACKET_INVALID)
			break;

		uarea = odp_packet_user_area(pkts[i]);

		CU_ASSERT(*uarea == UAREA);
	}

	odp_packet_free_multi(pkts, i);
	odp_pool_destroy(pool);
	odp_shm_free(shm);
}

static void test_packet_pool_ext_alloc_max(void)
{
	packet_pool_ext_alloc(PKT_LEN_MAX);
}

static void test_packet_pool_ext_alloc_seg(void)
{
	packet_pool_ext_alloc(PKT_LEN_SEGMENTED);
}

static void test_packet_pool_ext_disassemble(void)
{
	odp_shm_t shm;
	odp_pool_t pool;
	odp_pool_ext_param_t param;
	odp_pool_ext_capability_t capa;
	uint32_t i, j, buf_size, num_buf, num_pkt, num_alloc, buf_index;
	uint32_t pkt_len, head_offset, trailer_size, headroom, max_headroom;
	uint32_t hr, max_payload, buf_data_size;
	uint32_t num_seg;
	void *buf[EXT_NUM_BUF];
	odp_packet_t pkt_tbl[EXT_NUM_BUF];

	CU_ASSERT_FATAL(odp_pool_ext_capability(ODP_POOL_PACKET, &capa) == 0);
	CU_ASSERT_FATAL(capa.pkt.max_segs_per_pkt > 1);

	pool_ext_init_packet_pool_param(&param);
	num_buf    = param.pkt.num_buf;
	buf_size   = param.pkt.buf_size;

	pool = odp_pool_ext_create("pool_ext_0", &param);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	shm = populate_pool(pool, &capa, buf, num_buf, buf_size);
	CU_ASSERT_FATAL(shm != ODP_SHM_INVALID);

	head_offset  = capa.pkt.odp_header_size + param.pkt.app_header_size;
	max_headroom = capa.pkt.max_headroom_size;
	headroom = param.pkt.headroom;
	trailer_size = capa.pkt.odp_trailer_size;
	buf_data_size = buf_size - head_offset - trailer_size;
	max_payload = buf_data_size - max_headroom;

	 /* length that results 2 segments */
	pkt_len = max_payload + (buf_size / 2);
	num_seg = 2;
	num_pkt = num_buf / num_seg;

	for (i = 0; i < num_pkt; i++) {
		odp_packet_t pkt;
		odp_packet_seg_t seg;
		uint32_t num_pkt_buf, data_offset, data_len;
		void *head, *data, *pkt_head;
		odp_packet_buf_t pkt_buf[num_seg];
		void *seg_data[num_seg];
		uint32_t seg_len[num_seg];

		pkt = odp_packet_alloc(pool, pkt_len);
		pkt_tbl[i] = pkt;
		CU_ASSERT(pkt != ODP_PACKET_INVALID);
		if (pkt == ODP_PACKET_INVALID)
			break;

		CU_ASSERT(odp_packet_len(pkt) == pkt_len);
		CU_ASSERT(odp_packet_headroom(pkt) >= headroom);
		buf_index = find_buf(pkt, buf, num_buf, head_offset);
		CU_ASSERT(buf_index < num_buf);
		pkt_head = odp_packet_head(pkt);
		hr = (uintptr_t)odp_packet_data(pkt) - (uintptr_t)pkt_head;
		CU_ASSERT(hr == odp_packet_headroom(pkt));
		CU_ASSERT((int)num_seg == odp_packet_num_segs(pkt));

		seg = odp_packet_first_seg(pkt);
		for (j = 0; j < num_seg; j++) {
			seg_data[j] = odp_packet_seg_data(pkt, seg);
			seg_len[j]  = odp_packet_seg_data_len(pkt, seg);
			seg = odp_packet_next_seg(pkt, seg);
		}

		CU_ASSERT(odp_packet_data(pkt) == seg_data[0]);
		CU_ASSERT(odp_packet_seg_len(pkt) == seg_len[0])

		/* Disassemble packet */
		num_pkt_buf = odp_packet_disassemble(pkt, pkt_buf, num_seg);
		CU_ASSERT_FATAL(num_pkt_buf == num_seg);

		CU_ASSERT(odp_packet_buf_head(pkt_buf[0]) == pkt_head);
		CU_ASSERT(odp_packet_buf_data_offset(pkt_buf[0]) == hr);

		for (j = 0; j < num_seg; j++) {
			CU_ASSERT(odp_packet_buf_size(pkt_buf[j]) == buf_data_size);

			head = odp_packet_buf_head(pkt_buf[j]);
			data_offset = odp_packet_buf_data_offset(pkt_buf[j]);
			data = (uint8_t *)head + data_offset;
			CU_ASSERT(seg_data[j] == data);
			data_len = odp_packet_buf_data_len(pkt_buf[j]);
			CU_ASSERT(seg_len[j] == data_len);

			CU_ASSERT(odp_packet_buf_from_head(pool, head) == pkt_buf[j]);

			/* Pull in head and tail by one byte */
			odp_packet_buf_data_set(pkt_buf[j], data_offset + 1, data_len - 2);
			CU_ASSERT(odp_packet_buf_data_offset(pkt_buf[j]) == data_offset + 1);
			CU_ASSERT(odp_packet_buf_data_len(pkt_buf[j]) == data_len - 2);
		}

		/* Reassemble packet, each segment is now 2 bytes shorter */
		pkt = odp_packet_reassemble(pool, pkt_buf, num_seg);

		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		CU_ASSERT(odp_packet_num_segs(pkt) == (int)num_seg);
		pkt_tbl[i] = pkt;

		CU_ASSERT(odp_packet_len(pkt) == (pkt_len - (num_seg * 2)));
	}

	num_alloc = i;
	CU_ASSERT(num_alloc == num_pkt);

	/* Pool is now empty */
	CU_ASSERT(odp_packet_alloc(pool, pkt_len) == ODP_PACKET_INVALID);

	for (i = 0; i < num_alloc; i++)
		odp_packet_free(pkt_tbl[i]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
	CU_ASSERT(odp_shm_free(shm) == 0);
}

static int pool_suite_init(void)
{
	memset(&global_pool_capa, 0, sizeof(odp_pool_capability_t));
	memset(&default_pool_param, 0, sizeof(odp_pool_param_t));

	if (odp_pool_capability(&global_pool_capa) < 0) {
		ODPH_ERR("odp_pool_capability() failed in suite init\n");
		return -1;
	}

	odp_pool_param_init(&default_pool_param);

	return 0;
}

static int pool_ext_suite_init(void)
{
	memset(&global_pool_ext_capa, 0, sizeof(odp_pool_ext_capability_t));

	if (odp_pool_ext_capability(ODP_POOL_PACKET, &global_pool_ext_capa)) {
		ODPH_ERR("Pool ext capa failed in suite init\n");
		return -1;
	}

	if (global_pool_ext_capa.type != ODP_POOL_PACKET) {
		ODPH_ERR("Bad type from pool ext capa in suite init\n");
		return -1;
	}

	return 0;
}

static int check_pool_ext_support(void)
{
	if (global_pool_ext_capa.max_pools == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int check_pool_ext_uarea_init_support(void)
{
	if (global_pool_ext_capa.max_pools == 0 || !global_pool_ext_capa.pkt.uarea_persistence ||
	    global_pool_ext_capa.pkt.max_uarea_size == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int check_pool_ext_segment_support(void)
{
	if (global_pool_ext_capa.max_pools == 0 || global_pool_ext_capa.pkt.max_segs_per_pkt < 2)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

odp_testinfo_t pool_suite[] = {
	ODP_TEST_INFO(pool_test_param_init),
	ODP_TEST_INFO(pool_test_create_destroy_buffer),
	ODP_TEST_INFO(pool_test_create_destroy_packet),
	ODP_TEST_INFO(pool_test_create_destroy_timeout),
	ODP_TEST_INFO(pool_test_create_destroy_vector),
	ODP_TEST_INFO_CONDITIONAL(pool_test_buffer_uarea_init, pool_check_buffer_uarea_init),
	ODP_TEST_INFO_CONDITIONAL(pool_test_packet_uarea_init, pool_check_packet_uarea_init),
	ODP_TEST_INFO_CONDITIONAL(pool_test_vector_uarea_init, pool_check_vector_uarea_init),
	ODP_TEST_INFO_CONDITIONAL(pool_test_timeout_uarea_init, pool_check_timeout_uarea_init),
	ODP_TEST_INFO(pool_test_lookup_info_print),
	ODP_TEST_INFO(pool_test_same_name_buf),
	ODP_TEST_INFO(pool_test_same_name_pkt),
	ODP_TEST_INFO(pool_test_same_name_tmo),
	ODP_TEST_INFO(pool_test_same_name_vec),
	ODP_TEST_INFO(pool_test_alloc_buffer),
	ODP_TEST_INFO(pool_test_alloc_buffer_min_cache),
	ODP_TEST_INFO(pool_test_alloc_buffer_max_cache),
	ODP_TEST_INFO(pool_test_alloc_packet_vector),
	ODP_TEST_INFO(pool_test_alloc_packet_vector_min_cache),
	ODP_TEST_INFO(pool_test_alloc_packet_vector_max_cache),
	ODP_TEST_INFO(pool_test_alloc_packet),
	ODP_TEST_INFO(pool_test_alloc_packet_min_cache),
	ODP_TEST_INFO(pool_test_alloc_packet_max_cache),
	ODP_TEST_INFO(pool_test_alloc_packet_subparam),
	ODP_TEST_INFO(pool_test_alloc_timeout),
	ODP_TEST_INFO(pool_test_alloc_timeout_min_cache),
	ODP_TEST_INFO(pool_test_alloc_timeout_max_cache),
	ODP_TEST_INFO(pool_test_info_packet),
	ODP_TEST_INFO(pool_test_info_data_range),
	ODP_TEST_INFO(pool_test_buf_max_num),
	ODP_TEST_INFO(pool_test_pkt_max_num),
	ODP_TEST_INFO(pool_test_packet_vector_max_num),
	ODP_TEST_INFO(pool_test_pkt_seg_len),
	ODP_TEST_INFO(pool_test_tmo_max_num),
	ODP_TEST_INFO(pool_test_create_after_fork),
	ODP_TEST_INFO(pool_test_pool_index),
	ODP_TEST_INFO(pool_test_create_max_pkt_pools),
	ODP_TEST_INFO_CONDITIONAL(pool_test_buffer_pool_statistics,
				  pool_check_buffer_pool_statistics),
	ODP_TEST_INFO_CONDITIONAL(pool_test_packet_pool_statistics,
				  pool_check_packet_pool_statistics),
	ODP_TEST_INFO_CONDITIONAL(pool_test_packet_vector_pool_statistics,
				  pool_check_packet_vector_pool_statistics),
	ODP_TEST_INFO_CONDITIONAL(pool_test_timeout_pool_statistics,
				  pool_check_timeout_pool_statistics),
	ODP_TEST_INFO_NULL,
};

odp_testinfo_t pool_ext_suite[] = {
	ODP_TEST_INFO(test_packet_pool_ext_capa),
	ODP_TEST_INFO_CONDITIONAL(test_packet_pool_ext_param_init, check_pool_ext_support),
	ODP_TEST_INFO_CONDITIONAL(test_packet_pool_ext_create, check_pool_ext_support),
	ODP_TEST_INFO_CONDITIONAL(test_packet_pool_ext_lookup, check_pool_ext_support),
	ODP_TEST_INFO_CONDITIONAL(test_packet_pool_ext_info, check_pool_ext_support),
	ODP_TEST_INFO_CONDITIONAL(test_packet_pool_ext_populate, check_pool_ext_support),
	ODP_TEST_INFO_CONDITIONAL(test_packet_pool_ext_alloc, check_pool_ext_support),
	ODP_TEST_INFO_CONDITIONAL(test_packet_pool_ext_uarea_init,
				  check_pool_ext_uarea_init_support),
	ODP_TEST_INFO_CONDITIONAL(test_packet_pool_ext_alloc_max, check_pool_ext_support),
	ODP_TEST_INFO_CONDITIONAL(test_packet_pool_ext_alloc_seg, check_pool_ext_segment_support),
	ODP_TEST_INFO_CONDITIONAL(test_packet_pool_ext_disassemble, check_pool_ext_segment_support),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t pool_suites[] = {
	{ .name         = "Pool tests",
	  .testinfo_tbl = pool_suite,
	  .init_func    = pool_suite_init,
	},
	{ .name         = "Ext mem pool tests",
	  .testinfo_tbl = pool_ext_suite,
	  .init_func    = pool_ext_suite_init,
	},
	ODP_SUITE_INFO_NULL,
};

int main(int argc, char *argv[])
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

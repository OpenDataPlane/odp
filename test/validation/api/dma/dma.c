/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2025 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include "odp_cunit_common.h"

#define COMPL_POOL_NAME "DMA compl pool"

#define MIN_SEG_LEN  1024
#define SHM_ALIGN    ODP_CACHE_LINE_SIZE
#define RETRIES      5
#define TIMEOUT      5
#define OFFSET       10
#define TRAILER      10
#define MULTI        1
#define RESULT       1
#define USER_DATA    0xdeadbeef
#define ELEM_NUM     10u
#define UAREA        0xaa

typedef struct global_t {
	odp_dma_capability_t dma_capa;
	odp_shm_t shm;
	odp_pool_param_t pool_param;
	int disabled;
	uint8_t *src_addr;
	uint8_t *dst_addr;
	uint32_t data_size;
	uint32_t len;
	odp_pool_t pkt_pool;
	uint32_t pkt_len;
	odp_queue_t queue;
	odp_pool_t compl_pool;
	uint32_t event_count;
	uint32_t cache_size;
	odp_packet_t src_ref_opts;

} global_t;

typedef struct {
	uint32_t count;
	uint8_t mark[ELEM_NUM];
} uarea_init_t;

typedef struct {
	odp_bool_t seg_free;
	odp_bool_t unique_src_segs;
	odp_bool_t single_pool;
	odp_bool_t seg_alloc;
	odp_bool_t unique_dst_segs;
} opts_t;

static global_t global;

static int dma_suite_init(void)
{
	odp_shm_t shm;
	odp_pool_param_t pool_param;
	odp_dma_pool_param_t dma_pool_param;
	odp_pool_capability_t pool_capa;
	odp_queue_param_t queue_param;
	uint32_t shm_len, pkt_len;
	void *addr;

	memset(&global, 0, sizeof(global_t));
	global.shm = ODP_SHM_INVALID;
	global.pkt_pool = ODP_POOL_INVALID;
	global.queue = ODP_QUEUE_INVALID;
	global.compl_pool = ODP_POOL_INVALID;

	if (odp_dma_capability(&global.dma_capa)) {
		ODPH_ERR("DMA capability failed\n");
		return -1;
	}

	if (global.dma_capa.max_sessions == 0) {
		global.disabled = 1;
		ODPH_DBG("DMA test disabled\n");
		return 0;
	}

	shm_len = MIN_SEG_LEN * global.dma_capa.max_segs * global.dma_capa.max_transfers;
	shm = odp_shm_reserve("DMA test", shm_len, SHM_ALIGN, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("SHM reserve failed\n");
		return -1;
	}

	addr = odp_shm_addr(shm);

	if (addr == NULL) {
		ODPH_ERR("SHM addr failed\n");
		return -1;
	}

	global.shm = shm;
	global.data_size = shm_len / 2;
	global.src_addr = addr;
	global.dst_addr = (uint8_t *)global.src_addr + global.data_size;
	global.len = global.data_size - OFFSET - TRAILER;

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Pool capa failed\n");
		return -1;
	}

	pkt_len = pool_capa.pkt.max_len;
	if (pkt_len == 0)
		pkt_len = 4000;

	pkt_len = ODPH_MIN(pkt_len, global.dma_capa.max_seg_len);
	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_PACKET;
	pool_param.pkt.num = global.dma_capa.max_src_segs + global.dma_capa.max_dst_segs;
	pool_param.pkt.len = pkt_len;
	pool_param.pkt.max_len = pkt_len;

	global.pkt_len = pkt_len;
	global.pkt_pool = odp_pool_create("DMA test pkt pool", &pool_param);
	global.pool_param = pool_param;

	if (global.pkt_pool == ODP_POOL_INVALID) {
		ODPH_ERR("Packet pool create failed\n");
		return -1;
	}

	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.sync  = ODP_SCHED_SYNC_PARALLEL;
	queue_param.sched.prio  = odp_schedule_default_prio();
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	global.queue = odp_queue_create("DMA test queue", &queue_param);

	if (global.queue == ODP_QUEUE_INVALID) {
		ODPH_ERR("Queue create failed\n");
		return -1;
	}

	if (global.dma_capa.compl_mode_mask & ODP_DMA_COMPL_EVENT) {
		if (global.dma_capa.pool.max_num < global.dma_capa.max_transfers) {
			ODPH_ERR("Too small DMA compl pool %u\n", global.dma_capa.pool.max_num);
			return -1;
		}

		odp_dma_pool_param_init(&dma_pool_param);
		dma_pool_param.num = global.dma_capa.max_transfers;
		global.cache_size = dma_pool_param.cache_size;

		global.compl_pool = odp_dma_pool_create(COMPL_POOL_NAME, &dma_pool_param);

		if (global.compl_pool == ODP_POOL_INVALID) {
			ODPH_ERR("Completion pool create failed\n");
			return -1;
		}
	}

	return 0;
}

static int dma_suite_term(void)
{
	if (global.compl_pool != ODP_POOL_INVALID &&
	    odp_pool_destroy(global.compl_pool)) {
		ODPH_ERR("Completion pool destroy failed\n");
		return -1;
	}

	if (global.queue != ODP_QUEUE_INVALID &&
	    odp_queue_destroy(global.queue)) {
		ODPH_ERR("Queue destroy failed\n");
		return -1;
	}

	if (global.pkt_pool != ODP_POOL_INVALID &&
	    odp_pool_destroy(global.pkt_pool)) {
		ODPH_ERR("Packet pool destroy failed\n");
		return -1;
	}

	if (global.shm != ODP_SHM_INVALID &&
	    odp_shm_free(global.shm)) {
		ODPH_ERR("SHM free failed\n");
		return -1;
	}

	return odp_cunit_print_inactive();
}

static void test_dma_capability(void)
{
	odp_dma_capability_t capa;

	memset(&capa, 0, sizeof(odp_dma_capability_t));
	CU_ASSERT_FATAL(odp_dma_capability(&capa) == 0);

	if (capa.max_sessions == 0)
		return;

	CU_ASSERT(capa.max_transfers > 0);
	CU_ASSERT(capa.max_src_segs > 0);
	CU_ASSERT(capa.max_dst_segs > 0);
	CU_ASSERT(capa.max_segs > 1);
	CU_ASSERT(capa.max_segs > capa.max_src_segs);
	CU_ASSERT(capa.max_segs > capa.max_dst_segs);
	CU_ASSERT(capa.max_seg_len > 0);
	CU_ASSERT(capa.compl_mode_mask & ODP_DMA_COMPL_SYNC);

	if (capa.compl_mode_mask & ODP_DMA_COMPL_EVENT) {
		odp_pool_capability_t pool_capa;

		CU_ASSERT_FATAL(odp_pool_capability(&pool_capa) == 0);

		CU_ASSERT(capa.queue_type_sched || capa.queue_type_plain);
		CU_ASSERT(capa.pool.max_pools > 0 && capa.pool.max_pools <= pool_capa.max_pools);
		CU_ASSERT(capa.pool.max_num > 0);
		CU_ASSERT(capa.pool.min_cache_size <= capa.pool.max_cache_size);
	}
}

static void test_dma_param(uint8_t fill)
{
	odp_dma_param_t dma_param;
	odp_dma_transfer_param_t trs_param;
	odp_dma_compl_param_t compl_param;
	odp_dma_pool_param_t dma_pool_param;

	memset(&dma_param, fill, sizeof(dma_param));
	odp_dma_param_init(&dma_param);
	CU_ASSERT(dma_param.direction == ODP_DMA_MAIN_TO_MAIN);
	CU_ASSERT(dma_param.type == ODP_DMA_TYPE_COPY);
	CU_ASSERT(dma_param.mt_mode == ODP_DMA_MT_SAFE);
	CU_ASSERT(dma_param.order == ODP_DMA_ORDER_NONE);

	memset(&trs_param, fill, sizeof(trs_param));
	odp_dma_transfer_param_init(&trs_param);
	CU_ASSERT(trs_param.src_format == ODP_DMA_FORMAT_ADDR);
	CU_ASSERT(trs_param.dst_format == ODP_DMA_FORMAT_ADDR);
	CU_ASSERT(trs_param.num_src == 1);
	CU_ASSERT(trs_param.num_dst == 1);

	memset(&compl_param, fill, sizeof(compl_param));
	odp_dma_compl_param_init(&compl_param);
	CU_ASSERT(compl_param.user_ptr == NULL);

	memset(&dma_pool_param, fill, sizeof(dma_pool_param));
	odp_dma_pool_param_init(&dma_pool_param);
	CU_ASSERT(dma_pool_param.uarea_init.init_fn == NULL);
	CU_ASSERT(dma_pool_param.uarea_init.args == NULL);
	CU_ASSERT(dma_pool_param.uarea_size == 0);
	CU_ASSERT(dma_pool_param.cache_size <= global.dma_capa.pool.max_cache_size);
	CU_ASSERT(dma_pool_param.cache_size >= global.dma_capa.pool.min_cache_size);
}

static void test_dma_param_init(void)
{
	test_dma_param(0);
	test_dma_param(0xff);
}

static void test_dma_debug(void)
{
	odp_dma_param_t dma_param;
	odp_dma_t dma, dma2;
	uint64_t u64;
	const char *name = "dma_debug";

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = ODP_DMA_COMPL_SYNC;
	dma = odp_dma_create(name, &dma_param);
	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	dma2 = odp_dma_lookup(name);
	CU_ASSERT(dma2 != ODP_DMA_INVALID);
	CU_ASSERT(dma2 == dma);

	u64 = odp_dma_to_u64(dma);
	CU_ASSERT(u64 != odp_dma_to_u64(ODP_DMA_INVALID));
	printf("\n    DMA handle: 0x%" PRIx64 "\n", u64);

	odp_dma_print(dma);

	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_same_name_null(void)
{
	odp_dma_param_t dma_param;
	odp_dma_t dma_a, dma_b;

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = ODP_DMA_COMPL_SYNC;
	dma_a = odp_dma_create(NULL, &dma_param);

	CU_ASSERT_FATAL(dma_a != ODP_DMA_INVALID);

	dma_b = odp_dma_create(NULL, &dma_param);

	CU_ASSERT_FATAL(dma_b != ODP_DMA_INVALID);
	CU_ASSERT(odp_dma_to_u64(dma_a) != odp_dma_to_u64(dma_b));
	CU_ASSERT(odp_dma_destroy(dma_a) == 0);
	CU_ASSERT(odp_dma_destroy(dma_b) == 0);
}

static void test_dma_same_name_named(void)
{
	odp_dma_param_t dma_param;
	const char *name = "DMA session";
	odp_dma_t dma, dma_a, dma_b;

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = ODP_DMA_COMPL_SYNC;
	dma_a = odp_dma_create(name, &dma_param);

	CU_ASSERT_FATAL(dma_a != ODP_DMA_INVALID);

	dma = odp_dma_lookup(name);

	CU_ASSERT(odp_dma_to_u64(dma) == odp_dma_to_u64(dma_a));

	dma_b = odp_dma_create(name, &dma_param);

	CU_ASSERT_FATAL(dma_b != ODP_DMA_INVALID);

	dma = odp_dma_lookup(name);

	CU_ASSERT(odp_dma_to_u64(dma) == odp_dma_to_u64(dma_a) ||
		  odp_dma_to_u64(dma) == odp_dma_to_u64(dma_b));
	CU_ASSERT(odp_dma_to_u64(dma_a) != odp_dma_to_u64(dma_b));
	CU_ASSERT(odp_dma_destroy(dma_a) == 0);
	CU_ASSERT(odp_dma_destroy(dma_b) == 0);
}

static void test_dma_long_name(void)
{
	odp_dma_param_t dma_param;
	odp_dma_t dma;
	char name[ODP_DMA_NAME_LEN];

	memset(name, 'a', sizeof(name));
	name[sizeof(name) - 1] = 0;

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = ODP_DMA_COMPL_SYNC;
	dma = odp_dma_create(name, &dma_param);

	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);
	CU_ASSERT(odp_dma_to_u64(dma) == odp_dma_to_u64(odp_dma_lookup(name)));
	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_compl_pool(void)
{
	odp_pool_t pool;
	odp_pool_info_t pool_info;
	odp_dma_compl_t compl[global.dma_capa.max_transfers];
	odp_event_t ev;
	uint64_t u64;
	int ret;
	uint32_t i, j;
	const char *name = COMPL_POOL_NAME;

	CU_ASSERT_FATAL(global.compl_pool != ODP_POOL_INVALID);

	pool = odp_pool_lookup(name);
	CU_ASSERT(pool == global.compl_pool);

	memset(&pool_info, 0x55, sizeof(odp_pool_info_t));
	ret = odp_pool_info(global.compl_pool, &pool_info);
	CU_ASSERT(ret == 0);
	CU_ASSERT(strcmp(pool_info.name, name) == 0);
	CU_ASSERT(pool_info.pool_ext == 0);
	CU_ASSERT(pool_info.type == ODP_POOL_DMA_COMPL);
	CU_ASSERT(pool_info.dma_pool_param.num == global.dma_capa.max_transfers);
	CU_ASSERT(pool_info.dma_pool_param.uarea_size == 0);
	CU_ASSERT(pool_info.dma_pool_param.cache_size == global.cache_size);

	for (i = 0; i < global.dma_capa.max_transfers; i++) {
		compl[i] = odp_dma_compl_alloc(global.compl_pool);

		u64 = odp_dma_compl_to_u64(compl[i]);
		CU_ASSERT(u64 != odp_dma_compl_to_u64(ODP_DMA_COMPL_INVALID));

		if (compl[i] == ODP_DMA_COMPL_INVALID)
			break;

		/* No source pool for DMA completion events */
		ev = odp_dma_compl_to_event(compl[i]);
		CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
		CU_ASSERT(odp_event_pool(ev) == ODP_POOL_INVALID);

		printf("\n    DMA compl handle: 0x%" PRIx64 "\n", u64);
		odp_dma_compl_print(compl[i]);
	}

	for (j = 0; j < i; j++)
		odp_dma_compl_free(compl[j]);
}

static void test_dma_compl_pool_same_name(void)
{
	odp_dma_pool_param_t dma_pool_param;
	odp_pool_t pool, pool_a, pool_b;
	const char *name = COMPL_POOL_NAME;

	pool_a = global.compl_pool;

	pool = odp_pool_lookup(name);
	CU_ASSERT(pool == pool_a);

	odp_dma_pool_param_init(&dma_pool_param);
	dma_pool_param.num = global.dma_capa.max_transfers;

	/* Second pool with the same name */
	pool_b = odp_dma_pool_create(name, &dma_pool_param);
	CU_ASSERT_FATAL(pool_b != ODP_POOL_INVALID);

	pool = odp_pool_lookup(name);
	CU_ASSERT(pool == pool_a || pool == pool_b);

	CU_ASSERT_FATAL(odp_pool_destroy(pool_b) == 0);
}

static void test_dma_compl_pool_long_name(void)
{
	odp_dma_pool_param_t dma_pool_param;
	odp_pool_t pool;
	char name[ODP_POOL_NAME_LEN];

	memset(name, 'a', sizeof(name));
	name[sizeof(name) - 1] = 0;

	odp_dma_pool_param_init(&dma_pool_param);
	dma_pool_param.num = 1;
	pool = odp_dma_pool_create(name, &dma_pool_param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	CU_ASSERT(pool == odp_pool_lookup(name));
	CU_ASSERT_FATAL(odp_pool_destroy(pool) == 0);
}

static void test_dma_compl_pool_max_pools(void)
{
	odp_dma_pool_param_t dma_pool_param;
	/* Max pools minus the ones already created in global init */
	uint32_t num = global.dma_capa.pool.max_pools - 2, i, j;
	odp_pool_t pools[num];
	int ret;

	odp_dma_pool_param_init(&dma_pool_param);
	dma_pool_param.num = global.dma_capa.max_transfers;

	for (i = 0; i < num; i++) {
		pools[i] = odp_dma_pool_create(NULL, &dma_pool_param);
		CU_ASSERT(pools[i] != ODP_POOL_INVALID);

		if (pools[i] == ODP_POOL_INVALID) {
			ODPH_ERR("DMA completion pool create failed: %u / %u\n", i, num);
			break;
		}
	}

	for (j = 0; j < i; j++) {
		ret = odp_pool_destroy(pools[j]);
		CU_ASSERT(ret == 0);

		if (ret == -1)
			ODPH_ERR("DMA completion pool destroy failed: %u / %u\n", j, i);
	}
}

static void test_dma_compl_user_area(void)
{
	odp_dma_pool_param_t dma_pool_param;
	uint32_t num = ODPH_MIN(ELEM_NUM, global.dma_capa.pool.max_num),
	size = global.dma_capa.pool.max_uarea_size, i;
	odp_pool_t pool;
	odp_dma_compl_t compl_evs[num];
	void *addr, *prev = NULL;

	odp_dma_pool_param_init(&dma_pool_param);
	dma_pool_param.num = num;
	dma_pool_param.uarea_size = size;
	pool = odp_dma_pool_create(NULL, &dma_pool_param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	for (i = 0; i < num; i++) {
		odp_event_t ev;
		int flag = 0;

		compl_evs[i] = odp_dma_compl_alloc(pool);

		if (compl_evs[i] == ODP_DMA_COMPL_INVALID)
			break;

		addr = odp_dma_compl_user_area(compl_evs[i]);

		CU_ASSERT_FATAL(addr != NULL);
		CU_ASSERT(prev != addr);

		ev = odp_dma_compl_to_event(compl_evs[i]);
		odp_event_user_flag_set(ev, 1);
		CU_ASSERT(odp_event_user_area(ev) == addr);
		CU_ASSERT(odp_event_user_area_and_flag(ev, &flag) == addr);
		CU_ASSERT(flag < 0);

		prev = addr;
		memset(addr, 0, size);
	}

	CU_ASSERT(i == num);

	for (uint32_t j = 0; j < i; j++)
		odp_dma_compl_free(compl_evs[j]);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void init_event_uarea(void *uarea, uint32_t size, void *args, uint32_t index)
{
	uarea_init_t *data = args;

	data->count++;
	data->mark[index] = 1;
	memset(uarea, UAREA, size);
}

static void test_dma_compl_user_area_init(void)
{
	odp_dma_pool_param_t dma_pool_param;
	uint32_t num = ODPH_MIN(ELEM_NUM, global.dma_capa.pool.max_num), i;
	odp_pool_t pool;
	uarea_init_t data;
	odp_dma_compl_t compl_evs[num];
	uint8_t *uarea;

	memset(&data, 0, sizeof(uarea_init_t));
	odp_dma_pool_param_init(&dma_pool_param);
	dma_pool_param.uarea_init.init_fn = init_event_uarea;
	dma_pool_param.uarea_init.args = &data;
	dma_pool_param.num = num;
	dma_pool_param.uarea_size = 1;
	pool = odp_dma_pool_create(NULL, &dma_pool_param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	CU_ASSERT(data.count == num);

	for (i = 0; i < num; i++) {
		CU_ASSERT(data.mark[i] == 1);

		compl_evs[i] = odp_dma_compl_alloc(pool);

		CU_ASSERT(compl_evs[i] != ODP_DMA_COMPL_INVALID);

		if (compl_evs[i] == ODP_DMA_COMPL_INVALID)
			break;

		uarea = odp_dma_compl_user_area(compl_evs[i]);

		CU_ASSERT(*uarea == UAREA);
	}

	for (uint32_t j = 0; j < i; j++)
		odp_dma_compl_free(compl_evs[j]);

	odp_pool_destroy(pool);
}

static void init_source(uint8_t *src, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		src[i] = i;
}

static int check_equal(uint8_t *src, uint8_t *dst, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		if (src[i] != dst[i])
			return -1;

	return 0;
}

static int check_zero(uint8_t *ptr, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		if (ptr[i])
			return -1;

	return 0;
}

static void check_dst_alloc(odp_dma_result_t *res, odp_pool_t dst_pool)
{
	odp_packet_t dst;

	CU_ASSERT(res->num_dst == 1)

	if (res->num_dst == 1) {
		dst = res->dst_pkt[0];
		CU_ASSERT(odp_packet_pool(dst) == dst_pool);
		CU_ASSERT(check_equal(odp_packet_data(global.src_ref_opts), odp_packet_data(dst),
				      odp_packet_seg_len(dst)) == 0);
		odp_packet_free(dst);
	}
}

static int do_transfer(odp_dma_t dma, const odp_dma_transfer_param_t *trs_param, int multi, int res)
{
	int i, ret;
	odp_dma_result_t result;
	const odp_dma_transfer_param_t *trs_ptr[1] = {trs_param};
	odp_dma_result_t *result_ptr[1] = {&result};

	memset(&result, 0, sizeof(odp_dma_result_t));

	for (i = 0; i < RETRIES; i++) {
		if (!multi && !res)
			ret = odp_dma_transfer(dma, trs_param, NULL);
		else if (!multi && res)
			ret = odp_dma_transfer(dma, trs_param, &result);
		else if (multi && !res)
			ret = odp_dma_transfer_multi(dma, trs_ptr, NULL, 1);
		else
			ret = odp_dma_transfer_multi(dma, trs_ptr, result_ptr, 1);

		if (ret)
			break;
	}

	CU_ASSERT(ret == 1);

	if (res) {
		CU_ASSERT(result.success);

		if (trs_param->opts.seg_alloc)
			check_dst_alloc(&result, trs_param->dst_seg_pool);
	}

	return ret;
}

static int do_transfer_async(odp_dma_t dma, odp_dma_transfer_param_t *trs_param,
			     odp_dma_compl_mode_t compl_mode, int multi)
{
	int num_trs = multi ? multi : 1;
	odp_dma_compl_param_t compl_param[num_trs];
	const odp_dma_compl_param_t *compl_ptr[num_trs];
	const odp_dma_transfer_param_t *trs_ptr[num_trs];
	odp_event_t ev;
	odp_dma_compl_t compl;
	int i, j, ret, done;
	uint64_t u64;
	uint32_t user_data = USER_DATA;
	odp_dma_result_t result;
	uint64_t wait_ns = 500 * ODP_TIME_MSEC_IN_NS;
	uint64_t sched_wait = odp_schedule_wait_time(wait_ns);
	void *user_ptr = &user_data;

	for (i = 0; i < num_trs; i++) {
		odp_dma_compl_param_init(&compl_param[i]);
		compl_param[i].compl_mode = compl_mode;

		if (compl_mode == ODP_DMA_COMPL_EVENT) {
			compl = odp_dma_compl_alloc(global.compl_pool);

			CU_ASSERT(compl != ODP_DMA_COMPL_INVALID);
			if (compl == ODP_DMA_COMPL_INVALID)
				return -1;

			compl_param[i].event = odp_dma_compl_to_event(compl);
			compl_param[i].queue = global.queue;
		} else if (compl_mode == ODP_DMA_COMPL_POLL) {
			compl_param[i].transfer_id = odp_dma_transfer_id_alloc(dma);

			CU_ASSERT(compl_param[i].transfer_id != ODP_DMA_TRANSFER_ID_INVALID);
			if (compl_param[i].transfer_id == ODP_DMA_TRANSFER_ID_INVALID)
				return -1;

			u64 = odp_dma_transfer_id_to_u64(compl_param[i].transfer_id);
			CU_ASSERT(u64 != odp_dma_transfer_id_to_u64(ODP_DMA_TRANSFER_ID_INVALID));

		} else if (compl_mode != ODP_DMA_COMPL_NONE) {
			ODPH_ERR("Wrong compl mode: %u\n", compl_mode);
			return -1;
		}

		compl_param[i].user_ptr = user_ptr;

		if (multi) {
			trs_ptr[i] = &trs_param[i];
			compl_ptr[i] = &compl_param[i];
		}
	}

	for (i = 0; i < RETRIES; i++) {
		if (multi)
			ret = odp_dma_transfer_start_multi(dma, trs_ptr, compl_ptr, num_trs);
		else
			ret = odp_dma_transfer_start(dma, trs_param, compl_param);

		if (ret)
			break;
	}

	CU_ASSERT(ret == num_trs);

	if (ret < 1)
		return ret;

	for (i = 0; i < ret; i++) {
		memset(&result, 0, sizeof(odp_dma_result_t));

		if (compl_mode == ODP_DMA_COMPL_POLL) {
			for (j = 0; j < TIMEOUT; j++) {
				done = odp_dma_transfer_done(dma, compl_param[i].transfer_id,
							     &result);
				if (done)
					break;

				odp_time_wait_ns(wait_ns);
			}

			CU_ASSERT(done == 1);
			CU_ASSERT(result.success);
			CU_ASSERT(result.user_ptr == user_ptr);
			CU_ASSERT(user_data == USER_DATA);

			if (trs_param->opts.seg_alloc)
				check_dst_alloc(&result, trs_param->dst_seg_pool);

			odp_dma_transfer_id_free(dma, compl_param[i].transfer_id);
		} else if (compl_mode == ODP_DMA_COMPL_EVENT) {
			odp_queue_t from = ODP_QUEUE_INVALID;

			for (j = 0; j < TIMEOUT; j++) {
				ev = odp_schedule(&from, sched_wait);
				if (ev != ODP_EVENT_INVALID)
					break;
			}

			CU_ASSERT(ev != ODP_EVENT_INVALID);
			if (ev == ODP_EVENT_INVALID)
				return -1;

			CU_ASSERT(from == global.queue);
			CU_ASSERT(odp_event_type(ev) == ODP_EVENT_DMA_COMPL);

			compl = odp_dma_compl_from_event(ev);
			CU_ASSERT(compl != ODP_DMA_COMPL_INVALID);

			CU_ASSERT(odp_dma_compl_result(compl, &result) == 0);
			CU_ASSERT(result.success);
			CU_ASSERT(result.user_ptr == user_ptr);
			CU_ASSERT(user_data == USER_DATA);

			if (trs_param->opts.seg_alloc)
				check_dst_alloc(&result, trs_param->dst_seg_pool);

			/* Test also without result struct output */
			CU_ASSERT(odp_dma_compl_result(compl, NULL) == 0);

			/* Test compl event print on the first event */
			if (global.event_count == 0) {
				printf("\n\n");
				odp_dma_compl_print(compl);
			}

			/* Test both ways to free the event */
			if (global.event_count % 2)
				odp_event_free(ev);
			else
				odp_dma_compl_free(compl);

			global.event_count++;
		}
	}

	return 1;
}

static void test_dma_addr_to_addr(odp_dma_compl_mode_t compl_mode_mask, uint32_t num,
				  int multi, int res)
{
	odp_dma_param_t dma_param;
	odp_dma_transfer_param_t trs_param;
	odp_dma_t dma;
	odp_dma_seg_t src_seg[num];
	odp_dma_seg_t dst_seg[num];
	int ret;
	uint32_t i, cur_len;
	uint8_t *src = global.src_addr + OFFSET;
	uint8_t *dst = global.dst_addr + OFFSET;
	uint32_t seg_len = ODPH_MIN(global.len / num, global.dma_capa.max_seg_len);
	uint32_t len = seg_len * num;
	uint32_t offset = 0;

	init_source(global.src_addr, global.data_size);
	memset(global.dst_addr, 0, global.data_size);

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = compl_mode_mask;
	dma = odp_dma_create("addr_to_addr", &dma_param);
	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	memset(src_seg, 0, sizeof(src_seg));
	memset(dst_seg, 0, sizeof(dst_seg));

	for (i = 0; i < num; i++) {
		cur_len = seg_len;
		if (i == num - 1)
			cur_len = len - seg_len * i;

		src_seg[i].addr = src + offset;
		src_seg[i].len  = cur_len;
		dst_seg[i].addr = dst + offset;
		dst_seg[i].len  = cur_len;
		offset += cur_len;
	}

	odp_dma_transfer_param_init(&trs_param);
	trs_param.num_src = num;
	trs_param.num_dst = num;
	trs_param.src_seg = src_seg;
	trs_param.dst_seg = dst_seg;

	if (compl_mode_mask == ODP_DMA_COMPL_SYNC)
		ret = do_transfer(dma, &trs_param, multi, res);
	else
		ret = do_transfer_async(dma, &trs_param, compl_mode_mask, multi);

	if (ret > 0) {
		CU_ASSERT(check_equal(src, dst, len) == 0);
		CU_ASSERT(check_zero(global.dst_addr, OFFSET) == 0);
		CU_ASSERT(check_zero(dst + len, global.len - len + TRAILER) == 0);
	}

	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_addr_to_addr_trs(odp_dma_compl_mode_t compl_mode_mask, uint32_t num_trs,
				      int multi, int res)
{
	odp_dma_param_t dma_param;
	odp_dma_transfer_param_t trs_param;
	odp_dma_t dma;
	odp_dma_seg_t src_seg;
	odp_dma_seg_t dst_seg;
	int compl_none;
	uint32_t i, cur_len;
	odp_dma_compl_mode_t compl_mode;
	uint8_t *src = global.src_addr + OFFSET;
	uint8_t *dst = global.dst_addr + OFFSET;
	uint32_t trs_len = ODPH_MIN(global.len / num_trs, global.dma_capa.max_seg_len);
	uint32_t len = trs_len * num_trs;
	uint32_t offset = 0;
	int ret = -1;

	compl_none = 0;
	if (compl_mode_mask & ODP_DMA_COMPL_NONE)
		compl_none = 1;

	init_source(global.src_addr, global.data_size);
	memset(global.dst_addr, 0, global.data_size);

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = compl_mode_mask;
	dma = odp_dma_create("addr_to_addr", &dma_param);
	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	odp_dma_transfer_param_init(&trs_param);
	trs_param.src_seg = &src_seg;
	trs_param.dst_seg = &dst_seg;

	memset(&src_seg, 0, sizeof(src_seg));
	memset(&dst_seg, 0, sizeof(dst_seg));

	for (i = 0; i < num_trs; i++) {
		compl_mode = compl_mode_mask;
		if (compl_none)
			compl_mode = ODP_DMA_COMPL_NONE;

		cur_len = trs_len;
		if (i == num_trs - 1) {
			cur_len = len - trs_len * i;
			compl_mode = compl_mode_mask & ~ODP_DMA_COMPL_NONE;
		}

		src_seg.addr = src + offset;
		src_seg.len  = cur_len;
		dst_seg.addr = dst + offset;
		dst_seg.len  = cur_len;
		offset += cur_len;

		if (compl_mode_mask == ODP_DMA_COMPL_SYNC)
			ret = do_transfer(dma, &trs_param, multi, res);
		else
			ret = do_transfer_async(dma, &trs_param, compl_mode, multi);

		if (ret < 1)
			break;
	}

	if (ret > 0) {
		CU_ASSERT(check_equal(src, dst, len) == 0);
		CU_ASSERT(check_zero(global.dst_addr, OFFSET) == 0);
		CU_ASSERT(check_zero(dst + len, global.len - len + TRAILER) == 0);
	}

	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_addr_to_addr_max_trs(odp_dma_compl_mode_t compl_mode_mask)
{
	odp_dma_param_t dma_param;
	uint32_t num_trs = global.dma_capa.max_transfers;
	odp_dma_transfer_param_t trs_param[num_trs];
	odp_dma_t dma;
	odp_dma_seg_t src_seg[num_trs];
	odp_dma_seg_t dst_seg[num_trs];
	int ret;
	uint32_t i, cur_len;
	uint8_t *src = global.src_addr + OFFSET;
	uint8_t *dst = global.dst_addr + OFFSET;
	uint32_t seg_len = ODPH_MIN(global.len / num_trs, global.dma_capa.max_seg_len);
	uint32_t len = seg_len * num_trs;
	uint32_t offset = 0;

	init_source(global.src_addr, global.data_size);
	memset(global.dst_addr, 0, global.data_size);

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = compl_mode_mask;
	dma = odp_dma_create("addr_to_addr", &dma_param);
	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	memset(src_seg, 0, sizeof(src_seg));
	memset(dst_seg, 0, sizeof(dst_seg));

	for (i = 0; i < num_trs; i++) {
		cur_len = seg_len;
		if (i == num_trs - 1)
			cur_len = len - seg_len * i;

		src_seg[i].addr = src + offset;
		src_seg[i].len  = cur_len;
		dst_seg[i].addr = dst + offset;
		dst_seg[i].len  = cur_len;
		offset += cur_len;
	}

	for (i = 0; i < num_trs; i++) {
		odp_dma_transfer_param_init(&trs_param[i]);
		trs_param[i].num_src = 1;
		trs_param[i].num_dst = 1;
		trs_param[i].src_seg = &src_seg[i];
		trs_param[i].dst_seg = &dst_seg[i];
	}

	ret = do_transfer_async(dma, trs_param, compl_mode_mask, num_trs);

	if (ret > 0) {
		CU_ASSERT(check_equal(src, dst, len) == 0);
		CU_ASSERT(check_zero(global.dst_addr, OFFSET) == 0);
		CU_ASSERT(check_zero(dst + len, global.len - len + TRAILER) == 0);
	}

	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_addr_to_pkt(odp_dma_compl_mode_t compl_mode_mask, int multi)
{
	odp_dma_param_t dma_param;
	odp_dma_transfer_param_t trs_param;
	odp_dma_t dma;
	odp_dma_seg_t src_seg;
	odp_dma_seg_t dst_seg;
	int ret;
	uint8_t *src, *pkt_data;
	odp_packet_t pkt;
	uint32_t len, seg_len;

	init_source(global.src_addr, global.data_size);

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = compl_mode_mask;
	dma = odp_dma_create("addr_to_pkt", &dma_param);
	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	pkt = odp_packet_alloc(global.pkt_pool, global.pkt_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	seg_len  = odp_packet_seg_len(pkt);
	pkt_data = odp_packet_data(pkt);
	memset(pkt_data, 0, seg_len);
	CU_ASSERT_FATAL(seg_len > OFFSET + TRAILER);

	len = seg_len - OFFSET - TRAILER;
	if (len > global.len)
		len = global.len;

	src = global.src_addr + OFFSET;

	memset(&src_seg, 0, sizeof(odp_dma_seg_t));
	memset(&dst_seg, 0, sizeof(odp_dma_seg_t));
	src_seg.addr   = src;
	src_seg.len    = len;
	dst_seg.packet = pkt;
	dst_seg.offset = OFFSET;
	dst_seg.len    = len;

	odp_dma_transfer_param_init(&trs_param);
	trs_param.src_format = ODP_DMA_FORMAT_ADDR;
	trs_param.dst_format = ODP_DMA_FORMAT_PACKET;
	trs_param.src_seg    = &src_seg;
	trs_param.dst_seg    = &dst_seg;

	if (compl_mode_mask == ODP_DMA_COMPL_SYNC)
		ret = do_transfer(dma, &trs_param, multi, 0);
	else
		ret = do_transfer_async(dma, &trs_param, compl_mode_mask, multi);

	if (ret > 0) {
		uint8_t *dst = pkt_data + OFFSET;

		CU_ASSERT(check_equal(src, dst, len) == 0);
		CU_ASSERT(check_zero(pkt_data, OFFSET) == 0);
		CU_ASSERT(check_zero(dst + len, TRAILER) == 0);
	}

	odp_packet_free(pkt);
	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_pkt_to_addr(odp_dma_compl_mode_t compl_mode_mask, int multi)
{
	odp_dma_param_t dma_param;
	odp_dma_transfer_param_t trs_param;
	odp_dma_t dma;
	odp_dma_seg_t src_seg;
	odp_dma_seg_t dst_seg;
	int ret;
	uint8_t *dst, *pkt_data;
	odp_packet_t pkt;
	uint32_t len, seg_len;

	memset(global.dst_addr, 0, global.data_size);

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = compl_mode_mask;
	dma = odp_dma_create("pkt_to_addr", &dma_param);
	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	pkt = odp_packet_alloc(global.pkt_pool, global.pkt_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	seg_len  = odp_packet_seg_len(pkt);
	pkt_data = odp_packet_data(pkt);
	init_source(pkt_data, seg_len);

	CU_ASSERT_FATAL(seg_len > OFFSET + TRAILER);

	len = seg_len - OFFSET - TRAILER;
	if (len > global.len)
		len = global.len;

	dst = global.dst_addr + OFFSET;

	memset(&src_seg, 0, sizeof(odp_dma_seg_t));
	memset(&dst_seg, 0, sizeof(odp_dma_seg_t));
	src_seg.packet = pkt;
	src_seg.offset = OFFSET;
	src_seg.len    = len;
	dst_seg.addr   = dst;
	dst_seg.len    = len;

	odp_dma_transfer_param_init(&trs_param);
	trs_param.src_format = ODP_DMA_FORMAT_PACKET;
	trs_param.dst_format = ODP_DMA_FORMAT_ADDR;
	trs_param.src_seg    = &src_seg;
	trs_param.dst_seg    = &dst_seg;

	if (compl_mode_mask == ODP_DMA_COMPL_SYNC)
		ret = do_transfer(dma, &trs_param, multi, 0);
	else
		ret = do_transfer_async(dma, &trs_param, compl_mode_mask, multi);

	if (ret > 0) {
		uint8_t *src = pkt_data + OFFSET;

		CU_ASSERT(check_equal(src, dst, len) == 0);
		CU_ASSERT(check_zero(global.dst_addr, OFFSET) == 0);
		CU_ASSERT(check_zero(dst + len, TRAILER) == 0);
	}

	odp_packet_free(pkt);
	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_pkt_to_pkt(odp_dma_compl_mode_t compl_mode_mask, int multi)
{
	odp_dma_param_t dma_param;
	odp_dma_transfer_param_t trs_param;
	odp_dma_t dma;
	odp_dma_seg_t src_seg;
	odp_dma_seg_t dst_seg;
	int ret;
	uint8_t *pkt_data, *pkt_data_2;
	odp_packet_t pkt, pkt_2;
	uint32_t len, seg_len, seg_len_2;

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = compl_mode_mask;
	dma = odp_dma_create("pkt_to_pkt", &dma_param);
	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	pkt = odp_packet_alloc(global.pkt_pool, global.pkt_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	pkt_2 = odp_packet_alloc(global.pkt_pool, global.pkt_len);
	CU_ASSERT_FATAL(pkt_2 != ODP_PACKET_INVALID);

	seg_len  = odp_packet_seg_len(pkt);
	pkt_data = odp_packet_data(pkt);
	init_source(pkt_data, seg_len);

	seg_len_2  = odp_packet_seg_len(pkt_2);
	pkt_data_2 = odp_packet_data(pkt_2);
	memset(pkt_data_2, 0, seg_len_2);

	CU_ASSERT_FATAL(seg_len > OFFSET + TRAILER);

	if (seg_len > seg_len_2)
		seg_len = seg_len_2;

	len = seg_len - OFFSET - TRAILER;

	memset(&src_seg, 0, sizeof(odp_dma_seg_t));
	memset(&dst_seg, 0, sizeof(odp_dma_seg_t));
	src_seg.packet = pkt;
	src_seg.offset = OFFSET;
	src_seg.len    = len;
	dst_seg.packet = pkt_2;
	dst_seg.offset = OFFSET;
	dst_seg.len    = len;

	odp_dma_transfer_param_init(&trs_param);
	trs_param.src_format = ODP_DMA_FORMAT_PACKET;
	trs_param.dst_format = ODP_DMA_FORMAT_PACKET;
	trs_param.src_seg    = &src_seg;
	trs_param.dst_seg    = &dst_seg;

	if (compl_mode_mask == ODP_DMA_COMPL_SYNC)
		ret = do_transfer(dma, &trs_param, multi, 0);
	else
		ret = do_transfer_async(dma, &trs_param, compl_mode_mask, multi);

	if (ret > 0) {
		uint8_t *src = pkt_data + OFFSET;
		uint8_t *dst = pkt_data_2 + OFFSET;

		CU_ASSERT(check_equal(src, dst, len) == 0);
		CU_ASSERT(check_zero(pkt_data_2, OFFSET) == 0);
		CU_ASSERT(check_zero(dst + len, TRAILER) == 0);
	}

	odp_packet_free(pkt);
	odp_packet_free(pkt_2);
	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_pkt_segs_to_addr_sync(void)
{
	odp_dma_param_t dma_param;
	odp_dma_transfer_param_t trs_param;
	odp_dma_t dma;
	odp_dma_seg_t src_seg;
	odp_dma_seg_t dst_seg;
	int ret;
	uint8_t *dst;
	odp_packet_t pkt;
	uint32_t i, len, num_segs;
	uint32_t pkt_len = ODPH_MIN(global.pkt_len, global.len);

	memset(global.dst_addr, 0, global.data_size);

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = ODP_DMA_COMPL_SYNC;
	dma = odp_dma_create("pkt_segs_to_addr", &dma_param);
	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	pkt = odp_packet_alloc(global.pkt_pool, pkt_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	num_segs = odp_packet_num_segs(pkt);
	if (num_segs > global.dma_capa.max_src_segs)
		num_segs = global.dma_capa.max_src_segs;

	init_source(global.src_addr, global.data_size);
	CU_ASSERT_FATAL(odp_packet_copy_from_mem(pkt, 0, pkt_len, global.src_addr) == 0);

	len = pkt_len - OFFSET - TRAILER;
	dst = global.dst_addr + OFFSET;

	memset(&src_seg, 0, sizeof(odp_dma_seg_t));
	memset(&dst_seg, 0, sizeof(odp_dma_seg_t));
	src_seg.packet = pkt;
	src_seg.offset = OFFSET;
	src_seg.len    = len;
	dst_seg.addr   = dst;
	dst_seg.len    = len;

	odp_dma_transfer_param_init(&trs_param);
	trs_param.src_format = ODP_DMA_FORMAT_PACKET;
	trs_param.dst_format = ODP_DMA_FORMAT_ADDR;
	trs_param.src_seg    = &src_seg;
	trs_param.dst_seg    = &dst_seg;

	for (i = 0; i < RETRIES; i++) {
		ret = odp_dma_transfer(dma, &trs_param, NULL);

		if (ret)
			break;
	}

	CU_ASSERT(ret > 0);

	if (ret > 0) {
		odp_packet_seg_t pkt_seg = odp_packet_first_seg(pkt);
		uint8_t *src = odp_packet_data(pkt);
		uint32_t seg_len = odp_packet_seg_len(pkt);

		src += OFFSET;
		seg_len -= OFFSET;

		for (i = 0; i < num_segs; i++) {
			if (i == (num_segs - 1))
				seg_len -= TRAILER;

			CU_ASSERT(check_equal(src, dst, seg_len) == 0);

			dst += seg_len;
			pkt_seg = odp_packet_next_seg(pkt, pkt_seg);
			if (pkt_seg != ODP_PACKET_SEG_INVALID) {
				src     = odp_packet_seg_data(pkt, pkt_seg);
				seg_len = odp_packet_seg_data_len(pkt, pkt_seg);
			}
		}

		CU_ASSERT(check_zero(global.dst_addr, OFFSET) == 0);
		CU_ASSERT(check_zero(global.dst_addr + OFFSET + len, TRAILER) == 0);
	}

	odp_packet_free(pkt);
	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static int check_sync(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int check_session_count(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.max_sessions > 1)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_event(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.compl_mode_mask & ODP_DMA_COMPL_EVENT)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_event_user_area(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if ((global.dma_capa.compl_mode_mask & ODP_DMA_COMPL_EVENT) &&
	    global.dma_capa.pool.max_uarea_size > 0)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_event_user_area_init(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.pool.max_uarea_size > 0 && global.dma_capa.pool.uarea_persistence)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_scheduled(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.queue_type_sched &&
	    (global.dma_capa.compl_mode_mask & ODP_DMA_COMPL_EVENT))
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_multiple_segs(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.max_src_segs > 1 && global.dma_capa.max_dst_segs > 1 &&
	    global.dma_capa.max_segs > 3)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_poll(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.compl_mode_mask & ODP_DMA_COMPL_POLL)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_sched_none(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.queue_type_sched &&
	    (global.dma_capa.compl_mode_mask & ODP_DMA_COMPL_EVENT) &&
	    (global.dma_capa.compl_mode_mask & ODP_DMA_COMPL_NONE))
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_poll_none(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.compl_mode_mask & ODP_DMA_COMPL_POLL &&
	    global.dma_capa.compl_mode_mask & ODP_DMA_COMPL_NONE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_src_seg_free_sync(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.src_seg_free && check_sync() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_src_seg_free_segs_sync(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (check_src_seg_free_sync() == ODP_TEST_ACTIVE &&
	    check_multiple_segs() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_dst_seg_alloc_sync(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.dst_seg_alloc && check_sync() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_dst_seg_alloc_segs_sync(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (check_dst_seg_alloc_sync() == ODP_TEST_ACTIVE &&
	    check_multiple_segs() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_src_seg_free_poll(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.src_seg_free && check_poll() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_src_seg_free_segs_poll(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (check_src_seg_free_poll() == ODP_TEST_ACTIVE &&
	    check_multiple_segs() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_dst_seg_alloc_poll(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.dst_seg_alloc && check_poll() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_dst_seg_alloc_segs_poll(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (check_dst_seg_alloc_poll() == ODP_TEST_ACTIVE &&
	    check_multiple_segs() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_src_seg_free_event(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.src_seg_free && check_event() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_src_seg_free_segs_event(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (check_src_seg_free_event() == ODP_TEST_ACTIVE &&
	    check_multiple_segs() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_dst_seg_alloc_event(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (global.dma_capa.dst_seg_alloc && check_event() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_dst_seg_alloc_segs_event(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (check_dst_seg_alloc_event() == ODP_TEST_ACTIVE &&
	    check_multiple_segs() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int check_src_seg_free_dst_seg_alloc(void)
{
	if (global.disabled)
		return ODP_TEST_INACTIVE;

	if (check_src_seg_free_sync() == ODP_TEST_ACTIVE &&
	    check_dst_seg_alloc_sync() == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static void test_dma_addr_to_addr_sync(void)
{
	test_dma_addr_to_addr(ODP_DMA_COMPL_SYNC, 1, 0, 0);
}

static void test_dma_addr_to_addr_sync_mtrs(void)
{
	test_dma_addr_to_addr_trs(ODP_DMA_COMPL_SYNC, global.dma_capa.max_transfers * 2, 0, 0);
}

static void test_dma_addr_to_addr_sync_mseg(void)
{
	if (global.dma_capa.max_src_segs > 1 && global.dma_capa.max_dst_segs > 1)
		test_dma_addr_to_addr(ODP_DMA_COMPL_SYNC, 2, 0, 0);

	if (global.dma_capa.max_src_segs > 2 && global.dma_capa.max_dst_segs > 2)
		test_dma_addr_to_addr(ODP_DMA_COMPL_SYNC, 3, 0, 0);
}

static void test_dma_addr_to_addr_sync_res(void)
{
	test_dma_addr_to_addr(ODP_DMA_COMPL_SYNC, 1, 0, RESULT);
}

static void get_seg_lens(uint32_t max_len, uint32_t *src, uint32_t *dst)
{
	uint32_t src_segs = *src, dst_segs = *dst, denom = ODPH_MIN(src_segs, dst_segs);

	max_len = ODPH_MIN(max_len / denom, global.dma_capa.max_seg_len) * denom;
	*src = max_len / src_segs;
	*dst = *src * src_segs / dst_segs + *src * src_segs % dst_segs;
}

static void test_dma_addr_to_addr_sync_max_seg(void)
{
	odp_dma_param_t dma_param;
	odp_dma_transfer_param_t trs_param;
	odp_dma_t dma;
	odp_dma_seg_t src_seg[global.dma_capa.max_src_segs];
	odp_dma_seg_t dst_seg[global.dma_capa.max_dst_segs];
	uint32_t src_len = global.dma_capa.max_src_segs, dst_len = global.dma_capa.max_dst_segs,
	len;
	int ret;

	init_source(global.src_addr, global.data_size);
	memset(global.dst_addr, 0, global.data_size);
	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = ODP_DMA_COMPL_SYNC;
	dma = odp_dma_create("addr_to_addr_max_seg", &dma_param);

	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	get_seg_lens(global.len, &src_len, &dst_len);

	for (uint32_t i = 0; i < global.dma_capa.max_src_segs; i++) {
		uint8_t *addr = global.src_addr + i * src_len;

		memset(&src_seg[i], 0, sizeof(odp_dma_seg_t));
		src_seg[i].addr = addr;
		src_seg[i].len = src_len;
	}

	len = src_len * global.dma_capa.max_src_segs;

	for (uint32_t i = 0; i < global.dma_capa.max_dst_segs; i++) {
		uint8_t *addr = global.dst_addr + i * dst_len;

		memset(&dst_seg[i], 0, sizeof(odp_dma_seg_t));
		dst_seg[i].addr = addr;
		dst_seg[i].len = ODPH_MIN(len, dst_len);
		len -= dst_len;
	}

	odp_dma_transfer_param_init(&trs_param);
	trs_param.src_format = ODP_DMA_FORMAT_ADDR;
	trs_param.dst_format = ODP_DMA_FORMAT_ADDR;
	trs_param.num_src = global.dma_capa.max_src_segs;
	trs_param.num_dst = global.dma_capa.max_dst_segs;
	trs_param.src_seg = src_seg;
	trs_param.dst_seg = dst_seg;
	ret = do_transfer(dma, &trs_param, 0, 0);

	if (ret > 0) {
		len = src_len * global.dma_capa.max_src_segs;

		CU_ASSERT(check_equal(global.src_addr, global.dst_addr, len) == 0);
	}

	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_addr_to_pkt_sync(void)
{
	test_dma_addr_to_pkt(ODP_DMA_COMPL_SYNC, 0);
}

static void test_dma_pkt_to_addr_sync(void)
{
	test_dma_pkt_to_addr(ODP_DMA_COMPL_SYNC, 0);
}

static void test_dma_pkt_to_pkt_sync(void)
{
	test_dma_pkt_to_pkt(ODP_DMA_COMPL_SYNC, 0);
}

static void test_dma_pkt_to_pkt_sync_max_seg(void)
{
	odp_dma_param_t dma_param;
	odp_dma_transfer_param_t trs_param;
	odp_dma_t dma;
	odp_packet_t pkt;
	odp_dma_seg_t src_seg[global.dma_capa.max_src_segs];
	odp_dma_seg_t dst_seg[global.dma_capa.max_dst_segs];
	uint32_t src_len = global.dma_capa.max_src_segs, dst_len = global.dma_capa.max_dst_segs,
	len;
	int ret;

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = ODP_DMA_COMPL_SYNC;
	dma = odp_dma_create("pkt_to_pkt_max_seg", &dma_param);

	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	pkt = odp_packet_alloc(global.pkt_pool, global.pkt_len);

	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	get_seg_lens(odp_packet_seg_len(pkt), &src_len, &dst_len);
	odp_packet_free(pkt);

	for (uint32_t i = 0; i < global.dma_capa.max_src_segs; i++) {
		pkt = odp_packet_alloc(global.pkt_pool, src_len);

		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

		init_source(odp_packet_data(pkt), src_len);
		memset(&src_seg[i], 0, sizeof(odp_dma_seg_t));
		src_seg[i].packet = pkt;
		src_seg[i].len = src_len;
	}

	len = src_len * global.dma_capa.max_src_segs;

	for (uint32_t i = 0; i < global.dma_capa.max_dst_segs; i++) {
		pkt = odp_packet_alloc(global.pkt_pool, dst_len);

		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

		memset(odp_packet_data(pkt), 0, dst_len);
		memset(&dst_seg[i], 0, sizeof(odp_dma_seg_t));
		dst_seg[i].packet = pkt;
		dst_seg[i].len = ODPH_MIN(len, dst_len);
		len -= dst_len;
	}

	odp_dma_transfer_param_init(&trs_param);
	trs_param.src_format = ODP_DMA_FORMAT_PACKET;
	trs_param.dst_format = ODP_DMA_FORMAT_PACKET;
	trs_param.num_src = global.dma_capa.max_src_segs;
	trs_param.num_dst = global.dma_capa.max_dst_segs;
	trs_param.src_seg = src_seg;
	trs_param.dst_seg = dst_seg;
	ret = do_transfer(dma, &trs_param, 0, 0);

	if (ret > 0) {
		len = src_len * global.dma_capa.max_src_segs;
		uint8_t src[len], dst[len];

		for (uint32_t i = 0; i < global.dma_capa.max_src_segs; i++) {
			memcpy(src + i * src_len, odp_packet_data(src_seg[i].packet),
			       src_seg[i].len);
			odp_packet_free(src_seg[i].packet);
		}

		for (uint32_t i = 0; i < global.dma_capa.max_dst_segs; i++) {
			memcpy(dst + i * dst_len, odp_packet_data(dst_seg[i].packet),
			       dst_seg[i].len);
			odp_packet_free(dst_seg[i].packet);
		}

		CU_ASSERT(check_equal(src, dst, len) == 0);
	}

	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_pkt_to_pkt_multiple_offsets(void)
{
	/* Test transfers data from two source packets to single destination packet, but with two
	 * offsets, so allocate three packets and reserve two destination segments for the
	 * different offsets. */
	odp_dma_param_t dma_param;
	odp_dma_transfer_param_t trs_param;
	odp_dma_t dma;
	const uint32_t num_pkts = 2;
	odp_packet_t dst_pkt, src_pkts[num_pkts];
	uint32_t seg_len, len, offset = 0;
	int ret;
	odp_dma_seg_t src_seg[num_pkts];
	odp_dma_seg_t dst_seg[num_pkts];

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = ODP_DMA_COMPL_SYNC;
	dma = odp_dma_create("pkt_to_pkt_offsets", &dma_param);
	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	dst_pkt = odp_packet_alloc(global.pkt_pool, global.pkt_len);
	CU_ASSERT_FATAL(dst_pkt != ODP_PACKET_INVALID);

	seg_len = odp_packet_seg_len(dst_pkt);
	len = (seg_len - OFFSET) / num_pkts;
	ret = odp_packet_alloc_multi(global.pkt_pool, len, src_pkts, num_pkts);
	CU_ASSERT_FATAL(ret == (int)num_pkts);

	for (uint32_t i = 0; i < num_pkts; i++)
		init_source(odp_packet_data(src_pkts[i]), len);

	memset(odp_packet_data(dst_pkt), 0, seg_len);
	memset(src_seg, 0, sizeof(src_seg));
	memset(dst_seg, 0, sizeof(dst_seg));

	for (uint32_t i = 0; i < num_pkts; i++) {
		odp_dma_seg_t *seg = &src_seg[i];

		seg->packet = src_pkts[i];
		seg->len = len;

		seg = &dst_seg[i];
		seg->packet = dst_pkt;
		seg->offset = offset;
		seg->len = len;
		offset += len + OFFSET;
	}

	odp_dma_transfer_param_init(&trs_param);
	trs_param.src_format = ODP_DMA_FORMAT_PACKET;
	trs_param.dst_format = ODP_DMA_FORMAT_PACKET;
	trs_param.num_src = num_pkts;
	trs_param.num_dst = num_pkts;
	trs_param.src_seg = src_seg;
	trs_param.dst_seg = dst_seg;
	ret = do_transfer(dma, &trs_param, 0, 0);

	if (ret > 0) {
		uint8_t *src_data = odp_packet_data(src_pkts[0]);
		uint8_t *dst_data = odp_packet_data(dst_pkt);

		CU_ASSERT(check_equal(src_data, dst_data, len) == 0);

		src_data = odp_packet_data(src_pkts[1]);

		CU_ASSERT(check_equal(src_data, dst_data + len + OFFSET, len) == 0);
		CU_ASSERT(check_zero(dst_data + len, OFFSET) == 0);
	}

	odp_packet_free_multi(src_pkts, num_pkts);
	odp_packet_free(dst_pkt);
	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static odp_dma_t create_dma(odp_dma_compl_mode_t mask)
{
	odp_dma_param_t dma_param;
	odp_dma_t dma;

	odp_dma_param_init(&dma_param);
	dma_param.compl_mode_mask = mask;
	dma = odp_dma_create("pkt_to_pkt_opts", &dma_param);

	CU_ASSERT_FATAL(dma != ODP_DMA_INVALID);

	return dma;
}

static odp_pool_t create_pool(uint32_t num)
{
	odp_pool_param_t pool_param = global.pool_param;
	odp_pool_t pool;

	pool_param.pkt.num = num;
	pool = odp_pool_create("pkt_to_pkt_opts", &pool_param);

	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	return pool;
}

static uint32_t allocate_packets(odp_pool_t pool, odp_packet_t pkts[], uint32_t len, uint32_t num)
{
	odp_packet_t pkt;
	uint32_t seg_len = 0;

	for (uint32_t i = 0; i < num; i++) {
		pkt = odp_packet_alloc(pool, len);

		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

		seg_len = odp_packet_seg_len(pkt);
		init_source(odp_packet_data(pkt), seg_len);
		pkts[i] = pkt;
	}

	return seg_len;
}

static void setup_segs(odp_dma_seg_t segs[], odp_packet_t pkt, uint32_t len, uint32_t num,
		       odp_bool_t use_idx)
{
	odp_dma_seg_t *seg;
	const uint32_t seg_len = len / num;
	uint32_t offset = 0;

	for (uint32_t i = 0; i < num; i++) {
		seg = &segs[i];

		if (use_idx) {
			seg->pkt_index = 0;
			seg->pkt_len = len;
		} else {
			seg->packet = pkt;
		}

		seg->len = seg_len;
		seg->offset = offset;
		offset += seg_len;
	}
}

static void set_src_ref(odp_dma_transfer_param_t *trs)
{
	odp_packet_t src = trs->src_seg[0].packet, src_ref = ODP_PACKET_INVALID;

	src_ref = trs->opts.seg_free ? odp_packet_copy(src, global.pkt_pool) : src;

	CU_ASSERT_FATAL(src_ref != ODP_PACKET_INVALID);

	global.src_ref_opts = src_ref;
}

static void test_dma_pkt_to_pkt_opts(odp_dma_compl_mode_t mask, const opts_t *opts)
{
	odp_dma_t dma;
	odp_pool_t pool = global.pkt_pool;
	/* One source and one destination packet. */
	const uint32_t num_pkts = 2, src_idx = 0, dst_idx = 1,
	num_src_seg = opts->unique_src_segs ? 1 : 2, num_dst_seg = opts->unique_dst_segs ? 1 : 2;
	odp_packet_t pkts[num_pkts], pkt;
	uint32_t seg_len;
	odp_dma_seg_t src_seg[num_pkts];
	odp_dma_seg_t dst_seg[num_pkts];
	odp_dma_transfer_param_t trs_param;
	int ret;

	memset(src_seg, 0, sizeof(src_seg));
	memset(dst_seg, 0, sizeof(dst_seg));
	dma = create_dma(mask);

	if (opts->seg_free)
		pool = create_pool(num_pkts);

	seg_len = allocate_packets(pool, pkts, global.pkt_len, num_pkts);
	setup_segs(src_seg, pkts[src_idx], seg_len, num_src_seg, false);
	setup_segs(dst_seg, pkts[dst_idx], seg_len, num_dst_seg, opts->seg_alloc);

	odp_dma_transfer_param_init(&trs_param);
	trs_param.src_format = ODP_DMA_FORMAT_PACKET;
	trs_param.dst_format = ODP_DMA_FORMAT_PACKET;
	trs_param.num_src = num_src_seg;
	trs_param.num_dst = num_dst_seg;
	trs_param.src_seg = src_seg;
	trs_param.dst_seg = dst_seg;
	trs_param.opts.seg_free = opts->seg_free;
	trs_param.opts.unique_src_segs = opts->unique_src_segs;
	trs_param.opts.single_pool = opts->single_pool;
	trs_param.opts.seg_alloc = opts->seg_alloc;
	trs_param.opts.unique_dst_segs = opts->unique_dst_segs;
	set_src_ref(&trs_param);

	if (opts->seg_alloc)
		trs_param.dst_seg_pool = global.pkt_pool;

	if (mask == ODP_DMA_COMPL_SYNC)
		ret = do_transfer(dma, &trs_param, 0, 1);
	else
		ret = do_transfer_async(dma, &trs_param, mask, 0);

	if (ret == 1) {
		if (!opts->seg_alloc)
			CU_ASSERT(check_equal(odp_packet_data(global.src_ref_opts),
					      odp_packet_data(pkts[dst_idx]), seg_len) == 0);

		if (opts->seg_free) {
			/* The transfer-freed packet should be available now. */
			pkt = odp_packet_alloc(pool, global.pkt_len);

			CU_ASSERT(pkt != ODP_PACKET_INVALID);

			odp_packet_free(pkt);
		}
	} else if (opts->seg_free) {
		odp_packet_free(pkts[src_idx]);
	}

	/* 'global.src_ref_opts' is either 'pkts[src_idx]' if source segments are not freed or a
	   copy of it if they are. */
	odp_packet_free(global.src_ref_opts);
	odp_packet_free(pkts[dst_idx]);

	if (opts->seg_free)
		CU_ASSERT(odp_pool_destroy(pool) == 0);

	CU_ASSERT(odp_dma_destroy(dma) == 0);
}

static void test_dma_src_seg_free_sync(void)
{
	const opts_t opts = { .seg_free = true,
			      .unique_src_segs = true,
			      .single_pool = false,
			      .seg_alloc = false,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_SYNC, &opts);
}

static void test_dma_src_seg_free_single_pool_sync(void)
{
	const opts_t opts = { .seg_free = true,
			      .unique_src_segs = true,
			      .single_pool = true,
			      .seg_alloc = false,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_SYNC, &opts);
}

static void test_dma_src_seg_free_multiple_offsets_sync(void)
{
	const opts_t opts = { .seg_free = true,
			      .unique_src_segs = false,
			      .single_pool = false,
			      .seg_alloc = false,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_SYNC, &opts);
}

static void test_dma_dst_seg_alloc_sync(void)
{
	const opts_t opts = { .seg_free = false,
			      .unique_src_segs = true,
			      .single_pool = false,
			      .seg_alloc = true,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_SYNC, &opts);
}

static void test_dma_dst_seg_alloc_multiple_offsets_sync(void)
{
	const opts_t opts = { .seg_free = false,
			      .unique_src_segs = true,
			      .single_pool = false,
			      .seg_alloc = true,
			      .unique_dst_segs = false };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_SYNC, &opts);
}

static void test_dma_src_seg_free_dst_seg_alloc(void)
{
	const opts_t opts = { .seg_free = true,
			      .unique_src_segs = true,
			      .single_pool = false,
			      .seg_alloc = true,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_SYNC, &opts);
}

static void test_dma_addr_to_addr_poll(void)
{
	test_dma_addr_to_addr(ODP_DMA_COMPL_POLL, 1, 0, 0);
}

static void test_dma_addr_to_addr_poll_mtrs(void)
{
	test_dma_addr_to_addr_trs(ODP_DMA_COMPL_POLL, 2, 0, 0);
}

static void test_dma_addr_to_addr_poll_mseg(void)
{
	if (global.dma_capa.max_src_segs > 1 && global.dma_capa.max_dst_segs > 1)
		test_dma_addr_to_addr(ODP_DMA_COMPL_POLL, 2, 0, 0);

	if (global.dma_capa.max_src_segs > 2 && global.dma_capa.max_dst_segs > 2)
		test_dma_addr_to_addr(ODP_DMA_COMPL_POLL, 3, 0, 0);
}

static void test_dma_addr_to_pkt_poll(void)
{
	test_dma_addr_to_pkt(ODP_DMA_COMPL_POLL, 0);
}

static void test_dma_pkt_to_addr_poll(void)
{
	test_dma_pkt_to_addr(ODP_DMA_COMPL_POLL, 0);
}

static void test_dma_pkt_to_pkt_poll(void)
{
	test_dma_pkt_to_pkt(ODP_DMA_COMPL_POLL, 0);
}

static void test_dma_src_seg_free_poll(void)
{
	const opts_t opts = { .seg_free = true,
			      .unique_src_segs = true,
			      .single_pool = false,
			      .seg_alloc = false,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_POLL, &opts);
}

static void test_dma_src_seg_free_single_pool_poll(void)
{
	const opts_t opts = { .seg_free = true,
			      .unique_src_segs = true,
			      .single_pool = true,
			      .seg_alloc = false,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_POLL, &opts);
}

static void test_dma_src_seg_free_multiple_offsets_poll(void)
{
	const opts_t opts = { .seg_free = true,
			      .unique_src_segs = false,
			      .single_pool = false,
			      .seg_alloc = false,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_POLL, &opts);
}

static void test_dma_dst_seg_alloc_poll(void)
{
	const opts_t opts = { .seg_free = false,
			      .unique_src_segs = true,
			      .single_pool = false,
			      .seg_alloc = true,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_POLL, &opts);
}

static void test_dma_dst_seg_alloc_multiple_offsets_poll(void)
{
	const opts_t opts = { .seg_free = false,
			      .unique_src_segs = true,
			      .single_pool = false,
			      .seg_alloc = true,
			      .unique_dst_segs = false };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_POLL, &opts);
}

static void test_dma_addr_to_addr_event(void)
{
	test_dma_addr_to_addr(ODP_DMA_COMPL_EVENT, 1, 0, 0);
}

static void test_dma_addr_to_addr_event_mtrs(void)
{
	test_dma_addr_to_addr_trs(ODP_DMA_COMPL_EVENT, 2, 0, 0);
}

static void test_dma_addr_to_addr_event_mseg(void)
{
	if (global.dma_capa.max_src_segs > 1 && global.dma_capa.max_dst_segs > 1)
		test_dma_addr_to_addr(ODP_DMA_COMPL_EVENT, 2, 0, 0);

	if (global.dma_capa.max_src_segs > 2 && global.dma_capa.max_dst_segs > 2)
		test_dma_addr_to_addr(ODP_DMA_COMPL_EVENT, 3, 0, 0);
}

static void test_dma_addr_to_pkt_event(void)
{
	test_dma_addr_to_pkt(ODP_DMA_COMPL_EVENT, 0);
}

static void test_dma_pkt_to_addr_event(void)
{
	test_dma_pkt_to_addr(ODP_DMA_COMPL_EVENT, 0);
}

static void test_dma_pkt_to_pkt_event(void)
{
	test_dma_pkt_to_pkt(ODP_DMA_COMPL_EVENT, 0);
}

static void test_dma_src_seg_free_event(void)
{
	const opts_t opts = { .seg_free = true,
			      .unique_src_segs = true,
			      .single_pool = false,
			      .seg_alloc = false,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_EVENT, &opts);
}

static void test_dma_src_seg_free_single_pool_event(void)
{
	const opts_t opts = { .seg_free = true,
			      .unique_src_segs = true,
			      .single_pool = true,
			      .seg_alloc = false,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_EVENT, &opts);
}

static void test_dma_src_seg_free_multiple_offsets_event(void)
{
	const opts_t opts = { .seg_free = true,
			      .unique_src_segs = false,
			      .single_pool = false,
			      .seg_alloc = false,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_EVENT, &opts);
}

static void test_dma_dst_seg_alloc_event(void)
{
	const opts_t opts = { .seg_free = false,
			      .unique_src_segs = true,
			      .single_pool = false,
			      .seg_alloc = true,
			      .unique_dst_segs = true };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_EVENT, &opts);
}

static void test_dma_dst_seg_alloc_multiple_offsets_event(void)
{
	const opts_t opts = { .seg_free = false,
			      .unique_src_segs = true,
			      .single_pool = false,
			      .seg_alloc = true,
			      .unique_dst_segs = false };

	test_dma_pkt_to_pkt_opts(ODP_DMA_COMPL_EVENT, &opts);
}

static void test_dma_addr_to_addr_poll_none(void)
{
	test_dma_addr_to_addr_trs(ODP_DMA_COMPL_POLL | ODP_DMA_COMPL_NONE, 2, 0, 0);
}

static void test_dma_addr_to_addr_event_none(void)
{
	test_dma_addr_to_addr_trs(ODP_DMA_COMPL_EVENT | ODP_DMA_COMPL_NONE, 2, 0, 0);
}

static void test_dma_multi_addr_to_addr_sync(void)
{
	test_dma_addr_to_addr(ODP_DMA_COMPL_SYNC, 1, MULTI, 0);
}

static void test_dma_multi_addr_to_addr_sync_res(void)
{
	test_dma_addr_to_addr(ODP_DMA_COMPL_SYNC, 1, MULTI, RESULT);
}

static void test_dma_multi_addr_to_pkt_sync(void)
{
	test_dma_addr_to_pkt(ODP_DMA_COMPL_SYNC, MULTI);
}

static void test_dma_multi_pkt_to_addr_sync(void)
{
	test_dma_pkt_to_addr(ODP_DMA_COMPL_SYNC, MULTI);
}

static void test_dma_multi_pkt_to_pkt_sync(void)
{
	test_dma_pkt_to_pkt(ODP_DMA_COMPL_SYNC, MULTI);
}

static void test_dma_multi_addr_to_addr_poll(void)
{
	test_dma_addr_to_addr(ODP_DMA_COMPL_POLL, 1, MULTI, 0);
}

static void test_dma_multi_addr_to_addr_poll_max_trs(void)
{
	test_dma_addr_to_addr_max_trs(ODP_DMA_COMPL_POLL);
}

static void test_dma_multi_addr_to_pkt_poll(void)
{
	test_dma_addr_to_pkt(ODP_DMA_COMPL_POLL, MULTI);
}

static void test_dma_multi_pkt_to_addr_poll(void)
{
	test_dma_pkt_to_addr(ODP_DMA_COMPL_POLL, MULTI);
}

static void test_dma_multi_pkt_to_pkt_poll(void)
{
	test_dma_pkt_to_pkt(ODP_DMA_COMPL_POLL, MULTI);
}

static void test_dma_multi_addr_to_addr_event(void)
{
	test_dma_addr_to_addr(ODP_DMA_COMPL_EVENT, 1, MULTI, 0);
}

static void test_dma_multi_addr_to_addr_event_max_trs(void)
{
	test_dma_addr_to_addr_max_trs(ODP_DMA_COMPL_EVENT);
}

static void test_dma_multi_addr_to_pkt_event(void)
{
	test_dma_addr_to_pkt(ODP_DMA_COMPL_EVENT, MULTI);
}

static void test_dma_multi_pkt_to_addr_event(void)
{
	test_dma_pkt_to_addr(ODP_DMA_COMPL_EVENT, MULTI);
}

static void test_dma_multi_pkt_to_pkt_event(void)
{
	test_dma_pkt_to_pkt(ODP_DMA_COMPL_EVENT, MULTI);
}

odp_testinfo_t dma_suite[] = {
	ODP_TEST_INFO(test_dma_capability),
	ODP_TEST_INFO_CONDITIONAL(test_dma_param_init, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_debug, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_same_name_null, check_session_count),
	ODP_TEST_INFO_CONDITIONAL(test_dma_same_name_named, check_session_count),
	ODP_TEST_INFO_CONDITIONAL(test_dma_long_name, check_session_count),
	ODP_TEST_INFO_CONDITIONAL(test_dma_compl_pool, check_event),
	ODP_TEST_INFO_CONDITIONAL(test_dma_compl_pool_same_name, check_event),
	ODP_TEST_INFO_CONDITIONAL(test_dma_compl_pool_long_name, check_event),
	ODP_TEST_INFO_CONDITIONAL(test_dma_compl_pool_max_pools, check_event),
	ODP_TEST_INFO_CONDITIONAL(test_dma_compl_user_area, check_event_user_area),
	ODP_TEST_INFO_CONDITIONAL(test_dma_compl_user_area_init, check_event_user_area_init),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_sync, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_sync_mtrs, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_sync_mseg, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_sync_res, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_sync_max_seg, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_pkt_sync, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_pkt_to_addr_sync, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_pkt_to_pkt_sync, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_pkt_to_pkt_sync_max_seg, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_pkt_to_pkt_multiple_offsets, check_multiple_segs),
	ODP_TEST_INFO_CONDITIONAL(test_dma_src_seg_free_sync, check_src_seg_free_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_src_seg_free_single_pool_sync, check_src_seg_free_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_src_seg_free_multiple_offsets_sync,
				  check_src_seg_free_segs_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_dst_seg_alloc_sync, check_dst_seg_alloc_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_dst_seg_alloc_multiple_offsets_sync,
				  check_dst_seg_alloc_segs_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_src_seg_free_dst_seg_alloc,
				  check_src_seg_free_dst_seg_alloc),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_poll, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_poll_mtrs, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_poll_mseg, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_pkt_poll, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_pkt_to_addr_poll, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_pkt_to_pkt_poll, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_src_seg_free_poll, check_src_seg_free_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_src_seg_free_single_pool_poll, check_src_seg_free_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_src_seg_free_multiple_offsets_poll,
				  check_src_seg_free_segs_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_dst_seg_alloc_poll, check_dst_seg_alloc_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_dst_seg_alloc_multiple_offsets_poll,
				  check_dst_seg_alloc_segs_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_event, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_event_mtrs, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_event_mseg, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_pkt_event, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_pkt_to_addr_event, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_pkt_to_pkt_event, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_src_seg_free_event, check_src_seg_free_event),
	ODP_TEST_INFO_CONDITIONAL(test_dma_src_seg_free_single_pool_event,
				  check_src_seg_free_event),
	ODP_TEST_INFO_CONDITIONAL(test_dma_src_seg_free_multiple_offsets_event,
				  check_src_seg_free_segs_event),
	ODP_TEST_INFO_CONDITIONAL(test_dma_dst_seg_alloc_event, check_dst_seg_alloc_event),
	ODP_TEST_INFO_CONDITIONAL(test_dma_dst_seg_alloc_multiple_offsets_event,
				  check_dst_seg_alloc_segs_event),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_poll_none, check_poll_none),
	ODP_TEST_INFO_CONDITIONAL(test_dma_addr_to_addr_event_none, check_sched_none),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_addr_to_addr_sync, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_addr_to_addr_sync_res, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_addr_to_pkt_sync, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_pkt_to_addr_sync, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_pkt_to_pkt_sync, check_sync),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_addr_to_addr_poll, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_addr_to_addr_poll_max_trs, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_addr_to_pkt_poll, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_pkt_to_addr_poll, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_pkt_to_pkt_poll, check_poll),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_addr_to_addr_event, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_addr_to_addr_event_max_trs, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_addr_to_pkt_event, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_pkt_to_addr_event, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_multi_pkt_to_pkt_event, check_scheduled),
	ODP_TEST_INFO_CONDITIONAL(test_dma_pkt_segs_to_addr_sync, check_sync),
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t dma_suites[] = {
		{"DMA", dma_suite_init, dma_suite_term, dma_suite},
		ODP_SUITE_INFO_NULL
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(dma_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

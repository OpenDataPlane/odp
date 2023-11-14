/* Copyright (c) 2015-2018, Linaro Limited
 * Copyright (c) 2021-2023, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp_cunit_common.h>
#include "odp_classification_testsuites.h"
#include "classification.h"

#define PMR_SET_NUM	5

/* Limit handle array allocation from stack to about 256kB */
#define MAX_HANDLES     (32 * 1024)

static void test_defaults(uint8_t fill)
{
	odp_cls_cos_param_t cos_param;
	odp_pmr_param_t pmr_param;

	memset(&cos_param, fill, sizeof(cos_param));
	odp_cls_cos_param_init(&cos_param);

	CU_ASSERT(cos_param.action == ODP_COS_ACTION_ENQUEUE);
	CU_ASSERT(cos_param.num_queue == 1);
	CU_ASSERT_EQUAL(cos_param.stats_enable, false);
	CU_ASSERT_EQUAL(cos_param.red.enable, false);
	CU_ASSERT_EQUAL(cos_param.bp.enable, false);
	CU_ASSERT_EQUAL(cos_param.vector.enable, false);

	memset(&pmr_param, fill, sizeof(pmr_param));
	odp_cls_pmr_param_init(&pmr_param);
	CU_ASSERT_EQUAL(pmr_param.range_term, false);
}

static void cls_default_values(void)
{
	test_defaults(0);
	test_defaults(0xff);
}

static void cls_create_cos(void)
{
	odp_cos_t cos;
	odp_cls_cos_param_t cls_param;
	odp_pool_t pool;
	odp_queue_t queue;

	pool = pool_create("cls_basic_pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	queue = queue_create("cls_basic_queue", true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create(NULL, &cls_param);
	CU_ASSERT(odp_cos_to_u64(cos) != odp_cos_to_u64(ODP_COS_INVALID));
	odp_cos_destroy(cos);
	odp_pool_destroy(pool);
	odp_queue_destroy(queue);
}

static void cls_create_cos_max_common(odp_bool_t stats)
{
	uint32_t i, num;
	odp_cls_cos_param_t cls_param;
	odp_cls_capability_t capa;

	CU_ASSERT_FATAL(odp_cls_capability(&capa) == 0);

	num = capa.max_cos;
	if (num > MAX_HANDLES)
		num = MAX_HANDLES;

	if (stats && capa.max_cos_stats < num)
		num = capa.max_cos_stats;

	odp_cos_t cos[num];

	for (i = 0; i < num; i++) {
		odp_cls_cos_param_init(&cls_param);
		cls_param.action = ODP_COS_ACTION_DROP;
		cls_param.stats_enable = stats;

		cos[i] = odp_cls_cos_create(NULL, &cls_param);
		if (cos[i] == ODP_COS_INVALID) {
			ODPH_ERR("odp_cls_cos_create() failed at CoS %u out of %u.\n", i + 1, num);
			break;
		}
	}

	CU_ASSERT(i == num);

	for (uint32_t j = 0; j < i; j++)
		CU_ASSERT(!odp_cos_destroy(cos[j]));
}

static int cos_create_multi(const char *name[], const odp_cls_cos_param_t param[], odp_cos_t cos[],
			    uint32_t num)
{
	const uint32_t max_retries = 100;
	uint32_t num_created = 0;
	uint32_t num_retries = 0;

	do {
		const char **cur_name = (name != NULL) ? &name[num_created] : NULL;
		int ret =  odp_cls_cos_create_multi(cur_name, &param[num_created],
						    &cos[num_created], num - num_created);
		if (ret < 0) {
			CU_FAIL("CoS create multi failed");
			break;
		}
		num_retries = (ret == 0) ? num_retries + 1 : 0;
		num_created += ret;
	} while (num_created < num && num_retries < max_retries);

	return num_created;
}

static void cos_destroy_multi(odp_cos_t cos[], uint32_t num)
{
	uint32_t num_left = num;
	uint32_t num_freed = 0;

	while (num_left) {
		int ret = odp_cos_destroy_multi(&cos[num_freed], num_left);

		CU_ASSERT_FATAL(ret > 0 && (uint32_t)ret <= num_left);

		num_left -= ret;
		num_freed += ret;
	}
	CU_ASSERT_FATAL(num_freed == num);
}

static void cls_create_cos_multi(void)
{
	odp_cls_cos_param_t param_single;
	odp_cls_cos_param_t param[MAX_HANDLES];
	odp_cls_capability_t capa;
	odp_cos_t cos[MAX_HANDLES];
	const char *name[MAX_HANDLES] = {NULL, "aaa", NULL, "bbb", "ccc", NULL, "ddd"};
	uint32_t num, num_created;

	CU_ASSERT_FATAL(odp_cls_capability(&capa) == 0);
	CU_ASSERT_FATAL(capa.max_cos);

	num = capa.max_cos < MAX_HANDLES ? capa.max_cos : MAX_HANDLES;

	for (uint32_t i = 0; i < num; i++) {
		odp_cls_cos_param_init(&param[i]);
		param[i].action = ODP_COS_ACTION_DROP;
	}
	odp_cls_cos_param_init(&param_single);
	param_single.action = ODP_COS_ACTION_DROP;

	num_created = cos_create_multi(NULL, &param_single, cos, 1);
	CU_ASSERT(num_created == 1)
	cos_destroy_multi(cos, num_created);

	num_created = cos_create_multi(name, param, cos, num);
	CU_ASSERT(num_created == num)
	cos_destroy_multi(cos, num_created);

	num_created = cos_create_multi(NULL, param, cos, num);
	CU_ASSERT(num_created == num)
	cos_destroy_multi(cos, num_created);
}

static void cls_create_cos_max(void)
{
	cls_create_cos_max_common(false);
}

static void cls_create_cos_max_stats(void)
{
	cls_create_cos_max_common(true);
}

static void cls_destroy_cos(void)
{
	odp_cos_t cos;
	char name[ODP_COS_NAME_LEN];
	odp_pool_t pool;
	odp_queue_t queue;
	odp_cls_cos_param_t cls_param;
	int retval;

	pool = pool_create("cls_basic_pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	queue = queue_create("cls_basic_queue", true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	sprintf(name, "ClassOfService");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create(name, &cls_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);
	retval = odp_cos_destroy(cos);
	CU_ASSERT(retval == 0);
	retval = odp_cos_destroy(ODP_COS_INVALID);
	CU_ASSERT(retval < 0);

	odp_pool_destroy(pool);
	odp_queue_destroy(queue);
}

static void cls_create_pmr_match(void)
{
	odp_pmr_t pmr;
	uint16_t val;
	uint16_t mask;
	int retval;
	odp_pmr_param_t pmr_param;
	odp_cos_t default_cos;
	odp_cos_t cos;
	odp_queue_t default_queue;
	odp_queue_t queue;
	odp_pool_t default_pool;
	odp_pool_t pool;
	odp_pool_t pkt_pool;
	odp_cls_cos_param_t cls_param;
	odp_pktio_t pktio;

	pkt_pool = pool_create("pkt_pool");
	CU_ASSERT_FATAL(pkt_pool != ODP_POOL_INVALID);

	pktio = create_pktio(ODP_QUEUE_TYPE_SCHED, pkt_pool, true);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	configure_default_cos(pktio, &default_cos,
			      &default_queue, &default_pool);

	queue = queue_create("pmr_match", true);
	CU_ASSERT(queue != ODP_QUEUE_INVALID);

	pool = pool_create("pmr_match");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create("pmr_match", &cls_param);
	CU_ASSERT(cos != ODP_COS_INVALID);

	val = 1024;
	mask = 0xffff;
	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = find_first_supported_l3_pmr();
	pmr_param.range_term = false;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pmr = odp_cls_pmr_create(&pmr_param, 1, default_cos, cos);
	CU_ASSERT(pmr != ODP_PMR_INVALID);
	CU_ASSERT(odp_pmr_to_u64(pmr) != odp_pmr_to_u64(ODP_PMR_INVALID));
	/* destroy the created PMR */
	retval = odp_cls_pmr_destroy(pmr);
	CU_ASSERT(retval == 0);

	/* destroy an INVALID PMR */
	retval = odp_cls_pmr_destroy(ODP_PMR_INVALID);
	CU_ASSERT(retval < 0);

	odp_cos_destroy(cos);
	odp_queue_destroy(queue);
	odp_pool_destroy(pool);
	odp_pool_destroy(pkt_pool);
	odp_pktio_default_cos_set(pktio, ODP_COS_INVALID);
	odp_cos_destroy(default_cos);
	odp_queue_destroy(default_queue);
	odp_pool_destroy(default_pool);
	odp_pktio_close(pktio);
}

/* Create maximum number of PMRs into the default CoS */
static void cls_max_pmr_from_default_action(int drop)
{
	odp_cls_cos_param_t cos_param;
	odp_queue_param_t queue_param;
	odp_cls_capability_t capa;
	odp_schedule_capability_t sched_capa;
	odp_pmr_param_t pmr_param;
	odp_pool_t pool;
	odp_pktio_t pktio;
	odp_cos_t default_cos;
	uint32_t i, num_cos, num_pmr;
	int ret;
	uint32_t cos_created = 0;
	uint32_t queue_created = 0;
	uint32_t pmr_created = 0;
	uint16_t val = 1024;
	uint16_t mask = 0xffff;

	CU_ASSERT_FATAL(odp_cls_capability(&capa) == 0);

	CU_ASSERT_FATAL(odp_schedule_capability(&sched_capa) == 0);

	pool = pool_create("pkt_pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	pktio = create_pktio(ODP_QUEUE_TYPE_SCHED, pool, true);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	num_cos = capa.max_cos;

	if (num_cos > sched_capa.max_queues)
		num_cos = sched_capa.max_queues;

	if (num_cos > MAX_HANDLES)
		num_cos = MAX_HANDLES;

	CU_ASSERT_FATAL(num_cos > 1);

	num_pmr = num_cos - 1;

	odp_cos_t cos[num_cos];
	odp_queue_t queue[num_cos];
	odp_pmr_t pmr[num_pmr];

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;

	odp_cls_cos_param_init(&cos_param);
	if (drop)
		cos_param.action = ODP_COS_ACTION_DROP;

	for (i = 0; i < num_cos; i++) {
		if (!drop) {
			queue[i] = odp_queue_create(NULL, &queue_param);

			if (queue[i] == ODP_QUEUE_INVALID) {
				ODPH_ERR("odp_queue_create() failed %u / %u\n", i + 1, num_cos);
				break;
			}

			cos_param.queue = queue[i];
			queue_created++;
		}

		cos[i] = odp_cls_cos_create(NULL, &cos_param);

		if (cos[i] == ODP_COS_INVALID) {
			ODPH_ERR("odp_cls_cos_create() failed %u / %u\n", i + 1, num_cos);
			break;
		}

		cos_created++;
	}

	if (!drop)
		CU_ASSERT(queue_created == num_cos);

	CU_ASSERT(cos_created == num_cos);

	if (cos_created != num_cos)
		goto destroy_cos;

	default_cos = cos[0];

	ret = odp_pktio_default_cos_set(pktio, default_cos);
	CU_ASSERT_FATAL(ret == 0);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = find_first_supported_l3_pmr();
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	for (i = 0; i < num_pmr; i++) {
		pmr[i] = odp_cls_pmr_create(&pmr_param, 1, default_cos, cos[i + 1]);

		if (pmr[i] == ODP_PMR_INVALID)
			break;

		val++;
		pmr_created++;
	}

	printf("\n    Number of CoS created: %u\n    Number of PMR created: %u\n", cos_created,
	       pmr_created);

	for (i = 0; i < pmr_created; i++)
		CU_ASSERT(odp_cls_pmr_destroy(pmr[i]) == 0);

	ret = odp_pktio_default_cos_set(pktio, ODP_COS_INVALID);
	CU_ASSERT_FATAL(ret == 0);

destroy_cos:
	for (i = 0; i < cos_created; i++)
		CU_ASSERT(odp_cos_destroy(cos[i]) == 0);

	for (i = 0; i < queue_created; i++)
		CU_ASSERT(odp_queue_destroy(queue[i]) == 0);

	CU_ASSERT(odp_pktio_close(pktio) == 0);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void cls_max_pmr_from_default_drop(void)
{
	cls_max_pmr_from_default_action(1);
}

static void cls_max_pmr_from_default_enqueue(void)
{
	cls_max_pmr_from_default_action(0);
}

static void cls_create_pmr_multi(void)
{
	odp_cls_cos_param_t cos_param;
	odp_cls_capability_t capa;
	odp_pool_t pool;
	odp_pktio_t pktio;
	uint32_t i, num_cos, num_pmr, num_left;
	int ret;
	const uint32_t max_retries = 100;
	uint32_t num_retries = 0;
	uint32_t num_freed = 0;
	uint32_t cos_created = 0;
	uint32_t pmr_created = 0;
	uint16_t mask = 0xffff;

	CU_ASSERT_FATAL(odp_cls_capability(&capa) == 0);

	pool = pool_create("pkt_pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	pktio = create_pktio(ODP_QUEUE_TYPE_SCHED, pool, true);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	num_cos = capa.max_cos;
	if (num_cos > MAX_HANDLES)
		num_cos = MAX_HANDLES;

	CU_ASSERT_FATAL(num_cos > 1);

	num_pmr = num_cos - 1;

	odp_cos_t src_cos[num_cos];
	odp_cos_t cos[num_cos];
	odp_pmr_t pmr[num_pmr];
	odp_pmr_create_opt_t pmr_opt[num_pmr];
	odp_pmr_param_t pmr_param[num_pmr];
	uint16_t val[num_pmr];

	odp_cls_cos_param_init(&cos_param);
	cos_param.action = ODP_COS_ACTION_DROP;

	for (i = 0; i < num_cos; i++) {
		cos[i] = odp_cls_cos_create(NULL, &cos_param);

		if (cos[i] == ODP_COS_INVALID) {
			ODPH_ERR("odp_cls_cos_create() failed %u / %u\n", i + 1, num_cos);
			break;
		}
		/* Same source CoS used for all PMRs */
		src_cos[i] = cos[0];

		cos_created++;
	}

	CU_ASSERT(cos_created == num_cos);

	if (cos_created != num_cos)
		goto destroy_cos;

	ret = odp_pktio_default_cos_set(pktio, cos[0]);
	CU_ASSERT_FATAL(ret == 0);

	for (i = 0; i < num_pmr; i++) {
		val[i] = 1024 + i;

		odp_cls_pmr_param_init(&pmr_param[i]);
		pmr_param[i].term = find_first_supported_l3_pmr();
		pmr_param[i].match.value = &val[i];
		pmr_param[i].match.mask = &mask;
		pmr_param[i].val_sz = sizeof(val[i]);

		odp_cls_pmr_create_opt_init(&pmr_opt[i]);
		pmr_opt[i].terms = &pmr_param[i];
		pmr_opt[i].num_terms = 1;
	}

	do {
		ret = odp_cls_pmr_create_multi(&pmr_opt[pmr_created],
					       &src_cos[pmr_created],
					       &cos[pmr_created + 1],
					       &pmr[pmr_created],
					       num_pmr - pmr_created);
		CU_ASSERT_FATAL(ret <= (int)(num_pmr - pmr_created));

		if (ret < 0)
			break;

		num_retries = (ret == 0) ? num_retries + 1 : 0;
		pmr_created += ret;
	} while (pmr_created < num_pmr && num_retries < max_retries);

	CU_ASSERT(pmr_created > 0);

	num_left = pmr_created;
	while (num_left) {
		ret = odp_cls_pmr_destroy_multi(&pmr[num_freed], num_left);

		CU_ASSERT_FATAL(ret > 0 && (uint32_t)ret <= num_left);

		num_left -= ret;
		num_freed += ret;
	}

	ret = odp_pktio_default_cos_set(pktio, ODP_COS_INVALID);
	CU_ASSERT_FATAL(ret == 0);

destroy_cos:
	for (i = 0; i < cos_created; i++)
		CU_ASSERT(odp_cos_destroy(cos[i]) == 0);

	CU_ASSERT(odp_pktio_close(pktio) == 0);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

static void cls_cos_set_queue(void)
{
	int retval;
	char cosname[ODP_COS_NAME_LEN];
	odp_cls_cos_param_t cls_param;
	odp_pool_t pool;
	odp_queue_t queue;
	odp_queue_t queue_cos;
	odp_cos_t cos_queue;
	odp_queue_t recvqueue;
	odp_queue_t queue_out = ODP_QUEUE_INVALID;

	pool = pool_create("cls_basic_pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	queue = queue_create("cls_basic_queue", true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	sprintf(cosname, "CoSQueue");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos_queue = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_queue != ODP_COS_INVALID);

	queue_cos = queue_create("QueueCoS", true);
	CU_ASSERT_FATAL(queue_cos != ODP_QUEUE_INVALID);

	retval = odp_cos_queue_set(cos_queue, queue_cos);
	CU_ASSERT(retval == 0);
	recvqueue = odp_cos_queue(cos_queue);
	CU_ASSERT(recvqueue == queue_cos);
	CU_ASSERT(odp_cls_cos_num_queue(cos_queue) == 1);
	CU_ASSERT(odp_cls_cos_queues(cos_queue, &queue_out, 1) == 1);
	CU_ASSERT(queue_out == queue_cos);

	odp_cos_destroy(cos_queue);
	odp_queue_destroy(queue_cos);
	odp_queue_destroy(queue);
	odp_pool_destroy(pool);
}

static void cls_cos_set_pool(void)
{
	int retval;
	char cosname[ODP_COS_NAME_LEN];
	odp_cls_cos_param_t cls_param;
	odp_pool_t pool;
	odp_queue_t queue;
	odp_pool_t cos_pool;
	odp_cos_t cos;
	odp_pool_t recvpool;

	pool = pool_create("cls_basic_pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	queue = queue_create("cls_basic_queue", true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	sprintf(cosname, "CoSQueue");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	cos_pool = pool_create("PoolCoS");
	CU_ASSERT_FATAL(cos_pool != ODP_POOL_INVALID);

	retval = odp_cls_cos_pool_set(cos, cos_pool);
	CU_ASSERT(retval == 0);
	recvpool = odp_cls_cos_pool(cos);
	CU_ASSERT(recvpool == cos_pool);

	odp_cos_destroy(cos);
	odp_queue_destroy(queue);
	odp_pool_destroy(pool);
	odp_pool_destroy(cos_pool);
}

static void cls_pmr_composite_create(void)
{
	odp_pmr_t pmr_composite;
	int retval;
	odp_pmr_param_t pmr_terms[PMR_SET_NUM];
	odp_cos_t default_cos;
	odp_cos_t cos;
	odp_queue_t default_queue;
	odp_queue_t queue;
	odp_pool_t default_pool;
	odp_pool_t pool;
	odp_pool_t pkt_pool;
	odp_cls_cos_param_t cls_param;
	odp_pktio_t pktio;
	uint16_t val = 1024;
	uint16_t mask = 0xffff;
	int i;

	pkt_pool = pool_create("pkt_pool");
	CU_ASSERT_FATAL(pkt_pool != ODP_POOL_INVALID);

	pktio = create_pktio(ODP_QUEUE_TYPE_SCHED, pkt_pool, true);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	configure_default_cos(pktio, &default_cos,
			      &default_queue, &default_pool);

	queue = queue_create("pmr_match", true);
	CU_ASSERT(queue != ODP_QUEUE_INVALID);

	pool = pool_create("pmr_match");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create("pmr_match", &cls_param);
	CU_ASSERT(cos != ODP_COS_INVALID);

	for (i = 0; i < PMR_SET_NUM; i++) {
		odp_cls_pmr_param_init(&pmr_terms[i]);
		pmr_terms[i].term = ODP_PMR_TCP_DPORT;
		pmr_terms[i].match.value = &val;
		pmr_terms[i].range_term = false;
		pmr_terms[i].match.mask = &mask;
		pmr_terms[i].val_sz = sizeof(val);
	}

	pmr_composite = odp_cls_pmr_create(pmr_terms, PMR_SET_NUM,
					   default_cos, cos);
	CU_ASSERT(odp_pmr_to_u64(pmr_composite) !=
		  odp_pmr_to_u64(ODP_PMR_INVALID));

	printf("\n");
	odp_cls_print_all();

	retval = odp_cls_pmr_destroy(pmr_composite);
	CU_ASSERT(retval == 0);

	odp_cos_destroy(cos);
	odp_queue_destroy(queue);
	odp_pool_destroy(pool);
	odp_pool_destroy(pkt_pool);
	odp_pktio_default_cos_set(pktio, ODP_COS_INVALID);
	odp_cos_destroy(default_cos);
	odp_queue_destroy(default_queue);
	odp_pool_destroy(default_pool);
	odp_pktio_close(pktio);
}

static void cls_create_cos_with_hash_queues(void)
{
	odp_pool_t pool;
	odp_cls_capability_t capa;
	int ret;
	odp_queue_param_t q_param;
	odp_cls_cos_param_t cls_param;
	odp_cos_t cos;

	pool = pool_create("cls_basic_pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	ret = odp_cls_capability(&capa);
	CU_ASSERT_FATAL(ret == 0);
	CU_ASSERT_FATAL(capa.hash_protocols.all_bits != 0);

	odp_queue_param_init(&q_param);
	q_param.type = ODP_QUEUE_TYPE_SCHED;
	odp_cls_cos_param_init(&cls_param);
	cls_param.num_queue = capa.max_hash_queues;
	cls_param.queue_param = q_param;
	cls_param.hash_proto.all_bits = capa.hash_protocols.all_bits;
	cls_param.pool = pool;

	cos = odp_cls_cos_create(NULL, &cls_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	ret = odp_cos_destroy(cos);
	CU_ASSERT(ret == 0);

	odp_pool_destroy(pool);
}

static int check_capa_cos_hashing(void)
{
	odp_cls_capability_t capa;

	if (odp_cls_capability(&capa) < 0)
		return ODP_TEST_INACTIVE;

	return capa.max_hash_queues > 1 ? ODP_TEST_ACTIVE : ODP_TEST_INACTIVE;
}

odp_testinfo_t classification_suite_basic[] = {
	ODP_TEST_INFO(cls_default_values),
	ODP_TEST_INFO(cls_create_cos),
	ODP_TEST_INFO(cls_create_cos_multi),
	ODP_TEST_INFO(cls_create_cos_max),
	ODP_TEST_INFO(cls_create_cos_max_stats),
	ODP_TEST_INFO(cls_destroy_cos),
	ODP_TEST_INFO(cls_create_pmr_match),
	ODP_TEST_INFO(cls_create_pmr_multi),
	ODP_TEST_INFO(cls_max_pmr_from_default_drop),
	ODP_TEST_INFO(cls_max_pmr_from_default_enqueue),
	ODP_TEST_INFO(cls_cos_set_queue),
	ODP_TEST_INFO(cls_cos_set_pool),
	ODP_TEST_INFO(cls_pmr_composite_create),
	ODP_TEST_INFO_CONDITIONAL(cls_create_cos_with_hash_queues, check_capa_cos_hashing),
	ODP_TEST_INFO_NULL,
};

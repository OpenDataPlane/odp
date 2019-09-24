/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp_cunit_common.h>
#include "odp_classification_testsuites.h"
#include "classification.h"

#define PMR_SET_NUM	5

static void classification_test_create_cos(void)
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
	cls_param.drop_policy = ODP_COS_DROP_POOL;

	cos = odp_cls_cos_create(NULL, &cls_param);
	CU_ASSERT(odp_cos_to_u64(cos) != odp_cos_to_u64(ODP_COS_INVALID));
	odp_cos_destroy(cos);
	odp_pool_destroy(pool);
	odp_queue_destroy(queue);
}

static void classification_test_destroy_cos(void)
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
	cls_param.drop_policy = ODP_COS_DROP_POOL;

	cos = odp_cls_cos_create(name, &cls_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);
	retval = odp_cos_destroy(cos);
	CU_ASSERT(retval == 0);
	retval = odp_cos_destroy(ODP_COS_INVALID);
	CU_ASSERT(retval < 0);

	odp_pool_destroy(pool);
	odp_queue_destroy(queue);
}

static void classification_test_create_pmr_match(void)
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
	cls_param.drop_policy = ODP_COS_DROP_POOL;

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

	odp_queue_destroy(queue);
	odp_pool_destroy(pool);
	odp_pool_destroy(pkt_pool);
	odp_cos_destroy(cos);
	odp_queue_destroy(default_queue);
	odp_pool_destroy(default_pool);
	odp_cos_destroy(default_cos);
	odp_pktio_close(pktio);
}

static void classification_test_cos_set_queue(void)
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
	cls_param.drop_policy = ODP_COS_DROP_POOL;
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

static void classification_test_cos_set_pool(void)
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
	cls_param.drop_policy = ODP_COS_DROP_POOL;
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

static void classification_test_cos_set_drop(void)
{
	int retval;
	char cosname[ODP_COS_NAME_LEN];
	odp_cos_t cos_drop;
	odp_queue_t queue;
	odp_pool_t pool;
	odp_cls_cos_param_t cls_param;

	pool = pool_create("cls_basic_pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	queue = queue_create("cls_basic_queue", true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	sprintf(cosname, "CoSDrop");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;
	cls_param.drop_policy = ODP_COS_DROP_POOL;
	cos_drop = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_drop != ODP_COS_INVALID);

	retval = odp_cos_drop_set(cos_drop, ODP_COS_DROP_POOL);
	CU_ASSERT(retval == 0);
	CU_ASSERT(ODP_COS_DROP_POOL == odp_cos_drop(cos_drop));

	retval = odp_cos_drop_set(cos_drop, ODP_COS_DROP_NEVER);
	CU_ASSERT(retval == 0);
	CU_ASSERT(ODP_COS_DROP_NEVER == odp_cos_drop(cos_drop));
	odp_cos_destroy(cos_drop);
	odp_pool_destroy(pool);
	odp_queue_destroy(queue);
}

static void classification_test_pmr_composite_create(void)
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
	cls_param.drop_policy = ODP_COS_DROP_POOL;

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

	retval = odp_cls_pmr_destroy(pmr_composite);
	CU_ASSERT(retval == 0);

	odp_queue_destroy(queue);
	odp_pool_destroy(pool);
	odp_pool_destroy(pkt_pool);
	odp_cos_destroy(cos);
	odp_queue_destroy(default_queue);
	odp_pool_destroy(default_pool);
	odp_cos_destroy(default_cos);
	odp_pktio_close(pktio);
}

odp_testinfo_t classification_suite_basic[] = {
	ODP_TEST_INFO(classification_test_create_cos),
	ODP_TEST_INFO(classification_test_destroy_cos),
	ODP_TEST_INFO(classification_test_create_pmr_match),
	ODP_TEST_INFO(classification_test_cos_set_queue),
	ODP_TEST_INFO(classification_test_cos_set_drop),
	ODP_TEST_INFO(classification_test_cos_set_pool),
	ODP_TEST_INFO(classification_test_pmr_composite_create),
	ODP_TEST_INFO_NULL,
};

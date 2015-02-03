/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp_classification_testsuites.h"

#define PMR_SET_NUM	5

static void classification_create_cos(void)
{
	odp_cos_t cos;
	char name[ODP_COS_NAME_LEN];
	sprintf(name, "ClassOfService");
	cos = odp_cos_create(name);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);
	odp_cos_destroy(cos);
}

static void classification_destroy_cos(void)
{
	odp_cos_t cos;
	char name[ODP_COS_NAME_LEN];
	int retval;
	sprintf(name, "ClassOfService");
	cos = odp_cos_create(name);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);
	retval = odp_cos_destroy(cos);
	CU_ASSERT(retval == 0);
	retval = odp_cos_destroy(ODP_COS_INVALID);
	CU_ASSERT(retval < 0);
}

static void classification_create_pmr_match(void)
{
	odp_pmr_t pmr;
	uint16_t val;
	uint16_t mask;
	val = 1024;
	mask = 0xffff;
	pmr = odp_pmr_create_match(ODP_PMR_TCP_SPORT, &val, &mask, sizeof(val));
	CU_ASSERT(pmr != ODP_PMR_INVAL);
	odp_pmr_destroy(pmr);
}

static void classification_create_pmr_range(void)
{
	odp_pmr_t pmr;
	uint16_t val1;
	uint16_t val2;
	val1 = 1024;
	val2 = 2048;
	pmr = odp_pmr_create_range(ODP_PMR_TCP_SPORT, &val1,
				   &val2, sizeof(val1));
	CU_ASSERT(pmr != ODP_PMR_INVAL);
	odp_pmr_destroy(pmr);
}

static void classification_destroy_pmr(void)
{
	odp_pmr_t pmr;
	uint16_t val;
	uint16_t mask;
	int retval;
	val = 1024;
	mask = 0xffff;
	pmr = odp_pmr_create_match(ODP_PMR_TCP_SPORT, &val, &mask, sizeof(val));
	retval = odp_pmr_destroy(pmr);
	CU_ASSERT(retval == 0);
	retval = odp_pmr_destroy(ODP_PMR_INVAL);
	retval = odp_pmr_destroy(ODP_PMR_INVAL);
	CU_ASSERT(retval < 0);
}

static void classification_cos_set_queue(void)
{
	int retval;
	char cosname[ODP_COS_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	odp_queue_t queue_cos;
	odp_cos_t cos_queue;
	sprintf(cosname, "CoSQueue");
	cos_queue = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos_queue != ODP_COS_INVALID);

	qparam.sched.prio = ODP_SCHED_PRIO_HIGHEST;
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "QueueCoS");

	queue_cos = odp_queue_create(queuename,
				     ODP_QUEUE_TYPE_SCHED, &qparam);
	retval = odp_cos_set_queue(cos_queue, queue_cos);
	CU_ASSERT(retval == 0);
	odp_cos_destroy(cos_queue);
	odp_queue_destroy(queue_cos);
}

static void classification_cos_set_drop(void)
{
	int retval;
	char cosname[ODP_COS_NAME_LEN];
	sprintf(cosname, "CoSDrop");
	odp_cos_t cos_drop;
	cos_drop = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos_drop != ODP_COS_INVALID);

	retval = odp_cos_set_drop(cos_drop, ODP_COS_DROP_POOL);
	CU_ASSERT(retval == 0);
	retval = odp_cos_set_drop(cos_drop, ODP_COS_DROP_NEVER);
	CU_ASSERT(retval == 0);
	odp_cos_destroy(cos_drop);
}

static void classification_pmr_match_set_create(void)
{
	odp_pmr_set_t pmr_set;
	int retval;
	odp_pmr_match_t pmr_terms[PMR_SET_NUM];
	uint16_t val = 1024;
	uint16_t mask = 0xffff;
	int i;
	for (i = 0; i < PMR_SET_NUM; i++) {
		pmr_terms[i].match_type = ODP_PMR_MASK;
		pmr_terms[i].mask.term = ODP_PMR_TCP_DPORT;
		pmr_terms[i].mask.val = &val;
		pmr_terms[i].mask.mask = &mask;
		pmr_terms[i].mask.val_sz = sizeof(val);
	}

	retval = odp_pmr_match_set_create(PMR_SET_NUM, pmr_terms, &pmr_set);
	CU_ASSERT(retval > 0);

	retval = odp_pmr_match_set_destroy(pmr_set);
	CU_ASSERT(retval == 0);
}

static void classification_pmr_match_set_destroy(void)
{
	odp_pmr_set_t pmr_set;
	int retval;
	odp_pmr_match_t pmr_terms[PMR_SET_NUM];
	uint16_t val = 1024;
	uint16_t mask = 0xffff;
	int i;

	retval = odp_pmr_match_set_destroy(ODP_PMR_SET_INVAL);
	CU_ASSERT(retval < 0);

	for (i = 0; i < PMR_SET_NUM; i++) {
		pmr_terms[i].match_type = ODP_PMR_MASK;
		pmr_terms[i].mask.term = ODP_PMR_TCP_DPORT;
		pmr_terms[i].mask.val = &val;
		pmr_terms[i].mask.mask = &mask;
		pmr_terms[i].mask.val_sz = sizeof(val);
	}

	retval = odp_pmr_match_set_create(PMR_SET_NUM, pmr_terms, &pmr_set);
	CU_ASSERT(retval > 0);

	retval = odp_pmr_match_set_destroy(pmr_set);
	CU_ASSERT(retval == 0);
}

CU_TestInfo classification_basic[] = {
	_CU_TEST_INFO(classification_create_cos),
	_CU_TEST_INFO(classification_destroy_cos),
	_CU_TEST_INFO(classification_create_pmr_match),
	_CU_TEST_INFO(classification_create_pmr_range),
	_CU_TEST_INFO(classification_destroy_pmr),
	_CU_TEST_INFO(classification_cos_set_queue),
	_CU_TEST_INFO(classification_cos_set_drop),
	_CU_TEST_INFO(classification_pmr_match_set_create),
	_CU_TEST_INFO(classification_pmr_match_set_destroy),
	CU_TEST_INFO_NULL,
};

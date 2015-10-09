/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp_cunit_common.h>
#include "odp_classification_testsuites.h"
#include "classification.h"

#define PMR_SET_NUM	5

void classification_test_create_cos(void)
{
	odp_cos_t cos;
	char name[ODP_COS_NAME_LEN];
	sprintf(name, "ClassOfService");
	cos = odp_cos_create(name);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);
	CU_ASSERT(odp_cos_to_u64(cos) != odp_cos_to_u64(ODP_COS_INVALID));
	odp_cos_destroy(cos);
}

void classification_test_destroy_cos(void)
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

void classification_test_create_pmr_match(void)
{
	odp_pmr_t pmr;
	uint16_t val;
	uint16_t mask;
	odp_pmr_match_t match;

	val = 1024;
	mask = 0xffff;
	match.term = ODP_PMR_TCP_SPORT;
	match.val = &val;
	match.mask = &mask;
	match.val_sz = sizeof(val);

	pmr = odp_pmr_create(&match);
	CU_ASSERT(pmr != ODP_PMR_INVAL);
	CU_ASSERT(odp_pmr_to_u64(pmr) != odp_pmr_to_u64(ODP_PMR_INVAL));
	odp_pmr_destroy(pmr);
}

void classification_test_destroy_pmr(void)
{
	odp_pmr_t pmr;
	uint16_t val;
	uint16_t mask;
	int retval;
	odp_pmr_match_t match;

	val = 1024;
	mask = 0xffff;
	match.term = ODP_PMR_TCP_SPORT;
	match.val = &val;
	match.mask = &mask;
	match.val_sz = sizeof(val);

	pmr = odp_pmr_create(&match);
	retval = odp_pmr_destroy(pmr);
	CU_ASSERT(retval == 0);
	retval = odp_pmr_destroy(ODP_PMR_INVAL);
	retval = odp_pmr_destroy(ODP_PMR_INVAL);
	CU_ASSERT(retval < 0);
}

void classification_test_cos_set_queue(void)
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

	odp_queue_param_init(&qparam);
	qparam.sched.prio = ODP_SCHED_PRIO_HIGHEST;
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "QueueCoS");

	queue_cos = odp_queue_create(queuename,
				     ODP_QUEUE_TYPE_SCHED, &qparam);
	retval = odp_cos_queue_set(cos_queue, queue_cos);
	CU_ASSERT(retval == 0);
	odp_cos_destroy(cos_queue);
	odp_queue_destroy(queue_cos);
}

void classification_test_cos_set_drop(void)
{
	int retval;
	char cosname[ODP_COS_NAME_LEN];
	sprintf(cosname, "CoSDrop");
	odp_cos_t cos_drop;
	cos_drop = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos_drop != ODP_COS_INVALID);

	retval = odp_cos_drop_set(cos_drop, ODP_COS_DROP_POOL);
	CU_ASSERT(retval == 0);
	retval = odp_cos_drop_set(cos_drop, ODP_COS_DROP_NEVER);
	CU_ASSERT(retval == 0);
	odp_cos_destroy(cos_drop);
}

void classification_test_pmr_match_set_create(void)
{
	odp_pmr_set_t pmr_set;
	int retval;
	odp_pmr_match_t pmr_terms[PMR_SET_NUM];
	uint16_t val = 1024;
	uint16_t mask = 0xffff;
	int i;
	for (i = 0; i < PMR_SET_NUM; i++) {
		pmr_terms[i].term = ODP_PMR_TCP_DPORT;
		pmr_terms[i].val = &val;
		pmr_terms[i].mask = &mask;
		pmr_terms[i].val_sz = sizeof(val);
	}

	retval = odp_pmr_match_set_create(PMR_SET_NUM, pmr_terms, &pmr_set);
	CU_ASSERT(retval > 0);
	CU_ASSERT(odp_pmr_set_to_u64(pmr_set) !=
		  odp_pmr_set_to_u64(ODP_PMR_SET_INVAL));

	retval = odp_pmr_match_set_destroy(pmr_set);
	CU_ASSERT(retval == 0);
}

void classification_test_pmr_match_set_destroy(void)
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
		pmr_terms[i].term = ODP_PMR_TCP_DPORT;
		pmr_terms[i].val = &val;
		pmr_terms[i].mask = &mask;
		pmr_terms[i].val_sz = sizeof(val);
	}

	retval = odp_pmr_match_set_create(PMR_SET_NUM, pmr_terms, &pmr_set);
	CU_ASSERT(retval > 0);

	retval = odp_pmr_match_set_destroy(pmr_set);
	CU_ASSERT(retval == 0);
}

CU_TestInfo classification_suite_basic[] = {
	_CU_TEST_INFO(classification_test_create_cos),
	_CU_TEST_INFO(classification_test_destroy_cos),
	_CU_TEST_INFO(classification_test_create_pmr_match),
	_CU_TEST_INFO(classification_test_destroy_pmr),
	_CU_TEST_INFO(classification_test_cos_set_queue),
	_CU_TEST_INFO(classification_test_cos_set_drop),
	_CU_TEST_INFO(classification_test_pmr_match_set_create),
	_CU_TEST_INFO(classification_test_pmr_match_set_destroy),
	CU_TEST_INFO_NULL,
};

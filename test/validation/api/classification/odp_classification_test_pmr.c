/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2019-2025 Nokia
 */

#include "odp_classification_testsuites.h"
#include "classification.h"
#include <odp_cunit_common.h>
#include <odp/helper/odph_api.h>

#define MAX_NUM_UDP 4
#define MARK_IP     1
#define MARK_UDP    2
#define TEST_IPV4   false
#define TEST_IPV6   true

static odp_pool_t pkt_pool;
/** sequence number of IP packets */
static odp_atomic_u32_t seq;

static cls_packet_info_t default_pkt_info;
static odp_cls_capability_t cls_capa;
static odp_schedule_capability_t sched_capa;

/* Common things initialized in common_test_init() */
typedef struct test_state_t {
	odp_pktio_t pktio;
	odp_queue_t pktin_queue;
	odp_pool_t  default_pool;
	odp_cos_t   default_cos;
	odp_queue_t default_queue;
} test_state_t;

typedef enum cls_flag_t {
	DISABLE_CLS,
	ENABLE_CLS
} cls_flag_t;

int classification_suite_pmr_init(void)
{
	memset(&cls_capa,   0, sizeof(cls_capa));
	memset(&sched_capa, 0, sizeof(sched_capa));

	if (odp_cls_capability(&cls_capa)) {
		ODPH_ERR("Classifier capability call failed\n");
		return -1;
	}
	if (odp_schedule_capability(&sched_capa)) {
		ODPH_ERR("Scheduler capability call failed\n");
		return -1;
	}

	pkt_pool = pool_create("classification_pmr_pool");
	if (ODP_POOL_INVALID == pkt_pool) {
		ODPH_ERR("Packet pool creation failed\n");
		return -1;
	}

	memset(&default_pkt_info, 0, sizeof(cls_packet_info_t));
	default_pkt_info.pool = pkt_pool;
	default_pkt_info.seq = &seq;

	odp_atomic_init_u32(&seq, 0);

	return 0;
}

static int start_pktio(odp_pktio_t pktio)
{
	if (odp_pktio_start(pktio)) {
		ODPH_ERR("Unable to start loop\n");
		return -1;
	}

	return 0;
}

void configure_default_cos(odp_pktio_t pktio, odp_cos_t *cos,
			   odp_queue_t *queue, odp_pool_t *pool)
{
	odp_cls_cos_param_t cls_param;
	odp_pool_t default_pool;
	odp_cos_t default_cos;
	odp_queue_t default_queue;
	int retval;
	char cosname[ODP_COS_NAME_LEN];

	default_pool  = pool_create("DefaultPool");
	CU_ASSERT(default_pool != ODP_POOL_INVALID);

	default_queue = queue_create("DefaultQueue", true);
	CU_ASSERT(default_queue != ODP_QUEUE_INVALID);

	sprintf(cosname, "DefaultCos");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = default_pool;
	cls_param.queue = default_queue;

	default_cos = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT(default_cos != ODP_COS_INVALID);

	retval = odp_pktio_default_cos_set(pktio, default_cos);
	CU_ASSERT(retval == 0);

	*cos = default_cos;
	*queue = default_queue;
	*pool = default_pool;
}

int classification_suite_pmr_term(void)
{
	int ret = 0;

	if (0 != odp_pool_destroy(pkt_pool)) {
		ODPH_ERR("Packet pool destroy failed\n");
		ret += -1;
	}

	if (odp_cunit_print_inactive())
		ret += -1;

	return ret;
}

/* We do not do this in suite init to make things start fresh in each test */
static test_state_t test_init(cls_flag_t cls)
{
	test_state_t ts;

	ts.pktio = create_pktio(ODP_QUEUE_TYPE_SCHED, pkt_pool, cls == ENABLE_CLS);
	CU_ASSERT_FATAL(ts.pktio != ODP_PKTIO_INVALID);
	CU_ASSERT(odp_pktin_event_queue(ts.pktio, &ts.pktin_queue, 1) == 1);
	CU_ASSERT(start_pktio(ts.pktio) == 0);

	configure_default_cos(ts.pktio, &ts.default_cos, &ts.default_queue, &ts.default_pool);
	return ts;
}

static void test_term(const test_state_t *ts)
{
	CU_ASSERT(odp_pktio_default_cos_set(ts->pktio, ODP_COS_INVALID) == 0);
	CU_ASSERT(odp_cos_destroy(ts->default_cos) == 0);
	CU_ASSERT(stop_pktio(ts->pktio) == 0);
	CU_ASSERT(odp_queue_destroy(ts->default_queue) == 0);
	CU_ASSERT(odp_pool_destroy(ts->default_pool) == 0);
	CU_ASSERT(odp_pktio_close(ts->pktio) == 0);
}

static uint32_t send_packet(odp_packet_t pkt, odp_pktio_t pktio)
{
	uint32_t seqno;
	odph_ethhdr_t *eth;
	uint32_t len;

	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, &len);
	CU_ASSERT_FATAL(len >= sizeof(*eth));
	odp_pktio_mac_addr(pktio, eth->src.addr, ODPH_ETHADDR_LEN);
	odp_pktio_mac_addr(pktio, eth->dst.addr, ODPH_ETHADDR_LEN);

	enqueue_pktio_interface(pkt, pktio);

	return seqno;
}

static void cls_pktin_classifier_flag(void)
{
	const test_state_t ts = test_init(DISABLE_CLS);
	odp_packet_t pkt;
	odph_tcphdr_t *tcp;
	uint32_t seqno;
	uint16_t val;
	uint16_t mask;
	odp_queue_t queue;
	odp_pmr_t pmr;
	odp_cos_t cos;
	char cosname[ODP_COS_NAME_LEN];
	odp_cls_cos_param_t cls_param;
	odp_pool_t pool;
	odp_pmr_param_t pmr_param;

	val  = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);
	mask = odp_cpu_to_be_16(0xffff);
	seqno = 0;

	queue = queue_create("tcp_dport1", true);
	CU_ASSERT(queue != ODP_QUEUE_INVALID);

	pool = pool_create("tcp_dport1");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	sprintf(cosname, "tcp_dport");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT(cos != ODP_COS_INVALID);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_TCP_DPORT;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pmr = odp_cls_pmr_create(&pmr_param, 1, ts.default_cos, cos);
	CU_ASSERT(pmr != ODP_PMR_INVALID);

	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	tcp->dst_port = val;

	seqno = send_packet(pkt, ts.pktio);

	/* since classifier flag is disabled in pktin queue configuration
	packet will not be delivered in classifier queues */
	pkt = receive_and_check(seqno, ts.pktin_queue, pkt_pool, false);
	odp_packet_free(pkt);

	odp_cls_pmr_destroy(pmr);
	odp_cos_destroy(cos);
	odp_queue_destroy(queue);
	odp_pool_destroy(pool);

	test_term(&ts);
}

static void cls_pmr_term_tcp_dport_n(int num_pkt)
{
	const test_state_t ts = test_init(ENABLE_CLS);
	odp_packet_t pkt;
	odph_tcphdr_t *tcp;
	uint32_t seqno[num_pkt];
	uint16_t val;
	uint16_t mask;
	int i, sent_queue, recv_queue, sent_default, recv_default;
	odp_queue_t queue;
	odp_queue_t retqueue;
	odp_pmr_t pmr;
	odp_cos_t cos;
	char cosname[ODP_COS_NAME_LEN];
	odp_cls_cos_param_t cls_param;
	odp_pool_t pool;
	odp_pmr_param_t pmr_param;

	val  = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);
	mask = odp_cpu_to_be_16(0xffff);

	queue = queue_create("tcp_dport1", true);
	CU_ASSERT(queue != ODP_QUEUE_INVALID);

	pool = pool_create("tcp_dport1");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	sprintf(cosname, "tcp_dport");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT(cos != ODP_COS_INVALID);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_TCP_DPORT;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pmr = odp_cls_pmr_create(&pmr_param, 1, ts.default_cos, cos);
	CU_ASSERT(pmr != ODP_PMR_INVALID);

	for (i = 0; i < num_pkt; i++) {
		pkt = create_packet(default_pkt_info);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);
		tcp->dst_port = val;

		seqno[i] = send_packet(pkt, ts.pktio);
	}

	for (i = 0; i < num_pkt; i++) {
		pkt = receive_and_check(seqno[i], queue, pool, false);
		odp_packet_free(pkt);
	}

	/* Other packets are delivered to default queue */
	for (i = 0; i < num_pkt; i++) {
		pkt = create_packet(default_pkt_info);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);
		tcp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT + 1);

		seqno[i] = send_packet(pkt, ts.pktio);
	}

	for (i = 0; i < num_pkt; i++) {
		pkt = receive_and_check(seqno[i], ts.default_queue, ts.default_pool, false);
		odp_packet_free(pkt);
	}

	sent_queue = 0;
	sent_default = 0;

	/* Both queues simultaneously */
	for (i = 0; i < 2 * num_pkt; i++) {
		pkt = create_packet(default_pkt_info);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

		tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);

		if ((i % 5) < 2) {
			sent_queue++;
			tcp->dst_port = val;
		} else {
			sent_default++;
			tcp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT + 1);
		}

		(void)send_packet(pkt, ts.pktio);
	}

	recv_queue = 0;
	recv_default = 0;

	for (i = 0; i < 2 * num_pkt; i++) {
		pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS, false);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		CU_ASSERT(retqueue == queue || retqueue == ts.default_queue);

		tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);

		if (retqueue == queue) {
			recv_queue++;
			CU_ASSERT(tcp->dst_port == val);
		} else if (retqueue == ts.default_queue) {
			recv_default++;
			CU_ASSERT(tcp->dst_port ==
				  odp_cpu_to_be_16(CLS_DEFAULT_DPORT + 1));
		}
		odp_packet_free(pkt);
	}

	CU_ASSERT(sent_queue == recv_queue);
	CU_ASSERT(sent_default == recv_default);

	odp_cls_pmr_destroy(pmr);
	odp_cos_destroy(cos);
	odp_queue_destroy(queue);
	odp_pool_destroy(pool);

	test_term(&ts);
}

static odp_cos_t cos_create(odp_pool_t pool)
{
	odp_queue_t queue;
	odp_cls_cos_param_t cos_param;
	odp_cos_t cos;

	queue = queue_create("CoS queue", true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	odp_cls_cos_param_init(&cos_param);
	cos_param.pool = pool;
	cos_param.queue = queue;
	cos = odp_cls_cos_create("CoS", &cos_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);
	CU_ASSERT(odp_cos_queue(cos) == queue);

	return cos;
}

static void cos_destroy(odp_cos_t cos)
{
	odp_queue_t queue = odp_cos_queue(cos);

	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);
	CU_ASSERT(odp_queue_destroy(queue) == 0);
	CU_ASSERT(odp_cos_destroy(cos) == 0);
}

static odp_packet_t create_udp_packet(uint16_t port)
{
	cls_packet_info_t pkt_info;
	odp_packet_t pkt;
	odph_udphdr_t *udp;
	uint32_t len;

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, &len);
	CU_ASSERT_FATAL(len >= sizeof(*udp));
	udp->dst_port = odp_cpu_to_be_16(port);
	return pkt;
}

static void classify_and_check_result(const test_state_t *ts, odp_queue_t expected_queue)
{
	odp_packet_t pkt;
	uint32_t seqno;

	pkt = create_udp_packet(CLS_DEFAULT_DPORT);
	seqno = send_packet(pkt, ts->pktio);
	pkt = receive_and_check(seqno, expected_queue, ts->default_pool, false);
	odp_packet_free(pkt);
}

#define USE_PMR_CREATE 1  /* Use odp_cls_pmr_create() if possible */

static odp_pmr_t create_pmr_with_prio(uint32_t priority,
				      uint16_t udp_dst_port,
				      odp_cos_t src_cos,
				      odp_cos_t dst_cos,
				      uint32_t flags)
{
	uint16_t val  = odp_cpu_to_be_16(udp_dst_port);
	uint16_t mask = odp_cpu_to_be_16(0xffff);
	odp_pmr_param_t pmr_param;
	odp_pmr_create_opt_t pmr_opt;
	odp_pmr_t pmr;

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_UDP_DPORT;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	if (flags & USE_PMR_CREATE && priority == 0) {
		pmr = odp_cls_pmr_create(&pmr_param, 1, src_cos, dst_cos);
	} else {
		odp_cls_pmr_create_opt_init(&pmr_opt);
		pmr_opt.terms = &pmr_param;
		pmr_opt.num_terms = 1;
		pmr_opt.priority = priority;
		pmr = odp_cls_pmr_create_opt(&pmr_opt, src_cos, dst_cos);
	}
	CU_ASSERT_FATAL(pmr != ODP_PMR_INVALID);

	return pmr;
}

static void test_pmr_priority(const test_state_t *ts,
			      uint32_t prio_1, odp_cos_t cos_1,
			      uint32_t prio_2, odp_cos_t cos_2,
			      uint32_t flags)
{
	odp_pmr_t pmr_1;
	odp_pmr_t pmr_2;
	odp_queue_t expected_queue;

	pmr_1 = create_pmr_with_prio(prio_1, CLS_DEFAULT_DPORT, ts->default_cos, cos_1, flags);
	pmr_2 = create_pmr_with_prio(prio_2, CLS_DEFAULT_DPORT, ts->default_cos, cos_2, flags);

	if (prio_1 > prio_2)
		expected_queue = odp_cos_queue(cos_1);
	else
		expected_queue = odp_cos_queue(cos_2);
	CU_ASSERT(expected_queue != ODP_QUEUE_INVALID);

	classify_and_check_result(ts, expected_queue);

	CU_ASSERT(odp_cls_pmr_destroy(pmr_1) == 0);
	CU_ASSERT(odp_cls_pmr_destroy(pmr_2) == 0);
}

static void cls_pmr_priority(void)
{
	const test_state_t ts = test_init(ENABLE_CLS);
	odp_cos_t cos_1 = cos_create(ts.default_pool);
	odp_cos_t cos_2 = cos_create(ts.default_pool);
	const uint32_t max_exhaustive = 260;
	uint32_t max = cls_capa.max_pmr_priority;

	/* test that odp_cls_pmr_create() creates a PMR with priority 0 */
	test_pmr_priority(&ts,   0, cos_1,   1, cos_2, USE_PMR_CREATE);
	test_pmr_priority(&ts,   1, cos_1,   0, cos_2, USE_PMR_CREATE);
	/* test PMR prioritization between 0 and maximum priority */
	test_pmr_priority(&ts,   0, cos_1, max, cos_2, 0);
	test_pmr_priority(&ts, max, cos_1,   0, cos_2, 0);

	/* test PMR prioritization between several pairs of priority values */
	for (uint64_t prio = 0; prio < max; prio++) {
		test_pmr_priority(&ts, prio,     cos_1, prio + 1, cos_2, 0);
		test_pmr_priority(&ts, prio + 1, cos_1, prio,     cos_2, 0);
		if (prio > max_exhaustive)
			prio += prio / 3;
	}

	cos_destroy(cos_1);
	cos_destroy(cos_2);
	test_term(&ts);
}

/*
 * Test that PMR deletion does not break the priority order of the
 * remaining PMRs. Delete the high priority PMR that was created first.
 */
static void test_pmr_priority_after_pmr_del_1(const test_state_t *ts,
					      odp_cos_t cos_1,
					      odp_cos_t cos_2,
					      odp_cos_t cos_3)
{
	odp_pmr_t pmr_1;
	odp_pmr_t pmr_2;
	odp_pmr_t pmr_3;
	odp_queue_t expected_queue;

	pmr_1 = create_pmr_with_prio(1, CLS_DEFAULT_DPORT, ts->default_cos, cos_1, 0);
	pmr_2 = create_pmr_with_prio(0, CLS_DEFAULT_DPORT, ts->default_cos, cos_2, 0);
	pmr_3 = create_pmr_with_prio(1, CLS_DEFAULT_DPORT, ts->default_cos, cos_3, 0);
	CU_ASSERT(odp_cls_pmr_destroy(pmr_1) == 0);

	expected_queue = odp_cos_queue(cos_3);
	CU_ASSERT(expected_queue != ODP_QUEUE_INVALID);

	classify_and_check_result(ts, expected_queue);

	CU_ASSERT(odp_cls_pmr_destroy(pmr_2) == 0);
	CU_ASSERT(odp_cls_pmr_destroy(pmr_3) == 0);
}

/*
 * Test that PMR deletion does not break the priority order of the
 * remaining PMRs. Delete the high priority PMR that was created last.
 */
static void test_pmr_priority_after_pmr_del_2(const test_state_t *ts,
					      odp_cos_t cos_1,
					      odp_cos_t cos_2,
					      odp_cos_t cos_3)
{
	odp_pmr_t pmr_1;
	odp_pmr_t pmr_2;
	odp_pmr_t pmr_3;
	odp_queue_t expected_queue;

	pmr_1 = create_pmr_with_prio(1, CLS_DEFAULT_DPORT, ts->default_cos, cos_1, 0);
	pmr_2 = create_pmr_with_prio(0, CLS_DEFAULT_DPORT, ts->default_cos, cos_2, 0);
	pmr_3 = create_pmr_with_prio(1, CLS_DEFAULT_DPORT, ts->default_cos, cos_3, 0);
	CU_ASSERT(odp_cls_pmr_destroy(pmr_3) == 0);

	expected_queue = odp_cos_queue(cos_1);
	CU_ASSERT(expected_queue != ODP_QUEUE_INVALID);

	classify_and_check_result(ts, expected_queue);

	CU_ASSERT(odp_cls_pmr_destroy(pmr_1) == 0);
	CU_ASSERT(odp_cls_pmr_destroy(pmr_2) == 0);
}

static void cls_pmr_priority_after_del(void)
{
	const test_state_t ts = test_init(ENABLE_CLS);
	odp_cos_t cos_1 = cos_create(ts.default_pool);
	odp_cos_t cos_2 = cos_create(ts.default_pool);
	odp_cos_t cos_3 = cos_create(ts.default_pool);

	test_pmr_priority_after_pmr_del_1(&ts, cos_1, cos_2, cos_3);
	test_pmr_priority_after_pmr_del_2(&ts, cos_1, cos_2, cos_3);

	cos_destroy(cos_1);
	cos_destroy(cos_2);
	cos_destroy(cos_3);
	test_term(&ts);
}

/* Test that a higher priority rule is ignored if it does not match */
static void cls_pmr_priority_no_match(void)
{
	const test_state_t ts = test_init(ENABLE_CLS);
	odp_cos_t cos_1 = cos_create(ts.default_pool);
	odp_cos_t cos_2 = cos_create(ts.default_pool);
	odp_pmr_t pmr_1;
	odp_pmr_t pmr_2;
	odp_queue_t expected_queue;

	pmr_1 = create_pmr_with_prio(1, CLS_DEFAULT_DPORT + 1, ts.default_cos, cos_1, 0);
	pmr_2 = create_pmr_with_prio(0, CLS_DEFAULT_DPORT,     ts.default_cos, cos_2, 0);

	expected_queue = odp_cos_queue(cos_2);
	CU_ASSERT(expected_queue != ODP_QUEUE_INVALID);

	classify_and_check_result(&ts, expected_queue);

	CU_ASSERT(odp_cls_pmr_destroy(pmr_1) == 0);
	CU_ASSERT(odp_cls_pmr_destroy(pmr_2) == 0);
	cos_destroy(cos_1);
	cos_destroy(cos_2);
	test_term(&ts);
}

/* Test priorities in a CoS hierarchy:
 *
 * [default_cos]---(pri 0)--->[cos_1]---(pri hi)--->[cos_1a]
 *              \--(pri 1)--->[cos_2]---(pri 0)---->[cos_2a]
 *
 * Packets should end up through cos_2 in cos_2a.
 */
static void cls_pmr_priority_in_cos_hierarchy(void)
{
	const test_state_t ts = test_init(ENABLE_CLS);
	odp_cos_t cos_1  = cos_create(ts.default_pool);
	odp_cos_t cos_2  = cos_create(ts.default_pool);
	odp_cos_t cos_1a = cos_create(ts.default_pool);
	odp_cos_t cos_2a = cos_create(ts.default_pool);
	odp_pmr_t pmr_1, pmr_2, pmr_1a, pmr_2a;
	odp_queue_t expected_queue;
	uint32_t hipri = cls_capa.max_pmr_priority;

	pmr_1  = create_pmr_with_prio(0,     CLS_DEFAULT_DPORT, ts.default_cos, cos_1, 0);
	pmr_2  = create_pmr_with_prio(1,     CLS_DEFAULT_DPORT, ts.default_cos, cos_2, 0);
	pmr_1a = create_pmr_with_prio(hipri, CLS_DEFAULT_DPORT, cos_1, cos_1a, 0);
	pmr_2a = create_pmr_with_prio(0,     CLS_DEFAULT_DPORT, cos_2, cos_2a, 0);

	expected_queue = odp_cos_queue(cos_2a);
	CU_ASSERT(expected_queue != ODP_QUEUE_INVALID);

	classify_and_check_result(&ts, expected_queue);

	CU_ASSERT(odp_cls_pmr_destroy(pmr_1) == 0);
	CU_ASSERT(odp_cls_pmr_destroy(pmr_2) == 0);
	CU_ASSERT(odp_cls_pmr_destroy(pmr_1a) == 0);
	CU_ASSERT(odp_cls_pmr_destroy(pmr_2a) == 0);
	cos_destroy(cos_1);
	cos_destroy(cos_2);
	cos_destroy(cos_1a);
	cos_destroy(cos_2a);
	test_term(&ts);
}

static int check_capa_pmr_prio(void)
{
	return (sched_capa.max_queues >= 2 &&
		cls_capa.max_cos >= 2 &&
		cls_capa.max_pmr >= 2 &&
		cls_capa.max_pmr_per_cos >= 2 &&
		cls_capa.max_pmr_priority >= 1 &&
		cls_capa.supported_terms.bit.udp_dport);
}

static int check_capa_pmr_prio_after_del(void)
{
	return (sched_capa.max_queues >= 3 &&
		cls_capa.max_cos >= 3 &&
		cls_capa.max_pmr >= 3 &&
		cls_capa.max_pmr_per_cos >= 3 &&
		cls_capa.max_pmr_priority >= 1 &&
		cls_capa.supported_terms.bit.udp_dport);
}

static int check_capa_pmr_prio_hierarchy(void)
{
	return (sched_capa.max_queues >= 4 &&
		cls_capa.max_cos >= 4 &&
		cls_capa.max_pmr >= 4 &&
		cls_capa.max_pmr_per_cos >= 2 &&
		cls_capa.max_pmr_priority >= 1 &&
		cls_capa.supported_terms.bit.udp_dport);
}

typedef enum match_t {
	MATCH,
	NO_MATCH
} match_t;

/*
 * Test that PMR created using the given parameters matches or does not match
 * given packet. The packet, that gets consumed, must have been created using
 * create_packet() so that it contains the testing sequence number.
 *
 * Ethernet addresses of the packet will be overwritten.
 */
static void test_pmr(const odp_pmr_param_t *pmr_param, odp_packet_t pkt,
		     match_t match)
{
	const test_state_t ts = test_init(ENABLE_CLS);
	uint32_t seqno;
	odp_queue_t queue;
	odp_pool_t pool;
	odp_pmr_t pmr;
	odp_cos_t cos;
	odp_cls_cos_param_t cls_param;

	queue = queue_create("PMR test queue", true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	pool = pool_create("PMR test pool");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create("PMR test cos", &cls_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	pmr = odp_cls_pmr_create(pmr_param, 1, ts.default_cos, cos);
	CU_ASSERT(pmr != ODP_PMR_INVALID);

	seqno = send_packet(pkt, ts.pktio);
	if (match == MATCH)
		pkt = receive_and_check(seqno, queue, pool, false);
	else
		pkt = receive_and_check(seqno, ts.default_queue, ts.default_pool, false);
	odp_packet_free(pkt);

	odp_cls_pmr_destroy(pmr);
	odp_cos_destroy(cos);
	odp_pool_destroy(pool);
	odp_queue_destroy(queue);

	test_term(&ts);
}

static void cls_pmr_term_tcp_sport(void)
{
	odp_packet_t pkt;
	odph_tcphdr_t *tcp;
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;

	val  = odp_cpu_to_be_16(CLS_DEFAULT_SPORT);
	mask = odp_cpu_to_be_16(0xffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_TCP_SPORT;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	tcp->src_port = val;

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	tcp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT + 1);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_udp_dport(void)
{
	odp_packet_t pkt;
	odph_udphdr_t *udp;
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val  = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);
	mask = odp_cpu_to_be_16(0xffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_UDP_DPORT;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->dst_port = val;

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT + 1);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_udp_sport(void)
{
	odp_packet_t pkt;
	odph_udphdr_t *udp;
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val  = odp_cpu_to_be_16(CLS_DEFAULT_SPORT);
	mask = odp_cpu_to_be_16(0xffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_UDP_SPORT;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->src_port = val;

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT + 1);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_proto_ip(odp_bool_t ipv6)
{
	odp_packet_t pkt;
	uint8_t val;
	uint8_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val = ODPH_IPPROTO_UDP;
	mask = 0xff;

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_IPPROTO;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.ipv6 = ipv6;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt_info.l4_type = CLS_PKT_L4_TCP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_ipv4_proto(void)
{
	cls_pmr_term_proto_ip(TEST_IPV4);
}

static void cls_pmr_term_ipv6_proto(void)
{
	cls_pmr_term_proto_ip(TEST_IPV6);
}

static void cls_pmr_term_dscp_ip(odp_bool_t ipv6)
{
	odp_packet_t pkt;
	uint8_t val;
	uint8_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val  = DSCP_CLASS4;
	mask = 0x3f;

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_IP_DSCP;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.ipv6    = ipv6;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt_info.dscp    = DSCP_CLASS4;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt_info.dscp = 0;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_ipv4_dscp(void)
{
	cls_pmr_term_dscp_ip(TEST_IPV4);
}

static void cls_pmr_term_ipv6_dscp(void)
{
	cls_pmr_term_dscp_ip(TEST_IPV6);
}

static void cls_pmr_term_dmac(void)
{
	const test_state_t ts = test_init(ENABLE_CLS);
	odp_packet_t pkt;
	uint32_t seqno;
	odp_queue_t queue;
	odp_pool_t pool;
	odp_pmr_t pmr;
	odp_cos_t cos;
	char cosname[ODP_COS_NAME_LEN];
	odp_cls_cos_param_t cls_param;
	odp_pmr_param_t pmr_param;
	odph_ethhdr_t *eth;
	cls_packet_info_t pkt_info;
	uint8_t val[]  = {0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
	uint8_t mask[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	seqno = 0;

	queue = queue_create("dmac", true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	pool = pool_create("dmac");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	sprintf(cosname, "dmac");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_DMAC;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = ODPH_ETHADDR_LEN;

	pmr = odp_cls_pmr_create(&pmr_param, 1, ts.default_cos, cos);
	CU_ASSERT(pmr != ODP_PMR_INVALID);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	memcpy(eth->dst.addr, val, ODPH_ETHADDR_LEN);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	enqueue_pktio_interface(pkt, ts.pktio);
	pkt = receive_and_check(seqno, queue, pool, false);
	odp_packet_free(pkt);

	/* Other packets delivered to default queue */
	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	enqueue_pktio_interface(pkt, ts.pktio);
	pkt = receive_and_check(seqno, ts.default_queue, ts.default_pool, false);
	odp_packet_free(pkt);

	odp_cls_pmr_destroy(pmr);
	odp_cos_destroy(cos);
	odp_pool_destroy(pool);
	odp_queue_destroy(queue);

	test_term(&ts);
}

static void cls_pmr_term_packet_len(void)
{
	odp_packet_t pkt;
	uint32_t val;
	uint32_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val = 1024;
	/*Mask value will match any packet of length 1000 - 1099*/
	mask = 0xff00;

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_LEN;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	/* create packet of payload length 1024 */
	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt_info.len = 1024;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_vlan_id_0(void)
{
	odp_packet_t pkt;
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;
	odph_ethhdr_t *eth;
	odph_vlanhdr_t *vlan_0;
	cls_packet_info_t pkt_info;

	val  = odp_cpu_to_be_16(0x123);
	mask = odp_cpu_to_be_16(0xfff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_VLAN_ID_0;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.vlan = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	vlan_0 = (odph_vlanhdr_t *)(eth + 1);
	vlan_0->tci = val;

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_vlan_id_x(void)
{
	odp_packet_t pkt;
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;
	odph_ethhdr_t *eth;
	odph_vlanhdr_t *vlan_x;
	cls_packet_info_t pkt_info;

	val  = odp_cpu_to_be_16(0x345);
	mask = odp_cpu_to_be_16(0xfff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_VLAN_ID_X;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	/* Single VLAN */
	pkt_info = default_pkt_info;
	pkt_info.vlan = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	vlan_x = (odph_vlanhdr_t *)(eth + 1);
	vlan_x->tci = val;

	test_pmr(&pmr_param, pkt, MATCH);

	/* Two VLANs */
	pkt_info.vlan_qinq = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	vlan_x = (odph_vlanhdr_t *)(eth + 1);
	vlan_x++;
	vlan_x->tci = val;

	test_pmr(&pmr_param, pkt, MATCH);

	/* No VLAN */
	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_vlan_pcp_0(void)
{
	odp_packet_t pkt;
	uint8_t val;
	uint8_t mask;
	uint16_t tci;
	odp_pmr_param_t pmr_param;
	odph_ethhdr_t *eth;
	odph_vlanhdr_t *vlan_0;
	cls_packet_info_t pkt_info;

	val  = 5;
	mask = 0x7;
	tci  = ((uint16_t)val) << ODPH_VLANHDR_PCP_SHIFT;
	tci |= 0x123;

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_VLAN_PCP_0;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.vlan = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	vlan_0 = (odph_vlanhdr_t *)(eth + 1);
	vlan_0->tci = odp_cpu_to_be_16(tci);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_eth_type_0(void)
{
	odp_packet_t pkt;
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val  = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV6);
	mask = odp_cpu_to_be_16(0xffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_ETHTYPE_0;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.ipv6 = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_eth_type_x(void)
{
	odp_packet_t pkt;
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;
	odph_ethhdr_t *eth;
	odph_vlanhdr_t *vlan_x;
	cls_packet_info_t pkt_info;

	val  = odp_cpu_to_be_16(0x0800);
	mask = odp_cpu_to_be_16(0xffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_ETHTYPE_X;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	/* Single VLAN */
	pkt_info = default_pkt_info;
	pkt_info.vlan = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	vlan_x = (odph_vlanhdr_t *)(eth + 1);
	vlan_x->tci = odp_cpu_to_be_16(0x123);

	test_pmr(&pmr_param, pkt, MATCH);

	/* Two VLANs */
	pkt_info.vlan_qinq = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	vlan_x = (odph_vlanhdr_t *)(eth + 1);
	vlan_x++;
	vlan_x->tci = odp_cpu_to_be_16(0x123);

	test_pmr(&pmr_param, pkt, MATCH);

	/* No VLAN */
	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_pool_set(void)
{
	const test_state_t ts = test_init(ENABLE_CLS);
	odp_packet_t pkt;
	uint32_t seqno;
	uint8_t val;
	uint8_t mask;
	int retval;
	odp_queue_t queue;
	odp_pool_t pool;
	odp_pool_t pool_new;
	odp_pmr_t pmr;
	odp_cos_t cos;
	char cosname[ODP_COS_NAME_LEN];
	odp_cls_cos_param_t cls_param;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val = ODPH_IPPROTO_UDP;
	mask = 0xff;
	seqno = 0;

	queue = queue_create("ipproto1", true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	pool = pool_create("ipproto1");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	sprintf(cosname, "ipproto1");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	pool_new = pool_create("ipproto2");
	CU_ASSERT_FATAL(pool_new != ODP_POOL_INVALID);

	/* new pool is set on CoS */
	retval = odp_cls_cos_pool_set(cos, pool_new);
	CU_ASSERT(retval == 0);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_IPPROTO;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pmr = odp_cls_pmr_create(&pmr_param, 1, ts.default_cos, cos);
	CU_ASSERT(pmr != ODP_PMR_INVALID);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	seqno = send_packet(pkt, ts.pktio);
	pkt = receive_and_check(seqno, queue, pool_new, false);
	odp_packet_free(pkt);

	odp_cls_pmr_destroy(pmr);
	odp_cos_destroy(cos);
	odp_pool_destroy(pool);
	odp_pool_destroy(pool_new);
	odp_queue_destroy(queue);

	test_term(&ts);
}

static void cls_pmr_queue_set(void)
{
	const test_state_t ts = test_init(ENABLE_CLS);
	odp_packet_t pkt;
	uint32_t seqno;
	uint8_t val;
	uint8_t mask;
	int retval;
	odp_queue_t queue;
	odp_pool_t pool;
	odp_queue_t queue_new;
	odp_pmr_t pmr;
	odp_cos_t cos;
	char cosname[ODP_COS_NAME_LEN];
	odp_cls_cos_param_t cls_param;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val = ODPH_IPPROTO_UDP;
	mask = 0xff;
	seqno = 0;

	queue = queue_create("ipproto1", true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	pool = pool_create("ipproto1");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	sprintf(cosname, "ipproto1");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue;

	cos = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	queue_new = queue_create("ipproto2", true);
	CU_ASSERT_FATAL(queue_new != ODP_QUEUE_INVALID);

	/* new queue is set on CoS */
	retval = odp_cos_queue_set(cos, queue_new);
	CU_ASSERT(retval == 0);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_IPPROTO;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pmr = odp_cls_pmr_create(&pmr_param, 1, ts.default_cos, cos);
	CU_ASSERT(pmr != ODP_PMR_INVALID);
	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	seqno = send_packet(pkt, ts.pktio);
	pkt = receive_and_check(seqno, queue_new, pool, false);
	odp_packet_free(pkt);

	odp_cls_pmr_destroy(pmr);
	odp_cos_destroy(cos);
	odp_pool_destroy(pool);
	odp_queue_destroy(queue_new);
	odp_queue_destroy(queue);

	test_term(&ts);
}

static void test_pmr_term_ipv4_addr(int dst)
{
	odp_packet_t pkt;
	uint32_t dst_addr, src_addr;
	uint32_t dst_mask, src_mask;
	odp_pmr_param_t pmr_param;
	odph_ipv4hdr_t *ip;
	const char *src_str = "10.0.0.88/32";
	const char *dst_str = "10.0.0.99/32";

	parse_ipv4_string(src_str, &src_addr, &src_mask);
	parse_ipv4_string(dst_str, &dst_addr, &dst_mask);
	src_addr = odp_cpu_to_be_32(src_addr);
	src_mask = odp_cpu_to_be_32(src_mask);
	dst_addr = odp_cpu_to_be_32(dst_addr);
	dst_mask = odp_cpu_to_be_32(dst_mask);

	odp_cls_pmr_param_init(&pmr_param);

	if (dst) {
		pmr_param.term = ODP_PMR_DIP_ADDR;
		pmr_param.match.value = &dst_addr;
		pmr_param.match.mask = &dst_mask;
		pmr_param.val_sz = sizeof(dst_addr);
	} else {
		pmr_param.term = ODP_PMR_SIP_ADDR;
		pmr_param.match.value = &src_addr;
		pmr_param.match.mask = &src_mask;
		pmr_param.val_sz = sizeof(src_addr);
	}

	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	ip->src_addr = src_addr;
	ip->dst_addr = dst_addr;
	odph_ipv4_csum_update(pkt);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_ipv4_saddr(void)
{
	test_pmr_term_ipv4_addr(0);
}

static void cls_pmr_term_ipv4_daddr(void)
{
	test_pmr_term_ipv4_addr(1);
}

static void cls_pmr_term_ipv6daddr(void)
{
	odp_packet_t pkt;
	odp_pmr_param_t pmr_param;
	odph_ipv6hdr_t *ip;
	cls_packet_info_t pkt_info;

	uint8_t IPV6_DST_ADDR[ODPH_IPV6ADDR_LEN] = {
		/* I.e. ::ffff:10.1.1.100 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 1, 1, 100
	};
	uint8_t ipv6_mask[ODPH_IPV6ADDR_LEN] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_DIP6_ADDR;
	pmr_param.match.value = IPV6_DST_ADDR;
	pmr_param.match.mask = ipv6_mask;
	pmr_param.val_sz = ODPH_IPV6ADDR_LEN;

	pkt_info = default_pkt_info;
	pkt_info.ipv6 = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	ip = (odph_ipv6hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	memcpy(ip->dst_addr, IPV6_DST_ADDR, ODPH_IPV6ADDR_LEN);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_ipv6saddr(void)
{
	odp_packet_t pkt;
	odp_pmr_param_t pmr_param;
	odph_ipv6hdr_t *ip;
	cls_packet_info_t pkt_info;
	uint8_t IPV6_SRC_ADDR[ODPH_IPV6ADDR_LEN] = {
		/* I.e. ::ffff:10.0.0.100 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 1, 1, 1
	};
	uint8_t ipv6_mask[ODPH_IPV6ADDR_LEN] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_SIP6_ADDR;
	pmr_param.match.value = IPV6_SRC_ADDR;
	pmr_param.match.mask = ipv6_mask;
	pmr_param.val_sz = ODPH_IPV6ADDR_LEN;

	pkt_info = default_pkt_info;
	pkt_info.ipv6 = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	ip = (odph_ipv6hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	memcpy(ip->src_addr, IPV6_SRC_ADDR, ODPH_IPV6ADDR_LEN);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_tcp_dport(void)
{
	cls_pmr_term_tcp_dport_n(2);
}

static void cls_pmr_term_tcp_dport_multi(void)
{
	cls_pmr_term_tcp_dport_n(SHM_PKT_NUM_BUFS / 4);
}

static void test_pmr_term_custom(int custom_l3)
{
	odp_packet_t pkt;
	uint32_t dst_addr, src_addr;
	uint32_t addr_be, mask_be;
	uint32_t dst_mask, src_mask;
	odp_pmr_param_t pmr_param;
	odph_ipv4hdr_t *ip;
	const char *pmr_src_str = "10.0.8.0/24";
	const char *pmr_dst_str = "10.0.9.0/24";
	const char *pkt_src_str = "10.0.8.88/32";
	const char *pkt_dst_str = "10.0.9.99/32";

	/* Match values for custom PRM rules are passed in network endian */
	parse_ipv4_string(pmr_src_str, &src_addr, &src_mask);
	parse_ipv4_string(pmr_dst_str, &dst_addr, &dst_mask);

	odp_cls_pmr_param_init(&pmr_param);

	if (custom_l3) {
		addr_be = odp_cpu_to_be_32(dst_addr);
		mask_be = odp_cpu_to_be_32(dst_mask);
		pmr_param.term = ODP_PMR_CUSTOM_L3;
		pmr_param.match.value = &addr_be;
		pmr_param.match.mask = &mask_be;
		pmr_param.val_sz = sizeof(addr_be);
		/* Offset from start of L3 to IPv4 dst address */
		pmr_param.offset = 16;
	} else {
		addr_be = odp_cpu_to_be_32(src_addr);
		mask_be = odp_cpu_to_be_32(src_mask);
		pmr_param.term = ODP_PMR_CUSTOM_FRAME;
		pmr_param.match.value = &addr_be;
		pmr_param.match.mask = &mask_be;
		pmr_param.val_sz = sizeof(addr_be);
		/* Offset from start of ethernet/IPv4 frame to IPv4
		 * src address */
		pmr_param.offset = 26;
	}

	/* IPv4 packet with matching addresses */
	parse_ipv4_string(pkt_src_str, &src_addr, NULL);
	parse_ipv4_string(pkt_dst_str, &dst_addr, NULL);
	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	ip->src_addr = odp_cpu_to_be_32(src_addr);
	ip->dst_addr = odp_cpu_to_be_32(dst_addr);
	odph_ipv4_csum_update(pkt);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

/*
 * Test a series of PMR rules and CoS. When num_udp is 1, test is serial
 * from IP CoS to UDP CoS. When num_udp is larger than 1, a set of parallel
 * UDP CoS are tested.
 *
 *             dst IP        dst UDP[0 ... 3]
 * default_cos   ->   cos_ip        ->        cos_udp[0 ... 3]
 */
static void test_pmr_series(const int num_udp, int marking)
{
	const test_state_t ts = test_init(ENABLE_CLS);
	odp_packet_t pkt;
	uint32_t seqno;
	int i;
	cls_packet_info_t pkt_info;
	odp_pool_t pool;
	odp_pmr_t pmr_ip;
	odp_queue_t queue_ip;
	odp_cos_t cos_ip;
	uint32_t dst_addr;
	uint32_t dst_addr_be, ip_mask_be;
	uint32_t dst_mask;
	odp_pmr_param_t pmr_param;
	odp_cls_cos_param_t cls_param;
	odp_pmr_create_opt_t create_opt;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	odp_cos_t cos_udp[num_udp];
	odp_queue_t queue_udp[num_udp];
	odp_pmr_t pmr_udp[num_udp];
	uint16_t dst_port = 1000;

	pool = pool_create("pmr_series");
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	/* Dest IP address */
	queue_ip = queue_create("queue_ip", true);
	CU_ASSERT_FATAL(queue_ip != ODP_QUEUE_INVALID);

	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool;
	cls_param.queue = queue_ip;

	cos_ip = odp_cls_cos_create("cos_ip", &cls_param);
	CU_ASSERT_FATAL(cos_ip != ODP_COS_INVALID);

	parse_ipv4_string("10.0.9.99/32", &dst_addr, &dst_mask);
	dst_addr_be = odp_cpu_to_be_32(dst_addr);
	ip_mask_be  = odp_cpu_to_be_32(dst_mask);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term        = ODP_PMR_DIP_ADDR;
	pmr_param.match.value = &dst_addr_be;
	pmr_param.match.mask  = &ip_mask_be;
	pmr_param.val_sz      = sizeof(dst_addr_be);
	pmr_param.offset      = 0;

	if (marking) {
		odp_cls_pmr_create_opt_init(&create_opt);
		create_opt.terms     = &pmr_param;
		create_opt.num_terms = 1;
		create_opt.mark      = MARK_IP;

		pmr_ip = odp_cls_pmr_create_opt(&create_opt, ts.default_cos, cos_ip);
	} else {
		pmr_ip = odp_cls_pmr_create(&pmr_param, 1, ts.default_cos, cos_ip);
	}

	CU_ASSERT_FATAL(pmr_ip != ODP_PMR_INVALID);

	/* Dest UDP port */
	for (i = 0; i < num_udp; i++) {
		uint16_t dst_port_be  = odp_cpu_to_be_16(dst_port + i);
		uint16_t port_mask_be = odp_cpu_to_be_16(0xffff);
		char name[] = "udp_0";

		name[4] += i;
		queue_udp[i] = queue_create(name, true);
		CU_ASSERT_FATAL(queue_udp[i] != ODP_QUEUE_INVALID);

		odp_cls_cos_param_init(&cls_param);
		cls_param.pool = pool;
		cls_param.queue = queue_udp[i];

		cos_udp[i] = odp_cls_cos_create(name, &cls_param);
		CU_ASSERT_FATAL(cos_udp[i] != ODP_COS_INVALID);

		odp_cls_pmr_param_init(&pmr_param);
		pmr_param.term        = ODP_PMR_UDP_DPORT;
		pmr_param.match.value = &dst_port_be;
		pmr_param.match.mask  = &port_mask_be;
		pmr_param.val_sz      = 2;
		pmr_param.offset      = 0;

		if (marking) {
			odp_cls_pmr_create_opt_init(&create_opt);
			create_opt.terms     = &pmr_param;
			create_opt.num_terms = 1;
			create_opt.mark      = MARK_UDP + i;

			pmr_udp[i] = odp_cls_pmr_create_opt(&create_opt, cos_ip, cos_udp[i]);
		} else {
			pmr_udp[i] = odp_cls_pmr_create(&pmr_param, 1, cos_ip, cos_udp[i]);
		}

		CU_ASSERT_FATAL(pmr_udp[i] != ODP_PMR_INVALID);
	}

	/* Matching TCP/IP packet */
	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_TCP;

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	ip  = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	ip->dst_addr  = dst_addr_be;
	odph_ipv4_csum_update(pkt);

	seqno = send_packet(pkt, ts.pktio);
	pkt = receive_and_check(seqno, queue_ip, pool, false);

	if (marking) {
		CU_ASSERT(odp_packet_cls_mark(pkt) == MARK_IP);
		CU_ASSERT(odp_packet_reset(pkt, odp_packet_len(pkt)) == 0);
		CU_ASSERT(odp_packet_cls_mark(pkt) == 0);
	} else {
		/* Default is 0 */
		CU_ASSERT(odp_packet_cls_mark(pkt) == 0);
	}

	odp_packet_free(pkt);

	/* Matching UDP/IP packets */
	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_UDP;

	for (i = 0; i < num_udp; i++) {
		pkt = create_packet(pkt_info);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

		ip  = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
		udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);

		ip->dst_addr  = dst_addr_be;
		odph_ipv4_csum_update(pkt);
		udp->dst_port = odp_cpu_to_be_16(dst_port + i);

		seqno = send_packet(pkt, ts.pktio);
		pkt = receive_and_check(seqno, queue_udp[i], pool, false);

		if (marking) {
			CU_ASSERT(odp_packet_cls_mark(pkt) == (uint64_t)(MARK_UDP + i));
		} else {
			/* Default is 0 */
			CU_ASSERT(odp_packet_cls_mark(pkt) == 0);
		}

		odp_packet_free(pkt);
	}

	/* Other packets delivered to default queue */
	pkt = create_packet(default_pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	seqno = send_packet(pkt, ts.pktio);
	pkt = receive_and_check(seqno, ts.default_queue, ts.default_pool, false);
	odp_packet_free(pkt);

	odp_cls_pmr_destroy(pmr_ip);

	for (i = 0; i < num_udp; i++) {
		odp_cls_pmr_destroy(pmr_udp[i]);
		odp_cos_destroy(cos_udp[i]);
	}

	odp_cos_destroy(cos_ip);
	odp_pool_destroy(pool);

	for (i = 0; i < num_udp; i++)
		odp_queue_destroy(queue_udp[i]);

	odp_queue_destroy(queue_ip);

	test_term(&ts);
}

static void cls_pmr_term_sctp_port(bool is_dport)
{
	odp_packet_t pkt;
	odph_sctphdr_t *sctp;
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val  = odp_cpu_to_be_16(CLS_DEFAULT_SPORT);
	if (is_dport)
		val  = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);
	mask = odp_cpu_to_be_16(0xffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_SCTP_SPORT;
	if (is_dport)
		pmr_param.term = ODP_PMR_SCTP_DPORT;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_SCTP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	sctp = (odph_sctphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	if (is_dport)
		sctp->dst_port = val;
	else
		sctp->src_port = val;
	CU_ASSERT(odph_sctp_chksum_set(pkt) == 0);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	sctp = (odph_sctphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	if (is_dport)
		sctp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT + 1);
	else
		sctp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT + 1);
	CU_ASSERT(odph_sctp_chksum_set(pkt) == 0);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_sctp_sport(void)
{
	cls_pmr_term_sctp_port(0);
}

static void cls_pmr_term_sctp_dport(void)
{
	cls_pmr_term_sctp_port(1);
}

static void cls_pmr_term_icmp_type(void)
{
	odp_packet_t pkt;
	odph_icmphdr_t *icmp;
	uint8_t val;
	uint8_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val  = ODPH_ICMP_ECHO;
	mask = 0xff;

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_ICMP_TYPE;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_ICMP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	icmp = (odph_icmphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	icmp->type = val;

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	icmp = (odph_icmphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	icmp->type = ODPH_ICMP_ECHOREPLY;

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_icmp_code(void)
{
	odp_packet_t pkt;
	odph_icmphdr_t *icmp;
	uint8_t val;
	uint8_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val  = 0x1;
	mask = 0xff;

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_ICMP_CODE;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_ICMP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	icmp = (odph_icmphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	icmp->code = 0x1;

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	icmp = (odph_icmphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	icmp->code = 0;

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_icmp_id(void)
{
	odp_packet_t pkt;
	odph_icmphdr_t *icmp;
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val  = odp_cpu_to_be_16(0x1234);
	mask = odp_cpu_to_be_16(0xffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_ICMP_ID;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_ICMP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	icmp = (odph_icmphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	icmp->un.echo.id = odp_cpu_to_be_16(0x1234);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	icmp = (odph_icmphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	icmp->un.echo.id = 0x4567;

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_gtpu_teid(void)
{
	odp_packet_t pkt;
	odph_gtphdr_t *gtpu;
	odph_udphdr_t *udp;
	uint32_t val;
	uint32_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;
	uint8_t *hlen = 0;

	val  = odp_cpu_to_be_32(CLS_MAGIC_VAL);
	mask = odp_cpu_to_be_32(0xffffffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_GTPV1_TEID;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_GTP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, MATCH);

	/* Check packet with wrong UDP port, packets should goto default cos */
	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_GTP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);

	test_pmr(&pmr_param, pkt, NO_MATCH);

	/* Check GTPv2 packets, should goto default cos */
	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_GTP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	hlen = (uint8_t *)odp_packet_l4_ptr(pkt, NULL);
	gtpu = (odph_gtphdr_t *)(hlen + ODPH_UDPHDR_LEN);
	/* Version:2, piggybacking:1, teid:1 */
	gtpu->gtp_hdr_info = 0x58;
	CU_ASSERT(odph_udp_tcp_chksum(pkt, ODPH_CHKSUM_GENERATE, NULL) == 0);

	test_pmr(&pmr_param, pkt, NO_MATCH);

	/* All other packets should goto default cos */
	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_GTP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	hlen = (uint8_t *)odp_packet_l4_ptr(pkt, NULL);
	gtpu = (odph_gtphdr_t *)(hlen + ODPH_UDPHDR_LEN);
	gtpu->teid = odp_cpu_to_be_32(CLS_MAGIC_VAL + 1);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_igmp_grpaddr(void)
{
	odp_packet_t pkt;
	odph_igmphdr_t *igmp;
	uint32_t val;
	uint32_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;

	val  = odp_cpu_to_be_32(CLS_MAGIC_VAL);
	mask = odp_cpu_to_be_32(0xffffffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_IGMP_GRP_ADDR;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_IGMP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	test_pmr(&pmr_param, pkt, MATCH);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_IGMP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	igmp = (odph_igmphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	igmp->group = odp_cpu_to_be_32(CLS_MAGIC_VAL + 1);

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_serial(void)
{
	test_pmr_series(1, 0);
}

static void cls_pmr_parallel(void)
{
	test_pmr_series(MAX_NUM_UDP, 0);
}

static void cls_pmr_marking(void)
{
	test_pmr_series(MAX_NUM_UDP, 1);
}

static void cls_pmr_term_custom_frame(void)
{
	test_pmr_term_custom(0);
}

static void cls_pmr_term_custom_l3(void)
{
	test_pmr_term_custom(1);
}

static void test_pmr_term_ipsec_spi_ah(odp_bool_t is_ipv6)
{
	uint32_t val;
	uint32_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;
	odp_packet_t pkt;
	odph_ahhdr_t *ah;

	val = odp_cpu_to_be_32(0x11223344);
	mask = odp_cpu_to_be_32(0xffffffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_IPSEC_SPI;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_AH;
	pkt_info.ipv6 = is_ipv6;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	ah = (odph_ahhdr_t *)odp_packet_l4_ptr(pkt, NULL);
	ah->spi = val;

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	ah = (odph_ahhdr_t *)odp_packet_l4_ptr(pkt, NULL);
	ah->spi = val + 1;

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_ipsec_spi_ah_ipv4(void)
{
	test_pmr_term_ipsec_spi_ah(TEST_IPV4);
}

static void test_pmr_term_ipsec_spi_esp(odp_bool_t is_ipv6)
{
	uint32_t val;
	uint32_t mask;
	odp_pmr_param_t pmr_param;
	cls_packet_info_t pkt_info;
	odp_packet_t pkt;
	odph_esphdr_t *esp;

	val = odp_cpu_to_be_32(0x11223344);
	mask = odp_cpu_to_be_32(0xffffffff);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_IPSEC_SPI;
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_ESP;
	pkt_info.ipv6 = is_ipv6;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	esp = (odph_esphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	esp->spi = val;

	test_pmr(&pmr_param, pkt, MATCH);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	esp = (odph_esphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	esp->spi = val + 1;

	test_pmr(&pmr_param, pkt, NO_MATCH);
}

static void cls_pmr_term_ipsec_spi_esp_ipv4(void)
{
	test_pmr_term_ipsec_spi_esp(TEST_IPV4);
}

static void cls_pmr_term_ipsec_spi_ah_ipv6(void)
{
	test_pmr_term_ipsec_spi_ah(TEST_IPV6);
}

static void cls_pmr_term_ipsec_spi_esp_ipv6(void)
{
	test_pmr_term_ipsec_spi_esp(TEST_IPV6);
}

static int check_capa_tcp_dport(void)
{
	return cls_capa.supported_terms.bit.tcp_dport;
}

static int check_capa_tcp_sport(void)
{
	return cls_capa.supported_terms.bit.tcp_sport;
}

static int check_capa_udp_dport(void)
{
	return cls_capa.supported_terms.bit.udp_dport;
}

static int check_capa_udp_sport(void)
{
	return cls_capa.supported_terms.bit.udp_sport;
}

static int check_capa_ip_proto(void)
{
	return cls_capa.supported_terms.bit.ip_proto;
}

static int check_capa_ip_dscp(void)
{
	return cls_capa.supported_terms.bit.ip_dscp;
}

static int check_capa_dmac(void)
{
	return cls_capa.supported_terms.bit.dmac;
}

static int check_capa_ipv4_saddr(void)
{
	return cls_capa.supported_terms.bit.sip_addr;
}

static int check_capa_ipv4_daddr(void)
{
	return cls_capa.supported_terms.bit.dip_addr;
}

static int check_capa_ipv6_saddr(void)
{
	return cls_capa.supported_terms.bit.sip6_addr;
}

static int check_capa_ipv6_daddr(void)
{
	return cls_capa.supported_terms.bit.dip6_addr;
}

static int check_capa_packet_len(void)
{
	return cls_capa.supported_terms.bit.len;
}

static int check_capa_vlan_id_0(void)
{
	return cls_capa.supported_terms.bit.vlan_id_0;
}

static int check_capa_vlan_id_x(void)
{
	return cls_capa.supported_terms.bit.vlan_id_x;
}

static int check_capa_vlan_pcp_0(void)
{
	return cls_capa.supported_terms.bit.vlan_pcp_0;
}

static int check_capa_ethtype_0(void)
{
	return cls_capa.supported_terms.bit.ethtype_0;
}

static int check_capa_ethtype_x(void)
{
	return cls_capa.supported_terms.bit.ethtype_x;
}

static int check_capa_custom_frame(void)
{
	return cls_capa.supported_terms.bit.custom_frame;
}

static int check_capa_custom_l3(void)
{
	return cls_capa.supported_terms.bit.custom_l3;
}

static int check_capa_ipsec_spi(void)
{
	return cls_capa.supported_terms.bit.ipsec_spi;
}

static int check_capa_pmr_series(void)
{
	uint64_t support;

	support = cls_capa.supported_terms.bit.dip_addr &&
		  cls_capa.supported_terms.bit.udp_dport;

	return support;
}

static int check_capa_pmr_marking(void)
{
	uint64_t terms;

	terms = cls_capa.supported_terms.bit.dip_addr &&
		cls_capa.supported_terms.bit.udp_dport;

	/* one PMR for IP, MAX_NUM_UDP PMRs for UDP */
	if (terms && cls_capa.max_mark >= (MARK_UDP + MAX_NUM_UDP - 1))
		return 1;

	return 0;
}

static int check_capa_sctp_sport(void)
{
	return cls_capa.supported_terms.bit.sctp_sport;
}

static int check_capa_sctp_dport(void)
{
	return cls_capa.supported_terms.bit.sctp_dport;
}

static int check_capa_icmp_type(void)
{
	return cls_capa.supported_terms.bit.icmp_type;
}

static int check_capa_icmp_code(void)
{
	return cls_capa.supported_terms.bit.icmp_code;
}

static int check_capa_icmp_id(void)
{
	return cls_capa.supported_terms.bit.icmp_id;
}

static int check_capa_gtpu_teid(void)
{
	return cls_capa.supported_terms.bit.gtpv1_teid;
}

static int check_capa_igmp_grpaddr(void)
{
	return cls_capa.supported_terms.bit.igmp_grp_addr;
}

odp_testinfo_t classification_suite_pmr[] = {
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_tcp_dport, check_capa_tcp_dport),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_tcp_sport, check_capa_tcp_sport),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_udp_dport, check_capa_udp_dport),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_udp_sport, check_capa_udp_sport),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_gtpu_teid, check_capa_gtpu_teid),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_igmp_grpaddr, check_capa_igmp_grpaddr),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_sctp_sport, check_capa_sctp_sport),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_sctp_dport, check_capa_sctp_dport),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_icmp_type, check_capa_icmp_type),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_icmp_code, check_capa_icmp_code),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_icmp_id, check_capa_icmp_id),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipv4_proto, check_capa_ip_proto),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipv6_proto, check_capa_ip_proto),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipv4_dscp, check_capa_ip_dscp),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipv6_dscp, check_capa_ip_dscp),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_dmac, check_capa_dmac),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_pool_set, check_capa_ip_proto),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_queue_set, check_capa_ip_proto),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipv4_saddr, check_capa_ipv4_saddr),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipv4_daddr, check_capa_ipv4_daddr),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipv6saddr, check_capa_ipv6_saddr),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipv6daddr, check_capa_ipv6_daddr),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_packet_len, check_capa_packet_len),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_vlan_id_0, check_capa_vlan_id_0),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_vlan_id_x, check_capa_vlan_id_x),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_vlan_pcp_0, check_capa_vlan_pcp_0),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_eth_type_0, check_capa_ethtype_0),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_eth_type_x, check_capa_ethtype_x),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_custom_frame, check_capa_custom_frame),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_custom_l3, check_capa_custom_l3),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipsec_spi_ah_ipv4, check_capa_ipsec_spi),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipsec_spi_esp_ipv4, check_capa_ipsec_spi),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipsec_spi_ah_ipv6, check_capa_ipsec_spi),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_term_ipsec_spi_esp_ipv6, check_capa_ipsec_spi),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_serial, check_capa_pmr_series),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_parallel, check_capa_pmr_series),
	ODP_TEST_INFO(cls_pktin_classifier_flag),
	ODP_TEST_INFO(cls_pmr_term_tcp_dport_multi),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_marking, check_capa_pmr_marking),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_priority, check_capa_pmr_prio),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_priority_after_del, check_capa_pmr_prio_after_del),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_priority_no_match, check_capa_pmr_prio),
	ODP_TEST_INFO_CONDITIONAL(cls_pmr_priority_in_cos_hierarchy,
				  check_capa_pmr_prio_hierarchy),
	ODP_TEST_INFO_NULL,
};

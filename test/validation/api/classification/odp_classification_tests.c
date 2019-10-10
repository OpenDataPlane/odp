/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp_classification_testsuites.h"
#include "classification.h"
#include <odp_cunit_common.h>

static odp_cos_t cos_list[CLS_ENTRIES];
static odp_pmr_t pmr_list[CLS_ENTRIES];
static odp_queue_t queue_list[CLS_ENTRIES];
static odp_pool_t pool_list[CLS_ENTRIES];

static odp_pool_t pool_default;
static odp_pktio_t pktio_loop;
static odp_cls_testcase_u tc;
static int global_num_l2_qos;

#define NUM_COS_PMR_CHAIN	2
#define NUM_COS_DEFAULT	1
#define NUM_COS_ERROR	1
#define NUM_COS_L2_PRIO	CLS_L2_QOS_MAX
#define NUM_COS_PMR	1
#define NUM_COS_COMPOSITE	1
/** sequence number of IP packets */
odp_atomic_u32_t seq;

/* default packet info */
static cls_packet_info_t default_pkt_info;

int classification_suite_init(void)
{
	int i;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	tc.all_bits = 0;

	pool_default = pool_create("classification_pool");
	if (ODP_POOL_INVALID == pool_default) {
		fprintf(stderr, "Packet pool creation failed.\n");
		return -1;
	}

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio_loop = odp_pktio_open("loop", pool_default, &pktio_param);
	if (pktio_loop == ODP_PKTIO_INVALID) {
		ret = odp_pool_destroy(pool_default);
		if (ret)
			fprintf(stderr, "unable to destroy pool.\n");
		return -1;
	}

	memset(&default_pkt_info, 0, sizeof(cls_packet_info_t));
	default_pkt_info.pool = pool_default;
	default_pkt_info.seq = &seq;

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
	pktin_param.classifier_enable = true;
	pktin_param.hash_enable = false;

	if (odp_pktin_queue_config(pktio_loop, &pktin_param)) {
		fprintf(stderr, "pktin queue config failed.\n");
		return -1;
	}

	if (odp_pktout_queue_config(pktio_loop, NULL)) {
		fprintf(stderr, "pktout queue config failed.\n");
		return -1;
	}

	for (i = 0; i < CLS_ENTRIES; i++)
		cos_list[i] = ODP_COS_INVALID;

	for (i = 0; i < CLS_ENTRIES; i++)
		pmr_list[i] = ODP_PMR_INVALID;

	for (i = 0; i < CLS_ENTRIES; i++)
		queue_list[i] = ODP_QUEUE_INVALID;

	for (i = 0; i < CLS_ENTRIES; i++)
		pool_list[i] = ODP_POOL_INVALID;

	odp_atomic_init_u32(&seq, 0);

	ret = odp_pktio_start(pktio_loop);
	if (ret) {
		fprintf(stderr, "unable to start loop\n");
		return -1;
	}

	return 0;
}

int classification_suite_term(void)
{
	int i;
	int retcode = 0;

	if (0 >	stop_pktio(pktio_loop)) {
		fprintf(stderr, "stop pktio failed.\n");
		retcode = -1;
	}

	if (0 > odp_pktio_close(pktio_loop)) {
		fprintf(stderr, "pktio close failed.\n");
		retcode = -1;
	}

	if (0 != odp_pool_destroy(pool_default)) {
		fprintf(stderr, "pool_default destroy failed.\n");
		retcode = -1;
	}

	for (i = 0; i < CLS_ENTRIES; i++) {
		if (cos_list[i] != ODP_COS_INVALID)
			odp_cos_destroy(cos_list[i]);
	}

	for (i = 0; i < CLS_ENTRIES; i++) {
		if (pmr_list[i] != ODP_PMR_INVALID)
			odp_cls_pmr_destroy(pmr_list[i]);
	}

	for (i = 0; i < CLS_ENTRIES; i++) {
		if (queue_list[i] != ODP_QUEUE_INVALID)
			odp_queue_destroy(queue_list[i]);
	}

	for (i = 0; i < CLS_ENTRIES; i++) {
		if (pool_list[i] != ODP_POOL_INVALID)
			odp_pool_destroy(pool_list[i]);
	}

	if (odp_cunit_print_inactive())
		retcode = -1;

	return retcode;
}

void configure_cls_pmr_chain(void)
{
	/* PKTIO --> PMR_SRC(SRC IP ADDR) --> PMR_DST (TCP SPORT) */

	/* Packet matching only the SRC IP ADDR should be delivered
	in queue[CLS_PMR_CHAIN_SRC] and a packet matching both SRC IP ADDR and
	TCP SPORT should be delivered to queue[CLS_PMR_CHAIN_DST] */

	uint16_t val;
	uint16_t maskport;
	char cosname[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	odp_cls_cos_param_t cls_param;
	char queuename[ODP_QUEUE_NAME_LEN];
	char poolname[ODP_POOL_NAME_LEN];
	uint32_t addr;
	uint32_t mask;
	odp_pmr_param_t pmr_param;
	odp_schedule_capability_t schedule_capa;

	CU_ASSERT_FATAL(odp_schedule_capability(&schedule_capa) == 0);

	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio = odp_schedule_default_prio();
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	qparam.sched.lock_count = schedule_capa.max_ordered_locks;
	sprintf(queuename, "%s", "SrcQueue");

	queue_list[CLS_PMR_CHAIN_SRC] = odp_queue_create(queuename, &qparam);

	CU_ASSERT_FATAL(queue_list[CLS_PMR_CHAIN_SRC] != ODP_QUEUE_INVALID);

	sprintf(poolname, "%s", "SrcPool");
	pool_list[CLS_PMR_CHAIN_SRC] = pool_create(poolname);
	CU_ASSERT_FATAL(pool_list[CLS_PMR_CHAIN_SRC] != ODP_POOL_INVALID);

	sprintf(cosname, "SrcCos");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool_list[CLS_PMR_CHAIN_SRC];
	cls_param.queue = queue_list[CLS_PMR_CHAIN_SRC];
	cls_param.drop_policy = ODP_COS_DROP_POOL;

	cos_list[CLS_PMR_CHAIN_SRC] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_PMR_CHAIN_SRC] != ODP_COS_INVALID);

	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio = odp_schedule_default_prio();
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "DstQueue");

	queue_list[CLS_PMR_CHAIN_DST] = odp_queue_create(queuename, &qparam);
	CU_ASSERT_FATAL(queue_list[CLS_PMR_CHAIN_DST] != ODP_QUEUE_INVALID);

	sprintf(poolname, "%s", "DstPool");
	pool_list[CLS_PMR_CHAIN_DST] = pool_create(poolname);
	CU_ASSERT_FATAL(pool_list[CLS_PMR_CHAIN_DST] != ODP_POOL_INVALID);

	sprintf(cosname, "DstCos");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool_list[CLS_PMR_CHAIN_DST];
	cls_param.queue = queue_list[CLS_PMR_CHAIN_DST];
	cls_param.drop_policy = ODP_COS_DROP_POOL;
	cos_list[CLS_PMR_CHAIN_DST] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_PMR_CHAIN_DST] != ODP_COS_INVALID);

	parse_ipv4_string(CLS_PMR_CHAIN_SADDR, &addr, &mask);
	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_SIP_ADDR;
	pmr_param.match.value = &addr;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(addr);
	pmr_list[CLS_PMR_CHAIN_SRC] =
	odp_cls_pmr_create(&pmr_param, 1, cos_list[CLS_DEFAULT],
			   cos_list[CLS_PMR_CHAIN_SRC]);
	CU_ASSERT_FATAL(pmr_list[CLS_PMR_CHAIN_SRC] != ODP_PMR_INVALID);

	val = CLS_PMR_CHAIN_PORT;
	maskport = 0xffff;
	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = find_first_supported_l3_pmr();
	pmr_param.match.value = &val;
	pmr_param.match.mask = &maskport;
	pmr_param.val_sz = sizeof(val);
	pmr_list[CLS_PMR_CHAIN_DST] =
	odp_cls_pmr_create(&pmr_param, 1, cos_list[CLS_PMR_CHAIN_SRC],
			   cos_list[CLS_PMR_CHAIN_DST]);
	CU_ASSERT_FATAL(pmr_list[CLS_PMR_CHAIN_DST] != ODP_PMR_INVALID);
}

void test_cls_pmr_chain(void)
{
	odp_packet_t pkt;
	odph_ipv4hdr_t *ip;
	odp_queue_t queue;
	odp_pool_t pool;
	uint32_t addr = 0;
	uint32_t mask;
	uint32_t seqno = 0;
	cls_packet_info_t pkt_info;

	pkt_info = default_pkt_info;
	pkt_info.udp = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	parse_ipv4_string(CLS_PMR_CHAIN_SADDR, &addr, &mask);
	ip->src_addr = odp_cpu_to_be_32(addr);
	odph_ipv4_csum_update(pkt);

	set_first_supported_pmr_port(pkt, CLS_PMR_CHAIN_PORT);

	enqueue_pktio_interface(pkt, pktio_loop);

	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(queue == queue_list[CLS_PMR_CHAIN_DST]);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[CLS_PMR_CHAIN_DST]);
	odp_packet_free(pkt);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	parse_ipv4_string(CLS_PMR_CHAIN_SADDR, &addr, &mask);
	ip->src_addr = odp_cpu_to_be_32(addr);
	odph_ipv4_csum_update(pkt);

	enqueue_pktio_interface(pkt, pktio_loop);
	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(queue == queue_list[CLS_PMR_CHAIN_SRC]);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[CLS_PMR_CHAIN_SRC]);
	odp_packet_free(pkt);
}

void configure_pktio_default_cos(void)
{
	int retval;
	odp_queue_param_t qparam;
	odp_cls_cos_param_t cls_param;
	char cosname[ODP_COS_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	char poolname[ODP_POOL_NAME_LEN];

	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio = odp_schedule_default_prio();
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "DefaultQueue");
	queue_list[CLS_DEFAULT] = odp_queue_create(queuename, &qparam);
	CU_ASSERT_FATAL(queue_list[CLS_DEFAULT] != ODP_QUEUE_INVALID);

	sprintf(poolname, "DefaultPool");
	pool_list[CLS_DEFAULT] = pool_create(poolname);
	CU_ASSERT_FATAL(pool_list[CLS_DEFAULT] != ODP_POOL_INVALID);

	sprintf(cosname, "DefaultCoS");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool_list[CLS_DEFAULT];
	cls_param.queue = queue_list[CLS_DEFAULT];
	cls_param.drop_policy = ODP_COS_DROP_POOL;
	cos_list[CLS_DEFAULT] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_DEFAULT] != ODP_COS_INVALID);

	retval = odp_pktio_default_cos_set(pktio_loop, cos_list[CLS_DEFAULT]);
	CU_ASSERT(retval == 0);
}

void test_pktio_default_cos(void)
{
	odp_packet_t pkt;
	odp_queue_t queue;
	uint32_t seqno = 0;
	odp_pool_t pool;
	cls_packet_info_t pkt_info;

	/* create a default packet */
	pkt_info = default_pkt_info;
	pkt_info.udp = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	enqueue_pktio_interface(pkt, pktio_loop);

	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	/* Default packet should be received in default queue */
	CU_ASSERT(queue == queue_list[CLS_DEFAULT]);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[CLS_DEFAULT]);

	odp_packet_free(pkt);
}

void configure_pktio_error_cos(void)
{
	int retval;
	odp_queue_param_t qparam;
	odp_cls_cos_param_t cls_param;
	char queuename[ODP_QUEUE_NAME_LEN];
	char cosname[ODP_COS_NAME_LEN];
	char poolname[ODP_POOL_NAME_LEN];

	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio = odp_schedule_min_prio();
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "ErrorCos");

	queue_list[CLS_ERROR] = odp_queue_create(queuename, &qparam);
	CU_ASSERT_FATAL(queue_list[CLS_ERROR] != ODP_QUEUE_INVALID);

	sprintf(poolname, "ErrorPool");
	pool_list[CLS_ERROR] = pool_create(poolname);
	CU_ASSERT_FATAL(pool_list[CLS_ERROR] != ODP_POOL_INVALID);

	sprintf(cosname, "%s", "ErrorCos");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool_list[CLS_ERROR];
	cls_param.queue = queue_list[CLS_ERROR];
	cls_param.drop_policy = ODP_COS_DROP_POOL;
	cos_list[CLS_ERROR] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_ERROR] != ODP_COS_INVALID);

	retval = odp_pktio_error_cos_set(pktio_loop, cos_list[CLS_ERROR]);
	CU_ASSERT(retval == 0);
}

void test_pktio_error_cos(void)
{
	odp_queue_t queue;
	odp_packet_t pkt;
	odp_pool_t pool;
	cls_packet_info_t pkt_info;

	/*Create an error packet */
	pkt_info = default_pkt_info;
	pkt_info.udp = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);

	/* Incorrect IpV4 version */
	ip->ver_ihl = 8 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->chksum = 0;
	enqueue_pktio_interface(pkt, pktio_loop);

	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	/* Error packet should be received in error queue */
	CU_ASSERT(queue == queue_list[CLS_ERROR]);
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[CLS_ERROR]);
	odp_packet_free(pkt);
}

static void classification_test_pktio_set_skip(void)
{
	int retval;
	size_t offset = 5;

	retval = odp_pktio_skip_set(pktio_loop, offset);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_skip_set(ODP_PKTIO_INVALID, offset);
	CU_ASSERT(retval < 0);

	/* reset skip value to zero as validation suite expects
	offset to be zero*/

	retval = odp_pktio_skip_set(pktio_loop, 0);
	CU_ASSERT(retval == 0);
}

static void classification_test_pktio_set_headroom(void)
{
	size_t headroom;
	int retval;

	headroom = 5;
	retval = odp_pktio_headroom_set(pktio_loop, headroom);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_headroom_set(ODP_PKTIO_INVALID, headroom);
	CU_ASSERT(retval < 0);
}

void configure_cos_with_l2_priority(void)
{
	uint8_t num_qos = CLS_L2_QOS_MAX;
	odp_cos_t cos_tbl[CLS_L2_QOS_MAX];
	odp_queue_t queue_tbl[CLS_L2_QOS_MAX];
	odp_pool_t pool;
	uint8_t qos_tbl[CLS_L2_QOS_MAX];
	char cosname[ODP_COS_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	char poolname[ODP_POOL_NAME_LEN];
	int retval;
	int i;
	odp_queue_param_t qparam;
	odp_cls_cos_param_t cls_param;

	/** Initialize scalar variable qos_tbl **/
	for (i = 0; i < CLS_L2_QOS_MAX; i++)
		qos_tbl[i] = 0;

	if (odp_schedule_num_prio() < num_qos)
		num_qos = odp_schedule_num_prio();

	global_num_l2_qos = num_qos;

	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	for (i = 0; i < num_qos; i++) {
		qparam.sched.prio = odp_schedule_min_prio() + i;
		sprintf(queuename, "%s_%d", "L2_Queue", i);
		queue_tbl[i] = odp_queue_create(queuename, &qparam);
		CU_ASSERT_FATAL(queue_tbl[i] != ODP_QUEUE_INVALID);
		queue_list[CLS_L2_QOS_0 + i] = queue_tbl[i];

		sprintf(poolname, "%s_%d", "L2_Pool", i);
		pool = pool_create(poolname);
		CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
		pool_list[CLS_L2_QOS_0 + i] = pool;

		sprintf(cosname, "%s_%d", "L2_Cos", i);
		odp_cls_cos_param_init(&cls_param);
		cls_param.pool = pool;
		cls_param.queue = queue_tbl[i];
		cls_param.drop_policy = ODP_COS_DROP_POOL;
		cos_tbl[i] = odp_cls_cos_create(cosname, &cls_param);
		if (cos_tbl[i] == ODP_COS_INVALID)
			break;

		cos_list[CLS_L2_QOS_0 + i] = cos_tbl[i];
		qos_tbl[i] = i;
	}
	/* count 'i' is passed instead of num_qos to handle the rare scenario
	if the odp_cls_cos_create() failed in the middle*/
	retval = odp_cos_with_l2_priority(pktio_loop, i, qos_tbl, cos_tbl);
	CU_ASSERT(retval == 0);
}

void test_cos_with_l2_priority(void)
{
	odp_packet_t pkt;
	odph_ethhdr_t *ethhdr;
	odph_vlanhdr_t *vlan;
	odp_queue_t queue;
	odp_pool_t pool;
	uint32_t seqno = 0;
	cls_packet_info_t pkt_info;
	uint8_t i;

	pkt_info = default_pkt_info;
	pkt_info.udp = true;
	pkt_info.vlan = true;

	for (i = 0; i < global_num_l2_qos; i++) {
		pkt = create_packet(pkt_info);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		seqno = cls_pkt_get_seq(pkt);
		CU_ASSERT(seqno != TEST_SEQ_INVALID);
		ethhdr = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
		vlan = (odph_vlanhdr_t *)(ethhdr + 1);
		vlan->tci = odp_cpu_to_be_16(i << 13);
		enqueue_pktio_interface(pkt, pktio_loop);
		pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		CU_ASSERT(queue == queue_list[CLS_L2_QOS_0 + i]);
		pool = odp_packet_pool(pkt);
		CU_ASSERT(pool == pool_list[CLS_L2_QOS_0 + i]);
		CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
		odp_packet_free(pkt);
	}
}

void configure_pmr_cos(void)
{
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;
	odp_queue_param_t qparam;
	odp_cls_cos_param_t cls_param;
	char cosname[ODP_COS_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	char poolname[ODP_POOL_NAME_LEN];

	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio = odp_schedule_max_prio();
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "PMR_CoS");

	queue_list[CLS_PMR] = odp_queue_create(queuename, &qparam);
	CU_ASSERT_FATAL(queue_list[CLS_PMR] != ODP_QUEUE_INVALID);

	sprintf(poolname, "PMR_Pool");
	pool_list[CLS_PMR] = pool_create(poolname);
	CU_ASSERT_FATAL(pool_list[CLS_PMR] != ODP_POOL_INVALID);

	sprintf(cosname, "PMR_CoS");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool_list[CLS_PMR];
	cls_param.queue = queue_list[CLS_PMR];
	cls_param.drop_policy = ODP_COS_DROP_POOL;
	cos_list[CLS_PMR] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_PMR] != ODP_COS_INVALID);

	val = CLS_PMR_PORT;
	mask = 0xffff;
	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = find_first_supported_l3_pmr();
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pmr_list[CLS_PMR] = odp_cls_pmr_create(&pmr_param, 1,
					       cos_list[CLS_DEFAULT],
					       cos_list[CLS_PMR]);
	CU_ASSERT_FATAL(pmr_list[CLS_PMR] != ODP_PMR_INVALID);
}

void test_pmr_cos(void)
{
	odp_packet_t pkt;
	odp_queue_t queue;
	odp_pool_t pool;
	uint32_t seqno = 0;
	cls_packet_info_t pkt_info;

	pkt_info = default_pkt_info;
	pkt_info.udp = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);
	set_first_supported_pmr_port(pkt, CLS_PMR_PORT);
	enqueue_pktio_interface(pkt, pktio_loop);
	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(queue == queue_list[CLS_PMR]);
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[CLS_PMR]);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	odp_packet_free(pkt);
}

void configure_pktio_pmr_composite(void)
{
	odp_pmr_param_t pmr_params[2];
	uint16_t val;
	uint16_t maskport;
	int num_terms = 2; /* one pmr for each L3 and L4 */
	odp_queue_param_t qparam;
	odp_cls_cos_param_t cls_param;
	char cosname[ODP_COS_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	char poolname[ODP_POOL_NAME_LEN];
	uint32_t addr = 0;
	uint32_t mask;

	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio = odp_schedule_max_prio();
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "cos_pmr_composite_queue");

	queue_list[CLS_PMR_SET] = odp_queue_create(queuename, &qparam);
	CU_ASSERT_FATAL(queue_list[CLS_PMR_SET] != ODP_QUEUE_INVALID);

	sprintf(poolname, "cos_pmr_composite_pool");
	pool_list[CLS_PMR_SET] = pool_create(poolname);
	CU_ASSERT_FATAL(pool_list[CLS_PMR_SET] != ODP_POOL_INVALID);

	sprintf(cosname, "cos_pmr_composite");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool_list[CLS_PMR_SET];
	cls_param.queue = queue_list[CLS_PMR_SET];
	cls_param.drop_policy = ODP_COS_DROP_POOL;
	cos_list[CLS_PMR_SET] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_PMR_SET] != ODP_COS_INVALID);

	parse_ipv4_string(CLS_PMR_SET_SADDR, &addr, &mask);
	odp_cls_pmr_param_init(&pmr_params[0]);
	pmr_params[0].term = ODP_PMR_SIP_ADDR;
	pmr_params[0].match.value = &addr;
	pmr_params[0].match.mask = &mask;
	pmr_params[0].val_sz = sizeof(addr);

	val = CLS_PMR_SET_PORT;
	maskport = 0xffff;
	odp_cls_pmr_param_init(&pmr_params[1]);
	pmr_params[1].term = find_first_supported_l3_pmr();
	pmr_params[1].match.value = &val;
	pmr_params[1].match.mask = &maskport;
	pmr_params[1].range_term = false;
	pmr_params[1].val_sz = sizeof(val);

	pmr_list[CLS_PMR_SET] = odp_cls_pmr_create(pmr_params, num_terms,
						   cos_list[CLS_DEFAULT],
						   cos_list[CLS_PMR_SET]);
	CU_ASSERT_FATAL(pmr_list[CLS_PMR_SET] != ODP_PMR_INVALID);
}

void test_pktio_pmr_composite_cos(void)
{
	uint32_t addr = 0;
	uint32_t mask;
	odph_ipv4hdr_t *ip;
	odp_packet_t pkt;
	odp_pool_t pool;
	odp_queue_t queue;
	uint32_t seqno = 0;
	cls_packet_info_t pkt_info;

	pkt_info = default_pkt_info;
	pkt_info.udp = true;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	parse_ipv4_string(CLS_PMR_SET_SADDR, &addr, &mask);
	ip->src_addr = odp_cpu_to_be_32(addr);
	odph_ipv4_csum_update(pkt);

	set_first_supported_pmr_port(pkt, CLS_PMR_SET_PORT);
	enqueue_pktio_interface(pkt, pktio_loop);
	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(queue == queue_list[CLS_PMR_SET]);
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[CLS_PMR_SET]);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	odp_packet_free(pkt);
}

static void classification_test_pktio_configure(void)
{
	odp_cls_capability_t capa;
	int num_cos;

	odp_cls_capability(&capa);
	num_cos = capa.max_cos;

	/* Configure the Different CoS for the pktio interface */
	if (num_cos >= NUM_COS_DEFAULT && TEST_DEFAULT) {
		configure_pktio_default_cos();
		tc.default_cos = 1;
		num_cos -= NUM_COS_DEFAULT;
	}
	if (num_cos >= NUM_COS_ERROR && TEST_ERROR) {
		configure_pktio_error_cos();
		tc.error_cos = 1;
		num_cos -= NUM_COS_ERROR;
	}
	if (num_cos >= NUM_COS_PMR_CHAIN && TEST_PMR_CHAIN) {
		configure_cls_pmr_chain();
		tc.pmr_chain = 1;
		num_cos -= NUM_COS_PMR_CHAIN;
	}
	if (num_cos >= NUM_COS_L2_PRIO && TEST_L2_QOS) {
		configure_cos_with_l2_priority();
		tc.l2_priority = 1;
		num_cos -= NUM_COS_L2_PRIO;
	}
	if (num_cos >= NUM_COS_PMR && TEST_PMR) {
		configure_pmr_cos();
		tc.pmr_cos = 1;
		num_cos -= NUM_COS_PMR;
	}
	if (num_cos >= NUM_COS_COMPOSITE && TEST_PMR_SET) {
		configure_pktio_pmr_composite();
		tc.pmr_composite_cos = 1;
		num_cos -= NUM_COS_COMPOSITE;
	}

}

static void classification_test_pktio_test(void)
{
	/* Test Different CoS on the pktio interface */
	if (tc.default_cos && TEST_DEFAULT)
		test_pktio_default_cos();
	if (tc.error_cos && TEST_ERROR)
		test_pktio_error_cos();
	if (tc.pmr_chain && TEST_PMR_CHAIN)
		test_cls_pmr_chain();
	if (tc.l2_priority && TEST_L2_QOS)
		test_cos_with_l2_priority();
	if (tc.pmr_cos && TEST_PMR)
		test_pmr_cos();
	if (tc.pmr_composite_cos && TEST_PMR_SET)
		test_pktio_pmr_composite_cos();
}

odp_testinfo_t classification_suite[] = {
	ODP_TEST_INFO(classification_test_pktio_set_skip),
	ODP_TEST_INFO(classification_test_pktio_set_headroom),
	ODP_TEST_INFO(classification_test_pktio_configure),
	ODP_TEST_INFO(classification_test_pktio_test),
	ODP_TEST_INFO_NULL,
};

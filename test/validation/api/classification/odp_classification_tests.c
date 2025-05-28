/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2020-2024 Nokia
 */

#include "odp_classification_testsuites.h"
#include "classification.h"
#include <odp_cunit_common.h>
#include <odp/helper/odph_api.h>

static odp_cos_t cos_list[CLS_ENTRIES];
static odp_pmr_t pmr_list[CLS_ENTRIES];
static odp_queue_t queue_list[CLS_ENTRIES];
static odp_pool_t pool_list[CLS_ENTRIES];

static odp_pool_t pool_default;
static odp_pktio_t pktio_loop;
static odp_pktio_capability_t pktio_capa;
static odp_cls_testcase_u tc;

#define NUM_COS_PMR_CHAIN	2
#define NUM_COS_DEFAULT	1
#define NUM_COS_DROP	1
#define NUM_COS_ERROR	1
#define NUM_COS_PMR	1
#define NUM_COS_COMPOSITE	1
#define PKTV_DEFAULT_SIZE	8

/** sequence number of IP packets */
static odp_atomic_u32_t seq;

/* default packet info */
static cls_packet_info_t default_pkt_info;

/* Packet vector configuration */
static odp_pktin_vector_config_t pktv_config;

static int classification_suite_common_init(odp_bool_t enable_pktv)
{
	int i;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;

	tc.all_bits = 0;

	pool_default = pool_create("classification_pool");
	if (ODP_POOL_INVALID == pool_default) {
		ODPH_ERR("Packet pool creation failed\n");
		return -1;
	}

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio_loop = odp_pktio_open("loop", pool_default, &pktio_param);
	if (pktio_loop == ODP_PKTIO_INVALID) {
		ret = odp_pool_destroy(pool_default);
		if (ret)
			ODPH_ERR("Unable to destroy pool\n");
		return -1;
	}

	ret = odp_pktio_capability(pktio_loop, &pktio_capa);
	if (ret) {
		ODPH_ERR("Unable to get pktio capability\n");
		return -1;
	}

	memset(&default_pkt_info, 0, sizeof(cls_packet_info_t));
	default_pkt_info.pool = pool_default;
	default_pkt_info.seq = &seq;

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
	pktin_param.classifier_enable = true;
	pktin_param.hash_enable = false;

	if (enable_pktv) {
		odp_pktio_capability_t capa;
		odp_pool_t pktv_pool;

		pktv_pool = pktv_pool_create("packet_vector_pool");
		if (pktv_pool == ODP_POOL_INVALID) {
			ODPH_ERR("Packet vector pool creation failed\n");
			return -1;
		}

		if (odp_pktio_capability(pktio_loop, &capa)) {
			ODPH_ERR("Pktio capability failed\n");
			return -1;
		}

		if (!capa.vector.supported) {
			printf("Packet vector mode is not supported. Test suite skipped.\n");
			pktv_config.enable = false;
			pktv_config.pool = pktv_pool;
		} else {
			pktin_param.vector.enable = true;
			pktin_param.vector.pool = pktv_pool;
			pktin_param.vector.max_size = capa.vector.max_size < PKTV_DEFAULT_SIZE ?
						capa.vector.max_size : PKTV_DEFAULT_SIZE;
			pktin_param.vector.max_tmo_ns = capa.vector.min_tmo_ns;

			/* Copy packet vector config for global access */
			pktv_config = pktin_param.vector;
		}
	}

	if (odp_pktin_queue_config(pktio_loop, &pktin_param)) {
		ODPH_ERR("Pktin queue config failed\n");
		return -1;
	}

	if (odp_pktout_queue_config(pktio_loop, NULL)) {
		ODPH_ERR("Pktout queue config failed\n");
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
		ODPH_ERR("Unable to start loop\n");
		return -1;
	}

	return 0;
}

static int classification_suite_common_term(odp_bool_t enable_pktv)
{
	int i;
	int retcode = 0;

	if (0 >	stop_pktio(pktio_loop)) {
		ODPH_ERR("Stop pktio failed\n");
		retcode = -1;
	}

	if (0 > odp_pktio_close(pktio_loop)) {
		ODPH_ERR("Pktio close failed\n");
		retcode = -1;
	}

	for (i = 0; i < CLS_ENTRIES; i++) {
		if (pmr_list[i] != ODP_PMR_INVALID)
			odp_cls_pmr_destroy(pmr_list[i]);
	}

	for (i = 0; i < CLS_ENTRIES; i++) {
		if (cos_list[i] != ODP_COS_INVALID)
			odp_cos_destroy(cos_list[i]);
	}

	if (0 != odp_pool_destroy(pool_default)) {
		ODPH_ERR("Pool_default destroy failed\n");
		retcode = -1;
	}

	if (enable_pktv) {
		if (odp_pool_destroy(pktv_config.pool)) {
			ODPH_ERR("Packet vector pool destroy failed\n");
			retcode = -1;
		}
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

int classification_suite_init(void)
{
	return classification_suite_common_init(false);
}

int classification_suite_term(void)
{
	return classification_suite_common_term(false);
}

int classification_suite_pktv_init(void)
{
	return classification_suite_common_init(true);
}

int classification_suite_pktv_term(void)
{
	return classification_suite_common_term(true);
}

static void configure_cls_pmr_chain_create_saddr_pmr(int src, int dst, const char *saddr)
{
	uint32_t addr;
	uint32_t mask;
	odp_pmr_param_t pmr_param;

	parse_ipv4_string(saddr, &addr, &mask);
	addr = odp_cpu_to_be_32(addr);
	mask = odp_cpu_to_be_32(mask);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = ODP_PMR_SIP_ADDR;
	pmr_param.match.value = &addr;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(addr);
	pmr_list[dst] =
	odp_cls_pmr_create(&pmr_param, 1, cos_list[src],
			   cos_list[dst]);
	CU_ASSERT_FATAL(pmr_list[dst] != ODP_PMR_INVALID);
}

static void configure_cls_pmr_chain_create_port_pmr(int src, int dst, uint16_t port)
{
	uint16_t val;
	uint16_t maskport;
	odp_pmr_param_t pmr_param;

	val = odp_cpu_to_be_16(port);
	maskport = odp_cpu_to_be_16(0xffff);
	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = find_first_supported_l3_pmr();
	pmr_param.match.value = &val;
	pmr_param.match.mask = &maskport;
	pmr_param.val_sz = sizeof(val);
	pmr_list[dst] =
	odp_cls_pmr_create(&pmr_param, 1, cos_list[src],
			   cos_list[dst]);
	CU_ASSERT_FATAL(pmr_list[dst] != ODP_PMR_INVALID);
}

void configure_cls_pmr_chain(odp_bool_t enable_pktv, int src, int dst, const char *saddr,
			     uint16_t port, odp_bool_t saddr_first)
{
	/* PKTIO --> PMR_SRC(SRC IP ADDR) --> PMR_DST (TCP SPORT) */

	/* Packet matching only the SRC IP ADDR should be delivered
	in queue[src] and a packet matching both SRC IP ADDR and
	TCP SPORT should be delivered to queue[dst] */

	char cosname[ODP_COS_NAME_LEN];
	odp_queue_param_t qparam;
	odp_cls_cos_param_t cls_param;
	char queuename[ODP_QUEUE_NAME_LEN];
	char poolname[ODP_POOL_NAME_LEN];
	odp_schedule_capability_t schedule_capa;

	CU_ASSERT_FATAL(odp_schedule_capability(&schedule_capa) == 0);

	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio = odp_schedule_default_prio();
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	qparam.sched.lock_count = schedule_capa.max_ordered_locks;
	sprintf(queuename, "%s", "SrcQueue");

	queue_list[src] = odp_queue_create(queuename, &qparam);

	CU_ASSERT_FATAL(queue_list[src] != ODP_QUEUE_INVALID);

	sprintf(poolname, "%s", "SrcPool");
	pool_list[src] = pool_create(poolname);
	CU_ASSERT_FATAL(pool_list[src] != ODP_POOL_INVALID);

	sprintf(cosname, "SrcCos");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool_list[src];
	cls_param.queue = queue_list[src];

	if (enable_pktv) {
		cls_param.vector.enable = true;
		cls_param.vector.pool = pktv_config.pool;
		cls_param.vector.max_size = pktv_config.max_size;
		cls_param.vector.max_tmo_ns = pktv_config.max_tmo_ns;
	}

	cos_list[src] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[src] != ODP_COS_INVALID);

	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio = odp_schedule_default_prio();
	qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "DstQueue");

	queue_list[dst] = odp_queue_create(queuename, &qparam);
	CU_ASSERT_FATAL(queue_list[dst] != ODP_QUEUE_INVALID);

	sprintf(poolname, "%s", "DstPool");
	pool_list[dst] = pool_create(poolname);
	CU_ASSERT_FATAL(pool_list[dst] != ODP_POOL_INVALID);

	sprintf(cosname, "DstCos");
	odp_cls_cos_param_init(&cls_param);
	cls_param.pool = pool_list[dst];
	cls_param.queue = queue_list[dst];

	if (enable_pktv) {
		cls_param.vector.enable = true;
		cls_param.vector.pool = pktv_config.pool;
		cls_param.vector.max_size = pktv_config.max_size;
		cls_param.vector.max_tmo_ns = pktv_config.max_tmo_ns;
	}

	cos_list[dst] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[dst] != ODP_COS_INVALID);

	if (saddr_first) {
		configure_cls_pmr_chain_create_saddr_pmr(CLS_DEFAULT, src, saddr);
		configure_cls_pmr_chain_create_port_pmr(src, dst, port);
	} else {
		configure_cls_pmr_chain_create_port_pmr(src, dst, port);
		configure_cls_pmr_chain_create_saddr_pmr(CLS_DEFAULT, src, saddr);
	}
}

void test_cls_pmr_chain(odp_bool_t enable_pktv, int src, int dst, const char *saddr, uint16_t port)
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
	pkt_info.l4_type = find_first_supported_proto();
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	parse_ipv4_string(saddr, &addr, &mask);
	ip->src_addr = odp_cpu_to_be_32(addr);
	odph_ipv4_csum_update(pkt);

	set_first_supported_pmr_port(pkt, port);

	enqueue_pktio_interface(pkt, pktio_loop);

	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS, enable_pktv);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(queue == queue_list[dst]);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[dst]);
	odp_packet_free(pkt);

	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	parse_ipv4_string(saddr, &addr, &mask);
	ip->src_addr = odp_cpu_to_be_32(addr);
	odph_ipv4_csum_update(pkt);

	enqueue_pktio_interface(pkt, pktio_loop);
	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS, enable_pktv);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(queue == queue_list[src]);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[src]);
	odp_packet_free(pkt);
}

void configure_pktio_default_cos(odp_bool_t enable_pktv)
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

	if (enable_pktv) {
		cls_param.vector.enable = true;
		cls_param.vector.pool = pktv_config.pool;
		cls_param.vector.max_size = pktv_config.max_size;
		cls_param.vector.max_tmo_ns = pktv_config.max_tmo_ns;
	}

	cos_list[CLS_DEFAULT] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_DEFAULT] != ODP_COS_INVALID);

	retval = odp_pktio_default_cos_set(pktio_loop, cos_list[CLS_DEFAULT]);
	CU_ASSERT(retval == 0);
}

void test_pktio_default_cos(odp_bool_t enable_pktv)
{
	odp_packet_t pkt;
	odp_queue_t queue;
	uint32_t seqno = 0;
	odp_pool_t pool;
	cls_packet_info_t pkt_info;

	/* create a default packet */
	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	enqueue_pktio_interface(pkt, pktio_loop);

	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS, enable_pktv);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	/* Default packet should be received in default queue */
	CU_ASSERT(queue == queue_list[CLS_DEFAULT]);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[CLS_DEFAULT]);

	odp_packet_free(pkt);
}

void configure_pktio_drop_cos(odp_bool_t enable_pktv, uint32_t max_cos_stats)
{
	uint16_t val;
	uint16_t mask;
	odp_pmr_param_t pmr_param;
	odp_cls_cos_param_t cls_param;
	char cosname[ODP_COS_NAME_LEN];

	sprintf(cosname, "DropCoS");
	odp_cls_cos_param_init(&cls_param);

	cls_param.action = ODP_COS_ACTION_DROP;
	cls_param.stats_enable = max_cos_stats > 0;

	if (enable_pktv) {
		cls_param.vector.enable = true;
		cls_param.vector.pool = pktv_config.pool;
		cls_param.vector.max_size = pktv_config.max_size;
		cls_param.vector.max_tmo_ns = pktv_config.max_tmo_ns;
	}

	cos_list[CLS_DROP] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_DROP] != ODP_COS_INVALID);

	val = odp_cpu_to_be_16(CLS_DROP_PORT);
	mask = odp_cpu_to_be_16(0xffff);
	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term = find_first_supported_l3_pmr();
	pmr_param.match.value = &val;
	pmr_param.match.mask = &mask;
	pmr_param.val_sz = sizeof(val);

	pmr_list[CLS_DROP] = odp_cls_pmr_create(&pmr_param, 1,
						cos_list[CLS_DEFAULT],
						cos_list[CLS_DROP]);
	CU_ASSERT_FATAL(pmr_list[CLS_DROP] != ODP_PMR_INVALID);
}

void test_pktio_drop_cos(odp_bool_t enable_pktv)
{
	odp_packet_t pkt;
	odp_queue_t queue;
	uint32_t seqno = 0;
	cls_packet_info_t pkt_info;
	odp_cls_capability_t capa;
	odp_cls_cos_stats_t start, stop;

	CU_ASSERT_FATAL(odp_cls_capability(&capa) == 0);
	pkt_info = default_pkt_info;
	pkt_info.l4_type = find_first_supported_proto();
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);
	set_first_supported_pmr_port(pkt, CLS_DROP_PORT);
	CU_ASSERT(odp_cls_cos_stats(cos_list[CLS_DROP], &start) == 0);
	enqueue_pktio_interface(pkt, pktio_loop);
	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS / 10, enable_pktv);
	CU_ASSERT(odp_cls_cos_stats(cos_list[CLS_DROP], &stop) == 0);
	CU_ASSERT_FATAL(pkt == ODP_PACKET_INVALID);
	if (capa.stats.cos.counter.packets)
		CU_ASSERT((stop.packets - start.packets) == 1);
	if (capa.stats.cos.counter.discards)
		CU_ASSERT((stop.discards - start.discards) == 0);
	if (capa.stats.cos.counter.errors)
		CU_ASSERT((stop.errors - start.errors) == 0);
}

static int check_queue_stats(void)
{
	odp_cls_capability_t capa;

	if (odp_cls_capability(&capa))
		return ODP_TEST_INACTIVE;

	if (capa.stats.queue.all_counters)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static void cls_queue_stats(odp_bool_t enable_pktv)
{
	odp_cls_capability_t capa;
	odp_cls_queue_stats_t stats_start;
	odp_cls_queue_stats_t stats_stop;
	odp_cos_t cos;
	odp_queue_t queue;

	/* Default CoS used for test packets */
	if (!tc.default_cos || !TEST_DEFAULT) {
		printf("Default CoS not supported, skipping test\n");
		return;
	}

	cos = cos_list[CLS_DEFAULT];
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);
	queue = odp_cos_queue(cos);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	CU_ASSERT_FATAL(odp_cls_capability(&capa) == 0);

	CU_ASSERT(odp_cls_queue_stats(cos, queue, &stats_start) == 0);

	test_pktio_default_cos(enable_pktv);

	CU_ASSERT(odp_cls_queue_stats(cos, queue, &stats_stop) == 0);

	if (capa.stats.queue.counter.packets)
		CU_ASSERT(stats_stop.packets > stats_start.packets);
	if (capa.stats.queue.counter.octets)
		CU_ASSERT(stats_stop.octets > stats_start.octets);
	CU_ASSERT((stats_stop.discards - stats_start.discards) == 0);
	CU_ASSERT((stats_stop.errors - stats_start.errors) == 0);

	printf("\nQueue statistics\n----------------\n");
	printf("  discards: %" PRIu64 "\n", stats_stop.discards);
	printf("  errors:   %" PRIu64 "\n", stats_stop.errors);
	printf("  octets:   %" PRIu64 "\n", stats_stop.octets);
	printf("  packets:  %" PRIu64 "\n", stats_stop.packets);

	/* Check that all unsupported counters are still zero */
	if (!capa.stats.queue.counter.discards)
		CU_ASSERT(stats_stop.discards == 0);
	if (!capa.stats.queue.counter.errors)
		CU_ASSERT(stats_stop.errors == 0);
	if (!capa.stats.queue.counter.octets)
		CU_ASSERT(stats_stop.octets == 0);
	if (!capa.stats.queue.counter.packets)
		CU_ASSERT(stats_stop.packets == 0);
}

static void cls_queue_stats_pkt(void)
{
	cls_queue_stats(false);
}

static void cls_queue_stats_pktv(void)
{
	cls_queue_stats(true);
}

void configure_pktio_error_cos(odp_bool_t enable_pktv)
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

	if (enable_pktv) {
		cls_param.vector.enable = true;
		cls_param.vector.pool = pktv_config.pool;
		cls_param.vector.max_size = pktv_config.max_size;
		cls_param.vector.max_tmo_ns = pktv_config.max_tmo_ns;
	}

	cos_list[CLS_ERROR] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_ERROR] != ODP_COS_INVALID);

	retval = odp_pktio_error_cos_set(pktio_loop, cos_list[CLS_ERROR]);
	CU_ASSERT(retval == 0);
}

void test_pktio_error_cos(odp_bool_t enable_pktv)
{
	odp_queue_t queue;
	odp_packet_t pkt;
	odp_pool_t pool;
	cls_packet_info_t pkt_info;

	/*Create an error packet */
	pkt_info = default_pkt_info;
	pkt_info.l4_type = CLS_PKT_L4_UDP;
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);

	/* Incorrect IpV4 version */
	ip->ver_ihl = 8 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->chksum = 0;
	enqueue_pktio_interface(pkt, pktio_loop);

	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS, enable_pktv);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	/* Error packet should be received in error queue */
	CU_ASSERT(queue == queue_list[CLS_ERROR]);
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[CLS_ERROR]);
	odp_packet_free(pkt);
}

static void cls_pktio_set_skip(void)
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

static void cls_pktio_set_headroom(void)
{
	size_t headroom;
	int retval;

	headroom = 5;
	retval = odp_pktio_headroom_set(pktio_loop, headroom);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_headroom_set(ODP_PKTIO_INVALID, headroom);
	CU_ASSERT(retval < 0);
}

void configure_pmr_cos(odp_bool_t enable_pktv)
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

	if (enable_pktv) {
		cls_param.vector.enable = true;
		cls_param.vector.pool = pktv_config.pool;
		cls_param.vector.max_size = pktv_config.max_size;
		cls_param.vector.max_tmo_ns = pktv_config.max_tmo_ns;
	}

	cos_list[CLS_PMR] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_PMR] != ODP_COS_INVALID);

	val = odp_cpu_to_be_16(CLS_PMR_PORT);
	mask = odp_cpu_to_be_16(0xffff);
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

void test_pmr_cos(odp_bool_t enable_pktv)
{
	odp_packet_t pkt;
	odp_queue_t queue;
	odp_pool_t pool;
	uint32_t seqno = 0;
	cls_packet_info_t pkt_info;

	pkt_info = default_pkt_info;
	pkt_info.l4_type = find_first_supported_proto();
	pkt = create_packet(pkt_info);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);
	set_first_supported_pmr_port(pkt, CLS_PMR_PORT);
	enqueue_pktio_interface(pkt, pktio_loop);
	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS, enable_pktv);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(queue == queue_list[CLS_PMR]);
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[CLS_PMR]);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	odp_packet_free(pkt);
}

void configure_pktio_pmr_composite(odp_bool_t enable_pktv)
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

	if (enable_pktv) {
		cls_param.vector.enable = true;
		cls_param.vector.pool = pktv_config.pool;
		cls_param.vector.max_size = pktv_config.max_size;
		cls_param.vector.max_tmo_ns = pktv_config.max_tmo_ns;
	}

	cos_list[CLS_PMR_SET] = odp_cls_cos_create(cosname, &cls_param);
	CU_ASSERT_FATAL(cos_list[CLS_PMR_SET] != ODP_COS_INVALID);

	parse_ipv4_string(CLS_PMR_SET_SADDR, &addr, &mask);
	addr = odp_cpu_to_be_32(addr);
	mask = odp_cpu_to_be_32(mask);

	odp_cls_pmr_param_init(&pmr_params[0]);
	pmr_params[0].term = ODP_PMR_SIP_ADDR;
	pmr_params[0].match.value = &addr;
	pmr_params[0].match.mask = &mask;
	pmr_params[0].val_sz = sizeof(addr);

	val = odp_cpu_to_be_16(CLS_PMR_SET_PORT);
	maskport = odp_cpu_to_be_16(0xffff);
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

void test_pktio_pmr_composite_cos(odp_bool_t enable_pktv)
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
	pkt_info.l4_type = find_first_supported_proto();
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
	pkt = receive_packet(&queue, ODP_TIME_SEC_IN_NS, enable_pktv);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(queue == queue_list[CLS_PMR_SET]);
	pool = odp_packet_pool(pkt);
	CU_ASSERT(pool == pool_list[CLS_PMR_SET]);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	odp_packet_free(pkt);
}

static void cls_pktio_configure_common(odp_bool_t enable_pktv)
{
	odp_cls_capability_t capa;
	int num_cos;

	if (odp_cls_capability(&capa)) {
		CU_FAIL("odp_cls_capability() failed");
		return;
	}
	num_cos = capa.max_cos;

	/* Configure the Different CoS for the pktio interface */
	if (num_cos >= NUM_COS_DEFAULT && TEST_DEFAULT) {
		configure_pktio_default_cos(enable_pktv);
		tc.default_cos = 1;
		num_cos -= NUM_COS_DEFAULT;
	}
	if (num_cos >= NUM_COS_DEFAULT && TEST_DROP) {
		configure_pktio_drop_cos(enable_pktv, capa.max_cos_stats);
		tc.drop_cos = 1;
		num_cos -= NUM_COS_DROP;
	}
	if (num_cos >= NUM_COS_ERROR && TEST_ERROR) {
		configure_pktio_error_cos(enable_pktv);
		tc.error_cos = 1;
		num_cos -= NUM_COS_ERROR;
	}
	if (num_cos >= NUM_COS_PMR_CHAIN && TEST_PMR_CHAIN) {
		configure_cls_pmr_chain(enable_pktv, CLS_PMR_CHAIN_SRC, CLS_PMR_CHAIN_DST,
					CLS_PMR_CHAIN_SADDR, CLS_PMR_CHAIN_PORT, true);
		tc.pmr_chain = 1;
		num_cos -= NUM_COS_PMR_CHAIN;
	}
	if (num_cos >= NUM_COS_PMR_CHAIN && TEST_PMR_CHAIN_REV) {
		configure_cls_pmr_chain(enable_pktv, CLS_PMR_CHAIN_REV_SRC, CLS_PMR_CHAIN_REV_DST,
					CLS_PMR_CHAIN_REV_SADDR, CLS_PMR_CHAIN_REV_PORT, false);
		tc.pmr_chain_rev = 1;
		num_cos -= NUM_COS_PMR_CHAIN;
	}
	if (num_cos >= NUM_COS_PMR && TEST_PMR) {
		configure_pmr_cos(enable_pktv);
		tc.pmr_cos = 1;
		num_cos -= NUM_COS_PMR;
	}
	if (num_cos >= NUM_COS_COMPOSITE && TEST_PMR_SET) {
		configure_pktio_pmr_composite(enable_pktv);
		tc.pmr_composite_cos = 1;
		num_cos -= NUM_COS_COMPOSITE;
	}

	odp_cls_print_all();
}

static void cls_pktio_configure(void)
{
	cls_pktio_configure_common(false);
}

static void cls_pktio_configure_pktv(void)
{
	cls_pktio_configure_common(true);
}

static void cls_pktio_test_common(odp_bool_t enable_pktv)
{
	/* Test Different CoS on the pktio interface */
	if (tc.default_cos && TEST_DEFAULT)
		test_pktio_default_cos(enable_pktv);
	if (tc.drop_cos && TEST_DROP)
		test_pktio_drop_cos(enable_pktv);
	if (tc.error_cos && TEST_ERROR)
		test_pktio_error_cos(enable_pktv);
	if (tc.pmr_chain && TEST_PMR_CHAIN)
		test_cls_pmr_chain(enable_pktv, CLS_PMR_CHAIN_SRC, CLS_PMR_CHAIN_DST,
				   CLS_PMR_CHAIN_SADDR, CLS_PMR_CHAIN_PORT);
	if (tc.pmr_chain_rev && TEST_PMR_CHAIN_REV)
		test_cls_pmr_chain(enable_pktv, CLS_PMR_CHAIN_REV_SRC, CLS_PMR_CHAIN_REV_DST,
				   CLS_PMR_CHAIN_REV_SADDR, CLS_PMR_CHAIN_REV_PORT);
	if (tc.pmr_cos && TEST_PMR)
		test_pmr_cos(enable_pktv);
	if (tc.pmr_composite_cos && TEST_PMR_SET)
		test_pktio_pmr_composite_cos(enable_pktv);
}

static void cls_pktio_test(void)
{
	cls_pktio_test_common(false);
}

static void cls_pktio_test_pktv(void)
{
	cls_pktio_test_common(true);
}

static int check_pktv(void)
{
	return pktv_config.enable ? ODP_TEST_ACTIVE : ODP_TEST_INACTIVE;
}

static int check_capa_skip_offset(void)
{
	return pktio_capa.set_op.op.skip_offset;
}

odp_testinfo_t classification_suite[] = {
	ODP_TEST_INFO_CONDITIONAL(cls_pktio_set_skip, check_capa_skip_offset),
	ODP_TEST_INFO(cls_pktio_set_headroom),
	ODP_TEST_INFO(cls_pktio_configure),
	ODP_TEST_INFO(cls_pktio_test),
	ODP_TEST_INFO_CONDITIONAL(cls_queue_stats_pkt, check_queue_stats),
	ODP_TEST_INFO_NULL,
};

odp_testinfo_t classification_suite_pktv[] = {
	ODP_TEST_INFO_CONDITIONAL(cls_pktio_configure_pktv, check_pktv),
	ODP_TEST_INFO_CONDITIONAL(cls_pktio_test_pktv, check_pktv),
	ODP_TEST_INFO_CONDITIONAL(cls_queue_stats_pktv, check_queue_stats),
	ODP_TEST_INFO_NULL,
};

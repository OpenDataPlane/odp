/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp_classification_testsuites.h"
#include "classification.h"
#include <odp_cunit_common.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <odp/helper/tcp.h>

static odp_pool_t pool_default;

/** sequence number of IP packets */
odp_atomic_u32_t seq;

int classification_suite_pmr_init(void)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);
	param.pkt.seg_len = SHM_PKT_BUF_SIZE;
	param.pkt.len     = SHM_PKT_BUF_SIZE;
	param.pkt.num     = SHM_PKT_NUM_BUFS;
	param.type        = ODP_POOL_PACKET;

	pool_default = odp_pool_create("classification_pmr_pool", &param);
	if (ODP_POOL_INVALID == pool_default) {
		fprintf(stderr, "Packet pool creation failed.\n");
		return -1;
	}

	odp_atomic_init_u32(&seq, 0);
	return 0;
}

odp_pktio_t create_pktio(odp_queue_type_t q_type)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	int ret;

	if (pool_default == ODP_POOL_INVALID)
		return ODP_PKTIO_INVALID;

	odp_pktio_param_init(&pktio_param);
	if (q_type == ODP_QUEUE_TYPE_POLL)
		pktio_param.in_mode = ODP_PKTIN_MODE_POLL;
	else
		pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open("loop", pool_default, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		ret = odp_pool_destroy(pool_default);
		if (ret)
			fprintf(stderr, "unable to destroy pool.\n");
		return ODP_PKTIO_INVALID;
	}

	ret = odp_pktio_start(pktio);
	if (ret) {
		fprintf(stderr, "unable to start loop\n");
		return ODP_PKTIO_INVALID;
	}

	return pktio;
}

odp_queue_t create_default_inq(odp_pktio_t pktio, odp_queue_type_t qtype)
{
	odp_queue_param_t qparam;
	odp_queue_t inq_def;
	char inq_name[ODP_QUEUE_NAME_LEN];

	odp_queue_param_init(&qparam);
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	snprintf(inq_name, sizeof(inq_name), "inq-pktio-%" PRIu64,
		 odp_pktio_to_u64(pktio));
	inq_def = odp_queue_lookup(inq_name);
	if (inq_def == ODP_QUEUE_INVALID)
		inq_def = odp_queue_create(
				inq_name,
				ODP_QUEUE_TYPE_PKTIN,
				qtype == ODP_QUEUE_TYPE_POLL ? NULL : &qparam);

	CU_ASSERT(inq_def != ODP_QUEUE_INVALID);

	if (0 > odp_pktio_inq_setdef(pktio, inq_def))
		return ODP_QUEUE_INVALID;

	return inq_def;
}

int classification_suite_pmr_term(void)
{
	int retcode = 0;

	if (0 != odp_pool_destroy(pool_default)) {
		fprintf(stderr, "pool_default destroy failed.\n");
		retcode = -1;
	}

	return retcode;
}

static void classification_test_pmr_term_tcp_dport(void)
{
	odp_packet_t pkt;
	odph_tcphdr_t *tcp;
	uint32_t seqno;
	uint16_t val;
	uint16_t mask;
	int retval;
	odp_pktio_t pktio;
	odp_queue_t queue;
	odp_queue_t retqueue;
	odp_queue_t defqueue;
	odp_pmr_t pmr;
	odp_cos_t cos;
	char cosname[ODP_QUEUE_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	odp_pmr_match_t match;

	val = CLS_DEFAULT_DPORT;
	mask = 0xffff;
	seqno = 0;

	pktio = create_pktio(ODP_QUEUE_TYPE_SCHED);
	CU_ASSERT(pktio != ODP_PKTIO_INVALID);
	defqueue = create_default_inq(pktio, ODP_QUEUE_TYPE_SCHED);
	CU_ASSERT(defqueue != ODP_QUEUE_INVALID);

	match.term = ODP_PMR_TCP_DPORT;
	match.val = &val;
	match.mask = &mask;
	match.val_sz = sizeof(val);

	pmr = odp_pmr_create(&match);
	CU_ASSERT(pmr != ODP_PMR_INVAL);

	sprintf(cosname, "tcp_dport");
	cos = odp_cos_create(cosname);
	CU_ASSERT(cos != ODP_COS_INVALID);

	sprintf(queuename, "%s", "tcp_dport1");

	queue = queue_create(queuename, true);
	CU_ASSERT(queue != ODP_QUEUE_INVALID);

	retval = odp_cos_queue_set(cos, queue);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_pmr_cos(pmr, pktio, cos);
	CU_ASSERT(retval == 0);

	pkt = create_packet(pool_default, false, &seq, false);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	tcp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);

	enqueue_pktio_interface(pkt, pktio);

	pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(retqueue == queue);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));

	odp_packet_free(pkt);

	/* Other packets are delivered to default queue */
	pkt = create_packet(pool_default, false, &seq, false);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	tcp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT + 1);

	enqueue_pktio_interface(pkt, pktio);

	pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	CU_ASSERT(retqueue == defqueue);

	odp_packet_free(pkt);
	odp_cos_destroy(cos);
	odp_pmr_destroy(pmr);
	destroy_inq(pktio);
	odp_queue_destroy(queue);
	odp_pktio_close(pktio);
}

static void classification_test_pmr_term_tcp_sport(void)
{
	odp_packet_t pkt;
	odph_tcphdr_t *tcp;
	uint32_t seqno;
	uint16_t val;
	uint16_t mask;
	int retval;
	odp_pktio_t pktio;
	odp_queue_t queue;
	odp_queue_t retqueue;
	odp_queue_t defqueue;
	odp_pmr_t pmr;
	odp_cos_t cos;
	char cosname[ODP_QUEUE_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	odp_pmr_match_t match;

	val = CLS_DEFAULT_SPORT;
	mask = 0xffff;
	seqno = 0;

	pktio = create_pktio(ODP_QUEUE_TYPE_SCHED);
	defqueue = create_default_inq(pktio, ODP_QUEUE_TYPE_SCHED);

	match.term = ODP_PMR_TCP_SPORT;
	match.val = &val;
	match.mask = &mask;
	match.val_sz = sizeof(val);

	pmr = odp_pmr_create(&match);
	CU_ASSERT(pmr != ODP_PMR_INVAL);

	sprintf(cosname, "tcp_sport");
	cos = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	sprintf(queuename, "%s", "tcp_sport");

	queue = queue_create(queuename, true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	retval = odp_cos_queue_set(cos, queue);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_pmr_cos(pmr, pktio, cos);
	CU_ASSERT(retval == 0);

	pkt = create_packet(pool_default, false, &seq, false);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	tcp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT);

	enqueue_pktio_interface(pkt, pktio);

	pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	CU_ASSERT(retqueue == queue);
	odp_packet_free(pkt);

	pkt = create_packet(pool_default, false, &seq, false);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	tcp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT + 1);

	enqueue_pktio_interface(pkt, pktio);

	pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	CU_ASSERT(retqueue == defqueue);

	odp_packet_free(pkt);
	odp_cos_destroy(cos);
	odp_pmr_destroy(pmr);
	destroy_inq(pktio);
	odp_queue_destroy(queue);
	odp_pktio_close(pktio);
}

static void classification_test_pmr_term_udp_dport(void)
{
	odp_packet_t pkt;
	odph_udphdr_t *udp;
	uint32_t seqno;
	uint16_t val;
	uint16_t mask;
	int retval;
	odp_pktio_t pktio;
	odp_queue_t queue;
	odp_queue_t retqueue;
	odp_queue_t defqueue;
	odp_pmr_t pmr;
	odp_cos_t cos;
	char cosname[ODP_QUEUE_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	odp_pmr_match_t match;

	val = CLS_DEFAULT_DPORT;
	mask = 0xffff;
	seqno = 0;

	pktio = create_pktio(ODP_QUEUE_TYPE_SCHED);
	defqueue = create_default_inq(pktio, ODP_QUEUE_TYPE_SCHED);

	match.term = ODP_PMR_UDP_DPORT;
	match.val = &val;
	match.mask = &mask;
	match.val_sz = sizeof(val);

	pmr = odp_pmr_create(&match);
	CU_ASSERT(pmr != ODP_PMR_INVAL);

	sprintf(cosname, "udp_dport");
	cos = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	sprintf(queuename, "%s", "udp_dport");

	queue = queue_create(queuename, true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	retval = odp_cos_queue_set(cos, queue);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_pmr_cos(pmr, pktio, cos);
	CU_ASSERT(retval == 0);

	pkt = create_packet(pool_default, false, &seq, true);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);

	enqueue_pktio_interface(pkt, pktio);

	pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	CU_ASSERT(retqueue == queue);
	odp_packet_free(pkt);

	/* Other packets received in default queue */
	pkt = create_packet(pool_default, false, &seq, true);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT + 1);

	enqueue_pktio_interface(pkt, pktio);

	pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	CU_ASSERT(retqueue == defqueue);

	odp_packet_free(pkt);
	odp_cos_destroy(cos);
	odp_pmr_destroy(pmr);
	destroy_inq(pktio);
	odp_queue_destroy(queue);
	odp_pktio_close(pktio);
}

static void classification_test_pmr_term_udp_sport(void)
{
	odp_packet_t pkt;
	odph_udphdr_t *udp;
	uint32_t seqno;
	uint16_t val;
	uint16_t mask;
	int retval;
	odp_pktio_t pktio;
	odp_queue_t queue;
	odp_queue_t retqueue;
	odp_queue_t defqueue;
	odp_pmr_t pmr;
	odp_cos_t cos;
	char cosname[ODP_QUEUE_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	odp_pmr_match_t match;

	val = CLS_DEFAULT_SPORT;
	mask = 0xffff;
	seqno = 0;

	pktio = create_pktio(ODP_QUEUE_TYPE_SCHED);
	defqueue = create_default_inq(pktio, ODP_QUEUE_TYPE_SCHED);

	match.term = ODP_PMR_UDP_SPORT;
	match.val = &val;
	match.mask = &mask;
	match.val_sz = sizeof(val);

	pmr = odp_pmr_create(&match);
	CU_ASSERT(pmr != ODP_PMR_INVAL);

	sprintf(cosname, "udp_sport");
	cos = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	sprintf(queuename, "%s", "udp_sport");

	queue = queue_create(queuename, true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	retval = odp_cos_queue_set(cos, queue);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_pmr_cos(pmr, pktio, cos);
	CU_ASSERT(retval == 0);

	pkt = create_packet(pool_default, false, &seq, true);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT);

	enqueue_pktio_interface(pkt, pktio);

	pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	CU_ASSERT(retqueue == queue);
	odp_packet_free(pkt);

	pkt = create_packet(pool_default, false, &seq, true);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT + 1);

	enqueue_pktio_interface(pkt, pktio);

	pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	CU_ASSERT(retqueue == defqueue);
	odp_packet_free(pkt);

	odp_cos_destroy(cos);
	odp_pmr_destroy(pmr);
	destroy_inq(pktio);
	odp_queue_destroy(queue);
	odp_pktio_close(pktio);
}

static void classification_test_pmr_term_ipproto(void)
{
	odp_packet_t pkt;
	uint32_t seqno;
	uint8_t val;
	uint8_t mask;
	int retval;
	odp_pktio_t pktio;
	odp_queue_t queue;
	odp_queue_t retqueue;
	odp_queue_t defqueue;
	odp_pmr_t pmr;
	odp_cos_t cos;
	char cosname[ODP_QUEUE_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	odp_pmr_match_t match;

	val = ODPH_IPPROTO_UDP;
	mask = 0xff;
	seqno = 0;

	pktio = create_pktio(ODP_QUEUE_TYPE_SCHED);
	defqueue = create_default_inq(pktio, ODP_QUEUE_TYPE_SCHED);

	match.term = ODP_PMR_IPPROTO;
	match.val = &val;
	match.mask = &mask;
	match.val_sz = sizeof(val);

	pmr = odp_pmr_create(&match);
	CU_ASSERT(pmr != ODP_PMR_INVAL);

	sprintf(cosname, "ipproto");
	cos = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	sprintf(queuename, "%s", "ipproto");

	queue = queue_create(queuename, true);
	CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

	retval = odp_cos_queue_set(cos, queue);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_pmr_cos(pmr, pktio, cos);
	CU_ASSERT(retval == 0);

	pkt = create_packet(pool_default, false, &seq, true);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	enqueue_pktio_interface(pkt, pktio);

	pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	CU_ASSERT(retqueue == queue);
	odp_packet_free(pkt);

	/* Other packets delivered to default queue */
	pkt = create_packet(pool_default, false, &seq, false);
	seqno = cls_pkt_get_seq(pkt);
	CU_ASSERT(seqno != TEST_SEQ_INVALID);

	enqueue_pktio_interface(pkt, pktio);

	pkt = receive_packet(&retqueue, ODP_TIME_SEC_IN_NS);
	CU_ASSERT(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(seqno == cls_pkt_get_seq(pkt));
	CU_ASSERT(retqueue == defqueue);

	odp_cos_destroy(cos);
	odp_pmr_destroy(pmr);
	odp_packet_free(pkt);
	destroy_inq(pktio);
	odp_queue_destroy(queue);
	odp_pktio_close(pktio);
}

odp_testinfo_t classification_suite_pmr[] = {
	ODP_TEST_INFO(classification_test_pmr_term_tcp_dport),
	ODP_TEST_INFO(classification_test_pmr_term_tcp_sport),
	ODP_TEST_INFO(classification_test_pmr_term_udp_dport),
	ODP_TEST_INFO(classification_test_pmr_term_udp_sport),
	ODP_TEST_INFO(classification_test_pmr_term_ipproto),
	ODP_TEST_INFO_NULL,
};

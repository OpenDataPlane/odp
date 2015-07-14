/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp_classification_testsuites.h"
#include <odp_cunit_common.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>

#define SHM_PKT_NUM_BUFS        32
#define SHM_PKT_BUF_SIZE        1024

/* Config values for Default CoS */
#define TEST_DEFAULT		1
#define	CLS_DEFAULT		0
#define CLS_DEFAULT_SADDR	"10.0.0.1/32"
#define CLS_DEFAULT_DADDR	"10.0.0.100/32"
#define CLS_DEFAULT_SPORT	1024
#define CLS_DEFAULT_DPORT	2048

/* Config values for Error CoS */
#define TEST_ERROR		1
#define CLS_ERROR		1

/* Config values for PMR_CHAIN */
#define TEST_PMR_CHAIN		1
#define CLS_PMR_CHAIN_SRC	2
#define CLS_PMR_CHAIN_DST	3
#define CLS_PMR_CHAIN_SADDR	"10.0.0.5/32"
#define CLS_PMR_CHAIN_SPORT	3000

/* Config values for PMR */
#define TEST_PMR		1
#define CLS_PMR			4
#define CLS_PMR_SPORT		4000

/* Config values for PMR SET */
#define TEST_PMR_SET		1
#define CLS_PMR_SET		5
#define CLS_PMR_SET_SADDR	"10.0.0.6/32"
#define CLS_PMR_SET_SPORT	5000

/* Config values for CoS L2 Priority */
#define TEST_L2_QOS		1
#define CLS_L2_QOS_0		6
#define CLS_L2_QOS_MAX		5

#define CLS_ENTRIES		(CLS_L2_QOS_0 + CLS_L2_QOS_MAX)

/* Test Packet values */
#define DATA_MAGIC		0x01020304
#define TEST_SEQ_INVALID	((uint32_t)~0)

static odp_cos_t cos_list[CLS_ENTRIES];
static odp_pmr_t pmr_list[CLS_ENTRIES];
static odp_queue_t queue_list[CLS_ENTRIES];
static odp_pmr_set_t pmr_set;

static odp_pool_t pool_default;
static odp_pktio_t pktio_loop;

/** sequence number of IP packets */
odp_atomic_u32_t seq;

typedef struct cls_test_packet {
	uint32be_t magic;
	uint32be_t seq;
} cls_test_packet_t;

static inline
int parse_ipv4_string(const char *ipaddress, uint32_t *addr, uint32_t *mask)
{
	int b[4];
	int qualifier = 32;
	int converted;

	if (strchr(ipaddress, '/')) {
		converted = sscanf(ipaddress, "%d.%d.%d.%d/%d",
				&b[3], &b[2], &b[1], &b[0],
				&qualifier);
		if (5 != converted)
			return -1;
	} else {
		converted = sscanf(ipaddress, "%d.%d.%d.%d",
				&b[3], &b[2], &b[1], &b[0]);
		if (4 != converted)
			return -1;
	}

	if ((b[0] > 255) || (b[1] > 255) || (b[2] > 255) || (b[3] > 255))
		return -1;
	if (!qualifier || (qualifier > 32))
		return -1;

	*addr = b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
	if (mask)
		*mask = ~(0xFFFFFFFF & ((1ULL << (32 - qualifier)) - 1));

	return 0;
}

static inline
void enqueue_loop_interface(odp_packet_t pkt)
{
	odp_event_t ev;
	odp_queue_t defqueue = odp_pktio_outq_getdef(pktio_loop);

	ev = odp_packet_to_event(pkt);
	CU_ASSERT(odp_queue_enq(defqueue, ev) == 0);
}

static inline
odp_packet_t receive_packet(odp_queue_t *queue, uint64_t ns)
{
	odp_event_t ev;

	ev = odp_schedule(queue, ns);
	return odp_packet_from_event(ev);
}

static int cls_pkt_set_seq(odp_packet_t pkt)
{
	static uint32_t seq;
	cls_test_packet_t data;
	uint32_t offset;
	int status;

	data.magic = DATA_MAGIC;
	data.seq = ++seq;

	offset = odp_packet_l4_offset(pkt);
	CU_ASSERT_FATAL(offset != 0);

	status = odp_packet_copydata_in(pkt, offset + ODPH_UDPHDR_LEN,
					sizeof(data), &data);

	return status;
}

static uint32_t cls_pkt_get_seq(odp_packet_t pkt)
{
	uint32_t offset;
	cls_test_packet_t data;

	offset = odp_packet_l4_offset(pkt);
	if (offset) {
		odp_packet_copydata_out(pkt, offset + ODPH_UDPHDR_LEN,
					sizeof(data), &data);

		if (data.magic == DATA_MAGIC)
			return data.seq;
	}

	return TEST_SEQ_INVALID;
}

static int destroy_inq(odp_pktio_t pktio)
{
	odp_queue_t inq;
	odp_event_t ev;

	inq = odp_pktio_inq_getdef(pktio);

	if (inq == ODP_QUEUE_INVALID) {
		CU_FAIL("attempting to destroy invalid inq");
		return -1;
	}

	if (0 > odp_pktio_inq_remdef(pktio))
		return -1;

	while (1) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev != ODP_EVENT_INVALID)
			odp_buffer_free(odp_buffer_from_event(ev));
		else
			break;
	}

	return odp_queue_destroy(inq);
}
odp_packet_t create_packet(bool vlan)
{
	uint32_t seqno;
	odph_ethhdr_t *ethhdr;
	odph_udphdr_t *udp;
	odph_ipv4hdr_t *ip;
	uint8_t payload_len;
	char src_mac[ODPH_ETHADDR_LEN]  = {0};
	char dst_mac[ODPH_ETHADDR_LEN] = {0};
	uint32_t addr = 0;
	uint32_t mask;
	int offset;
	odp_packet_t pkt;
	int packet_len = 0;

	payload_len = sizeof(cls_test_packet_t);
	packet_len += ODPH_ETHHDR_LEN;
	packet_len += ODPH_IPV4HDR_LEN;
	packet_len += ODPH_UDPHDR_LEN;
	packet_len += payload_len;

	if (vlan)
		packet_len += ODPH_VLANHDR_LEN;

	pkt = odp_packet_alloc(pool_default, packet_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	/* Ethernet Header */
	offset = 0;
	odp_packet_l2_offset_set(pkt, offset);
	ethhdr = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	memcpy(ethhdr->src.addr, src_mac, ODPH_ETHADDR_LEN);
	memcpy(ethhdr->dst.addr, dst_mac, ODPH_ETHADDR_LEN);
	offset += sizeof(odph_ethhdr_t);
	if (vlan) {
		/* Default vlan header */
		uint8_t *parseptr;
		odph_vlanhdr_t *vlan = (odph_vlanhdr_t *)(&ethhdr->type);
		parseptr = (uint8_t *)vlan;
		vlan->tci = odp_cpu_to_be_16(0);
		vlan->tpid = odp_cpu_to_be_16(ODPH_ETHTYPE_VLAN);
		offset += sizeof(odph_vlanhdr_t);
		parseptr += sizeof(odph_vlanhdr_t);
		uint16be_t *type = (uint16be_t *)(void *)parseptr;
		*type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);
	} else {
		ethhdr->type =	odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);
	}

	odp_packet_l3_offset_set(pkt, offset);

	/* ipv4 */
	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);

	parse_ipv4_string(CLS_DEFAULT_SADDR, &addr, &mask);
	ip->dst_addr = odp_cpu_to_be_32(addr);

	parse_ipv4_string(CLS_DEFAULT_DADDR, &addr, &mask);
	ip->src_addr = odp_cpu_to_be_32(addr);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(ODPH_UDPHDR_LEN + payload_len +
			ODPH_IPV4HDR_LEN);
	ip->ttl = 128;
	ip->proto = ODPH_IPPROTO_UDP;
	seqno = odp_atomic_fetch_inc_u32(&seq);
	ip->id = odp_cpu_to_be_16(seqno);
	ip->chksum = 0;
	ip->chksum = odp_cpu_to_be_16(odph_ipv4_csum_update(pkt));
	offset += ODPH_IPV4HDR_LEN;

	/* udp */
	odp_packet_l4_offset_set(pkt, offset);
	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT);
	udp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);
	udp->length = odp_cpu_to_be_16(payload_len + ODPH_UDPHDR_LEN);
	udp->chksum = 0;

	/* set pkt sequence number */
	cls_pkt_set_seq(pkt);

	return pkt;
}

int classification_suite_init(void)
{
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_queue_t inq_def;
	odp_queue_param_t qparam;
	char queuename[ODP_QUEUE_NAME_LEN];
	int i;
	int ret;

	memset(&param, 0, sizeof(param));
	param.pkt.seg_len = SHM_PKT_BUF_SIZE;
	param.pkt.len     = SHM_PKT_BUF_SIZE;
	param.pkt.num     = SHM_PKT_NUM_BUFS;
	param.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("classification_pool",
				      ODP_SHM_NULL, &param);
	if (ODP_POOL_INVALID == pool) {
		fprintf(stderr, "Packet pool creation failed.\n");
		return -1;
	}

	pool_default = odp_pool_lookup("classification_pool");
	if (pool_default == ODP_POOL_INVALID)
		return -1;

	pktio_loop = odp_pktio_open("loop", pool_default);
	if (pktio_loop == ODP_PKTIO_INVALID) {
		ret = odp_pool_destroy(pool_default);
		if (ret)
			fprintf(stderr, "unable to destroy pool.\n");
		return -1;
	}
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;

	sprintf(queuename, "%s", "inq_loop");
	inq_def = odp_queue_create(queuename,
			ODP_QUEUE_TYPE_PKTIN, &qparam);
	odp_pktio_inq_setdef(pktio_loop, inq_def);

	for (i = 0; i < CLS_ENTRIES; i++)
		cos_list[i] = ODP_COS_INVALID;

	for (i = 0; i < CLS_ENTRIES; i++)
		pmr_list[i] = ODP_PMR_INVAL;

	for (i = 0; i < CLS_ENTRIES; i++)
		queue_list[i] = ODP_QUEUE_INVALID;

	odp_atomic_init_u32(&seq, 0);
	return 0;
}

int classification_suite_term(void)
{
	int i;
	int retcode = 0;

	if (0 >	destroy_inq(pktio_loop)) {
		fprintf(stderr, "destroy pktio inq failed.\n");
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

	for (i = 0; i < CLS_ENTRIES; i++)
		odp_cos_destroy(cos_list[i]);

	for (i = 0; i < CLS_ENTRIES; i++)
		odp_pmr_destroy(pmr_list[i]);

	for (i = 0; i < CLS_ENTRIES; i++)
		odp_queue_destroy(queue_list[i]);

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
	int retval;
	char cosname[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	char queuename[ODP_QUEUE_NAME_LEN];
	uint32_t addr;
	uint32_t mask;

	sprintf(cosname, "SrcCos");
	cos_list[CLS_PMR_CHAIN_SRC] = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos_list[CLS_PMR_CHAIN_SRC] != ODP_COS_INVALID)

	qparam.sched.prio = ODP_SCHED_PRIO_NORMAL;
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "SrcQueue");

	queue_list[CLS_PMR_CHAIN_SRC] = odp_queue_create(queuename,
						     ODP_QUEUE_TYPE_SCHED,
						     &qparam);

	CU_ASSERT_FATAL(queue_list[CLS_PMR_CHAIN_SRC] != ODP_QUEUE_INVALID);
	retval = odp_cos_set_queue(cos_list[CLS_PMR_CHAIN_SRC],
				   queue_list[CLS_PMR_CHAIN_SRC]);
	CU_ASSERT(retval == 0);

	sprintf(cosname, "DstCos");
	cos_list[CLS_PMR_CHAIN_DST] = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos_list[CLS_PMR_CHAIN_DST] != ODP_COS_INVALID);

	qparam.sched.prio = ODP_SCHED_PRIO_NORMAL;
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "DstQueue");

	queue_list[CLS_PMR_CHAIN_DST] = odp_queue_create(queuename,
						     ODP_QUEUE_TYPE_SCHED,
						     &qparam);
	CU_ASSERT_FATAL(queue_list[CLS_PMR_CHAIN_DST] != ODP_QUEUE_INVALID);

	retval = odp_cos_set_queue(cos_list[CLS_PMR_CHAIN_DST],
				   queue_list[CLS_PMR_CHAIN_DST]);

	parse_ipv4_string(CLS_PMR_CHAIN_SADDR, &addr, &mask);
	pmr_list[CLS_PMR_CHAIN_SRC] = odp_pmr_create(ODP_PMR_SIP_ADDR, &addr,
						     &mask, sizeof(addr));
	CU_ASSERT_FATAL(pmr_list[CLS_PMR_CHAIN_SRC] != ODP_PMR_INVAL);

	val = CLS_PMR_CHAIN_SPORT;
	maskport = 0xffff;
	pmr_list[CLS_PMR_CHAIN_DST] = odp_pmr_create(ODP_PMR_UDP_SPORT, &val,
						     &maskport, sizeof(val));
	CU_ASSERT_FATAL(pmr_list[CLS_PMR_CHAIN_DST] != ODP_PMR_INVAL);

	retval = odp_pktio_pmr_cos(pmr_list[CLS_PMR_CHAIN_SRC], pktio_loop,
				   cos_list[CLS_PMR_CHAIN_SRC]);
	CU_ASSERT(retval == 0);

	retval = odp_cos_pmr_cos(pmr_list[CLS_PMR_CHAIN_DST],
				 cos_list[CLS_PMR_CHAIN_SRC],
				 cos_list[CLS_PMR_CHAIN_DST]);
	CU_ASSERT(retval == 0);
}

void test_cls_pmr_chain(void)
{
	odp_packet_t pkt;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	odp_queue_t queue;
	uint32_t addr = 0;
	uint32_t mask;
	uint32_t seq;

	pkt = create_packet(false);
	seq = cls_pkt_get_seq(pkt);
	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	parse_ipv4_string(CLS_PMR_CHAIN_SADDR, &addr, &mask);
	ip->src_addr = odp_cpu_to_be_32(addr);
	ip->chksum = 0;
	ip->chksum = odp_cpu_to_be_16(odph_ipv4_csum_update(pkt));

	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->src_port = odp_cpu_to_be_16(CLS_PMR_CHAIN_SPORT);

	enqueue_loop_interface(pkt);

	pkt = receive_packet(&queue, ODP_TIME_SEC);
	CU_ASSERT(queue == queue_list[CLS_PMR_CHAIN_DST]);
	CU_ASSERT(seq == cls_pkt_get_seq(pkt));
	odp_packet_free(pkt);

	pkt = create_packet(false);
	seq = cls_pkt_get_seq(pkt);
	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	parse_ipv4_string(CLS_PMR_CHAIN_SADDR, &addr, &mask);
	ip->src_addr = odp_cpu_to_be_32(addr);
	ip->chksum = 0;
	ip->chksum = odp_cpu_to_be_16(odph_ipv4_csum_update(pkt));

	enqueue_loop_interface(pkt);
	pkt = receive_packet(&queue, ODP_TIME_SEC);
	CU_ASSERT(queue == queue_list[CLS_PMR_CHAIN_SRC]);
	CU_ASSERT(seq == cls_pkt_get_seq(pkt));
	odp_packet_free(pkt);
}

void configure_pktio_default_cos(void)
{
	int retval;
	odp_queue_param_t qparam;
	char cosname[ODP_COS_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];

	sprintf(cosname, "DefaultCoS");
	cos_list[CLS_DEFAULT] = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos_list[CLS_DEFAULT] != ODP_COS_INVALID);

	qparam.sched.prio = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "DefaultQueue");
	queue_list[CLS_DEFAULT] = odp_queue_create(queuename,
					 ODP_QUEUE_TYPE_SCHED, &qparam);
	CU_ASSERT_FATAL(queue_list[CLS_DEFAULT] != ODP_QUEUE_INVALID);

	retval = odp_cos_set_queue(cos_list[CLS_DEFAULT],
				   queue_list[CLS_DEFAULT]);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_default_cos_set(pktio_loop, cos_list[CLS_DEFAULT]);
	CU_ASSERT(retval == 0);
}

void test_pktio_default_cos(void)
{
	odp_packet_t pkt;
	odp_queue_t queue;
	uint32_t seq;
	/* create a default packet */
	pkt = create_packet(false);
	seq = cls_pkt_get_seq(pkt);
	enqueue_loop_interface(pkt);

	pkt = receive_packet(&queue, ODP_TIME_SEC);
	/* Default packet should be received in default queue */
	CU_ASSERT(queue == queue_list[CLS_DEFAULT]);
	CU_ASSERT(seq == cls_pkt_get_seq(pkt));

	odp_packet_free(pkt);
}

void configure_pktio_error_cos(void)
{
	int retval;
	odp_queue_param_t qparam;
	char queuename[ODP_QUEUE_NAME_LEN];
	char cosname[ODP_COS_NAME_LEN];

	qparam.sched.prio = ODP_SCHED_PRIO_LOWEST;
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "ErrorCos");

	queue_list[CLS_ERROR] = odp_queue_create(queuename,
						 ODP_QUEUE_TYPE_SCHED,
						 &qparam);
	CU_ASSERT_FATAL(queue_list[CLS_ERROR] != ODP_QUEUE_INVALID);

	sprintf(cosname, "%s", "ErrorCos");
	cos_list[CLS_ERROR] = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos_list[CLS_ERROR] != ODP_COS_INVALID);

	retval = odp_cos_set_queue(cos_list[CLS_ERROR], queue_list[CLS_ERROR]);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_error_cos_set(pktio_loop, cos_list[CLS_ERROR]);
	CU_ASSERT(retval == 0);
}

void test_pktio_error_cos(void)
{
	odp_queue_t queue;
	odp_packet_t pkt;

	/*Create an error packet */
	pkt = create_packet(false);
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);

	/* Incorrect IpV4 version */
	ip->ver_ihl = 8 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->chksum = 0;
	enqueue_loop_interface(pkt);

	pkt = receive_packet(&queue, ODP_TIME_SEC);
	/* Error packet should be received in error queue */
	CU_ASSERT(queue == queue_list[CLS_ERROR]);
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
	uint8_t qos_tbl[CLS_L2_QOS_MAX];
	char cosname[ODP_COS_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	int retval;
	int i;
	odp_queue_param_t qparam;

	/** Initialize scalar variable qos_tbl **/
	for (i = 0; i < CLS_L2_QOS_MAX; i++)
		qos_tbl[i] = 0;

	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	for (i = 0; i < num_qos; i++) {
		qparam.sched.prio = ODP_SCHED_PRIO_LOWEST - i;
		sprintf(cosname, "%s_%d", "L2_Cos", i);
		cos_tbl[i] = odp_cos_create(cosname);
		if (cos_tbl[i] == ODP_COS_INVALID)
			break;

		cos_list[CLS_L2_QOS_0 + i] = cos_tbl[i];
		sprintf(queuename, "%s_%d", "L2_Queue", i);
		queue_tbl[i] = odp_queue_create(queuename, ODP_QUEUE_TYPE_SCHED,
					      &qparam);
		CU_ASSERT_FATAL(queue_tbl[i] != ODP_QUEUE_INVALID);
		queue_list[CLS_L2_QOS_0 + i] = queue_tbl[i];
		retval = odp_cos_set_queue(cos_tbl[i], queue_tbl[i]);
		CU_ASSERT(retval == 0);
		qos_tbl[i] = i;
	}
	/* count 'i' is passed instead of num_qos to handle the rare scenario
	if the odp_cos_create() failed in the middle*/
	retval = odp_cos_with_l2_priority(pktio_loop, i, qos_tbl, cos_tbl);
	CU_ASSERT(retval == 0);
}

void test_cos_with_l2_priority(void)
{
	odp_packet_t pkt;
	odph_ethhdr_t *ethhdr;
	odph_vlanhdr_t *vlan;
	odp_queue_t queue;
	uint32_t seq;

	uint8_t i;
	for (i = 0; i < CLS_L2_QOS_MAX; i++) {
		pkt = create_packet(true);
		seq = cls_pkt_get_seq(pkt);
		ethhdr = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
		vlan = (odph_vlanhdr_t *)(&ethhdr->type);
		vlan->tci = odp_cpu_to_be_16(i << 13);
		enqueue_loop_interface(pkt);
		pkt = receive_packet(&queue, ODP_TIME_SEC);
		CU_ASSERT(queue == queue_list[CLS_L2_QOS_0 + i]);
		CU_ASSERT(seq == cls_pkt_get_seq(pkt));
		odp_packet_free(pkt);
	}
}

void configure_pmr_cos(void)
{
	uint16_t val;
	uint16_t mask;
	int retval;
	val = CLS_PMR_SPORT;
	mask = 0xffff;
	odp_queue_param_t qparam;
	char cosname[ODP_COS_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];

	pmr_list[CLS_PMR] = odp_pmr_create(ODP_PMR_UDP_SPORT, &val,
					   &mask, sizeof(val));
	CU_ASSERT(pmr_list[CLS_PMR] != ODP_PMR_INVAL);

	sprintf(cosname, "PMR_CoS");
	cos_list[CLS_PMR] = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos_list[CLS_PMR] != ODP_COS_INVALID);

	qparam.sched.prio = ODP_SCHED_PRIO_HIGHEST;
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "PMR_CoS");

	queue_list[CLS_PMR] = odp_queue_create(queuename,
					       ODP_QUEUE_TYPE_SCHED,
					       &qparam);
	CU_ASSERT_FATAL(queue_list[CLS_PMR] != ODP_QUEUE_INVALID);

	retval = odp_cos_set_queue(cos_list[CLS_PMR],
				   queue_list[CLS_PMR]);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_pmr_cos(pmr_list[CLS_PMR], pktio_loop,
				   cos_list[CLS_PMR]);
	CU_ASSERT(retval == 0);
}

void test_pmr_cos(void)
{
	odp_packet_t pkt;
	odph_udphdr_t *udp;
	odp_queue_t queue;
	uint32_t seq;

	pkt = create_packet(false);
	seq = cls_pkt_get_seq(pkt);
	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->src_port = odp_cpu_to_be_16(CLS_PMR_SPORT);
	enqueue_loop_interface(pkt);
	pkt = receive_packet(&queue, ODP_TIME_SEC);
	CU_ASSERT(queue == queue_list[CLS_PMR]);
	CU_ASSERT(seq == cls_pkt_get_seq(pkt));
	odp_packet_free(pkt);
}

void configure_pktio_pmr_match_set_cos(void)
{
	int retval;
	odp_pmr_match_t pmr_terms[2];
	uint16_t val;
	uint16_t maskport;
	int num_terms = 2; /* one pmr for each L3 and L4 */
	odp_queue_param_t qparam;
	char cosname[ODP_COS_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	uint32_t addr = 0;
	uint32_t mask;

	parse_ipv4_string(CLS_PMR_SET_SADDR, &addr, &mask);
	pmr_terms[0].term = ODP_PMR_SIP_ADDR;
	pmr_terms[0].val = &addr;
	pmr_terms[0].mask = &mask;
	pmr_terms[0].val_sz = sizeof(addr);


	val = CLS_PMR_SET_SPORT;
	maskport = 0xffff;
	pmr_terms[1].term = ODP_PMR_UDP_SPORT;
	pmr_terms[1].val = &val;
	pmr_terms[1].mask = &maskport;
	pmr_terms[1].val_sz = sizeof(val);

	retval = odp_pmr_match_set_create(num_terms, pmr_terms, &pmr_set);
	CU_ASSERT(retval > 0);

	sprintf(cosname, "cos_pmr_set");
	cos_list[CLS_PMR_SET] = odp_cos_create(cosname);
	CU_ASSERT_FATAL(cos_list[CLS_PMR_SET] != ODP_COS_INVALID)

	qparam.sched.prio = ODP_SCHED_PRIO_HIGHEST;
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	sprintf(queuename, "%s", "cos_pmr_set_queue");

	queue_list[CLS_PMR_SET] = odp_queue_create(queuename,
							 ODP_QUEUE_TYPE_SCHED,
							 &qparam);
	CU_ASSERT_FATAL(queue_list[CLS_PMR_SET] != ODP_QUEUE_INVALID);

	retval = odp_cos_set_queue(cos_list[CLS_PMR_SET],
				   queue_list[CLS_PMR_SET]);
	CU_ASSERT(retval == 0);

	retval = odp_pktio_pmr_match_set_cos(pmr_set, pktio_loop,
					     cos_list[CLS_PMR_SET]);
	CU_ASSERT(retval == 0);
}

void test_pktio_pmr_match_set_cos(void)
{
	uint32_t addr = 0;
	uint32_t mask;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	odp_packet_t pkt;
	odp_queue_t queue;
	uint32_t seq;

	pkt = create_packet(false);
	seq = cls_pkt_get_seq(pkt);
	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	parse_ipv4_string(CLS_PMR_SET_SADDR, &addr, &mask);
	ip->src_addr = odp_cpu_to_be_32(addr);
	ip->chksum = 0;
	ip->chksum = odp_cpu_to_be_16(odph_ipv4_csum_update(pkt));

	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	udp->src_port = odp_cpu_to_be_16(CLS_PMR_SET_SPORT);
	enqueue_loop_interface(pkt);
	pkt = receive_packet(&queue, ODP_TIME_SEC);
	CU_ASSERT(queue == queue_list[CLS_PMR_SET]);
	CU_ASSERT(seq == cls_pkt_get_seq(pkt));
	odp_packet_free(pkt);
}

static void classification_test_pmr_terms_avail(void)
{
	int retval;
	/* Since this API called at the start of the suite the return value
	should be greater than 0 */
	retval = odp_pmr_terms_avail();
	CU_ASSERT(retval > 0);
}

static void classification_test_pmr_terms_cap(void)
{
	unsigned long long retval;
	/* Need to check different values for different platforms */
	retval = odp_pmr_terms_cap();
	CU_ASSERT(retval & (1 << ODP_PMR_IPPROTO));
}

static void classification_test_pktio_configure(void)
{
	/* Configure the Different CoS for the pktio interface */
	if (TEST_DEFAULT)
		configure_pktio_default_cos();
	if (TEST_ERROR)
		configure_pktio_error_cos();
	if (TEST_PMR_CHAIN)
		configure_cls_pmr_chain();
	if (TEST_L2_QOS)
		configure_cos_with_l2_priority();
	if (TEST_PMR)
		configure_pmr_cos();
	if (TEST_PMR_SET)
		configure_pktio_pmr_match_set_cos();
}

static void classification_test_pktio_test(void)
{
	/* Test Different CoS on the pktio interface */
	if (TEST_DEFAULT)
		test_pktio_default_cos();
	if (TEST_ERROR)
		test_pktio_error_cos();
	if (TEST_PMR_CHAIN)
		test_cls_pmr_chain();
	if (TEST_L2_QOS)
		test_cos_with_l2_priority();
	if (TEST_PMR)
		test_pmr_cos();
	if (TEST_PMR_SET)
		test_pktio_pmr_match_set_cos();
}

CU_TestInfo classification_suite[] = {
	_CU_TEST_INFO(classification_test_pmr_terms_avail),
	_CU_TEST_INFO(classification_test_pktio_set_skip),
	_CU_TEST_INFO(classification_test_pktio_set_headroom),
	_CU_TEST_INFO(classification_test_pmr_terms_cap),
	_CU_TEST_INFO(classification_test_pktio_configure),
	_CU_TEST_INFO(classification_test_pktio_test),
	CU_TEST_INFO_NULL,
};

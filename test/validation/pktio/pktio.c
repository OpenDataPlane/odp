/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <odp.h>
#include <odp_cunit_common.h>

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>

#include <stdlib.h>
#include "pktio.h"

#define PKT_BUF_NUM            32
#define PKT_BUF_SIZE           (9 * 1024)
#define PKT_LEN_NORMAL         64
#define PKT_LEN_JUMBO          (PKT_BUF_SIZE - ODPH_ETHHDR_LEN - \
				ODPH_IPV4HDR_LEN - ODPH_UDPHDR_LEN)
#define MAX_NUM_IFACES         2
#define TEST_SEQ_INVALID       ((uint32_t)~0)
#define TEST_SEQ_MAGIC         0x92749451
#define TX_BATCH_LEN           4

/** interface names used for testing */
static const char *iface_name[MAX_NUM_IFACES];

/** number of interfaces being used (1=loopback, 2=pair) */
static int num_ifaces;

/** local container for pktio attributes */
typedef struct {
	const char *name;
	odp_pktio_t id;
	odp_queue_t outq;
	odp_queue_t inq;
	odp_pktio_input_mode_t in_mode;
} pktio_info_t;

/** magic number and sequence at start of UDP payload */
typedef struct ODP_PACKED {
	uint32be_t magic;
	uint32be_t seq;
} pkt_head_t;

/** magic number at end of UDP payload */
typedef struct ODP_PACKED {
	uint32be_t magic;
} pkt_tail_t;

/** Run mode */
typedef enum {
	PKT_POOL_UNSEGMENTED,
	PKT_POOL_SEGMENTED,
} pkt_segmented_e
;
/** size of transmitted packets */
static uint32_t packet_len = PKT_LEN_NORMAL;

/** default packet pool */
odp_pool_t default_pkt_pool = ODP_POOL_INVALID;

/** sequence number of IP packets */
odp_atomic_u32_t ip_seq;

/** Type of pool segmentation */
pkt_segmented_e pool_segmentation = PKT_POOL_UNSEGMENTED;

odp_pool_t pool[MAX_NUM_IFACES] = {ODP_POOL_INVALID, ODP_POOL_INVALID};

static void set_pool_len(odp_pool_param_t *params)
{
	switch (pool_segmentation) {
	case PKT_POOL_SEGMENTED:
		/* Force segment to minimum size */
		params->pkt.seg_len = 0;
		params->pkt.len = PKT_BUF_SIZE;
		break;
	case PKT_POOL_UNSEGMENTED:
	default:
		params->pkt.seg_len = PKT_BUF_SIZE;
		params->pkt.len = PKT_BUF_SIZE;
		break;
	}
}

static void pktio_pkt_set_macs(odp_packet_t pkt,
			       pktio_info_t *src, pktio_info_t *dst)
{
	uint32_t len;
	odph_ethhdr_t *eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, &len);
	int ret;

	ret = odp_pktio_mac_addr(src->id, &eth->src, sizeof(eth->src));
	CU_ASSERT(ret == ODPH_ETHADDR_LEN);

	ret = odp_pktio_mac_addr(dst->id, &eth->dst, sizeof(eth->dst));
	CU_ASSERT(ret == ODPH_ETHADDR_LEN);
}

static uint32_t pktio_pkt_set_seq(odp_packet_t pkt)
{
	static uint32_t tstseq;
	size_t off;
	pkt_head_t head;
	pkt_tail_t tail;

	off = odp_packet_l4_offset(pkt);
	if (off == ODP_PACKET_OFFSET_INVALID) {
		CU_FAIL("packet L4 offset not set");
		return TEST_SEQ_INVALID;
	}

	head.magic = TEST_SEQ_MAGIC;
	head.seq   = tstseq;

	off += ODPH_UDPHDR_LEN;
	if (odp_packet_copydata_in(pkt, off, sizeof(head), &head) != 0)
		return TEST_SEQ_INVALID;

	tail.magic = TEST_SEQ_MAGIC;
	off = odp_packet_len(pkt) - sizeof(pkt_tail_t);
	if (odp_packet_copydata_in(pkt, off, sizeof(tail), &tail) != 0)
		return TEST_SEQ_INVALID;

	tstseq++;

	return head.seq;
}

static uint32_t pktio_pkt_seq(odp_packet_t pkt)
{
	size_t off;
	uint32_t seq = TEST_SEQ_INVALID;
	pkt_head_t head;
	pkt_tail_t tail;

	if (pkt == ODP_PACKET_INVALID)
		return -1;

	off = odp_packet_l4_offset(pkt);
	if (off ==  ODP_PACKET_OFFSET_INVALID)
		return TEST_SEQ_INVALID;

	off += ODPH_UDPHDR_LEN;
	if (odp_packet_copydata_out(pkt, off, sizeof(head), &head) != 0)
		return TEST_SEQ_INVALID;

	if (head.magic != TEST_SEQ_MAGIC)
		return TEST_SEQ_INVALID;

	if (odp_packet_len(pkt) == packet_len) {
		off = packet_len - sizeof(tail);
		if (odp_packet_copydata_out(pkt, off, sizeof(tail), &tail) != 0)
			return TEST_SEQ_INVALID;

		if (tail.magic == TEST_SEQ_MAGIC)
			seq = head.seq;
	}

	return seq;
}

static uint32_t pktio_init_packet(odp_packet_t pkt)
{
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	char *buf;
	uint16_t seq;
	uint8_t mac[ODPH_ETHADDR_LEN] = {0};
	int pkt_len = odp_packet_len(pkt);

	buf = odp_packet_data(pkt);

	/* Ethernet */
	odp_packet_l2_offset_set(pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy(eth->src.addr, mac, ODPH_ETHADDR_LEN);
	memcpy(eth->dst.addr, mac, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	/* IP */
	odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(0x0a000064);
	ip->src_addr = odp_cpu_to_be_32(0x0a000001);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(pkt_len - ODPH_ETHHDR_LEN);
	ip->ttl = 128;
	ip->proto = ODPH_IPPROTO_UDP;
	seq = odp_atomic_fetch_inc_u32(&ip_seq);
	ip->id = odp_cpu_to_be_16(seq);
	ip->chksum = 0;
	odph_ipv4_csum_update(pkt);

	/* UDP */
	odp_packet_l4_offset_set(pkt, ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp = (odph_udphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp->src_port = odp_cpu_to_be_16(12049);
	udp->dst_port = odp_cpu_to_be_16(12050);
	udp->length = odp_cpu_to_be_16(pkt_len -
				       ODPH_ETHHDR_LEN - ODPH_IPV4HDR_LEN);
	udp->chksum = 0;

	return pktio_pkt_set_seq(pkt);
}

static int pktio_fixup_checksums(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	uint32_t len;

	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, &len);

	if (ip->proto != ODPH_IPPROTO_UDP) {
		CU_FAIL("unexpected L4 protocol");
		return -1;
	}

	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, &len);

	ip->chksum = 0;
	odph_ipv4_csum_update(pkt);
	udp->chksum = 0;
	udp->chksum = odp_cpu_to_be_16(odph_ipv4_udp_chksum(pkt));

	return 0;
}

static int default_pool_create(void)
{
	odp_pool_param_t params;
	char pool_name[ODP_POOL_NAME_LEN];

	if (default_pkt_pool != ODP_POOL_INVALID)
		return -1;

	memset(&params, 0, sizeof(params));
	set_pool_len(&params);
	params.pkt.num     = PKT_BUF_NUM;
	params.type        = ODP_POOL_PACKET;

	snprintf(pool_name, sizeof(pool_name),
		 "pkt_pool_default_%d", pool_segmentation);
	default_pkt_pool = odp_pool_create(pool_name, &params);
	if (default_pkt_pool == ODP_POOL_INVALID)
		return -1;

	return 0;
}

static odp_pktio_t create_pktio(int iface_idx, odp_pktio_input_mode_t imode,
				odp_pktio_output_mode_t omode)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	const char *iface = iface_name[iface_idx];

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = imode;
	pktio_param.out_mode = omode;

	pktio = odp_pktio_open(iface, pool[iface_idx], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		pktio = odp_pktio_lookup(iface);
	CU_ASSERT(pktio != ODP_PKTIO_INVALID);
	CU_ASSERT(odp_pktio_to_u64(pktio) !=
		  odp_pktio_to_u64(ODP_PKTIO_INVALID));
	/* Print pktio debug info and test that the odp_pktio_print() function
	 * is implemented. */
	if (pktio != ODP_PKTIO_INVALID)
		odp_pktio_print(pktio);

	return pktio;
}

static int create_inq(odp_pktio_t pktio, odp_queue_type_t qtype)
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

	return odp_pktio_inq_setdef(pktio, inq_def);
}

static int destroy_inq(odp_pktio_t pktio)
{
	odp_queue_t inq;
	odp_event_t ev;
	odp_queue_type_t q_type;

	inq = odp_pktio_inq_getdef(pktio);

	if (inq == ODP_QUEUE_INVALID) {
		CU_FAIL("attempting to destroy invalid inq");
		return -1;
	}

	CU_ASSERT(odp_pktio_inq_remdef(pktio) == 0);

	q_type = odp_queue_type(inq);

	/* flush any pending events */
	while (1) {
		if (q_type == ODP_QUEUE_TYPE_POLL)
			ev = odp_queue_deq(inq);
		else
			ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev != ODP_EVENT_INVALID)
			odp_event_free(ev);
		else
			break;
	}

	return odp_queue_destroy(inq);
}

static odp_event_t queue_deq_wait_time(odp_queue_t queue, uint64_t ns)
{
	odp_time_t wait, end;
	odp_event_t ev;

	wait = odp_time_local_from_ns(ns);
	end = odp_time_sum(odp_time_local(), wait);
	do {
		ev = odp_queue_deq(queue);
		if (ev != ODP_EVENT_INVALID)
			return ev;
	} while (odp_time_cmp(end, odp_time_local()) > 0);

	return ODP_EVENT_INVALID;
}

static odp_packet_t wait_for_packet(pktio_info_t *pktio_rx,
				    uint32_t seq, uint64_t ns)
{
	odp_time_t wait_time, end;
	odp_event_t ev;
	odp_packet_t pkt;
	uint64_t wait;

	wait = odp_schedule_wait_time(ns);
	wait_time = odp_time_local_from_ns(ns);
	end = odp_time_sum(odp_time_local(), wait_time);
	do {
		pkt = ODP_PACKET_INVALID;

		if (pktio_rx->in_mode == ODP_PKTIN_MODE_RECV) {
			odp_pktio_recv(pktio_rx->id, &pkt, 1);
		} else {
			if (pktio_rx->in_mode == ODP_PKTIN_MODE_POLL)
				ev = queue_deq_wait_time(pktio_rx->inq, ns);
			else
				ev = odp_schedule(NULL, wait);

			if (ev != ODP_EVENT_INVALID) {
				if (odp_event_type(ev) == ODP_EVENT_PACKET)
					pkt = odp_packet_from_event(ev);
				else
					odp_event_free(ev);
			}
		}

		if (pkt != ODP_PACKET_INVALID) {
			if (pktio_pkt_seq(pkt) == seq)
				return pkt;

			odp_packet_free(pkt);
		}
	} while (odp_time_cmp(end, odp_time_local()) > 0);

	CU_FAIL("failed to receive transmitted packet");

	return ODP_PACKET_INVALID;
}

static void pktio_txrx_multi(pktio_info_t *pktio_a, pktio_info_t *pktio_b,
			     int num_pkts)
{
	odp_packet_t tx_pkt[num_pkts];
	odp_event_t tx_ev[num_pkts];
	odp_packet_t rx_pkt;
	uint32_t tx_seq[num_pkts];
	int i, ret;

	/* generate test packets to send */
	for (i = 0; i < num_pkts; ++i) {
		tx_pkt[i] = odp_packet_alloc(default_pkt_pool, packet_len);
		if (tx_pkt[i] == ODP_PACKET_INVALID)
			break;

		tx_seq[i] = pktio_init_packet(tx_pkt[i]);
		if (tx_seq[i] == TEST_SEQ_INVALID)
			break;

		pktio_pkt_set_macs(tx_pkt[i], pktio_a, pktio_b);
		if (pktio_fixup_checksums(tx_pkt[i]) != 0)
			break;

		tx_ev[i] = odp_packet_to_event(tx_pkt[i]);
	}

	if (i != num_pkts) {
		CU_FAIL("failed to generate test packets");
		return;
	}

	/* send packet(s) out */
	if (num_pkts == 1) {
		ret = odp_queue_enq(pktio_a->outq, tx_ev[0]);
		if (ret != 0) {
			CU_FAIL("failed to enqueue test packet");
			odp_packet_free(tx_pkt[0]);
			return;
		}
	} else {
		ret = odp_queue_enq_multi(pktio_a->outq, tx_ev, num_pkts);
		if (ret != num_pkts) {
			CU_FAIL("failed to enqueue test packets");
			i = ret < 0 ? 0 : ret;
			for ( ; i < num_pkts; i++)
				odp_packet_free(tx_pkt[i]);
			return;
		}
	}

	/* and wait for them to arrive back */
	for (i = 0; i < num_pkts; ++i) {
		rx_pkt = wait_for_packet(pktio_b, tx_seq[i],
					 ODP_TIME_SEC_IN_NS);

		if (rx_pkt == ODP_PACKET_INVALID)
			break;
		CU_ASSERT(odp_packet_input(rx_pkt) == pktio_b->id);
		CU_ASSERT(odp_packet_has_error(rx_pkt) == 0);
		odp_packet_free(rx_pkt);
	}

	CU_ASSERT(i == num_pkts);
}

static void test_txrx(odp_pktio_input_mode_t in_mode, int num_pkts)
{
	int ret, i, if_b;
	pktio_info_t pktios[MAX_NUM_IFACES];
	pktio_info_t *io;

	/* create pktios and associate input/output queues */
	for (i = 0; i < num_ifaces; ++i) {
		io = &pktios[i];

		io->name = iface_name[i];
		io->id   = create_pktio(i, in_mode, ODP_PKTOUT_MODE_SEND);
		if (io->id == ODP_PKTIO_INVALID) {
			CU_FAIL("failed to open iface");
			return;
		}
		io->outq = odp_pktio_outq_getdef(io->id);
		io->in_mode = in_mode;

		if (in_mode == ODP_PKTIN_MODE_POLL) {
			create_inq(io->id, ODP_QUEUE_TYPE_POLL);
			io->inq = odp_pktio_inq_getdef(io->id);
		} else if (in_mode == ODP_PKTIN_MODE_SCHED) {
			create_inq(io->id, ODP_QUEUE_TYPE_SCHED);
			io->inq = ODP_QUEUE_INVALID;
		}

		ret = odp_pktio_start(io->id);
		CU_ASSERT(ret == 0);
	}

	/* if we have two interfaces then send through one and receive on
	 * another but if there's only one assume it's a loopback */
	if_b = (num_ifaces == 1) ? 0 : 1;
	pktio_txrx_multi(&pktios[0], &pktios[if_b], num_pkts);

	for (i = 0; i < num_ifaces; ++i) {
		ret = odp_pktio_stop(pktios[i].id);
		CU_ASSERT(ret == 0);
		if (in_mode != ODP_PKTIN_MODE_RECV)
			destroy_inq(pktios[i].id);
		ret = odp_pktio_close(pktios[i].id);
		CU_ASSERT(ret == 0);
	}
}

void pktio_test_poll_queue(void)
{
	test_txrx(ODP_PKTIN_MODE_POLL, 1);
}

void pktio_test_poll_multi(void)
{
	test_txrx(ODP_PKTIN_MODE_POLL, TX_BATCH_LEN);
}

void pktio_test_sched_queue(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, 1);
}

void pktio_test_sched_multi(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, TX_BATCH_LEN);
}

void pktio_test_recv(void)
{
	test_txrx(ODP_PKTIN_MODE_RECV, 1);
}

void pktio_test_recv_multi(void)
{
	test_txrx(ODP_PKTIN_MODE_RECV, TX_BATCH_LEN);
}

void pktio_test_jumbo(void)
{
	packet_len = PKT_LEN_JUMBO;
	pktio_test_sched_multi();
	packet_len = PKT_LEN_NORMAL;
}

void pktio_test_mtu(void)
{
	int ret;
	int mtu;

	odp_pktio_t pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
					 ODP_PKTOUT_MODE_SEND);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	mtu = odp_pktio_mtu(pktio);
	CU_ASSERT(mtu > 0);

	printf(" %d ",  mtu);

	ret = odp_pktio_close(pktio);
	CU_ASSERT(ret == 0);
}

void pktio_test_promisc(void)
{
	int ret;

	odp_pktio_t pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
					 ODP_PKTOUT_MODE_SEND);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	ret = odp_pktio_promisc_mode_set(pktio, 1);
	CU_ASSERT(0 == ret);

	/* Verify that promisc mode set */
	ret = odp_pktio_promisc_mode(pktio);
	CU_ASSERT(1 == ret);

	ret = odp_pktio_promisc_mode_set(pktio, 0);
	CU_ASSERT(0 == ret);

	/* Verify that promisc mode is not set */
	ret = odp_pktio_promisc_mode(pktio);
	CU_ASSERT(0 == ret);

	ret = odp_pktio_close(pktio);
	CU_ASSERT(ret == 0);
}

void pktio_test_mac(void)
{
	unsigned char mac_addr[ODPH_ETHADDR_LEN];
	int mac_len;
	int ret;
	odp_pktio_t pktio;

	pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
			     ODP_PKTOUT_MODE_SEND);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	printf("testing mac for %s\n", iface_name[0]);

	mac_len = odp_pktio_mac_addr(pktio, mac_addr, sizeof(mac_addr));
	CU_ASSERT(ODPH_ETHADDR_LEN == mac_len);

	printf(" %X:%X:%X:%X:%X:%X ",
	       mac_addr[0], mac_addr[1], mac_addr[2],
	       mac_addr[3], mac_addr[4], mac_addr[5]);

	/* Fail case: wrong addr_size. Expected <0. */
	mac_len = odp_pktio_mac_addr(pktio, mac_addr, 2);
	CU_ASSERT(mac_len < 0);

	ret = odp_pktio_close(pktio);
	CU_ASSERT(0 == ret);
}

void pktio_test_inq_remdef(void)
{
	odp_pktio_t pktio;
	odp_queue_t inq;
	odp_event_t ev;
	uint64_t wait;
	int i;

	pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
			     ODP_PKTOUT_MODE_SEND);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);
	CU_ASSERT(create_inq(pktio, ODP_QUEUE_TYPE_POLL) == 0);
	inq = odp_pktio_inq_getdef(pktio);
	CU_ASSERT(inq != ODP_QUEUE_INVALID);
	CU_ASSERT(odp_pktio_inq_remdef(pktio) == 0);

	wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);
	for (i = 0; i < 100; i++) {
		ev = odp_schedule(NULL, wait);
		if (ev != ODP_EVENT_INVALID) {
			odp_event_free(ev);
			CU_FAIL("received unexpected event");
		}
	}

	CU_ASSERT(odp_queue_destroy(inq) == 0);
	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

void pktio_test_open(void)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	int i;

	/* test the sequence open->close->open->close() */
	for (i = 0; i < 2; ++i) {
		pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
				     ODP_PKTOUT_MODE_SEND);
		CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);
		CU_ASSERT(odp_pktio_close(pktio) == 0);
	}

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open("nothere", default_pkt_pool, &pktio_param);
	CU_ASSERT(pktio == ODP_PKTIO_INVALID);
}

void pktio_test_lookup(void)
{
	odp_pktio_t pktio, pktio_inval;
	odp_pktio_param_t pktio_param;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(iface_name[0], default_pkt_pool, &pktio_param);
	CU_ASSERT(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT(odp_pktio_lookup(iface_name[0]) == pktio);

	pktio_inval = odp_pktio_open(iface_name[0], default_pkt_pool,
				     &pktio_param);
	CU_ASSERT(odp_errno() != 0);
	CU_ASSERT(pktio_inval == ODP_PKTIO_INVALID);

	CU_ASSERT(odp_pktio_close(pktio) == 0);

	CU_ASSERT(odp_pktio_lookup(iface_name[0]) == ODP_PKTIO_INVALID);
}

void pktio_test_inq(void)
{
	odp_pktio_t pktio;

	pktio = create_pktio(0, ODP_PKTIN_MODE_POLL,
			     ODP_PKTOUT_MODE_SEND);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT(create_inq(pktio, ODP_QUEUE_TYPE_POLL) == 0);
	CU_ASSERT(destroy_inq(pktio) == 0);
	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

static void pktio_test_start_stop(void)
{
	odp_pktio_t pktio[MAX_NUM_IFACES];
	odp_packet_t pkt;
	odp_event_t tx_ev[1000];
	odp_event_t ev;
	int i, pkts, ret, alloc = 0;
	odp_queue_t outq;
	uint64_t wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);

	for (i = 0; i < num_ifaces; i++) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_SCHED,
					ODP_PKTOUT_MODE_SEND);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
		create_inq(pktio[i],  ODP_QUEUE_TYPE_SCHED);
	}

	outq = odp_pktio_outq_getdef(pktio[0]);

	/* Interfaces are stopped by default,
	 * Check that stop when stopped generates an error */
	ret = odp_pktio_stop(pktio[0]);
	CU_ASSERT(ret <= 0);

	/* start first */
	ret = odp_pktio_start(pktio[0]);
	CU_ASSERT(ret == 0);
	/* Check that start when started generates an error */
	ret = odp_pktio_start(pktio[0]);
	CU_ASSERT(ret < 0);

	/* Test Rx on a stopped interface. Only works if there are 2 */
	if (num_ifaces > 1) {
		for (alloc = 0; alloc < 1000; alloc++) {
			pkt = odp_packet_alloc(default_pkt_pool, packet_len);
			if (pkt == ODP_PACKET_INVALID)
				break;
			pktio_init_packet(pkt);
			tx_ev[alloc] = odp_packet_to_event(pkt);
		}

		for (pkts = 0; pkts != alloc; ) {
			ret = odp_queue_enq_multi(outq, &tx_ev[pkts],
						  alloc - pkts);
			if (ret < 0) {
				CU_FAIL("unable to enqueue packet\n");
				break;
			}
			pkts += ret;
		}
		/* check that packets did not arrive */
		for (i = 0, pkts = 0; i < 1000; i++) {
			ev = odp_schedule(NULL, wait);
			if (ev == ODP_EVENT_INVALID)
				continue;

			if (odp_event_type(ev) == ODP_EVENT_PACKET) {
				pkt = odp_packet_from_event(ev);
				if (pktio_pkt_seq(pkt) != TEST_SEQ_INVALID)
					pkts++;
			}
			odp_event_free(ev);
		}
		if (pkts)
			CU_FAIL("pktio stopped, received unexpected events");

		/* start both, send and get packets */
		/* 0 already started */
		ret = odp_pktio_start(pktio[1]);
		CU_ASSERT(ret == 0);

		/* flush packets with magic number in pipes */
		for (i = 0; i < 1000; i++) {
			ev = odp_schedule(NULL, wait);
			if (ev != ODP_EVENT_INVALID)
				odp_event_free(ev);
		}
	}

	/* alloc */
	for (alloc = 0; alloc < 1000; alloc++) {
		pkt = odp_packet_alloc(default_pkt_pool, packet_len);
		if (pkt == ODP_PACKET_INVALID)
			break;
		pktio_init_packet(pkt);
		tx_ev[alloc] = odp_packet_to_event(pkt);
	}

	/* send */
	for (pkts = 0; pkts != alloc; ) {
		ret = odp_queue_enq_multi(outq, &tx_ev[pkts], alloc - pkts);
		if (ret < 0) {
			CU_FAIL("unable to enqueue packet\n");
			break;
		}
		pkts += ret;
	}

	/* get */
	for (i = 0, pkts = 0; i < 1000; i++) {
		ev = odp_schedule(NULL, wait);
		if (ev != ODP_EVENT_INVALID) {
			if (odp_event_type(ev) == ODP_EVENT_PACKET) {
				pkt = odp_packet_from_event(ev);
				if (pktio_pkt_seq(pkt) != TEST_SEQ_INVALID)
					pkts++;
			}
			odp_event_free(ev);
		}
	}
	CU_ASSERT(pkts == alloc);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT(odp_pktio_stop(pktio[i]) == 0);
		destroy_inq(pktio[i]);
		CU_ASSERT(odp_pktio_close(pktio[i]) == 0);
	}
}

/*
 * This is a pre-condition check that the pktio_test_send_failure()
 * test case can be run. If the TX interface MTU is larger that the
 * biggest packet we can allocate then the test won't be able to
 * attempt to send packets larger than the MTU, so skip the test.
 */
static int pktio_check_send_failure(void)
{
	odp_pktio_t pktio_tx;
	int mtu;
	odp_pktio_param_t pktio_param;
	int iface_idx = 0;
	const char *iface = iface_name[iface_idx];

	memset(&pktio_param, 0, sizeof(pktio_param));

	pktio_param.in_mode = ODP_PKTIN_MODE_RECV;

	pktio_tx = odp_pktio_open(iface, pool[iface_idx], &pktio_param);
	if (pktio_tx == ODP_PKTIO_INVALID) {
		fprintf(stderr, "%s: failed to open pktio\n", __func__);
		return 0;
	}

	/* read the MTU from the transmit interface */
	mtu = odp_pktio_mtu(pktio_tx);

	odp_pktio_close(pktio_tx);

	return (mtu <= ODP_CONFIG_PACKET_BUF_LEN_MAX - 32);
}

static void pktio_test_send_failure(void)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	uint32_t pkt_seq[TX_BATCH_LEN];
	int ret, mtu, i, alloc_pkts;
	odp_pool_param_t pool_params;
	odp_pool_t pkt_pool;
	int long_pkt_idx = TX_BATCH_LEN / 2;
	pktio_info_t info_rx;

	pktio_tx = create_pktio(0, ODP_PKTIN_MODE_RECV,
				ODP_PKTOUT_MODE_SEND);
	if (pktio_tx == ODP_PKTIO_INVALID) {
		CU_FAIL("failed to open pktio");
		return;
	}

	/* read the MTU from the transmit interface */
	mtu = odp_pktio_mtu(pktio_tx);

	ret = odp_pktio_start(pktio_tx);
	CU_ASSERT_FATAL(ret == 0);

	/* configure the pool so that we can generate test packets larger
	 * than the interface MTU */
	memset(&pool_params, 0, sizeof(pool_params));
	pool_params.pkt.len     = mtu + 32;
	pool_params.pkt.seg_len = pool_params.pkt.len;
	pool_params.pkt.num     = TX_BATCH_LEN + 1;
	pool_params.type        = ODP_POOL_PACKET;
	pkt_pool = odp_pool_create("pkt_pool_oversize", &pool_params);
	CU_ASSERT_FATAL(pkt_pool != ODP_POOL_INVALID);

	if (num_ifaces > 1) {
		pktio_rx = create_pktio(1, ODP_PKTIN_MODE_RECV,
					ODP_PKTOUT_MODE_SEND);
		ret = odp_pktio_start(pktio_rx);
		CU_ASSERT_FATAL(ret == 0);
	} else {
		pktio_rx = pktio_tx;
	}

	/* generate a batch of packets with a single overly long packet
	 * in the middle */
	for (i = 0; i < TX_BATCH_LEN; ++i) {
		uint32_t pkt_len;

		if (i == long_pkt_idx)
			pkt_len = pool_params.pkt.len;
		else
			pkt_len = PKT_LEN_NORMAL;

		pkt_tbl[i] = odp_packet_alloc(pkt_pool, pkt_len);
		if (pkt_tbl[i] == ODP_PACKET_INVALID)
			break;

		pkt_seq[i] = pktio_init_packet(pkt_tbl[i]);
		if (pkt_seq[i] == TEST_SEQ_INVALID)
			break;
	}
	alloc_pkts = i;

	if (alloc_pkts == TX_BATCH_LEN) {
		/* try to send the batch with the long packet in the middle,
		 * the initial short packets should be sent successfully */
		odp_errno_zero();
		ret = odp_pktio_send(pktio_tx, pkt_tbl, TX_BATCH_LEN);
		CU_ASSERT(ret == long_pkt_idx);
		CU_ASSERT(odp_errno() == 0);

		info_rx.id   = pktio_rx;
		info_rx.outq = ODP_QUEUE_INVALID;
		info_rx.inq  = ODP_QUEUE_INVALID;
		info_rx.in_mode = ODP_PKTIN_MODE_RECV;

		for (i = 0; i < ret; ++i) {
			pkt_tbl[i] = wait_for_packet(&info_rx, pkt_seq[i],
						     ODP_TIME_SEC_IN_NS);
			if (pkt_tbl[i] == ODP_PACKET_INVALID)
				break;
		}

		if (i == ret) {
			/* now try to send starting with the too-long packet
			 * and verify it fails */
			odp_errno_zero();
			ret = odp_pktio_send(pktio_tx,
					     &pkt_tbl[long_pkt_idx],
					     TX_BATCH_LEN - long_pkt_idx);
			CU_ASSERT(ret == -1);
			CU_ASSERT(odp_errno() != 0);
		} else {
			CU_FAIL("failed to receive transmitted packets\n");
		}

		/* now reduce the size of the long packet and attempt to send
		 * again - should work this time */
		i = long_pkt_idx;
		odp_packet_pull_tail(pkt_tbl[i],
				     odp_packet_len(pkt_tbl[i]) -
				     PKT_LEN_NORMAL);
		pkt_seq[i] = pktio_init_packet(pkt_tbl[i]);
		CU_ASSERT_FATAL(pkt_seq[i] != TEST_SEQ_INVALID);
		ret = odp_pktio_send(pktio_tx, &pkt_tbl[i], TX_BATCH_LEN - i);
		CU_ASSERT_FATAL(ret == (TX_BATCH_LEN - i));

		for (; i < TX_BATCH_LEN; ++i) {
			pkt_tbl[i] = wait_for_packet(&info_rx,
						     pkt_seq[i],
						     ODP_TIME_SEC_IN_NS);
			if (pkt_tbl[i] == ODP_PACKET_INVALID)
				break;
		}
		CU_ASSERT(i == TX_BATCH_LEN);
	} else {
		CU_FAIL("failed to generate test packets\n");
	}

	for (i = 0; i < alloc_pkts; ++i) {
		if (pkt_tbl[i] != ODP_PACKET_INVALID)
			odp_packet_free(pkt_tbl[i]);
	}

	if (pktio_rx != pktio_tx)
		CU_ASSERT(odp_pktio_close(pktio_rx) == 0);
	CU_ASSERT(odp_pktio_close(pktio_tx) == 0);
	CU_ASSERT(odp_pool_destroy(pkt_pool) == 0);
}

static void pktio_test_recv_on_wonly(void)
{
	odp_pktio_t pktio;
	odp_packet_t pkt;
	int ret;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DISABLED,
			     ODP_PKTOUT_MODE_SEND);

	if (pktio == ODP_PKTIO_INVALID) {
		CU_FAIL("failed to open pktio");
		return;
	}

	ret = odp_pktio_start(pktio);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_pktio_recv(pktio, &pkt, 1);
	CU_ASSERT(ret < 0);

	if (ret > 0)
		odp_packet_free(pkt);

	ret = odp_pktio_stop(pktio);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_pktio_close(pktio);
	CU_ASSERT_FATAL(ret == 0);
}

static void pktio_test_send_on_ronly(void)
{
	odp_pktio_t pktio;
	odp_packet_t pkt;
	int ret;

	pktio = create_pktio(0, ODP_PKTIN_MODE_RECV,
			     ODP_PKTOUT_MODE_DISABLED);

	if (pktio == ODP_PKTIO_INVALID) {
		CU_FAIL("failed to open pktio");
		return;
	}

	ret = odp_pktio_start(pktio);
	CU_ASSERT_FATAL(ret == 0);

	pkt = odp_packet_alloc(default_pkt_pool, packet_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID)

	pktio_init_packet(pkt);

	ret = odp_pktio_send(pktio, &pkt, 1);
	CU_ASSERT(ret < 0);

	if (ret <= 0)
		odp_packet_free(pkt);

	ret = odp_pktio_stop(pktio);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_pktio_close(pktio);
	CU_ASSERT_FATAL(ret == 0);
}

static int create_pool(const char *iface, int num)
{
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_param_t params;

	memset(&params, 0, sizeof(params));
	set_pool_len(&params);
	params.pkt.num     = PKT_BUF_NUM;
	params.type        = ODP_POOL_PACKET;

	snprintf(pool_name, sizeof(pool_name), "pkt_pool_%s_%d",
		 iface, pool_segmentation);

	pool[num] = odp_pool_create(pool_name, &params);
	if (ODP_POOL_INVALID == pool[num]) {
		fprintf(stderr, "%s: failed to create pool: %d",
			__func__, odp_errno());
		return -1;
	}

	return 0;
}

static int pktio_suite_init(void)
{
	odp_atomic_init_u32(&ip_seq, 0);
	iface_name[0] = getenv("ODP_PKTIO_IF0");
	iface_name[1] = getenv("ODP_PKTIO_IF1");
	num_ifaces = 1;
	int i;

	if (!iface_name[0]) {
		printf("No interfaces specified, using default \"loop\".\n");
		iface_name[0] = "loop";
	} else if (!iface_name[1]) {
		printf("Using loopback interface: %s\n", iface_name[0]);
	} else {
		num_ifaces = 2;
		printf("Using paired interfaces: %s %s\n",
		       iface_name[0], iface_name[1]);
	}

	for (i = 0; i < num_ifaces; i++) {
		if (create_pool(iface_name[i], i) != 0)
			return -1;
	}

	if (default_pool_create() != 0) {
		fprintf(stderr, "error: failed to create default pool\n");
		return -1;
	}

	return 0;
}

int pktio_suite_init_unsegmented(void)
{
	pool_segmentation = PKT_POOL_UNSEGMENTED;
	return pktio_suite_init();
}

int pktio_suite_init_segmented(void)
{
	pool_segmentation = PKT_POOL_SEGMENTED;
	return pktio_suite_init();
}

int pktio_suite_term(void)
{
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_t pool;
	int i;
	int ret = 0;

	for (i = 0; i < num_ifaces; ++i) {
		snprintf(pool_name, sizeof(pool_name),
			 "pkt_pool_%s_%d", iface_name[i], pool_segmentation);
		pool = odp_pool_lookup(pool_name);
		if (pool == ODP_POOL_INVALID)
			continue;

		if (odp_pool_destroy(pool) != 0) {
			fprintf(stderr, "error: failed to destroy pool %s\n",
				pool_name);
			ret = -1;
		}
	}

	if (odp_pool_destroy(default_pkt_pool) != 0) {
		fprintf(stderr, "error: failed to destroy default pool\n");
		ret = -1;
	}
	default_pkt_pool = ODP_POOL_INVALID;

	return ret;
}

odp_testinfo_t pktio_suite_unsegmented[] = {
	ODP_TEST_INFO(pktio_test_open),
	ODP_TEST_INFO(pktio_test_lookup),
	ODP_TEST_INFO(pktio_test_inq),
	ODP_TEST_INFO(pktio_test_poll_queue),
	ODP_TEST_INFO(pktio_test_poll_multi),
	ODP_TEST_INFO(pktio_test_sched_queue),
	ODP_TEST_INFO(pktio_test_sched_multi),
	ODP_TEST_INFO(pktio_test_recv),
	ODP_TEST_INFO(pktio_test_recv_multi),
	ODP_TEST_INFO(pktio_test_jumbo),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_send_failure,
				  pktio_check_send_failure),
	ODP_TEST_INFO(pktio_test_mtu),
	ODP_TEST_INFO(pktio_test_promisc),
	ODP_TEST_INFO(pktio_test_mac),
	ODP_TEST_INFO(pktio_test_inq_remdef),
	ODP_TEST_INFO(pktio_test_start_stop),
	ODP_TEST_INFO(pktio_test_recv_on_wonly),
	ODP_TEST_INFO(pktio_test_send_on_ronly),
	ODP_TEST_INFO_NULL
};

odp_testinfo_t pktio_suite_segmented[] = {
	ODP_TEST_INFO(pktio_test_poll_queue),
	ODP_TEST_INFO(pktio_test_poll_multi),
	ODP_TEST_INFO(pktio_test_sched_queue),
	ODP_TEST_INFO(pktio_test_sched_multi),
	ODP_TEST_INFO(pktio_test_recv),
	ODP_TEST_INFO(pktio_test_recv_multi),
	ODP_TEST_INFO(pktio_test_jumbo),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_send_failure,
				  pktio_check_send_failure),
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t pktio_suites[] = {
	{"Packet I/O Unsegmented", pktio_suite_init_unsegmented,
	 pktio_suite_term, pktio_suite_unsegmented},
	{"Packet I/O Segmented", pktio_suite_init_segmented,
	 pktio_suite_term, pktio_suite_segmented},
	ODP_SUITE_INFO_NULL
};

int pktio_main(void)
{
	int ret = odp_cunit_register(pktio_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <odp.h>
#include <odp_cunit_common.h>

#include <odph_eth.h>
#include <odph_ip.h>
#include <odph_udp.h>

#include <stdlib.h>

#define PKT_BUF_NUM            32
#define PKT_BUF_SIZE           1856
#define MAX_NUM_IFACES         2
#define TEST_SEQ_INVALID       ((uint32_t)~0)
#define TEST_SEQ_MAGIC         0x92749451

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
} pktio_info_t;

/** structure of test packet UDP payload */
typedef struct {
	uint32be_t magic;
	uint32be_t seq;
} pkt_test_data_t;

/** default packet pool */
odp_buffer_pool_t default_pkt_pool = ODP_BUFFER_POOL_INVALID;

/** sequence number of IP packets */
odp_atomic_u32_t ip_seq;

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

static int pktio_pkt_set_seq(odp_packet_t pkt)
{
	static uint32_t tstseq;
	size_t l4_off;
	pkt_test_data_t data;

	data.magic = TEST_SEQ_MAGIC;
	data.seq   = tstseq;

	l4_off = odp_packet_l4_offset(pkt);
	if (!l4_off) {
		CU_FAIL("packet L4 offset not set");
		return -1;
	}

	odp_packet_copydata_in(pkt, l4_off+ODPH_UDPHDR_LEN,
			       sizeof(data), &data);

	tstseq++;

	return 0;
}

static uint32_t pktio_pkt_seq(odp_packet_t pkt)
{
	size_t l4_off;
	pkt_test_data_t data;

	l4_off = odp_packet_l4_offset(pkt);
	if (l4_off) {
		odp_packet_copydata_out(pkt, l4_off+ODPH_UDPHDR_LEN,
					sizeof(data), &data);

		if (data.magic == TEST_SEQ_MAGIC)
			return data.seq;
	}

	return TEST_SEQ_INVALID;
}

static odp_packet_t pktio_create_packet(void)
{
	odp_packet_t pkt;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	char *buf;
	uint16_t seq;
	size_t payload_len = sizeof(pkt_test_data_t);
	uint8_t mac[ODPH_ETHADDR_LEN] = {0};

	pkt = odp_packet_alloc(default_pkt_pool, payload_len + ODPH_UDPHDR_LEN +
			       ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);
	if (pkt == ODP_PACKET_INVALID) {
		CU_FAIL("failed to allocate packet buffer");
		return ODP_PACKET_INVALID;
	}
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
	ip->dst_addr = odp_cpu_to_be_32(0);
	ip->src_addr = odp_cpu_to_be_32(0);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(payload_len + ODPH_UDPHDR_LEN +
				       ODPH_IPV4HDR_LEN);
	ip->ttl = 128;
	ip->proto = ODPH_IPPROTO_UDP;
	seq = odp_atomic_fetch_inc_u32(&ip_seq);
	ip->id = odp_cpu_to_be_16(seq);
	ip->chksum = 0;
	odph_ipv4_csum_update(pkt);

	/* UDP */
	odp_packet_l4_offset_set(pkt, ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp = (odph_udphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp->src_port = odp_cpu_to_be_16(0);
	udp->dst_port = odp_cpu_to_be_16(0);
	udp->length = odp_cpu_to_be_16(payload_len + ODPH_UDPHDR_LEN);
	udp->chksum = 0;

	if (pktio_pkt_set_seq(pkt) != 0) {
		odp_packet_free(pkt);
		return ODP_PACKET_INVALID;
	}

	return pkt;
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
	udp->chksum = odph_ipv4_udp_chksum(pkt);

	return 0;
}

static int default_pool_create(void)
{
	odp_buffer_pool_param_t params;

	if (default_pkt_pool != ODP_BUFFER_POOL_INVALID)
		return -1;

	params.buf_size  = PKT_BUF_SIZE;
	params.buf_align = 0;
	params.num_bufs  = PKT_BUF_NUM;
	params.buf_type  = ODP_BUFFER_TYPE_PACKET;

	default_pkt_pool = odp_buffer_pool_create("pkt_pool_default",
						  ODP_SHM_NULL, &params);
	if (default_pkt_pool == ODP_BUFFER_POOL_INVALID)
		return -1;

	return 0;
}

static odp_pktio_t create_pktio(const char *iface)
{
	odp_buffer_pool_t pool;
	odp_pktio_t pktio;
	char pool_name[ODP_BUFFER_POOL_NAME_LEN];
	odp_buffer_pool_param_t params;

	params.buf_size  = PKT_BUF_SIZE;
	params.buf_align = 0;
	params.num_bufs  = PKT_BUF_NUM;
	params.buf_type  = ODP_BUFFER_TYPE_PACKET;

	snprintf(pool_name, sizeof(pool_name), "pkt_pool_%s", iface);
	pool = odp_buffer_pool_lookup(pool_name);
	if (pool == ODP_BUFFER_POOL_INVALID)
		pool = odp_buffer_pool_create(pool_name, ODP_SHM_NULL, &params);
	CU_ASSERT(pool != ODP_BUFFER_POOL_INVALID);

	pktio = odp_pktio_open(iface, pool);
	if (pktio == ODP_PKTIO_INVALID)
		pktio = odp_pktio_lookup(iface);
	CU_ASSERT(pktio != ODP_PKTIO_INVALID);

	return pktio;
}

static int create_inq(odp_pktio_t pktio)
{
	odp_queue_param_t qparam;
	odp_queue_t inq_def;
	char inq_name[ODP_QUEUE_NAME_LEN];

	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;

	snprintf(inq_name, sizeof(inq_name), "inq-pktio-%d", pktio);
	inq_def = odp_queue_lookup(inq_name);
	if (inq_def == ODP_QUEUE_INVALID)
		inq_def = odp_queue_create(inq_name,
				ODP_QUEUE_TYPE_PKTIN, &qparam);
	CU_ASSERT(inq_def != ODP_QUEUE_INVALID);

	return odp_pktio_inq_setdef(pktio, inq_def);
}

static odp_buffer_t queue_deq_wait_time(odp_queue_t queue, uint64_t ns)
{
	uint64_t start, now, diff;
	odp_buffer_t buf;

	start = odp_time_cycles();

	do {
		buf = odp_queue_deq(queue);
		if (buf != ODP_BUFFER_INVALID)
			return buf;
		now = odp_time_cycles();
		diff = odp_time_diff_cycles(start, now);
	} while (odp_time_cycles_to_ns(diff) < ns);

	return ODP_BUFFER_INVALID;
}

static odp_packet_t wait_for_packet(odp_queue_t queue,
				    uint32_t seq, uint64_t ns)
{
	uint64_t start, now, diff;
	odp_event_t ev;
	odp_buffer_t buf;
	odp_packet_t pkt = ODP_PACKET_INVALID;

	start = odp_time_cycles();

	do {
		if (queue != ODP_QUEUE_INVALID) {
			buf = queue_deq_wait_time(queue, ns);
		} else {
			ev  = odp_schedule(NULL, ns);
			buf = odp_buffer_from_event(ev);
		}

		if (buf != ODP_BUFFER_INVALID &&
		    odp_buffer_type(buf) == ODP_BUFFER_TYPE_PACKET) {
			pkt = odp_packet_from_buffer(buf);
			if (pktio_pkt_seq(pkt) == seq)
				return pkt;
		}

		now = odp_time_cycles();
		diff = odp_time_diff_cycles(start, now);
	} while (odp_time_cycles_to_ns(diff) < ns);

	CU_FAIL("failed to receive transmitted packet");

	return ODP_PACKET_INVALID;
}

static void pktio_txrx_multi(pktio_info_t *pktio_a, pktio_info_t *pktio_b,
			     int num_pkts)
{
	odp_packet_t tx_pkt[num_pkts];
	odp_buffer_t tx_buf[num_pkts];
	odp_packet_t rx_pkt;
	uint32_t tx_seq[num_pkts];
	int i, ret;

	/* generate test packets to send */
	for (i = 0; i < num_pkts; ++i) {
		tx_pkt[i] = pktio_create_packet();
		if (tx_pkt[i] == ODP_PACKET_INVALID)
			break;

		tx_seq[i] = pktio_pkt_seq(tx_pkt[i]);
		if (tx_seq[i] == TEST_SEQ_INVALID)
			break;

		pktio_pkt_set_macs(tx_pkt[i], pktio_a, pktio_b);
		if (pktio_fixup_checksums(tx_pkt[i]) != 0)
			break;

		tx_buf[i] = odp_packet_to_buffer(tx_pkt[i]);
	}

	if (i != num_pkts) {
		CU_FAIL("failed to generate test packets");
		return;
	}

	/* send packet(s) out */
	if (num_pkts == 1)
		ret = odp_queue_enq(pktio_a->outq,
				    odp_buffer_to_event(tx_buf[0]));
	else
		ret = odp_queue_enq_multi(pktio_a->outq, tx_buf, num_pkts);

	if (ret != 0) {
		CU_FAIL("failed to enqueue test packets");
		return;
	}

	/* and wait for them to arrive back */
	for (i = 0; i < num_pkts; ++i) {
		rx_pkt = wait_for_packet(pktio_b->inq, tx_seq[i], ODP_TIME_SEC);

		if (rx_pkt == ODP_PACKET_INVALID)
			break;
		CU_ASSERT(odp_packet_input(rx_pkt) == pktio_b->id);
		CU_ASSERT(odp_packet_error(rx_pkt) == 0);
		odp_packet_free(rx_pkt);
	}

	CU_ASSERT(i == num_pkts);
}

static void pktio_test_txrx(odp_queue_type_t q_type, int num_pkts)
{
	int ret, i, if_b;
	pktio_info_t pktios[MAX_NUM_IFACES];
	pktio_info_t *io;

	/* create pktios and associate input/output queues */
	for (i = 0; i < num_ifaces; ++i) {
		io = &pktios[i];

		io->name = iface_name[i];
		io->id   = create_pktio(iface_name[i]);
		if (io->id == ODP_PKTIO_INVALID) {
			CU_FAIL("failed to open iface");
			return;
		}
		create_inq(io->id);
		io->outq = odp_pktio_outq_getdef(io->id);
		if (q_type == ODP_QUEUE_TYPE_POLL)
			io->inq = odp_pktio_inq_getdef(io->id);
		else
			io->inq = ODP_QUEUE_INVALID;
	}

	/* if we have two interfaces then send through one and receive on
	 * another but if there's only one assume it's a loopback */
	if_b = (num_ifaces == 1) ? 0 : 1;
	pktio_txrx_multi(&pktios[0], &pktios[if_b], num_pkts);

	for (i = 0; i < num_ifaces; ++i) {
		odp_pktio_inq_remdef(pktios[i].id);
		ret = odp_pktio_close(pktios[i].id);
		CU_ASSERT(ret == 0);
	}
}

static void test_odp_pktio_poll_queue(void)
{
	pktio_test_txrx(ODP_QUEUE_TYPE_POLL, 1);
}

static void test_odp_pktio_poll_multi(void)
{
	pktio_test_txrx(ODP_QUEUE_TYPE_POLL, 4);
}

static void test_odp_pktio_sched_queue(void)
{
	pktio_test_txrx(ODP_QUEUE_TYPE_SCHED, 1);
}

static void test_odp_pktio_sched_multi(void)
{
	pktio_test_txrx(ODP_QUEUE_TYPE_SCHED, 4);
}

static void test_odp_pktio_mtu(void)
{
	int ret;
	int mtu;
	odp_pktio_t pktio = create_pktio(iface_name[0]);

	mtu = odp_pktio_mtu(pktio);
	CU_ASSERT(mtu > 0);

	printf(" %d ",  mtu);

	ret = odp_pktio_close(pktio);
	CU_ASSERT(ret == 0);

	return;
}

static void test_odp_pktio_promisc(void)
{
	int ret;
	odp_pktio_t pktio = create_pktio(iface_name[0]);

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

	return;
}

static void test_odp_pktio_mac(void)
{
	unsigned char mac_addr[ODPH_ETHADDR_LEN];
	size_t mac_len;
	int ret;
	odp_pktio_t pktio = create_pktio(iface_name[0]);

	printf("testing mac for %s\n", iface_name[0]);

	mac_len = odp_pktio_mac_addr(pktio, mac_addr, ODPH_ETHADDR_LEN);
	CU_ASSERT(ODPH_ETHADDR_LEN == mac_len);

	printf(" %X:%X:%X:%X:%X:%X ",
	       mac_addr[0], mac_addr[1], mac_addr[2],
	       mac_addr[3], mac_addr[4], mac_addr[5]);

	/* Fail case: wrong addr_size. Expected 0. */
	mac_len = odp_pktio_mac_addr(pktio, mac_addr, 2);
	CU_ASSERT(0 == mac_len);

	ret = odp_pktio_close(pktio);
	CU_ASSERT(0 == ret);

	return;
}

static void test_odp_pktio_inq_remdef(void)
{
	odp_pktio_t pktio = create_pktio(iface_name[0]);
	int i;

	CU_ASSERT(pktio != ODP_PKTIO_INVALID);
	CU_ASSERT(create_inq(pktio) == 0);
	CU_ASSERT(odp_pktio_inq_remdef(pktio) == 0);

	for (i = 0; i < 100; i++)
		odp_schedule(NULL, ODP_TIME_MSEC);

	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

static void test_odp_pktio_open(void)
{
	odp_pktio_t pktio;
	int i;

	/* test the sequence open->close->open->close() */
	for (i = 0; i < 2; ++i) {
		pktio = create_pktio(iface_name[0]);
		CU_ASSERT(pktio != ODP_PKTIO_INVALID);
		CU_ASSERT(odp_pktio_close(pktio) == 0);
	}

	pktio = odp_pktio_open("nothere", default_pkt_pool);
	CU_ASSERT(pktio == ODP_PKTIO_INVALID);
}

static void test_odp_pktio_lookup(void)
{
	odp_pktio_t pktio, pktio_inval;

	pktio = odp_pktio_open(iface_name[0], default_pkt_pool);
	CU_ASSERT(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT(odp_pktio_lookup(iface_name[0]) == pktio);

	pktio_inval = odp_pktio_open(iface_name[0], default_pkt_pool);
	CU_ASSERT(errno == -EEXIST);
	CU_ASSERT(pktio_inval == ODP_PKTIO_INVALID);

	CU_ASSERT(odp_pktio_close(pktio) == 0);

	CU_ASSERT(odp_pktio_lookup(iface_name[0]) == ODP_PKTIO_INVALID);
}

static void test_odp_pktio_inq(void)
{
	odp_pktio_t pktio;

	pktio = create_pktio(iface_name[0]);
	CU_ASSERT(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT(create_inq(pktio) == 0);

	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

static void test_odp_pktio_outq(void)
{
	odp_queue_t testq;

	testq = odp_pktio_outq_getdef(ODP_PKTIO_INVALID);
	CU_ASSERT(testq == ODP_QUEUE_INVALID);
}

static void test_odp_pktio_close(void)
{
	int res;

	res = odp_pktio_close(ODP_PKTIO_INVALID);
	CU_ASSERT_EQUAL(res, -1);
}

static int init_pktio_suite(void)
{
	iface_name[0] = getenv("ODP_PKTIO_IF0");
	iface_name[1] = getenv("ODP_PKTIO_IF1");
	num_ifaces = 1;

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

	if (default_pool_create() != 0) {
		fprintf(stderr, "error: failed to create default pool\n");
		return -1;
	}

	return 0;
}

static int term_pktio_suite(void)
{
	if (odp_buffer_pool_destroy(default_pkt_pool) != 0) {
		fprintf(stderr, "error: failed to destroy default pool\n");
		return -1;
	}

	return 0;
}

CU_TestInfo pktio_tests[] = {
	{"pktio open",		test_odp_pktio_open},
	{"pktio lookup",	test_odp_pktio_lookup},
	{"pktio close",		test_odp_pktio_close},
	{"pktio inq",		test_odp_pktio_inq},
	{"pktio outq",		test_odp_pktio_outq},
	{"pktio poll queues",	test_odp_pktio_poll_queue},
	{"pktio poll multi",	test_odp_pktio_poll_multi},
	{"pktio sched queues",	test_odp_pktio_sched_queue},
	{"pktio sched multi",	test_odp_pktio_sched_multi},
	{"pktio mtu",		test_odp_pktio_mtu},
	{"pktio promisc mode",	test_odp_pktio_promisc},
	{"pktio mac",		test_odp_pktio_mac},
	{"pktio inq_remdef",	test_odp_pktio_inq_remdef},
	CU_TEST_INFO_NULL
};

CU_SuiteInfo odp_testsuites[] = {
	{"Packet I/O",
		init_pktio_suite, term_pktio_suite, NULL, NULL, pktio_tests},
	CU_SUITE_INFO_NULL
};

/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include <test_packet_parser.h>

#include <odp/helper/odph_api.h>

#include <stdlib.h>
#include "parser.h"

#define MAX_NUM_IFACES         2
#define PKT_POOL_NUM           256
#define PKT_POOL_BUF_LEN       (2 * 1024)

/**
 * local container for pktio attributes
 */
typedef struct {
	const char *name;
	odp_pktio_t hdl;
	odp_pktout_queue_t pktout;
	odp_pktin_queue_t pktin;
} pktio_info_t;

/** Interface names used for testing */
static const char *iface_name[MAX_NUM_IFACES];

/** Test interfaces */
pktio_info_t pktios[MAX_NUM_IFACES];
pktio_info_t *pktio_a;
pktio_info_t *pktio_b;

/** Number of interfaces being used (1=loopback, 2=pair) */
static int num_ifaces;

/** While testing real-world interfaces additional time may be needed for
 *  external network to enable link to pktio interface that just become up.
 */
static bool wait_for_network;

/** Parser packet pool */
odp_pool_t parser_pool = ODP_POOL_INVALID;

static inline void wait_linkup(odp_pktio_t pktio)
{
	/* wait 1 second for link up */
	uint64_t wait_ns = (10 * ODP_TIME_MSEC_IN_NS);
	int wait_num = 100;
	int i;
	int ret = -1;

	for (i = 0; i < wait_num; i++) {
		ret = odp_pktio_link_status(pktio);
		if (ret < 0 || ret == 1)
			break;
		/* link is down, call status again after delay */
		odp_time_wait_ns(wait_ns);
	}
}

static int pkt_pool_create(void)
{
	odp_pool_capability_t capa;
	odp_pool_param_t params;

	if (odp_pool_capability(&capa) != 0) {
		printf("Error: unable to query pool capability.\n");
		return -1;
	}

	if (capa.pkt.max_num && capa.pkt.max_num < PKT_POOL_NUM) {
		printf("Error: packet pool size not supported.\n");
		printf("MAX: %" PRIu32 "\n", capa.pkt.max_num);
		return -1;
	} else if (capa.pkt.max_len && capa.pkt.max_len < PKT_POOL_BUF_LEN) {
		printf("Error: packet length not supported.\n");
		return -1;
	} else if (capa.pkt.max_seg_len &&
		   capa.pkt.max_seg_len < PKT_POOL_BUF_LEN) {
		printf("Error: segment length not supported.\n");
		return -1;
	}

	odp_pool_param_init(&params);
	params.pkt.seg_len = PKT_POOL_BUF_LEN;
	params.pkt.len = PKT_POOL_BUF_LEN;
	params.pkt.num     = PKT_POOL_NUM;
	params.type        = ODP_POOL_PACKET;

	parser_pool = odp_pool_create("pkt_pool_default", &params);
	if (parser_pool == ODP_POOL_INVALID) {
		printf("Error: packet pool create failed.\n");
		return -1;
	}

	return 0;
}

static odp_pktio_t create_pktio(int iface_idx, odp_pool_t pool)
{
	odp_pktio_t pktio;
	odp_pktio_config_t config;
	odp_pktio_param_t pktio_param;
	const char *iface = iface_name[iface_idx];

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	pktio = odp_pktio_open(iface, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		printf("Error: failed to open %s\n", iface);
		return ODP_PKTIO_INVALID;
	}

	odp_pktio_config_init(&config);
	config.parser.layer = ODP_PROTO_LAYER_ALL;
	if (odp_pktio_config(pktio, &config)) {
		printf("Error:  failed to configure %s\n", iface);
		return ODP_PKTIO_INVALID;
	}

	/* By default, single input and output queue is used */
	if (odp_pktin_queue_config(pktio, NULL)) {
		printf("Error: failed to config input queue for %s\n", iface);
		return ODP_PKTIO_INVALID;
	}
	if (odp_pktout_queue_config(pktio, NULL)) {
		printf("Error: failed to config output queue for %s\n", iface);
		return ODP_PKTIO_INVALID;
	}

	if (wait_for_network)
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS / 4);

	return pktio;
}

static odp_packet_t create_packet(const uint8_t *data, uint32_t len)
{
	odp_packet_t pkt;

	pkt = odp_packet_alloc(parser_pool, len);
	if (pkt == ODP_PACKET_INVALID)
		return ODP_PACKET_INVALID;

	if (odp_packet_copy_from_mem(pkt, 0, len, data)) {
		printf("Error: failed to copy test packet data\n");
		odp_packet_free(pkt);
		return ODP_PACKET_INVALID;
	}

	odp_packet_l2_offset_set(pkt, 0);

	return pkt;
}

/**
 * Receive incoming packets and compare them to the original. Function returns
 * a valid packet handle only when the received packet matches to the original
 * packet.
 */
static odp_packet_t recv_and_cmp_packet(odp_pktin_queue_t pktin,
					odp_packet_t orig_pkt, uint64_t ns)
{
	odp_packet_t pkt = ODP_PACKET_INVALID;
	odp_time_t wait_time, end;
	uint32_t orig_len;
	uint8_t *orig_data;

	orig_len = odp_packet_len(orig_pkt);
	orig_data = odp_packet_data(orig_pkt);
	wait_time = odp_time_local_from_ns(ns);
	end = odp_time_sum(odp_time_local(), wait_time);

	do {
		int ret;
		odp_packet_t tmp_pkt;

		ret = odp_pktin_recv(pktin, &tmp_pkt, 1);
		if (ret < 0)
			break;

		if (ret == 1) {
			uint32_t len;
			uint8_t *data;

			len = odp_packet_len(tmp_pkt);
			data = odp_packet_data(tmp_pkt);

			if (len == orig_len &&
			    memcmp(data, orig_data, len) == 0) {
				pkt = tmp_pkt;
				break;
			}
			odp_packet_free(tmp_pkt);
		}
	} while (odp_time_cmp(end, odp_time_local()) > 0);

	return pkt;
}

static void pktio_pkt_set_macs(odp_packet_t pkt, odp_pktio_t src, odp_pktio_t dst)
{
	uint32_t len;
	odph_ethhdr_t *eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, &len);
	int ret;

	ret = odp_pktio_mac_addr(src, &eth->src, ODP_PKTIO_MACADDR_MAXSIZE);
	CU_ASSERT(ret == ODPH_ETHADDR_LEN);
	CU_ASSERT(ret <= ODP_PKTIO_MACADDR_MAXSIZE);

	ret = odp_pktio_mac_addr(dst, &eth->dst, ODP_PKTIO_MACADDR_MAXSIZE);
	CU_ASSERT(ret == ODPH_ETHADDR_LEN);
	CU_ASSERT(ret <= ODP_PKTIO_MACADDR_MAXSIZE);
}

/**
 * Creates a test packet from data array and loops it through the test pktio
 * interfaces forcing packet parsing.
 */
static odp_packet_t loopback_packet(pktio_info_t *pktio_a,
				    pktio_info_t *pktio_b, const uint8_t *data,
				    uint32_t len)
{
	odp_packet_t pkt;
	odp_packet_t sent_pkt;

	pkt = create_packet(data, len);
	if (pkt == ODP_PACKET_INVALID) {
		CU_FAIL("failed to generate test packet");
		return ODP_PACKET_INVALID;
	}

	pktio_pkt_set_macs(pkt, pktio_a->hdl, pktio_b->hdl);

	sent_pkt = odp_packet_copy(pkt, parser_pool);
	if (sent_pkt == ODP_PACKET_INVALID) {
		CU_FAIL_FATAL("failed to copy test packet");
		odp_packet_free(pkt);
		return ODP_PACKET_INVALID;
	}

	while (1) {
		int ret = odp_pktout_send(pktio_a->pktout, &pkt, 1);

		if (ret < 0) {
			CU_FAIL_FATAL("failed to send test packet");
			odp_packet_free(pkt);
			odp_packet_free(sent_pkt);
			return ODP_PACKET_INVALID;
		}
		if (ret == 1)
			break;
	}

	/* and wait for them to arrive back */
	pkt = recv_and_cmp_packet(pktio_b->pktin, sent_pkt, ODP_TIME_SEC_IN_NS);
	odp_packet_free(sent_pkt);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_input(pkt) == pktio_b->hdl);
	CU_ASSERT(odp_packet_has_error(pkt) == 0);

	return pkt;
}

static void parser_test_arp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_arp,
			      sizeof(test_packet_arp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_arp(pkt));

	CU_ASSERT(!odp_packet_has_ipv4(pkt));
	CU_ASSERT(!odp_packet_has_ipv6(pkt));

	odp_packet_free(pkt);
}

static void parser_test_ipv4_icmp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_ipv4_icmp,
			      sizeof(test_packet_ipv4_icmp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_ipv4(pkt));
	CU_ASSERT(odp_packet_has_icmp(pkt));

	CU_ASSERT(!odp_packet_has_ipv6(pkt));
	CU_ASSERT(!odp_packet_has_tcp(pkt));
	CU_ASSERT(!odp_packet_has_udp(pkt));
	CU_ASSERT(!odp_packet_has_sctp(pkt));

	odp_packet_free(pkt);
}

static void parser_test_ipv4_tcp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_ipv4_tcp,
			      sizeof(test_packet_ipv4_tcp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_ipv4(pkt));
	CU_ASSERT(odp_packet_has_tcp(pkt));

	CU_ASSERT(!odp_packet_has_ipv6(pkt));
	CU_ASSERT(!odp_packet_has_udp(pkt));
	CU_ASSERT(!odp_packet_has_sctp(pkt));

	odp_packet_free(pkt);
}

static void parser_test_ipv4_udp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_ipv4_udp,
			      sizeof(test_packet_ipv4_udp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_ipv4(pkt));
	CU_ASSERT(odp_packet_has_udp(pkt));

	CU_ASSERT(!odp_packet_has_ipv6(pkt));
	CU_ASSERT(!odp_packet_has_tcp(pkt));
	CU_ASSERT(!odp_packet_has_sctp(pkt));

	odp_packet_free(pkt);
}

static void parser_test_vlan_ipv4_udp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_vlan_ipv4_udp,
			      sizeof(test_packet_vlan_ipv4_udp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_vlan(pkt));
	CU_ASSERT(odp_packet_has_ipv4(pkt));
	CU_ASSERT(odp_packet_has_udp(pkt));

	CU_ASSERT(!odp_packet_has_ipv6(pkt));
	CU_ASSERT(!odp_packet_has_tcp(pkt));
	CU_ASSERT(!odp_packet_has_sctp(pkt));

	odp_packet_free(pkt);
}

static void parser_test_vlan_qinq_ipv4_udp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_vlan_qinq_ipv4_udp,
			      sizeof(test_packet_vlan_qinq_ipv4_udp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_vlan(pkt));
	CU_ASSERT(odp_packet_has_vlan_qinq(pkt));
	CU_ASSERT(odp_packet_has_ipv4(pkt));
	CU_ASSERT(odp_packet_has_udp(pkt));

	CU_ASSERT(!odp_packet_has_ipv6(pkt));
	CU_ASSERT(!odp_packet_has_tcp(pkt));
	CU_ASSERT(!odp_packet_has_sctp(pkt));

	odp_packet_free(pkt);
}

static void parser_test_ipv4_sctp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_ipv4_sctp,
			      sizeof(test_packet_ipv4_sctp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_ipv4(pkt));
	CU_ASSERT(odp_packet_has_sctp(pkt));

	CU_ASSERT(!odp_packet_has_ipv6(pkt));
	CU_ASSERT(!odp_packet_has_tcp(pkt));
	CU_ASSERT(!odp_packet_has_udp(pkt));

	odp_packet_free(pkt);
}

static void parser_test_ipv6_icmp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_ipv6_icmp,
			      sizeof(test_packet_ipv6_icmp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_ipv6(pkt));
	CU_ASSERT(odp_packet_has_icmp(pkt));

	CU_ASSERT(!odp_packet_has_ipv4(pkt));
	CU_ASSERT(!odp_packet_has_tcp(pkt));
	CU_ASSERT(!odp_packet_has_udp(pkt));
	CU_ASSERT(!odp_packet_has_sctp(pkt));

	odp_packet_free(pkt);
}

static void parser_test_ipv6_tcp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_ipv6_tcp,
			      sizeof(test_packet_ipv6_tcp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_ipv6(pkt));
	CU_ASSERT(odp_packet_has_tcp(pkt));

	CU_ASSERT(!odp_packet_has_ipv4(pkt));
	CU_ASSERT(!odp_packet_has_udp(pkt));
	CU_ASSERT(!odp_packet_has_sctp(pkt));

	odp_packet_free(pkt);
}

static void parser_test_ipv6_udp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_ipv6_udp,
			      sizeof(test_packet_ipv6_udp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_ipv6(pkt));
	CU_ASSERT(odp_packet_has_udp(pkt));

	CU_ASSERT(!odp_packet_has_ipv4(pkt));
	CU_ASSERT(!odp_packet_has_tcp(pkt));
	CU_ASSERT(!odp_packet_has_sctp(pkt));

	odp_packet_free(pkt);
}

static void parser_test_vlan_ipv6_udp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_vlan_ipv6_udp,
			      sizeof(test_packet_vlan_ipv6_udp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_vlan(pkt));
	CU_ASSERT(odp_packet_has_ipv6(pkt));
	CU_ASSERT(odp_packet_has_udp(pkt));

	CU_ASSERT(!odp_packet_has_ipv4(pkt));
	CU_ASSERT(!odp_packet_has_tcp(pkt));
	CU_ASSERT(!odp_packet_has_sctp(pkt));

	odp_packet_free(pkt);
}

static void parser_test_ipv6_sctp(void)
{
	odp_packet_t pkt;

	pkt = loopback_packet(pktio_a, pktio_b, test_packet_ipv6_sctp,
			      sizeof(test_packet_ipv6_sctp));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_eth(pkt));
	CU_ASSERT(odp_packet_has_ipv6(pkt));
	CU_ASSERT(odp_packet_has_sctp(pkt));

	CU_ASSERT(!odp_packet_has_ipv4(pkt));
	CU_ASSERT(!odp_packet_has_tcp(pkt));
	CU_ASSERT(!odp_packet_has_udp(pkt));

	odp_packet_free(pkt);
}

int parser_suite_init(void)
{
	int i;

	if (getenv("ODP_WAIT_FOR_NETWORK"))
		wait_for_network = true;

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

	if (pkt_pool_create() != 0) {
		printf("Error: failed to create parser pool\n");
		return -1;
	}

	/* Create pktios and associate input/output queues */
	for (i = 0; i < num_ifaces; ++i) {
		pktio_info_t *io;

		io = &pktios[i];
		io->name = iface_name[i];
		io->hdl   = create_pktio(i, parser_pool);
		if (io->hdl == ODP_PKTIO_INVALID) {
			printf("Error: failed to open iface");
			return -1;
		}

		if (odp_pktout_queue(io->hdl, &io->pktout, 1) != 1) {
			printf("Error: failed to start iface: %s\n", io->name);
			return -1;
		}

		if (odp_pktin_queue(io->hdl, &io->pktin, 1) != 1) {
			printf("Error: failed to start iface: %s\n", io->name);
			return -1;
		}

		if (odp_pktio_start(io->hdl)) {
			printf("Error: failed to start iface: %s\n", io->name);
			return -1;
		}

		wait_linkup(io->hdl);
	}

	pktio_a = &pktios[0];
	pktio_b = &pktios[1];
	if (num_ifaces == 1)
		pktio_b = pktio_a;

	return 0;
}

int parser_suite_term(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < num_ifaces; ++i) {
		if (odp_pktio_stop(pktios[i].hdl)) {
			printf("Error: failed to stop pktio: %s\n",
			       pktios[i].name);
			ret = -1;
		}
		if (odp_pktio_close(pktios[i].hdl)) {
			printf("Error: failed to close pktio: %s\n",
			       pktios[i].name);
			ret = -1;
		}
	}

	if (odp_pool_destroy(parser_pool) != 0) {
		printf("Error: failed to destroy packet pool\n");
		ret = -1;
	}

	if (odp_cunit_print_inactive())
		ret = -1;

	return ret;
}

/**
 * Certain tests can only be run with 'loop' pktio.
 */
static int loop_pktio(void)
{
	if (strcmp(iface_name[0], "loop") == 0)
		return ODP_TEST_ACTIVE;
	else
		return ODP_TEST_INACTIVE;
}

odp_testinfo_t parser_suite[] = {
	ODP_TEST_INFO(parser_test_arp),
	ODP_TEST_INFO(parser_test_ipv4_icmp),
	ODP_TEST_INFO(parser_test_ipv4_tcp),
	ODP_TEST_INFO(parser_test_ipv4_udp),
	ODP_TEST_INFO_CONDITIONAL(parser_test_vlan_ipv4_udp, loop_pktio),
	ODP_TEST_INFO_CONDITIONAL(parser_test_vlan_qinq_ipv4_udp, loop_pktio),
	ODP_TEST_INFO(parser_test_ipv4_sctp),
	ODP_TEST_INFO(parser_test_ipv6_icmp),
	ODP_TEST_INFO(parser_test_ipv6_tcp),
	ODP_TEST_INFO(parser_test_ipv6_udp),
	ODP_TEST_INFO_CONDITIONAL(parser_test_vlan_ipv6_udp, loop_pktio),
	ODP_TEST_INFO(parser_test_ipv6_sctp),
	ODP_TEST_INFO_NULL
};

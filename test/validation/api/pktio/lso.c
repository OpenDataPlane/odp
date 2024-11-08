/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2024 Nokia
 */

#include <odp_api.h>
#include <odp_cunit_common.h>
#include <test_packet_ipv4.h>
#include <test_packet_custom.h>

#include <odp/helper/odph_api.h>

#include "lso.h"

#define MAX_NUM_IFACES  2
#define PKT_POOL_NUM    256
#define PKT_POOL_LEN    (2 * 1024)

/* Maximum number of segments test is prepared to receive per outgoing packet */
#define MAX_NUM_SEG     256

/* Constants specific to the lso_test() family of tests */
#define LSO_TEST_MARKER_ETHERTYPE 0x88B6 /* Local experimental Ethertype */
#define LSO_TEST_CUSTOM_ETHERTYPE 0x88B5 /* Must match test packets. */
#define LSO_TEST_CUSTOM_ETH_SEGNUM_OFFSET 16
#define LSO_TEST_CUSTOM_ETH_BITS_OFFSET LSO_TEST_CUSTOM_ETH_SEGNUM_OFFSET /* Intentional overlap */
#define LSO_TEST_MIN_ETH_PKT_LEN 60  /* CRC not included in ODP packets */
#define LSO_TEST_IPV4_FLAG_MF 0x2000 /* More fragments flag within the frag_offset field */
#define LSO_TEST_IPV4_FLAG_DF 0x4000 /* Don't fragment flag within the frag_offset field */
#define LSO_TEST_IPV4_FRAG_OFFS_MASK 0x1fff /* Fragment offset bits in the frag_offset field */
/* Segment number field value in the original packet. Nonzero to verify that the LSO operation
 * adds to the value instead of simply overwriting it. We use binary 10101010 bit pattern in the
 * most significant byte for testing overlapping write bits operations */
#define LSO_TEST_CUSTOM_ETH_SEGNUM 0xaafe
/* Parameters for write bits custom operation. These should flip the corresponding bit pairs
 * of the original packet (in the most significant byte of the segment number field */
#define LSO_TEST_FIRST_SEG_MASK   (3 << 2)
#define LSO_TEST_FIRST_SEG_VALUE ((1 << 2) | 1) /* set an extra bit that must be ignored */
#define LSO_TEST_MIDDLE_SEG_MASK  (3 << 4)
#define LSO_TEST_MIDDLE_SEG_VALUE (1 << 4)
#define LSO_TEST_LAST_SEG_MASK    (3 << 6)
#define LSO_TEST_LAST_SEG_VALUE   (1 << 6)

/* Pktio interface info
 */
typedef struct {
	const char *name;
	odp_pktio_t hdl;
	odp_pktout_queue_t pktout;
	odp_pktin_queue_t pktin;
	odp_pktio_capability_t capa;
} pktio_info_t;

/* Interface names used for testing */
static const char *iface_name[MAX_NUM_IFACES];

/* Test interfaces */
static pktio_info_t pktios[MAX_NUM_IFACES];
static pktio_info_t *pktio_a;
static pktio_info_t *pktio_b;

/* Number of interfaces being used (1=loopback, 2=pair) */
static int num_ifaces;

/* Some interface types cannot be restarted.
 * These control test case execution in that case. */
static int num_starts;
static int disable_restart;

/* While testing real-world interfaces additional time may be needed for
 * external network to enable link to pktio interface that just become up. */
static int wait_for_network;

/* LSO test packet pool */
odp_pool_t lso_pool = ODP_POOL_INVALID;

/* Check test packet size */
ODP_STATIC_ASSERT(sizeof(test_packet_ipv4_udp_1500) == 1500, "error: size is not 1500");
ODP_STATIC_ASSERT(sizeof(test_packet_ipv4_udp_325) == 325, "error: size is not 325");
ODP_STATIC_ASSERT(sizeof(test_packet_custom_eth_1) == 723, "error: size is not 723");

static inline void wait_linkup(odp_pktio_t pktio)
{
	/* wait 1 second for link up */
	uint64_t wait_ns = (10 * ODP_TIME_MSEC_IN_NS);
	int wait_num = 100;
	int i;
	int ret = -1;

	for (i = 0; i < wait_num; i++) {
		ret = odp_pktio_link_status(pktio);
		if (ret == ODP_PKTIO_LINK_STATUS_UNKNOWN || ret == ODP_PKTIO_LINK_STATUS_UP)
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
		ODPH_ERR("Pool capability failed\n");
		return -1;
	}

	if (capa.pkt.max_num && capa.pkt.max_num < PKT_POOL_NUM) {
		ODPH_ERR("Packet pool size not supported. Max %" PRIu32 "\n", capa.pkt.max_num);
		return -1;
	} else if (capa.pkt.max_len && capa.pkt.max_len < PKT_POOL_LEN) {
		ODPH_ERR("Packet length not supported.\n");
		return -1;
	} else if (capa.pkt.max_seg_len &&
		   capa.pkt.max_seg_len < PKT_POOL_LEN) {
		ODPH_ERR("Segment length not supported.\n");
		return -1;
	}

	odp_pool_param_init(&params);
	params.pkt.seg_len = PKT_POOL_LEN;
	params.pkt.len     = PKT_POOL_LEN;
	params.pkt.num     = PKT_POOL_NUM;
	params.type        = ODP_POOL_PACKET;

	lso_pool = odp_pool_create("lso_pool", &params);
	if (lso_pool == ODP_POOL_INVALID) {
		ODPH_ERR("Packet pool create failed.\n");
		return -1;
	}

	return 0;
}

static odp_pktio_t create_pktio(int idx, const char *name, odp_pool_t pool)
{
	odp_pktio_t pktio;
	odp_pktio_config_t config;
	odp_pktio_param_t pktio_param;
	odp_pktio_capability_t *capa;
	int tx = (idx == 0) ? 1 : 0;
	int rx = (idx == 0) ? 0 : 1;

	if (num_ifaces == 1) {
		tx = 1;
		rx = 1;
	}

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	pktio = odp_pktio_open(name, pool, &pktio_param);
	pktios[idx].hdl  = pktio;
	pktios[idx].name = name;
	if (pktio == ODP_PKTIO_INVALID) {
		ODPH_ERR("Failed to open %s\n", name);
		return ODP_PKTIO_INVALID;
	}

	if (odp_pktio_capability(pktio, &pktios[idx].capa)) {
		ODPH_ERR("Pktio capa failed: %s\n", name);
		return ODP_PKTIO_INVALID;
	}

	capa = &pktios[idx].capa;

	odp_pktio_config_init(&config);

	if (tx) {
		if (capa->config.enable_lso)
			config.enable_lso = 1;
		else
			ODPH_DBG("LSO not supported\n");
	}

	if (rx) {
		config.parser.layer = ODP_PROTO_LAYER_ALL;
		if (capa->config.pktin.bit.ipv4_chksum)
			config.pktin.bit.ipv4_chksum = 1;
		else
			ODPH_DBG("IPv4 checksum not verified\n");
	}

	if (odp_pktio_config(pktio, &config)) {
		ODPH_ERR("Failed to configure %s\n", name);
		return ODP_PKTIO_INVALID;
	}

	/* By default, single input and output queue is used */
	if (odp_pktin_queue_config(pktio, NULL)) {
		ODPH_ERR("Failed to config input queue for %s\n", name);
		return ODP_PKTIO_INVALID;
	}
	if (odp_pktout_queue_config(pktio, NULL)) {
		ODPH_ERR("Failed to config output queue for %s\n", name);
		return ODP_PKTIO_INVALID;
	}

	if (wait_for_network)
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS / 4);

	return pktio;
}

static odp_packet_t create_packet(const uint8_t *data, uint32_t len)
{
	odp_packet_t pkt;

	pkt = odp_packet_alloc(lso_pool, len);
	if (pkt == ODP_PACKET_INVALID)
		return ODP_PACKET_INVALID;

	if (odp_packet_copy_from_mem(pkt, 0, len, data)) {
		ODPH_ERR("Failed to copy test packet data\n");
		odp_packet_free(pkt);
		return ODP_PACKET_INVALID;
	}

	odp_packet_l2_offset_set(pkt, 0);

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

static odp_packet_t create_packet_for_pktio(const uint8_t *data, uint32_t len,
					    odp_pktio_t src, odp_pktio_t dst)
{
	odp_packet_t pkt;

	pkt = create_packet(data, len);
	if (pkt != ODP_PACKET_INVALID) {
		pktio_pkt_set_macs(pkt, src, dst);
		CU_ASSERT(odp_packet_has_lso_request(pkt) == 0);
	}
	return pkt;
}

static int send_packet(odp_lso_profile_t lso_profile, pktio_info_t *pktio,
		       odp_packet_t pkt, uint32_t hdr_len, uint32_t max_payload,
		       uint32_t l3_offset, int use_opt)
{
	int ret;
	odp_packet_lso_opt_t lso_opt;
	odp_packet_lso_opt_t *opt_ptr = NULL;
	int retries = 10;

	memset(&lso_opt, 0, sizeof(odp_packet_lso_opt_t));
	lso_opt.lso_profile     = lso_profile;
	lso_opt.payload_offset  = hdr_len;
	lso_opt.max_payload_len = max_payload;

	if (use_opt) {
		opt_ptr = &lso_opt;
	} else {
		if (odp_packet_lso_request(pkt, &lso_opt)) {
			CU_FAIL("LSO request failed");
			return -1;
		}

		CU_ASSERT(odp_packet_has_lso_request(pkt));
		CU_ASSERT(odp_packet_payload_offset(pkt) == hdr_len);
	}

	if (l3_offset)
		odp_packet_l3_offset_set(pkt, l3_offset);

	while (retries) {
		ret = odp_pktout_send_lso(pktio->pktout, &pkt, 1, opt_ptr);

		CU_ASSERT_FATAL(ret < 2);

		if (ret < 0) {
			CU_FAIL("LSO send failed\n");
			odp_packet_free(pkt);
			return -1;
		}
		if (ret == 1)
			break;

		odp_time_wait_ns(10 * ODP_TIME_MSEC_IN_NS);
		retries--;
	}

	if (ret < 1) {
		CU_FAIL("LSO send timeout\n");
		odp_packet_free(pkt);
		return -1;
	}

	return 0;
}

static uint16_t ethertype(odp_packet_t pkt)
{
	uint32_t len;
	odph_ethhdr_t *eth = odp_packet_l2_ptr(pkt, &len);
	odp_u16be_t type;

	if (len < sizeof(*eth))
		return 0;
	memcpy(&type, &eth->type, sizeof(type));
	return odp_be_to_cpu_16(type);
}

static int recv_packets(pktio_info_t *pktio_info, uint64_t timeout_ns,
			int (*is_test_pkt)(odp_packet_t),
			odp_packet_t *pkt_out, int max_num)
{
	odp_packet_t pkt;
	odp_time_t wait_time, end;
	int ret;
	odp_pktin_queue_t pktin = pktio_info->pktin;
	int num = 0;

	wait_time = odp_time_local_from_ns(timeout_ns);
	end = odp_time_sum(odp_time_local(), wait_time);

	while (1) {
		pkt = ODP_PACKET_INVALID;
		ret = odp_pktin_recv(pktin, &pkt, 1);

		CU_ASSERT_FATAL(ret < 2);
		if (ret < 0) {
			CU_FAIL("Packet receive failed\n");
			if (num)
				odp_packet_free_multi(pkt_out, num);
			return -1;
		}

		if (ret == 1) {
			CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
			if (ethertype(pkt) == LSO_TEST_MARKER_ETHERTYPE) {
				odp_packet_free(pkt);
				break;
			}
			if (is_test_pkt(pkt)) {
				pkt_out[num] = pkt;
				num++;
			} else {
				odp_packet_free(pkt);
			}
			if (num == max_num) {
				CU_FAIL("Too many packets received\n");
				return num;
			}
		}

		if (odp_time_cmp(end, odp_time_local()) < 0) {
			CU_FAIL("Timeout when waiting for end marker packet");
			break;
		}
	};

	return num;
}

static int compare_data(odp_packet_t pkt, uint32_t offset, const uint8_t *data, uint32_t len)
{
	uint32_t i;
	uint8_t *u8;

	for (i = 0; i < len; i++) {
		u8 = odp_packet_offset(pkt, offset + i, NULL, NULL);
		if (*u8 != data[i])
			return i;
	}

	return -1;
}

static int start_interfaces(void)
{
	int i;

	for (i = 0; i < num_ifaces; ++i) {
		odp_pktio_t pktio = pktios[i].hdl;

		if (odp_pktio_start(pktio)) {
			ODPH_ERR("Failed to start interface: %s\n", pktios[i].name);
			return -1;
		}

		wait_linkup(pktio);
	}

	return 0;
}

static int stop_interfaces(void)
{
	int i;

	for (i = 0; i < num_ifaces; ++i) {
		odp_pktio_t pktio = pktios[i].hdl;

		if (odp_pktio_stop(pktio)) {
			ODPH_ERR("Failed to stop interface: %s\n", pktios[i].name);
			return -1;
		}
	}

	return 0;
}

int lso_suite_init(void)
{
	int i;

	if (getenv("ODP_PKTIO_TEST_DISABLE_START_STOP"))
		disable_restart = 1;

	if (getenv("ODP_WAIT_FOR_NETWORK"))
		wait_for_network = 1;

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
		ODPH_ERR("Failed to create pool\n");
		return -1;
	}

	/* Create pktios and associate input/output queues */
	for (i = 0; i < num_ifaces; ++i) {
		odp_pktio_t pktio;
		const char *name = iface_name[i];

		pktio = create_pktio(i, name, lso_pool);

		if (pktio == ODP_PKTIO_INVALID) {
			ODPH_ERR("Failed to open interface: %s\n", name);
			return -1;
		}

		if (odp_pktout_queue(pktio, &pktios[i].pktout, 1) != 1) {
			ODPH_ERR("Failed to get pktout queue: %s\n", name);
			return -1;
		}

		if (odp_pktin_queue(pktio, &pktios[i].pktin, 1) != 1) {
			ODPH_ERR("Failed to get pktin queue: %s\n", name);
			return -1;
		}
	}

	pktio_a = &pktios[0];
	pktio_b = &pktios[1];
	if (num_ifaces == 1)
		pktio_b = pktio_a;

	return 0;
}

int lso_suite_term(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < num_ifaces; ++i) {
		if (odp_pktio_close(pktios[i].hdl)) {
			ODPH_ERR("Failed to close pktio: %s\n", pktios[i].name);
			ret = -1;
		}
	}

	if (odp_pool_destroy(lso_pool) != 0) {
		ODPH_ERR("Failed to destroy pool\n");
		ret = -1;
	}

	if (odp_cunit_print_inactive())
		ret = -1;

	return ret;
}

static int check_lso_custom(void)
{
	if (pktio_a->capa.lso.max_profiles == 0 || pktio_a->capa.lso.max_profiles_per_pktio == 0)
		return ODP_TEST_INACTIVE;

	if (pktio_a->capa.lso.proto.custom == 0)
		return ODP_TEST_INACTIVE;

	if (pktio_a->capa.lso.mod_op.add_segment_num == 0 &&
	    pktio_a->capa.lso.mod_op.write_bits == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int check_lso_custom_segnum(void)
{
	if (check_lso_custom() == ODP_TEST_INACTIVE)
		return ODP_TEST_INACTIVE;

	if (pktio_a->capa.lso.mod_op.add_segment_num == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int check_lso_custom_segs(uint32_t num)
{
	if (check_lso_custom() == ODP_TEST_INACTIVE)
		return ODP_TEST_INACTIVE;

	if (num > pktio_a->capa.lso.max_segments)
		return ODP_TEST_INACTIVE;

	if (disable_restart && num_starts > 0)
		return ODP_TEST_INACTIVE;

	/* Run only one packet IO test case when interface restart is disabled */
	num_starts++;

	return ODP_TEST_ACTIVE;
}

static int check_lso_custom_segs_1(void)
{
	return check_lso_custom_segs(1);
}

static int check_lso_custom_segs_2(void)
{
	return check_lso_custom_segs(2);
}

static int check_lso_custom_segs_3(void)
{
	return check_lso_custom_segs(3);
}

static int check_lso_ipv4(void)
{
	if (pktio_a->capa.lso.max_profiles == 0 || pktio_a->capa.lso.max_profiles_per_pktio == 0)
		return ODP_TEST_INACTIVE;

	if (pktio_a->capa.lso.proto.ipv4 == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int check_lso_ipv4_segs(uint32_t num)
{
	if (check_lso_ipv4() == ODP_TEST_INACTIVE)
		return ODP_TEST_INACTIVE;

	if (num > pktio_a->capa.lso.max_segments)
		return ODP_TEST_INACTIVE;

	if (disable_restart && num_starts > 0)
		return ODP_TEST_INACTIVE;

	num_starts++;

	return ODP_TEST_ACTIVE;
}

static int check_lso_ipv4_segs_1(void)
{
	return check_lso_ipv4_segs(1);
}

static int check_lso_ipv4_segs_2(void)
{
	return check_lso_ipv4_segs(2);
}

static int check_lso_ipv4_segs_3(void)
{
	return check_lso_ipv4_segs(3);
}

static void lso_capability(void)
{
	/* LSO not supported when max_profiles is zero */
	if (pktio_a->capa.lso.max_profiles == 0 || pktio_a->capa.lso.max_profiles_per_pktio == 0)
		return;

	CU_ASSERT(pktio_a->capa.lso.max_profiles >= pktio_a->capa.lso.max_profiles_per_pktio);
	CU_ASSERT(pktio_a->capa.lso.max_packet_segments > 0);
	/* At least 32 bytes of payload */
	CU_ASSERT(pktio_a->capa.lso.max_payload_len >= 32);
	/* LSO can create at least two segments */
	CU_ASSERT(pktio_a->capa.lso.max_segments > 1);
	/* LSO can copy at least Ethernet header to segments */
	CU_ASSERT(pktio_a->capa.lso.max_payload_offset >= ODPH_ETHHDR_LEN);

	if (pktio_a->capa.lso.proto.custom) {
		CU_ASSERT(pktio_a->capa.lso.max_num_custom > 0);

		CU_ASSERT(pktio_a->capa.lso.mod_op.add_segment_num ||
			  pktio_a->capa.lso.mod_op.add_payload_len ||
			  pktio_a->capa.lso.mod_op.add_payload_offset ||
			  pktio_a->capa.lso.mod_op.write_bits)
	}
}

static void lso_create_ipv4_profile(void)
{
	odp_lso_profile_param_t param;
	odp_lso_profile_t profile;

	odp_lso_profile_param_init(&param);
	CU_ASSERT(param.lso_proto == ODP_LSO_PROTO_NONE);
	CU_ASSERT(param.custom.num_custom == 0);

	param.lso_proto = ODP_LSO_PROTO_IPV4;

	profile = odp_lso_profile_create(pktio_a->hdl, &param);
	CU_ASSERT_FATAL(profile != ODP_LSO_PROFILE_INVALID);

	CU_ASSERT_FATAL(odp_lso_profile_destroy(profile) == 0);
}

static void lso_create_custom_profile(void)
{
	odp_lso_profile_param_t param_0, param_1;
	odp_lso_profile_t profile_0, profile_1;

	odp_lso_profile_param_init(&param_0);
	CU_ASSERT(param_0.lso_proto == ODP_LSO_PROTO_NONE);
	CU_ASSERT(param_0.custom.num_custom == 0);

	param_0.lso_proto = ODP_LSO_PROTO_CUSTOM;
	param_0.custom.num_custom = 1;
	param_0.custom.field[0].mod_op = ODP_LSO_ADD_SEGMENT_NUM;
	param_0.custom.field[0].offset = 16;
	param_0.custom.field[0].size   = 2;

	profile_0 = odp_lso_profile_create(pktio_a->hdl, &param_0);
	CU_ASSERT_FATAL(profile_0 != ODP_LSO_PROFILE_INVALID);

	CU_ASSERT_FATAL(odp_lso_profile_destroy(profile_0) == 0);

	if (pktio_a->capa.lso.max_profiles < 2 || pktio_a->capa.lso.max_num_custom < 3)
		return;

	if (pktio_a->capa.lso.mod_op.add_payload_len == 0 ||
	    pktio_a->capa.lso.mod_op.add_payload_offset == 0)
		return;

	odp_lso_profile_param_init(&param_1);
	param_1.lso_proto = ODP_LSO_PROTO_CUSTOM;
	param_1.custom.num_custom = 3;
	param_1.custom.field[0].mod_op = ODP_LSO_ADD_PAYLOAD_LEN;
	param_1.custom.field[0].offset = 14;
	param_1.custom.field[0].size   = 2;
	param_1.custom.field[1].mod_op = ODP_LSO_ADD_SEGMENT_NUM;
	param_1.custom.field[1].offset = 16;
	param_1.custom.field[1].size   = 2;
	param_1.custom.field[2].mod_op = ODP_LSO_ADD_PAYLOAD_OFFSET;
	param_1.custom.field[2].offset = 18;
	param_1.custom.field[2].size   = 2;

	profile_0 = odp_lso_profile_create(pktio_a->hdl, &param_0);
	CU_ASSERT_FATAL(profile_0 != ODP_LSO_PROFILE_INVALID);

	profile_1 = odp_lso_profile_create(pktio_a->hdl, &param_1);
	CU_ASSERT_FATAL(profile_1 != ODP_LSO_PROFILE_INVALID);

	CU_ASSERT_FATAL(odp_lso_profile_destroy(profile_1) == 0);
	CU_ASSERT_FATAL(odp_lso_profile_destroy(profile_0) == 0);
}

static void test_lso_request_clear(odp_lso_profile_t lso_profile, const uint8_t *data,
				   uint32_t len, uint32_t hdr_len, uint32_t max_payload)
{
	odp_packet_t pkt;
	odp_packet_lso_opt_t lso_opt;

	memset(&lso_opt, 0, sizeof(odp_packet_lso_opt_t));
	lso_opt.lso_profile     = lso_profile;
	lso_opt.payload_offset  = hdr_len;
	lso_opt.max_payload_len = max_payload;

	pkt = create_packet(data, len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_lso_request(pkt) == 0);
	CU_ASSERT(odp_packet_lso_request(pkt, &lso_opt) == 0);
	CU_ASSERT(odp_packet_has_lso_request(pkt) != 0);
	CU_ASSERT(odp_packet_payload_offset(pkt) == hdr_len);
	odp_packet_lso_request_clr(pkt);
	CU_ASSERT(odp_packet_has_lso_request(pkt) == 0);
	CU_ASSERT(odp_packet_payload_offset(pkt) == hdr_len);
	CU_ASSERT(odp_packet_payload_offset_set(pkt, ODP_PACKET_OFFSET_INVALID) == 0);
	CU_ASSERT(odp_packet_payload_offset(pkt) == ODP_PACKET_OFFSET_INVALID);

	odp_packet_free(pkt);
}

static int send_marker(pktio_info_t *src, pktio_info_t *dst)
{
	odph_ethhdr_t marker = {.type = odp_cpu_to_be_16(LSO_TEST_MARKER_ETHERTYPE)};
	odp_packet_t pkt;
	int retries = 10;

	pkt = create_packet_for_pktio((uint8_t *)&marker, sizeof(marker), src->hdl, dst->hdl);
	if (pkt == ODP_PACKET_INVALID) {
		CU_FAIL("Marker allocation failed");
		return -1;
	}

	while (retries) {
		int ret = odp_pktout_send(src->pktout, &pkt, 1);

		CU_ASSERT_FATAL(ret < 2);
		if (ret < 0) {
			CU_FAIL("Marker sending failed");
			odp_packet_free(pkt);
			return -1;
		}
		if (ret == 1)
			return 0;

		odp_time_wait_ns(10 * ODP_TIME_MSEC_IN_NS);
		retries--;
	}

	CU_FAIL("Marker sending timeout");
	odp_packet_free(pkt);
	return -1;
}

static void lso_test(odp_lso_profile_param_t param, uint32_t max_payload,
		     const uint8_t *test_packet, uint32_t pkt_len,
		     uint32_t hdr_len, uint32_t l3_offset,
		     int use_opt,
		     int (*is_test_pkt)(odp_packet_t),
		     void (*update_hdr)(uint8_t *hdr, uint32_t hdr_len, odp_packet_t pkt,
					uint16_t seg_num, uint16_t seg_offset, uint16_t num_segs))
{
	int ret, num, seg_num;
	odp_lso_profile_t profile;
	odp_packet_t pkt;
	uint8_t orig_hdr[hdr_len];
	uint32_t offset, len, payload_len, payload_sum;
	odp_packet_t pkt_out[MAX_NUM_SEG];
	uint32_t sent_payload = pkt_len - hdr_len;

	profile = odp_lso_profile_create(pktio_a->hdl, &param);
	CU_ASSERT_FATAL(profile != ODP_LSO_PROFILE_INVALID);
	memset(&param, 0, sizeof(param)); /* ODP is not supposed to use param anymore */

	CU_ASSERT_FATAL(start_interfaces() == 0);

	test_lso_request_clear(profile, test_packet, pkt_len, hdr_len, max_payload);

	pkt = create_packet_for_pktio(test_packet, pkt_len, pktio_a->hdl, pktio_b->hdl);
	if (pkt == ODP_PACKET_INVALID) {
		CU_FAIL("failed to generate test packet");
		return;
	}

	CU_ASSERT(odp_packet_copy_to_mem(pkt, 0, hdr_len, orig_hdr) == 0);

	ret = send_packet(profile, pktio_a, pkt, hdr_len, max_payload, l3_offset, use_opt);
	CU_ASSERT_FATAL(ret == 0);
	ret = send_marker(pktio_a, pktio_b);
	CU_ASSERT_FATAL(ret == 0);

	ODPH_DBG("\n    Sent payload length:     %u bytes\n", sent_payload);

	/* Wait a bit to receive all created segments. Timeout and MAX_NUM_SEG values should be
	 * large enough to ensure that we receive all created segments. */
	num = recv_packets(pktio_b, 100 * ODP_TIME_MSEC_IN_NS, is_test_pkt, pkt_out, MAX_NUM_SEG);
	CU_ASSERT(num > 0);
	CU_ASSERT(num < MAX_NUM_SEG);

	offset = hdr_len;
	payload_sum = 0;
	for (seg_num = 0; seg_num < num; seg_num++) {
		uint8_t expected_hdr[hdr_len];
		odp_packet_t seg = pkt_out[seg_num];

		len = odp_packet_len(seg);
		CU_ASSERT_FATAL(len > hdr_len);
		/* Assume no Ethernet padding in test packets */
		CU_ASSERT(len >= LSO_TEST_MIN_ETH_PKT_LEN);
		payload_len = len - hdr_len;

		ODPH_DBG("    LSO segment[%u] payload:  %u bytes\n", seg_num, payload_len);

		memcpy(expected_hdr, orig_hdr, sizeof(expected_hdr));
		if (num > 1)
			update_hdr(expected_hdr, hdr_len, seg, seg_num, offset - hdr_len, num);

		if (compare_data(seg, 0, expected_hdr, hdr_len) >= 0) {
			ODPH_ERR("    Header compare failed\n");
			CU_FAIL("Header comparison failed");
		}

		CU_ASSERT(payload_len <= max_payload);

		if (compare_data(seg, hdr_len, test_packet + offset, payload_len) >= 0) {
			ODPH_ERR("    Payload compare failed at offset %u\n", offset);
			CU_FAIL("Payload comparison failed");
		}

		offset      += payload_len;
		payload_sum += payload_len;
	}

	ODPH_DBG("    Received payload length: %u bytes\n", payload_sum);

	CU_ASSERT(payload_sum == sent_payload);

	if (num > 0)
		odp_packet_free_multi(pkt_out, num);

	CU_ASSERT_FATAL(stop_interfaces() == 0);

	CU_ASSERT_FATAL(odp_lso_profile_destroy(profile) == 0);
}

static int is_custom_eth_test_pkt(odp_packet_t pkt)
{
	return ethertype(pkt) == LSO_TEST_CUSTOM_ETHERTYPE;
}

static void update_custom_hdr_segnum(uint8_t *hdr, uint32_t hdr_len, odp_packet_t pkt,
				     uint16_t seg_num, uint16_t seg_offset, uint16_t num_segs)
{
	(void)pkt;
	(void)seg_offset;
	(void)hdr_len;
	(void)num_segs;
	odp_u16be_t segnum_be = odp_cpu_to_be_16(seg_num + LSO_TEST_CUSTOM_ETH_SEGNUM);

	memcpy(hdr + LSO_TEST_CUSTOM_ETH_SEGNUM_OFFSET, &segnum_be, sizeof(segnum_be));
}

static void update_custom_hdr_bits(uint8_t *hdr, uint32_t hdr_len, odp_packet_t pkt,
				   uint16_t seg_num, uint16_t seg_offset, uint16_t num_segs)
{
	(void)hdr_len;
	(void)pkt;
	(void)seg_offset;
	uint8_t value;

	if (seg_num == 0) {
		value = LSO_TEST_FIRST_SEG_VALUE & LSO_TEST_FIRST_SEG_MASK;
		hdr[LSO_TEST_CUSTOM_ETH_BITS_OFFSET] &= ~LSO_TEST_FIRST_SEG_MASK;
		hdr[LSO_TEST_CUSTOM_ETH_BITS_OFFSET] |= value;
	} else if (seg_num < num_segs - 1) {
		value = LSO_TEST_MIDDLE_SEG_VALUE & LSO_TEST_MIDDLE_SEG_MASK;
		hdr[LSO_TEST_CUSTOM_ETH_BITS_OFFSET] &= ~LSO_TEST_MIDDLE_SEG_MASK;
		hdr[LSO_TEST_CUSTOM_ETH_BITS_OFFSET] |= value;
	} else {
		value = LSO_TEST_LAST_SEG_VALUE & LSO_TEST_LAST_SEG_MASK;
		hdr[LSO_TEST_CUSTOM_ETH_BITS_OFFSET] &= ~LSO_TEST_LAST_SEG_MASK;
		hdr[LSO_TEST_CUSTOM_ETH_BITS_OFFSET] |= value;
	}
}

static void update_custom_hdr_segnum_bits(uint8_t *hdr, uint32_t hdr_len, odp_packet_t pkt,
					  uint16_t seg_num, uint16_t seg_offset, uint16_t num_segs)
{
	update_custom_hdr_segnum(hdr, hdr_len, pkt, seg_num, seg_offset, num_segs);
	update_custom_hdr_bits(hdr, hdr_len, pkt, seg_num, seg_offset, num_segs);
}

static void add_profile_param_custom_segnum(odp_lso_profile_param_t *param)
{
	uint8_t idx = param->custom.num_custom++;

	param->custom.field[idx].mod_op = ODP_LSO_ADD_SEGMENT_NUM;
	param->custom.field[idx].offset = LSO_TEST_CUSTOM_ETH_SEGNUM_OFFSET;
	param->custom.field[idx].size   = 2;
}

static void add_profile_param_custom_write_bits(odp_lso_profile_param_t *param)
{
	uint8_t idx = param->custom.num_custom++;

	param->custom.field[idx].mod_op = ODP_LSO_WRITE_BITS;
	param->custom.field[idx].offset = LSO_TEST_CUSTOM_ETH_BITS_OFFSET;
	param->custom.field[idx].size   = 1;
	param->custom.field[idx].write_bits.first_seg.mask[0]   = LSO_TEST_FIRST_SEG_MASK;
	param->custom.field[idx].write_bits.first_seg.value[0]  = LSO_TEST_FIRST_SEG_VALUE;
	param->custom.field[idx].write_bits.middle_seg.mask[0]  = LSO_TEST_MIDDLE_SEG_MASK;
	param->custom.field[idx].write_bits.middle_seg.value[0] = LSO_TEST_MIDDLE_SEG_VALUE;
	param->custom.field[idx].write_bits.last_seg.mask[0]    = LSO_TEST_LAST_SEG_MASK;
	param->custom.field[idx].write_bits.last_seg.value[0]   = LSO_TEST_LAST_SEG_VALUE;
}

static void lso_send_custom_eth(const uint8_t *test_packet, uint32_t pkt_len, uint32_t max_payload,
				int use_opt)
{
	odp_lso_profile_param_t param;
	const uint32_t hdr_len = ODPH_ETHHDR_LEN + 8;	/* Ethernet header + custom header 8B */
	uint32_t l3_offset = 0;

	if (pktio_a->capa.lso.mod_op.add_segment_num) {
		odp_lso_profile_param_init(&param);
		param.lso_proto = ODP_LSO_PROTO_CUSTOM;
		add_profile_param_custom_segnum(&param);
		lso_test(param, max_payload, test_packet, pkt_len, hdr_len, l3_offset, use_opt,
			 is_custom_eth_test_pkt,
			 update_custom_hdr_segnum);
	}
	if (pktio_a->capa.lso.mod_op.write_bits) {
		odp_lso_profile_param_init(&param);
		param.lso_proto = ODP_LSO_PROTO_CUSTOM;
		add_profile_param_custom_write_bits(&param);
		lso_test(param, max_payload, test_packet, pkt_len, hdr_len, l3_offset, use_opt,
			 is_custom_eth_test_pkt,
			 update_custom_hdr_bits);
	}

	if (pktio_a->capa.lso.max_num_custom >= 2 &&
	    pktio_a->capa.lso.mod_op.add_segment_num &&
	    pktio_a->capa.lso.mod_op.write_bits) {
		odp_lso_profile_param_init(&param);
		param.lso_proto = ODP_LSO_PROTO_CUSTOM;
		add_profile_param_custom_segnum(&param);
		add_profile_param_custom_write_bits(&param);
		lso_test(param, max_payload, test_packet, pkt_len, hdr_len, l3_offset, use_opt,
			 is_custom_eth_test_pkt,
			 update_custom_hdr_segnum_bits);
	}
}

static void lso_send_custom_eth_723(uint32_t max_payload, int use_opt)
{
	uint32_t pkt_len = sizeof(test_packet_custom_eth_1);
	odp_u16be_t segnum = odp_cpu_to_be_16(LSO_TEST_CUSTOM_ETH_SEGNUM);
	uint8_t test_pkt[pkt_len];

	memcpy(test_pkt, test_packet_custom_eth_1, pkt_len);
	memcpy(test_pkt + LSO_TEST_CUSTOM_ETH_SEGNUM_OFFSET, &segnum, sizeof(segnum));

	if (max_payload > pktio_a->capa.lso.max_payload_len)
		max_payload = pktio_a->capa.lso.max_payload_len;

	lso_send_custom_eth(test_pkt, pkt_len, max_payload, use_opt);
}

/* No segmentation needed: packet size 723 bytes, LSO segment payload 800 bytes */
static void lso_send_custom_eth_723_800_pkt_meta(void)
{
	lso_send_custom_eth_723(800, 0);
}

static void lso_send_custom_eth_723_800_opt(void)
{
	lso_send_custom_eth_723(800, 1);
}

/* At least 2 segments: packet size 723 bytes, LSO segment payload 500 bytes */
static void lso_send_custom_eth_723_500_pkt_meta(void)
{
	lso_send_custom_eth_723(500, 0);
}

static void lso_send_custom_eth_723_500_opt(void)
{
	lso_send_custom_eth_723(500, 1);
}

/* At least 3 segments: packet size 723 bytes, LSO segment payload 288 bytes */
static void lso_send_custom_eth_723_288_pkt_meta(void)
{
	lso_send_custom_eth_723(288, 0);
}

static void lso_send_custom_eth_723_288_opt(void)
{
	lso_send_custom_eth_723(288, 1);
}

static int is_ipv4_test_pkt(odp_packet_t pkt)
{
	uint32_t len;
	odph_ipv4hdr_t *ip;

	if (!odp_packet_has_ipv4(pkt))
		return 0;

	ip = odp_packet_l3_ptr(pkt, &len);

	if (len < sizeof(*ip) ||
	    odp_be_to_cpu_32(ip->dst_addr) != 0xc0a80101 ||
	    odp_be_to_cpu_32(ip->src_addr) != 0xc0a80102)
		return 0;

	return 1;
}

static void update_ipv4_hdr(uint8_t *hdr, uint32_t hdr_len, odp_packet_t pkt,
			    uint16_t seg_num, uint16_t seg_offset, uint16_t num_segs)
{
	uint32_t l3_offset = ODPH_ETHHDR_LEN;
	uint16_t frag_offset;
	odph_ipv4hdr_t ip;

	CU_ASSERT(odp_packet_has_error(pkt) == 0);

	memcpy(&ip, &hdr[l3_offset], sizeof(ip));

	frag_offset = odp_be_to_cpu_16(ip.frag_offset);
	frag_offset += seg_offset / 8;
	if (seg_num < num_segs - 1)
		frag_offset |= LSO_TEST_IPV4_FLAG_MF;
	ip.tot_len = odp_cpu_to_be_16(odp_packet_len(pkt) - l3_offset);
	ip.frag_offset = odp_cpu_to_be_16(frag_offset);
	ip.chksum = 0;
	ip.chksum = ~odp_chksum_ones_comp16(&ip, hdr_len - l3_offset);
	memcpy(&hdr[l3_offset], &ip, sizeof(ip));
}

static void change_ipv4_frag_offset(uint8_t *ip_packet, uint16_t value, uint16_t mask)
{
	odph_ipv4hdr_t ip;
	uint16_t frag_offset;

	memcpy(&ip, ip_packet, sizeof(ip));
	frag_offset = odp_be_to_cpu_16(ip.frag_offset);
	frag_offset &= ~mask;
	frag_offset |= (value & mask);
	ip.frag_offset = odp_cpu_to_be_16(frag_offset);
	ip.chksum = 0;
	memcpy(ip_packet, &ip, sizeof(ip));
	ip.chksum = ~odp_chksum_ones_comp16(ip_packet, ODPH_IPV4HDR_IHL(ip.ver_ihl) * 4);
	memcpy(ip_packet, &ip, sizeof(ip));
}

static void lso_send_ipv4(const uint8_t *test_packet, uint32_t pkt_len, uint32_t max_payload,
			  int use_opt)
{
	odp_lso_profile_param_t param;
	const uint32_t l3_offset = ODPH_ETHHDR_LEN;
	const uint32_t hdr_len = l3_offset + ODPH_IPV4HDR_LEN;
	uint8_t pkt2[pkt_len];

	odp_lso_profile_param_init(&param);
	param.lso_proto = ODP_LSO_PROTO_IPV4;

	lso_test(param, max_payload, test_packet, pkt_len, hdr_len, l3_offset, use_opt,
		 is_ipv4_test_pkt,
		 update_ipv4_hdr);

	/* Same test with DF set */
	memcpy(pkt2, test_packet, pkt_len);
	change_ipv4_frag_offset(&pkt2[l3_offset], LSO_TEST_IPV4_FLAG_DF, LSO_TEST_IPV4_FLAG_DF);
	lso_test(param, max_payload, pkt2, pkt_len, hdr_len, l3_offset, use_opt,
		 is_ipv4_test_pkt,
		 update_ipv4_hdr);

	/* Same test with a first fragment */
	memcpy(pkt2, test_packet, pkt_len);
	change_ipv4_frag_offset(&pkt2[l3_offset], LSO_TEST_IPV4_FLAG_MF, LSO_TEST_IPV4_FLAG_MF);
	lso_test(param, max_payload, pkt2, pkt_len, hdr_len, l3_offset, use_opt,
		 is_ipv4_test_pkt,
		 update_ipv4_hdr);

	/* Same test with a middle fragment */
	memcpy(pkt2, test_packet, pkt_len);
	change_ipv4_frag_offset(&pkt2[l3_offset], 500, LSO_TEST_IPV4_FRAG_OFFS_MASK);
	change_ipv4_frag_offset(&pkt2[l3_offset], LSO_TEST_IPV4_FLAG_MF, LSO_TEST_IPV4_FLAG_MF);
	lso_test(param, max_payload, pkt2, pkt_len, hdr_len, l3_offset, use_opt,
		 is_ipv4_test_pkt,
		 update_ipv4_hdr);

	/* Same test with a last fragment */
	memcpy(pkt2, test_packet, pkt_len);
	change_ipv4_frag_offset(&pkt2[l3_offset], 500, LSO_TEST_IPV4_FRAG_OFFS_MASK);
	lso_test(param, max_payload, pkt2, pkt_len, hdr_len, l3_offset, use_opt,
		 is_ipv4_test_pkt,
		 update_ipv4_hdr);
}

static void lso_send_ipv4_udp_325(uint32_t max_payload, int use_opt)
{
	uint32_t pkt_len = sizeof(test_packet_ipv4_udp_325);

	if (max_payload > pktio_a->capa.lso.max_payload_len)
		max_payload = pktio_a->capa.lso.max_payload_len;

	lso_send_ipv4(test_packet_ipv4_udp_325, pkt_len, max_payload, use_opt);
}

static void lso_send_ipv4_udp_1500(uint32_t max_payload, int use_opt)
{
	uint32_t pkt_len = sizeof(test_packet_ipv4_udp_1500);

	if (max_payload > pktio_a->capa.lso.max_payload_len)
		max_payload = pktio_a->capa.lso.max_payload_len;

	lso_send_ipv4(test_packet_ipv4_udp_1500, pkt_len, max_payload, use_opt);
}

/* No segmentation needed: packet size 325 bytes, LSO segment payload 700 bytes */
static void lso_send_ipv4_325_700_pkt_meta(void)
{
	lso_send_ipv4_udp_325(700, 0);
}

static void lso_send_ipv4_325_700_opt(void)
{
	lso_send_ipv4_udp_325(700, 1);
}

/* At least 2 segments: packet size 1500 bytes, LSO segment payload 1000 bytes */
static void lso_send_ipv4_1500_1000_pkt_meta(void)
{
	lso_send_ipv4_udp_1500(1000, 0);
}

static void lso_send_ipv4_1500_1000_opt(void)
{
	lso_send_ipv4_udp_1500(1000, 1);
}

/* At least 3 segments: packet size 1500 bytes, LSO segment payload 700 bytes */
static void lso_send_ipv4_1500_700_pkt_meta(void)
{
	lso_send_ipv4_udp_1500(700, 0);
}

static void lso_send_ipv4_1500_700_opt(void)
{
	lso_send_ipv4_udp_1500(700, 1);
}

odp_testinfo_t lso_suite[] = {
	ODP_TEST_INFO(lso_capability),
	ODP_TEST_INFO_CONDITIONAL(lso_create_ipv4_profile, check_lso_ipv4),
	ODP_TEST_INFO_CONDITIONAL(lso_create_custom_profile, check_lso_custom_segnum),
	ODP_TEST_INFO_CONDITIONAL(lso_send_ipv4_325_700_pkt_meta, check_lso_ipv4_segs_1),
	ODP_TEST_INFO_CONDITIONAL(lso_send_ipv4_325_700_opt, check_lso_ipv4_segs_1),
	ODP_TEST_INFO_CONDITIONAL(lso_send_ipv4_1500_1000_pkt_meta, check_lso_ipv4_segs_2),
	ODP_TEST_INFO_CONDITIONAL(lso_send_ipv4_1500_1000_opt, check_lso_ipv4_segs_2),
	ODP_TEST_INFO_CONDITIONAL(lso_send_ipv4_1500_700_pkt_meta, check_lso_ipv4_segs_3),
	ODP_TEST_INFO_CONDITIONAL(lso_send_ipv4_1500_700_opt, check_lso_ipv4_segs_3),
	ODP_TEST_INFO_CONDITIONAL(lso_send_custom_eth_723_800_pkt_meta, check_lso_custom_segs_1),
	ODP_TEST_INFO_CONDITIONAL(lso_send_custom_eth_723_800_opt, check_lso_custom_segs_1),
	ODP_TEST_INFO_CONDITIONAL(lso_send_custom_eth_723_500_pkt_meta, check_lso_custom_segs_2),
	ODP_TEST_INFO_CONDITIONAL(lso_send_custom_eth_723_500_opt, check_lso_custom_segs_2),
	ODP_TEST_INFO_CONDITIONAL(lso_send_custom_eth_723_288_pkt_meta, check_lso_custom_segs_3),
	ODP_TEST_INFO_CONDITIONAL(lso_send_custom_eth_723_288_opt, check_lso_custom_segs_3),
	ODP_TEST_INFO_NULL
};

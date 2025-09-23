/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2020-2025 Nokia
 * Copyright (c) 2020 Marvell
 */

#include <odp_api.h>
#include <odp_cunit_common.h>

#include <odp/helper/odph_api.h>

#include <inttypes.h>
#include <stdlib.h>
#include "parser.h"
#include "lso.h"

#define PKT_BUF_NUM            128
#define PKT_BUF_SIZE           (9 * 1024)
#define PKT_LEN_NORMAL         64
#define PKT_LEN_MAX            (PKT_BUF_SIZE - ODPH_ETHHDR_LEN - \
				ODPH_IPV4HDR_LEN - ODPH_UDPHDR_LEN)

#define NUM_TEST_PKTS          100
#define NUM_RX_ATTEMPTS        200

#define USE_MTU                0
#define MAX_NUM_IFACES         2
#define TEST_SEQ_INVALID       ((uint32_t)~0)
#define TEST_SEQ_MAGIC         0x92749451
#define TX_BATCH_LEN           4
#define PKTV_TX_BATCH_LEN      32
#define PKTV_DEFAULT_SIZE      8
#define EVV_DEFAULT_SIZE       8
#define MAX_QUEUES             128

#define PKTIO_TS_INTERVAL      (10 * ODP_TIME_MSEC_IN_NS)
#define PKTIO_TS_MIN_RES       1000
#define PKTIO_TS_MAX_RES       10000000000

#define PKTIO_SRC_MAC		{1, 2, 3, 4, 5, 6}
#define PKTIO_DST_MAC		{6, 5, 4, 3, 2, 1}
#undef DEBUG_STATS

/** interface names used for testing */
static const char *iface_name[MAX_NUM_IFACES];

/** number of interfaces being used (1=loopback, 2=pair) */
static int num_ifaces;

/** while testing real-world interfaces additional time may be
    needed for external network to enable link to pktio
    interface that just become up.*/
static bool wait_for_network;

/* Dummy global variable to avoid compiler optimizing out API calls */
static volatile uint64_t test_pktio_dummy_u64;

/* Optional test flags that can be or'ed */
typedef enum {
	TEST_WITH_DEF_POOL = 1,
	TEST_WITH_REFS = 2,
} test_flag_values_t;

#define NUM_TEST_FLAGS 2
#define NUM_TEST_FLAG_COMBOS (1 << NUM_TEST_FLAGS)

/** local container for pktio attributes */
typedef struct {
	const char *name;
	odp_pktio_t id;
	odp_pktout_queue_t pktout;
	odp_queue_t queue_out;
	odp_queue_t inq;
	odp_pktin_mode_t in_mode;
	uint64_t aggr_tmo;
} pktio_info_t;

/** magic number and sequence at start of UDP payload */
typedef struct ODP_PACKED {
	odp_u32be_t magic;
	odp_u32be_t seq;
} pkt_head_t;

/** magic number at end of UDP payload */
typedef struct ODP_PACKED {
	odp_u32be_t magic;
} pkt_tail_t;

/** Run mode */
typedef enum {
	PKT_POOL_UNSEGMENTED,
	PKT_POOL_SEGMENTED,
} pkt_segmented_e;

typedef enum {
	TXRX_MODE_SINGLE,
	TXRX_MODE_MULTI,
	TXRX_MODE_MULTI_EVENT
} txrx_mode_e;

typedef enum {
	RECV_TMO,
	RECV_MQ_TMO,
	RECV_MQ_TMO_NO_IDX,
} recv_tmo_mode_e;

typedef enum {
	ETH_UNICAST,
	ETH_BROADCAST,
} eth_addr_type_e;

typedef enum vector_mode_t {
	VECTOR_MODE_DISABLED = 0,
	VECTOR_MODE_PACKET,
	VECTOR_MODE_EVENT
} vector_mode_t;

/** size of transmitted packets */
static uint32_t packet_len = PKT_LEN_NORMAL;

/** default packet pool */
odp_pool_t default_pkt_pool = ODP_POOL_INVALID;

/** default packet vector pool */
odp_pool_t default_pktv_pool = ODP_POOL_INVALID;

/** default event vector pool */
odp_pool_t default_evv_pool = ODP_POOL_INVALID;

/** sequence number of IP packets */
odp_atomic_u32_t ip_seq;

/** Type of pool segmentation */
pkt_segmented_e pool_segmentation = PKT_POOL_UNSEGMENTED;

odp_pool_t pool[MAX_NUM_IFACES] = {ODP_POOL_INVALID, ODP_POOL_INVALID};

odp_pool_t pktv_pool[MAX_NUM_IFACES] = {ODP_POOL_INVALID, ODP_POOL_INVALID};

odp_pool_t evv_pool[MAX_NUM_IFACES] = {ODP_POOL_INVALID, ODP_POOL_INVALID};

static odp_pool_t expected_rx_pool(uint32_t test_flags)
{
	if (test_flags & TEST_WITH_DEF_POOL)
		return default_pkt_pool;

	return pool[num_ifaces - 1];
}

static inline void _pktio_wait_linkup(odp_pktio_t pktio)
{
	/* wait up to 2 seconds for link up */
	uint64_t wait_ns = (10 * ODP_TIME_MSEC_IN_NS);
	int wait_num = 200;
	int i;
	int ret = -1;

	for (i = 0; i < wait_num; i++) {
		ret = odp_pktio_link_status(pktio);
		if (ret == ODP_PKTIO_LINK_STATUS_UNKNOWN || ret == ODP_PKTIO_LINK_STATUS_UP)
			break;
		/* link is down, call status again after delay */
		odp_time_wait_ns(wait_ns);
	}

	if (ret != -1) {
		/* assert only if link state supported and
		 * it's down. */
		CU_ASSERT_FATAL(ret == 1);
	}
}

static void set_pool_len(odp_pool_param_t *params, odp_pool_capability_t *capa)
{
	uint32_t len;
	uint32_t seg_len;

	len = (capa->pkt.max_len && capa->pkt.max_len < PKT_BUF_SIZE) ?
			capa->pkt.max_len : PKT_BUF_SIZE;
	seg_len = (capa->pkt.max_seg_len && capa->pkt.max_seg_len < PKT_BUF_SIZE) ?
			capa->pkt.max_seg_len : PKT_BUF_SIZE;

	switch (pool_segmentation) {
	case PKT_POOL_SEGMENTED:
		/* Force segment to minimum size */
		params->pkt.seg_len = 0;
		params->pkt.len = len;
		break;
	case PKT_POOL_UNSEGMENTED:
	default:
		params->pkt.seg_len = seg_len;
		params->pkt.len = len;
		break;
	}
}

static void pktio_pkt_set_macs(odp_packet_t pkt, odp_pktio_t src, odp_pktio_t dst,
			       eth_addr_type_e dst_addr_type)
{
	uint32_t len;
	odph_ethhdr_t *eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, &len);
	int ret;

	ret = odp_pktio_mac_addr(src, &eth->src, ODP_PKTIO_MACADDR_MAXSIZE);
	CU_ASSERT(ret == ODPH_ETHADDR_LEN);
	CU_ASSERT(ret <= ODP_PKTIO_MACADDR_MAXSIZE);

	if (dst_addr_type == ETH_UNICAST) {
		ret = odp_pktio_mac_addr(dst, &eth->dst, ODP_PKTIO_MACADDR_MAXSIZE);
		CU_ASSERT(ret == ODPH_ETHADDR_LEN);
		CU_ASSERT(ret <= ODP_PKTIO_MACADDR_MAXSIZE);
	} else {
		CU_ASSERT(odph_eth_addr_parse(&eth->dst, "ff:ff:ff:ff:ff:ff") == 0);
	}
}

static uint32_t pktio_pkt_set_seq(odp_packet_t pkt, size_t l4_hdr_len)
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

	off += l4_hdr_len;
	if (odp_packet_copy_from_mem(pkt, off, sizeof(head), &head) != 0)
		return TEST_SEQ_INVALID;

	tail.magic = TEST_SEQ_MAGIC;
	off = odp_packet_len(pkt) - sizeof(pkt_tail_t);
	if (odp_packet_copy_from_mem(pkt, off, sizeof(tail), &tail) != 0)
		return TEST_SEQ_INVALID;

	tstseq++;

	return head.seq;
}

static uint32_t pktio_pkt_seq_hdr(odp_packet_t pkt, size_t l4_hdr_len)
{
	size_t off;
	uint32_t seq = TEST_SEQ_INVALID;
	pkt_head_t head;
	pkt_tail_t tail;

	if (pkt == ODP_PACKET_INVALID) {
		ODPH_ERR("pkt invalid\n");
		return TEST_SEQ_INVALID;
	}

	off = odp_packet_l4_offset(pkt);
	if (off ==  ODP_PACKET_OFFSET_INVALID) {
		ODPH_ERR("offset invalid\n");
		return TEST_SEQ_INVALID;
	}

	off += l4_hdr_len;
	if (odp_packet_copy_to_mem(pkt, off, sizeof(head), &head) != 0) {
		ODPH_ERR("header copy failed\n");
		return TEST_SEQ_INVALID;
	}

	if (head.magic != TEST_SEQ_MAGIC) {
		ODPH_ERR("header magic invalid 0x%" PRIx32 "\n", head.magic);
		odp_packet_print(pkt);
		return TEST_SEQ_INVALID;
	}

	if (odp_packet_len(pkt) == packet_len) {
		off = packet_len - sizeof(tail);
		if (odp_packet_copy_to_mem(pkt, off, sizeof(tail),
					   &tail) != 0) {
			ODPH_ERR("header copy failed\n");
			return TEST_SEQ_INVALID;
		}

		if (tail.magic == TEST_SEQ_MAGIC) {
			seq = head.seq;
			CU_ASSERT(seq != TEST_SEQ_INVALID);
		} else {
			ODPH_ERR("tail magic invalid 0x%" PRIx32 "\n", tail.magic);
		}
	} else {
		ODPH_ERR("packet length invalid: %" PRIu32 "(%" PRIu32 ")\n",
			 odp_packet_len(pkt), packet_len);
	}

	return seq;
}

static uint32_t pktio_pkt_seq(odp_packet_t pkt)
{
	return pktio_pkt_seq_hdr(pkt, ODPH_UDPHDR_LEN);
}

static void pktio_init_packet_eth_ipv4(odp_packet_t pkt, uint8_t proto)
{
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	char *buf;
	uint16_t seq;
	uint8_t src_mac[ODP_PKTIO_MACADDR_MAXSIZE] = PKTIO_SRC_MAC;
	uint8_t dst_mac[ODP_PKTIO_MACADDR_MAXSIZE] = PKTIO_DST_MAC;
	int pkt_len = odp_packet_len(pkt);

	buf = odp_packet_data(pkt);

	/* Ethernet */
	odp_packet_l2_offset_set(pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy(eth->src.addr, src_mac, ODPH_ETHADDR_LEN);
	memcpy(eth->dst.addr, dst_mac, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	/* IP */
	odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(0x0a000064);
	ip->src_addr = odp_cpu_to_be_32(0x0a000001);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(pkt_len - ODPH_ETHHDR_LEN);
	ip->ttl = 128;
	ip->proto = proto;
	seq = odp_atomic_fetch_inc_u32(&ip_seq);
	ip->id = odp_cpu_to_be_16(seq);
	ip->chksum = 0;
	ip->frag_offset = 0;
	ip->tos = 0;
	odph_ipv4_csum_update(pkt);
}

static uint32_t pktio_init_packet_udp(odp_packet_t pkt)
{
	odph_udphdr_t *udp;
	char *buf;
	int pkt_len = odp_packet_len(pkt);

	buf = odp_packet_data(pkt);

	pktio_init_packet_eth_ipv4(pkt, ODPH_IPPROTO_UDP);

	/* UDP */
	odp_packet_l4_offset_set(pkt, ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp = (odph_udphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp->src_port = odp_cpu_to_be_16(12049);
	udp->dst_port = odp_cpu_to_be_16(12050);
	udp->length = odp_cpu_to_be_16(pkt_len -
				       ODPH_ETHHDR_LEN - ODPH_IPV4HDR_LEN);
	udp->chksum = 0;

	return pktio_pkt_set_seq(pkt, ODPH_UDPHDR_LEN);
}

static uint32_t pktio_init_packet_sctp(odp_packet_t pkt)
{
	odph_sctphdr_t *sctp;
	char *buf;

	buf = odp_packet_data(pkt);

	pktio_init_packet_eth_ipv4(pkt, ODPH_IPPROTO_SCTP);

	/* SCTP */
	odp_packet_l4_offset_set(pkt, ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	sctp = (odph_sctphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	sctp->src_port = odp_cpu_to_be_16(12049);
	sctp->dst_port = odp_cpu_to_be_16(12050);
	sctp->tag = 0;
	sctp->chksum = 0;

	return pktio_pkt_set_seq(pkt, ODPH_SCTPHDR_LEN);
}

static int pktio_zero_checksums(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ip;
	uint32_t len;

	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, &len);

	ip->chksum = 0;

	if (ip->proto == ODPH_IPPROTO_UDP) {
		odph_udphdr_t *udp;

		udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, &len);
		udp->chksum = 0;
	} else if (ip->proto == ODPH_IPPROTO_SCTP) {
		odph_sctphdr_t *sctp;

		sctp = (odph_sctphdr_t *)odp_packet_l4_ptr(pkt, &len);
		sctp->chksum = 0;
	} else {
		CU_FAIL("unexpected L4 protocol");
		return -1;
	}

	return 0;
}

static int pktio_fixup_checksums(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ip;

	pktio_zero_checksums(pkt);

	odph_ipv4_csum_update(pkt);

	ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	if (ip->proto == ODPH_IPPROTO_UDP) {
		odph_udphdr_t *udp;

		udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
		udp->chksum = odph_ipv4_udp_chksum(pkt);
	} else if (ip->proto == ODPH_IPPROTO_SCTP) {
		odph_sctp_chksum_set(pkt);
	} else {
		CU_FAIL("unexpected L4 protocol");
		return -1;
	}

	return 0;
}

static int default_pool_create(void)
{
	odp_pool_param_t params;
	odp_pool_capability_t pool_capa;
	char pool_name[ODP_POOL_NAME_LEN];

	if (odp_pool_capability(&pool_capa) != 0)
		return -1;

	if (default_pkt_pool != ODP_POOL_INVALID)
		return -1;

	odp_pool_param_init(&params);
	set_pool_len(&params, &pool_capa);
	params.pkt.num     = PKT_BUF_NUM;
	params.type        = ODP_POOL_PACKET;

	snprintf(pool_name, sizeof(pool_name),
		 "pkt_pool_default_%d", pool_segmentation);
	default_pkt_pool = odp_pool_create(pool_name, &params);
	if (default_pkt_pool == ODP_POOL_INVALID)
		return -1;

	return 0;
}

static int default_pktv_pool_create(void)
{
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_capability_t pool_capa;
	odp_pool_param_t params;

	if (odp_pool_capability(&pool_capa) != 0)
		return -1;

	if (pool_capa.vector.max_num && pool_capa.vector.max_num < PKT_BUF_NUM)
		return -1;

	if (default_pktv_pool != ODP_POOL_INVALID)
		return -1;

	odp_pool_param_init(&params);
	params.type = ODP_POOL_VECTOR;
	params.vector.num = PKT_BUF_NUM;
	params.vector.max_size = pool_capa.vector.max_size;

	snprintf(pool_name, sizeof(pool_name),
		 "pktv_pool_default_%d", pool_segmentation);
	default_pktv_pool = odp_pool_create(pool_name, &params);
	if (default_pktv_pool == ODP_POOL_INVALID)
		return -1;

	return 0;
}

static int default_evv_pool_create(void)
{
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_capability_t pool_capa;
	odp_pool_param_t params;

	if (odp_pool_capability(&pool_capa) != 0)
		return -1;

	if (pool_capa.event_vector.max_num && pool_capa.event_vector.max_num < PKT_BUF_NUM)
		return -1;

	if (default_evv_pool != ODP_POOL_INVALID)
		return -1;

	odp_pool_param_init(&params);
	params.type = ODP_POOL_EVENT_VECTOR;
	params.event_vector.num = PKT_BUF_NUM;
	params.event_vector.max_size = pool_capa.event_vector.max_size;

	snprintf(pool_name, sizeof(pool_name), "evv_pool_default_%d", pool_segmentation);
	default_evv_pool = odp_pool_create(pool_name, &params);
	if (default_evv_pool == ODP_POOL_INVALID)
		return -1;

	return 0;
}

static odp_pktio_t create_pktio_with_flags(int iface_idx,
					   odp_pktin_mode_t imode,
					   odp_pktout_mode_t omode,
					   uint32_t test_flags)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	const char *iface = iface_name[iface_idx];
	odp_pool_t pktio_pool = pool[iface_idx];

	if (test_flags & TEST_WITH_DEF_POOL)
		pktio_pool = default_pkt_pool;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = imode;
	pktio_param.out_mode = omode;

	pktio = odp_pktio_open(iface, pktio_pool, &pktio_param);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);
	CU_ASSERT(odp_pktio_to_u64(pktio) !=
		  odp_pktio_to_u64(ODP_PKTIO_INVALID));

	odp_pktin_queue_param_init(&pktin_param);

	/* Atomic queue when in scheduled mode */
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

	/* By default, single input and output queue in all modes. Config can
	 * be overridden before starting the interface. */
	CU_ASSERT(odp_pktin_queue_config(pktio, &pktin_param) == 0);
	CU_ASSERT(odp_pktout_queue_config(pktio, NULL) == 0);

	if (wait_for_network)
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS / 4);

	return pktio;
}

static odp_pktio_t create_pktio(int iface_idx, odp_pktin_mode_t imode,
				odp_pktout_mode_t omode)
{
	return create_pktio_with_flags(iface_idx, imode, omode, 0);
}

static odp_pktio_t create_pktv_pktio(int iface_idx, odp_pktin_mode_t imode,
				     odp_pktout_mode_t omode, odp_schedule_sync_t sync_mode,
				     uint32_t test_flags)
{
	const char *iface = iface_name[iface_idx];
	odp_pktout_queue_param_t pktout_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktio_param_t pktio_param;
	odp_pktio_capability_t capa;
	odp_pktio_t pktio;
	odp_pool_t pktio_pool = pool[iface_idx];

	if (test_flags & TEST_WITH_DEF_POOL)
		pktio_pool = default_pkt_pool;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = imode;
	pktio_param.out_mode = omode;

	pktio = odp_pktio_open(iface, pktio_pool, &pktio_param);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT(odp_pktio_capability(pktio, &capa) == 0);
	if (!capa.vector.supported) {
		printf("Vector mode is not supported. Test Skipped.\n");
		return ODP_PKTIO_INVALID;
	}

	odp_pktin_queue_param_init(&pktin_param);

	if (imode == ODP_PKTIN_MODE_SCHED) {
		pktin_param.queue_param.sched.prio = odp_schedule_default_prio();
		pktin_param.queue_param.sched.sync = sync_mode;
		pktin_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	}

	pktin_param.hash_enable = 0;
	pktin_param.num_queues = 1;
	pktin_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	pktin_param.vector.enable = 1;
	pktin_param.vector.pool = pktv_pool[iface_idx];
	pktin_param.vector.max_size = capa.vector.max_size < PKTV_DEFAULT_SIZE ?
					capa.vector.max_size : PKTV_DEFAULT_SIZE;
	pktin_param.vector.max_tmo_ns = capa.vector.min_tmo_ns;
	CU_ASSERT(odp_pktin_queue_config(pktio, &pktin_param) == 0);

	odp_pktout_queue_param_init(&pktout_param);
	pktout_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	pktout_param.num_queues = 1;
	CU_ASSERT(odp_pktout_queue_config(pktio, &pktout_param) == 0);

	if (wait_for_network)
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS / 4);

	return pktio;
}

static int event_aggr_capability(odp_event_aggr_capability_t *aggr_capa, odp_pktin_mode_t imode)
{
	if (imode == ODP_PKTIN_MODE_SCHED) {
		odp_schedule_capability_t sched_capa;

		if (odp_schedule_capability(&sched_capa)) {
			ODPH_ERR("Reading schedule capabilities failed\n");
			return -1;
		}
		*aggr_capa = sched_capa.aggr;
	} else {
		odp_queue_capability_t queue_capa;

		if (odp_queue_capability(&queue_capa)) {
			ODPH_ERR("Reading queue capabilities failed\n");
			return -1;
		}
		*aggr_capa = queue_capa.plain.aggr;
	}
	return 0;
}

static odp_pktio_t create_evv_pktio(int iface_idx, odp_pktin_mode_t imode,
				    odp_pktout_mode_t omode, odp_schedule_sync_t sync_mode,
				    uint64_t *aggr_tmo)
{
	const char *iface = iface_name[iface_idx];
	odp_pktout_queue_param_t pktout_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktio_param_t pktio_param;
	odp_event_aggr_capability_t aggr_capa;
	odp_pktio_t pktio;
	odp_event_aggr_config_t aggr_config;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = imode;
	pktio_param.out_mode = omode;

	pktio = odp_pktio_open(iface, pool[iface_idx], &pktio_param);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(event_aggr_capability(&aggr_capa, imode) == 0);

	odp_pktin_queue_param_init(&pktin_param);

	if (imode == ODP_PKTIN_MODE_SCHED)
		pktin_param.queue_param.sched.sync = sync_mode;

	pktin_param.num_queues = 1;
	pktin_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;

	memset(&aggr_config, 0, sizeof(odp_event_aggr_config_t));
	aggr_config.pool = evv_pool[iface_idx];
	aggr_config.max_tmo_ns = aggr_capa.min_tmo_ns;
	aggr_config.max_size = aggr_capa.max_size < EVV_DEFAULT_SIZE ?
				aggr_capa.max_size : EVV_DEFAULT_SIZE;
	aggr_config.event_type = ODP_EVENT_ANY;
	*aggr_tmo = aggr_config.max_tmo_ns;

	pktin_param.queue_param.aggr = &aggr_config;
	pktin_param.queue_param.num_aggr = 1;

	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &pktin_param) == 0);

	odp_pktout_queue_param_init(&pktout_param);
	pktout_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	pktout_param.num_queues = 1;
	CU_ASSERT_FATAL(odp_pktout_queue_config(pktio, &pktout_param) == 0);

	if (wait_for_network)
		odp_time_wait_ns(ODP_TIME_SEC_IN_NS / 4);

	return pktio;
}

static int flush_input_queue(odp_pktio_t pktio, odp_pktin_mode_t imode)
{
	odp_event_t ev;
	odp_queue_t queue = ODP_QUEUE_INVALID;

	if (imode == ODP_PKTIN_MODE_QUEUE) {
		CU_ASSERT_FATAL(odp_pktin_event_queue(pktio, &queue, 1) == 1);
	} else if (imode == ODP_PKTIN_MODE_DIRECT) {
		return 0;
	}

	/* flush any pending events */
	while (1) {
		if (queue != ODP_QUEUE_INVALID)
			ev = odp_queue_deq(queue);
		else
			ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev != ODP_EVENT_INVALID)
			odp_event_free(ev);
		else
			break;
	}

	return 0;
}

static int create_packets_udp(odp_packet_t pkt_tbl[],
			      uint32_t pkt_seq[],
			      int num,
			      odp_pktio_t pktio_src,
			      odp_pktio_t pktio_dst,
			      odp_bool_t fix_cs,
			      eth_addr_type_e dst_addr_type)
{
	int i, ret;

	for (i = 0; i < num; i++) {
		pkt_tbl[i] = odp_packet_alloc(default_pkt_pool, packet_len);
		if (pkt_tbl[i] == ODP_PACKET_INVALID)
			break;

		pkt_seq[i] = pktio_init_packet_udp(pkt_tbl[i]);
		if (pkt_seq[i] == TEST_SEQ_INVALID) {
			odp_packet_free(pkt_tbl[i]);
			break;
		}

		pktio_pkt_set_macs(pkt_tbl[i], pktio_src, pktio_dst, dst_addr_type);

		/* Set user pointer. It should be NULL on receive side. */
		odp_packet_user_ptr_set(pkt_tbl[i], (void *)1);

		if (fix_cs)
			ret = pktio_fixup_checksums(pkt_tbl[i]);
		else
			ret = pktio_zero_checksums(pkt_tbl[i]);
		if (ret != 0) {
			odp_packet_free(pkt_tbl[i]);
			break;
		}
	}

	return i;
}

static int create_packets_sctp(odp_packet_t pkt_tbl[],
			       uint32_t pkt_seq[],
			       int num,
			       odp_pktio_t pktio_src,
			       odp_pktio_t pktio_dst)
{
	int i, ret;

	for (i = 0; i < num; i++) {
		pkt_tbl[i] = odp_packet_alloc(default_pkt_pool, packet_len);
		if (pkt_tbl[i] == ODP_PACKET_INVALID)
			break;

		pkt_seq[i] = pktio_init_packet_sctp(pkt_tbl[i]);
		if (pkt_seq[i] == TEST_SEQ_INVALID) {
			odp_packet_free(pkt_tbl[i]);
			break;
		}

		pktio_pkt_set_macs(pkt_tbl[i], pktio_src, pktio_dst, ETH_UNICAST);

		ret = pktio_zero_checksums(pkt_tbl[i]);
		if (ret != 0) {
			odp_packet_free(pkt_tbl[i]);
			break;
		}
	}

	return i;
}

static int create_packets(odp_packet_t pkt_tbl[], uint32_t pkt_seq[], int num,
			  odp_pktio_t pktio_src, odp_pktio_t pktio_dst)
{
	return create_packets_udp(pkt_tbl, pkt_seq, num, pktio_src, pktio_dst,
				  true, ETH_UNICAST);
}

static int get_packets(pktio_info_t *pktio_rx, odp_packet_t pkt_tbl[],
		       int num, txrx_mode_e mode, vector_mode_t vector_mode)
{
	odp_event_t evt_tbl[num];
	int num_evts = 0;
	int num_pkts = 0;
	int i, ret;

	if (pktio_rx->in_mode == ODP_PKTIN_MODE_DIRECT) {
		odp_pktin_queue_t pktin;

		ret = odp_pktin_queue(pktio_rx->id, &pktin, 1);

		if (ret != 1) {
			CU_FAIL_FATAL("No pktin queues");
			return -1;
		}

		return odp_pktin_recv(pktin, pkt_tbl, num);
	}

	if (mode == TXRX_MODE_MULTI) {
		if (pktio_rx->in_mode == ODP_PKTIN_MODE_QUEUE)
			num_evts = odp_queue_deq_multi(pktio_rx->inq, evt_tbl,
						       num);
		else
			num_evts = odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT,
						      evt_tbl, num);
	} else {
		odp_event_t evt_tmp = ODP_EVENT_INVALID;

		if (pktio_rx->in_mode == ODP_PKTIN_MODE_QUEUE)
			evt_tmp = odp_queue_deq(pktio_rx->inq);
		else
			evt_tmp = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (evt_tmp != ODP_EVENT_INVALID)
			evt_tbl[num_evts++] = evt_tmp;
	}

	/* convert events to packets, discarding any non-packet events */
	for (i = 0; i < num_evts; ++i) {
		if (odp_event_type(evt_tbl[i]) == ODP_EVENT_PACKET) {
			pkt_tbl[num_pkts++] = odp_packet_from_event(evt_tbl[i]);
		} else if (vector_mode == VECTOR_MODE_PACKET &&
			   odp_event_type(evt_tbl[i]) == ODP_EVENT_PACKET_VECTOR &&
			   num_pkts < num) {
			odp_packet_vector_t pktv;
			odp_packet_t *pkts;
			int pktv_len;

			pktv = odp_packet_vector_from_event(evt_tbl[i]);
			pktv_len = odp_packet_vector_tbl(pktv, &pkts);
			CU_ASSERT(odp_packet_vector_user_flag(pktv) == 0);

			/* Make sure too many packets are not received */
			if (num_pkts + pktv_len > num) {
				int new_pkts = num - num_pkts;

				memcpy(&pkt_tbl[num_pkts], pkts, new_pkts * sizeof(odp_packet_t));
				odp_packet_free_multi(&pkts[new_pkts], pktv_len - new_pkts);
				num_pkts += new_pkts;

			} else {
				memcpy(&pkt_tbl[num_pkts], pkts, pktv_len * sizeof(odp_packet_t));
				num_pkts += pktv_len;
			}
			odp_packet_vector_free(pktv);
		} else if (vector_mode == VECTOR_MODE_EVENT &&
			   odp_event_type(evt_tbl[i]) == ODP_EVENT_VECTOR &&
			   num_pkts < num) {
			odp_event_vector_t evv;
			odp_event_t *event_tbl;
			int evv_len;

			evv = odp_event_vector_from_event(evt_tbl[i]);
			evv_len = odp_event_vector_tbl(evv, &event_tbl);
			CU_ASSERT(evv_len > 0);
			CU_ASSERT(odp_event_vector_type(evv) == ODP_EVENT_ANY ||
				  odp_event_vector_type(evv) == ODP_EVENT_PACKET);
			CU_ASSERT(odp_event_vector_user_flag(evv) == 0);

			/* Make sure too many packets are not received */
			if (num_pkts + evv_len > num) {
				int new_pkts = num - num_pkts;

				odp_packet_from_event_multi(&pkt_tbl[num_pkts], event_tbl,
							    new_pkts);
				odp_event_free_multi(&event_tbl[new_pkts], evv_len - new_pkts);
				num_pkts += new_pkts;
			} else {
				odp_packet_from_event_multi(&pkt_tbl[num_pkts], event_tbl, evv_len);
				num_pkts += evv_len;
			}
			odp_event_vector_free(evv);
		} else {
			odp_event_free(evt_tbl[i]);
		}
	}

	return num_pkts;
}

static int wait_for_packets_hdr(pktio_info_t *pktio_rx, odp_packet_t pkt_tbl[],
				uint32_t seq_tbl[], int num, txrx_mode_e mode,
				uint64_t ns, size_t l4_hdr_len, vector_mode_t vector_mode)
{
	odp_time_t wait_time, end, start;
	int num_rx = 0;
	int i;
	odp_packet_t pkt_tmp[num];

	wait_time = odp_time_local_from_ns(ns);
	start     = odp_time_local();
	end       = odp_time_sum(start, wait_time);

	while (num_rx < num && odp_time_cmp(end, odp_time_local()) > 0) {
		int n = get_packets(pktio_rx, pkt_tmp, num - num_rx, mode, vector_mode);

		if (n < 0)
			break;

		if (n == 0)
			continue;

		for (i = 0; i < n; ++i) {
			if (pktio_pkt_seq_hdr(pkt_tmp[i], l4_hdr_len) ==
			    seq_tbl[num_rx])
				pkt_tbl[num_rx++] = pkt_tmp[i];
			else
				odp_packet_free(pkt_tmp[i]);
		}
	}

	return num_rx;
}

static int wait_for_packets(pktio_info_t *pktio_rx, odp_packet_t pkt_tbl[],
			    uint32_t seq_tbl[], int num, txrx_mode_e mode,
			    uint64_t ns, vector_mode_t vector_mode)
{
	return wait_for_packets_hdr(pktio_rx, pkt_tbl, seq_tbl, num, mode, ns,
				    ODPH_UDPHDR_LEN, vector_mode);
}

static int recv_packets_tmo(odp_pktio_t pktio, odp_packet_t pkt_tbl[],
			    uint32_t seq_tbl[], int num, recv_tmo_mode_e mode,
			    uint64_t tmo, uint64_t ns, int no_pkt)
{
	odp_packet_t pkt_tmp[num];
	odp_pktin_queue_t pktin[MAX_QUEUES];
	odp_time_t ts1, ts2;
	int num_rx = 0;
	int num_q;
	int i;
	int n;
	uint32_t from_val = 0;
	uint32_t *from = NULL;

	if (mode == RECV_MQ_TMO)
		from = &from_val;

	num_q = odp_pktin_queue(pktio, pktin, MAX_QUEUES);
	CU_ASSERT_FATAL(num_q > 0);

	/** Multiple odp_pktin_recv_tmo()/odp_pktin_recv_mq_tmo() calls may be
	 *  required to discard possible non-test packets. */
	do {
		ts1 = odp_time_global();
		if (mode == RECV_TMO)
			n = odp_pktin_recv_tmo(pktin[0], pkt_tmp, num - num_rx,
					       tmo);
		else
			n = odp_pktin_recv_mq_tmo(pktin, (uint32_t)num_q, from, pkt_tmp,
						  num - num_rx, tmo);
		ts2 = odp_time_global();

		CU_ASSERT(n >= 0);

		if (n <= 0)
			break;

		/* When we don't expect any packets, drop all packets and
		 * retry timeout test. */
		if (no_pkt) {
			printf("    drop %i dummy packets\n", n);
			odp_packet_free_multi(pkt_tmp, n);
			continue;
		}

		for (i = 0; i < n; i++) {
			if (pktio_pkt_seq(pkt_tmp[i]) == seq_tbl[num_rx])
				pkt_tbl[num_rx++] = pkt_tmp[i];
			else
				odp_packet_free(pkt_tmp[i]);
		}
		if (mode == RECV_MQ_TMO)
			CU_ASSERT(from_val < (uint32_t)num_q);
	} while (num_rx < num);

	if (num_rx < num) {
		uint64_t diff = odp_time_diff_ns(ts2, ts1);

		if (diff < ns)
			printf("    diff %" PRIu64 ", ns %" PRIu64 "\n",
			       diff, ns);

		CU_ASSERT(diff >= ns);
	}

	return num_rx;
}

static int send_packets(odp_pktout_queue_t pktout,
			odp_packet_t *pkt_tbl, unsigned pkts)
{
	int ret;
	unsigned sent = 0;

	while (sent < pkts) {
		ret = odp_pktout_send(pktout, &pkt_tbl[sent], pkts - sent);

		if (ret < 0) {
			CU_FAIL_FATAL("failed to send test packet");
			return -1;
		}

		sent += ret;
	}

	return 0;
}

static int send_packet_events(odp_queue_t queue,
			      odp_packet_t *pkt_tbl, unsigned pkts)
{
	int ret;
	unsigned i;
	unsigned sent = 0;
	odp_event_t ev_tbl[pkts];

	for (i = 0; i < pkts; i++)
		ev_tbl[i] = odp_packet_to_event(pkt_tbl[i]);

	while (sent < pkts) {
		ret = odp_queue_enq_multi(queue, &ev_tbl[sent], pkts - sent);

		if (ret < 0) {
			CU_FAIL_FATAL("failed to send test packet as events");
			return -1;
		}

		sent += ret;
	}

	return 0;
}

static void check_parser_capa(odp_pktio_t pktio, int *l2, int *l3, int *l4)
{
	int ret;
	odp_pktio_capability_t capa;

	*l2 = 0;
	*l3 = 0;
	*l4 = 0;

	ret = odp_pktio_capability(pktio, &capa);
	CU_ASSERT(ret == 0);

	if (ret < 0)
		return;

	switch (capa.config.parser.layer) {
	case ODP_PROTO_LAYER_ALL:
		/* Fall through */
	case ODP_PROTO_LAYER_L4:
		*l2 = 1;
		*l3 = 1;
		*l4 = 1;
		break;
	case ODP_PROTO_LAYER_L3:
		*l2 = 1;
		*l3 = 1;
		break;
	case ODP_PROTO_LAYER_L2:
		*l2 = 1;
		break;
	default:
		break;
	}
}

static void make_refs(odp_packet_t ref[], odp_packet_t pkt[], uint32_t num)
{
	for (uint32_t i = 0; i < num; i++) {
		ref[i] = odp_packet_ref_static(pkt[i]);
		CU_ASSERT_FATAL(ref[i] != ODP_PACKET_INVALID);
		CU_ASSERT(odp_packet_has_ref(ref[i]));
		CU_ASSERT(odp_packet_has_ref(pkt[i]));
	}
}

static void free_refs(odp_packet_t ref[], uint32_t num)
{
	for (uint32_t i = 0; i < num; i++) {
		CU_ASSERT(odp_packet_has_ref(ref[i]) == 0);
		odp_packet_free(ref[i]);
	}
}

static void pktio_txrx_multi(pktio_info_t *pktio_info_a,
			     pktio_info_t *pktio_info_b,
			     int num_pkts, txrx_mode_e mode,
			     vector_mode_t vector_mode,
			     uint32_t test_flags)
{
	odp_packet_t tx_pkt[num_pkts];
	odp_packet_t rx_pkt[num_pkts];
	odp_packet_t ref_tbl[num_pkts];
	uint32_t tx_seq[num_pkts];
	int i, ret, num_rx;
	int parser_l2, parser_l3, parser_l4;
	odp_pktio_t pktio_a = pktio_info_a->id;
	odp_pktio_t pktio_b = pktio_info_b->id;
	int pktio_index_b = odp_pktio_index(pktio_b);
	/* Use extra flush packets in event vector mode if timeouts are not supported */
	const odp_bool_t flush_aggr = (vector_mode == VECTOR_MODE_EVENT && !pktio_info_b->aggr_tmo);
	odp_packet_t tx_pkt_flush[EVV_DEFAULT_SIZE];
	uint32_t tx_seq_flush[EVV_DEFAULT_SIZE];

	/* Check RX interface parser capability */
	check_parser_capa(pktio_b, &parser_l2, &parser_l3, &parser_l4);

	if (packet_len == USE_MTU) {
		odp_pool_capability_t pool_capa;
		uint32_t maxlen;

		maxlen = odp_pktout_maxlen(pktio_a);
		if (odp_pktout_maxlen(pktio_b) < maxlen)
			maxlen = odp_pktout_maxlen(pktio_b);
		CU_ASSERT_FATAL(maxlen > 0);
		packet_len = maxlen;
		if (packet_len > PKT_LEN_MAX)
			packet_len = PKT_LEN_MAX;

		CU_ASSERT_FATAL(odp_pool_capability(&pool_capa) == 0);

		if (pool_capa.pkt.max_len &&
		    packet_len > pool_capa.pkt.max_len)
			packet_len = pool_capa.pkt.max_len;
	}

	/* generate test packets to send */
	ret = create_packets(tx_pkt, tx_seq, num_pkts, pktio_a, pktio_b);
	if (ret != num_pkts) {
		CU_FAIL("failed to generate test packets");
		return;
	}

	/* Extra packets for flushing pending packets from aggregation */
	if (flush_aggr) {
		ret = create_packets(tx_pkt_flush, tx_seq_flush, EVV_DEFAULT_SIZE, pktio_a,
				     pktio_b);
		if (ret != EVV_DEFAULT_SIZE) {
			CU_FAIL("failed to generate event vector flush packets");
			return;
		}
	}

	if (test_flags & TEST_WITH_REFS)
		make_refs(ref_tbl, tx_pkt, num_pkts);

	/* send packet(s) out */
	if (mode == TXRX_MODE_SINGLE) {
		for (i = 0; i < num_pkts; ++i) {
			ret = odp_pktout_send(pktio_info_a->pktout,
					      &tx_pkt[i], 1);
			if (ret != 1) {
				CU_FAIL_FATAL("failed to send test packet");
				odp_packet_free(tx_pkt[i]);
				return;
			}
		}
	} else if (mode == TXRX_MODE_MULTI) {
		send_packets(pktio_info_a->pktout, tx_pkt, num_pkts);
	} else {
		send_packet_events(pktio_info_a->queue_out, tx_pkt, num_pkts);
	}

	/* Send extra aggregation flush packets */
	if (flush_aggr) {
		if (mode == TXRX_MODE_MULTI_EVENT)
			send_packet_events(pktio_info_a->queue_out, tx_pkt_flush, EVV_DEFAULT_SIZE);
		else
			send_packets(pktio_info_a->pktout, tx_pkt_flush, EVV_DEFAULT_SIZE);
	}

	/* and wait for them to arrive back */
	num_rx = wait_for_packets(pktio_info_b, rx_pkt, tx_seq, num_pkts, mode,
				  ODP_TIME_SEC_IN_NS, vector_mode);
	CU_ASSERT(num_rx == num_pkts);
	if (num_rx != num_pkts)
		ODPH_ERR("received %i, out of %i packets\n", num_rx, num_pkts);

	if (test_flags & TEST_WITH_REFS)
		free_refs(ref_tbl, num_pkts);

	for (i = 0; i < num_rx; ++i) {
		odp_packet_data_range_t range;
		uint16_t sum;
		odp_packet_t pkt = rx_pkt[i];

		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		CU_ASSERT(odp_packet_has_ref(pkt) == 0);
		CU_ASSERT(odp_packet_input(pkt) == pktio_b);
		CU_ASSERT(odp_packet_input_index(pkt) == pktio_index_b);
		CU_ASSERT(odp_packet_pool(pkt) == expected_rx_pool(test_flags));
		CU_ASSERT(odp_packet_has_error(pkt) == 0);
		if (parser_l2) {
			CU_ASSERT(odp_packet_has_l2(pkt));
			CU_ASSERT(odp_packet_has_eth(pkt));
		}
		if (parser_l3) {
			CU_ASSERT(odp_packet_has_l3(pkt));
			CU_ASSERT(odp_packet_has_ipv4(pkt));
		}
		if (parser_l4) {
			CU_ASSERT(odp_packet_has_l4(pkt));
			CU_ASSERT(odp_packet_has_udp(pkt));
		}

		CU_ASSERT(odp_packet_user_flag(pkt) == 0);
		CU_ASSERT(odp_packet_user_ptr(pkt) == NULL);
		CU_ASSERT(odp_packet_cls_mark(pkt) == 0);

		odp_packet_input_set(pkt, ODP_PKTIO_INVALID);
		CU_ASSERT(odp_packet_input(pkt) == ODP_PKTIO_INVALID);
		CU_ASSERT(odp_packet_input_index(pkt) < 0);

		odp_packet_input_set(pkt, pktio_b);
		CU_ASSERT(odp_packet_input(pkt) == pktio_b);
		CU_ASSERT(odp_packet_input_index(pkt) == pktio_index_b);

		/* Dummy read to ones complement in case pktio has set it */
		sum = odp_packet_ones_comp(pkt, &range);
		if (range.length > 0)
			test_pktio_dummy_u64 += sum;

		/* Dummy read to flow hash in case pktio has set it */
		if (odp_packet_has_flow_hash(pkt))
			test_pktio_dummy_u64 += odp_packet_flow_hash(pkt);

		odp_packet_free(pkt);
	}
}

static void do_test_txrx(odp_pktin_mode_t in_mode, int num_pkts,
			 txrx_mode_e mode, odp_schedule_sync_t sync_mode,
			 vector_mode_t vector_mode, uint32_t test_flags)
{
	int ret, i, if_b;
	pktio_info_t pktios[MAX_NUM_IFACES];
	pktio_info_t *io;

	/* create pktios and associate input/output queues */
	for (i = 0; i < num_ifaces; ++i) {
		odp_pktout_queue_t pktout;
		odp_queue_t queue = ODP_QUEUE_INVALID;
		odp_pktout_mode_t out_mode = ODP_PKTOUT_MODE_DIRECT;
		uint64_t aggr_tmo = 0;

		if (mode == TXRX_MODE_MULTI_EVENT)
			out_mode = ODP_PKTOUT_MODE_QUEUE;

		io = &pktios[i];

		io->name = iface_name[i];
		if (vector_mode == VECTOR_MODE_PACKET)
			io->id = create_pktv_pktio(i, in_mode, out_mode, sync_mode, test_flags);
		else if (vector_mode == VECTOR_MODE_EVENT)
			io->id = create_evv_pktio(i, in_mode, out_mode, sync_mode, &aggr_tmo);
		else
			io->id = create_pktio_with_flags(i, in_mode, out_mode, test_flags);
		if (io->id == ODP_PKTIO_INVALID) {
			CU_FAIL("failed to open iface");
			return;
		}
		io->aggr_tmo = aggr_tmo;

		if (mode == TXRX_MODE_MULTI_EVENT) {
			CU_ASSERT_FATAL(odp_pktout_event_queue(io->id,
							       &queue, 1) == 1);
		} else {
			CU_ASSERT_FATAL(odp_pktout_queue(io->id,
							 &pktout, 1) == 1);
			io->pktout = pktout;
		}

		io->queue_out = queue;
		io->in_mode   = in_mode;

		if (in_mode == ODP_PKTIN_MODE_QUEUE) {
			CU_ASSERT_FATAL(odp_pktin_event_queue(io->id, &queue, 1)
					== 1);
			io->inq = queue;
		} else {
			io->inq = ODP_QUEUE_INVALID;
		}

		ret = odp_pktio_start(io->id);
		CU_ASSERT(ret == 0);

		_pktio_wait_linkup(io->id);
	}

	/* if we have two interfaces then send through one and receive on
	 * another but if there's only one assume it's a loopback */
	if_b = (num_ifaces == 1) ? 0 : 1;
	pktio_txrx_multi(&pktios[0], &pktios[if_b], num_pkts, mode, vector_mode, test_flags);

	for (i = 0; i < num_ifaces; ++i) {
		ret = odp_pktio_stop(pktios[i].id);
		CU_ASSERT_FATAL(ret == 0);
		flush_input_queue(pktios[i].id, in_mode);
		ret = odp_pktio_close(pktios[i].id);
		CU_ASSERT(ret == 0);
	}
}

static void test_txrx(odp_pktin_mode_t in_mode, int num_pkts,
		      txrx_mode_e mode, odp_schedule_sync_t sync_mode,
		      odp_bool_t vector_mode)
{
	for (uint32_t flags = 0; flags < NUM_TEST_FLAG_COMBOS; flags++)
		do_test_txrx(in_mode, num_pkts, mode, sync_mode, vector_mode, flags);
}

static void pktio_test_plain_queue(void)
{
	test_txrx(ODP_PKTIN_MODE_QUEUE, 1, TXRX_MODE_SINGLE, 0, VECTOR_MODE_DISABLED);
	test_txrx(ODP_PKTIN_MODE_QUEUE, TX_BATCH_LEN, TXRX_MODE_SINGLE, 0, VECTOR_MODE_DISABLED);
}

static void pktio_test_plain_multi(void)
{
	test_txrx(ODP_PKTIN_MODE_QUEUE, TX_BATCH_LEN, TXRX_MODE_MULTI, 0, VECTOR_MODE_DISABLED);
	test_txrx(ODP_PKTIN_MODE_QUEUE, 1, TXRX_MODE_MULTI, 0, VECTOR_MODE_DISABLED);
}

static void pktio_test_plain_multi_event(void)
{
	test_txrx(ODP_PKTIN_MODE_QUEUE, 1, TXRX_MODE_MULTI_EVENT, 0, VECTOR_MODE_DISABLED);
	test_txrx(ODP_PKTIN_MODE_QUEUE, TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT, 0,
		  VECTOR_MODE_DISABLED);
}

static void pktio_test_sched_queue(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, 1, TXRX_MODE_SINGLE, 0, VECTOR_MODE_DISABLED);
	test_txrx(ODP_PKTIN_MODE_SCHED, TX_BATCH_LEN, TXRX_MODE_SINGLE, 0, VECTOR_MODE_DISABLED);
}

static void pktio_test_sched_multi(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, TX_BATCH_LEN, TXRX_MODE_MULTI, 0, VECTOR_MODE_DISABLED);
	test_txrx(ODP_PKTIN_MODE_SCHED, 1, TXRX_MODE_MULTI, 0, VECTOR_MODE_DISABLED);
}

static void pktio_test_sched_multi_event(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, 1, TXRX_MODE_MULTI_EVENT, 0, VECTOR_MODE_DISABLED);
	test_txrx(ODP_PKTIN_MODE_SCHED, TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT, 0,
		  VECTOR_MODE_DISABLED);
}

static void pktio_test_recv(void)
{
	test_txrx(ODP_PKTIN_MODE_DIRECT, 1, TXRX_MODE_SINGLE, 0, VECTOR_MODE_DISABLED);
}

static void pktio_test_recv_multi(void)
{
	test_txrx(ODP_PKTIN_MODE_DIRECT, TX_BATCH_LEN, TXRX_MODE_MULTI, 0, VECTOR_MODE_DISABLED);
}

static void pktio_test_recv_multi_event(void)
{
	test_txrx(ODP_PKTIN_MODE_DIRECT, 1, TXRX_MODE_MULTI_EVENT, 0, VECTOR_MODE_DISABLED);
	test_txrx(ODP_PKTIN_MODE_DIRECT, TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT, 0,
		  VECTOR_MODE_DISABLED);
}

static void pktio_test_recv_queue(void)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {0};
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t in_queue_param;
	odp_pktout_queue_param_t out_queue_param;
	odp_pktout_queue_t pktout_queue[MAX_QUEUES];
	odp_pktin_queue_t pktin_queue[MAX_QUEUES];
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	odp_packet_t tmp_pkt[TX_BATCH_LEN];
	uint32_t pkt_seq[TX_BATCH_LEN];
	odp_time_t wait_time, end;
	int num_rx = 0;
	int num_queues;
	int ret;
	int i;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_DIRECT,
					ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio[i], &capa) == 0);

		odp_pktin_queue_param_init(&in_queue_param);
		num_queues = capa.max_input_queues;
		in_queue_param.num_queues  = num_queues;
		in_queue_param.hash_enable = (num_queues > 1) ? 1 : 0;
		in_queue_param.hash_proto.proto.ipv4_udp = 1;

		ret = odp_pktin_queue_config(pktio[i], &in_queue_param);
		CU_ASSERT_FATAL(ret == 0);

		odp_pktout_queue_param_init(&out_queue_param);
		out_queue_param.num_queues  = capa.max_output_queues;

		ret = odp_pktout_queue_config(pktio[i], &out_queue_param);
		CU_ASSERT_FATAL(ret == 0);

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; ++i)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	if (num_ifaces > 1)
		pktio_rx = pktio[1];
	else
		pktio_rx = pktio_tx;

	/* Allocate and initialize test packets */
	ret = create_packets(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx,
			     pktio_rx);
	if (ret != TX_BATCH_LEN) {
		CU_FAIL("Failed to generate test packets");
		return;
	}

	/* Send packets */
	num_queues = odp_pktout_queue(pktio_tx, pktout_queue, MAX_QUEUES);
	CU_ASSERT_FATAL(num_queues > 0);
	if (num_queues > MAX_QUEUES)
		num_queues = MAX_QUEUES;

	ret = odp_pktout_send(pktout_queue[num_queues - 1], pkt_tbl,
			      TX_BATCH_LEN);
	CU_ASSERT_FATAL(ret == TX_BATCH_LEN);

	/* Receive packets */
	num_queues = odp_pktin_queue(pktio_rx, pktin_queue, MAX_QUEUES);
	CU_ASSERT_FATAL(num_queues > 0);
	if (num_queues > MAX_QUEUES)
		num_queues = MAX_QUEUES;

	wait_time = odp_time_local_from_ns(ODP_TIME_SEC_IN_NS);
	end = odp_time_sum(odp_time_local(), wait_time);
	do {
		int n = 0;

		for (i = 0; i < num_queues; i++) {
			n = odp_pktin_recv(pktin_queue[i], tmp_pkt,
					   TX_BATCH_LEN);
			if (n != 0)
				break;
		}
		if (n < 0)
			break;
		for (i = 0; i < n; i++) {
			if (pktio_pkt_seq(tmp_pkt[i]) == pkt_seq[num_rx])
				pkt_tbl[num_rx++] = tmp_pkt[i];
			else
				odp_packet_free(tmp_pkt[i]);
		}
	} while (num_rx < TX_BATCH_LEN &&
		 odp_time_cmp(end, odp_time_local()) > 0);

	CU_ASSERT(num_rx == TX_BATCH_LEN);

	for (i = 0; i < num_rx; i++)
		odp_packet_free(pkt_tbl[i]);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static void test_recv_tmo(recv_tmo_mode_e mode)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {0};
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t in_queue_param;
	odp_pktout_queue_t pktout_queue;
	int test_pkt_count = 6;
	odp_packet_t pkt_tbl[test_pkt_count];
	uint32_t pkt_seq[test_pkt_count];
	uint64_t ns;
	uint32_t num_q;
	int ret;
	int i;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_DIRECT,
					ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio[i], &capa) == 0);

		odp_pktin_queue_param_init(&in_queue_param);
		if (mode == RECV_TMO)
			num_q = 1;
		else
			num_q = (capa.max_input_queues < MAX_QUEUES) ?
					capa.max_input_queues : MAX_QUEUES;
		in_queue_param.num_queues  = num_q;
		in_queue_param.hash_enable = (num_q > 1) ? 1 : 0;
		in_queue_param.hash_proto.proto.ipv4_udp = 1;

		ret = odp_pktin_queue_config(pktio[i], &in_queue_param);
		CU_ASSERT_FATAL(ret == 0);

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; i++)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	memset(pkt_seq, 0, sizeof(pkt_seq));

	ns = 100 * ODP_TIME_MSEC_IN_NS;

	ret = create_packets(pkt_tbl, pkt_seq, test_pkt_count, pktio_tx,
			     pktio_rx);
	CU_ASSERT_FATAL(ret == test_pkt_count);

	ret = odp_pktout_send(pktout_queue, pkt_tbl, test_pkt_count);
	CU_ASSERT_FATAL(ret == test_pkt_count);

	ret = recv_packets_tmo(pktio_rx, &pkt_tbl[0], &pkt_seq[0], 1, mode,
			       odp_pktin_wait_time(10 * ODP_TIME_SEC_IN_NS),
			       0, 0);
	CU_ASSERT_FATAL(ret == 1);

	ret = recv_packets_tmo(pktio_rx, &pkt_tbl[1], &pkt_seq[1], 1, mode,
			       ODP_PKTIN_NO_WAIT, 0, 0);
	CU_ASSERT_FATAL(ret == 1);

	ret = recv_packets_tmo(pktio_rx, &pkt_tbl[2], &pkt_seq[2], 1, mode,
			       odp_pktin_wait_time(0), 0, 0);
	CU_ASSERT_FATAL(ret == 1);

	ret = recv_packets_tmo(pktio_rx, &pkt_tbl[3], &pkt_seq[3], 3, mode,
			       odp_pktin_wait_time(ns), ns, 0);
	CU_ASSERT_FATAL(ret == 3);

	for (i = 0; i < test_pkt_count; i++)
		odp_packet_free(pkt_tbl[i]);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static void pktio_test_recv_tmo(void)
{
	test_recv_tmo(RECV_TMO);
}

static void pktio_test_recv_mq_tmo(void)
{
	test_recv_tmo(RECV_MQ_TMO);
	test_recv_tmo(RECV_MQ_TMO_NO_IDX);
}

static void pktio_test_recv_mtu(void)
{
	packet_len = USE_MTU;
	pktio_test_sched_multi();
	packet_len = PKT_LEN_NORMAL;
}

static void pktio_test_maxlen(void)
{
	int ret;
	uint32_t maxlen;

	odp_pktio_t pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
					 ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	maxlen = odp_pktout_maxlen(pktio);
	CU_ASSERT(maxlen > 0);

	maxlen = odp_pktin_maxlen(pktio);
	CU_ASSERT(maxlen > 0);

	ret = odp_pktio_close(pktio);
	CU_ASSERT(ret == 0);
}

static int pktio_check_maxlen_set(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || !capa.set_op.op.maxlen)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_maxlen_set(void)
{
	odp_pktio_capability_t capa;
	int ret;
	uint32_t maxlen, input_orig, output_orig;

	odp_pktio_t pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT,
					 ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(!odp_pktio_capability(pktio, &capa));

	input_orig = odp_pktin_maxlen(pktio);
	CU_ASSERT(input_orig > 0);

	output_orig = odp_pktout_maxlen(pktio);
	CU_ASSERT(output_orig > 0);

	if (capa.maxlen.equal) { /* Input and output values have to be equal */
		CU_ASSERT(capa.maxlen.min_input == capa.maxlen.min_output);
		CU_ASSERT(capa.maxlen.max_input == capa.maxlen.max_output);
		CU_ASSERT(capa.maxlen.max_input > capa.maxlen.min_input);

		maxlen = capa.maxlen.min_input;
		CU_ASSERT(!odp_pktio_maxlen_set(pktio, maxlen, maxlen));
		CU_ASSERT(odp_pktin_maxlen(pktio) == maxlen);
		CU_ASSERT(odp_pktout_maxlen(pktio) == maxlen);

		maxlen = capa.maxlen.max_input;
		CU_ASSERT(!odp_pktio_maxlen_set(pktio, maxlen, maxlen));
		CU_ASSERT(odp_pktin_maxlen(pktio) == maxlen);
		CU_ASSERT(odp_pktout_maxlen(pktio) == maxlen);

		CU_ASSERT(!odp_pktio_maxlen_set(pktio, input_orig, input_orig));
	} else {
		CU_ASSERT(capa.maxlen.max_input || capa.maxlen.max_output);
		if (capa.maxlen.max_output == 0) { /* Only input supported */
			CU_ASSERT(capa.maxlen.min_output == 0);
			CU_ASSERT(capa.maxlen.min_input < capa.maxlen.max_input);

			CU_ASSERT(!odp_pktio_maxlen_set(pktio, capa.maxlen.min_input, 0));
			CU_ASSERT(odp_pktin_maxlen(pktio) == capa.maxlen.min_input);
			CU_ASSERT(!odp_pktio_maxlen_set(pktio, capa.maxlen.max_input, 0));
			CU_ASSERT(odp_pktin_maxlen(pktio) == capa.maxlen.max_input);
			CU_ASSERT(!odp_pktio_maxlen_set(pktio, input_orig, 0));
		} else if (capa.maxlen.max_input == 0) { /* Only output supported */
			CU_ASSERT(capa.maxlen.min_input == 0);
			CU_ASSERT(capa.maxlen.min_output < capa.maxlen.max_output);

			CU_ASSERT(!odp_pktio_maxlen_set(pktio, 0, capa.maxlen.min_output));
			CU_ASSERT(odp_pktout_maxlen(pktio) == capa.maxlen.min_output);
			CU_ASSERT(!odp_pktio_maxlen_set(pktio, 0, capa.maxlen.max_output));
			CU_ASSERT(odp_pktout_maxlen(pktio) == capa.maxlen.max_output);
			CU_ASSERT(!odp_pktio_maxlen_set(pktio, 0, output_orig));
		} else { /* Both directions supported */
			CU_ASSERT(capa.maxlen.min_input < capa.maxlen.max_input);
			CU_ASSERT(capa.maxlen.min_output < capa.maxlen.max_output);

			CU_ASSERT(!odp_pktio_maxlen_set(pktio, capa.maxlen.min_input,
							capa.maxlen.min_output));
			CU_ASSERT(odp_pktin_maxlen(pktio) == capa.maxlen.min_input);
			CU_ASSERT(odp_pktout_maxlen(pktio) == capa.maxlen.min_output);

			CU_ASSERT(!odp_pktio_maxlen_set(pktio, capa.maxlen.max_input,
							capa.maxlen.max_output));
			CU_ASSERT(odp_pktin_maxlen(pktio) == capa.maxlen.max_input);
			CU_ASSERT(odp_pktout_maxlen(pktio) == capa.maxlen.max_output);

			CU_ASSERT(!odp_pktio_maxlen_set(pktio, capa.maxlen.max_input,
							capa.maxlen.min_output));
			CU_ASSERT(odp_pktin_maxlen(pktio) == capa.maxlen.max_input);
			CU_ASSERT(odp_pktout_maxlen(pktio) == capa.maxlen.min_output);

			CU_ASSERT(!odp_pktio_maxlen_set(pktio, capa.maxlen.min_input,
							capa.maxlen.max_output));
			CU_ASSERT(odp_pktin_maxlen(pktio) == capa.maxlen.min_input);
			CU_ASSERT(odp_pktout_maxlen(pktio) == capa.maxlen.max_output);

			CU_ASSERT(!odp_pktio_maxlen_set(pktio, input_orig, output_orig));
		}
	}
	CU_ASSERT(odp_pktin_maxlen(pktio) == input_orig);
	CU_ASSERT(odp_pktout_maxlen(pktio) == output_orig);
	ret = odp_pktio_close(pktio);
	CU_ASSERT(ret == 0);
}

static void pktio_test_promisc(void)
{
	int ret;
	odp_pktio_capability_t capa;

	odp_pktio_t pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
					 ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);
	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0);

	ret = odp_pktio_promisc_mode(pktio);
	CU_ASSERT(ret >= 0);
	CU_ASSERT(ret == 0 || ret == 1);

	if (capa.set_op.op.promisc_mode) {
		/* Disabled by default */
		CU_ASSERT(ret == 0);
	}

	if (!capa.set_op.op.promisc_mode) {
		printf("promiscuous mode not supported\n");
		ret = odp_pktio_close(pktio);
		CU_ASSERT(ret == 0);
		return;
	}

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

static void pktio_test_mac(void)
{
	unsigned char mac_addr[ODP_PKTIO_MACADDR_MAXSIZE];
	unsigned char mac_addr_ref[ODP_PKTIO_MACADDR_MAXSIZE] =	{
		0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0};
	int mac_len;
	int ret;
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;

	pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
			     ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	printf("testing mac for %s\n", iface_name[0]);

	mac_len = odp_pktio_mac_addr(pktio, mac_addr,
				     ODP_PKTIO_MACADDR_MAXSIZE);
	CU_ASSERT(ODPH_ETHADDR_LEN == mac_len);
	CU_ASSERT(ODP_PKTIO_MACADDR_MAXSIZE >= mac_len);

	printf(" %X:%X:%X:%X:%X:%X ",
	       mac_addr[0], mac_addr[1], mac_addr[2],
	       mac_addr[3], mac_addr[4], mac_addr[5]);

	/* Fail case: wrong addr_size. Expected <0. */
	mac_len = odp_pktio_mac_addr(pktio, mac_addr, 2);
	CU_ASSERT(mac_len < 0);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0);
	if (capa.set_op.op.mac_addr) {
		/* Fail case: wrong addr_size. Expected <0. */
		ret = odp_pktio_mac_addr_set(pktio, mac_addr_ref, 2);
		CU_ASSERT_FATAL(ret < 0);

		ret = odp_pktio_mac_addr_set(pktio, mac_addr_ref,
					     ODPH_ETHADDR_LEN);
		CU_ASSERT_FATAL(ret == 0);

		mac_len = odp_pktio_mac_addr(pktio, mac_addr,
					     ODPH_ETHADDR_LEN);
		CU_ASSERT(ODPH_ETHADDR_LEN == mac_len);

		CU_ASSERT(odp_memcmp(mac_addr_ref, mac_addr,
				     ODPH_ETHADDR_LEN) == 0);
	} else
		printf("\n mac address set not supported for %s!\n",
		       iface_name[0]);

	ret = odp_pktio_close(pktio);
	CU_ASSERT(0 == ret);
}

static void test_defaults(uint8_t fill)
{
	odp_pktio_param_t pktio_p;
	odp_pktin_queue_param_t qp_in;
	odp_pktout_queue_param_t qp_out;
	odp_pktio_config_t pktio_conf;

	memset(&pktio_p, fill, sizeof(pktio_p));
	odp_pktio_param_init(&pktio_p);
	CU_ASSERT(pktio_p.in_mode == ODP_PKTIN_MODE_DIRECT);
	CU_ASSERT(pktio_p.out_mode == ODP_PKTOUT_MODE_DIRECT);

	memset(&qp_in, fill, sizeof(qp_in));
	odp_pktin_queue_param_init(&qp_in);
	CU_ASSERT(qp_in.op_mode == ODP_PKTIO_OP_MT);
	CU_ASSERT(qp_in.classifier_enable == 0);
	CU_ASSERT(qp_in.hash_enable == 0);
	CU_ASSERT(qp_in.hash_proto.all_bits == 0);
	CU_ASSERT(qp_in.num_queues == 1);
	CU_ASSERT(qp_in.queue_size[0] == 0);
	CU_ASSERT(qp_in.queue_param.enq_mode == ODP_QUEUE_OP_MT);
	CU_ASSERT(qp_in.queue_param.sched.prio == odp_schedule_default_prio());
	CU_ASSERT(qp_in.queue_param.sched.sync == ODP_SCHED_SYNC_PARALLEL);
	CU_ASSERT(qp_in.queue_param.sched.group == ODP_SCHED_GROUP_ALL);
	CU_ASSERT(qp_in.queue_param.sched.lock_count == 0);
	CU_ASSERT(qp_in.queue_param.order == ODP_QUEUE_ORDER_KEEP);
	CU_ASSERT(qp_in.queue_param.nonblocking == ODP_BLOCKING);
	CU_ASSERT(qp_in.queue_param.context == NULL);
	CU_ASSERT(qp_in.queue_param.context_len == 0);
	CU_ASSERT(qp_in.queue_param_ovr == NULL);
	CU_ASSERT(qp_in.vector.enable == false);

	memset(&qp_out, fill, sizeof(qp_out));
	odp_pktout_queue_param_init(&qp_out);
	CU_ASSERT(qp_out.op_mode == ODP_PKTIO_OP_MT);
	CU_ASSERT(qp_out.num_queues == 1);
	CU_ASSERT(qp_out.queue_size[0] == 0);

	memset(&pktio_conf, fill, sizeof(pktio_conf));
	odp_pktio_config_init(&pktio_conf);
	CU_ASSERT(pktio_conf.pktin.all_bits == 0);
	CU_ASSERT(pktio_conf.pktout.all_bits == 0);
	CU_ASSERT(pktio_conf.parser.layer == ODP_PROTO_LAYER_ALL);
	CU_ASSERT(pktio_conf.enable_loop == false);
	CU_ASSERT(pktio_conf.inbound_ipsec == false);
	CU_ASSERT(pktio_conf.outbound_ipsec == false);
	CU_ASSERT(pktio_conf.enable_lso == false);
	CU_ASSERT(pktio_conf.reassembly.en_ipv4 == false);
	CU_ASSERT(pktio_conf.reassembly.en_ipv6 == false);
	CU_ASSERT(pktio_conf.reassembly.max_wait_time == 0);
	CU_ASSERT(pktio_conf.reassembly.max_num_frags == 2);
}

static void pktio_test_default_values(void)
{
	test_defaults(0);
	test_defaults(0xff);
}

static void pktio_test_open(void)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	int i;

	/* test the sequence open->close->open->close() */
	for (i = 0; i < 2; ++i) {
		pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED,
				     ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);
		CU_ASSERT(odp_pktio_close(pktio) == 0);
	}

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open("nothere", default_pkt_pool, &pktio_param);
	CU_ASSERT(pktio == ODP_PKTIO_INVALID);
}

static void pktio_test_lookup(void)
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
	CU_ASSERT(pktio_inval == ODP_PKTIO_INVALID);

	CU_ASSERT(odp_pktio_close(pktio) == 0);

	CU_ASSERT(odp_pktio_lookup(iface_name[0]) == ODP_PKTIO_INVALID);
}

static void pktio_test_index(void)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	int ndx;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(iface_name[0], default_pkt_pool, &pktio_param);
	CU_ASSERT(pktio != ODP_PKTIO_INVALID);

	ndx = odp_pktio_index(pktio);
	CU_ASSERT(ndx >= 0);

	CU_ASSERT(ODP_PKTIO_MAX_INDEX >= odp_pktio_max_index());
	CU_ASSERT(ODP_PKTIO_MAX_INDEX >= 0 && ODP_PKTIO_MAX_INDEX <= 1024);

	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

static void pktio_test_print(void)
{
	odp_pktio_t pktio;
	int i;

	for (i = 0; i < num_ifaces; ++i) {
		pktio = create_pktio(i, ODP_PKTIN_MODE_QUEUE,
				     ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

		/* Print pktio debug info and test that the
		 * odp_pktio_print() function is implemented. */
		odp_pktio_print(pktio);

		CU_ASSERT(odp_pktio_close(pktio) == 0);
	}
}

static void pktio_test_pktio_config(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;
	const char *iface = iface_name[0];

	pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	memset(&config, 0xff, sizeof(config));
	odp_pktio_config_init(&config);

	/* Check default values */
	CU_ASSERT(config.pktin.all_bits == 0);
	CU_ASSERT(config.pktout.all_bits == 0);
	CU_ASSERT(config.parser.layer == ODP_PROTO_LAYER_ALL);
	CU_ASSERT(!config.enable_loop);
	CU_ASSERT(!config.inbound_ipsec);
	CU_ASSERT(!config.outbound_ipsec);
	CU_ASSERT(!config.enable_lso);
	CU_ASSERT(!config.reassembly.en_ipv4);
	CU_ASSERT(!config.reassembly.en_ipv6);
	CU_ASSERT(config.reassembly.max_wait_time == 0);
	CU_ASSERT(config.reassembly.max_num_frags == 2);
	CU_ASSERT(config.flow_control.pause_rx == ODP_PKTIO_LINK_PAUSE_OFF);
	CU_ASSERT(config.flow_control.pause_tx == ODP_PKTIO_LINK_PAUSE_OFF);

	/* Indicate packet refs might be used */
	config.pktout.bit.no_packet_refs = 0;

	CU_ASSERT(odp_pktio_config(pktio, NULL) == 0);

	CU_ASSERT(odp_pktio_config(pktio, &config) == 0);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0);

	/* Loop interface supports loopback mode by definition */
	if (!strcmp(iface, "loop"))
		CU_ASSERT(capa.config.enable_loop);

	config = capa.config;

	/* Disable inbound_ipsec as it requires IPsec config to be done */
	config.inbound_ipsec = 0;

	CU_ASSERT(odp_pktio_config(pktio, &config) == 0);

	CU_ASSERT_FATAL(odp_pktio_close(pktio) == 0);
}

static void pktio_test_info(void)
{
	odp_pktio_t pktio;
	odp_pktio_info_t pktio_info;
	int i;

	for (i = 0; i < num_ifaces; i++) {
		pktio = create_pktio(i, ODP_PKTIN_MODE_QUEUE,
				     ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_info(pktio, &pktio_info) == 0);

		printf("pktio %d\n  name   %s\n  driver %s\n", i,
		       pktio_info.name, pktio_info.drv_name);

		CU_ASSERT(strcmp(pktio_info.name, iface_name[i]) == 0);
		CU_ASSERT(pktio_info.pool == pool[i]);
		CU_ASSERT(pktio_info.param.in_mode == ODP_PKTIN_MODE_QUEUE);
		CU_ASSERT(pktio_info.param.out_mode == ODP_PKTOUT_MODE_DIRECT);

		CU_ASSERT(odp_pktio_info(ODP_PKTIO_INVALID, &pktio_info) < 0);

		CU_ASSERT(odp_pktio_close(pktio) == 0);
	}
}

static void pktio_test_link_info(void)
{
	odp_pktio_t pktio;
	odp_pktio_link_info_t link_info;
	int i;

	for (i = 0; i < num_ifaces; i++) {
		memset(&link_info, 0, sizeof(link_info));

		pktio = create_pktio(i, ODP_PKTIN_MODE_QUEUE,
				     ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_link_info(pktio, &link_info) == 0);

		CU_ASSERT(link_info.autoneg == ODP_PKTIO_LINK_AUTONEG_UNKNOWN ||
			  link_info.autoneg == ODP_PKTIO_LINK_AUTONEG_ON ||
			  link_info.autoneg == ODP_PKTIO_LINK_AUTONEG_OFF);
		CU_ASSERT(link_info.duplex == ODP_PKTIO_LINK_DUPLEX_UNKNOWN ||
			  link_info.duplex == ODP_PKTIO_LINK_DUPLEX_HALF ||
			  link_info.duplex == ODP_PKTIO_LINK_DUPLEX_FULL);
		CU_ASSERT(link_info.pause_rx == ODP_PKTIO_LINK_PAUSE_UNKNOWN ||
			  link_info.pause_rx == ODP_PKTIO_LINK_PAUSE_OFF ||
			  link_info.pause_rx == ODP_PKTIO_LINK_PAUSE_ON ||
			  link_info.pause_rx == ODP_PKTIO_LINK_PFC_ON);
		CU_ASSERT(link_info.pause_tx == ODP_PKTIO_LINK_PAUSE_UNKNOWN ||
			  link_info.pause_tx == ODP_PKTIO_LINK_PAUSE_OFF ||
			  link_info.pause_tx == ODP_PKTIO_LINK_PAUSE_ON ||
			  link_info.pause_tx == ODP_PKTIO_LINK_PFC_ON);
		CU_ASSERT(link_info.status == ODP_PKTIO_LINK_STATUS_UNKNOWN ||
			  link_info.status == ODP_PKTIO_LINK_STATUS_UP ||
			  link_info.status == ODP_PKTIO_LINK_STATUS_DOWN);
		CU_ASSERT(link_info.media != NULL);

		CU_ASSERT(odp_pktio_link_info(ODP_PKTIO_INVALID, &link_info) < 0);

		CU_ASSERT(odp_pktio_close(pktio) == 0);
	}
}

static int pktio_check_flow_control(int pfc, int rx)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0)
		return ODP_TEST_INACTIVE;

	if (pfc == 0 && rx == 1 && capa.flow_control.pause_rx == 1)
		return ODP_TEST_ACTIVE;

	if (pfc == 1 && rx == 1 && capa.flow_control.pfc_rx == 1)
		return ODP_TEST_ACTIVE;

	if (pfc == 0 && rx == 0 && capa.flow_control.pause_tx == 1)
		return ODP_TEST_ACTIVE;

	if (pfc == 1 && rx == 0 && capa.flow_control.pfc_tx == 1)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int pktio_check_pause_rx(void)
{
	return pktio_check_flow_control(0, 1);
}

static int pktio_check_pause_tx(void)
{
	return pktio_check_flow_control(0, 0);
}

static int pktio_check_pause_both(void)
{
	int rx = pktio_check_pause_rx();
	int tx = pktio_check_pause_tx();

	if (rx == ODP_TEST_ACTIVE && tx == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static int pktio_check_pfc_rx(void)
{
	return pktio_check_flow_control(1, 1);
}

static int pktio_check_pfc_tx(void)
{
	return pktio_check_flow_control(1, 0);
}

static int pktio_check_pfc_both(void)
{
	int rx = pktio_check_pfc_rx();
	int tx = pktio_check_pfc_tx();

	if (rx == ODP_TEST_ACTIVE && tx == ODP_TEST_ACTIVE)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static odp_cos_t set_default_cos(odp_pktio_t pktio, odp_queue_t queue)
{
	odp_cls_cos_param_t cos_param;
	odp_cos_t cos;
	int ret;

	odp_cls_cos_param_init(&cos_param);
	cos_param.queue = queue;
	cos_param.pool  = pool[0];

	cos = odp_cls_cos_create("Default CoS", &cos_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	ret = odp_pktio_default_cos_set(pktio, cos);
	CU_ASSERT_FATAL(ret == 0);

	return cos;
}

static odp_cos_t create_pfc_cos(odp_cos_t default_cos, odp_queue_t queue, odp_pmr_t *pmr_out)
{
	odp_cls_cos_param_t cos_param;
	odp_cos_t cos;
	odp_pmr_param_t pmr_param;
	odp_pmr_t pmr;
	uint8_t pcp = 1;
	uint8_t mask = 0x7;

	/* Setup a CoS to control generation of PFC frame generation. PFC for the VLAN
	 * priority level is generated when queue/pool resource usage gets above 80%. */
	odp_cls_cos_param_init(&cos_param);
	cos_param.queue = queue;
	cos_param.pool = pool[0];
	cos_param.bp.enable = 1;
	cos_param.bp.threshold.type = ODP_THRESHOLD_PERCENT;
	cos_param.bp.threshold.percent.max = 80;
	cos_param.bp.pfc_level = pcp;

	cos = odp_cls_cos_create("PFC CoS", &cos_param);
	CU_ASSERT_FATAL(cos != ODP_COS_INVALID);

	odp_cls_pmr_param_init(&pmr_param);
	pmr_param.term        = ODP_PMR_VLAN_PCP_0;
	pmr_param.match.value = &pcp;
	pmr_param.match.mask  = &mask;
	pmr_param.val_sz      = 1;

	pmr = odp_cls_pmr_create(&pmr_param, 1, default_cos, cos);
	CU_ASSERT_FATAL(pmr != ODP_PMR_INVALID);

	*pmr_out = pmr;

	return cos;
}

static void pktio_config_flow_control(int pfc, int rx, int tx)
{
	odp_pktio_t pktio;
	odp_pktio_config_t config;
	int ret;
	odp_cos_t default_cos = ODP_COS_INVALID;
	odp_cos_t cos = ODP_COS_INVALID;
	odp_pmr_t pmr = ODP_PMR_INVALID;
	odp_queue_t queue = ODP_QUEUE_INVALID;
	odp_pktio_link_pause_t mode = ODP_PKTIO_LINK_PAUSE_ON;

	pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	odp_pktio_config_init(&config);

	if (pfc)
		mode = ODP_PKTIO_LINK_PFC_ON;

	if (rx)
		config.flow_control.pause_rx = mode;

	if (tx)
		config.flow_control.pause_tx = mode;

	ret = odp_pktio_config(pktio, &config);
	CU_ASSERT_FATAL(ret == 0);

	if (pfc && tx) {
		/* Enable classifier for PFC backpressure configuration. Overrides previous
		 * pktin queue config. */
		odp_pktin_queue_param_t pktin_param;

		odp_pktin_queue_param_init(&pktin_param);

		pktin_param.classifier_enable = 1;

		ret = odp_pktin_queue_config(pktio, &pktin_param);
		CU_ASSERT_FATAL(ret == 0);
	}

	ret = odp_pktio_start(pktio);
	CU_ASSERT(ret == 0);

	if (pfc && tx) {
		odp_queue_param_t qparam;

		odp_queue_param_init(&qparam);
		qparam.type = ODP_QUEUE_TYPE_SCHED;

		queue = odp_queue_create("CoS queue", &qparam);
		CU_ASSERT_FATAL(queue != ODP_QUEUE_INVALID);

		default_cos = set_default_cos(pktio, queue);

		cos = create_pfc_cos(default_cos, queue, &pmr);
	}

	if (pmr != ODP_PMR_INVALID)
		odp_cls_pmr_destroy(pmr);

	if (cos != ODP_COS_INVALID)
		odp_cos_destroy(cos);

	if (default_cos != ODP_COS_INVALID) {
		odp_pktio_default_cos_set(pktio, ODP_COS_INVALID);
		odp_cos_destroy(default_cos);
	}

	if (queue != ODP_QUEUE_INVALID)
		odp_queue_destroy(queue);

	CU_ASSERT(odp_pktio_stop(pktio) == 0);
	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

static void pktio_test_enable_pause_rx(void)
{
	pktio_config_flow_control(0, 1, 0);
}

static void pktio_test_enable_pause_tx(void)
{
	pktio_config_flow_control(0, 0, 1);
}

static void pktio_test_enable_pause_both(void)
{
	pktio_config_flow_control(0, 1, 1);
}

static void pktio_test_enable_pfc_rx(void)
{
	pktio_config_flow_control(1, 1, 0);
}

static void pktio_test_enable_pfc_tx(void)
{
	pktio_config_flow_control(1, 0, 1);
}

static void pktio_test_enable_pfc_both(void)
{
	pktio_config_flow_control(1, 1, 1);
}

static void pktio_test_pktin_queue_config_direct(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t queue_param;
	odp_pktin_queue_t pktin_queues[MAX_QUEUES];
	odp_queue_t in_queues[MAX_QUEUES];
	int num_queues;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT(odp_pktio_capability(ODP_PKTIO_INVALID, &capa) < 0);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0 &&
			capa.max_input_queues > 0);
	num_queues = capa.max_input_queues;

	odp_pktin_queue_param_init(&queue_param);

	queue_param.hash_enable = (num_queues > 1) ? 1 : 0;
	queue_param.hash_proto.proto.ipv4_udp = 1;
	queue_param.num_queues  = num_queues;
	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktin_queue(pktio, pktin_queues, MAX_QUEUES)
		  == num_queues);
	CU_ASSERT(odp_pktin_event_queue(pktio, in_queues, MAX_QUEUES) < 0);

	queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	queue_param.num_queues  = 1;
	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktin_queue_config(ODP_PKTIO_INVALID, &queue_param) < 0);

	queue_param.num_queues = capa.max_input_queues + 1;
	CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) < 0);

	CU_ASSERT_FATAL(odp_pktio_close(pktio) == 0);
}

static void pktio_test_pktin_queue_config_sched(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t queue_param;
	odp_pktin_queue_t pktin_queues[MAX_QUEUES];
	odp_queue_t in_queues[MAX_QUEUES];
	int num_queues;

	pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0 &&
			capa.max_input_queues > 0);
	num_queues = capa.max_input_queues;

	odp_pktin_queue_param_init(&queue_param);

	queue_param.hash_enable = (num_queues > 1) ? 1 : 0;
	queue_param.hash_proto.proto.ipv4_udp = 1;
	queue_param.num_queues = num_queues;
	queue_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	queue_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktin_event_queue(pktio, in_queues, MAX_QUEUES)
		  == num_queues);
	CU_ASSERT(odp_pktin_queue(pktio, pktin_queues, MAX_QUEUES) < 0);

	queue_param.num_queues = 1;
	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	queue_param.num_queues = capa.max_input_queues + 1;
	CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) < 0);

	CU_ASSERT_FATAL(odp_pktio_close(pktio) == 0);
}

static void pktio_test_pktin_queue_config_multi_sched(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t queue_param;
	odp_queue_t in_queues[MAX_QUEUES];
	odp_pktin_queue_param_ovr_t queue_param_ovr[MAX_QUEUES];
	int num_queues, i;

	pktio = create_pktio(0, ODP_PKTIN_MODE_SCHED, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0 &&
			capa.max_input_queues > 0);
	num_queues = (capa.max_input_queues < MAX_QUEUES) ?
		capa.max_input_queues : MAX_QUEUES;

	odp_pktin_queue_param_init(&queue_param);

	queue_param.hash_enable = 0;
	queue_param.num_queues = num_queues;
	queue_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	queue_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;

	for (i = 0; i < num_queues; i++)
		queue_param_ovr[i].group = ODP_SCHED_GROUP_ALL;
	queue_param.queue_param_ovr = queue_param_ovr;

	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktin_event_queue(pktio, in_queues, MAX_QUEUES)
		  == num_queues);

	CU_ASSERT_FATAL(odp_pktio_close(pktio) == 0);
}

static void pktio_test_pktin_queue_config_queue(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t queue_param;
	odp_pktin_queue_t pktin_queues[MAX_QUEUES];
	int num_queues;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0 &&
			capa.max_input_queues > 0);
	num_queues = capa.max_input_queues;
	CU_ASSERT_FATAL(num_queues <= ODP_PKTIN_MAX_QUEUES);

	CU_ASSERT(capa.min_input_queue_size <= capa.max_input_queue_size);

	odp_pktin_queue_param_init(&queue_param);

	queue_param.hash_enable = (num_queues > 1) ? 1 : 0;
	queue_param.hash_proto.proto.ipv4_udp = 1;
	queue_param.num_queues  = num_queues;
	for (int i = 0; i < num_queues; i++)
		queue_param.queue_size[i] = capa.max_input_queue_size;

	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktin_queue(pktio, pktin_queues, MAX_QUEUES) == num_queues);

	queue_param.num_queues = 1;
	queue_param.queue_size[0] = capa.min_input_queue_size;

	CU_ASSERT_FATAL(odp_pktin_queue_config(pktio, &queue_param) == 0);

	queue_param.num_queues = capa.max_input_queues + 1;
	CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) < 0);

	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

static void pktio_test_pktout_queue_config(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktout_queue_param_t queue_param;
	odp_pktout_queue_t pktout_queues[MAX_QUEUES];
	int num_queues;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0 &&
			capa.max_output_queues > 0);
	num_queues = capa.max_output_queues;
	CU_ASSERT_FATAL(num_queues <= ODP_PKTOUT_MAX_QUEUES);

	CU_ASSERT(capa.min_output_queue_size <= capa.max_output_queue_size);

	odp_pktout_queue_param_init(&queue_param);

	queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
	queue_param.num_queues  = num_queues;
	for (int i = 0; i < num_queues; i++)
		queue_param.queue_size[i] = capa.max_output_queue_size;

	CU_ASSERT(odp_pktout_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktout_queue(pktio, pktout_queues, MAX_QUEUES)
		  == num_queues);

	queue_param.op_mode = ODP_PKTIO_OP_MT;
	queue_param.num_queues  = 1;
	queue_param.queue_size[0] = capa.min_output_queue_size;

	CU_ASSERT(odp_pktout_queue_config(pktio, &queue_param) == 0);

	CU_ASSERT(odp_pktout_queue_config(ODP_PKTIO_INVALID, &queue_param) < 0);

	queue_param.num_queues = capa.max_output_queues + 1;
	CU_ASSERT(odp_pktout_queue_config(pktio, &queue_param) < 0);

	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

#ifdef DEBUG_STATS
static void _print_pktio_stats(odp_pktio_stats_t *s, const char *name)
{
	ODPH_ERR("\n%s:\n"
		 "  in_octets %" PRIu64 "\n"
		 "  in_packets %" PRIu64 "\n"
		 "  in_ucast_pkts %" PRIu64 "\n"
		 "  in_mcast_pkts %" PRIu64 "\n"
		 "  in_bcast_pkts %" PRIu64 "\n"
		 "  in_discards %" PRIu64 "\n"
		 "  in_errors %" PRIu64 "\n"
		 "  out_octets %" PRIu64 "\n"
		 "  out_packets %" PRIu64 "\n"
		 "  out_ucast_pkts %" PRIu64 "\n"
		 "  out_mcast_pkts %" PRIu64 "\n"
		 "  out_bcast_pkts %" PRIu64 "\n"
		 "  out_discards %" PRIu64 "\n"
		 "  out_errors %" PRIu64 "\n",
		 name,
		 s->in_octets,
		 s->in_packets,
		 s->in_ucast_pkts,
		 s->in_mcast_pkts,
		 s->in_bcast_pkts,
		 s->in_discards,
		 s->in_errors,
		 s->out_octets,
		 s->out_packets,
		 s->out_ucast_pkts,
		 s->out_mcast_pkts,
		 s->out_bcast_pkts,
		 s->out_discards,
		 s->out_errors);
}
#endif

static int pktio_check_statistics_counters(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || capa.stats.pktio.all_counters == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_statistics_counters(void)
{
	odp_pktio_t pktio_rx, pktio_tx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {
		ODP_PKTIO_INVALID, ODP_PKTIO_INVALID
	};
	odp_packet_t pkt;
	odp_packet_t tx_pkt[NUM_TEST_PKTS];
	uint32_t pkt_seq[NUM_TEST_PKTS];
	odp_event_t ev;
	int i, pkts, tx_pkts, ret, alloc = 0;
	odp_pktout_queue_t pktout;
	uint64_t wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);
	odp_pktio_stats_t stats[2];
	odp_pktio_stats_t *rx_stats, *tx_stats;
	odp_pktio_capability_t rx_capa, tx_capa;

	for (i = 0; i < num_ifaces; i++) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_SCHED,
					ODP_PKTOUT_MODE_DIRECT);

		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
	}
	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &tx_capa) == 0);
	CU_ASSERT_FATAL(odp_pktio_capability(pktio_rx, &rx_capa) == 0);

	CU_ASSERT_FATAL(odp_pktout_queue(pktio_tx, &pktout, 1) == 1);

	ret = odp_pktio_start(pktio_tx);
	CU_ASSERT(ret == 0);
	if (num_ifaces > 1) {
		ret = odp_pktio_start(pktio_rx);
		CU_ASSERT(ret == 0);
	}

	alloc = create_packets(tx_pkt, pkt_seq, NUM_TEST_PKTS, pktio_tx, pktio_rx);

	ret = odp_pktio_stats_reset(pktio_tx);
	CU_ASSERT(ret == 0);
	if (num_ifaces > 1) {
		ret = odp_pktio_stats_reset(pktio_rx);
		CU_ASSERT(ret == 0);
	}

	/* send */
	for (pkts = 0; pkts != alloc; ) {
		ret = odp_pktout_send(pktout, &tx_pkt[pkts], alloc - pkts);
		if (ret < 0) {
			CU_FAIL("unable to send packet\n");
			break;
		}
		pkts += ret;
	}
	tx_pkts = pkts;

	/* get */
	for (i = 0, pkts = 0; i < NUM_RX_ATTEMPTS && pkts != tx_pkts; i++) {
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

	CU_ASSERT(pkts == tx_pkts);

	ret = odp_pktio_stats(pktio_tx, &stats[0]);
	CU_ASSERT(ret == 0);
	tx_stats = &stats[0];

	CU_ASSERT((tx_capa.stats.pktio.counter.out_octets == 0) ||
		  (tx_stats->out_octets >= (PKT_LEN_NORMAL * (uint64_t)pkts)));
	CU_ASSERT((tx_capa.stats.pktio.counter.out_packets == 0) ||
		  (tx_stats->out_packets >= (uint64_t)pkts));
	CU_ASSERT((tx_capa.stats.pktio.counter.out_ucast_pkts == 0) ||
		  (tx_stats->out_ucast_pkts >= (uint64_t)pkts));
	CU_ASSERT(tx_stats->out_discards == 0);
	CU_ASSERT(tx_stats->out_errors == 0);

	rx_stats = &stats[0];
	if (num_ifaces > 1) {
		rx_stats = &stats[1];
		ret = odp_pktio_stats(pktio_rx, rx_stats);
		CU_ASSERT(ret == 0);
	}
	CU_ASSERT((rx_capa.stats.pktio.counter.in_octets == 0) ||
		  (rx_stats->in_octets >= (PKT_LEN_NORMAL * (uint64_t)pkts)));
	CU_ASSERT((rx_capa.stats.pktio.counter.in_packets == 0) ||
		  (rx_stats->in_packets >= (uint64_t)pkts));
	CU_ASSERT((rx_capa.stats.pktio.counter.in_ucast_pkts == 0) ||
		  (rx_stats->in_ucast_pkts >= (uint64_t)pkts));
	CU_ASSERT(rx_stats->in_discards == 0);
	CU_ASSERT(rx_stats->in_errors == 0);

	/* Check that all unsupported counters are still zero */
	if (!rx_capa.stats.pktio.counter.in_octets)
		CU_ASSERT(rx_stats->in_octets == 0);
	if (!rx_capa.stats.pktio.counter.in_packets)
		CU_ASSERT(rx_stats->in_packets == 0);
	if (!rx_capa.stats.pktio.counter.in_ucast_pkts)
		CU_ASSERT(rx_stats->in_ucast_pkts == 0);
	if (!rx_capa.stats.pktio.counter.in_mcast_pkts)
		CU_ASSERT(rx_stats->in_mcast_pkts == 0);
	if (!rx_capa.stats.pktio.counter.in_bcast_pkts)
		CU_ASSERT(rx_stats->in_bcast_pkts == 0);
	if (!rx_capa.stats.pktio.counter.in_discards)
		CU_ASSERT(rx_stats->in_discards == 0);
	if (!rx_capa.stats.pktio.counter.in_errors)
		CU_ASSERT(rx_stats->in_errors == 0);

	if (!tx_capa.stats.pktio.counter.out_octets)
		CU_ASSERT(tx_stats->out_octets == 0);
	if (!tx_capa.stats.pktio.counter.out_packets)
		CU_ASSERT(tx_stats->out_packets == 0);
	if (!tx_capa.stats.pktio.counter.out_ucast_pkts)
		CU_ASSERT(tx_stats->out_ucast_pkts == 0);
	if (!tx_capa.stats.pktio.counter.out_mcast_pkts)
		CU_ASSERT(tx_stats->out_mcast_pkts == 0);
	if (!tx_capa.stats.pktio.counter.out_bcast_pkts)
		CU_ASSERT(tx_stats->out_bcast_pkts == 0);
	if (!tx_capa.stats.pktio.counter.out_discards)
		CU_ASSERT(tx_stats->out_discards == 0);
	if (!tx_capa.stats.pktio.counter.out_errors)
		CU_ASSERT(tx_stats->out_errors == 0);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT(odp_pktio_stop(pktio[i]) == 0);
#ifdef DEBUG_STATS
		_print_pktio_stats(&stats[i], iface_name[i]);
#endif
		flush_input_queue(pktio[i], ODP_PKTIN_MODE_SCHED);
		CU_ASSERT(odp_pktio_close(pktio[i]) == 0);
	}
}

static int pktio_check_statistics_counters_bcast(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || (capa.stats.pktio.counter.in_bcast_pkts == 0 &&
			capa.stats.pktio.counter.out_bcast_pkts == 0))
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_statistics_counters_bcast(void)
{
	odp_pktio_t pktio_rx, pktio_tx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {
		ODP_PKTIO_INVALID, ODP_PKTIO_INVALID
	};
	odp_packet_t pkt;
	odp_packet_t tx_pkt[1000];
	uint32_t pkt_seq[1000];
	odp_event_t ev;
	int i, pkts, tx_pkts, ret, alloc = 0;
	odp_pktout_queue_t pktout;
	uint64_t wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);
	odp_pktio_stats_t stats[2];
	odp_pktio_stats_t *rx_stats, *tx_stats;
	odp_pktio_capability_t rx_capa, tx_capa;

	for (i = 0; i < num_ifaces; i++) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_SCHED,
					ODP_PKTOUT_MODE_DIRECT);

		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
	}
	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &tx_capa) == 0);
	CU_ASSERT_FATAL(odp_pktio_capability(pktio_rx, &rx_capa) == 0);

	CU_ASSERT_FATAL(odp_pktout_queue(pktio_tx, &pktout, 1) == 1);

	CU_ASSERT_FATAL(odp_pktio_start(pktio_tx) == 0);
	if (num_ifaces > 1)
		CU_ASSERT_FATAL(odp_pktio_start(pktio_rx) == 0);

	alloc = create_packets_udp(tx_pkt, pkt_seq, 1000, pktio_tx, pktio_rx,
				   true, ETH_BROADCAST);

	CU_ASSERT(odp_pktio_stats_reset(pktio_tx) == 0);
	if (num_ifaces > 1)
		CU_ASSERT(odp_pktio_stats_reset(pktio_rx) == 0);

	/* send */
	for (pkts = 0; pkts != alloc; ) {
		ret = odp_pktout_send(pktout, &tx_pkt[pkts], alloc - pkts);
		if (ret < 0) {
			CU_FAIL("unable to send packet\n");
			break;
		}
		pkts += ret;
	}
	tx_pkts = pkts;

	/* get */
	for (i = 0, pkts = 0; i < 1000 && pkts != tx_pkts; i++) {
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

	CU_ASSERT(pkts == tx_pkts);

	CU_ASSERT(odp_pktio_stats(pktio_tx, &stats[0]) == 0);
	tx_stats = &stats[0];

	CU_ASSERT((tx_capa.stats.pktio.counter.out_bcast_pkts == 0) ||
		  (tx_stats->out_bcast_pkts >= (uint64_t)pkts));
	CU_ASSERT((tx_capa.stats.pktio.counter.out_octets == 0) ||
		  (tx_stats->out_octets >= (PKT_LEN_NORMAL * (uint64_t)pkts)));
	CU_ASSERT((tx_capa.stats.pktio.counter.out_packets == 0) ||
		  (tx_stats->out_packets >= (uint64_t)pkts));

	rx_stats = &stats[0];
	if (num_ifaces > 1) {
		rx_stats = &stats[1];
		CU_ASSERT(odp_pktio_stats(pktio_rx, rx_stats) == 0);
	}
	CU_ASSERT((rx_capa.stats.pktio.counter.in_bcast_pkts == 0) ||
		  (rx_stats->in_bcast_pkts >= (uint64_t)pkts));
	CU_ASSERT((rx_capa.stats.pktio.counter.in_octets == 0) ||
		  (rx_stats->in_octets >= (PKT_LEN_NORMAL * (uint64_t)pkts)));
	CU_ASSERT((rx_capa.stats.pktio.counter.in_packets == 0) ||
		  (rx_stats->in_packets >= (uint64_t)pkts));

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT(odp_pktio_stop(pktio[i]) == 0);
#ifdef DEBUG_STATS
		_print_pktio_stats(&stats[i], iface_name[i]);
#endif
		flush_input_queue(pktio[i], ODP_PKTIN_MODE_SCHED);
		CU_ASSERT(odp_pktio_close(pktio[i]) == 0);
	}
}

static int pktio_check_queue_statistics_counters(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || (capa.stats.pktin_queue.all_counters == 0 &&
			capa.stats.pktout_queue.all_counters == 0))
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_queue_statistics_counters(void)
{
	odp_pktio_t pktio_rx, pktio_tx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {
		ODP_PKTIO_INVALID, ODP_PKTIO_INVALID
	};
	odp_packet_t tx_pkt[NUM_TEST_PKTS];
	uint32_t pkt_seq[NUM_TEST_PKTS];
	int i, pkts, tx_pkts, ret, alloc = 0;
	odp_pktout_queue_t pktout;
	odp_pktin_queue_t pktin;
	uint64_t wait = odp_pktin_wait_time(ODP_TIME_SEC_IN_NS);
	odp_pktin_queue_stats_t rx_stats;
	odp_pktout_queue_stats_t tx_stats;
	odp_pktio_capability_t rx_capa, tx_capa;

	for (i = 0; i < num_ifaces; i++) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_DIRECT,
					ODP_PKTOUT_MODE_DIRECT);

		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
	}
	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &tx_capa) == 0);
	CU_ASSERT_FATAL(odp_pktio_capability(pktio_rx, &rx_capa) == 0);

	CU_ASSERT_FATAL(odp_pktin_queue(pktio_rx, &pktin, 1) == 1);
	CU_ASSERT_FATAL(odp_pktout_queue(pktio_tx, &pktout, 1) == 1);

	CU_ASSERT_FATAL(odp_pktio_start(pktio_tx) == 0);
	if (num_ifaces > 1)
		CU_ASSERT_FATAL(odp_pktio_start(pktio_rx) == 0);

	alloc = create_packets(tx_pkt, pkt_seq, NUM_TEST_PKTS, pktio_tx, pktio_rx);

	CU_ASSERT(odp_pktio_stats_reset(pktio_tx) == 0);
	if (num_ifaces > 1)
		CU_ASSERT(odp_pktio_stats_reset(pktio_rx) == 0);

	for (pkts = 0; pkts != alloc; ) {
		ret = odp_pktout_send(pktout, &tx_pkt[pkts], alloc - pkts);
		if (ret < 0) {
			CU_FAIL("unable to send packet\n");
			break;
		}
		pkts += ret;
	}
	tx_pkts = pkts;

	for (i = 0, pkts = 0; i < NUM_RX_ATTEMPTS && pkts != tx_pkts; i++) {
		odp_packet_t pkt;

		if (odp_pktin_recv_tmo(pktin, &pkt, 1, wait) != 1)
			break;

		if (pktio_pkt_seq(pkt) != TEST_SEQ_INVALID)
			pkts++;

		odp_packet_free(pkt);
	}

	CU_ASSERT(pkts == tx_pkts);

	CU_ASSERT_FATAL(odp_pktout_queue_stats(pktout, &tx_stats) == 0);
	CU_ASSERT((!tx_capa.stats.pktout_queue.counter.octets) ||
		  (tx_stats.octets >= (PKT_LEN_NORMAL * (uint64_t)pkts)));
	CU_ASSERT((!tx_capa.stats.pktout_queue.counter.packets) ||
		  (tx_stats.packets >= (uint64_t)pkts));
	CU_ASSERT(tx_stats.discards == 0);
	CU_ASSERT(tx_stats.errors == 0);

	CU_ASSERT_FATAL(odp_pktin_queue_stats(pktin, &rx_stats) == 0);
	CU_ASSERT((!rx_capa.stats.pktin_queue.counter.octets) ||
		  (rx_stats.octets >= (PKT_LEN_NORMAL * (uint64_t)pkts)));
	CU_ASSERT((!rx_capa.stats.pktin_queue.counter.packets) ||
		  (rx_stats.packets >= (uint64_t)pkts));
	CU_ASSERT(rx_stats.discards == 0);
	CU_ASSERT(rx_stats.errors == 0);

	/* Check that all unsupported counters are still zero */
	if (!rx_capa.stats.pktin_queue.counter.octets)
		CU_ASSERT(rx_stats.octets == 0);
	if (!rx_capa.stats.pktin_queue.counter.packets)
		CU_ASSERT(rx_stats.packets == 0);
	if (!tx_capa.stats.pktout_queue.counter.octets)
		CU_ASSERT(tx_stats.octets == 0);
	if (!tx_capa.stats.pktout_queue.counter.packets)
		CU_ASSERT(tx_stats.packets == 0);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT(odp_pktio_close(pktio[i]) == 0);
	}
}

static int pktio_check_event_queue_statistics_counters(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
	pktio_param.out_mode = ODP_PKTOUT_MODE_QUEUE;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || (capa.stats.pktin_queue.all_counters == 0 &&
			capa.stats.pktout_queue.all_counters == 0))
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_event_queue_statistics_counters(void)
{
	odp_pktio_t pktio_rx, pktio_tx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {
		ODP_PKTIO_INVALID, ODP_PKTIO_INVALID
	};
	odp_packet_t pkt;
	odp_packet_t tx_pkt[NUM_TEST_PKTS];
	uint32_t pkt_seq[NUM_TEST_PKTS];
	odp_event_t ev;
	int i, pkts, tx_pkts;
	odp_queue_t pktout;
	odp_queue_t pktin;
	uint64_t wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);
	odp_pktin_queue_stats_t rx_stats;
	odp_pktout_queue_stats_t tx_stats;
	odp_pktio_capability_t rx_capa, tx_capa;

	for (i = 0; i < num_ifaces; i++) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_SCHED,
					ODP_PKTOUT_MODE_QUEUE);

		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
	}
	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &tx_capa) == 0);
	CU_ASSERT_FATAL(odp_pktio_capability(pktio_rx, &rx_capa) == 0);

	CU_ASSERT_FATAL(odp_pktin_event_queue(pktio_rx, &pktin, 1) == 1);
	CU_ASSERT_FATAL(odp_pktout_event_queue(pktio_tx, &pktout, 1) == 1);

	CU_ASSERT_FATAL(odp_pktio_start(pktio_tx) == 0);
	if (num_ifaces > 1)
		CU_ASSERT_FATAL(odp_pktio_start(pktio_rx) == 0);

	tx_pkts = create_packets(tx_pkt, pkt_seq, NUM_TEST_PKTS, pktio_tx, pktio_rx);

	CU_ASSERT(odp_pktio_stats_reset(pktio_tx) == 0);
	if (num_ifaces > 1)
		CU_ASSERT(odp_pktio_stats_reset(pktio_rx) == 0);

	CU_ASSERT_FATAL(send_packet_events(pktout, tx_pkt, tx_pkts) == 0);

	/* Receive */
	for (i = 0, pkts = 0; i < NUM_RX_ATTEMPTS && pkts != tx_pkts; i++) {
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
	CU_ASSERT(pkts == tx_pkts);

	CU_ASSERT_FATAL(odp_pktout_event_queue_stats(pktio_tx, pktout, &tx_stats) == 0);
	CU_ASSERT((!tx_capa.stats.pktout_queue.counter.octets) ||
		  (tx_stats.octets >= (PKT_LEN_NORMAL * (uint64_t)pkts)));
	CU_ASSERT((!tx_capa.stats.pktout_queue.counter.packets) ||
		  (tx_stats.packets >= (uint64_t)pkts));
	CU_ASSERT(tx_stats.discards == 0);
	CU_ASSERT(tx_stats.errors == 0);

	CU_ASSERT_FATAL(odp_pktin_event_queue_stats(pktio_rx, pktin, &rx_stats) == 0);
	CU_ASSERT((!rx_capa.stats.pktin_queue.counter.octets) ||
		  (rx_stats.octets >= (PKT_LEN_NORMAL * (uint64_t)pkts)));
	CU_ASSERT((!rx_capa.stats.pktin_queue.counter.packets) ||
		  (rx_stats.packets >= (uint64_t)pkts));
	CU_ASSERT(rx_stats.discards == 0);
	CU_ASSERT(rx_stats.errors == 0);

	/* Check that all unsupported counters are still zero */
	if (!rx_capa.stats.pktin_queue.counter.octets)
		CU_ASSERT(rx_stats.octets == 0);
	if (!rx_capa.stats.pktin_queue.counter.packets)
		CU_ASSERT(rx_stats.packets == 0);
	if (!tx_capa.stats.pktout_queue.counter.octets)
		CU_ASSERT(tx_stats.octets == 0);
	if (!tx_capa.stats.pktout_queue.counter.packets)
		CU_ASSERT(tx_stats.packets == 0);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT(odp_pktio_stop(pktio[i]) == 0);
		flush_input_queue(pktio[i], ODP_PKTIN_MODE_SCHED);
		CU_ASSERT(odp_pktio_close(pktio[i]) == 0);
	}
}

static void pktio_test_extra_stats(void)
{
	odp_pktio_t pktio;
	int num_info, num_stats, i, ret;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);
	CU_ASSERT_FATAL(odp_pktio_start(pktio) == 0);

	num_info = odp_pktio_extra_stat_info(pktio, NULL, 0);
	CU_ASSERT_FATAL(num_info >= 0);

	num_stats = odp_pktio_extra_stats(pktio, NULL, 0);
	CU_ASSERT_FATAL(num_stats >= 0);

	CU_ASSERT_FATAL(num_info == num_stats);

	/* No extra statistics supported */
	if (num_stats == 0) {
		CU_ASSERT(odp_pktio_stop(pktio) == 0);
		CU_ASSERT(odp_pktio_close(pktio) == 0);
		return;
	}

	odp_pktio_extra_stat_info_t stats_info[num_stats];
	uint64_t extra_stats[num_stats];

	ret = odp_pktio_extra_stat_info(pktio, stats_info, num_stats);
	CU_ASSERT(ret == num_stats);
	num_info = ret;

	ret = odp_pktio_extra_stats(pktio, extra_stats, num_stats);
	CU_ASSERT(ret == num_stats);
	CU_ASSERT_FATAL(ret <= num_stats);
	num_stats = ret;

	CU_ASSERT_FATAL(num_info == num_stats);

	printf("\nPktio extra statistics\n----------------------\n");
	for (i = 0; i < num_stats; i++)
		printf("  %s=%" PRIu64 "\n", stats_info[i].name, extra_stats[i]);

	for (i = 0; i < num_stats; i++) {
		uint64_t stat = 0;

		CU_ASSERT(odp_pktio_extra_stat_counter(pktio, i, &stat) == 0);
	}

	odp_pktio_extra_stats_print(pktio);

	CU_ASSERT(odp_pktio_stop(pktio) == 0);
	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

static int pktio_check_proto_statistics_counters(void)
{
	odp_proto_stats_capability_t capa;
	odp_pktio_param_t pktio_param;
	odp_pktio_t pktio;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_proto_stats_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || capa.tx.counters.all_bits == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void validate_proto_stats(odp_proto_stats_t stat, odp_packet_proto_stats_opt_t opt,
				 odp_proto_stats_capability_t capa, uint64_t pkts)
{
	odp_proto_stats_data_t data;
	int ret;

	ret = odp_proto_stats(stat, &data);
	CU_ASSERT(ret == 0);

	CU_ASSERT(!(capa.tx.counters.bit.tx_pkt_drops && (data.tx_pkt_drops > 0)));
	CU_ASSERT(!(capa.tx.counters.bit.tx_oct_count0_drops && (data.tx_oct_count0_drops > 0)));
	CU_ASSERT(!(capa.tx.counters.bit.tx_oct_count1_drops && (data.tx_oct_count1_drops > 0)));
	CU_ASSERT(!(capa.tx.counters.bit.tx_pkts && (data.tx_pkts != pkts)));

	if (capa.tx.counters.bit.tx_oct_count0) {
		int64_t counted_bytes = PKT_LEN_NORMAL;

		if (capa.tx.oct_count0_adj)
			counted_bytes += opt.oct_count0_adj;
		CU_ASSERT(data.tx_oct_count0 == counted_bytes * pkts);
	}

	if (capa.tx.counters.bit.tx_oct_count1) {
		int64_t counted_bytes = PKT_LEN_NORMAL;

		if (capa.tx.oct_count1_adj)
			counted_bytes += opt.oct_count1_adj;
		CU_ASSERT(data.tx_oct_count1 == counted_bytes * pkts);
	}
}

static void pktio_test_proto_statistics_counters(void)
{
	odp_pktio_t pktio_rx, pktio_tx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {
		ODP_PKTIO_INVALID, ODP_PKTIO_INVALID
	};
	odp_packet_t pkt;
	const uint32_t num_pkts = 10;
	odp_packet_t tx_pkt[num_pkts];
	uint32_t pkt_seq[num_pkts];
	odp_event_t ev;
	int i, pkts, tx_pkts, ret, alloc = 0;
	odp_pktout_queue_t pktout;
	uint64_t wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);
	uint64_t flow0_pkts = 0, flow1_pkts = 0;
	odp_proto_stats_capability_t capa;
	odp_packet_proto_stats_opt_t opt0;
	odp_packet_proto_stats_opt_t opt1;
	odp_proto_stats_param_t param;
	odp_pktio_config_t config;
	odp_proto_stats_t stat0;
	odp_proto_stats_t stat1;

	memset(&pktout, 0, sizeof(pktout));

	for (i = 0; i < num_ifaces; i++) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_SCHED,
					ODP_PKTOUT_MODE_DIRECT);

		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
	}
	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;

	/* Enable protocol stats on Tx interface */
	odp_pktio_config_init(&config);
	config.pktout.bit.proto_stats_ena = 1;
	ret = odp_pktio_config(pktio_tx, &config);
	CU_ASSERT(ret == 0);

	CU_ASSERT_FATAL(odp_pktout_queue(pktio_tx, &pktout, 1) == 1);

	ret = odp_pktio_start(pktio_tx);
	CU_ASSERT(ret == 0);
	if (num_ifaces > 1) {
		ret = odp_pktio_start(pktio_rx);
		CU_ASSERT(ret == 0);
	}

	odp_proto_stats_param_init(&param);
	odp_proto_stats_capability(pktio_tx, &capa);
	CU_ASSERT(capa.tx.counters.all_bits != 0);
	param.counters.all_bits = capa.tx.counters.all_bits;
	/* Create statistics object with all supported counters */
	stat0 = odp_proto_stats_create("flow0_stat", &param);
	CU_ASSERT_FATAL(stat0 != ODP_PROTO_STATS_INVALID);
	stat1 = odp_proto_stats_create("flow1_stat", &param);
	CU_ASSERT_FATAL(stat1 != ODP_PROTO_STATS_INVALID);

	/* Flow-0 options */
	opt0.stat = stat0;
	opt0.oct_count0_adj = 0;
	/* oct1 contains byte count of packets excluding Ethernet header */
	opt0.oct_count1_adj = -14;

	/* Flow-1 options */
	opt1.stat = stat1;
	opt1.oct_count0_adj = -8;
	opt1.oct_count1_adj = 14;

	alloc = create_packets(tx_pkt, pkt_seq, num_pkts, pktio_tx, pktio_rx);

	/* Attach statistics object to all Tx packets */
	for (pkts = 0; pkts < alloc; pkts++) {
		if ((pkts % 2) == 0) {
			odp_packet_proto_stats_request(tx_pkt[pkts], &opt0);
			flow0_pkts++;
		} else {
			odp_packet_proto_stats_request(tx_pkt[pkts], &opt1);
			flow1_pkts++;
		}
	}

	/* send */
	for (pkts = 0; pkts != alloc; ) {
		ret = odp_pktout_send(pktout, &tx_pkt[pkts], alloc - pkts);
		if (ret < 0) {
			CU_FAIL("unable to send packet\n");
			break;
		}
		pkts += ret;
	}
	tx_pkts = pkts;

	/* get */
	for (i = 0, pkts = 0; i < (int)num_pkts && pkts != tx_pkts; i++) {
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

	CU_ASSERT(pkts == tx_pkts);

	/* Validate Flow-0 packet statistics */
	validate_proto_stats(stat0, opt0, capa, flow0_pkts);

	/* Validate Flow-1 packet statistics */
	validate_proto_stats(stat1, opt1, capa, flow1_pkts);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT(odp_pktio_stop(pktio[i]) == 0);
		flush_input_queue(pktio[i], ODP_PKTIN_MODE_SCHED);
		CU_ASSERT(odp_pktio_close(pktio[i]) == 0);
	}

	/* Destroy proto statistics object */
	CU_ASSERT(odp_proto_stats_destroy(stat0) == 0);
	CU_ASSERT(odp_proto_stats_destroy(stat1) == 0);
}

static int pktio_check_start_stop(void)
{
	if (getenv("ODP_PKTIO_TEST_DISABLE_START_STOP"))
		return ODP_TEST_INACTIVE;
	return ODP_TEST_ACTIVE;
}

static void pktio_test_start_stop(void)
{
	odp_pktio_t pktio[MAX_NUM_IFACES];
	odp_pktio_t pktio_in;
	odp_packet_t pkt;
	odp_packet_t tx_pkt[NUM_TEST_PKTS];
	uint32_t pkt_seq[NUM_TEST_PKTS];
	odp_event_t ev;
	int i, pkts, ret, alloc = 0;
	odp_pktout_queue_t pktout;
	uint64_t wait = odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS);

	for (i = 0; i < num_ifaces; i++) {
		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_SCHED,
					ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
	}

	CU_ASSERT_FATAL(odp_pktout_queue(pktio[0], &pktout, 1) == 1);

	/* Interfaces are stopped by default,
	 * Check that stop when stopped generates an error */
	ret = odp_pktio_stop(pktio[0]);
	CU_ASSERT(ret < 0);

	/* start first */
	ret = odp_pktio_start(pktio[0]);
	CU_ASSERT(ret == 0);
	/* Check that start when started generates an error */
	ret = odp_pktio_start(pktio[0]);
	CU_ASSERT(ret < 0);

	_pktio_wait_linkup(pktio[0]);

	/* Test Rx on a stopped interface. Only works if there are 2 */
	if (num_ifaces > 1) {
		alloc = create_packets(tx_pkt, pkt_seq, NUM_TEST_PKTS, pktio[0],
				       pktio[1]);

		for (pkts = 0; pkts != alloc; ) {
			ret = odp_pktout_send(pktout, &tx_pkt[pkts],
					      alloc - pkts);
			if (ret < 0) {
				CU_FAIL("unable to enqueue packet\n");
				break;
			}
			pkts += ret;
		}
		/* check that packets did not arrive */
		for (i = 0, pkts = 0; i < NUM_RX_ATTEMPTS; i++) {
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

		_pktio_wait_linkup(pktio[1]);
		/* flush packets with magic number in pipes */
		for (i = 0; i < NUM_RX_ATTEMPTS; i++) {
			ev = odp_schedule(NULL, wait);
			if (ev != ODP_EVENT_INVALID)
				odp_event_free(ev);
		}
	}

	if (num_ifaces > 1)
		pktio_in = pktio[1];
	else
		pktio_in = pktio[0];

	alloc = create_packets(tx_pkt, pkt_seq, NUM_TEST_PKTS, pktio[0], pktio_in);

	/* send */
	for (pkts = 0; pkts != alloc; ) {
		ret = odp_pktout_send(pktout, &tx_pkt[pkts], alloc - pkts);
		if (ret < 0) {
			CU_FAIL("unable to enqueue packet\n");
			break;
		}
		pkts += ret;
	}

	/* get */
	for (i = 0, pkts = 0; i < NUM_RX_ATTEMPTS; i++) {
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
		CU_ASSERT(odp_pktio_close(pktio[i]) == 0);
	}

	/* Verify that a schedule call after stop and close does not generate
	   errors. */
	ev = odp_schedule(NULL, wait);
	CU_ASSERT(ev == ODP_EVENT_INVALID);
	if (ev != ODP_EVENT_INVALID)
		odp_event_free(ev);
}

static void pktio_test_recv_on_wonly(void)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktin_queue_t pktin;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DISABLED,
			     ODP_PKTOUT_MODE_DIRECT);

	if (pktio == ODP_PKTIO_INVALID) {
		CU_FAIL("failed to open pktio");
		return;
	}

	CU_ASSERT(odp_pktin_queue(pktio, &pktin, 1) == 0);

	ret = odp_pktio_start(pktio);
	CU_ASSERT_FATAL(ret == 0);

	_pktio_wait_linkup(pktio);

	ret = odp_pktio_stop(pktio);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_pktio_close(pktio);
	CU_ASSERT_FATAL(ret == 0);
}

static void pktio_test_send_on_ronly(void)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktout_queue_t pktout;

	pktio = create_pktio(0, ODP_PKTIN_MODE_DIRECT,
			     ODP_PKTOUT_MODE_DISABLED);

	if (pktio == ODP_PKTIO_INVALID) {
		CU_FAIL("failed to open pktio");
		return;
	}

	CU_ASSERT(odp_pktout_queue(pktio, &pktout, 1) == 0);

	ret = odp_pktio_start(pktio);
	CU_ASSERT_FATAL(ret == 0);

	_pktio_wait_linkup(pktio);

	ret = odp_pktio_stop(pktio);
	CU_ASSERT_FATAL(ret == 0);

	ret = odp_pktio_close(pktio);
	CU_ASSERT_FATAL(ret == 0);
}

static int pktio_check_pktin_ts(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || !capa.config.pktin.bit.ts_all)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void test_pktin_ts(uint32_t test_flags)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {0};
	pktio_info_t pktio_rx_info;
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;
	odp_pktout_queue_t pktout_queue;
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	odp_packet_t ref_tbl[TX_BATCH_LEN];
	uint32_t pkt_seq[TX_BATCH_LEN];
	uint64_t ns1, ns2;
	uint64_t res, res_ns, input_delay;
	odp_time_t ts_prev;
	odp_time_t ts;
	int num_rx = 0;
	int ret;
	int i;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio_with_flags(i, ODP_PKTIN_MODE_DIRECT,
						   ODP_PKTOUT_MODE_DIRECT,
						   test_flags);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio[i], &capa) == 0);
		CU_ASSERT_FATAL(capa.config.pktin.bit.ts_all);

		odp_pktio_config_init(&config);
		config.pktin.bit.ts_all = 1;
		CU_ASSERT_FATAL(odp_pktio_config(pktio[i], &config) == 0);

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; i++)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;
	pktio_rx_info.id   = pktio_rx;
	pktio_rx_info.inq  = ODP_QUEUE_INVALID;
	pktio_rx_info.in_mode = ODP_PKTIN_MODE_DIRECT;

	/* Test odp_pktio_ts_res() and odp_pktio_ts_from_ns() */
	res = odp_pktio_ts_res(pktio_tx);
	CU_ASSERT(res > PKTIO_TS_MIN_RES);
	CU_ASSERT(res < PKTIO_TS_MAX_RES);
	ns1 = 100;
	ts = odp_pktio_ts_from_ns(pktio_tx, ns1);
	ns2 = odp_time_to_ns(ts);
	CU_ASSERT_FATAL(res != 0);
	res_ns = ODP_TIME_SEC_IN_NS / res;
	if (ODP_TIME_SEC_IN_NS % res)
		res_ns++;
	/* Allow some arithmetic tolerance */
	CU_ASSERT((ns2 <= (ns1 + res_ns)) && (ns2 >= (ns1 - res_ns)));

	ret = create_packets(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx,
			     pktio_rx);
	CU_ASSERT_FATAL(ret == TX_BATCH_LEN);

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	if (test_flags & TEST_WITH_REFS)
		make_refs(ref_tbl, pkt_tbl, TX_BATCH_LEN);

	/* Send packets one at a time and add delay between the packets */
	for (i = 0; i < TX_BATCH_LEN;  i++) {
		CU_ASSERT_FATAL(odp_pktout_send(pktout_queue,
						&pkt_tbl[i], 1) == 1);
		ret = wait_for_packets(&pktio_rx_info, &pkt_tbl[i], &pkt_seq[i],
				       1, TXRX_MODE_SINGLE, ODP_TIME_SEC_IN_NS,
				       VECTOR_MODE_DISABLED);
		if (ret != 1)
			break;

		/* Compare to packet IO time to input timestamp */
		ts = odp_pktio_time(pktio_rx_info.id, NULL);
		CU_ASSERT_FATAL(odp_packet_has_ts(pkt_tbl[i]));
		ts_prev = odp_packet_ts(pkt_tbl[i]);
		CU_ASSERT(odp_time_cmp(ts, ts_prev) >= 0);
		input_delay = odp_time_diff_ns(ts, ts_prev);
		if (input_delay > 100 * ODP_TIME_MSEC_IN_NS) {
			printf("    Test packet %d input delay: %" PRIu64 "ns\n", i, input_delay);
			CU_FAIL("Packet input delay too long");
		}
		CU_ASSERT(odp_packet_pool(pkt_tbl[i]) == expected_rx_pool(test_flags));

		odp_time_wait_ns(PKTIO_TS_INTERVAL);
	}
	num_rx = i;
	CU_ASSERT(num_rx == TX_BATCH_LEN);

	if (test_flags & TEST_WITH_REFS)
		free_refs(ref_tbl, TX_BATCH_LEN);

	ts_prev = ODP_TIME_NULL;
	for (i = 0; i < num_rx; i++) {
		ts = odp_packet_ts(pkt_tbl[i]);

		CU_ASSERT(odp_time_cmp(ts, ts_prev) > 0);

		ts_prev = ts;
		odp_packet_free(pkt_tbl[i]);
	}

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static void pktio_test_pktin_ts(void)
{
	for (uint32_t flags = 0; flags < NUM_TEST_FLAG_COMBOS; flags++)
		test_pktin_ts(flags);
}

static int pktio_check_pktout_ts(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || !capa.config.pktout.bit.ts_ena)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void test_pktout_ts(uint32_t test_flags)
{
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	odp_pktio_t pktio[MAX_NUM_IFACES] = {0};
	odp_pktout_queue_t pktout_queue;
	odp_pktio_t pktio_tx, pktio_rx;
	uint32_t pkt_seq[TX_BATCH_LEN];
	pktio_info_t pktio_rx_info;
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;
	odp_time_t ts_prev;
	odp_time_t ts;
	int num_rx = 0;
	int ret;
	int i;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio_with_flags(i, ODP_PKTIN_MODE_DIRECT,
						   ODP_PKTOUT_MODE_DIRECT,
						   test_flags);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio[i], &capa) == 0);
		CU_ASSERT_FATAL(capa.config.pktin.bit.ts_all);

		odp_pktio_config_init(&config);
		config.pktout.bit.ts_ena = 1;
		CU_ASSERT_FATAL(odp_pktio_config(pktio[i], &config) == 0);

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; i++)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;
	pktio_rx_info.id   = pktio_rx;
	pktio_rx_info.inq  = ODP_QUEUE_INVALID;
	pktio_rx_info.in_mode = ODP_PKTIN_MODE_DIRECT;

	ret = create_packets(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx,
			     pktio_rx);
	CU_ASSERT_FATAL(ret == TX_BATCH_LEN);

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	/* Start with current pktio time */
	ts_prev = odp_pktio_time(pktio_tx, NULL);

	odp_time_wait_ns(PKTIO_TS_INTERVAL);

	/* Send packets one at a time and add delay between the packets */
	for (i = 0; i < TX_BATCH_LEN;  i++) {
		odp_packet_t ref_pkt;

		/* Enable ts capture on this pkt */
		odp_packet_ts_request(pkt_tbl[i], 1);

		if (test_flags & TEST_WITH_REFS)
			make_refs(&ref_pkt, &pkt_tbl[i], 1);

		CU_ASSERT_FATAL(odp_pktout_send(pktout_queue,
						&pkt_tbl[i], 1) == 1);
		ret = wait_for_packets(&pktio_rx_info, &pkt_tbl[i], &pkt_seq[i],
				       1, TXRX_MODE_SINGLE, ODP_TIME_SEC_IN_NS,
				       VECTOR_MODE_DISABLED);

		if (test_flags & TEST_WITH_REFS)
			free_refs(&ref_pkt, 1);

		if (ret != 1)
			break;

		/* Since we got packet back, check for sent ts */
		CU_ASSERT_FATAL(odp_pktout_ts_read(pktio_tx, &ts) == 0);

		CU_ASSERT(odp_time_cmp(ts, ts_prev) > 0);
		ts_prev = ts;

		CU_ASSERT(odp_packet_pool(pkt_tbl[i]) == expected_rx_pool(test_flags));

		odp_time_wait_ns(PKTIO_TS_INTERVAL);
	}
	num_rx = i;
	CU_ASSERT(num_rx == TX_BATCH_LEN);

	for (i = 0; i < num_rx; i++)
		odp_packet_free(pkt_tbl[i]);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static void pktio_test_pktout_ts(void)
{
	for (uint32_t flags = 0; flags < NUM_TEST_FLAG_COMBOS; flags++)
		test_pktout_ts(flags);
}

static void pktio_test_pktout_compl_event(bool use_plain_queue, uint32_t test_flags)
{
	odp_pktio_t pktio[MAX_NUM_IFACES] = {ODP_PKTIO_INVALID};
	odp_queue_t compl_queue[TX_BATCH_LEN];
	odp_schedule_capability_t sched_capa;
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	odp_packet_t ref_tbl[TX_BATCH_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	odp_pktio_capability_t pktio_capa;
	odp_queue_capability_t queue_capa;
	uint16_t seq_found[TX_BATCH_LEN];
	odp_pktout_queue_t pktout_queue;
	uint32_t pkt_seq[TX_BATCH_LEN];
	odp_pktio_t pktio_tx, pktio_rx;
	odp_packet_tx_compl_t tx_compl;
	odp_packet_tx_compl_opt_t opt;
	pktio_info_t pktio_rx_info;
	odp_pktio_config_t config;
	odp_queue_param_t qparam;
	int flag, ret, i, num_rx = 0;
	odp_event_t ev;
	uint64_t wait, u64;

	/* Create queues to receive PKTIO Tx completion events */
	CU_ASSERT_FATAL(!odp_schedule_capability(&sched_capa));
	CU_ASSERT_FATAL(!odp_queue_capability(&queue_capa));

	for (i = 0; i < TX_BATCH_LEN; i++) {
		sprintf(queuename, "TxComplQueue%u", i);
		odp_queue_param_init(&qparam);

		if (use_plain_queue) {
			qparam.type = ODP_QUEUE_TYPE_PLAIN;
		} else {
			qparam.type       = ODP_QUEUE_TYPE_SCHED;
			qparam.sched.prio = odp_schedule_default_prio();
			qparam.sched.sync = ODP_SCHED_SYNC_ATOMIC;
			qparam.sched.group = ODP_SCHED_GROUP_ALL;
		}
		compl_queue[i] = odp_queue_create(queuename, &qparam);
		CU_ASSERT_FATAL(compl_queue[i] != ODP_QUEUE_INVALID);
	}

	memset(&pktout_queue, 0, sizeof(pktout_queue));
	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio_with_flags(i, ODP_PKTIN_MODE_DIRECT,
						   ODP_PKTOUT_MODE_DIRECT,
						   test_flags);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio[i], &pktio_capa) == 0);

		/* Configure Tx completion offload for PKTIO Tx */
		if (i == 0) {
			CU_ASSERT_FATAL(pktio_capa.tx_compl.mode_event == 1);

			if (use_plain_queue) {
				CU_ASSERT_FATAL(pktio_capa.tx_compl.queue_type_plain != 0);
			} else {
				CU_ASSERT_FATAL(pktio_capa.tx_compl.queue_type_sched != 0);
			}

			odp_pktio_config_init(&config);
			config.tx_compl.mode_event = 1;
			CU_ASSERT_FATAL(odp_pktio_config(pktio[i], &config) == 0);
		}

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; i++)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;
	pktio_rx_info.id   = pktio_rx;
	pktio_rx_info.inq  = ODP_QUEUE_INVALID;
	pktio_rx_info.in_mode = ODP_PKTIN_MODE_DIRECT;

	ret = create_packets(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx, pktio_rx);
	CU_ASSERT_FATAL(ret == TX_BATCH_LEN);

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	memset(&opt, 0, sizeof(opt));

	/* Disabled by default */
	CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[0]) == 0);

	/* Check that disable works. Also COMPL_ALL should be still supported. */
	opt.queue = compl_queue[0];
#if ODP_DEPRECATED_API
	opt.mode = ODP_PACKET_TX_COMPL_ALL;
#else
	opt.mode = ODP_PACKET_TX_COMPL_EVENT;
#endif
	odp_packet_tx_compl_request(pkt_tbl[0], &opt);
	CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[0]) != 0);
	opt.mode = ODP_PACKET_TX_COMPL_DISABLED;
	odp_packet_tx_compl_request(pkt_tbl[0], &opt);
	CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[0]) == 0);
	opt.queue = compl_queue[0];
	opt.mode = ODP_PACKET_TX_COMPL_EVENT;
	odp_packet_tx_compl_request(pkt_tbl[0], &opt);
	CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[0]) != 0);
	opt.mode = ODP_PACKET_TX_COMPL_DISABLED;
	odp_packet_tx_compl_request(pkt_tbl[0], &opt);
	CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[0]) == 0);

	/* Prepare batch of pkts with different tx completion queues */
	for (i = 0; i < TX_BATCH_LEN;  i++) {
		CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[i]) == 0);
		opt.queue = compl_queue[i];
		opt.mode = ODP_PACKET_TX_COMPL_EVENT;
		odp_packet_tx_compl_request(pkt_tbl[i], &opt);
		CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[i]) != 0);
		/* Set pkt sequence number as its user ptr */
		odp_packet_user_ptr_set(pkt_tbl[i], (const void *)&pkt_seq[i]);
	}

	if (test_flags & TEST_WITH_REFS)
		make_refs(ref_tbl, pkt_tbl, TX_BATCH_LEN);

	CU_ASSERT_FATAL(odp_pktout_send(pktout_queue, pkt_tbl, TX_BATCH_LEN) == TX_BATCH_LEN);

	num_rx = wait_for_packets(&pktio_rx_info, pkt_tbl, pkt_seq, TX_BATCH_LEN, TXRX_MODE_SINGLE,
				  ODP_TIME_SEC_IN_NS, VECTOR_MODE_DISABLED);
	CU_ASSERT(num_rx == TX_BATCH_LEN);

	if (test_flags & TEST_WITH_REFS)
		free_refs(ref_tbl, TX_BATCH_LEN);

	for (i = 0; i < num_rx; i++) {
		CU_ASSERT(odp_packet_pool(pkt_tbl[i]) == expected_rx_pool(test_flags));
		odp_packet_free(pkt_tbl[i]);
	}

	wait = odp_schedule_wait_time(ODP_TIME_SEC_IN_NS);
	memset(seq_found, 0, sizeof(seq_found));

	/* Receive Packet Tx completion events for all sent/dropped pkts */
	for (i = 0; i < TX_BATCH_LEN; i++) {
		if (use_plain_queue) {
			ev = odp_queue_deq(compl_queue[i]);

			/* Event validation */
			CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
			CU_ASSERT_FATAL(odp_event_is_valid(ev) == 1);
			CU_ASSERT_FATAL(odp_event_type(ev) == ODP_EVENT_PACKET_TX_COMPL);
			CU_ASSERT_FATAL(odp_packet_tx_compl_from_event(ev) !=
					ODP_PACKET_TX_COMPL_INVALID);

			tx_compl = odp_packet_tx_compl_from_event(ev);
			CU_ASSERT_FATAL(odp_packet_tx_compl_to_event(tx_compl) == ev);

			u64 = odp_packet_tx_compl_to_u64(tx_compl);
			CU_ASSERT(u64 != odp_packet_tx_compl_to_u64(ODP_PACKET_TX_COMPL_INVALID));

			/* User ptr should be same as packet's user ptr */
			CU_ASSERT(odp_packet_tx_compl_user_ptr(tx_compl) ==
				  (const void *)&pkt_seq[i]);

			/* No user area/flag or source pool for TX completion events */
			odp_event_user_flag_set(ev, 1);
			CU_ASSERT(odp_event_user_area(ev) == NULL);
			CU_ASSERT(odp_event_user_area_and_flag(ev, &flag) == NULL);
			CU_ASSERT(flag < 0);

			CU_ASSERT(odp_event_pool(ev) == ODP_POOL_INVALID);

			/* Alternatively call event free / compl free */
			if (i % 2)
				odp_packet_tx_compl_free(tx_compl);
			else
				odp_event_free(ev);
		} else {
			odp_queue_t rcv_queue;
			int j;

			ev = odp_schedule(&rcv_queue, wait);

			/* Event validation */
			CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
			CU_ASSERT_FATAL(odp_event_is_valid(ev) == 1);
			CU_ASSERT_FATAL(odp_event_type(ev) == ODP_EVENT_PACKET_TX_COMPL);
			CU_ASSERT_FATAL(odp_packet_tx_compl_from_event(ev) !=
					ODP_PACKET_TX_COMPL_INVALID);

			tx_compl = odp_packet_tx_compl_from_event(ev);
			CU_ASSERT_FATAL(odp_packet_tx_compl_to_event(tx_compl) == ev);

			u64 = odp_packet_tx_compl_to_u64(tx_compl);
			CU_ASSERT(u64 != odp_packet_tx_compl_to_u64(ODP_PACKET_TX_COMPL_INVALID));

			/* User ptr should be same as packet's user ptr i.e seq array ptr */
			for (j = 0; j < TX_BATCH_LEN; j++) {
				if (!seq_found[j] &&
				    ((const void *)&pkt_seq[j] ==
				     odp_packet_tx_compl_user_ptr(tx_compl))) {
					/* Mark that sequence number is found */
					seq_found[j] = 1;

					/* Receive queue validation */
					CU_ASSERT(rcv_queue == compl_queue[j]);
					break;
				}
			}

			/* No user area/flag or source pool for TX completion events */
			odp_event_user_flag_set(ev, 1);
			CU_ASSERT(odp_event_user_area(ev) == NULL);
			CU_ASSERT(odp_event_user_area_and_flag(ev, &flag) == NULL);
			CU_ASSERT(flag < 0);

			CU_ASSERT(odp_event_pool(ev) == ODP_POOL_INVALID);

			/* Check that sequence number is found */
			CU_ASSERT(j < TX_BATCH_LEN);

			/* Alternatively call event free / compl free */
			if (i % 2)
				odp_packet_tx_compl_free(tx_compl);
			else
				odp_event_free(ev);
		}
	}

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}

	odp_schedule_pause();

	while (1) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}

	odp_schedule_resume();

	for (i = 0; i < TX_BATCH_LEN; i++)
		odp_queue_destroy(compl_queue[i]);
}

static void test_pktout_compl_poll(uint32_t test_flags)
{
	odp_pktio_t pktio[MAX_NUM_IFACES] = {ODP_PKTIO_INVALID};
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	odp_packet_t ref_tbl[TX_BATCH_LEN];
	odp_pktio_capability_t pktio_capa;
	odp_pktout_queue_t pktout_queue;
	uint32_t pkt_seq[TX_BATCH_LEN];
	odp_pktio_t pktio_tx, pktio_rx;
	odp_packet_tx_compl_opt_t opt;
	pktio_info_t pktio_rx_info;
	odp_pktio_config_t config;
	int ret, i, num_rx = 0;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio_with_flags(i, ODP_PKTIN_MODE_DIRECT,
						   ODP_PKTOUT_MODE_DIRECT,
						   test_flags);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio[i], &pktio_capa) == 0);

		/* Configure Tx completion offload for PKTIO Tx */
		if (i == 0) {
			CU_ASSERT_FATAL(pktio_capa.tx_compl.mode_poll == 1);
			CU_ASSERT_FATAL(pktio_capa.tx_compl.max_compl_id >= (TX_BATCH_LEN - 1));

			odp_pktio_config_init(&config);
			config.tx_compl.mode_poll = 1;
			config.tx_compl.max_compl_id = TX_BATCH_LEN - 1;
			CU_ASSERT_FATAL(odp_pktio_config(pktio[i], &config) == 0);
		}

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; i++)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;
	pktio_rx_info.id   = pktio_rx;
	pktio_rx_info.inq  = ODP_QUEUE_INVALID;
	pktio_rx_info.in_mode = ODP_PKTIN_MODE_DIRECT;

	for (i = 0; i < TX_BATCH_LEN;  i++) {
		/* Completion status is initially zero */
		CU_ASSERT(odp_packet_tx_compl_done(pktio_tx, i) == 0);
	}

	ret = create_packets(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx, pktio_rx);
	CU_ASSERT_FATAL(ret == TX_BATCH_LEN);

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	memset(&opt, 0, sizeof(opt));

	/* Disabled by default */
	CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[0]) == 0);

	/* Check that disable works */
	opt.compl_id = 0;
	opt.mode = ODP_PACKET_TX_COMPL_POLL;
	odp_packet_tx_compl_request(pkt_tbl[0], &opt);
	CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[0]) != 0);
	opt.mode = ODP_PACKET_TX_COMPL_DISABLED;
	odp_packet_tx_compl_request(pkt_tbl[0], &opt);
	CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[0]) == 0);

	/* Prepare batch of pkts with different tx completion identifiers */
	for (i = 0; i < TX_BATCH_LEN;  i++) {
		CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[i]) == 0);
		opt.compl_id = i;
		opt.mode = ODP_PACKET_TX_COMPL_POLL;
		odp_packet_tx_compl_request(pkt_tbl[i], &opt);
		CU_ASSERT(odp_packet_has_tx_compl_request(pkt_tbl[i]) != 0);
		/* Set pkt sequence number as its user ptr */
		odp_packet_user_ptr_set(pkt_tbl[i], (const void *)&pkt_seq[i]);

		/* Completion status should be still zero after odp_packet_tx_compl_request() */
		CU_ASSERT(odp_packet_tx_compl_done(pktio_tx, i) == 0);
	}

	if (test_flags & TEST_WITH_REFS)
		make_refs(ref_tbl, pkt_tbl, TX_BATCH_LEN);

	CU_ASSERT_FATAL(odp_pktout_send(pktout_queue, pkt_tbl, TX_BATCH_LEN) == TX_BATCH_LEN);

	num_rx = wait_for_packets(&pktio_rx_info, pkt_tbl, pkt_seq, TX_BATCH_LEN, TXRX_MODE_SINGLE,
				  ODP_TIME_SEC_IN_NS, VECTOR_MODE_DISABLED);
	CU_ASSERT(num_rx == TX_BATCH_LEN);

	if (test_flags & TEST_WITH_REFS)
		free_refs(ref_tbl, TX_BATCH_LEN);

	for (i = 0; i < num_rx; i++) {
		CU_ASSERT(odp_packet_pool(pkt_tbl[i]) == expected_rx_pool(test_flags));
		odp_packet_free(pkt_tbl[i]);
	}
	for (i = 0; i < num_rx; i++) {
		/* Transmits should be complete since we received the packets already */
		CU_ASSERT(odp_packet_tx_compl_done(pktio_tx, i) > 0);

		/* Check that the previous call did not clear the status */
		CU_ASSERT(odp_packet_tx_compl_done(pktio_tx, i) > 0);
	}

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static void pktio_test_pktout_compl_poll(void)
{
	for (uint32_t flags = 0; flags < NUM_TEST_FLAG_COMBOS; flags++)
		test_pktout_compl_poll(flags);
}

static int pktio_check_pktout_compl_event(bool plain)
{
	odp_pktio_param_t pktio_param;
	odp_pktio_capability_t capa;
	odp_pktio_t pktio;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || !capa.tx_compl.mode_event ||
	    (plain && !capa.tx_compl.queue_type_plain) ||
	    (!plain && !capa.tx_compl.queue_type_sched))
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pktio_check_pktout_compl_poll(void)
{
	odp_pktio_param_t pktio_param;
	odp_pktio_capability_t capa;
	odp_pktio_t pktio;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || capa.tx_compl.mode_poll == 0 ||
	    capa.tx_compl.max_compl_id < (TX_BATCH_LEN - 1))
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pktio_check_pktout_compl_event_plain_queue(void)
{
	return pktio_check_pktout_compl_event(true);
}

static int pktio_check_pktout_compl_event_sched_queue(void)
{
	return pktio_check_pktout_compl_event(false);
}

static void pktio_test_pktout_compl_event_plain_queue(void)
{
	for (uint32_t flags = 0; flags < NUM_TEST_FLAG_COMBOS; flags++)
		pktio_test_pktout_compl_event(true, flags);
}

static void pktio_test_pktout_compl_event_sched_queue(void)
{
	for (uint32_t flags = 0; flags < NUM_TEST_FLAG_COMBOS; flags++)
		pktio_test_pktout_compl_event(false, flags);
}

static void test_pktout_dont_free(uint32_t test_flags)
{
	odp_pktio_t pktio[MAX_NUM_IFACES] = {ODP_PKTIO_INVALID};
	odp_packet_t pkt, rx_pkt;
	odp_pktio_capability_t pktio_capa;
	odp_pktout_queue_t pktout_queue;
	odp_pktio_t pktio_tx, pktio_rx;
	pktio_info_t pktio_rx_info;
	uint32_t pkt_seq;
	int ret, i;
	const int num_pkt = 1;
	int transmits = 5;
	int num_rx = 0;
	odp_packet_t ref_tbl[num_pkt];

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio_with_flags(i, ODP_PKTIN_MODE_DIRECT,
						   ODP_PKTOUT_MODE_DIRECT,
						   test_flags);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;

	/* Check TX interface capa */
	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &pktio_capa) == 0);
	CU_ASSERT_FATAL(pktio_capa.free_ctrl.dont_free == 1);

	for (i = 0; i < num_ifaces; i++)
		_pktio_wait_linkup(pktio[i]);

	pktio_rx_info.id   = pktio_rx;
	pktio_rx_info.inq  = ODP_QUEUE_INVALID;
	pktio_rx_info.in_mode = ODP_PKTIN_MODE_DIRECT;

	ret = create_packets(&pkt, &pkt_seq, num_pkt, pktio_tx, pktio_rx);
	CU_ASSERT_FATAL(ret == num_pkt);

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	/* Set don't free flag */
	CU_ASSERT(odp_packet_free_ctrl(pkt) == ODP_PACKET_FREE_CTRL_DISABLED);
	odp_packet_free_ctrl_set(pkt, ODP_PACKET_FREE_CTRL_DONT_FREE);
	CU_ASSERT_FATAL(odp_packet_free_ctrl(pkt) == ODP_PACKET_FREE_CTRL_DONT_FREE);

	if (test_flags & TEST_WITH_REFS)
		make_refs(ref_tbl, &pkt, num_pkt);

	while (transmits--) {
		/* Retransmit the same packet after it has been received from the RX interface */
		CU_ASSERT_FATAL(odp_pktout_send(pktout_queue, &pkt, num_pkt) == num_pkt);

		num_rx = wait_for_packets(&pktio_rx_info, &rx_pkt, &pkt_seq, num_pkt,
					  TXRX_MODE_SINGLE, ODP_TIME_SEC_IN_NS,
					  VECTOR_MODE_DISABLED);
		CU_ASSERT(num_rx == num_pkt);

		if (num_rx != num_pkt)
			break;

		CU_ASSERT(odp_packet_pool(rx_pkt) == expected_rx_pool(test_flags));
		CU_ASSERT(odp_packet_len(pkt) == odp_packet_len(rx_pkt));
		odp_packet_free(rx_pkt);
	}

	odp_packet_free(pkt);

	if (test_flags & TEST_WITH_REFS)
		free_refs(ref_tbl, num_pkt);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static void pktio_test_pktout_dont_free(void)
{
	for (uint32_t flags = 0; flags < NUM_TEST_FLAG_COMBOS; flags++)
		test_pktout_dont_free(flags);
}

static int pktio_check_pktout_dont_free(void)
{
	odp_pktio_param_t pktio_param;
	odp_pktio_capability_t capa;
	odp_pktio_t pktio;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret == 0 && capa.free_ctrl.dont_free == 1)
		return ODP_TEST_ACTIVE;

	return ODP_TEST_INACTIVE;
}

static void test_chksum(void (*config_fn)(odp_pktio_t, odp_pktio_t),
			void (*prep_fn)(odp_packet_t pkt),
			void (*test_fn)(odp_packet_t pkt),
			uint32_t test_flags)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {ODP_PKTIO_INVALID};
	pktio_info_t pktio_rx_info;
	odp_pktout_queue_t pktout_queue;
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	odp_packet_t ref_tbl[TX_BATCH_LEN];
	uint32_t pkt_seq[TX_BATCH_LEN];
	int ret;
	int i, num_rx;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio_with_flags(i, ODP_PKTIN_MODE_DIRECT,
						   ODP_PKTOUT_MODE_DIRECT,
						   test_flags);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
	}

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;
	pktio_rx_info.id   = pktio_rx;
	pktio_rx_info.inq  = ODP_QUEUE_INVALID;
	pktio_rx_info.in_mode = ODP_PKTIN_MODE_DIRECT;

	config_fn(pktio_tx, pktio_rx);

	for (i = 0; i < num_ifaces; ++i) {
		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
		_pktio_wait_linkup(pktio[i]);
	}

	ret = create_packets_udp(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx,
				 pktio_rx, false, ETH_UNICAST);
	CU_ASSERT(ret == TX_BATCH_LEN);
	if (ret != TX_BATCH_LEN) {
		for (i = 0; i < num_ifaces; i++) {
			CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
			CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
		}
		return;
	}

	/* Provide L3 and L4 proto for pktout HW checksum generation */
	for (i = 0; i < TX_BATCH_LEN; i++) {
		odp_packet_has_ipv4_set(pkt_tbl[i], true);
		odp_packet_has_udp_set(pkt_tbl[i], true);
	}

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	for (i = 0; i < TX_BATCH_LEN; i++)
		if (prep_fn)
			prep_fn(pkt_tbl[i]);

	if (test_flags & TEST_WITH_REFS)
		make_refs(ref_tbl, pkt_tbl, TX_BATCH_LEN);
	send_packets(pktout_queue, pkt_tbl, TX_BATCH_LEN);
	num_rx = wait_for_packets(&pktio_rx_info, pkt_tbl, pkt_seq,
				  TX_BATCH_LEN, TXRX_MODE_MULTI,
				  ODP_TIME_SEC_IN_NS, VECTOR_MODE_DISABLED);
	CU_ASSERT(num_rx == TX_BATCH_LEN);
	if (test_flags & TEST_WITH_REFS)
		free_refs(ref_tbl, TX_BATCH_LEN);
	for (i = 0; i < num_rx; i++) {
		CU_ASSERT(odp_packet_pool(pkt_tbl[i]) == expected_rx_pool(test_flags));
		CU_ASSERT(odp_packet_has_ref(pkt_tbl[i]) == 0);
		test_fn(pkt_tbl[i]);
		odp_packet_free(pkt_tbl[i]);
	}

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static void pktio_test_chksum(void (*config_fn)(odp_pktio_t, odp_pktio_t),
			      void (*prep_fn)(odp_packet_t pkt),
			      void (*test_fn)(odp_packet_t pkt))
{
	for (uint32_t flags = 0; flags < NUM_TEST_FLAG_COMBOS; flags++)
		test_chksum(config_fn, prep_fn, test_fn, flags);
}

static void test_chksum_sctp(void (*config_fn)(odp_pktio_t, odp_pktio_t),
			     void (*prep_fn)(odp_packet_t pkt),
			     void (*test_fn)(odp_packet_t pkt),
			     uint32_t test_flags)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {ODP_PKTIO_INVALID};
	pktio_info_t pktio_rx_info;
	odp_pktout_queue_t pktout_queue;
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	odp_packet_t ref_tbl[TX_BATCH_LEN];
	uint32_t pkt_seq[TX_BATCH_LEN];
	int ret;
	int i, num_rx;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio_with_flags(i, ODP_PKTIN_MODE_DIRECT,
						   ODP_PKTOUT_MODE_DIRECT,
						   test_flags);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);
	}

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;
	pktio_rx_info.id   = pktio_rx;
	pktio_rx_info.inq  = ODP_QUEUE_INVALID;
	pktio_rx_info.in_mode = ODP_PKTIN_MODE_DIRECT;

	config_fn(pktio_tx, pktio_rx);

	for (i = 0; i < num_ifaces; ++i) {
		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
		_pktio_wait_linkup(pktio[i]);
	}

	ret = create_packets_sctp(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx,
				  pktio_rx);
	CU_ASSERT(ret == TX_BATCH_LEN);
	if (ret != TX_BATCH_LEN) {
		for (i = 0; i < num_ifaces; i++) {
			CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
			CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
		}
		return;
	}

	/* Provide L3 and L4 proto for pktout HW checksum generation */
	for (i = 0; i < TX_BATCH_LEN; i++) {
		odp_packet_has_ipv4_set(pkt_tbl[i], true);
		odp_packet_has_sctp_set(pkt_tbl[i], true);
	}

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	for (i = 0; i < TX_BATCH_LEN; i++)
		if (prep_fn)
			prep_fn(pkt_tbl[i]);

	if (test_flags & TEST_WITH_REFS)
		make_refs(ref_tbl, pkt_tbl, TX_BATCH_LEN);
	send_packets(pktout_queue, pkt_tbl, TX_BATCH_LEN);
	num_rx = wait_for_packets_hdr(&pktio_rx_info, pkt_tbl, pkt_seq,
				      TX_BATCH_LEN, TXRX_MODE_MULTI,
				      ODP_TIME_SEC_IN_NS, ODPH_SCTPHDR_LEN, VECTOR_MODE_DISABLED);
	CU_ASSERT(num_rx == TX_BATCH_LEN);
	if (test_flags & TEST_WITH_REFS)
		free_refs(ref_tbl, TX_BATCH_LEN);
	for (i = 0; i < num_rx; i++) {
		CU_ASSERT(odp_packet_pool(pkt_tbl[i]) == expected_rx_pool(test_flags));
		CU_ASSERT(odp_packet_has_ref(pkt_tbl[i]) == 0);
		test_fn(pkt_tbl[i]);
		odp_packet_free(pkt_tbl[i]);
	}

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static void pktio_test_chksum_sctp(void (*config_fn)(odp_pktio_t, odp_pktio_t),
				   void (*prep_fn)(odp_packet_t pkt),
				   void (*test_fn)(odp_packet_t pkt))
{
	for (uint32_t flags = 0; flags < NUM_TEST_FLAG_COMBOS; flags++)
		test_chksum_sctp(config_fn, prep_fn, test_fn, flags);
}

static int pktio_check_chksum_in_ipv4(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int idx = (num_ifaces == 1) ? 0 : 1;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[idx], pool[idx], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 ||
	    !capa.config.pktin.bit.ipv4_chksum)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_chksum_in_ipv4_config(odp_pktio_t pktio_tx ODP_UNUSED,
					     odp_pktio_t pktio_rx)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_rx, &capa) == 0);
	CU_ASSERT_FATAL(capa.config.pktin.bit.ipv4_chksum);

	odp_pktio_config_init(&config);
	config.pktin.bit.ipv4_chksum = 1;
	CU_ASSERT_FATAL(odp_pktio_config(pktio_rx, &config) == 0);
}

static void pktio_test_chksum_in_ipv4_prep(odp_packet_t pkt)
{
	odph_ipv4_csum_update(pkt);
}

static void pktio_test_chksum_in_ipv4_test(odp_packet_t pkt)
{
	CU_ASSERT(odp_packet_l3_chksum_status(pkt) == ODP_PACKET_CHKSUM_OK);
}

static void pktio_test_chksum_in_ipv4(void)
{
	pktio_test_chksum(pktio_test_chksum_in_ipv4_config,
			  pktio_test_chksum_in_ipv4_prep,
			  pktio_test_chksum_in_ipv4_test);
}

static int pktio_check_chksum_in_udp(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int idx = (num_ifaces == 1) ? 0 : 1;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[idx], pool[idx], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 ||
	    !capa.config.pktin.bit.udp_chksum)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_chksum_in_udp_config(odp_pktio_t pktio_tx ODP_UNUSED,
					    odp_pktio_t pktio_rx)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_rx, &capa) == 0);
	CU_ASSERT_FATAL(capa.config.pktin.bit.udp_chksum);

	odp_pktio_config_init(&config);
	config.pktin.bit.udp_chksum = 1;
	CU_ASSERT_FATAL(odp_pktio_config(pktio_rx, &config) == 0);
}

static void pktio_test_chksum_in_udp_prep(odp_packet_t pkt)
{
	odp_packet_has_ipv4_set(pkt, 1);
	odp_packet_has_udp_set(pkt, 1);
	odph_ipv4_csum_update(pkt);
	odph_udp_chksum_set(pkt);
}

static void pktio_test_chksum_in_udp_test(odp_packet_t pkt)
{
	CU_ASSERT(odp_packet_l4_chksum_status(pkt) == ODP_PACKET_CHKSUM_OK);
}

static void pktio_test_chksum_in_udp(void)
{
	pktio_test_chksum(pktio_test_chksum_in_udp_config,
			  pktio_test_chksum_in_udp_prep,
			  pktio_test_chksum_in_udp_test);
}

static int pktio_check_chksum_in_sctp(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int idx = (num_ifaces == 1) ? 0 : 1;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[idx], pool[idx], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 ||
	    !capa.config.pktin.bit.sctp_chksum)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_chksum_in_sctp_config(odp_pktio_t pktio_tx ODP_UNUSED,
					     odp_pktio_t pktio_rx)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_rx, &capa) == 0);
	CU_ASSERT_FATAL(capa.config.pktin.bit.sctp_chksum);

	odp_pktio_config_init(&config);
	config.pktin.bit.sctp_chksum = 1;
	CU_ASSERT_FATAL(odp_pktio_config(pktio_rx, &config) == 0);
}

static void pktio_test_chksum_in_sctp_prep(odp_packet_t pkt)
{
	odp_packet_has_ipv4_set(pkt, 1);
	odp_packet_has_sctp_set(pkt, 1);
	odph_ipv4_csum_update(pkt);
	odph_sctp_chksum_set(pkt);
}

static void pktio_test_chksum_in_sctp_test(odp_packet_t pkt)
{
	CU_ASSERT(odp_packet_l4_chksum_status(pkt) == ODP_PACKET_CHKSUM_OK);
}

static void pktio_test_chksum_in_sctp(void)
{
	pktio_test_chksum_sctp(pktio_test_chksum_in_sctp_config,
			       pktio_test_chksum_in_sctp_prep,
			       pktio_test_chksum_in_sctp_test);
}

static int pktio_check_chksum_out_ipv4(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 ||
	    !capa.config.pktout.bit.ipv4_chksum_ena ||
	    !capa.config.pktout.bit.ipv4_chksum)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_chksum_out_ipv4_config(odp_pktio_t pktio_tx,
					      odp_pktio_t pktio_rx ODP_UNUSED)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &capa) == 0);
	CU_ASSERT_FATAL(capa.config.pktout.bit.ipv4_chksum_ena);
	CU_ASSERT_FATAL(capa.config.pktout.bit.ipv4_chksum);

	odp_pktio_config_init(&config);
	config.pktout.bit.ipv4_chksum_ena = 1;
	CU_ASSERT_FATAL(odp_pktio_config(pktio_tx, &config) == 0);
}

static void pktio_test_chksum_out_ipv4_test(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ip = odp_packet_l3_ptr(pkt, NULL);

	CU_ASSERT(ip != NULL);
	if (ip != NULL)
		CU_ASSERT(ip->chksum != 0);
}

static void pktio_test_chksum_out_ipv4_no_ovr_prep(odp_packet_t pkt)
{
	odp_packet_l3_chksum_insert(pkt, false);
}

static void pktio_test_chksum_out_ipv4_no_ovr_test(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ip = odp_packet_l3_ptr(pkt, NULL);

	CU_ASSERT(ip != NULL);
	if (ip != NULL)
		CU_ASSERT(ip->chksum == 0);
}

static void pktio_test_chksum_out_ipv4_no_ovr(void)
{
	pktio_test_chksum(pktio_test_chksum_out_ipv4_config,
			  pktio_test_chksum_out_ipv4_no_ovr_prep,
			  pktio_test_chksum_out_ipv4_no_ovr_test);
}

static void pktio_test_chksum_out_ipv4_ovr_prep(odp_packet_t pkt)
{
	odp_packet_l3_chksum_insert(pkt, true);
}

static void pktio_test_chksum_out_ipv4_ovr_test(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ip = odp_packet_l3_ptr(pkt, NULL);

	CU_ASSERT(ip != NULL);
	if (ip != NULL)
		CU_ASSERT(ip->chksum != 0);
}

static void pktio_test_chksum_out_ipv4_ovr(void)
{
	pktio_test_chksum(pktio_test_chksum_out_ipv4_config,
			  pktio_test_chksum_out_ipv4_ovr_prep,
			  pktio_test_chksum_out_ipv4_ovr_test);
}

static void pktio_test_chksum_out_ipv4_pktio_config(odp_pktio_t pktio_tx,
						    odp_pktio_t pktio_rx
						    ODP_UNUSED)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &capa) == 0);
	CU_ASSERT_FATAL(capa.config.pktout.bit.ipv4_chksum_ena);
	CU_ASSERT_FATAL(capa.config.pktout.bit.ipv4_chksum);

	odp_pktio_config_init(&config);
	config.pktout.bit.ipv4_chksum_ena = 1;
	config.pktout.bit.ipv4_chksum = 1;
	CU_ASSERT_FATAL(odp_pktio_config(pktio_tx, &config) == 0);
}

static void pktio_test_chksum_out_ipv4_pktio(void)
{
	pktio_test_chksum(pktio_test_chksum_out_ipv4_pktio_config,
			  NULL,
			  pktio_test_chksum_out_ipv4_test);
}

static int pktio_check_chksum_out_udp(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 ||
	    !capa.config.pktout.bit.udp_chksum_ena ||
	    !capa.config.pktout.bit.udp_chksum)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_chksum_out_udp_config(odp_pktio_t pktio_tx,
					     odp_pktio_t pktio_rx ODP_UNUSED)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &capa) == 0);
	CU_ASSERT_FATAL(capa.config.pktout.bit.udp_chksum_ena);
	CU_ASSERT_FATAL(capa.config.pktout.bit.udp_chksum);

	odp_pktio_config_init(&config);
	config.pktout.bit.udp_chksum_ena = 1;
	CU_ASSERT_FATAL(odp_pktio_config(pktio_tx, &config) == 0);
}

static void pktio_test_chksum_out_udp_test(odp_packet_t pkt)
{
	odph_udphdr_t *udp = odp_packet_l4_ptr(pkt, NULL);

	CU_ASSERT(udp != NULL);
	if (udp != NULL) {
		CU_ASSERT(udp->chksum != 0);
		CU_ASSERT(!odph_udp_chksum_verify(pkt));
	}
}

static void pktio_test_chksum_out_udp_no_ovr_prep(odp_packet_t pkt)
{
	odph_ipv4_csum_update(pkt);
	odp_packet_l4_chksum_insert(pkt, false);
}

static void pktio_test_chksum_out_udp_no_ovr_test(odp_packet_t pkt)
{
	odph_udphdr_t *udp = odp_packet_l4_ptr(pkt, NULL);

	CU_ASSERT(udp != NULL);
	if (udp != NULL)
		CU_ASSERT(udp->chksum == 0);
}

static void pktio_test_chksum_out_udp_no_ovr(void)
{
	pktio_test_chksum(pktio_test_chksum_out_udp_config,
			  pktio_test_chksum_out_udp_no_ovr_prep,
			  pktio_test_chksum_out_udp_no_ovr_test);
}

static void pktio_test_chksum_out_udp_ovr_prep(odp_packet_t pkt)
{
	odp_packet_l4_chksum_insert(pkt, true);
}

static void pktio_test_chksum_out_udp_ovr_test(odp_packet_t pkt)
{
	odph_udphdr_t *udp = odp_packet_l4_ptr(pkt, NULL);

	CU_ASSERT(udp != NULL);
	if (udp != NULL) {
		CU_ASSERT(udp->chksum != 0);
		CU_ASSERT(!odph_udp_chksum_verify(pkt));
	}
}

static void pktio_test_chksum_out_udp_ovr(void)
{
	pktio_test_chksum(pktio_test_chksum_out_udp_config,
			  pktio_test_chksum_out_udp_ovr_prep,
			  pktio_test_chksum_out_udp_ovr_test);
}

static void pktio_test_chksum_out_udp_pktio_config(odp_pktio_t pktio_tx,
						   odp_pktio_t pktio_rx
						   ODP_UNUSED)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &capa) == 0);
	CU_ASSERT_FATAL(capa.config.pktout.bit.udp_chksum_ena);
	CU_ASSERT_FATAL(capa.config.pktout.bit.udp_chksum);

	odp_pktio_config_init(&config);
	config.pktout.bit.udp_chksum_ena = 1;
	config.pktout.bit.udp_chksum = 1;
	CU_ASSERT_FATAL(odp_pktio_config(pktio_tx, &config) == 0);
}

static void pktio_test_chksum_out_udp_pktio(void)
{
	pktio_test_chksum(pktio_test_chksum_out_udp_pktio_config,
			  NULL,
			  pktio_test_chksum_out_udp_test);
}

static int pktio_check_chksum_out_sctp(void)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 ||
	    !capa.config.pktout.bit.sctp_chksum_ena ||
	    !capa.config.pktout.bit.sctp_chksum)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void pktio_test_chksum_out_sctp_config(odp_pktio_t pktio_tx,
					      odp_pktio_t pktio_rx ODP_UNUSED)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &capa) == 0);
	CU_ASSERT_FATAL(capa.config.pktout.bit.sctp_chksum_ena);
	CU_ASSERT_FATAL(capa.config.pktout.bit.sctp_chksum);

	odp_pktio_config_init(&config);
	config.pktout.bit.sctp_chksum_ena = 1;
	CU_ASSERT_FATAL(odp_pktio_config(pktio_tx, &config) == 0);
}

static void pktio_test_chksum_out_sctp_test(odp_packet_t pkt)
{
	odph_sctphdr_t *sctp = odp_packet_l4_ptr(pkt, NULL);

	CU_ASSERT(sctp != NULL);
	if (sctp != NULL) {
		CU_ASSERT(sctp->chksum != 0);
		CU_ASSERT(!odph_sctp_chksum_verify(pkt));
	}
}

static void pktio_test_chksum_out_sctp_no_ovr_prep(odp_packet_t pkt)
{
	odph_ipv4_csum_update(pkt);
	odp_packet_l4_chksum_insert(pkt, false);
}

static void pktio_test_chksum_out_sctp_no_ovr_test(odp_packet_t pkt)
{
	odph_sctphdr_t *sctp = odp_packet_l4_ptr(pkt, NULL);

	CU_ASSERT(sctp != NULL);
	if (sctp != NULL)
		CU_ASSERT(sctp->chksum == 0);
}

static void pktio_test_chksum_out_sctp_no_ovr(void)
{
	pktio_test_chksum_sctp(pktio_test_chksum_out_sctp_config,
			       pktio_test_chksum_out_sctp_no_ovr_prep,
			       pktio_test_chksum_out_sctp_no_ovr_test);
}

static void pktio_test_chksum_out_sctp_ovr_prep(odp_packet_t pkt)
{
	odp_packet_l4_chksum_insert(pkt, true);
}

static void pktio_test_chksum_out_sctp_ovr_test(odp_packet_t pkt)
{
	odph_sctphdr_t *sctp = odp_packet_l4_ptr(pkt, NULL);

	CU_ASSERT(sctp != NULL);
	if (sctp != NULL) {
		CU_ASSERT(sctp->chksum != 0);
		CU_ASSERT(!odph_sctp_chksum_verify(pkt));
	}
}

static void pktio_test_chksum_out_sctp_ovr(void)
{
	pktio_test_chksum_sctp(pktio_test_chksum_out_sctp_config,
			       pktio_test_chksum_out_sctp_ovr_prep,
			       pktio_test_chksum_out_sctp_ovr_test);
}

static void pktio_test_chksum_out_sctp_pktio_config(odp_pktio_t pktio_tx,
						    odp_pktio_t pktio_rx
						    ODP_UNUSED)
{
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;

	CU_ASSERT_FATAL(odp_pktio_capability(pktio_tx, &capa) == 0);
	CU_ASSERT_FATAL(capa.config.pktout.bit.sctp_chksum_ena);
	CU_ASSERT_FATAL(capa.config.pktout.bit.sctp_chksum);

	odp_pktio_config_init(&config);
	config.pktout.bit.sctp_chksum_ena = 1;
	config.pktout.bit.sctp_chksum = 1;
	CU_ASSERT_FATAL(odp_pktio_config(pktio_tx, &config) == 0);
}

static void pktio_test_chksum_out_sctp_pktio(void)
{
	pktio_test_chksum_sctp(pktio_test_chksum_out_sctp_pktio_config,
			       NULL,
			       pktio_test_chksum_out_sctp_test);
}

static int create_pool(const char *iface, int num)
{
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_param_t params;
	odp_pool_capability_t pool_capa;

	if (odp_pool_capability(&pool_capa) != 0)
		return -1;

	odp_pool_param_init(&params);
	set_pool_len(&params, &pool_capa);
	/* Allocate enough buffers taking into consideration core starvation
	 * due to caching */
	params.pkt.num     = PKT_BUF_NUM + params.pkt.cache_size;
	params.type        = ODP_POOL_PACKET;

	snprintf(pool_name, sizeof(pool_name), "pkt_pool_%s_%d",
		 iface, pool_segmentation);

	pool[num] = odp_pool_create(pool_name, &params);
	if (ODP_POOL_INVALID == pool[num]) {
		ODPH_ERR("failed to create pool: %s\n", pool_name);
		return -1;
	}

	return 0;
}

static int create_pktv_pool(const char *iface, int num)
{
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_capability_t pool_capa;
	odp_pool_param_t params;

	if (odp_pool_capability(&pool_capa) != 0)
		return -1;

	if (pool_capa.vector.max_num && pool_capa.vector.max_num < PKT_BUF_NUM)
		return -1;

	odp_pool_param_init(&params);
	set_pool_len(&params, &pool_capa);
	params.type = ODP_POOL_VECTOR;
	params.vector.num = PKT_BUF_NUM;
	params.vector.max_size = pool_capa.vector.max_size;

	snprintf(pool_name, sizeof(pool_name), "pktv_pool_%s_%d",
		 iface, pool_segmentation);

	pktv_pool[num] = odp_pool_create(pool_name, &params);
	if (ODP_POOL_INVALID == pktv_pool[num]) {
		ODPH_ERR("failed to create pool: %s\n", pool_name);
		return -1;
	}

	return 0;
}

static int create_evv_pool(const char *iface, int num)
{
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_capability_t pool_capa;
	odp_pool_param_t params;

	if (odp_pool_capability(&pool_capa) != 0)
		return -1;

	if (pool_capa.event_vector.max_num && pool_capa.event_vector.max_num < PKT_BUF_NUM)
		return -1;

	odp_pool_param_init(&params);
	params.type = ODP_POOL_EVENT_VECTOR;
	params.event_vector.num = PKT_BUF_NUM;
	params.event_vector.max_size = pool_capa.event_vector.max_size;

	snprintf(pool_name, sizeof(pool_name), "evv_pool_%s_%d", iface, pool_segmentation);

	evv_pool[num] = odp_pool_create(pool_name, &params);
	if (evv_pool[num] == ODP_POOL_INVALID) {
		ODPH_ERR("failed to create pool: %s\n", pool_name);
		return -1;
	}

	return 0;
}

static int pktio_check_pktv(odp_pktin_mode_t in_mode)
{
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	odp_pktio_param_t pktio_param;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = in_mode;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || !capa.vector.supported)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pktio_check_pktv_queue(void)
{
	return pktio_check_pktv(ODP_PKTIN_MODE_QUEUE);
}

static int pktio_check_pktv_sched(void)
{
	return pktio_check_pktv(ODP_PKTIN_MODE_SCHED);
}

static void pktio_test_pktv_recv_plain(void)
{
	test_txrx(ODP_PKTIN_MODE_QUEUE, PKTV_TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT,
		  0, VECTOR_MODE_PACKET);
}

static void pktio_test_pktv_recv_parallel(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, PKTV_TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT,
		  ODP_SCHED_SYNC_PARALLEL, VECTOR_MODE_PACKET);
}

static void pktio_test_pktv_recv_ordered(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, PKTV_TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT,
		  ODP_SCHED_SYNC_ORDERED, VECTOR_MODE_PACKET);
}

static void pktio_test_pktv_recv_atomic(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, PKTV_TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT,
		  ODP_SCHED_SYNC_ATOMIC, VECTOR_MODE_PACKET);
}

static int pktio_check_evv(odp_pktin_mode_t in_mode)
{
	odp_event_aggr_capability_t aggr_capa;

	if (event_aggr_capability(&aggr_capa, in_mode) || aggr_capa.max_num < 1)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pktio_check_evv_queue(void)
{
	return pktio_check_evv(ODP_PKTIN_MODE_QUEUE);
}

static int pktio_check_evv_sched(void)
{
	return pktio_check_evv(ODP_PKTIN_MODE_SCHED);
}

static void pktio_test_evv_recv_plain(void)
{
	test_txrx(ODP_PKTIN_MODE_QUEUE, PKTV_TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT,
		  0, VECTOR_MODE_EVENT);
}

static void pktio_test_evv_recv_parallel(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, PKTV_TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT,
		  ODP_SCHED_SYNC_PARALLEL, VECTOR_MODE_EVENT);
}

static void pktio_test_evv_recv_ordered(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, PKTV_TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT,
		  ODP_SCHED_SYNC_ORDERED, VECTOR_MODE_EVENT);
}

static void pktio_test_evv_recv_atomic(void)
{
	test_txrx(ODP_PKTIN_MODE_SCHED, PKTV_TX_BATCH_LEN, TXRX_MODE_MULTI_EVENT,
		  ODP_SCHED_SYNC_ATOMIC, VECTOR_MODE_EVENT);
}

static void pktio_test_pktv_pktin_queue_config(odp_pktin_mode_t in_mode)
{
	odp_pktin_queue_param_t queue_param;
	odp_pktio_capability_t capa;
	odp_pktio_t pktio;
	int num_queues;
	int i;

	pktio = create_pktio(0, in_mode, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0 &&
			capa.max_input_queues > 0);
	num_queues = capa.max_input_queues;

	odp_pktin_queue_param_init(&queue_param);
	queue_param.hash_enable = (num_queues > 1) ? 1 : 0;
	queue_param.hash_proto.proto.ipv4_udp = 1;
	queue_param.num_queues = num_queues;
	queue_param.vector.enable = 1;
	queue_param.vector.pool = default_pktv_pool;
	queue_param.vector.max_size = capa.vector.min_size;
	queue_param.vector.max_tmo_ns = capa.vector.min_tmo_ns;
	CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) == 0);

	queue_param.vector.max_size = capa.vector.max_size;
	CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) == 0);

	if (capa.vector.max_size != capa.vector.min_size) {
		queue_param.vector.max_size = capa.vector.max_size - capa.vector.min_size;
		CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) == 0);
	}

	queue_param.vector.max_size = capa.vector.min_size - 1;
	CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) != 0);

	queue_param.vector.max_size = capa.vector.max_size + 1;
	CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) != 0);

	CU_ASSERT_FATAL(odp_pktio_close(pktio) == 0);

	for (i = 0; i < num_ifaces; i++) {
		pktio = create_pktio(i, in_mode, ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio, &capa) == 0);

		if (!capa.vector.supported) {
			printf("Vector mode is not supported. Test Skipped\n");
			return;
		}

		queue_param.vector.enable = 1;
		queue_param.vector.pool = pktv_pool[i];
		queue_param.vector.max_size = capa.vector.min_size;
		CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) == 0);

		queue_param.vector.max_size = capa.vector.max_size;
		CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) == 0);

		if (capa.vector.max_size != capa.vector.min_size) {
			queue_param.vector.max_size = capa.vector.max_size - capa.vector.min_size;
			CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) == 0);
		}

		queue_param.vector.max_size = capa.vector.min_size - 1;
		CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) != 0);

		queue_param.vector.max_size = capa.vector.max_size + 1;
		CU_ASSERT(odp_pktin_queue_config(pktio, &queue_param) != 0);

		CU_ASSERT_FATAL(odp_pktio_close(pktio) == 0);
	}
}

static void pktio_test_pktv_pktin_queue_config_queue(void)
{
	pktio_test_pktv_pktin_queue_config(ODP_PKTIN_MODE_QUEUE);
}

static void pktio_test_pktv_pktin_queue_config_sched(void)
{
	pktio_test_pktv_pktin_queue_config(ODP_PKTIN_MODE_SCHED);
}

static void pktio_test_evv_pktin_queue_config(odp_pktin_mode_t in_mode)
{
	odp_pktin_queue_param_t pktin_param;
	odp_pktio_capability_t pktio_capa;
	odp_event_aggr_capability_t aggr_capa;
	odp_queue_t pktin_queue;
	odp_queue_info_t queue_info;
	odp_queue_type_t queue_type = in_mode == ODP_PKTIN_MODE_SCHED ?
					ODP_QUEUE_TYPE_SCHED : ODP_QUEUE_TYPE_PLAIN;
	odp_pktio_t pktio;
	uint32_t num_queues, max_aggr_per_queue;
	odp_event_type_t event_types[] = {ODP_EVENT_BUFFER, ODP_EVENT_PACKET, ODP_EVENT_TIMEOUT,
					  ODP_EVENT_IPSEC_STATUS, ODP_EVENT_PACKET_TX_COMPL,
					  ODP_EVENT_DMA_COMPL, ODP_EVENT_ML_COMPL};

	CU_ASSERT_FATAL(event_aggr_capability(&aggr_capa, in_mode) == 0);

	pktio = create_pktio(0, in_mode, ODP_PKTOUT_MODE_DIRECT);
	CU_ASSERT_FATAL(pktio != ODP_PKTIO_INVALID);

	CU_ASSERT_FATAL(odp_pktio_capability(pktio, &pktio_capa) == 0 &&
			pktio_capa.max_input_queues > 0);
	num_queues = pktio_capa.max_input_queues;

	if (num_queues > aggr_capa.max_num)
		num_queues = aggr_capa.max_num;

	max_aggr_per_queue = aggr_capa.max_num_per_queue;
	if (num_queues * max_aggr_per_queue > aggr_capa.max_num)
		max_aggr_per_queue = aggr_capa.max_num / num_queues;

	CU_ASSERT_FATAL(max_aggr_per_queue > 0);

	odp_event_aggr_config_t aggr_config[max_aggr_per_queue];

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.hash_enable = num_queues > 1 ? 1 : 0;
	pktin_param.hash_proto.proto.ipv4_udp = 1;
	pktin_param.num_queues = num_queues;
	pktin_param.queue_param.aggr = aggr_config;
	pktin_param.queue_param.num_aggr = max_aggr_per_queue;

	memset(aggr_config, 0, max_aggr_per_queue * sizeof(odp_event_aggr_config_t));
	aggr_config[0].pool = default_evv_pool;
	aggr_config[0].event_type = ODP_EVENT_ANY;
	aggr_config[0].max_tmo_ns = aggr_capa.min_tmo_ns;
	aggr_config[0].max_size = aggr_capa.min_size;

	for (uint32_t i = 1; i < max_aggr_per_queue; i++)
		aggr_config[i] = aggr_config[0];

	CU_ASSERT(odp_pktin_queue_config(pktio, &pktin_param) == 0);

	CU_ASSERT_FATAL(odp_pktin_event_queue(pktio, &pktin_queue, 1) == (int)num_queues);
	CU_ASSERT_FATAL(odp_queue_info(pktin_queue, &queue_info) == 0);
	CU_ASSERT(queue_info.type == queue_type);

	aggr_config[0].max_size = aggr_capa.max_size;
	CU_ASSERT(odp_pktin_queue_config(pktio, &pktin_param) == 0);

	aggr_config[0].max_size = aggr_capa.min_size + aggr_capa.max_size - aggr_capa.min_size;
	CU_ASSERT(odp_pktin_queue_config(pktio, &pktin_param) == 0);

	aggr_config[0].max_tmo_ns = aggr_capa.max_tmo_ns;
	CU_ASSERT(odp_pktin_queue_config(pktio, &pktin_param) == 0);

	aggr_config[0].max_tmo_ns = aggr_capa.min_tmo_ns + aggr_capa.max_tmo_ns -
					aggr_capa.min_tmo_ns;
	CU_ASSERT(odp_pktin_queue_config(pktio, &pktin_param) == 0);

	for (uint32_t i = 0; i < ODPH_ARRAY_SIZE(event_types); i++) {
		aggr_config[0].event_type = event_types[i];
		CU_ASSERT(odp_pktin_queue_config(pktio, &pktin_param) == 0);
	}

	CU_ASSERT(odp_pktio_close(pktio) == 0);
}

static void pktio_test_evv_pktin_queue_config_queue(void)
{
	pktio_test_evv_pktin_queue_config(ODP_PKTIN_MODE_QUEUE);
}

static void pktio_test_evv_pktin_queue_config_sched(void)
{
	pktio_test_evv_pktin_queue_config(ODP_PKTIN_MODE_SCHED);
}

static void pktio_test_recv_maxlen_set(void)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {0};
	pktio_info_t pktio_rx_info;
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;
	odp_pktout_queue_t pktout_queue;
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	uint32_t pkt_seq[TX_BATCH_LEN];
	uint32_t max_len = PKT_LEN_MAX;
	int num_rx = 0;
	int ret;
	int i;

	CU_ASSERT_FATAL(num_ifaces >= 1);

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; i++) {
		uint32_t maxlen_tmp;

		pktio[i] = create_pktio(i, ODP_PKTIN_MODE_DIRECT, ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(!odp_pktio_capability(pktio[i], &capa));
		CU_ASSERT_FATAL(capa.set_op.op.maxlen);

		odp_pktio_config_init(&config);
		CU_ASSERT_FATAL(!odp_pktio_config(pktio[i], &config));

		maxlen_tmp = capa.maxlen.max_input;
		if (maxlen_tmp == 0)
			maxlen_tmp = odp_pktin_maxlen(pktio[i]);
		if (maxlen_tmp < max_len)
			max_len = maxlen_tmp;

		maxlen_tmp = capa.maxlen.max_output;
		if (maxlen_tmp == 0)
			maxlen_tmp = odp_pktout_maxlen(pktio[i]);
		if (maxlen_tmp < max_len)
			max_len = maxlen_tmp;

		CU_ASSERT_FATAL(!odp_pktio_maxlen_set(pktio[i], capa.maxlen.max_input,
						      capa.maxlen.max_output));

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; i++)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;
	pktio_rx_info.id   = pktio_rx;
	pktio_rx_info.inq  = ODP_QUEUE_INVALID;
	pktio_rx_info.in_mode = ODP_PKTIN_MODE_DIRECT;

	packet_len = max_len;
	ret = create_packets(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx,
			     pktio_rx);
	CU_ASSERT_FATAL(ret == TX_BATCH_LEN);

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	/* Send packets one at a time and add delay between the packets */
	for (i = 0; i < TX_BATCH_LEN;  i++) {
		CU_ASSERT_FATAL(odp_pktout_send(pktout_queue,
						&pkt_tbl[i], 1) == 1);
		ret = wait_for_packets(&pktio_rx_info, &pkt_tbl[i], &pkt_seq[i],
				       1, TXRX_MODE_SINGLE, ODP_TIME_SEC_IN_NS,
				       VECTOR_MODE_DISABLED);
		if (ret != 1)
			break;
	}
	num_rx = i;
	CU_ASSERT(num_rx == TX_BATCH_LEN);

	for (i = 0; i < num_rx; i++) {
		CU_ASSERT(odp_packet_pool(pkt_tbl[i]) == expected_rx_pool(0));
	}

	if (num_rx)
		odp_packet_free_multi(pkt_tbl, num_rx);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(!odp_pktio_stop(pktio[i]));
		CU_ASSERT_FATAL(!odp_pktio_close(pktio[i]));
	}

	/* Restore global variable */
	packet_len = PKT_LEN_NORMAL;
}

static int pktio_check_pktout_aging_tmo(void)
{
	odp_pktio_param_t pktio_param;
	odp_pktio_capability_t capa;
	odp_pktio_t pktio;
	int ret;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	pktio = odp_pktio_open(iface_name[0], pool[0], &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		return ODP_TEST_INACTIVE;

	ret = odp_pktio_capability(pktio, &capa);
	(void)odp_pktio_close(pktio);

	if (ret < 0 || !capa.max_tx_aging_tmo_ns)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void test_pktout_aging_tmo(uint32_t test_flags)
{
	odp_pktio_t pktio[MAX_NUM_IFACES] = {ODP_PKTIO_INVALID};
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	odp_packet_t ref_tbl[TX_BATCH_LEN];
	odp_pktio_capability_t pktio_capa;
	odp_pktout_queue_t pktout_queue;
	uint32_t pkt_seq[TX_BATCH_LEN];
	odp_pktio_t pktio_tx, pktio_rx;
	pktio_info_t pktio_rx_info;
	odp_pktio_config_t config;
	int ret, i, num_rx = 0;
	uint64_t tmo_0, tmo_1;

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio_with_flags(i, ODP_PKTIN_MODE_DIRECT,
						   ODP_PKTOUT_MODE_DIRECT,
						   test_flags);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		CU_ASSERT_FATAL(odp_pktio_capability(pktio[i], &pktio_capa) == 0);

		/* Configure Tx aging for PKTIO Tx */
		if (i == 0) {
			CU_ASSERT_FATAL(pktio_capa.max_tx_aging_tmo_ns > 0);

			odp_pktio_config_init(&config);
			config.pktout.bit.aging_ena = 1;
			CU_ASSERT_FATAL(odp_pktio_config(pktio[i], &config) == 0);
		}

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; i++)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	pktio_rx = (num_ifaces > 1) ? pktio[1] : pktio_tx;
	pktio_rx_info.id   = pktio_rx;
	pktio_rx_info.inq  = ODP_QUEUE_INVALID;
	pktio_rx_info.in_mode = ODP_PKTIN_MODE_DIRECT;

	ret = create_packets(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx,
			     pktio_rx);
	CU_ASSERT_FATAL(ret == TX_BATCH_LEN);

	ret = odp_pktout_queue(pktio_tx, &pktout_queue, 1);
	CU_ASSERT_FATAL(ret > 0);

	/* Prepare packets with aging */
	for (i = 0; i < TX_BATCH_LEN; i++) {
		/* Aging disabled by default */
		CU_ASSERT(odp_packet_aging_tmo(pkt_tbl[i]) == 0);

		/* Test tmo set relatively since we don't know about supported resolution */
		odp_packet_aging_tmo_set(pkt_tbl[i], pktio_capa.max_tx_aging_tmo_ns - 1);
		tmo_0 = odp_packet_aging_tmo(pkt_tbl[i]);

		odp_packet_aging_tmo_set(pkt_tbl[i], pktio_capa.max_tx_aging_tmo_ns / 2);
		tmo_1 = odp_packet_aging_tmo(pkt_tbl[i]);
		CU_ASSERT(tmo_0 > tmo_1);

		/* Set max before transmitting */
		odp_packet_aging_tmo_set(pkt_tbl[i], pktio_capa.max_tx_aging_tmo_ns);
		CU_ASSERT(odp_packet_aging_tmo(pkt_tbl[i]) != 0);
	}

	if (test_flags & TEST_WITH_REFS)
		make_refs(ref_tbl, pkt_tbl, TX_BATCH_LEN);

	CU_ASSERT_FATAL(odp_pktout_send(pktout_queue, pkt_tbl, TX_BATCH_LEN) == TX_BATCH_LEN);

	num_rx = wait_for_packets(&pktio_rx_info, pkt_tbl, pkt_seq, TX_BATCH_LEN, TXRX_MODE_SINGLE,
				  ODP_TIME_SEC_IN_NS, VECTOR_MODE_DISABLED);
	CU_ASSERT(num_rx == TX_BATCH_LEN);
	if (test_flags & TEST_WITH_REFS)
		free_refs(ref_tbl, TX_BATCH_LEN);

	for (i = 0; i < num_rx; i++) {
		CU_ASSERT(odp_packet_pool(pkt_tbl[i]) == expected_rx_pool(test_flags));
		odp_packet_free(pkt_tbl[i]);
	}

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}
}

static void pktio_test_pktout_aging_tmo(void)
{
	for (uint32_t flags = 0; flags < NUM_TEST_FLAG_COMBOS; flags++)
		test_pktout_aging_tmo(flags);
}

static void pktio_test_pktin_event_queue(odp_pktin_mode_t pktin_mode)
{
	odp_pktio_t pktio_tx, pktio_rx;
	odp_pktin_queue_param_t in_queue_param;
	odp_pktout_queue_param_t out_queue_param;
	odp_pktout_queue_t pktout_queue;
	odp_queue_t queue, from = ODP_QUEUE_INVALID;
	odp_pool_t buf_pool;
	odp_pool_param_t pool_param;
	odp_packet_t pkt_tbl[TX_BATCH_LEN];
	odp_packet_t pkt;
	odp_buffer_t buf;
	odp_event_t ev;
	uint32_t pkt_seq[TX_BATCH_LEN];
	int ret, i;
	odp_time_t t1, t2;
	int inactive = 0;
	int num_pkt = 0;
	int num_buf = 0;
	int num_bad = 0;
	odp_pktio_t pktio[MAX_NUM_IFACES] = {0};
	uint64_t wait_time = odp_schedule_wait_time(100 * ODP_TIME_MSEC_IN_NS);

	CU_ASSERT_FATAL(num_ifaces >= 1);

	odp_pool_param_init(&pool_param);
	pool_param.type = ODP_POOL_BUFFER;
	pool_param.buf.num = 2 * TX_BATCH_LEN;
	pool_param.buf.size = 100;

	buf_pool = odp_pool_create("buffer pool", &pool_param);
	CU_ASSERT_FATAL(buf_pool != ODP_POOL_INVALID);

	buf = odp_buffer_alloc(buf_pool);
	CU_ASSERT_FATAL(buf != ODP_BUFFER_INVALID);

	odp_pktin_queue_param_init(&in_queue_param);
	in_queue_param.num_queues  = 1;
	in_queue_param.hash_enable = 0;
	in_queue_param.classifier_enable = 0;

	if (pktin_mode == ODP_PKTIN_MODE_SCHED) {
		in_queue_param.queue_param.type = ODP_QUEUE_TYPE_SCHED;
		in_queue_param.queue_param.sched.prio  = odp_schedule_default_prio();
		in_queue_param.queue_param.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
		in_queue_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	}

	odp_pktout_queue_param_init(&out_queue_param);
	out_queue_param.num_queues  = 1;

	/* Open and configure interfaces */
	for (i = 0; i < num_ifaces; ++i) {
		pktio[i] = create_pktio(i, pktin_mode, ODP_PKTOUT_MODE_DIRECT);
		CU_ASSERT_FATAL(pktio[i] != ODP_PKTIO_INVALID);

		ret = odp_pktin_queue_config(pktio[i], &in_queue_param);
		CU_ASSERT_FATAL(ret == 0);

		ret = odp_pktout_queue_config(pktio[i], &out_queue_param);
		CU_ASSERT_FATAL(ret == 0);

		CU_ASSERT_FATAL(odp_pktio_start(pktio[i]) == 0);
	}

	for (i = 0; i < num_ifaces; ++i)
		_pktio_wait_linkup(pktio[i]);

	pktio_tx = pktio[0];
	if (num_ifaces > 1)
		pktio_rx = pktio[1];
	else
		pktio_rx = pktio_tx;

	CU_ASSERT_FATAL(odp_pktin_event_queue(pktio_rx, &queue, 1) == 1);
	CU_ASSERT_FATAL(odp_pktout_queue(pktio_tx, &pktout_queue, 1) == 1);

	/* Allocate and initialize test packets */
	ret = create_packets(pkt_tbl, pkt_seq, TX_BATCH_LEN, pktio_tx, pktio_rx);
	if (ret != TX_BATCH_LEN) {
		CU_FAIL("Failed to generate test packets");
		return;
	}

	/* Send packets */
	ret = odp_pktout_send(pktout_queue, pkt_tbl, TX_BATCH_LEN);
	CU_ASSERT_FATAL(ret == TX_BATCH_LEN);

	/* Send buffer event */
	ret = odp_queue_enq(queue, odp_buffer_to_event(buf));
	CU_ASSERT_FATAL(ret == 0);

	/* Receive events */
	while (1) {
		/* Break after a period of inactivity */
		if (pktin_mode == ODP_PKTIN_MODE_SCHED) {
			ev = odp_schedule(&from, wait_time);

			if (ev == ODP_EVENT_INVALID)
				break;
		} else {
			ev = odp_queue_deq(queue);

			if (ev == ODP_EVENT_INVALID) {
				if (inactive == 0) {
					inactive = 1;
					t1 = odp_time_local();
					continue;
				} else {
					t2 = odp_time_local();
					if (odp_time_diff_ns(t2, t1) > ODP_TIME_SEC_IN_NS)
						break;

					continue;
				}
			}

			inactive = 0;
		}

		if (odp_event_type(ev) == ODP_EVENT_PACKET) {
			pkt = odp_packet_from_event(ev);

			if (pktio_pkt_seq(pkt) != TEST_SEQ_INVALID) {
				num_pkt++;

				if (pktin_mode == ODP_PKTIN_MODE_SCHED)
					CU_ASSERT(from == queue);
			}
		} else if (odp_event_type(ev) == ODP_EVENT_BUFFER) {
			num_buf++;
		} else {
			CU_FAIL("Bad event type");
			num_bad++;
		}

		odp_event_free(ev);
	}

	CU_ASSERT(num_pkt == TX_BATCH_LEN);
	CU_ASSERT(num_buf == 1);
	CU_ASSERT(num_bad == 0);

	for (i = 0; i < num_ifaces; i++) {
		CU_ASSERT_FATAL(odp_pktio_stop(pktio[i]) == 0);
		CU_ASSERT_FATAL(odp_pktio_close(pktio[i]) == 0);
	}

	CU_ASSERT_FATAL(odp_pool_destroy(buf_pool) == 0);
}

static void pktio_test_pktin_event_sched(void)
{
	pktio_test_pktin_event_queue(ODP_PKTIN_MODE_SCHED);
}

static int pktio_check_pktin_event_sched(void)
{
	if (odp_cunit_ci_skip("pktio_test_pktin_event_sched"))
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int pktio_suite_init(void)
{
	int i;

	odp_atomic_init_u32(&ip_seq, 0);

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

	for (i = 0; i < num_ifaces; i++) {
		if (create_pool(iface_name[i], i) != 0)
			return -1;

		if (create_pktv_pool(iface_name[i], i) != 0)
			return -1;

		if (create_evv_pool(iface_name[i], i) != 0)
			return -1;
	}

	if (default_pool_create() != 0) {
		ODPH_ERR("failed to create default pool\n");
		return -1;
	}

	if (default_pktv_pool_create() != 0) {
		ODPH_ERR("failed to create default pktv pool\n");
		return -1;
	}

	if (default_evv_pool_create() != 0) {
		ODPH_ERR("failed to create default event vector pool\n");
		return -1;
	}

	return 0;
}

static int pktio_suite_init_unsegmented(void)
{
	pool_segmentation = PKT_POOL_UNSEGMENTED;
	return pktio_suite_init();
}

static int pktio_suite_init_segmented(void)
{
	pool_segmentation = PKT_POOL_SEGMENTED;
	return pktio_suite_init();
}

static int pktv_suite_init(void)
{
	pool_segmentation = PKT_POOL_UNSEGMENTED;
	return pktio_suite_init();
}

static int evv_suite_init(void)
{
	pool_segmentation = PKT_POOL_UNSEGMENTED;
	return pktio_suite_init();
}

static int pktio_suite_term(void)
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
			ODPH_ERR("failed to destroy pool %s\n", pool_name);
			ret = -1;
		}
	}

	for (i = 0; i < num_ifaces; ++i) {
		snprintf(pool_name, sizeof(pool_name),
			 "pktv_pool_%s_%d", iface_name[i], pool_segmentation);
		pool = odp_pool_lookup(pool_name);
		if (pool == ODP_POOL_INVALID)
			continue;

		if (odp_pool_destroy(pool) != 0) {
			ODPH_ERR("failed to destroy pool %s\n", pool_name);
			ret = -1;
		}
	}

	for (i = 0; i < num_ifaces; ++i) {
		snprintf(pool_name, sizeof(pool_name),
			 "evv_pool_%s_%d", iface_name[i], pool_segmentation);
		pool = odp_pool_lookup(pool_name);
		if (pool == ODP_POOL_INVALID)
			continue;

		if (odp_pool_destroy(pool) != 0) {
			ODPH_ERR("failed to destroy pool %s\n", pool_name);
			ret = -1;
		}
	}

	if (odp_pool_destroy(default_pkt_pool) != 0) {
		ODPH_ERR("failed to destroy default pool\n");
		ret = -1;
	}
	default_pkt_pool = ODP_POOL_INVALID;

	if (odp_pool_destroy(default_pktv_pool) != 0) {
		ODPH_ERR("failed to destroy default pktv pool\n");
		ret = -1;
	}
	default_pktv_pool = ODP_POOL_INVALID;

	if (odp_pool_destroy(default_evv_pool) != 0) {
		ODPH_ERR("failed to destroy default event vector pool\n");
		ret = -1;
	}
	default_evv_pool = ODP_POOL_INVALID;

	if (odp_cunit_print_inactive())
		ret = -1;

	return ret;
}

static int pktv_suite_term(void)
{
	pool_segmentation = PKT_POOL_UNSEGMENTED;
	return pktio_suite_term();
}

static int evv_suite_term(void)
{
	pool_segmentation = PKT_POOL_UNSEGMENTED;
	return pktio_suite_term();
}

odp_testinfo_t pktio_suite_unsegmented[] = {
	ODP_TEST_INFO(pktio_test_default_values),
	ODP_TEST_INFO(pktio_test_open),
	ODP_TEST_INFO(pktio_test_lookup),
	ODP_TEST_INFO(pktio_test_index),
	ODP_TEST_INFO(pktio_test_print),
	ODP_TEST_INFO(pktio_test_pktio_config),
	ODP_TEST_INFO(pktio_test_info),
	ODP_TEST_INFO(pktio_test_link_info),
	ODP_TEST_INFO(pktio_test_pktin_queue_config_direct),
	ODP_TEST_INFO(pktio_test_pktin_queue_config_sched),
	ODP_TEST_INFO(pktio_test_pktin_queue_config_multi_sched),
	ODP_TEST_INFO(pktio_test_pktin_queue_config_queue),
	ODP_TEST_INFO(pktio_test_pktout_queue_config),
	ODP_TEST_INFO(pktio_test_plain_queue),
	ODP_TEST_INFO(pktio_test_plain_multi),
	ODP_TEST_INFO(pktio_test_sched_queue),
	ODP_TEST_INFO(pktio_test_sched_multi),
	ODP_TEST_INFO(pktio_test_recv),
	ODP_TEST_INFO(pktio_test_recv_multi),
	ODP_TEST_INFO(pktio_test_recv_queue),
	ODP_TEST_INFO(pktio_test_recv_tmo),
	ODP_TEST_INFO(pktio_test_recv_mq_tmo),
	ODP_TEST_INFO(pktio_test_recv_mtu),
	ODP_TEST_INFO(pktio_test_maxlen),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_maxlen_set,
				  pktio_check_maxlen_set),
	ODP_TEST_INFO(pktio_test_promisc),
	ODP_TEST_INFO(pktio_test_mac),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_start_stop,
				  pktio_check_start_stop),
	ODP_TEST_INFO(pktio_test_recv_on_wonly),
	ODP_TEST_INFO(pktio_test_send_on_ronly),
	ODP_TEST_INFO(pktio_test_plain_multi_event),
	ODP_TEST_INFO(pktio_test_sched_multi_event),
	ODP_TEST_INFO(pktio_test_recv_multi_event),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktin_event_sched,
				  pktio_check_pktin_event_sched),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_statistics_counters,
				  pktio_check_statistics_counters),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_statistics_counters_bcast,
				  pktio_check_statistics_counters_bcast),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_queue_statistics_counters,
				  pktio_check_queue_statistics_counters),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_event_queue_statistics_counters,
				  pktio_check_event_queue_statistics_counters),
	ODP_TEST_INFO(pktio_test_extra_stats),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_proto_statistics_counters,
				  pktio_check_proto_statistics_counters),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktin_ts,
				  pktio_check_pktin_ts),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktout_ts,
				  pktio_check_pktout_ts),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_in_ipv4,
				  pktio_check_chksum_in_ipv4),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_in_udp,
				  pktio_check_chksum_in_udp),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_in_sctp,
				  pktio_check_chksum_in_sctp),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_out_ipv4_no_ovr,
				  pktio_check_chksum_out_ipv4),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_out_ipv4_pktio,
				  pktio_check_chksum_out_ipv4),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_out_ipv4_ovr,
				  pktio_check_chksum_out_ipv4),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_out_udp_no_ovr,
				  pktio_check_chksum_out_udp),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_out_udp_pktio,
				  pktio_check_chksum_out_udp),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_out_udp_ovr,
				  pktio_check_chksum_out_udp),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_out_sctp_no_ovr,
				  pktio_check_chksum_out_sctp),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_out_sctp_pktio,
				  pktio_check_chksum_out_sctp),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_chksum_out_sctp_ovr,
				  pktio_check_chksum_out_sctp),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_recv_maxlen_set,
				  pktio_check_maxlen_set),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktout_aging_tmo,
				  pktio_check_pktout_aging_tmo),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktout_compl_event_plain_queue,
				  pktio_check_pktout_compl_event_plain_queue),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktout_compl_event_sched_queue,
				  pktio_check_pktout_compl_event_sched_queue),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktout_compl_poll, pktio_check_pktout_compl_poll),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktout_dont_free, pktio_check_pktout_dont_free),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_enable_pause_rx, pktio_check_pause_rx),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_enable_pause_tx, pktio_check_pause_tx),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_enable_pause_both, pktio_check_pause_both),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_enable_pfc_rx, pktio_check_pfc_rx),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_enable_pfc_tx, pktio_check_pfc_tx),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_enable_pfc_both, pktio_check_pfc_both),
	ODP_TEST_INFO_NULL
};

odp_testinfo_t pktio_suite_segmented[] = {
	ODP_TEST_INFO(pktio_test_plain_queue),
	ODP_TEST_INFO(pktio_test_plain_multi),
	ODP_TEST_INFO(pktio_test_sched_queue),
	ODP_TEST_INFO(pktio_test_sched_multi),
	ODP_TEST_INFO(pktio_test_recv),
	ODP_TEST_INFO(pktio_test_recv_multi),
	ODP_TEST_INFO(pktio_test_recv_mtu),
	ODP_TEST_INFO_NULL
};

odp_testinfo_t pktv_suite[] = {
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktv_pktin_queue_config_queue, pktio_check_pktv_queue),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktv_pktin_queue_config_sched, pktio_check_pktv_sched),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktv_recv_plain, pktio_check_pktv_queue),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktv_recv_parallel, pktio_check_pktv_sched),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktv_recv_ordered, pktio_check_pktv_sched),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_pktv_recv_atomic, pktio_check_pktv_sched),
	ODP_TEST_INFO_NULL
};

odp_testinfo_t evv_suite[] = {
	ODP_TEST_INFO_CONDITIONAL(pktio_test_evv_pktin_queue_config_queue, pktio_check_evv_queue),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_evv_pktin_queue_config_sched, pktio_check_evv_sched),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_evv_recv_plain, pktio_check_evv_queue),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_evv_recv_parallel, pktio_check_evv_sched),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_evv_recv_ordered, pktio_check_evv_sched),
	ODP_TEST_INFO_CONDITIONAL(pktio_test_evv_recv_atomic, pktio_check_evv_sched),
	ODP_TEST_INFO_NULL
};

odp_suiteinfo_t pktio_suites[] = {
	{"Packet I/O Unsegmented", pktio_suite_init_unsegmented,
	 pktio_suite_term, pktio_suite_unsegmented},
	{"Packet I/O Segmented", pktio_suite_init_segmented,
	 pktio_suite_term, pktio_suite_segmented},
	{"Packet parser", parser_suite_init, parser_suite_term, parser_suite},
	{"Packet vector", pktv_suite_init, pktv_suite_term, pktv_suite},
	{"Event vector", evv_suite_init, evv_suite_term, evv_suite},
	{"Large Segment Offload", lso_suite_init, lso_suite_term, lso_suite},
	ODP_SUITE_INFO_NULL
};

int main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	ret = odp_cunit_register(pktio_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

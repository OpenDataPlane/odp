/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2022-2025 Marvell
 * Copyright (c) 2022 Nokia
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>
#include "odp_cunit_common.h"

#define TM_DEBUG                 0

#define MAX_NUM_IFACES           2
#define MAX_TM_SYSTEMS           3
#define NUM_LEVELS               3
#define NUM_PRIORITIES           4
#define NUM_QUEUES_PER_NODE      NUM_PRIORITIES
#define FANIN_RATIO              8u
#define NUM_LEVEL0_TM_NODES      1
#define NUM_LEVEL1_TM_NODES      FANIN_RATIO
#define NUM_LEVEL2_TM_NODES      (FANIN_RATIO * FANIN_RATIO)
#define NUM_TM_QUEUES            (NUM_LEVEL2_TM_NODES * NUM_QUEUES_PER_NODE)
#define NUM_SHAPER_PROFILES      64
#define NUM_SCHED_PROFILES       64
#define NUM_THRESHOLD_PROFILES   64
#define NUM_WRED_PROFILES        64
#define NUM_SHAPER_TEST_PROFILES 8
#define NUM_SCHED_TEST_PROFILES  8
#define NUM_THRESH_TEST_PROFILES 8
#define NUM_WRED_TEST_PROFILES   8

#define ODP_NUM_PKT_COLORS       ODP_NUM_PACKET_COLORS
#define PKT_GREEN                ODP_PACKET_GREEN
#define PKT_YELLOW               ODP_PACKET_YELLOW
#define PKT_RED                  ODP_PACKET_RED

#define MIN_COMMIT_BW            (64 * 1024)
#define MIN_COMMIT_BURST         8000
#define MIN_PEAK_BW              2000000
#define MIN_PEAK_BURST           16000

#define INITIAL_RCV_GAP_DROP     10   /* This is a percent of rcvd pkts */
#define ENDING_RCV_GAP_DROP      20   /* This is a percent of rcvd pkts */

#define MIN_SHAPER_BW_RCV_GAP    80   /* Percent of expected_rcv_gap */
#define MAX_SHAPER_BW_RCV_GAP    125  /* Percent of expected_rcv_gap */

#define MIN_PKT_THRESHOLD        10
#define MIN_BYTE_THRESHOLD       2048

#define MIN_WRED_THRESH          5
#define MED_WRED_THRESH          10
#define MED_DROP_PROB            4
#define MAX_DROP_PROB            8

#define MAX_PKTS                 1000u
#define PKT_BUF_SIZE             1460
#define MIN_HDR_LEN              (ODPH_ETHHDR_LEN + ODPH_UDPHDR_LEN + ODPH_IPV4HDR_LEN)
#define MAX_PAYLOAD              (PKT_BUF_SIZE - MIN_HDR_LEN)
#define USE_IPV4                 false
#define USE_IPV6                 true
#define USE_UDP                  false
#define USE_TCP                  true
#define LOW_DROP_PRECEDENCE      0x02
#define MEDIUM_DROP_PRECEDENCE   0x04
#define HIGH_DROP_PRECEDENCE     0x06
#define DROP_PRECEDENCE_MASK     0x06
#define DSCP_CLASS1              0x08
#define DSCP_CLASS2              0x10
#define DSCP_CLASS3              0x18
#define DSCP_CLASS4              0x20
#define DEFAULT_DSCP             (DSCP_CLASS2 | LOW_DROP_PRECEDENCE)
#define DEFAULT_ECN              ODPH_IP_ECN_ECT0
#define DEFAULT_TOS              ((DEFAULT_DSCP << ODPH_IP_TOS_DSCP_SHIFT) | \
					DEFAULT_ECN)
#define DEFAULT_TTL              128
#define DEFAULT_UDP_SRC_PORT     12049
#define DEFAULT_UDP_DST_PORT     12050
#define DEFAULT_TCP_SRC_PORT     0xDEAD
#define DEFAULT_TCP_DST_PORT     0xBABE
#define DEFAULT_TCP_SEQ_NUM      0x12345678
#define DEFAULT_TCP_ACK_NUM      0x12340000
#define DEFAULT_TCP_WINDOW       0x4000
#define VLAN_PRIORITY_BK         1      /* Background - lowest priority */
#define VLAN_PRIORITY_BE         0      /* Best Effort */
#define VLAN_PRIORITY_EE         2      /* Excellent Effort */
#define VLAN_PRIORITY_NC         7      /* Network Control - highest priority */
#define VLAN_DEFAULT_VID         12
#define VLAN_NO_DEI              ((VLAN_PRIORITY_EE << 13) | VLAN_DEFAULT_VID)
#define ETHERNET_IFG             12      /* Ethernet Interframe Gap */
#define ETHERNET_PREAMBLE        8
#define ETHERNET_OVHD_LEN        (ETHERNET_IFG + ETHERNET_PREAMBLE)
#define CRC_LEN                  4
#define SHAPER_LEN_ADJ           ETHERNET_OVHD_LEN
#define BILLION                  1000000000ULL
#define MS                       1000000  /* Millisecond in units of NS */
#define MBPS                     1000000
#define GBPS                     1000000000

#define TM_PERCENT(percent) ((uint32_t)(100 * percent))

typedef enum {
	SHAPER_PROFILE, SCHED_PROFILE, THRESHOLD_PROFILE, WRED_PROFILE
} profile_kind_t;

typedef enum {
	THRESHOLD_BYTE,
	THRESHOLD_PACKET,
	THRESHOLD_BYTE_AND_PACKET
} threshold_type_t;

typedef struct {
	uint32_t       num_queues;
	odp_tm_queue_t tm_queues[];
} tm_queue_desc_t;

typedef struct tm_node_desc_s tm_node_desc_t;

struct tm_node_desc_s {
	uint32_t         level;
	uint32_t         node_idx;
	uint32_t         num_children;
	char            *node_name;
	odp_tm_node_t    node;
	odp_tm_node_t    parent_node;
	tm_queue_desc_t *queue_desc;
	tm_node_desc_t  *children[];
};

typedef struct {
	uint32_t num_samples;
	uint32_t min_rcv_gap;
	uint32_t max_rcv_gap;
	uint32_t total_rcv_gap;
	uint64_t total_rcv_gap_squared;
	uint32_t avg_rcv_gap;
	uint32_t std_dev_gap;
} rcv_stats_t;

typedef struct {
	odp_time_t     xmt_time;
	odp_time_t     rcv_time;
	uint64_t       delta_ns;
	odp_tm_queue_t tm_queue;
	uint16_t       pkt_len;
	uint16_t       xmt_unique_id;
	uint16_t       xmt_idx;
	uint8_t        pkt_class;
	uint8_t        was_rcvd;
} xmt_pkt_desc_t;

typedef struct {
	odp_time_t      rcv_time;
	xmt_pkt_desc_t *xmt_pkt_desc;
	uint16_t        rcv_unique_id;
	uint16_t        xmt_idx;
	uint8_t         errors;
	uint8_t          matched;
	uint8_t         pkt_class;
	uint8_t         is_ipv4_pkt;
} rcv_pkt_desc_t;

typedef struct {
	odp_tm_percent_t confidence_percent;
	odp_tm_percent_t drop_percent;
	uint32_t         min_cnt;
	uint32_t         max_cnt;
} wred_pkt_cnts_t;

typedef struct {
	uint32_t       num_queues;
	uint32_t       priority;
	odp_tm_queue_t tm_queues[NUM_LEVEL2_TM_NODES];
} queue_array_t;

typedef struct {
	queue_array_t queue_array[NUM_PRIORITIES];
} queues_set_t;

typedef struct {
	uint16_t           vlan_tci;
	uint8_t            pkt_class;
	uint8_t            ip_tos;        /* TOS for IPv4 and TC for IPv6 */
	odp_packet_color_t pkt_color;
	odp_bool_t         drop_eligible;
	odp_bool_t         use_vlan;      /* Else no VLAN header */
	odp_bool_t         use_ipv6;      /* Else use IPv4 */
	odp_bool_t         use_tcp;       /* Else use UDP */
} pkt_info_t;

static const char ALPHABET[] =
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/* The following constant table determines the minimum and maximum number of
 * pkts that will be received when sending 100 pkts through a system with a
 * drop probability of p% (using a uniform probability distribution), with a
 * confidence of 99.9% 99.99% and 99.999%. The confidence is interpreted as
 * follows: a 99.99% confidence says that receiving LESS pkts than the given
 * minimum or receiving MORE pkts than the given maximum (assuming a uniform
 * drop percent of p) will happen less than 1 time in 10,000 trials.
 * Mathematically the minimum pkt cnt is the largest value of cnt
 * that satisfies the following equation:
 * "(1 - cf/100)/2 <= Sum(binomial(100,k) * (1-p)^k * p^(100-k), k=0..cnt)",
 * where cf is the confidence, caret (^) represents exponentiation,
 * binomial(n,k) is the binomial coefficient defined as n! / (k! * (n-k)!).
 * and p is the drop probability.  Similarly the maximum pkt cnt is the
 * smallest value of cnt that satisfies the equation:
 * "(1 - cf/100)/2 <= Sum(binomial(100,k) * (1-p)^k * p^(100-k), k=cnt..100)".
 * As a consequence of this, it should be the case that:
 * cf/100 <= Sum(binomial(100,k) * (1-p)^k * p^(100-k), k=min..max)".
 */
static wred_pkt_cnts_t EXPECTED_PKT_RCVD[] = {
	{ TM_PERCENT(99.0), TM_PERCENT(10.0), 82, 97 },
	{ TM_PERCENT(99.0), TM_PERCENT(20.0), 69, 90 },
	{ TM_PERCENT(99.0), TM_PERCENT(30.0), 58, 81 },
	{ TM_PERCENT(99.0), TM_PERCENT(40.0), 47, 72 },
	{ TM_PERCENT(99.0), TM_PERCENT(50.0), 37, 63 },
	{ TM_PERCENT(99.0), TM_PERCENT(60.0), 28, 53 },
	{ TM_PERCENT(99.0), TM_PERCENT(70.0), 19, 42 },
	{ TM_PERCENT(99.0), TM_PERCENT(80.0), 10, 31 },
	{ TM_PERCENT(99.0), TM_PERCENT(90.0),  3, 18 },

	{ TM_PERCENT(99.9), TM_PERCENT(10.0), 79, 98 },
	{ TM_PERCENT(99.9), TM_PERCENT(20.0), 66, 92 },
	{ TM_PERCENT(99.9), TM_PERCENT(30.0), 54, 84 },
	{ TM_PERCENT(99.9), TM_PERCENT(40.0), 44, 76 },
	{ TM_PERCENT(99.9), TM_PERCENT(50.0), 34, 66 },
	{ TM_PERCENT(99.9), TM_PERCENT(60.0), 24, 56 },
	{ TM_PERCENT(99.9), TM_PERCENT(70.0), 16, 46 },
	{ TM_PERCENT(99.9), TM_PERCENT(80.0),  8, 34 },
	{ TM_PERCENT(99.9), TM_PERCENT(90.0),  2, 21 },

	{ TM_PERCENT(99.99), TM_PERCENT(10.0), 77, 99 },
	{ TM_PERCENT(99.99), TM_PERCENT(20.0), 63, 94 },
	{ TM_PERCENT(99.99), TM_PERCENT(30.0), 51, 87 },
	{ TM_PERCENT(99.99), TM_PERCENT(40.0), 41, 78 },
	{ TM_PERCENT(99.99), TM_PERCENT(50.0), 31, 69 },
	{ TM_PERCENT(99.99), TM_PERCENT(60.0), 22, 59 },
	{ TM_PERCENT(99.99), TM_PERCENT(70.0), 13, 49 },
	{ TM_PERCENT(99.99), TM_PERCENT(80.0),  6, 37 },
	{ TM_PERCENT(99.99), TM_PERCENT(90.0),  1, 23 },
};

static uint8_t EQUAL_WEIGHTS[FANIN_RATIO] = {
	16, 16, 16, 16, 16, 16, 16, 16
};

static uint8_t INCREASING_WEIGHTS[FANIN_RATIO] = {
	8, 12, 16, 24, 32, 48, 64, 96
};

static uint8_t IPV4_SRC_ADDR[ODPH_IPV4ADDR_LEN] = {
	10, 0, 0, 1   /* I.e. 10.0.0.1 */
};

static uint8_t IPV4_DST_ADDR[ODPH_IPV4ADDR_LEN] = {
	10, 0, 0, 100   /* I.e. 10.0.0.100 */
};

static uint8_t IPV6_SRC_ADDR[ODPH_IPV6ADDR_LEN] = {
	/* I.e. ::ffff:10.0.0.1 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 0, 0, 1
};

static uint8_t IPV6_DST_ADDR[ODPH_IPV6ADDR_LEN] = {
	/* I.e. ::ffff:10.0.0.100 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 0, 0, 100
};

static odp_tm_t        odp_tm_systems[MAX_TM_SYSTEMS];
static tm_node_desc_t *root_node_descs[MAX_TM_SYSTEMS];
static uint32_t        num_odp_tm_systems;

static odp_tm_capabilities_t tm_capabilities;

static bool dynamic_shaper_update = true;
static bool dynamic_sched_update = true;
static bool dynamic_threshold_update = true;
static bool dynamic_wred_update = true;

static odp_tm_shaper_t    shaper_profiles[NUM_SHAPER_PROFILES];
static odp_tm_sched_t     sched_profiles[NUM_SCHED_PROFILES];
static odp_tm_threshold_t threshold_profiles[NUM_THRESHOLD_PROFILES];
static odp_tm_wred_t      wred_profiles[NUM_WRED_PROFILES][ODP_NUM_PKT_COLORS];

static uint32_t num_shaper_profiles;
static uint32_t num_sched_profiles;
static uint32_t num_threshold_profiles;
static uint32_t num_wred_profiles;

static uint8_t payload_data[MAX_PAYLOAD];

static odp_packet_t   xmt_pkts[MAX_PKTS];
static xmt_pkt_desc_t xmt_pkt_descs[MAX_PKTS];
static uint32_t       num_pkts_made;
static uint32_t       num_pkts_sent;

static odp_packet_t   rcv_pkts[MAX_PKTS];
static rcv_pkt_desc_t rcv_pkt_descs[MAX_PKTS];
static uint32_t       num_rcv_pkts;

static uint32_t rcv_gaps[MAX_PKTS];
static uint32_t rcv_gap_cnt;

static queues_set_t queues_set;
static uint32_t     unique_id_list[MAX_PKTS];

/* interface names used for testing */
static const char *iface_name[MAX_NUM_IFACES];

/** number of interfaces being used (1=loopback, 2=pair) */
static uint32_t num_ifaces;

static odp_pool_t pools[MAX_NUM_IFACES] = {ODP_POOL_INVALID, ODP_POOL_INVALID};

static odp_pktio_t pktios[MAX_NUM_IFACES];
static odp_bool_t pktio_started[MAX_NUM_IFACES];
static odp_pktin_queue_t pktins[MAX_NUM_IFACES];
static odp_pktin_queue_t rcv_pktin;
static odp_pktio_t xmt_pktio;
static odp_pktio_capability_t xmt_pktio_capa;
static odp_lso_profile_t lso_ipv4_profile;

static odph_ethaddr_t src_mac;
static odph_ethaddr_t dst_mac;

static uint32_t cpu_unique_id;
static uint32_t cpu_tcp_seq_num;

static int8_t suite_inactive;

static uint64_t tm_shaper_min_rate;
static uint64_t tm_shaper_max_rate;
static uint32_t tm_shaper_min_burst;
static uint32_t tm_shaper_max_burst;

static void busy_wait(uint64_t nanoseconds)
{
	odp_time_t start_time, end_time;

	start_time = odp_time_local();
	end_time   = odp_time_sum(start_time,
				  odp_time_local_from_ns(nanoseconds));

	while (odp_time_cmp(odp_time_local(), end_time) < 0)
		odp_cpu_pause();
}

static odp_bool_t approx_eq32(uint32_t val, uint32_t correct)
{
	uint64_t low_bound, val_times_100, high_bound;

	if (val == correct)
		return true;

	low_bound     = 98  * (uint64_t)correct;
	val_times_100 = 100 * (uint64_t)val;
	high_bound    = 102 * (uint64_t)correct;

	if ((low_bound <= val_times_100) && (val_times_100 <= high_bound))
		return true;
	else
		return false;
}

static odp_bool_t approx_eq64(uint64_t val, uint64_t correct)
{
	uint64_t low_bound, val_times_100, high_bound;

	if (val == correct)
		return true;

	low_bound     = 98  * correct;
	val_times_100 = 100 * val;
	high_bound    = 102 * correct;

	if ((low_bound <= val_times_100) && (val_times_100 <= high_bound))
		return true;
	else
		return false;
}

static uint64_t
clamp_rate(uint64_t rate)
{
	return ODPH_MIN(ODPH_MAX(rate, tm_shaper_min_rate), tm_shaper_max_rate);
}

static uint32_t
clamp_burst(uint32_t burst)
{
	return ODPH_MIN(ODPH_MAX(burst, tm_shaper_min_burst), tm_shaper_max_burst);
}

static int test_overall_capabilities(void)
{
	odp_tm_level_capabilities_t *per_level;
	odp_tm_capabilities_t        capabilities_array[2];
	odp_tm_capabilities_t       *cap_ptr;
	odp_tm_egress_t              egress;
	odp_bool_t                  *prio_modes;
	uint32_t                     num_records, idx, num_levels, level;
	int                          rc;

	odp_tm_egress_init(&egress);
	egress.egress_kind = ODP_TM_EGRESS_PKT_IO;
	egress.pktio = xmt_pktio;

	rc = odp_tm_egress_capabilities(&capabilities_array[0], &egress);
	CU_ASSERT_FATAL(rc == 0);
	num_records = 1;

	/* Get capabilities for egress kind function. */
	odp_tm_egress_init(&egress);
	egress.egress_kind = ODP_TM_EGRESS_FN;
	rc = odp_tm_egress_capabilities(&capabilities_array[1], &egress);
	CU_ASSERT_FATAL(rc == 0);

	/* Validate this record only if egress function is supported */
	if (capabilities_array[1].max_tm_queues)
		num_records++;

	/* Loop through the returned capabilities (there MUST be at least one)
	 * and do some basic checks to prove that it isn't just an empty
	 * record. */
	for (idx = 0; idx < num_records; idx++) {
		cap_ptr = &capabilities_array[idx];
		if (cap_ptr->max_tm_queues == 0) {
			CU_ASSERT(cap_ptr->max_tm_queues != 0);
			return -1;
		}

		if (cap_ptr->max_levels == 0) {
			CU_ASSERT(cap_ptr->max_levels != 0);
			return -1;
		}

		num_levels = cap_ptr->max_levels;
		for (level = 0; level < num_levels; level++) {
			per_level = &cap_ptr->per_level[level];

			if (per_level->max_num_tm_nodes == 0) {
				CU_ASSERT(per_level->max_num_tm_nodes != 0);
				return -1;
			}

			if (per_level->max_fanin_per_node == 0) {
				CU_ASSERT(per_level->max_fanin_per_node != 0);
				return -1;
			}

			if (per_level->max_priority == 0) {
				CU_ASSERT(per_level->max_priority != 0);
				return -1;
			}

			if (per_level->tm_node_shaper_supported ||
			    per_level->tm_node_rate_limiter_supported) {
				CU_ASSERT(per_level->max_burst > 0);
				CU_ASSERT(per_level->min_rate > 0);
				CU_ASSERT(per_level->max_rate > 0);
			}

			if (per_level->tm_node_shaper_packet_mode) {
				CU_ASSERT(per_level->max_burst_packets > 0);
				CU_ASSERT(per_level->min_rate_packets > 0);
				CU_ASSERT(per_level->max_rate_packets > 0);
			}
		}

		/* At least one pkt priority mode needs to be supported */
		prio_modes = cap_ptr->pkt_prio_modes;
		CU_ASSERT((prio_modes[ODP_TM_PKT_PRIO_MODE_PRESERVE] != 0) ||
			  (prio_modes[ODP_TM_PKT_PRIO_MODE_OVERWRITE] != 0))
	}

	return 0;
}

static int wait_linkup(odp_pktio_t pktio)
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

	return ret;
}

static int open_pktios(void)
{
	odp_pktio_param_t pktio_param;
	odp_pktio_config_t pktio_config;
	odp_pool_param_t  pool_param;
	odp_pktio_t       pktio;
	odp_pool_t        pkt_pool;
	uint32_t          iface;
	char              pool_name[ODP_POOL_NAME_LEN];
	int               rc, ret;
	int pkt_aging = 0;
	int lso = 0;

	odp_pool_param_init(&pool_param);
	pool_param.pkt.num  = 10 * MAX_PKTS;
	pool_param.type     = ODP_POOL_PACKET;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode  = ODP_PKTIN_MODE_DIRECT;

	for (iface = 0; iface < num_ifaces; iface++) {
		snprintf(pool_name, sizeof(pool_name), "pkt_pool_%s",
			 iface_name[iface]);

		pkt_pool = odp_pool_create(pool_name, &pool_param);
		if (pkt_pool == ODP_POOL_INVALID) {
			CU_FAIL("unable to create pool");
			return -1;
		}

		pools[iface] = pkt_pool;

		/* Zero'th device is always PKTOUT TM as we use it from XMIT */
		if (iface == 0) {
			pktio_param.out_mode = ODP_PKTOUT_MODE_TM;

			pktio = odp_pktio_open(iface_name[iface], pkt_pool,
					       &pktio_param);

			/* On failure check if pktio can be opened in non-TM mode.
			 * If non-TM mode works, then we can assume that PKTIO
			 * does not support TM
			 */
			if (pktio == ODP_PKTIO_INVALID) {
				pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;
				pktio = odp_pktio_open(iface_name[iface], pkt_pool,
						       &pktio_param);

				/* Return >0 to indicate no TM support */
				if (pktio != ODP_PKTIO_INVALID) {
					odp_pktio_close(pktio);
					return 1;
				}
			}
		} else {
			pktio_param.out_mode = ODP_PKTOUT_MODE_DISABLED;

			pktio = odp_pktio_open(iface_name[iface], pkt_pool,
					       &pktio_param);
		}

		pktios[iface] = pktio;
		if (pktio == ODP_PKTIO_INVALID) {
			ODPH_ERR("odp_pktio_open() failed\n");
			return -1;
		}

		/* Set defaults for PktIn and PktOut queues */
		(void)odp_pktin_queue_config(pktio, NULL);
		rc = odp_pktio_promisc_mode_set(pktio, true);
		if (rc != 0)
			printf("****** promisc_mode_set failed  ******\n");

		if (odp_pktin_queue(pktio, &pktins[iface], 1) != 1) {
			odp_pktio_close(pktio);
			ODPH_ERR("odp_pktio_open() failed: no pktin queue\n");
			return -1;
		}

		rc = -1;
		if (iface == 0)
			rc = odp_pktio_mac_addr(pktio, &src_mac,
						ODPH_ETHADDR_LEN);

		if ((iface == 1) || (num_ifaces == 1))
			rc = odp_pktio_mac_addr(pktio, &dst_mac,
						ODPH_ETHADDR_LEN);

		if (rc != ODPH_ETHADDR_LEN) {
			ODPH_ERR("odp_pktio_mac_addr() failed\n");
			return -1;
		}
	}

	if (2 <= num_ifaces) {
		xmt_pktio = pktios[0];
		rcv_pktin  = pktins[1];
		ret = odp_pktio_start(pktios[1]);
		if (ret != 0) {
			ODPH_ERR("odp_pktio_start() failed\n");
			return -1;
		}
		pktio_started[1] = true;
	} else {
		xmt_pktio = pktios[0];
		rcv_pktin  = pktins[0];
	}

	if (odp_pktio_capability(xmt_pktio, &xmt_pktio_capa)) {
		ODPH_ERR("pktio capa failed\n");
		return -1;
	}

	odp_pktio_config_init(&pktio_config);

	/* Enable packet aging if supported */
	if (xmt_pktio_capa.max_tx_aging_tmo_ns) {
		pkt_aging = 1;
		pktio_config.pktout.bit.aging_ena = 1;
	}

	/* Enable LSO if supported */
	if (xmt_pktio_capa.lso.max_profiles && xmt_pktio_capa.lso.max_profiles_per_pktio) {
		lso = 1;
		pktio_config.enable_lso = 1;
	}

	/* Enable selected features */
	if (lso || pkt_aging) {
		if (odp_pktio_config(xmt_pktio, &pktio_config)) {
			ODPH_ERR("pktio configure failed\n");
			return -1;
		}
	}

	/* Add LSO profiles before start */
	if (lso) {
		odp_lso_profile_param_t prof_param;

		if (xmt_pktio_capa.lso.proto.ipv4) {
			odp_lso_profile_param_init(&prof_param);
			prof_param.lso_proto = ODP_LSO_PROTO_IPV4;

			lso_ipv4_profile = odp_lso_profile_create(xmt_pktio, &prof_param);
			if (lso_ipv4_profile == ODP_LSO_PROFILE_INVALID) {
				ODPH_ERR("Failed to create IPv4 LSO profile\n");
				return -1;
			}
		}
	}

	ret = odp_pktio_start(xmt_pktio);
	if (ret != 0) {
		ODPH_ERR("odp_pktio_start() failed\n");
		return -1;
	}
	pktio_started[0] = true;

	/* Now wait until the link or links are up. */
	rc = wait_linkup(xmt_pktio);
	if (rc != 1) {
		ODPH_ERR("link %" PRIX64 " not up\n", odp_pktio_to_u64(xmt_pktio));
		return -1;
	}

	if (num_ifaces < 2)
		return 0;

	/* Wait for 2nd link to be up */
	rc = wait_linkup(pktios[1]);
	if (rc != 1) {
		ODPH_ERR("link %" PRIX64 " not up\n", odp_pktio_to_u64(pktios[1]));
		return -1;
	}

	return 0;
}

static int get_unique_id(odp_packet_t odp_pkt,
			 uint16_t    *unique_id_ptr,
			 uint8_t     *is_ipv4_pkt_ptr)
{
	odp_u32be_t be_ver_tc_flow;
	odp_u16be_t be_ip_ident;
	odp_bool_t  is_ipv4;
	uint32_t    l3_offset, ident_offset, flow_offset, ver_tc_flow;
	uint16_t    unique_id;

	l3_offset = odp_packet_l3_offset(odp_pkt);

	if (odp_packet_has_ipv4(odp_pkt)) {
		/* For IPv4 pkts use the ident field to store the unique_id. */
		ident_offset = l3_offset + offsetof(odph_ipv4hdr_t, id);

		CU_ASSERT_FATAL(odp_packet_copy_to_mem(odp_pkt, ident_offset, 2,
						       &be_ip_ident) == 0);
		unique_id = odp_be_to_cpu_16(be_ip_ident);
		is_ipv4   = true;
	} else if (odp_packet_has_ipv6(odp_pkt)) {
		/* For IPv6 pkts use the flow field to store the unique_id. */
		flow_offset = l3_offset + offsetof(odph_ipv6hdr_t, ver_tc_flow);

		CU_ASSERT_FATAL(odp_packet_copy_to_mem(odp_pkt, flow_offset, 4,
						       &be_ver_tc_flow) == 0);
		ver_tc_flow = odp_be_to_cpu_32(be_ver_tc_flow);
		unique_id   = ver_tc_flow & ODPH_IPV6HDR_FLOW_LABEL_MASK;
		is_ipv4     = false;
	} else {
		return -1;
	}

	if (unique_id_ptr != NULL)
		*unique_id_ptr = unique_id;

	if (is_ipv4_pkt_ptr != NULL)
		*is_ipv4_pkt_ptr = is_ipv4;

	return 0;
}

static int get_vlan_tci(odp_packet_t odp_pkt, uint16_t *vlan_tci_ptr)
{
	odph_vlanhdr_t *vlan_hdr;
	odph_ethhdr_t  *ether_hdr;
	uint32_t        hdr_len;
	uint16_t        vlan_tci;

	if (!odp_packet_has_vlan(odp_pkt))
		return -1;

	/* *TBD* check value of hdr_len? */
	ether_hdr = odp_packet_l2_ptr(odp_pkt, &hdr_len);
	vlan_hdr  = (odph_vlanhdr_t *)(ether_hdr + 1);
	vlan_tci  = odp_be_to_cpu_16(vlan_hdr->tci);
	if (vlan_tci_ptr != NULL)
		*vlan_tci_ptr = vlan_tci;

	return 0;
}

/* Returns either the TOS field for IPv4 pkts or the TC field for IPv6 pkts. */
static int get_ip_tos(odp_packet_t odp_pkt, uint8_t *tos_ptr)
{
	odph_ipv4hdr_t *ipv4_hdr;
	odph_ipv6hdr_t *ipv6_hdr;
	uint32_t        ver_tc_flow;
	uint8_t         tos, tc;
	uint32_t        hdr_len = 0;

	if (odp_packet_has_ipv4(odp_pkt)) {
		ipv4_hdr = odp_packet_l3_ptr(odp_pkt, &hdr_len);
		if (hdr_len < 12)
			return -1;

		tos = ipv4_hdr->tos;
	} else if (odp_packet_has_ipv6(odp_pkt)) {
		ipv6_hdr = odp_packet_l3_ptr(odp_pkt, &hdr_len);
		if (hdr_len < 4)
			return -1;

		ver_tc_flow = odp_be_to_cpu_32(ipv6_hdr->ver_tc_flow);
		tc          = (ver_tc_flow & ODPH_IPV6HDR_TC_MASK)
					>> ODPH_IPV6HDR_TC_SHIFT;
		tos = tc;
	} else {
	       return -1;
	}

	if (tos_ptr != NULL)
		*tos_ptr = tos;

	return 0;
}

static odp_packet_t make_pkt(odp_pool_t  pkt_pool,
			     uint32_t    payload_len,
			     uint16_t    unique_id,
			     pkt_info_t *pkt_info)
{
	odph_vlanhdr_t *vlan_hdr;
	odph_ipv4hdr_t *ipv4_hdr;
	odph_ipv6hdr_t *ipv6_hdr;
	odph_ethhdr_t  *eth_hdr;
	odph_udphdr_t  *udp_hdr;
	odph_tcphdr_t  *tcp_hdr;
	odp_packet_t    odp_pkt;
	uint32_t        l4_hdr_len, l3_hdr_len, vlan_hdr_len, l2_hdr_len;
	uint32_t        l4_len, l3_len, l2_len, pkt_len, l3_offset, l4_offset;
	uint32_t        version, tc, flow, ver_tc_flow, app_offset;
	uint16_t        final_ether_type;
	uint8_t        *buf, *pkt_class_ptr, next_hdr;
	int             rc;

	if (payload_len > MAX_PAYLOAD) {
		ODPH_ERR("packet payload length of %u exceeds MAX_PAYLOAD of %u\n",
			 payload_len, MAX_PAYLOAD);
		return ODP_PACKET_INVALID;
	}

	l4_hdr_len   = pkt_info->use_tcp  ? ODPH_TCPHDR_LEN  : ODPH_UDPHDR_LEN;
	l3_hdr_len   = pkt_info->use_ipv6 ? ODPH_IPV6HDR_LEN : ODPH_IPV4HDR_LEN;
	vlan_hdr_len = pkt_info->use_vlan ? ODPH_VLANHDR_LEN : 0;
	l2_hdr_len   = ODPH_ETHHDR_LEN + vlan_hdr_len;
	l4_len       = l4_hdr_len + payload_len;
	l3_len       = l3_hdr_len + l4_len;
	l2_len       = l2_hdr_len + l3_len;
	pkt_len      = l2_len;
	if (unique_id == 0) {
		ODPH_ERR("%s called with invalid unique_id of 0\n", __func__);
		return ODP_PACKET_INVALID;
	}

	odp_pkt = odp_packet_alloc(pkt_pool, pkt_len);
	if (odp_pkt == ODP_PACKET_INVALID)
		return ODP_PACKET_INVALID;

	buf = odp_packet_data(odp_pkt);

	/* Ethernet Header */
	odp_packet_l2_offset_set(odp_pkt, 0);
	eth_hdr          = (odph_ethhdr_t *)buf;
	final_ether_type = pkt_info->use_ipv6 ? ODPH_ETHTYPE_IPV6
					      : ODPH_ETHTYPE_IPV4;
	memcpy(eth_hdr->src.addr, &src_mac, ODPH_ETHADDR_LEN);
	memcpy(eth_hdr->dst.addr, &dst_mac, ODPH_ETHADDR_LEN);

	/* Vlan Header */
	if (pkt_info->use_vlan) {
		odp_packet_has_vlan_set(odp_pkt, 1);
		eth_hdr->type  = odp_cpu_to_be_16(ODPH_ETHTYPE_VLAN);
		vlan_hdr       = (odph_vlanhdr_t *)(eth_hdr + 1);
		vlan_hdr->tci  = odp_cpu_to_be_16(pkt_info->vlan_tci);
		vlan_hdr->type = odp_cpu_to_be_16(final_ether_type);
	} else {
		eth_hdr->type = odp_cpu_to_be_16(final_ether_type);
	}

	l3_offset = l2_hdr_len;
	next_hdr  = pkt_info->use_tcp ? ODPH_IPPROTO_TCP : ODPH_IPPROTO_UDP;
	odp_packet_l3_offset_set(odp_pkt, l3_offset);
	if (pkt_info->use_ipv6) {
		/* IPv6 Header */
		odp_packet_has_ipv6_set(odp_pkt, 1);
		version     = ODPH_IPV6        << ODPH_IPV6HDR_VERSION_SHIFT;
		tc          = pkt_info->ip_tos << ODPH_IPV6HDR_TC_SHIFT;
		flow        = unique_id        << ODPH_IPV6HDR_FLOW_LABEL_SHIFT;
		ver_tc_flow = version | tc | flow;

		ipv6_hdr              = (odph_ipv6hdr_t *)(buf + l3_offset);
		ipv6_hdr->ver_tc_flow = odp_cpu_to_be_32(ver_tc_flow);
		ipv6_hdr->payload_len = odp_cpu_to_be_16(l4_len);
		ipv6_hdr->next_hdr    = next_hdr;
		ipv6_hdr->hop_limit   = DEFAULT_TTL;
		memcpy(ipv6_hdr->src_addr, IPV6_SRC_ADDR, ODPH_IPV6ADDR_LEN);
		memcpy(ipv6_hdr->dst_addr, IPV6_DST_ADDR, ODPH_IPV6ADDR_LEN);
	} else {
		/* IPv4 Header */
		odp_packet_has_ipv4_set(odp_pkt, 1);
		ipv4_hdr              = (odph_ipv4hdr_t *)(buf + l3_offset);
		ipv4_hdr->ver_ihl     = (ODPH_IPV4 << 4) | ODPH_IPV4HDR_IHL_MIN;
		ipv4_hdr->tos         = pkt_info->ip_tos;
		ipv4_hdr->tot_len     = odp_cpu_to_be_16(l3_len);
		ipv4_hdr->id          = odp_cpu_to_be_16(unique_id);
		ipv4_hdr->frag_offset = 0;
		ipv4_hdr->ttl         = DEFAULT_TTL;
		ipv4_hdr->proto       = next_hdr;
		ipv4_hdr->chksum      = 0;
		memcpy(&ipv4_hdr->src_addr, IPV4_SRC_ADDR, ODPH_IPV4ADDR_LEN);
		memcpy(&ipv4_hdr->dst_addr, IPV4_DST_ADDR, ODPH_IPV4ADDR_LEN);
	}

	l4_offset = l3_offset + l3_hdr_len;
	odp_packet_l4_offset_set(odp_pkt, l4_offset);
	tcp_hdr = (odph_tcphdr_t *)(buf + l4_offset);
	udp_hdr = (odph_udphdr_t *)(buf + l4_offset);

	if (pkt_info->use_tcp) {
		/* TCP Header */
		odp_packet_has_tcp_set(odp_pkt, 1);
		tcp_hdr->src_port = odp_cpu_to_be_16(DEFAULT_TCP_SRC_PORT);
		tcp_hdr->dst_port = odp_cpu_to_be_16(DEFAULT_TCP_DST_PORT);
		tcp_hdr->seq_no   = odp_cpu_to_be_32(cpu_tcp_seq_num);
		tcp_hdr->ack_no   = odp_cpu_to_be_32(DEFAULT_TCP_ACK_NUM);
		tcp_hdr->window   = odp_cpu_to_be_16(DEFAULT_TCP_WINDOW);
		tcp_hdr->cksm     = 0;
		tcp_hdr->urgptr   = 0;

		tcp_hdr->doffset_flags = 0;
		tcp_hdr->hl            = 5;
		tcp_hdr->ack           = 1;
		cpu_tcp_seq_num       += payload_len;
	} else {
		/* UDP Header */
		odp_packet_has_udp_set(odp_pkt, 1);
		udp_hdr->src_port = odp_cpu_to_be_16(DEFAULT_UDP_SRC_PORT);
		udp_hdr->dst_port = odp_cpu_to_be_16(DEFAULT_UDP_DST_PORT);
		udp_hdr->length   = odp_cpu_to_be_16(l4_len);
		udp_hdr->chksum   = 0;
	}

	app_offset = l4_offset + l4_hdr_len;
	rc         = odp_packet_copy_from_mem(odp_pkt, app_offset, payload_len,
					      payload_data);
	CU_ASSERT_FATAL(rc == 0);

	pkt_class_ptr = odp_packet_offset(odp_pkt, app_offset, NULL, NULL);
	CU_ASSERT_FATAL(pkt_class_ptr != NULL);
	*pkt_class_ptr = pkt_info->pkt_class;

	/* Calculate and insert checksums. First the IPv4 header checksum. */
	if (!pkt_info->use_ipv6)
		odph_ipv4_csum_update(odp_pkt);

	/* Next the UDP/TCP checksum. */
	if (odph_udp_tcp_chksum(odp_pkt, ODPH_CHKSUM_GENERATE, NULL) != 0)
		ODPH_ERR("odph_udp_tcp_chksum failed\n");

	return odp_pkt;
}

static xmt_pkt_desc_t *find_matching_xmt_pkt_desc(uint16_t unique_id)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	uint32_t        xmt_pkt_idx;

	if (unique_id == 0)
		return NULL;

	for (xmt_pkt_idx = 0; xmt_pkt_idx < num_pkts_sent; xmt_pkt_idx++) {
		xmt_pkt_desc = &xmt_pkt_descs[xmt_pkt_idx];
		if (xmt_pkt_desc->xmt_unique_id == unique_id)
			return xmt_pkt_desc;
	}

	return NULL;
}

static int32_t receive_loop(odp_tm_t tm, odp_pktin_queue_t pktin, uint32_t num_pkts,
			    uint64_t timeout_ns)
{
	odp_time_t start_time, current_time;
	uint64_t duration_ns;
	uint32_t pkts_rcvd;
	int rc;

	pkts_rcvd   = 0;
	start_time  = odp_time_local();
	duration_ns = 0;

	while ((pkts_rcvd < num_pkts) || (!odp_tm_is_idle(tm))) {
		rc = odp_pktin_recv(pktin, &rcv_pkts[pkts_rcvd], 1);
		if (rc < 0)
			return -1;

		current_time = odp_time_local();
		duration_ns  = odp_time_diff_ns(current_time, start_time);

		if (rc == 1)
			rcv_pkt_descs[pkts_rcvd++].rcv_time = current_time;
		else if (timeout_ns < duration_ns)
			break;
	}

	return pkts_rcvd;
}

static int receive_pkts(odp_tm_t tm, odp_pktin_queue_t pktin, uint32_t num_pkts,
			uint64_t rate_bps)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	rcv_pkt_desc_t *rcv_pkt_desc;
	odp_packet_t    rcv_pkt;
	odp_time_t      xmt_time;
	odp_time_t      rcv_time, delta_time;
	uint64_t        delta_ns, tmp, timeout_ns;
	uint32_t        pkts_rcvd, rcv_idx, l4_offset, l4_hdr_len, app_offset;
	uint16_t        unique_id;
	uint8_t        *pkt_class_ptr, pkt_class, is_ipv4_pkt;
	int32_t         rc;

	tmp        = (1000000ULL * 10000ULL * (uint64_t)num_pkts) / rate_bps;
	timeout_ns = 1000ULL * ((4ULL * tmp) + 10000ULL);

	rc = receive_loop(tm, pktin, num_pkts, timeout_ns);
	if (rc < 0)
		return -1;

	pkts_rcvd = rc;

	/* Now go through matching the rcv pkts to the xmt pkts, determining
	 * which xmt_pkts were lost and for the ones that did arrive, how
	 * long did they take. We don't do this work while receiving the pkts
	 * in the loop above because we want to try to get as accurate a
	 * rcv timestamp as possible. */
	for (rcv_idx = 0; rcv_idx < pkts_rcvd; rcv_idx++) {
		rcv_pkt      = rcv_pkts[rcv_idx];
		rcv_pkt_desc = &rcv_pkt_descs[rcv_idx];

		if (odp_packet_has_error(rcv_pkt)) {
			rcv_pkt_desc->errors = 0x01 |
				(odp_packet_has_l2_error(rcv_pkt) << 1) |
				(odp_packet_has_l3_error(rcv_pkt) << 2) |
				(odp_packet_has_l4_error(rcv_pkt) << 3);

			ODPH_ERR("received a pkt with the following errors\n");
			ODPH_ERR("    l2_err=%u l3_err=%u l4_err=%u. "
				 "Skipping\n",
				 (rcv_pkt_desc->errors >> 1) & 0x1,
				 (rcv_pkt_desc->errors >> 2) & 0x1,
				 (rcv_pkt_desc->errors >> 3) & 0x1);
		}

		unique_id    = 0;
		rc           = get_unique_id(rcv_pkt, &unique_id, &is_ipv4_pkt);
		if (rc != 0) {
			ODPH_ERR("received a non IPv4/IPv6 pkt\n");
			return -1;
		}

		rcv_pkt_desc->rcv_unique_id = unique_id;
		rcv_pkt_desc->is_ipv4_pkt   = is_ipv4_pkt;
		if (odp_packet_has_udp(rcv_pkt))
			l4_hdr_len = ODPH_UDPHDR_LEN;
		else if (odp_packet_has_tcp(rcv_pkt))
			l4_hdr_len = ODPH_TCPHDR_LEN;
		else
			l4_hdr_len = 0;

		l4_offset     = odp_packet_l4_offset(rcv_pkt);
		app_offset    = l4_offset + l4_hdr_len;
		pkt_class_ptr = odp_packet_offset(rcv_pkt, app_offset,
						  NULL, NULL);
		if (pkt_class_ptr != NULL)
			rcv_pkt_desc->pkt_class = *pkt_class_ptr;

		xmt_pkt_desc = find_matching_xmt_pkt_desc(unique_id);
		if (xmt_pkt_desc != NULL) {
			rcv_pkt_desc->xmt_pkt_desc = xmt_pkt_desc;
			rcv_pkt_desc->matched      = true;

			xmt_time   = xmt_pkt_desc->xmt_time;
			rcv_time   = rcv_pkt_desc->rcv_time;
			pkt_class  = rcv_pkt_desc->pkt_class;
			delta_time = odp_time_diff(rcv_time, xmt_time);
			delta_ns   = odp_time_to_ns(delta_time);

			rcv_pkt_desc->xmt_idx   = xmt_pkt_desc->xmt_idx;
			xmt_pkt_desc->rcv_time  = rcv_time;
			xmt_pkt_desc->delta_ns  = delta_ns;
			xmt_pkt_desc->pkt_class = pkt_class;
			xmt_pkt_desc->was_rcvd  = 1;
		}
	}

	return pkts_rcvd;
}

static void dump_rcvd_pkts(uint32_t first_rcv_idx, uint32_t last_rcv_idx)
{
	rcv_pkt_desc_t *rcv_pkt_desc;
	odp_packet_t    rcv_pkt;
	uint32_t        rcv_idx;
	int32_t         xmt_idx;
	uint16_t        unique_id = 0;
	uint8_t         is_ipv4 = 0;
	int             rc;

	for (rcv_idx = first_rcv_idx; rcv_idx <= last_rcv_idx; rcv_idx++) {
		rcv_pkt      = rcv_pkts[rcv_idx];
		rcv_pkt_desc = &rcv_pkt_descs[rcv_idx];
		rc           = get_unique_id(rcv_pkt, &unique_id, &is_ipv4);
		xmt_idx      = -1;
		if (rcv_pkt_desc->matched)
			xmt_idx = rcv_pkt_desc->xmt_pkt_desc->xmt_idx;

		printf("rcv_idx=%" PRIu32 " odp_pkt=0x%" PRIX64 " "
		       "xmt_idx=%" PRId32 " pkt_class=%u is_ipv4=%u "
		       "unique_id=0x%X (rc=%d)\n",
		       rcv_idx, odp_packet_to_u64(rcv_pkt), xmt_idx,
		       rcv_pkt_desc->pkt_class, is_ipv4, unique_id, rc);
	}
}

static void free_rcvd_pkts(void)
{
	odp_packet_t rcv_pkt;
	uint32_t     rcv_idx;

	/* Go through all of the received pkts and free them. */
	for (rcv_idx = 0; rcv_idx < num_rcv_pkts; rcv_idx++) {
		rcv_pkt = rcv_pkts[rcv_idx];
		if (rcv_pkt != ODP_PACKET_INVALID) {
			odp_packet_free(rcv_pkt);
			rcv_pkts[rcv_idx] = ODP_PACKET_INVALID;
		}
	}
}

static void flush_leftover_pkts(odp_tm_t odp_tm, odp_pktin_queue_t pktin)
{
	odp_packet_t rcv_pkt;
	odp_time_t   start_time, current_time, duration;
	uint64_t     min_timeout_ns, max_timeout_ns, duration_ns;
	int          rc;

	/* Set the timeout to be at least 10 milliseconds and at most 100
	 * milliseconds */
	min_timeout_ns = 10 * ODP_TIME_MSEC_IN_NS;
	max_timeout_ns = 100 * ODP_TIME_MSEC_IN_NS;
	start_time     = odp_time_local();

	while (true) {
		rc = odp_pktin_recv(pktin, &rcv_pkt, 1);
		if (rc == 1)
			odp_packet_free(rcv_pkt);

		current_time = odp_time_local();
		duration     = odp_time_diff(current_time, start_time);
		duration_ns  = odp_time_to_ns(duration);

		if (max_timeout_ns <= duration_ns)
			break;
		else if (duration_ns < min_timeout_ns)
			;
		else if ((odp_tm_is_idle(odp_tm)) && (rc == 0))
			break;

		/* Busy wait here a little bit to prevent overwhelming the
		 * odp_pktin_recv logic. */
		busy_wait(10000);
	}
}

static void init_xmt_pkts(pkt_info_t *pkt_info)
{
	memset(xmt_pkts,      0, sizeof(xmt_pkts));
	memset(xmt_pkt_descs, 0, sizeof(xmt_pkt_descs));
	num_pkts_made = 0;
	num_pkts_sent = 0;

	free_rcvd_pkts();
	memset(rcv_pkts,      0, sizeof(rcv_pkts));
	memset(rcv_pkt_descs, 0, sizeof(rcv_pkt_descs));
	num_rcv_pkts = 0;

	memset(rcv_gaps, 0, sizeof(rcv_gaps));
	rcv_gap_cnt = 0;
	memset(pkt_info, 0, sizeof(pkt_info_t));
	pkt_info->ip_tos = DEFAULT_TOS;
}

static int make_pkts(uint32_t    num_pkts,
		     uint32_t    pkt_len,
		     pkt_info_t *pkt_info)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	odp_packet_t    odp_pkt;
	uint32_t        l4_hdr_len, l3_hdr_len, vlan_hdr_len, l2_hdr_len;
	uint32_t        hdrs_len, payload_len, idx, unique_id, xmt_pkt_idx;

	l4_hdr_len   = pkt_info->use_tcp  ? ODPH_TCPHDR_LEN  : ODPH_UDPHDR_LEN;
	l3_hdr_len   = pkt_info->use_ipv6 ? ODPH_IPV6HDR_LEN : ODPH_IPV4HDR_LEN;
	vlan_hdr_len = pkt_info->use_vlan ? ODPH_VLANHDR_LEN : 0;
	l2_hdr_len   = ODPH_ETHHDR_LEN + vlan_hdr_len;

	hdrs_len    = l2_hdr_len + l3_hdr_len + l4_hdr_len;
	payload_len = pkt_len - hdrs_len;

	for (idx = 0; idx < num_pkts; idx++) {
		unique_id                   = cpu_unique_id++;
		xmt_pkt_idx                 = num_pkts_made++;
		xmt_pkt_desc                = &xmt_pkt_descs[xmt_pkt_idx];
		xmt_pkt_desc->pkt_len       = pkt_len;
		xmt_pkt_desc->xmt_unique_id = unique_id;
		xmt_pkt_desc->pkt_class     = pkt_info->pkt_class;

		odp_pkt = make_pkt(pools[0], payload_len, unique_id, pkt_info);
		if (odp_pkt == ODP_PACKET_INVALID)
			return -1;

		odp_packet_color_set(odp_pkt, pkt_info->pkt_color);
		odp_packet_drop_eligible_set(odp_pkt, pkt_info->drop_eligible);
		odp_packet_shaper_len_adjust_set(odp_pkt, SHAPER_LEN_ADJ);

		xmt_pkts[xmt_pkt_idx] = odp_pkt;
	}

	return 0;
}

static uint32_t send_pkts_multi(odp_tm_queue_t tm_queue, uint32_t num_pkts)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	odp_packet_t    odp_pkt;
	uint32_t        xmt_pkt_idx, pkts_sent;
	int64_t         rc, i = 0;

	/* Now send the pkts as fast as we can. RED drops are internally
	 * consumed by odp_tm_enq_multi().
	 */
	xmt_pkt_idx = num_pkts_sent;
	rc = odp_tm_enq_multi(tm_queue, &xmt_pkts[xmt_pkt_idx], num_pkts);
	CU_ASSERT(rc >= 0);
	CU_ASSERT(rc <= num_pkts);

	/* Record consumed packets */
	pkts_sent = 0;
	for (i = 0; i < rc; i++) {
		xmt_pkt_desc = &xmt_pkt_descs[xmt_pkt_idx + i];
		xmt_pkt_desc->xmt_idx = xmt_pkt_idx + i;
		xmt_pkt_desc->xmt_time = odp_time_local();
		xmt_pkt_desc->tm_queue = tm_queue;
		pkts_sent++;
	}

	/* Free rejected pkts */
	for (; i < num_pkts; i++) {
		xmt_pkt_desc = &xmt_pkt_descs[xmt_pkt_idx + i];
		xmt_pkt_desc->xmt_idx = xmt_pkt_idx + i;

		odp_pkt = xmt_pkts[xmt_pkt_idx + i];
		odp_packet_free(odp_pkt);
		xmt_pkts[xmt_pkt_idx + i] = ODP_PACKET_INVALID;
	}
	num_pkts_sent += num_pkts;

	return pkts_sent;
}

static uint32_t send_pkts(odp_tm_queue_t tm_queue, uint32_t num_pkts)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	odp_packet_t    odp_pkt;
	uint32_t        idx, xmt_pkt_idx, pkts_sent;
	int             rc;

	/* Now send the pkts as fast as we can. */
	pkts_sent = 0;
	for (idx = 0; idx < num_pkts; idx++) {
		xmt_pkt_idx  = num_pkts_sent;
		odp_pkt      = xmt_pkts[xmt_pkt_idx];
		xmt_pkt_desc = &xmt_pkt_descs[xmt_pkt_idx];

		/* Alternate calling with odp_tm_enq and odp_tm_enq_with_cnt */
		if ((idx & 1) == 0) {
			rc = odp_tm_enq(tm_queue, odp_pkt);
			CU_ASSERT(rc <= 0);
		} else {
			rc = odp_tm_enq_with_cnt(tm_queue, odp_pkt);
		}

		xmt_pkt_desc->xmt_idx = xmt_pkt_idx;
		if (0 <= rc) {
			xmt_pkt_desc->xmt_time = odp_time_local();
			xmt_pkt_desc->tm_queue = tm_queue;
			pkts_sent++;
		} else {
			odp_packet_free(odp_pkt);
			xmt_pkts[xmt_pkt_idx] = ODP_PACKET_INVALID;
		}

		num_pkts_sent++;
	}

	return pkts_sent;
}

static uint32_t send_pkts_lso(odp_tm_queue_t tm_queue, uint32_t num_pkts,
			      odp_lso_protocol_t lso_proto, uint32_t max_len)
{
	odp_packet_lso_opt_t lso_opt;
	odp_lso_profile_t profile;
	xmt_pkt_desc_t *xmt_pkt_desc;
	odp_packet_t pkt;
	uint32_t offset, pkts_sent;
	int64_t rc, i, idx;

	pkt = xmt_pkts[0];

	if (lso_proto == ODP_LSO_PROTO_IPV4) {
		profile = lso_ipv4_profile;
		offset  = odp_packet_l4_offset(pkt);
	} else {
		ODPH_ERR("Bad LSO protocol\n");
		return 0;
	}

	lso_opt.lso_profile     = profile;
	lso_opt.payload_offset  = offset;
	lso_opt.max_payload_len = max_len;

	pkts_sent = 0;

	for (i = 0; i < num_pkts; i++) {
		idx = num_pkts_sent + i;
		pkt = xmt_pkts[idx];
		xmt_pkt_desc = &xmt_pkt_descs[idx];

		rc = odp_tm_enq_multi_lso(tm_queue, &pkt, 1, &lso_opt);

		CU_ASSERT(rc == 0 || rc == 1);

		if (rc < 0) {
			ODPH_ERR("Enqueue LSO failed\n");
			num_pkts_sent += i;
			return pkts_sent;
		}

		xmt_pkt_desc->xmt_idx = idx;

		if (rc > 0) {
			/* Record consumed packets */
			xmt_pkt_desc->xmt_time = odp_time_local();
			xmt_pkt_desc->tm_queue = tm_queue;
			pkts_sent++;
		} else {
			/* Free rejected pkts */
			odp_packet_free(pkt);
			xmt_pkts[idx] = ODP_PACKET_INVALID;
		}
	}

	num_pkts_sent += num_pkts;

	return pkts_sent;
}

static uint32_t pkts_rcvd_in_send_order(void)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	odp_time_t      last_rcv_time, rcv_time;
	uint32_t        xmt_pkt_idx, pkts_rcvd;

	pkts_rcvd     = 0;
	last_rcv_time = ODP_TIME_NULL;
	for (xmt_pkt_idx = 0; xmt_pkt_idx < num_pkts_sent; xmt_pkt_idx++) {
		xmt_pkt_desc = &xmt_pkt_descs[xmt_pkt_idx];
		rcv_time     = xmt_pkt_desc->rcv_time;
		if (xmt_pkt_desc->was_rcvd != 0) {
			if ((pkts_rcvd != 0) &&
			    (odp_time_cmp(rcv_time, last_rcv_time) < 0))
				return 0;

			pkts_rcvd++;
			last_rcv_time = xmt_pkt_desc->rcv_time;
		}
	}

	return pkts_rcvd;
}

static int unique_id_list_idx(uint32_t unique_id,
			      uint32_t unique_id_list[],
			      uint32_t unique_id_list_len)
{
	uint32_t idx;

	for (idx = 0; idx < unique_id_list_len; idx++)
		if (unique_id_list[idx] == unique_id)
			return idx;

	return -1;
}

static uint32_t pkts_rcvd_in_given_order(uint32_t   unique_id_list[],
					 uint32_t   unique_id_list_len,
					 uint8_t    pkt_class,
					 odp_bool_t match_pkt_class,
					 odp_bool_t ignore_pkt_class)
{
	rcv_pkt_desc_t *rcv_pkt_desc;
	odp_bool_t      is_match;
	uint32_t        rcv_pkt_idx, pkts_in_order;
	uint32_t        rcv_unique_id;
	int             last_pkt_idx, pkt_idx;

	pkts_in_order     = 1;
	last_pkt_idx      = -1;
	pkt_idx           = -1;

	for (rcv_pkt_idx = 0; rcv_pkt_idx < num_rcv_pkts; rcv_pkt_idx++) {
		rcv_pkt_desc = &rcv_pkt_descs[rcv_pkt_idx];

		if (ignore_pkt_class)
			is_match = true;
		else if (match_pkt_class)
			is_match = rcv_pkt_desc->pkt_class == pkt_class;
		else
			is_match = rcv_pkt_desc->pkt_class != pkt_class;

		if (is_match) {
			rcv_unique_id = rcv_pkt_desc->rcv_unique_id;
			pkt_idx       = unique_id_list_idx(rcv_unique_id,
							   unique_id_list,
							   unique_id_list_len);
			if (0 <= pkt_idx) {
				if (0 <= last_pkt_idx && last_pkt_idx < pkt_idx)
					pkts_in_order++;

				last_pkt_idx = pkt_idx;
			}
		}
	}

	return pkts_in_order;
}

static inline void record_rcv_gap(odp_time_t rcv_time, odp_time_t last_rcv_time)
{
	odp_time_t delta_time;
	uint64_t   delta_ns;
	uint32_t   rcv_gap;

	rcv_gap = 0;
	if (odp_time_cmp(last_rcv_time, rcv_time) <= 0) {
		delta_time = odp_time_diff(rcv_time, last_rcv_time);
		delta_ns   = odp_time_to_ns(delta_time);
		rcv_gap    = delta_ns / 1000;
	}

	/* Note that rcv_gap is in units of microseconds. */
	rcv_gaps[rcv_gap_cnt++] = rcv_gap;
}

static int rcv_gap_cmp(const void *left_ptr, const void *right_ptr)
{
	uint32_t left_value, right_value;

	left_value  = * (const uint32_t *)left_ptr;
	right_value = * (const uint32_t *)right_ptr;

	if (left_value < right_value)
		return -1;
	else if (left_value == right_value)
		return 0;
	else
		return 1;
}

static inline void calc_rcv_stats(rcv_stats_t *rcv_stats,
				  uint32_t     initial_drop_percent,
				  uint32_t     ending_drop_percent)
{
	uint32_t first_rcv_gap_idx, last_rcv_gap_idx, idx, rcv_gap;

	/* Sort the rcv_gaps, and then drop the outlying x values before doing
	 * doing the rcv stats on the remaining */
	qsort(&rcv_gaps[0], rcv_gap_cnt, sizeof(uint32_t), rcv_gap_cmp);

	/* Next we drop the outlying values before doing doing the rcv stats
	 * on the remaining rcv_gap values.  The number of initial (very low)
	 * rcv_gaps dropped and the number of ending (very high) rcv_gaps
	 * drops is based on the percentages passed in. */
	first_rcv_gap_idx = (rcv_gap_cnt * initial_drop_percent) / 100;
	last_rcv_gap_idx  = (rcv_gap_cnt * (100 - ending_drop_percent)) / 100;
	for (idx = first_rcv_gap_idx; idx <= last_rcv_gap_idx; idx++) {
		rcv_gap                = rcv_gaps[idx];
		rcv_stats->min_rcv_gap = ODPH_MIN(rcv_stats->min_rcv_gap, rcv_gap);
		rcv_stats->max_rcv_gap = ODPH_MAX(rcv_stats->max_rcv_gap, rcv_gap);
		rcv_stats->total_rcv_gap         += rcv_gap;
		rcv_stats->total_rcv_gap_squared += rcv_gap * rcv_gap;
		rcv_stats->num_samples++;
	}
}

static int rcv_rate_stats(rcv_stats_t *rcv_stats, uint8_t pkt_class)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	odp_time_t      last_rcv_time, rcv_time;
	uint32_t        pkt_idx, pkts_rcvd, num;
	uint32_t        avg, variance, std_dev;

	pkts_rcvd     = 0;
	last_rcv_time = ODP_TIME_NULL;
	memset(rcv_stats, 0, sizeof(rcv_stats_t));
	rcv_stats->min_rcv_gap = 1000000000;

	for (pkt_idx = 0; pkt_idx < num_pkts_sent; pkt_idx++) {
		xmt_pkt_desc = &xmt_pkt_descs[pkt_idx];
		if ((xmt_pkt_desc->was_rcvd != 0) &&
		    (xmt_pkt_desc->pkt_class == pkt_class)) {
			rcv_time = xmt_pkt_desc->rcv_time;
			if (pkts_rcvd != 0)
				record_rcv_gap(rcv_time, last_rcv_time);
			pkts_rcvd++;
			last_rcv_time = rcv_time;
		}
	}

	if (pkts_rcvd == 0)
		return -1;

	calc_rcv_stats(rcv_stats, INITIAL_RCV_GAP_DROP, ENDING_RCV_GAP_DROP);
	num      = rcv_stats->num_samples;
	if (num == 0)
		return -1;

	avg      = rcv_stats->total_rcv_gap / num;
	variance = (rcv_stats->total_rcv_gap_squared / num) - avg * avg;
	std_dev  = (uint32_t)sqrt((double)variance);

	rcv_stats->avg_rcv_gap = avg;
	rcv_stats->std_dev_gap = std_dev;
	return 0;
}

static int create_tm_queue(odp_tm_t         odp_tm,
			   odp_tm_node_t    tm_node,
			   uint32_t         node_idx,
			   tm_queue_desc_t *queue_desc,
			   uint32_t         priority)
{
	odp_tm_queue_params_t queue_params;
	odp_tm_queue_t        tm_queue;
	odp_tm_wred_t         green_profile, yellow_profile, red_profile;
	int                   rc;

	odp_tm_queue_params_init(&queue_params);
	queue_params.priority = priority;
	if (priority == 0) {
		green_profile  = wred_profiles[node_idx][PKT_GREEN];
		yellow_profile = wred_profiles[node_idx][PKT_YELLOW];
		red_profile    = wred_profiles[node_idx][PKT_RED];

		queue_params.shaper_profile    = shaper_profiles[0];
		queue_params.threshold_profile = threshold_profiles[0];
		queue_params.wred_profile[PKT_GREEN]  = green_profile;
		queue_params.wred_profile[PKT_YELLOW] = yellow_profile;
		queue_params.wred_profile[PKT_RED]    = red_profile;
		queue_params.ordered_enqueue          = true;
	}

	tm_queue = odp_tm_queue_create(odp_tm, &queue_params);
	if (tm_queue == ODP_TM_INVALID) {
		ODPH_ERR("odp_tm_queue_create() failed\n");
		return -1;
	}

	queue_desc->tm_queues[priority] = tm_queue;
	rc = odp_tm_queue_connect(tm_queue, tm_node);
	if (rc != 0) {
		ODPH_ERR("odp_tm_queue_connect() failed for queue %" PRIx64
			"\n", odp_tm_queue_to_u64(tm_queue));
		odp_tm_queue_destroy(tm_queue);
		return -1;
	}

	return 0;
}

static int destroy_tm_queue(odp_tm_queue_t tm_queue)
{
	odp_tm_queue_disconnect(tm_queue);
	return odp_tm_queue_destroy(tm_queue);
}

static tm_node_desc_t *create_tm_node(odp_tm_t        odp_tm,
				      uint32_t        level,
				      uint32_t        num_levels,
				      uint32_t        node_idx,
				      tm_node_desc_t *parent_node_desc)
{
	odp_tm_node_params_t  node_params;
	tm_queue_desc_t      *queue_desc;
	tm_node_desc_t       *node_desc;
	odp_tm_wred_t         green_profile, yellow_profile, red_profile;
	odp_tm_node_t         tm_node, parent_node;
	uint32_t              node_desc_size, queue_desc_size, priority;
	char                  node_name[ODP_TM_NAME_LEN];
	int                   rc;

	odp_tm_node_params_init(&node_params);
	node_params.shaper_profile           = ODP_TM_INVALID;
	node_params.threshold_profile        = ODP_TM_INVALID;
	node_params.wred_profile[PKT_GREEN]  = ODP_TM_INVALID;
	node_params.wred_profile[PKT_YELLOW] = ODP_TM_INVALID;
	node_params.wred_profile[PKT_RED]    = ODP_TM_INVALID;
	if (node_idx == 0) {
		node_params.shaper_profile    = shaper_profiles[0];
		node_params.threshold_profile = threshold_profiles[0];
		if (level == num_levels) {
			green_profile  = wred_profiles[node_idx][PKT_GREEN];
			yellow_profile = wred_profiles[node_idx][PKT_YELLOW];
			red_profile    = wred_profiles[node_idx][PKT_RED];

			node_params.wred_profile[PKT_GREEN]  = green_profile;
			node_params.wred_profile[PKT_YELLOW] = yellow_profile;
			node_params.wred_profile[PKT_RED]    = red_profile;
		}
	}

	node_params.max_fanin = FANIN_RATIO;
	node_params.level = level;
	/* This is ignored when pkt priority mode is not overwrite */
	node_params.priority = 0;

	if (parent_node_desc == NULL)
		snprintf(node_name, sizeof(node_name), "node_%" PRIu32,
			 node_idx + 1);
	else
		snprintf(node_name, sizeof(node_name), "%s_%" PRIu32,
			 parent_node_desc->node_name, node_idx + 1);

	tm_node = odp_tm_node_create(odp_tm, node_name, &node_params);
	if (tm_node == ODP_TM_INVALID) {
		ODPH_ERR("odp_tm_node_create() failed @ level=%" PRIu32 "\n",
			 level);
		return NULL;
	}

	/* Now connect this node to the lower level "parent" node. */
	if (level == 0 || !parent_node_desc)
		parent_node = ODP_TM_ROOT;
	else
		parent_node = parent_node_desc->node;

	rc = odp_tm_node_connect(tm_node, parent_node);
	if (rc != 0) {
		ODPH_ERR("odp_tm_node_connect() failed @ level=%" PRIu32 "\n",
			 level);
		odp_tm_node_destroy(tm_node);
		return NULL;
	}

	node_desc_size = sizeof(tm_node_desc_t) +
			 sizeof(odp_tm_node_t) * FANIN_RATIO;
	node_desc = malloc(node_desc_size);
	memset(node_desc, 0, node_desc_size);
	node_desc->level = level;
	node_desc->node_idx = node_idx;
	node_desc->num_children = FANIN_RATIO;
	node_desc->node = tm_node;
	node_desc->parent_node = parent_node;
	node_desc->node_name = strdup(node_name);

	/* Finally if the level is the highest then make fanin_ratio tm_queues
	 * feeding this node. */
	if (level < (num_levels - 1))
		return node_desc;

	node_desc->num_children = 0;
	queue_desc_size = sizeof(tm_queue_desc_t) +
			  sizeof(odp_tm_queue_t) * NUM_QUEUES_PER_NODE;
	queue_desc = malloc(queue_desc_size);
	memset(queue_desc, 0, queue_desc_size);
	queue_desc->num_queues = NUM_QUEUES_PER_NODE;
	node_desc->queue_desc = queue_desc;

	for (priority = 0; priority < NUM_QUEUES_PER_NODE; priority++) {
		rc = create_tm_queue(odp_tm, tm_node, node_idx, queue_desc,
				     priority);
		if (rc != 0) {
			ODPH_ERR("create_tm_queue() failed @ "
				 "level=%" PRIu32 "\n", level);
			while (priority > 0)
				(void)destroy_tm_queue
					(queue_desc->tm_queues[--priority]);
			free(queue_desc);
			free(node_desc);
			return NULL;
		}
	}

	return node_desc;
}

static tm_node_desc_t *create_tm_subtree(odp_tm_t        odp_tm,
					 uint32_t        level,
					 uint32_t        num_levels,
					 uint32_t        node_idx,
					 tm_node_desc_t *parent_node)
{
	tm_node_desc_t *node_desc, *child_desc;
	uint32_t        child_idx;

	node_desc = create_tm_node(odp_tm, level, num_levels,
				   node_idx, parent_node);
	if (node_desc == NULL) {
		ODPH_ERR("create_tm_node() failed @ level=%" PRIu32 "\n",
			 level);
		return NULL;
	}

	if (level < (num_levels - 1)) {
		for (child_idx = 0; child_idx < FANIN_RATIO; child_idx++) {
			child_desc = create_tm_subtree(odp_tm, level + 1,
						       num_levels, child_idx,
						       node_desc);
			if (child_desc == NULL) {
				ODPH_ERR("%s failed level=%" PRIu32 "\n",
					 __func__, level);

				return NULL;
			}

			node_desc->children[child_idx] = child_desc;
		}
	}

	return node_desc;
}

static odp_tm_node_t find_tm_node(uint8_t tm_system_idx, const char *node_name)
{
	return odp_tm_node_lookup(odp_tm_systems[tm_system_idx], node_name);
}

static tm_node_desc_t *find_node_desc(uint8_t     tm_system_idx,
				      const char *node_name)
{
	tm_node_desc_t *node_desc;
	uint32_t        child_num;
	char           *name_ptr;

	/* Assume node_name is "node_" followed by a sequence of integers
	 * separated by underscores, where each integer is the child number to
	 * get to the next level node. */
	node_desc = root_node_descs[tm_system_idx];
	name_ptr  = strchr(node_name, '_');
	if (name_ptr == NULL)
		return NULL;

	/* Skip over the first integer */
	name_ptr++;
	name_ptr  = strchr(name_ptr, '_');
	if (name_ptr != NULL)
		name_ptr++;

	while (node_desc != NULL) {
		if (strncmp(node_desc->node_name, node_name, ODP_TM_NAME_LEN) == 0)
			return node_desc;

		if (name_ptr == NULL)
			return NULL;

		child_num = atoi(name_ptr);
		if (node_desc->num_children < child_num)
			return NULL;

		node_desc = node_desc->children[child_num - 1];
		name_ptr  = strchr(name_ptr, '_');
		if (name_ptr != NULL)
			name_ptr++;
	}

	return NULL;
}

static odp_tm_queue_t find_tm_queue(uint8_t     tm_system_idx,
				    const char *node_name,
				    uint8_t     priority)
{
	tm_queue_desc_t *queue_desc;
	tm_node_desc_t  *node_desc;

	node_desc = find_node_desc(tm_system_idx, node_name);
	if (node_desc == NULL)
		return ODP_TM_INVALID;

	queue_desc = node_desc->queue_desc;
	if (queue_desc == NULL)
		return ODP_TM_INVALID;

	return queue_desc->tm_queues[priority];
}

static uint32_t find_child_queues(uint8_t         tm_system_idx,
				  tm_node_desc_t *node_desc,
				  uint8_t         priority,
				  odp_tm_queue_t  tm_queues[],
				  uint32_t        max_queues)
{
	tm_queue_desc_t *queue_desc;
	tm_node_desc_t  *child_node_desc;
	uint32_t         num_children, num_queues, child_idx, rem_queues;

	if (max_queues == 0)
		return 0;

	queue_desc = node_desc->queue_desc;
	if (queue_desc != NULL) {
		tm_queues[0] = queue_desc->tm_queues[priority];
		return 1;
	}

	num_children = node_desc->num_children;
	num_queues   = 0;

	for (child_idx = 0; child_idx < num_children; child_idx++) {
		child_node_desc = node_desc->children[child_idx];
		rem_queues  = max_queues - num_queues;
		num_queues += find_child_queues(tm_system_idx, child_node_desc,
						priority,
						&tm_queues[num_queues],
						rem_queues);
		if (num_queues == max_queues)
			break;
	}

	return num_queues;
}

static void
set_reqs_based_on_capas(odp_tm_requirements_t *req)
{
	odp_packet_color_t color;
	int j;

	/* Use tm capabilities identified based on egress capabilities
	 * to see what can be enabled.
	 */
	if (tm_capabilities.ecn_marking_supported)
		req->ecn_marking_needed = true;
	if (tm_capabilities.drop_prec_marking_supported)
		req->drop_prec_marking_needed = true;
	if (tm_capabilities.tm_queue_wred_supported)
		req->tm_queue_wred_needed = true;
	if (tm_capabilities.tm_queue_dual_slope_supported)
		req->tm_queue_dual_slope_needed = true;
	if (tm_capabilities.vlan_marking_supported)
		req->vlan_marking_needed = true;
	if (tm_capabilities.tm_queue_threshold.byte ||
	    tm_capabilities.tm_queue_threshold.packet ||
	    tm_capabilities.tm_queue_threshold.byte_and_packet)
		req->tm_queue_threshold_needed = true;

	for (j = 0; j < tm_capabilities.max_levels; j++) {
		if (tm_capabilities.per_level[j].tm_node_threshold.byte ||
		    tm_capabilities.per_level[j].tm_node_threshold.packet ||
		    tm_capabilities.per_level[j].tm_node_threshold.byte_and_packet)
			req->per_level[j].tm_node_threshold_needed = true;
	}

	/* Mark colors as needed if at least one of the marking
	 * feature is needed.
	 * */
	if (req->ecn_marking_needed || req->drop_prec_marking_needed) {
		for (color = 0; color < ODP_NUM_PACKET_COLORS; color++)
			req->marking_colors_needed[color] = true;
	}

	if (tm_capabilities.tm_queue_shaper_supported ||
	    tm_capabilities.tm_queue_rate_limiter_supported)
		req->tm_queue_shaper_needed = true;

	/* We can use any packet priority mode since it does not affect
	 * our tests. Our scheduler test tests scheduling only in a node
	 * directly connected to TM queues and such nodes see the original
	 * packet priority before it could have been overwritten by any node.
	 */
	req->pkt_prio_mode = ODP_TM_PKT_PRIO_MODE_PRESERVE;
	if (!tm_capabilities.pkt_prio_modes[ODP_TM_PKT_PRIO_MODE_PRESERVE])
		req->pkt_prio_mode = ODP_TM_PKT_PRIO_MODE_OVERWRITE;

}

static int create_tm_system(void)
{
	odp_tm_level_requirements_t *per_level;
	odp_tm_requirements_t        requirements;
	odp_tm_egress_t              egress;
	tm_node_desc_t              *root_node_desc;
	uint32_t                     level, max_nodes[ODP_TM_MAX_LEVELS];
	odp_tm_t                     odp_tm, found_odp_tm;
	char                         tm_name[ODP_TM_NAME_LEN];
	int                          rc;

	odp_tm_requirements_init(&requirements);
	odp_tm_egress_init(&egress);

	requirements.max_tm_queues              = NUM_TM_QUEUES;
	requirements.num_levels                 = NUM_LEVELS;

	set_reqs_based_on_capas(&requirements);

	/* Set the max_num_tm_nodes to be double the expected number of nodes
	 * at that level */
	memset(max_nodes, 0, sizeof(max_nodes));
	max_nodes[0] = 2 * NUM_LEVEL0_TM_NODES;
	max_nodes[1] = 2 * NUM_LEVEL1_TM_NODES;
	max_nodes[2] = 2 * NUM_LEVEL2_TM_NODES;
	max_nodes[3] = 2 * NUM_LEVEL2_TM_NODES * FANIN_RATIO;

	for (level = 0; level < NUM_LEVELS; level++) {
		per_level = &requirements.per_level[level];
		per_level->max_priority              = NUM_PRIORITIES - 1;
		per_level->max_num_tm_nodes          = max_nodes[level];
		per_level->max_fanin_per_node        = FANIN_RATIO;
		per_level->tm_node_shaper_needed     = true;
		per_level->tm_node_wred_needed       = false;
		per_level->tm_node_dual_slope_needed = false;
		per_level->fair_queuing_needed       = true;
		per_level->weights_needed            = true;
	}

	egress.egress_kind = ODP_TM_EGRESS_PKT_IO;
	egress.pktio      = xmt_pktio;

	snprintf(tm_name, sizeof(tm_name), "TM_system_%" PRIu32,
		 num_odp_tm_systems);
	odp_tm = odp_tm_create(tm_name, &requirements, &egress);
	CU_ASSERT_FATAL(odp_tm != ODP_TM_INVALID);


	odp_tm_systems[num_odp_tm_systems] = odp_tm;

	root_node_desc = create_tm_subtree(odp_tm, 0, NUM_LEVELS, 0, NULL);
	root_node_descs[num_odp_tm_systems] = root_node_desc;
	if (root_node_desc == NULL) {
		ODPH_ERR("create_tm_subtree() failed\n");
		return -1;
	}

	num_odp_tm_systems++;

	/* Test odp_tm_capability and odp_tm_find. */
	rc = odp_tm_capability(odp_tm, &tm_capabilities);
	if (rc != 0) {
		ODPH_ERR("odp_tm_capability() failed for tm: %" PRIx64 "\n",
			 odp_tm_to_u64(odp_tm));
		return -1;
	}

	/* Update dynamic capability flags from created tm system */
	dynamic_shaper_update = tm_capabilities.dynamic_shaper_update;
	dynamic_sched_update = tm_capabilities.dynamic_sched_update;
	dynamic_threshold_update = tm_capabilities.dynamic_threshold_update;
	dynamic_wred_update = tm_capabilities.dynamic_wred_update;

	found_odp_tm = odp_tm_find(tm_name, &requirements, &egress);
	if ((found_odp_tm == ODP_TM_INVALID) || (found_odp_tm != odp_tm)) {
		ODPH_ERR("odp_tm_find() failed\n");
		return -1;
	}

	/* Start TM system */
	CU_ASSERT((rc = odp_tm_start(odp_tm)) == 0);
	if (rc != 0) {
		ODPH_ERR("odp_tm_start() failed for tm: %" PRIx64 "\n",
			 odp_tm_to_u64(odp_tm));
		return -1;
	}

	return 0;
}

static void dump_tm_subtree(tm_node_desc_t *node_desc)
{
	odp_tm_node_info_t node_info;
	uint32_t           idx, num_queues, child_idx;
	int                rc;

	for (idx = 0; idx < node_desc->level; idx++)
		printf("  ");

	rc = odp_tm_node_info(node_desc->node, &node_info);
	if (rc != 0) {
		ODPH_ERR("odp_tm_node_info failed for tm_node=0x%" PRIX64 "\n",
			 odp_tm_node_to_u64(node_desc->node));
	}

	num_queues = 0;
	if (node_desc->queue_desc != NULL)
		num_queues = node_desc->queue_desc->num_queues;

	printf("node_desc=%p name='%s' tm_node=0x%" PRIX64 " idx=%" PRIu32 " "
	       "level=%" PRIu32" parent=0x%" PRIX64 " children=%" PRIu32 " "
	       "queues=%" PRIu32 " queue_fanin=%" PRIu32 " "
	       "node_fanin=%" PRIu32 "\n",
	       (void *)node_desc, node_desc->node_name,
	       odp_tm_node_to_u64(node_desc->node), node_desc->node_idx,
	       node_desc->level, odp_tm_node_to_u64(node_desc->parent_node),
	       node_desc->num_children, num_queues, node_info.tm_queue_fanin,
	       node_info.tm_node_fanin);

	for (child_idx = 0; child_idx < node_desc->num_children; child_idx++)
		dump_tm_subtree(node_desc->children[child_idx]);
}

static void dump_tm_tree(uint32_t tm_idx)
{
	tm_node_desc_t *root_node_desc;

	if (!TM_DEBUG)
		return;

	root_node_desc = root_node_descs[tm_idx];
	dump_tm_subtree(root_node_desc);
}

static int unconfig_tm_queue_profiles(odp_tm_queue_t tm_queue)
{
	odp_tm_queue_info_t queue_info;
	odp_tm_wred_t       wred_profile;
	uint32_t            color;
	int                 rc;

	rc = odp_tm_queue_info(tm_queue, &queue_info);
	if (rc != 0) {
		ODPH_ERR("odp_tm_queue_info failed code=%d\n", rc);
		return rc;
	}

	if (queue_info.shaper_profile != ODP_TM_INVALID) {
		rc = odp_tm_queue_shaper_config(tm_queue, ODP_TM_INVALID);
		if (rc != 0) {
			ODPH_ERR("odp_tm_queue_shaper_config failed code=%d\n",
				 rc);
			return rc;
		}
	}

	if (queue_info.threshold_profile != ODP_TM_INVALID) {
		rc = odp_tm_queue_threshold_config(tm_queue, ODP_TM_INVALID);
		if (rc != 0) {
			ODPH_ERR("odp_tm_queue_threshold_config failed "
				 "code=%d\n", rc);
			return rc;
		}
	}

	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
		wred_profile = queue_info.wred_profile[color];
		if (wred_profile != ODP_TM_INVALID) {
			rc = odp_tm_queue_wred_config(tm_queue, color,
						      ODP_TM_INVALID);
			if (rc != 0) {
				ODPH_ERR("odp_tm_queue_wred_config failed "
					 "color=%" PRIu32 " code=%d\n",
					color, rc);
				return rc;
			}
		}
	}

	return 0;
}

static int destroy_tm_queues(tm_queue_desc_t *queue_desc)
{
	odp_tm_queue_t tm_queue;
	uint32_t       num_queues, queue_idx;
	int            rc;

	num_queues = queue_desc->num_queues;
	for (queue_idx = 0; queue_idx < num_queues; queue_idx++) {
		tm_queue = queue_desc->tm_queues[queue_idx];
		if (tm_queue != ODP_TM_INVALID) {
			rc = odp_tm_queue_disconnect(tm_queue);
			if (rc != 0) {
				ODPH_ERR("odp_tm_queue_disconnect failed "
					 "idx=%" PRIu32 " code=%d\n",
					queue_idx, rc);
				return rc;
			}

			rc = unconfig_tm_queue_profiles(tm_queue);
			if (rc != 0) {
				ODPH_ERR("unconfig_tm_queue_profiles failed "
					 "idx=%" PRIu32 " code=%d\n",
					queue_idx, rc);
				return rc;
			}

			rc = odp_tm_queue_destroy(tm_queue);
			if (rc != 0) {
				ODPH_ERR("odp_tm_queue_destroy failed "
					 "idx=%" PRIu32 " code=%d\n",
					queue_idx, rc);
				return rc;
			}
		}
	}

	free(queue_desc);
	return 0;
}

static int unconfig_tm_node_profiles(odp_tm_node_t tm_node)
{
	odp_tm_node_info_t node_info;
	odp_tm_wred_t      wred_profile;
	uint32_t           color;
	int                rc;

	rc = odp_tm_node_info(tm_node, &node_info);
	if (rc != 0) {
		ODPH_ERR("odp_tm_node_info failed code=%d\n", rc);
		return rc;
	}

	if (node_info.shaper_profile != ODP_TM_INVALID) {
		rc = odp_tm_node_shaper_config(tm_node, ODP_TM_INVALID);
		if (rc != 0) {
			ODPH_ERR("odp_tm_node_shaper_config failed code=%d\n",
				 rc);
			return rc;
		}
	}

	if (node_info.threshold_profile != ODP_TM_INVALID) {
		rc = odp_tm_node_threshold_config(tm_node, ODP_TM_INVALID);
		if (rc != 0) {
			ODPH_ERR("odp_tm_node_threshold_config failed "
				 "code=%d\n", rc);
			return rc;
		}
	}

	for (color = 0; color < ODP_NUM_PACKET_COLORS; color++) {
		wred_profile = node_info.wred_profile[color];
		if (wred_profile != ODP_TM_INVALID) {
			rc = odp_tm_node_wred_config(tm_node, color,
						     ODP_TM_INVALID);
			if (rc != 0) {
				ODPH_ERR("odp_tm_node_wred_config failed "
					 "color=%" PRIu32 " code=%d\n",
					 color, rc);
				return rc;
			}
		}
	}

	return 0;
}

static int destroy_tm_subtree(tm_node_desc_t *node_desc)
{
	tm_queue_desc_t *queue_desc;
	tm_node_desc_t  *child_desc;
	odp_tm_node_t    tm_node;
	uint32_t         num_children, child_num;
	int              rc;

	num_children = node_desc->num_children;
	for (child_num = 0; child_num < num_children; child_num++) {
		child_desc = node_desc->children[child_num];
		if (child_desc != NULL) {
			rc = destroy_tm_subtree(child_desc);
			if (rc != 0) {
				ODPH_ERR("%s failed child_num=%" PRIu32 " "
					 "code=%d\n", __func__, child_num, rc);
				return rc;
			}
		}
	}

	queue_desc = node_desc->queue_desc;
	if (queue_desc != NULL) {
		rc = destroy_tm_queues(queue_desc);
		if (rc != 0) {
			ODPH_ERR("destroy_tm_queues failed code=%d\n", rc);
			return rc;
		}
	}

	tm_node = node_desc->node;
	rc = odp_tm_node_disconnect(tm_node);
	if (rc != 0) {
		ODPH_ERR("odp_tm_node_disconnect failed code=%d\n", rc);
		return rc;
	}

	rc = unconfig_tm_node_profiles(tm_node);
	if (rc != 0) {
		ODPH_ERR("unconfig_tm_node_profiles failed code=%d\n", rc);
		return rc;
	}

	rc = odp_tm_node_destroy(tm_node);
	if (rc != 0) {
		ODPH_ERR("odp_tm_node_destroy failed code=%d\n", rc);
		return rc;
	}

	if (node_desc->node_name)
		free(node_desc->node_name);

	free(node_desc);
	return 0;
}

static int destroy_all_shaper_profiles(void)
{
	odp_tm_shaper_t shaper_profile;
	uint32_t        idx;
	int             rc;

	for (idx = 0; idx < NUM_SHAPER_PROFILES; idx++) {
		shaper_profile = shaper_profiles[idx];
		if (shaper_profile != ODP_TM_INVALID) {
			rc = odp_tm_shaper_destroy(shaper_profile);
			if (rc != 0) {
				ODPH_ERR("odp_tm_sched_destroy failed "
					 "node=%" PRIx64 " idx=%" PRIu32
					 " code=%d\n",
					 odp_tm_shaper_to_u64(shaper_profile),
					 idx, rc);
				return rc;
			}
			shaper_profiles[idx] = ODP_TM_INVALID;
		}
	}

	return 0;
}

static int destroy_all_sched_profiles(void)
{
	odp_tm_sched_t sched_profile;
	uint32_t       idx;
	int            rc;

	for (idx = 0; idx < NUM_SCHED_PROFILES; idx++) {
		sched_profile = sched_profiles[idx];
		if (sched_profile != ODP_TM_INVALID) {
			rc = odp_tm_sched_destroy(sched_profile);
			if (rc != 0) {
				ODPH_ERR("odp_tm_sched_destroy failed "
					 "node=%" PRIx64 " idx=%" PRIu32
					 " code=%d\n",
					 odp_tm_sched_to_u64(sched_profile),
					 idx, rc);
				return rc;
			}
			sched_profiles[idx] = ODP_TM_INVALID;
		}
	}

	return 0;
}

static int destroy_all_threshold_profiles(void)
{
	odp_tm_threshold_t thr_profile;
	uint32_t           idx;
	int                rc;

	for (idx = 0; idx < NUM_THRESHOLD_PROFILES; idx++) {
		thr_profile = threshold_profiles[idx];
		if (thr_profile != ODP_TM_INVALID) {
			rc = odp_tm_threshold_destroy(thr_profile);
			if (rc != 0) {
				ODPH_ERR("odp_tm_threshold_destroy failed "
					 "node=%" PRIx64 " idx=%" PRIu32
					 " code=%d\n",
					 odp_tm_threshold_to_u64(thr_profile),
					 idx, rc);
				return rc;
			}
			threshold_profiles[idx] = ODP_TM_INVALID;
		}
	}

	return 0;
}

static int destroy_all_wred_profiles(void)
{
	odp_tm_wred_t wred_prof;
	uint32_t      idx, color;
	int           rc;

	for (idx = 0; idx < NUM_WRED_PROFILES; idx++) {
		for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
			wred_prof = wred_profiles[idx][color];
			if (wred_prof != ODP_TM_INVALID) {
				rc = odp_tm_wred_destroy(wred_prof);
				if (rc != 0) {
					ODPH_ERR("odp_tm_wred_destroy failed "
						 "node=%" PRIx64 " idx=%" PRIu32
						 " color=%" PRIu32 " code=%d\n",
						 odp_tm_wred_to_u64(wred_prof),
						 idx, color, rc);
					return rc;
				}
				wred_profiles[idx][color] = ODP_TM_INVALID;
			}
		}
	}

	return 0;
}

static int destroy_all_profiles(void)
{
	int rc;

	rc = destroy_all_shaper_profiles();
	if (rc != 0) {
		ODPH_ERR("destroy_all_shaper_profiles failed code=%d\n", rc);
		return rc;
	}

	rc = destroy_all_sched_profiles();
	if (rc != 0) {
		ODPH_ERR("destroy_all_sched_profiles failed code=%d\n", rc);
		return rc;
	}

	rc = destroy_all_threshold_profiles();
	if (rc != 0) {
		ODPH_ERR("destroy_all_threshold_profiles failed code=%d\n", rc);
		return rc;
	}

	rc = destroy_all_wred_profiles();
	if (rc != 0) {
		ODPH_ERR("destroy_all_wred_profiles failed code=%d\n", rc);
		return rc;
	}

	return 0;
}

static int destroy_tm_systems(void)
{
	uint32_t idx;

	/* Close/free the TM systems. */
	for (idx = 0; idx < num_odp_tm_systems; idx++) {
		if (odp_tm_stop(odp_tm_systems[idx]) != 0)
			return -1;

		if (destroy_tm_subtree(root_node_descs[idx]) != 0)
			return -1;

		if (odp_tm_destroy(odp_tm_systems[idx]) != 0)
			return -1;

		odp_tm_systems[idx] = ODP_TM_INVALID;
	}

	/* Close/free the TM profiles. */
	if (destroy_all_profiles() != 0)
		return -1;

	return 0;
}

static int traffic_mngr_suite_init(void)
{
	odp_tm_capabilities_t egress_capa;
	uint32_t payload_len, copy_len;
	odp_tm_egress_t egress;
	int j, ret;

	/* Initialize some global variables. */
	num_pkts_made   = 0;
	num_pkts_sent   = 0;
	num_rcv_pkts    = 0;
	cpu_unique_id   = 1;
	cpu_tcp_seq_num = DEFAULT_TCP_SEQ_NUM;
	memset(xmt_pkts, 0, sizeof(xmt_pkts));
	memset(rcv_pkts, 0, sizeof(rcv_pkts));

	payload_len = 0;
	while (payload_len < MAX_PAYLOAD) {
		copy_len = ODPH_MIN(MAX_PAYLOAD - payload_len, sizeof(ALPHABET));
		memcpy(&payload_data[payload_len], ALPHABET, copy_len);
		payload_len += copy_len;
	}

	/* Next open a single or pair of interfaces.  This should be the same
	 * logic as in the pktio_suite_init() function in the
	 * test/validation/pktio.c file. */
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

	pktios[0] = ODP_PKTIO_INVALID;
	pktios[1] = ODP_PKTIO_INVALID;

	ret = open_pktios();
	if (ret < 0)
		return -1;

	/* Positive return indicates, that pktio open failed with out mode as TM
	 * but succeeded with direct mode.
	 */
	if (ret > 0)
		goto skip_tests;

	odp_tm_egress_init(&egress);
	egress.egress_kind = ODP_TM_EGRESS_PKT_IO;
	egress.pktio = xmt_pktio;

	/* Get TM capabilities */
	ret = odp_tm_egress_capabilities(&egress_capa, &egress);
	if (ret) {
		ODPH_ERR("Failed to retrieve tm capabilities");
		return ret;
	}

	/* Check for sufficient TM queues */
	if (egress_capa.max_tm_queues < NUM_TM_QUEUES)
		goto skip_tests;

	/* Check for sufficient TM levels */
	if (egress_capa.max_levels < NUM_LEVELS)
		goto skip_tests;

	tm_shaper_min_rate = egress_capa.per_level[0].min_rate;
	tm_shaper_max_rate = egress_capa.per_level[0].max_rate;
	tm_shaper_min_burst = egress_capa.per_level[0].min_burst;
	tm_shaper_max_burst = egress_capa.per_level[0].max_burst;

	for (j = 0; j < NUM_LEVELS; j++) {
		odp_tm_level_capabilities_t *per_level =
			&egress_capa.per_level[j];

		/* Per node fanin */
		if (per_level->max_fanin_per_node < FANIN_RATIO)
			break;

		if (j == 0)
			continue;

		if (per_level->min_rate > tm_shaper_min_rate)
			tm_shaper_min_rate = per_level->min_rate;

		if (per_level->min_burst > tm_shaper_min_burst)
			tm_shaper_min_burst = per_level->min_burst;

		if (per_level->max_rate < tm_shaper_max_rate)
			tm_shaper_max_rate = per_level->max_rate;

		if (per_level->max_burst < tm_shaper_max_burst)
			tm_shaper_max_burst = per_level->max_burst;
	}

	if (tm_shaper_min_rate > tm_shaper_max_rate ||
	    tm_shaper_min_burst > tm_shaper_max_burst)
		goto skip_tests;

	if (j != NUM_LEVELS)
		goto skip_tests;

	if (egress_capa.pkt_prio_modes[ODP_TM_PKT_PRIO_MODE_PRESERVE] &&
	    egress_capa.max_schedulers_per_node < NUM_QUEUES_PER_NODE)
		goto skip_tests;

	if (!egress_capa.pkt_prio_modes[ODP_TM_PKT_PRIO_MODE_PRESERVE] &&
	    egress_capa.max_schedulers_per_node < 1)
		goto skip_tests;

	/* Init tm capabilities with matching egress capa until tm is created */
	tm_capabilities = egress_capa;

	if (!tm_capabilities.dynamic_shaper_update)
		dynamic_shaper_update = false;

	if (!tm_capabilities.dynamic_sched_update)
		dynamic_sched_update = false;

	if (!tm_capabilities.dynamic_threshold_update)
		dynamic_threshold_update = false;

	if (!tm_capabilities.dynamic_wred_update)
		dynamic_wred_update = false;

	return 0;
skip_tests:
	/* Mark all tests as inactive under this suite */
	odp_cunit_set_inactive();
	suite_inactive++;
	return 0;
}

static int traffic_mngr_suite_term(void)
{
	uint32_t iface;

	/* Close the pktios and associated packet pools. */
	free_rcvd_pkts();
	for (iface = 0; iface < num_ifaces; iface++) {
		/* Skip pktios not initialized */
		if (pktios[iface] != ODP_PKTIO_INVALID) {
			if (pktio_started[iface] &&
			    odp_pktio_stop(pktios[iface]) != 0)
				return -1;

			if (odp_pktio_close(pktios[iface]) != 0)
				return -1;
			pktios[iface] = ODP_PKTIO_INVALID;
			pktio_started[iface] = false;
		}

		if (odp_pool_destroy(pools[iface]) != 0)
			return -1;

		pools[iface] = ODP_POOL_INVALID;
	}

	if (odp_cunit_print_inactive())
		return -1;

	return 0;
}

static void check_shaper_profile(char *shaper_name, uint32_t shaper_idx)
{
	odp_tm_shaper_params_t shaper_params;
	odp_tm_shaper_t        profile;
	int		       rc;

	profile = odp_tm_shaper_lookup(shaper_name);
	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == shaper_profiles[shaper_idx - 1]);
	if (profile != shaper_profiles[shaper_idx - 1])
		return;

	memset(&shaper_params, 0, sizeof(shaper_params));
	rc = odp_tm_shaper_params_read(profile, &shaper_params);
	CU_ASSERT(rc == 0);
	CU_ASSERT(approx_eq64(shaper_params.commit_rate,
			      clamp_rate(shaper_idx * MIN_COMMIT_BW)));
	CU_ASSERT(approx_eq64(shaper_params.peak_rate,
			      clamp_rate(shaper_idx * MIN_PEAK_BW)));
	CU_ASSERT(approx_eq32(shaper_params.commit_burst,
			      clamp_burst(shaper_idx * MIN_COMMIT_BURST)));
	CU_ASSERT(approx_eq32(shaper_params.peak_burst,
			      clamp_burst(shaper_idx * MIN_PEAK_BURST)));

	CU_ASSERT(shaper_params.shaper_len_adjust == SHAPER_LEN_ADJ);
	CU_ASSERT(shaper_params.dual_rate         == true);
}

static void traffic_mngr_test_shaper_profile(void)
{
	odp_tm_shaper_params_t shaper_params;
	odp_tm_shaper_t        profile;
	uint32_t               idx, shaper_idx, i;
	char                   shaper_name[ODP_TM_NAME_LEN];

	odp_tm_shaper_params_init(&shaper_params);
	shaper_params.shaper_len_adjust = SHAPER_LEN_ADJ;
	shaper_params.dual_rate         = true;

	for (idx = 1; idx <= NUM_SHAPER_TEST_PROFILES; idx++) {
		snprintf(shaper_name, sizeof(shaper_name),
			 "shaper_profile_%" PRIu32, idx);
		shaper_params.commit_rate  = clamp_rate(idx * MIN_COMMIT_BW);
		shaper_params.peak_rate    = clamp_rate(idx * MIN_PEAK_BW);
		shaper_params.commit_burst = clamp_burst(idx * MIN_COMMIT_BURST);
		shaper_params.peak_burst   = clamp_burst(idx * MIN_PEAK_BURST);

		profile = odp_tm_shaper_create(shaper_name, &shaper_params);
		CU_ASSERT_FATAL(profile != ODP_TM_INVALID);

		/* Make sure profile handle is unique */
		for (i = 1; i < idx - 1; i++)
			CU_ASSERT(profile != shaper_profiles[i - 1]);

		shaper_profiles[idx - 1] = profile;
		num_shaper_profiles++;
	}

	/* Now test odp_tm_shaper_lookup */
	for (idx = 1; idx <= NUM_SHAPER_TEST_PROFILES; idx++) {
		/* The following equation is designed is somewhat randomize
		 * the lookup of the profiles to catch any implementations
		 *taking shortcuts. */
		shaper_idx = ((3 + 7 * idx) % NUM_SHAPER_TEST_PROFILES) + 1;
		snprintf(shaper_name, sizeof(shaper_name),
			 "shaper_profile_%" PRIu32, shaper_idx);

		check_shaper_profile(shaper_name, shaper_idx);
	}
}

static void check_sched_profile(char *sched_name, uint32_t sched_idx)
{
	odp_tm_sched_params_t sched_params;
	odp_tm_sched_t        profile;
	uint32_t              priority;

	profile = odp_tm_sched_lookup(sched_name);
	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == sched_profiles[sched_idx - 1]);
	if (profile != sched_profiles[sched_idx - 1])
		return;

	odp_tm_sched_params_read(profile, &sched_params);
	for (priority = 0; priority < NUM_PRIORITIES; priority++) {
		CU_ASSERT(sched_params.sched_modes[priority] ==
			  ODP_TM_BYTE_BASED_WEIGHTS);
		CU_ASSERT(approx_eq32(sched_params.sched_weights[priority],
				      8 + sched_idx + priority));
	}
}

static void traffic_mngr_test_sched_profile(void)
{
	odp_tm_sched_params_t sched_params;
	odp_tm_sched_t        profile;
	uint32_t              idx, priority, sched_idx, i;
	char                  sched_name[ODP_TM_NAME_LEN];

	odp_tm_sched_params_init(&sched_params);

	for (idx = 1; idx <= NUM_SCHED_TEST_PROFILES; idx++) {
		snprintf(sched_name, sizeof(sched_name),
			 "sched_profile_%" PRIu32, idx);
		for (priority = 0; priority < ODP_TM_MAX_PRIORITIES; priority++) {
			sched_params.sched_modes[priority] =
				ODP_TM_BYTE_BASED_WEIGHTS;
			sched_params.sched_weights[priority] = 8 + idx +
							       priority;
		}

		profile = odp_tm_sched_create(sched_name, &sched_params);
		CU_ASSERT_FATAL(profile != ODP_TM_INVALID);

		/* Make sure profile handle is unique */
		for (i = 1; i < idx - 1; i++)
			CU_ASSERT(profile != sched_profiles[i - 1]);

		sched_profiles[idx - 1] = profile;
		num_sched_profiles++;
	}

	/* Now test odp_tm_sched_lookup */
	for (idx = 1; idx <= NUM_SCHED_TEST_PROFILES; idx++) {
		/* The following equation is designed is somewhat randomize
		 * the lookup of the profiles to catch any implementations
		 * taking shortcuts. */
		sched_idx = ((3 + 7 * idx) % NUM_SCHED_TEST_PROFILES) + 1;
		snprintf(sched_name, sizeof(sched_name),
			 "sched_profile_%" PRIu32, sched_idx);
		check_sched_profile(sched_name, sched_idx);
	}
}

static void check_threshold_profile(char    *threshold_name,
				    uint32_t threshold_idx,
				    threshold_type_t threshold)
{
	odp_tm_threshold_params_t threshold_params;
	odp_tm_threshold_t        profile;
	int ret;

	profile = odp_tm_thresholds_lookup(threshold_name);
	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == threshold_profiles[threshold_idx - 1]);

	if (profile == threshold_profiles[threshold_idx - 1])
		return;

	ret = odp_tm_thresholds_params_read(profile, &threshold_params);
	CU_ASSERT(ret == 0);

	if (ret)
		return;

	if (threshold == THRESHOLD_PACKET || threshold == THRESHOLD_BYTE_AND_PACKET) {
		CU_ASSERT(threshold_params.enable_max_pkts  == 1);
		CU_ASSERT(threshold_params.max_pkts  == threshold_idx * MIN_PKT_THRESHOLD);
	}
	if (threshold == THRESHOLD_BYTE || threshold == THRESHOLD_BYTE_AND_PACKET) {
		CU_ASSERT(threshold_params.enable_max_bytes == 1);
		CU_ASSERT(threshold_params.max_bytes == threshold_idx * MIN_BYTE_THRESHOLD);
	}
}

static void traffic_mngr_test_threshold_profile(threshold_type_t threshold)
{
	odp_tm_threshold_params_t threshold_params;
	odp_tm_threshold_t        profile;
	uint32_t                  idx, threshold_idx, i;
	char                      threshold_name[ODP_TM_NAME_LEN];

	odp_tm_threshold_params_init(&threshold_params);

	if (threshold == THRESHOLD_PACKET || threshold == THRESHOLD_BYTE_AND_PACKET)
		threshold_params.enable_max_pkts  = 1;
	if (threshold == THRESHOLD_BYTE || threshold == THRESHOLD_BYTE_AND_PACKET)
		threshold_params.enable_max_bytes = 1;

	for (idx = 1; idx <= NUM_THRESH_TEST_PROFILES; idx++) {
		snprintf(threshold_name, sizeof(threshold_name),
			 "threshold_profile_%" PRIu32, idx);
		if (threshold == THRESHOLD_PACKET || threshold == THRESHOLD_BYTE_AND_PACKET)
			threshold_params.max_pkts = idx * MIN_PKT_THRESHOLD;
		if (threshold == THRESHOLD_BYTE || threshold == THRESHOLD_BYTE_AND_PACKET)
			threshold_params.max_bytes = idx * MIN_BYTE_THRESHOLD;

		profile = odp_tm_threshold_create(threshold_name,
						  &threshold_params);
		CU_ASSERT_FATAL(profile != ODP_TM_INVALID);

		/* Make sure profile handle is unique */
		for (i = 1; i < idx - 1; i++)
			CU_ASSERT(profile != threshold_profiles[i - 1]);

		threshold_profiles[idx - 1] = profile;
		num_threshold_profiles++;
	}

	/* Now test odp_tm_threshold_lookup */
	for (idx = 1; idx <= NUM_THRESH_TEST_PROFILES; idx++) {
		/* The following equation is designed is somewhat randomize
		 * the lookup of the profiles to catch any implementations
		 * taking shortcuts. */
		threshold_idx = ((3 + 7 * idx) % NUM_THRESH_TEST_PROFILES) + 1;
		snprintf(threshold_name, sizeof(threshold_name),
			 "threshold_profile_%" PRIu32, threshold_idx);
		check_threshold_profile(threshold_name, threshold_idx, threshold);
	}

	for (i = 0; i < NUM_THRESH_TEST_PROFILES; i++) {
		CU_ASSERT(odp_tm_threshold_destroy(threshold_profiles[i]) == 0);
		num_threshold_profiles--;
	}
}

static void traffic_mngr_test_threshold_profile_byte(void)
{
	traffic_mngr_test_threshold_profile(THRESHOLD_BYTE);
}

static void traffic_mngr_test_threshold_profile_packet(void)
{
	traffic_mngr_test_threshold_profile(THRESHOLD_PACKET);
}

static void traffic_mngr_test_threshold_profile_byte_and_packet(void)
{
	traffic_mngr_test_threshold_profile(THRESHOLD_BYTE_AND_PACKET);
}

static void check_wred_profile(char    *wred_name,
			       uint32_t wred_idx,
			       uint32_t color)
{
	odp_tm_wred_params_t wred_params;
	odp_tm_wred_t        profile;
	int ret;

	profile = odp_tm_wred_lookup(wred_name);
	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == wred_profiles[wred_idx - 1][color]);
	if (profile != wred_profiles[wred_idx - 1][color])
		return;

	ret = odp_tm_wred_params_read(profile, &wred_params);
	CU_ASSERT(ret == 0);

	if (ret)
		return;

	CU_ASSERT(wred_params.min_threshold == wred_idx * MIN_WRED_THRESH);
	CU_ASSERT(wred_params.med_threshold == wred_idx * MED_WRED_THRESH);
	CU_ASSERT(wred_params.med_drop_prob == wred_idx * MED_DROP_PROB);
	CU_ASSERT(wred_params.max_drop_prob == wred_idx * MAX_DROP_PROB);

	CU_ASSERT(wred_params.enable_wred       == 1);
	CU_ASSERT(wred_params.use_byte_fullness == 0);
}

static void traffic_mngr_test_wred_profile(void)
{
	odp_tm_wred_params_t wred_params;
	odp_tm_wred_t        profile;
	uint32_t             idx, color, wred_idx, i, c;
	char                 wred_name[ODP_TM_NAME_LEN];

	odp_tm_wred_params_init(&wred_params);
	wred_params.enable_wred       = 1;
	wred_params.use_byte_fullness = 0;

	for (idx = 1; idx <= NUM_WRED_TEST_PROFILES; idx++) {
		for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
			snprintf(wred_name, sizeof(wred_name),
				 "wred_profile_%" PRIu32 "_%" PRIu32,
				 idx, color);
			wred_params.min_threshold = idx * MIN_WRED_THRESH;
			wred_params.med_threshold = idx * MED_WRED_THRESH;
			wred_params.med_drop_prob = idx * MED_DROP_PROB;
			wred_params.max_drop_prob = idx * MAX_DROP_PROB;

			profile = odp_tm_wred_create(wred_name, &wred_params);
			CU_ASSERT_FATAL(profile != ODP_TM_INVALID);

			/* Make sure profile handle is unique */
			for (i = 1; i < idx - 1; i++)
				for (c = 0; c < ODP_NUM_PKT_COLORS; c++)
					CU_ASSERT(profile !=
						  wred_profiles[i - 1][c]);

			wred_profiles[idx - 1][color] = profile;
		}

		num_wred_profiles++;
	}

	/* Now test odp_tm_wred_lookup */
	for (idx = 1; idx <= NUM_WRED_TEST_PROFILES; idx++) {
		/* The following equation is designed is somewhat randomize
		 * the lookup of the profiles to catch any implementations
		 * taking shortcuts. */
		wred_idx = ((3 + 7 * idx) % NUM_WRED_TEST_PROFILES) + 1;

		for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
			snprintf(wred_name, sizeof(wred_name),
				 "wred_profile_%" PRIu32 "_%" PRIu32,
				 wred_idx, color);
			check_wred_profile(wred_name, wred_idx, color);
		}
	}
}

static int set_shaper(const char    *node_name,
		      const char    *shaper_name,
		      uint64_t      commit_bps,
		      uint64_t      commit_burst_in_bits)
{
	odp_tm_shaper_params_t shaper_params;
	odp_tm_shaper_t        shaper_profile;
	odp_tm_node_t          tm_node;
	int rc;

	commit_bps = clamp_rate(commit_bps);
	commit_burst_in_bits = clamp_burst(commit_burst_in_bits);

	tm_node = find_tm_node(0, node_name);
	if (tm_node == ODP_TM_INVALID) {
		ODPH_ERR("find_tm_node(%s) failed\n", node_name);
		CU_ASSERT_FATAL(tm_node != ODP_TM_INVALID);
		return -1;
	}

	odp_tm_shaper_params_init(&shaper_params);
	shaper_params.commit_rate       = commit_bps;
	shaper_params.peak_rate         = 0;
	shaper_params.commit_burst      = commit_burst_in_bits;
	shaper_params.peak_burst        = 0;
	shaper_params.shaper_len_adjust = 0;
	shaper_params.dual_rate         = 0;

	if (!dynamic_shaper_update) {
		/* Stop TM system before update when dynamic update is not
		 * supported.
		 */
		CU_ASSERT_FATAL(odp_tm_stop(odp_tm_systems[0]) == 0);
	}

	if (!shaper_name) {
		shaper_profile = ODP_TM_INVALID;
		goto skip_profile;
	}

	/* First see if a shaper profile already exists with this name, in
	 * which case we use that profile, else create a new one. */
	shaper_profile = odp_tm_shaper_lookup(shaper_name);
	if (shaper_profile != ODP_TM_INVALID) {
		odp_tm_shaper_params_update(shaper_profile, &shaper_params);
	} else {
		shaper_profile = odp_tm_shaper_create(shaper_name,
						      &shaper_params);
		shaper_profiles[num_shaper_profiles] = shaper_profile;
		num_shaper_profiles++;
	}

skip_profile:
	rc = odp_tm_node_shaper_config(tm_node, shaper_profile);

	if (!dynamic_shaper_update) {
		/* Start TM system, post update */
		CU_ASSERT_FATAL(odp_tm_start(odp_tm_systems[0]) == 0);
	}
	return rc;
}

static int traffic_mngr_check_shaper(void)
{
	odp_cpumask_t cpumask;
	int cpucount = odp_cpumask_all_available(&cpumask);

/* Skip the shaper test on arm64 systems */
#if defined(__aarch64__)
	printf("\nTemporarily skip shaper test which intermittently "
	       "fails on arm64 systems. Will be activated when issue "
	       "is resolved\n");
	return ODP_TEST_INACTIVE;
#endif

	if (cpucount < 2) {
		ODPH_DBG("\nSkipping shaper test because cpucount = %d "
			 "is less then min number 2 required\n", cpucount);
		ODPH_DBG("Rerun with more cpu resources\n");
		return ODP_TEST_INACTIVE;
	}

	/* This test needs 1 Mbps, 4 Mbps, 10 Mpbs, 40 Mbps, 100 Mbps */
	if ((tm_shaper_min_rate > 100 * MBPS) || (tm_shaper_max_rate < 1 * MBPS))
		return ODP_TEST_INACTIVE;

	/* All the subtests run with burst of 10000 bits */
	if ((tm_shaper_min_burst > 10000) || tm_shaper_max_burst < 10000)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int traffic_mngr_check_scheduler(void)
{
	odp_cpumask_t cpumask;
	int cpucount = odp_cpumask_all_available(&cpumask);

	if (cpucount < 2) {
		ODPH_DBG("\nSkipping scheduler test because cpucount = %d "
			 "is less then min number 2 required\n", cpucount);
		ODPH_DBG("Rerun with more cpu resources\n");
		return ODP_TEST_INACTIVE;
	}

	/* Scheduler test test_sched_queue_priority() depends on rate of
	 * 64 Kbps and burst of 5600.
	 */
	if ((tm_shaper_min_rate > 64 * 1000) ||
	    (tm_shaper_max_rate < 64 * 1000) ||
	    (tm_shaper_min_burst > 5600) ||
	    (tm_shaper_max_burst < 5600))
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int test_shaper_bw(const char *shaper_name,
			  const char *node_name,
			  uint8_t     priority,
			  uint64_t    commit_bps)
{
	odp_tm_queue_t tm_queue;
	rcv_stats_t    rcv_stats;
	pkt_info_t     pkt_info;
	uint64_t       expected_rcv_gap_us;
	uint32_t       num_pkts, pkt_len, pkts_rcvd_in_order, avg_rcv_gap;
	uint32_t       min_rcv_gap, max_rcv_gap, pkts_sent;
	int            rc, ret_code;

	/* This test can support a commit_bps from 64K to 2 Gbps and possibly
	 * up to a max of 10 Gbps, but no higher. */
	CU_ASSERT_FATAL(commit_bps <= (10ULL * 1000000000ULL));

	/* Pick a tm_queue and set the parent node's shaper BW to be commit_bps
	 * with a small burst tolerance.  Then send the traffic with a pkt_len
	 * such that the pkt start time to next pkt start time is 10,000 bit
	* times and then measure the average inter-arrival receive "gap" in
	 * microseconds. */
	tm_queue = find_tm_queue(0, node_name, priority);
	if (set_shaper(node_name, shaper_name, commit_bps, 10000) != 0)
		return -1;

	init_xmt_pkts(&pkt_info);
	num_pkts           = 50;
	pkt_len            = (10000 / 8) - (ETHERNET_OVHD_LEN + CRC_LEN);
	pkt_info.pkt_class = 1;
	if (make_pkts(num_pkts, pkt_len, &pkt_info) != 0)
		return -1;

	pkts_sent = send_pkts(tm_queue, num_pkts);

	/* The expected inter arrival receive gap in seconds is equal to
	 * "10,000 bits / commit_bps".  To get the gap time in microseconds
	 * we multiply this by one million.  The timeout we use is 50 times
	 * this gap time (since we send 50 pkts) multiplied by 4 to be
	 * conservative, plus a constant time of 1 millisecond to account for
	 * testing delays.  This then needs to be expressed in nanoseconds by
	 * multiplying by 1000. */
	expected_rcv_gap_us = (1000000ULL * 10000ULL) / commit_bps;
	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin, pkts_sent,
				    commit_bps);
	pkts_rcvd_in_order = pkts_rcvd_in_send_order();
	ret_code = -1;

	/* First verify that MOST of the pkts were received in any order. */
	if (num_rcv_pkts <= (pkts_sent / 2)) {
		/* This is fairly major failure in that most of the pkts didn't
		 * even get received, regardless of rate or order. Log the error
		 * to assist with debugging */
		ODPH_ERR("Sent %" PRIu32 " pkts but only %" PRIu32 " "
			 "came back\n", pkts_sent, num_rcv_pkts);
		CU_ASSERT(num_rcv_pkts <= (pkts_sent / 2));
	} else if (pkts_rcvd_in_order <= 32) {
		ODPH_ERR("Sent %" PRIu32 " pkts but only %" PRIu32 " "
			 "came back (%" PRIu32 " in order)\n",
			 pkts_sent, num_rcv_pkts, pkts_rcvd_in_order);
		CU_ASSERT(pkts_rcvd_in_order <= 32);
	} else {
		if (pkts_rcvd_in_order < pkts_sent)
			ODPH_DBG("Info: of %" PRIu32 " pkts sent %" PRIu32 " "
				 "came back (%" PRIu32 " in order)\n",
				 pkts_sent, num_rcv_pkts, pkts_rcvd_in_order);

		/* Next determine the inter arrival receive pkt statistics. */
		rc = rcv_rate_stats(&rcv_stats, pkt_info.pkt_class);
		CU_ASSERT(rc == 0);

		/* Next verify that the rcvd pkts have an average inter-receive
		 * gap of "expected_rcv_gap_us" microseconds, +/- 25%. */
		avg_rcv_gap = rcv_stats.avg_rcv_gap;
		min_rcv_gap = ((MIN_SHAPER_BW_RCV_GAP * expected_rcv_gap_us) /
					100) - 2;
		max_rcv_gap = ((MAX_SHAPER_BW_RCV_GAP * expected_rcv_gap_us) /
					100) + 2;
		if ((avg_rcv_gap < min_rcv_gap) ||
		    (max_rcv_gap < avg_rcv_gap)) {
			ODPH_ERR("min=%" PRIu32 " avg_rcv_gap=%" PRIu32 " "
				 "max=%" PRIu32 " std_dev_gap=%" PRIu32 "\n",
				 rcv_stats.min_rcv_gap, avg_rcv_gap,
				 rcv_stats.max_rcv_gap, rcv_stats.std_dev_gap);
			ODPH_ERR("  expected_rcv_gap=%" PRIu64 " acceptable "
				 "rcv_gap range=%" PRIu32 "..%" PRIu32 "\n",
				 expected_rcv_gap_us, min_rcv_gap, max_rcv_gap);
			ODPH_ERR("agv_rcv_gap=%" PRIu32 " acceptable "
				 "rcv_gap range=%" PRIu32 "..%" PRIu32 "\n",
				 avg_rcv_gap, min_rcv_gap, max_rcv_gap);
			ret_code = -1;
		} else if (expected_rcv_gap_us < rcv_stats.std_dev_gap) {
			ODPH_ERR("min=%" PRIu32 " avg_rcv_gap=%" PRIu32 " "
				 "max=%" PRIu32 " std_dev_gap=%" PRIu32 "\n",
				 rcv_stats.min_rcv_gap, avg_rcv_gap,
				 rcv_stats.max_rcv_gap, rcv_stats.std_dev_gap);
			ODPH_ERR("  expected_rcv_gap=%" PRIu64 " acceptable "
				 "rcv_gap range=%" PRIu32 "..%" PRIu32 "\n",
				 expected_rcv_gap_us, min_rcv_gap, max_rcv_gap);
			ODPH_ERR("std_dev_gap=%" PRIu32 " >  "
				 "expected_rcv_gap_us=%" PRIu64 "\n",
				 rcv_stats.std_dev_gap, expected_rcv_gap_us);
			ret_code = -1;
		} else {
			ret_code = 0;
		}
	}

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, NULL, 0, 0);
	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
	return ret_code;
}

static int set_sched_fanin(const char         *node_name,
			   const char         *sched_base_name,
			   odp_tm_sched_mode_t sched_mode,
			   uint8_t             sched_weights[FANIN_RATIO])
{
	odp_tm_sched_params_t sched_params;
	odp_tm_sched_t        sched_profile;
	tm_node_desc_t       *node_desc, *child_desc;
	odp_tm_node_t         tm_node, fanin_node;
	uint32_t              fanin_cnt, fanin, priority;
	uint8_t               sched_weight;
	char                  sched_name[ODP_TM_NAME_LEN];
	int                   rc;

	node_desc = find_node_desc(0, node_name);
	if (node_desc == NULL)
		return -1;

	if (!dynamic_sched_update) {
		/* Stop TM system before update when dynamic update is not
		 * supported.
		 */
		CU_ASSERT_FATAL(odp_tm_stop(odp_tm_systems[0]) == 0);
	}

	fanin_cnt = ODPH_MIN(node_desc->num_children, FANIN_RATIO);
	for (fanin = 0; fanin < fanin_cnt; fanin++) {
		odp_tm_sched_params_init(&sched_params);
		sched_weight = sched_weights[fanin];

		/* Set the weights and mode the same for all priorities */
		for (priority = 0; priority < NUM_PRIORITIES; priority++) {
			sched_params.sched_modes[priority]   = sched_mode;
			sched_params.sched_weights[priority] = sched_weight;
		}

		/* Create the scheduler profile name using the sched_base_name
		 * and the fanin index */
		snprintf(sched_name, sizeof(sched_name), "%s_%" PRIu32,
			 sched_base_name, fanin);

		/* First see if a sched profile already exists with this name,
		 * in which case we use that profile, else create a new one. */
		sched_profile = odp_tm_sched_lookup(sched_name);
		if (sched_profile != ODP_TM_INVALID) {
			odp_tm_sched_params_update(sched_profile,
						   &sched_params);
		} else {
			sched_profile = odp_tm_sched_create(sched_name,
							    &sched_params);
			sched_profiles[num_sched_profiles] = sched_profile;
			num_sched_profiles++;
		}

		/* Apply the weights to the nodes fan-in. */
		child_desc = node_desc->children[fanin];
		tm_node    = node_desc->node;
		fanin_node = child_desc->node;
		rc = odp_tm_node_sched_config(tm_node, fanin_node,
					      sched_profile);
		if (rc != 0)
			goto exit;
	}

exit:
	if (!dynamic_sched_update) {
		/* Start TM system, post update */
		CU_ASSERT_FATAL(odp_tm_start(odp_tm_systems[0]) == 0);
	}
	return rc;
}

static int test_sched_queue_priority(const char *shaper_name,
				     const char *node_name,
				     uint32_t    num_pkts)
{
	odp_tm_queue_t tm_queues[NUM_PRIORITIES];
	pkt_info_t     pkt_info;
	uint32_t       pkt_cnt, pkts_in_order, base_idx;
	uint32_t       idx, unique_id, pkt_len, base_pkt_len, pkts_sent;
	int            priority;

	memset(unique_id_list, 0, sizeof(unique_id_list));
	for (priority = 0; priority < NUM_PRIORITIES; priority++)
		tm_queues[priority] = find_tm_queue(0, node_name, priority);

	/* Enable the shaper to be low bandwidth. */
	pkt_len = 1400;
	set_shaper(node_name, shaper_name, 64 * 1000, 4 * pkt_len);

	/* Make a couple of low priority dummy pkts first. */
	init_xmt_pkts(&pkt_info);
	if (make_pkts(4, pkt_len, &pkt_info) != 0)
		return -1;

	/* Now make "num_pkts" first at the lowest priority, then "num_pkts"
	 * at the second lowest priority, etc until "num_pkts" are made last
	 * at the highest priority (which is always priority 0). */
	pkt_cnt      = NUM_PRIORITIES * num_pkts;
	base_pkt_len = 256;
	for (priority = NUM_PRIORITIES - 1; 0 <= priority; priority--) {
		unique_id          = cpu_unique_id;
		pkt_info.pkt_class = priority + 1;
		pkt_len            = base_pkt_len + 64 * priority;
		if (make_pkts(num_pkts, pkt_len, &pkt_info) != 0)
			return -1;

		base_idx = priority * num_pkts;
		for (idx = 0; idx < num_pkts; idx++)
			unique_id_list[base_idx + idx] = unique_id++;
	}

	/* Send the low priority dummy pkts first.  The arrival order of
	 * these pkts will be ignored. */
	pkts_sent = send_pkts_multi(tm_queues[NUM_PRIORITIES - 1], 4);

	/* Now send "num_pkts" first at the lowest priority, then "num_pkts"
	 * at the second lowest priority, etc until "num_pkts" are sent last
	 * at the highest priority. */
	for (priority = NUM_PRIORITIES - 1; 0 <= priority; priority--)
		pkts_sent += send_pkts_multi(tm_queues[priority], num_pkts);

	busy_wait(100 * ODP_TIME_MSEC_IN_NS);

	/* Disable the shaper, so as to get the pkts out quicker.
	 * We cannot do this if dynamic shaper update is not supported. Without
	 * dynamic update support set_shaper() can cause packet drops due to
	 * start/stop.
	 */
	if (dynamic_shaper_update)
		set_shaper(node_name, NULL, 0, 0);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin,
				    pkt_cnt + 4, 64 * 1000);

	/* Check rcvd packet arrivals to make sure that pkts arrived in
	 * priority order, except for perhaps the first few lowest priority
	 * dummy pkts. */
	pkts_in_order = pkts_rcvd_in_given_order(unique_id_list, pkt_cnt, 0,
						 false, false);
	if (pkts_in_order != pkt_cnt) {
		ODPH_ERR("pkts_sent=%" PRIu32 " pkt_cnt=%" PRIu32 " "
			 "num_rcv_pkts=%" PRIu32 " rcvd_in_order=%" PRIu32 "\n",
			 pkts_sent, pkt_cnt, num_rcv_pkts, pkts_in_order);
	}

	CU_ASSERT(pkts_in_order == pkt_cnt);

	/* Disable shaper in case it is still enabled */
	set_shaper(node_name, NULL, 0, 0);
	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
	return 0;
}

static int test_sched_node_priority(const char *shaper_name,
				    const char *node_name,
				    uint32_t    num_pkts)
{
	odp_tm_queue_t *tm_queues, tm_queue;
	tm_node_desc_t *node_desc;
	queue_array_t  *queue_array;
	pkt_info_t      pkt_info;
	uint32_t        total_num_queues, max_queues, num_queues, pkt_cnt;
	uint32_t        pkts_in_order, base_idx, queue_idx, idx, unique_id;
	uint32_t        pkt_len, base_pkt_len, total_pkt_cnt, pkts_sent;
	int             priority;

	memset(unique_id_list, 0, sizeof(unique_id_list));
	node_desc = find_node_desc(0, node_name);
	if (node_desc == NULL)
		return -1;

	total_num_queues = 0;
	for (priority = 0; priority < NUM_PRIORITIES; priority++) {
		max_queues  = NUM_LEVEL2_TM_NODES;
		queue_array = &queues_set.queue_array[priority];
		tm_queues   = queue_array->tm_queues;
		num_queues  = find_child_queues(0, node_desc, priority,
						tm_queues, max_queues);
		queue_array->num_queues = num_queues;
		queue_array->priority   = priority;
		total_num_queues       += num_queues;
	}

	/* Enable the shaper to be low bandwidth. */
	pkt_len = 1400;
	set_shaper(node_name, shaper_name, 64 * 1000, 4 * pkt_len);

	/* Make a couple of low priority large dummy pkts first. */
	init_xmt_pkts(&pkt_info);
	if (make_pkts(4, pkt_len, &pkt_info) != 0)
		return -1;

	/* Now make "num_pkts" for each tm_queue at the lowest priority, then
	 * "num_pkts" for each tm_queue at the second lowest priority, etc.
	 * until "num_pkts" for each tm_queue at the highest priority are made
	 * last.  Note that the highest priority is always priority 0. */
	total_pkt_cnt  = total_num_queues * num_pkts;
	base_pkt_len   = 256;
	base_idx       = 0;
	for (priority = NUM_PRIORITIES - 1; 0 <= priority; priority--) {
		unique_id          = cpu_unique_id;
		queue_array        = &queues_set.queue_array[priority];
		num_queues         = queue_array->num_queues;
		pkt_cnt            = num_queues * num_pkts;
		pkt_info.pkt_class = priority + 1;
		pkt_len            = base_pkt_len + 64 * priority;
		if (make_pkts(pkt_cnt, pkt_len, &pkt_info) != 0)
			return -1;

		base_idx = priority * num_pkts;
		for (idx = 0; idx < pkt_cnt; idx++)
			unique_id_list[base_idx + idx] = unique_id++;
	}

	/* Send the low priority dummy pkts first.  The arrival order of
	 * these pkts will be ignored. */
	queue_array = &queues_set.queue_array[NUM_PRIORITIES - 1];
	tm_queue    = queue_array->tm_queues[0];
	pkts_sent   = send_pkts(tm_queue, 4);

	/* Now send "num_pkts" for each tm_queue at the lowest priority, then
	 * "num_pkts" for each tm_queue at the second lowest priority, etc.
	 * until "num_pkts" for each tm_queue at the highest priority are sent
	 * last. */
	for (priority = NUM_PRIORITIES - 1; 0 <= priority; priority--) {
		queue_array = &queues_set.queue_array[priority];
		num_queues  = queue_array->num_queues;
		for (queue_idx = 0; queue_idx < num_queues; queue_idx++) {
			tm_queue   = queue_array->tm_queues[queue_idx];
			pkts_sent += send_pkts(tm_queue, num_pkts);
		}
	}

	busy_wait(100 * ODP_TIME_MSEC_IN_NS);

	/* Disable the shaper, so as to get the pkts out quicker.
	 * We cannot do this if dynamic shaper update is not supported. Without
	 * dynamic update support set_shaper() can cause packet drops due to
	 * start/stop.
	 */
	if (dynamic_shaper_update)
		set_shaper(node_name, NULL, 0, 0);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin,
				    pkts_sent, 64 * 1000);

	/* Check rcvd packet arrivals to make sure that pkts arrived in
	 * priority order, except for perhaps the first few lowest priority
	 * dummy pkts. */
	pkts_in_order = pkts_rcvd_in_given_order(unique_id_list, total_pkt_cnt,
						 0, false, false);
	CU_ASSERT(pkts_in_order == total_pkt_cnt);

	/* Disable shaper in case it is still enabled */
	set_shaper(node_name, NULL, 0, 0);
	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
	return 0;
}

static int test_sched_wfq(const char         *sched_base_name,
			  const char         *shaper_name,
			  const char         *node_name,
			  odp_tm_sched_mode_t sched_mode,
			  uint8_t             sched_weights[FANIN_RATIO])
{
	odp_tm_queue_t  tm_queues[FANIN_RATIO], tm_queue;
	tm_node_desc_t *node_desc, *child_desc;
	rcv_stats_t     rcv_stats[FANIN_RATIO];
	pkt_info_t      pkt_info;
	uint32_t        fanin_cnt, fanin, num_queues, pkt_cnt;
	uint32_t        pkt_len, pkts_sent, pkt_idx;
	uint8_t         pkt_class;
	int             priority, rc;

	memset(tm_queues, 0, sizeof(tm_queues));
	node_desc = find_node_desc(0, node_name);
	if (node_desc == NULL)
		return -1;

	rc = set_sched_fanin(node_name, sched_base_name, sched_mode,
			     sched_weights);
	if (rc != 0)
		return -1;

	/* Now determine at least one tm_queue that feeds into each fanin/
	 * child node. */
	priority  = 0;
	fanin_cnt = ODPH_MIN(node_desc->num_children, FANIN_RATIO);
	for (fanin = 0; fanin < fanin_cnt; fanin++) {
		child_desc = node_desc->children[fanin];
		num_queues = find_child_queues(0, child_desc, priority,
					       &tm_queues[fanin], 1);
		if (num_queues != 1)
			return -1;
	}

	/* Enable the shaper to be low bandwidth. */
	pkt_len = 1400;
	set_shaper(node_name, shaper_name, 64 * 1000, 8 * pkt_len);

	/* Make a couple of low priority dummy pkts first. */
	init_xmt_pkts(&pkt_info);
	if (make_pkts(4, pkt_len, &pkt_info) != 0)
		return -1;

	/* Make 100 pkts for each fanin of this node, alternating amongst
	 * the inputs. */
	pkt_cnt = FANIN_RATIO * 100;
	fanin   = 0;
	for (pkt_idx = 0; pkt_idx < pkt_cnt; pkt_idx++) {
		pkt_len            = 128 + 128 * fanin;
		pkt_info.pkt_class = 1 + fanin++;
		if (make_pkts(1, pkt_len, &pkt_info) != 0)
			return -1;

		if (FANIN_RATIO <= fanin)
			fanin = 0;
	}

	/* Send the low priority dummy pkts first.  The arrival order of
	 * these pkts will be ignored. */
	pkts_sent = send_pkts(tm_queues[NUM_PRIORITIES - 1], 4);

	/* Now send the test pkts, alternating amongst the input queues. */
	fanin = 0;
	for (pkt_idx = 0; pkt_idx < pkt_cnt; pkt_idx++) {
		tm_queue   = tm_queues[fanin++];
		pkts_sent += send_pkts(tm_queue, 1);
		if (FANIN_RATIO <= fanin)
			fanin = 0;
	}
	CU_ASSERT(pkts_sent == pkt_cnt + 4);

	busy_wait(1000000);   /* wait 1 millisecond */

	/* Disable the shaper, so as to get the pkts out quicker.
	 * We cannot do this if dynamic shaper update is not supported. Without
	 * dynamic update support set_shaper() can cause packet drops due to
	 * start/stop.
	 */
	if (dynamic_shaper_update)
		set_shaper(node_name, NULL, 0, 0);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin,
				    pkt_cnt + 4, 64 * 1000);

	/* Check rcvd packet arrivals to make sure that pkts arrived in
	 * an order commensurate with their weights, sched mode and pkt_len. */
	for (fanin = 0; fanin < fanin_cnt; fanin++) {
		pkt_class = 1 + fanin;
		CU_ASSERT(rcv_rate_stats(&rcv_stats[fanin], pkt_class) == 0);
	}

	/* Disable shaper in case it is still enabled */
	set_shaper(node_name, NULL, 0, 0);
	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
	return 0;
}

static int set_queue_thresholds(odp_tm_queue_t             tm_queue,
				const char                *threshold_name,
				odp_tm_threshold_params_t *threshold_params)
{
	odp_tm_threshold_t threshold_profile;
	int ret;

	if (!dynamic_threshold_update) {
		/* Stop TM system before update when dynamic update is not
		 * supported.
		 */
		CU_ASSERT_FATAL(odp_tm_stop(odp_tm_systems[0]) == 0);
	}

	/* First see if a threshold profile already exists with this name, in
	 * which case we use that profile, else create a new one. */
	threshold_profile = odp_tm_thresholds_lookup(threshold_name);
	if (threshold_profile != ODP_TM_INVALID) {
		ret = odp_tm_thresholds_params_update(threshold_profile,
						      threshold_params);
		if (ret)
			goto exit;
	} else {
		threshold_profile = odp_tm_threshold_create(threshold_name,
							    threshold_params);
		if (threshold_profile == ODP_TM_INVALID) {
			ret = -1;
			goto exit;
		}
		threshold_profiles[num_threshold_profiles] = threshold_profile;
		num_threshold_profiles++;
	}

	ret = odp_tm_queue_threshold_config(tm_queue, threshold_profile);
exit:
	if (!dynamic_threshold_update) {
		/* Start TM system, post update */
		CU_ASSERT_FATAL(odp_tm_start(odp_tm_systems[0]) == 0);
	}
	return ret;
}

static int test_threshold(const char *threshold_name,
			  const char *shaper_name,
			  const char *node_name,
			  uint8_t     priority,
			  uint32_t    max_pkts,
			  uint32_t    max_bytes)
{
	odp_tm_threshold_params_t threshold_params;
	odp_tm_queue_t            tm_queue;
	pkt_info_t                pkt_info;
	uint32_t                  pkt_len, pkts_sent;
	uint32_t                  num_pkts = 0;

	odp_tm_threshold_params_init(&threshold_params);
	if (max_pkts != 0) {
		max_pkts = ODPH_MIN(max_pkts, MAX_PKTS / 3);
		threshold_params.max_pkts        = max_pkts;
		threshold_params.enable_max_pkts = true;
		num_pkts = 2 * max_pkts;
		pkt_len  = 256;
	}

	if (max_bytes != 0) {
		max_bytes = ODPH_MIN(max_bytes, MAX_PKTS * MAX_PAYLOAD / 3);
		threshold_params.max_bytes        = max_bytes;
		threshold_params.enable_max_bytes = true;
		num_pkts = 2 * max_bytes / MAX_PAYLOAD;
		pkt_len  = MAX_PAYLOAD;
	}

	if (max_pkts == 0 && max_bytes == 0)
		return -1;

	/* Pick a tm_queue and set the tm_queue's threshold profile and then
	 * send in twice the amount of traffic as suggested by the thresholds
	 * and make sure at least SOME pkts get dropped. */
	tm_queue = find_tm_queue(0, node_name, priority);
	if (set_queue_thresholds(tm_queue, threshold_name,
				 &threshold_params) != 0) {
		ODPH_ERR("set_queue_thresholds failed\n");
		return -1;
	}

	/* Enable the shaper to be very low bandwidth. */
	set_shaper(node_name, shaper_name, 256 * 1000, 8 * pkt_len);

	init_xmt_pkts(&pkt_info);
	pkt_info.drop_eligible = true;
	pkt_info.pkt_class     = 1;
	if (make_pkts(num_pkts, pkt_len, &pkt_info) != 0) {
		ODPH_ERR("make_pkts failed\n");
		return -1;
	}

	pkts_sent = send_pkts(tm_queue, num_pkts);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin, pkts_sent,
				    1 * GBPS);

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, NULL, 0, 0);
	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));

	if (num_rcv_pkts < num_pkts)
		return 0;

	CU_ASSERT(num_rcv_pkts < pkts_sent);
	return 0;
}

static wred_pkt_cnts_t *search_expected_pkt_rcv_tbl(odp_tm_percent_t confidence,
						    odp_tm_percent_t drop_perc)
{
	wred_pkt_cnts_t *wred_pkt_cnts;
	uint32_t         idx, table_size;

	/* Search the EXPECTED_PKT_RCVD table to find a matching entry */
	table_size = ODPH_ARRAY_SIZE(EXPECTED_PKT_RCVD);
	for (idx = 0; idx < table_size; idx++) {
		wred_pkt_cnts = &EXPECTED_PKT_RCVD[idx];
		if ((wred_pkt_cnts->confidence_percent == confidence) &&
		    (wred_pkt_cnts->drop_percent       == drop_perc))
			return wred_pkt_cnts;
	}

	return NULL;
}

static int set_queue_wred(odp_tm_queue_t   tm_queue,
			  const char      *wred_name,
			  uint8_t          pkt_color,
			  odp_tm_percent_t drop_percent,
			  odp_bool_t       use_byte_fullness,
			  odp_bool_t       use_dual_slope)
{
	odp_tm_wred_params_t wred_params;
	odp_tm_wred_t        wred_profile;
	int rc;

	odp_tm_wred_params_init(&wred_params);
	if (use_dual_slope) {
		wred_params.min_threshold = TM_PERCENT(20);
		wred_params.med_threshold = TM_PERCENT(40);
		wred_params.med_drop_prob = drop_percent;
		wred_params.max_drop_prob = drop_percent;
	} else {
		wred_params.min_threshold = 0;
		wred_params.med_threshold = TM_PERCENT(20);
		wred_params.med_drop_prob = 0;
		wred_params.max_drop_prob = 2 * drop_percent;
	}

	wred_params.enable_wred       = true;
	wred_params.use_byte_fullness = use_byte_fullness;

	if (!dynamic_wred_update) {
		/* Stop TM system before update when dynamic update is not
		 * supported.
		 */
		CU_ASSERT_FATAL(odp_tm_stop(odp_tm_systems[0]) == 0);
	}

	/* First see if a wred profile already exists with this name, in
	 * which case we use that profile, else create a new one. */
	wred_profile = odp_tm_wred_lookup(wred_name);
	if (wred_profile != ODP_TM_INVALID) {
		odp_tm_wred_params_update(wred_profile, &wred_params);
	} else {
		wred_profile = odp_tm_wred_create(wred_name, &wred_params);
		if (wred_profiles[num_wred_profiles - 1][pkt_color] ==
			ODP_TM_INVALID) {
			wred_profiles[num_wred_profiles - 1][pkt_color] =
					wred_profile;
		} else {
			wred_profiles[num_wred_profiles][pkt_color] =
					wred_profile;
			num_wred_profiles++;
		}
	}

	rc = odp_tm_queue_wred_config(tm_queue, pkt_color, wred_profile);

	if (!dynamic_wred_update) {
		/* Start TM system, post update */
		CU_ASSERT_FATAL(odp_tm_start(odp_tm_systems[0]) == 0);
	}
	return rc;

}

static int test_byte_wred(const char      *wred_name,
			  const char      *shaper_name,
			  const char      *threshold_name,
			  const char      *node_name,
			  uint8_t          priority,
			  uint8_t          pkt_color,
			  odp_tm_percent_t drop_percent,
			  odp_bool_t       use_dual_slope)
{
	odp_tm_threshold_params_t threshold_params;
	wred_pkt_cnts_t          *wred_pkt_cnts;
	odp_tm_queue_t            tm_queue;
	pkt_info_t                pkt_info;
	uint32_t                  num_fill_pkts, num_test_pkts, pkts_sent;
	int ret;

	/* Pick the tm_queue and set the tm_queue's wred profile to drop the
	 * given percentage of traffic, then send 100 pkts and see how many
	 * pkts are received. */
	tm_queue = find_tm_queue(0, node_name, priority);
	set_queue_wred(tm_queue, wred_name, pkt_color, drop_percent,
		       true, use_dual_slope);

	/* Enable the shaper to be very low bandwidth. */
	set_shaper(node_name, shaper_name, 64 * 1000, 8 * PKT_BUF_SIZE);

	/* Set the threshold to be byte based and to handle 200 pkts of
	 * size PKT_BUF_SIZE. This way the byte-fullness for the wred test
	 * pkts will be around 60%. */
	odp_tm_threshold_params_init(&threshold_params);
	threshold_params.max_bytes        = 200 * PKT_BUF_SIZE;
	threshold_params.enable_max_bytes = true;
	if (set_queue_thresholds(tm_queue, threshold_name,
				 &threshold_params) != 0) {
		ODPH_ERR("set_queue_thresholds failed\n");
		return -1;
	}

	/* Make and send the first batch of pkts whose job is to set the
	 * queue byte fullness to around 60% for the subsequent test packets.
	 * These packets MUST have drop_eligible false. */
	init_xmt_pkts(&pkt_info);
	num_fill_pkts          = 120;
	pkt_info.pkt_color     = pkt_color;
	pkt_info.pkt_class     = 0;
	pkt_info.drop_eligible = false;
	if (make_pkts(num_fill_pkts, PKT_BUF_SIZE, &pkt_info) != 0)
		return -1;

	send_pkts(tm_queue, num_fill_pkts);

	/* Now send the real test pkts, which are all small so as to try to
	 * keep the byte fullness still close to the 60% point. These pkts
	 * MUST have drop_eligible true. */
	num_test_pkts          = 100;
	pkt_info.pkt_class     = 1;
	pkt_info.drop_eligible = true;
	if (make_pkts(num_test_pkts, 128, &pkt_info) != 0)
		return -1;

	pkts_sent = send_pkts(tm_queue, num_test_pkts);

	/* Disable the shaper, so as to get the pkts out quicker.
	 * We cannot do this if dynamic shaper update is not supported. Without
	 * dynamic update support set_shaper() can cause packet drops due to
	 * start/stop.
	 */
	if (dynamic_shaper_update)
		set_shaper(node_name, NULL, 0, 0);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin,
				    num_fill_pkts + pkts_sent, 64 * 1000);

	/* Search the EXPECTED_PKT_RCVD table to find a matching entry */
	wred_pkt_cnts = search_expected_pkt_rcv_tbl(TM_PERCENT(99.9),
						    drop_percent);
	if (wred_pkt_cnts == NULL)
		return -1;

	/* Disable shaper in case it is still enabled */
	set_shaper(node_name, NULL, 0, 0);
	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));

	ret = !((wred_pkt_cnts->min_cnt <= pkts_sent) &&
	      (pkts_sent <= wred_pkt_cnts->max_cnt));
	if (ret)
		ODPH_DBG("min %" PRIu32 " pkts %" PRIu32 " max %" PRIu32 "\n",
			 wred_pkt_cnts->min_cnt, pkts_sent,
			 wred_pkt_cnts->max_cnt);
	return odp_cunit_ret(ret);
}

static int test_pkt_wred(const char      *wred_name,
			 const char      *shaper_name,
			 const char      *threshold_name,
			 const char      *node_name,
			 uint8_t          priority,
			 uint8_t          pkt_color,
			 odp_tm_percent_t drop_percent,
			 odp_bool_t       use_dual_slope)
{
	odp_tm_threshold_params_t threshold_params;
	wred_pkt_cnts_t          *wred_pkt_cnts;
	odp_tm_queue_t            tm_queue;
	pkt_info_t                pkt_info;
	uint32_t                  num_fill_pkts, num_test_pkts, pkts_sent;
	int ret;

	/* Pick the tm_queue and set the tm_queue's wred profile to drop the
	 * given percentage of traffic, then send 100 pkts and see how many
	 * pkts are received. */
	tm_queue = find_tm_queue(0, node_name, priority);
	set_queue_wred(tm_queue, wred_name, pkt_color, drop_percent,
		       false, use_dual_slope);

	/* Enable the shaper to be very low bandwidth. */
	set_shaper(node_name, shaper_name, 64 * 1000, 1000);

	/* Set the threshold to be pkt based and to handle 1000 pkts.  This
	 * way the pkt-fullness for the wred test pkts will be around 60%. */
	odp_tm_threshold_params_init(&threshold_params);
	threshold_params.max_pkts        = 1000;
	threshold_params.enable_max_pkts = true;

	ret = set_queue_thresholds(tm_queue, threshold_name,
				   &threshold_params);
	if (ret) {
		ODPH_ERR("set_queue_thresholds failed\n");
		return -1;
	}

	/* Make and send the first batch of pkts whose job is to set the
	 * queue pkt fullness to around 60% for the subsequent test packets.
	 * These packets MUST have drop_eligible false. */
	init_xmt_pkts(&pkt_info);
	num_fill_pkts          = 600;
	pkt_info.pkt_color     = pkt_color;
	pkt_info.pkt_class     = 0;
	pkt_info.drop_eligible = false;
	if (make_pkts(num_fill_pkts, 80, &pkt_info) != 0)
		return -1;

	send_pkts(tm_queue, num_fill_pkts);

	/* Now send the real test pkts.  These pkts MUST have drop_eligible
	 * true. */
	num_test_pkts          = 100;
	pkt_info.pkt_class     = 1;
	pkt_info.drop_eligible = true;
	if (make_pkts(num_test_pkts, 80, &pkt_info) != 0)
		return -1;

	pkts_sent = send_pkts(tm_queue, num_test_pkts);

	/* Disable the shaper, so as to get the pkts out quicker.
	 * We cannot do this if dynamic shaper update is not supported. Without
	 * dynamic update support set_shaper() can cause packet drops due to
	 * start/stop.
	 */
	if (dynamic_shaper_update)
		set_shaper(node_name, NULL, 0, 0);

	ret = receive_pkts(odp_tm_systems[0], rcv_pktin,
			   num_fill_pkts + pkts_sent, 64 * 1000);
	if (ret < 0)
		return -1;

	num_rcv_pkts = ret;

	/* Search the EXPECTED_PKT_RCVD table to find a matching entry */
	wred_pkt_cnts = search_expected_pkt_rcv_tbl(TM_PERCENT(99.9),
						    drop_percent);
	if (wred_pkt_cnts == NULL)
		return -1;

	/* Disable shaper in case it is still enabled */
	set_shaper(node_name, NULL, 0, 0);
	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));

	if ((pkts_sent < wred_pkt_cnts->min_cnt) ||
	    (pkts_sent > wred_pkt_cnts->max_cnt)) {
		ODPH_ERR("min_cnt %d <= pkts_sent %d <= max_cnt %d\n",
			 wred_pkt_cnts->min_cnt, pkts_sent,
			 wred_pkt_cnts->max_cnt);
		return -1;
	}

	return 0;
}

static int test_query_functions(const char *shaper_name,
				const char *node_name,
				uint8_t     priority,
				uint32_t    num_pkts)
{
	odp_tm_query_info_t query_info;
	odp_tm_queue_t      tm_queue;
	pkt_info_t          pkt_info;
	uint64_t            commit_bps, expected_pkt_cnt, expected_byte_cnt;
	int                 rc;

	/* Pick a tm_queue and set the egress node's shaper BW to be 64K bps
	 * with a small burst tolerance.  Then send the traffic. */
	tm_queue   = find_tm_queue(0, node_name, priority);
	commit_bps = 64 * 1000;
	if (set_shaper(node_name, shaper_name, commit_bps, 1000) != 0)
		return -1;

	init_xmt_pkts(&pkt_info);
	pkt_info.pkt_class = 1;
	if (make_pkts(num_pkts, PKT_BUF_SIZE, &pkt_info) != 0)
		return -1;

	send_pkts(tm_queue, num_pkts);

	/* Assume all but 2 of the pkts are still in the queue.*/
	expected_pkt_cnt  = num_pkts - 2;
	expected_byte_cnt = expected_pkt_cnt * PKT_BUF_SIZE;

	memset(&query_info, 0, sizeof(query_info));
	rc = odp_tm_queue_query(tm_queue,
				ODP_TM_QUERY_PKT_CNT | ODP_TM_QUERY_BYTE_CNT,
				&query_info);
	CU_ASSERT(rc == 0);
	CU_ASSERT(query_info.total_pkt_cnt_valid);
	CU_ASSERT(expected_pkt_cnt < query_info.total_pkt_cnt);
	CU_ASSERT(query_info.total_byte_cnt_valid);
	CU_ASSERT(expected_byte_cnt < query_info.total_byte_cnt);

	memset(&query_info, 0, sizeof(query_info));
	rc = odp_tm_priority_query(odp_tm_systems[0], priority,
				   ODP_TM_QUERY_PKT_CNT | ODP_TM_QUERY_BYTE_CNT,
				   &query_info);
	CU_ASSERT(rc == 0);
	CU_ASSERT(query_info.total_pkt_cnt_valid);
	CU_ASSERT(expected_pkt_cnt < query_info.total_pkt_cnt);
	CU_ASSERT(query_info.total_byte_cnt_valid);
	CU_ASSERT(expected_byte_cnt < query_info.total_byte_cnt);

	memset(&query_info, 0, sizeof(query_info));
	rc = odp_tm_total_query(odp_tm_systems[0],
				ODP_TM_QUERY_PKT_CNT | ODP_TM_QUERY_BYTE_CNT,
				&query_info);
	CU_ASSERT(rc == 0);
	CU_ASSERT(query_info.total_pkt_cnt_valid);
	CU_ASSERT(expected_pkt_cnt < query_info.total_pkt_cnt);
	CU_ASSERT(query_info.total_byte_cnt_valid);
	CU_ASSERT(expected_byte_cnt < query_info.total_byte_cnt);

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, NULL, 0, 0);
	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin, num_pkts,
				    commit_bps);

	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
	return 0;
}

static int check_vlan_marking_pkts(void)
{
	odp_packet_t rcv_pkt;
	uint32_t     rcv_pkt_idx, err_cnt;
	uint16_t     tci;
	uint8_t      pkt_class, dei, expected_dei;

	/* Check rcvd packets to make sure that pkt_class 1 pkts continue to
	 * not have a VLAN header, pkt class 2 pkts have a VLAN header with the
	 * drop precedence not set and pkt class 3 pkts have a VLAN header with
	 * the  DEI bit set. */
	err_cnt = 0;
	for (rcv_pkt_idx = 0; rcv_pkt_idx < num_rcv_pkts; rcv_pkt_idx++) {
		rcv_pkt   = rcv_pkts[rcv_pkt_idx];
		pkt_class = rcv_pkt_descs[rcv_pkt_idx].pkt_class;

		switch (pkt_class) {
		case 1:
			/* Make sure no VLAN header. */
			if (odp_packet_has_vlan(rcv_pkt)) {
				err_cnt++;
				ODPH_ERR("VLAN incorrectly added\n");
				CU_ASSERT(odp_packet_has_vlan(rcv_pkt));
			}
			break;

		case 2:
		case 3:
			/* Make sure it does have a VLAN header */
			if (!odp_packet_has_vlan(rcv_pkt)) {
				err_cnt++;
				ODPH_ERR("VLAN header missing\n");
				CU_ASSERT(!odp_packet_has_vlan(rcv_pkt));
				break;
			}

			/* Make sure DEI bit is 0 if pkt_class == 2, and 1 if
			 * pkt_class == 3. */
			if (get_vlan_tci(rcv_pkt, &tci) != 0) {
				err_cnt++;
				ODPH_ERR("VLAN header missing\n");
				CU_ASSERT(!odp_packet_has_vlan(rcv_pkt));
				break;
			}

			dei          = (tci >> ODPH_VLANHDR_DEI_SHIFT) & 1;
			expected_dei = (pkt_class == 2) ? 0 : 1;
			if (dei != expected_dei) {
				ODPH_ERR("expected_dei=%u rcvd dei=%u\n",
					 expected_dei, dei);
				err_cnt++;
				CU_ASSERT(dei == expected_dei);
			}
			break;

		default:
			/* Log error but otherwise ignore, since it is
			 * probably a stray pkt from a previous test. */
			ODPH_ERR("Pkt rcvd with invalid pkt class\n");
		}
	}

	return (err_cnt == 0) ? 0 : -1;
}

static int test_vlan_marking(const char        *node_name,
			     odp_packet_color_t pkt_color)
{
	odp_packet_color_t color;
	odp_tm_queue_t     tm_queue;
	pkt_info_t         pkt_info;
	odp_tm_t           odp_tm;
	uint32_t           pkt_cnt, num_pkts, pkt_len, pkts_sent;
	int                rc;

	/* First disable vlan marking for all colors. These "disable" calls
	 * should NEVER fail. */
	odp_tm = odp_tm_systems[0];
	for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
		rc = odp_tm_vlan_marking(odp_tm, color, false);
		if (rc != 0) {
			ODPH_ERR("disabling odp_tm_vlan_marking() failed\n");
			return -1;
		}
	}

	/* Next enable vlan marking for just the given color parameter */
	rc = odp_tm_vlan_marking(odp_tm, pkt_color, true);

	tm_queue = find_tm_queue(0, node_name, 0);
	if (tm_queue == ODP_TM_INVALID) {
		ODPH_ERR("No tm_queue found for node_name='%s'\n", node_name);
		return -1;
	}

	/* Next make 2*X pkts of each color, half with vlan headers -
	 * half without. */
	init_xmt_pkts(&pkt_info);

	pkt_cnt            = 5;
	num_pkts           = 0;
	pkt_len            = 600;
	pkt_info.pkt_class = 1;
	for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
		num_pkts          += pkt_cnt;
		pkt_info.pkt_color = color;
		if (make_pkts(pkt_cnt, pkt_len, &pkt_info) != 0)
			return -1;
	}

	for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
		num_pkts          += pkt_cnt;
		pkt_info.pkt_color = color;
		pkt_info.pkt_class = (color == pkt_color) ? 3 : 2;
		pkt_info.use_vlan  = true;
		pkt_info.vlan_tci  = VLAN_NO_DEI;
		if (make_pkts(pkt_cnt, pkt_len, &pkt_info) != 0)
			return -1;
	}

	pkts_sent    = send_pkts(tm_queue, num_pkts);
	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin, pkts_sent,
				    1000 * 1000);
	if (num_rcv_pkts == 0) {
		ODPH_ERR("No pkts received\n");
		rc = -1;
	} else if (num_rcv_pkts != pkts_sent) {
		ODPH_ERR("pkts_sent=%" PRIu32 " but num_rcv_pkts=%" PRIu32 "\n",
			 pkts_sent, num_rcv_pkts);
		dump_rcvd_pkts(0, num_rcv_pkts - 1);
		CU_ASSERT(num_rcv_pkts == pkts_sent);
	} else {
		rc = check_vlan_marking_pkts();
	}

	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
	return rc;
}

static int check_tos_marking_pkts(odp_bool_t use_ipv6,
				  odp_bool_t use_tcp,
				  odp_bool_t test_ecn,
				  odp_bool_t test_drop_prec,
				  uint8_t    unmarked_tos,
				  uint8_t    new_dscp,
				  uint8_t    dscp_mask)
{
	odp_packet_t rcv_pkt;
	uint32_t     rcv_pkt_idx;
	uint8_t      unmarked_ecn, unmarked_dscp, shifted_dscp, pkt_class;
	uint8_t      tos, expected_tos;
	int          rc;

	/* Turn off test_ecn for UDP pkts, since ECN marking should
	 * only happen for TCP pkts. */
	if (!use_tcp)
		test_ecn = false;

	/* The expected_tos value is only the expected TOS/TC field for pkts
	 * that have been enabled for modification, as indicated by the
	 * pkt_class associated with this pkt. */
	unmarked_ecn  = (unmarked_tos & ODPH_IP_TOS_ECN_MASK)
				>> ODPH_IP_TOS_ECN_SHIFT;
	unmarked_dscp = (unmarked_tos & ODPH_IP_TOS_DSCP_MASK)
				>> ODPH_IP_TOS_DSCP_SHIFT;
	new_dscp      = (new_dscp & dscp_mask) | (unmarked_dscp & ~dscp_mask);
	shifted_dscp  = new_dscp << ODPH_IP_TOS_DSCP_SHIFT;

	if (test_ecn && test_drop_prec)
		expected_tos = shifted_dscp | ODPH_IP_ECN_CE;
	else if (test_ecn)
		expected_tos = unmarked_tos | ODPH_IP_ECN_CE;
	else if (test_drop_prec)
		expected_tos = shifted_dscp | unmarked_ecn;
	else
		expected_tos = unmarked_tos;

	for (rcv_pkt_idx = 0; rcv_pkt_idx < num_rcv_pkts; rcv_pkt_idx++) {
		rcv_pkt   = rcv_pkts[rcv_pkt_idx];
		pkt_class = rcv_pkt_descs[rcv_pkt_idx].pkt_class;

		/* Check that the pkts match the use_ipv6 setting */
		if (use_ipv6)
			rc = odp_packet_has_ipv6(rcv_pkt);
		else
			rc = odp_packet_has_ipv4(rcv_pkt);

		if (rc != 1) {
			if (use_ipv6)
				ODPH_ERR("Expected IPv6 pkt but got IPv4");
			else
				ODPH_ERR("Expected IPv4 pkt but got IPv6");

			return -1;
		}

		/* Check that the pkts match the use_tcp setting */
		if (use_tcp)
			rc = odp_packet_has_tcp(rcv_pkt);
		else
			rc = odp_packet_has_udp(rcv_pkt);

		if (rc != 1) {
			if (use_tcp)
				ODPH_ERR("Expected TCP pkt but got UDP");
			else
				ODPH_ERR("Expected UDP pkt but got TCP");

			return -1;
		}

		/* Now get the tos field to see if it was changed */
		rc = get_ip_tos(rcv_pkt, &tos);
		if (rc != 0) {
			ODPH_ERR("get_ip_tos failed\n");
			return -1;
		}

		switch (pkt_class) {
		case 2:
			/* Tos field must be unchanged. */
			if (unmarked_tos != tos) {
				ODPH_ERR("Tos was changed from 0x%X to 0x%X\n",
					 unmarked_tos, tos);
				return -1;
			}
			break;

		case 3:
			/* Tos field must be changed. */
			if (tos != expected_tos) {
				ODPH_ERR("tos=0x%X instead of expected 0x%X\n",
					 tos, expected_tos);
				CU_ASSERT(tos == expected_tos);
			}
			break;

		default:
			/* Log error but otherwise ignore, since it is
			 * probably a stray pkt from a previous test. */
			ODPH_ERR("Pkt rcvd with invalid pkt class=%u\n",
				 pkt_class);
		}
	}

	return 0;
}

static int test_ip_marking(const char        *node_name,
			   odp_packet_color_t pkt_color,
			   odp_bool_t         use_ipv6,
			   odp_bool_t         use_tcp,
			   odp_bool_t         test_ecn,
			   odp_bool_t         test_drop_prec,
			   uint8_t            new_dscp,
			   uint8_t            dscp_mask)
{
	odp_packet_color_t color;
	odp_tm_queue_t     tm_queue;
	pkt_info_t         pkt_info;
	odp_tm_t           odp_tm;
	uint32_t           pkt_cnt, num_pkts, pkt_len, pkts_sent;
	int                rc, ret_code;

	/* First disable IP TOS marking for all colors. These "disable" calls
	 * should NEVER fail. */
	odp_tm = odp_tm_systems[0];
	for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
		rc = odp_tm_ecn_marking(odp_tm, color, false);
		if (rc != 0) {
			ODPH_ERR("disabling odp_tm_ecn_marking() failed\n");
			return -1;
		}

		rc = odp_tm_drop_prec_marking(odp_tm, color, false);
		if (rc != 0) {
			ODPH_ERR("disabling odp_tm_drop_prec_marking failed\n");
			return -1;
		}
	}

	/* Next enable IP TOS marking for just the given color parameter */
	if ((!test_ecn) && (!test_drop_prec))
		return 0;

	if (test_ecn) {
		rc = odp_tm_ecn_marking(odp_tm, pkt_color, true);
		if (rc != 0) {
			ODPH_ERR("odp_tm_ecn_marking() call failed\n");
			return -1;
		}
	}

	if (test_drop_prec) {
		rc = odp_tm_drop_prec_marking(odp_tm, pkt_color, true);
		if (rc != 0) {
			ODPH_ERR("odp_tm_drop_prec_marking() call failed\n");
			return -1;
		}
	}

	tm_queue = find_tm_queue(0, node_name, 0);
	if (tm_queue == ODP_TM_INVALID) {
		ODPH_ERR("No tm_queue found for node_name='%s'\n", node_name);
		return -1;
	}

	init_xmt_pkts(&pkt_info);
	pkt_info.use_ipv6 = use_ipv6;
	pkt_info.use_tcp  = use_tcp;
	pkt_info.ip_tos   = DEFAULT_TOS;

	pkt_cnt  = 5;
	num_pkts = 0;
	pkt_len  = 1340;
	for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
		num_pkts          += pkt_cnt;
		pkt_info.pkt_color = color;
		if (test_drop_prec || (test_ecn && use_tcp))
			pkt_info.pkt_class = (color == pkt_color) ? 3 : 2;
		else
			pkt_info.pkt_class = 2;

		if (make_pkts(pkt_cnt, pkt_len, &pkt_info) != 0) {
			ODPH_ERR("make_pkts failed\n");
			return -1;
		}
	}

	pkts_sent    = send_pkts(tm_queue, num_pkts);
	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin, pkts_sent,
				    1000 * 1000);
	ret_code     = -1;

	if (num_rcv_pkts == 0) {
		ODPH_ERR("No pkts received\n");
		CU_ASSERT(num_rcv_pkts != 0);
		ret_code = -1;
	} else if (num_rcv_pkts != pkts_sent) {
		ODPH_ERR("pkts_sent=%" PRIu32 " but num_rcv_pkts=%" PRIu32 "\n",
			 pkts_sent, num_rcv_pkts);
		dump_rcvd_pkts(0, num_rcv_pkts - 1);
		CU_ASSERT(num_rcv_pkts == pkts_sent);
		ret_code = -1;
	} else {
		rc = check_tos_marking_pkts(use_ipv6, use_tcp, test_ecn,
					    test_drop_prec, DEFAULT_TOS,
					    new_dscp, dscp_mask);
		CU_ASSERT(rc == 0);
		ret_code = (rc == 0) ? 0 : -1;
	}

	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
	return ret_code;
}

static int test_protocol_marking(const char        *node_name,
				 odp_packet_color_t pkt_color,
				 odp_bool_t         test_ecn,
				 odp_bool_t         test_drop_prec,
				 uint8_t            new_dscp,
				 uint8_t            dscp_mask)
{
	uint32_t errs = 0;
	int      rc;

	/* Now call test_ip_marking once for all combinations of IPv4 or IPv6
	 * pkts AND for UDP or TCP. */
	rc = test_ip_marking(node_name, pkt_color, USE_IPV4, USE_UDP,
			     test_ecn, test_drop_prec, new_dscp, dscp_mask);
	CU_ASSERT(rc == 0);
	if (rc != 0) {
		ODPH_ERR("test_ip_marking failed using IPV4/UDP pkts color=%u "
			 "test_ecn=%u test_drop_prec=%u\n",
			pkt_color, test_ecn, test_drop_prec);
		errs++;
	}

	rc = test_ip_marking(node_name, pkt_color, USE_IPV6, USE_UDP,
			     test_ecn, test_drop_prec, new_dscp, dscp_mask);
	CU_ASSERT(rc == 0);
	if (rc != 0) {
		ODPH_ERR("test_ip_marking failed using IPV6/UDP pkts color=%u "
			 "test_ecn=%u test_drop_prec=%u\n",
			pkt_color, test_ecn, test_drop_prec);
		errs++;
	}

	rc = test_ip_marking(node_name, pkt_color, USE_IPV4, USE_TCP,
			     test_ecn, test_drop_prec, new_dscp, dscp_mask);
	CU_ASSERT(rc == 0);
	if (rc != 0) {
		ODPH_ERR("test_ip_marking failed using IPV4/TCP pkts color=%u "
			 "test_ecn=%u test_drop_prec=%u\n",
			pkt_color, test_ecn, test_drop_prec);
		errs++;
	}

	rc = test_ip_marking(node_name, pkt_color, USE_IPV6, USE_TCP,
			     test_ecn, test_drop_prec, new_dscp, dscp_mask);
	CU_ASSERT(rc == 0);
	if (rc != 0) {
		ODPH_ERR("test_ip_marking failed using IPV6/TCP pkts color=%u "
			 "test_ecn=%u test_drop_prec=%u\n",
			 pkt_color, test_ecn, test_drop_prec);
		errs++;
	}

	return (errs == 0) ? 0 : -1;
}

static int ip_marking_tests(const char *node_name,
			    odp_bool_t  test_ecn,
			    odp_bool_t  test_drop_prec)
{
	odp_packet_color_t color;
	uint32_t           errs = 0;
	uint8_t            new_dscp, dscp_mask;
	int                rc;

	dscp_mask = DROP_PRECEDENCE_MASK;
	for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
		if (tm_capabilities.marking_colors_supported[color]) {
			if (color == PKT_YELLOW)
				new_dscp = MEDIUM_DROP_PRECEDENCE;
			else if (color == PKT_RED)
				new_dscp = HIGH_DROP_PRECEDENCE;
			else
				new_dscp = LOW_DROP_PRECEDENCE;

			rc = test_protocol_marking(node_name, color, test_ecn,
						   test_drop_prec, new_dscp,
						   dscp_mask);
			CU_ASSERT(rc == 0);
			if (rc != 0)
				errs++;
		}
	}

	return (errs == 0) ? 0 : -1;
}

static int walk_tree_backwards(odp_tm_node_t tm_node)
{
	odp_tm_node_fanin_info_t fanin_info;
	odp_tm_node_info_t       node_info;
	odp_tm_queue_t           first_tm_queue;
	odp_tm_node_t            first_tm_node;
	uint32_t                 tm_queue_fanin, tm_node_fanin;
	int                      rc;

	/* Start from the given tm_node and try to go backwards until a valid
	 * and active tm_queue is reached. */
	rc = odp_tm_node_info(tm_node, &node_info);
	if (rc != 0) {
		ODPH_ERR("odp_tm_node_info failed for tm_node=0x%" PRIX64 "\n",
			 odp_tm_node_to_u64(tm_node));
		return rc;
	}

	if ((node_info.tm_queue_fanin == 0) &&
	    (node_info.tm_node_fanin  == 0)) {
		ODPH_ERR("odp_tm_node_info showed no fanin for this node\n");
		return -1;
	}

	fanin_info.tm_queue = ODP_TM_INVALID;
	fanin_info.tm_node  = ODP_TM_INVALID;
	fanin_info.is_last  = false;

	/* TBD* Loop over the entire fanin list verifying the fanin counts.
	 * Also remember the first tm_queue and tm_node seen. */
	tm_queue_fanin = 0;
	tm_node_fanin  = 0;
	first_tm_queue = ODP_TM_INVALID;
	first_tm_node  = ODP_TM_INVALID;

	while (!fanin_info.is_last) {
		rc = odp_tm_node_fanin_info(tm_node, &fanin_info);
		if (rc != 0)
			return rc;

		if ((fanin_info.tm_queue != ODP_TM_INVALID) &&
		    (fanin_info.tm_node  != ODP_TM_INVALID)) {
			ODPH_ERR("Both tm_queue and tm_node are set\n");
			return -1;
		} else if (fanin_info.tm_queue != ODP_TM_INVALID) {
			tm_queue_fanin++;
			if (first_tm_queue == ODP_TM_INVALID)
				first_tm_queue = fanin_info.tm_queue;
		} else if (fanin_info.tm_node != ODP_TM_INVALID) {
			tm_node_fanin++;
			if (first_tm_node == ODP_TM_INVALID)
				first_tm_node = fanin_info.tm_node;
		} else {
			ODPH_ERR("both tm_queue and tm_node are INVALID\n");
			return -1;
		}
	}

	if (tm_queue_fanin != node_info.tm_queue_fanin)
		ODPH_ERR("tm_queue_fanin count error\n");
	else if (tm_node_fanin != node_info.tm_node_fanin)
		ODPH_ERR("tm_node_fanin count error\n");

	/* If we have found a tm_queue then we are successfully done. */
	if (first_tm_queue != ODP_TM_INVALID)
		return 0;

	/* Now recurse up a level */
	return walk_tree_backwards(first_tm_node);
}

static int test_fanin_info(const char *node_name)
{
	tm_node_desc_t *node_desc;
	odp_tm_node_t   tm_node;

	node_desc = find_node_desc(0, node_name);
	if (node_desc == NULL) {
		ODPH_ERR("node_name %s not found\n", node_name);
		return -1;
	}

	tm_node = node_desc->node;
	if (tm_node == ODP_TM_INVALID) {
		ODPH_ERR("tm_node is ODP_TM_INVALID\n");
		return -1;
	}

	return walk_tree_backwards(node_desc->node);
}

static void test_packet_aging(uint64_t tmo_ns, uint32_t pkt_len, odp_bool_t is_dropping)
{
	odp_tm_queue_t tm_queue;
	const char *node_name = "node_1_1_1";
	const char *shaper_name = "test_shaper";
	const uint64_t rate = 256 * 1000;
	pkt_info_t pkt_info;
	const uint16_t num_pkts = 4;
	int recv_pkts;

	tm_queue = find_tm_queue(0, node_name, 0);
	CU_ASSERT_FATAL(tm_queue != ODP_TM_INVALID);
	init_xmt_pkts(&pkt_info);
	pkt_info.drop_eligible = false;
	pkt_info.pkt_class = 1;
	CU_ASSERT_FATAL(make_pkts(num_pkts, pkt_len, &pkt_info) == 0);

	for (int i = 0; i < num_pkts; i++)
		odp_packet_aging_tmo_set(xmt_pkts[i], tmo_ns);

	CU_ASSERT_FATAL(set_shaper(node_name, shaper_name, rate, rate) == 0);
	CU_ASSERT(send_pkts(tm_queue, num_pkts) == num_pkts);
	recv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin, num_pkts, MBPS);

	if (is_dropping)
		CU_ASSERT(recv_pkts < num_pkts)
	else
		CU_ASSERT(recv_pkts == num_pkts);

	set_shaper(node_name, NULL, 0, 0);
	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
}

static void test_defaults(uint8_t fill)
{
	odp_tm_requirements_t req;
	odp_tm_shaper_params_t shaper;
	odp_tm_sched_params_t sched;
	odp_tm_threshold_params_t threshold;
	odp_tm_wred_params_t wred;
	odp_tm_node_params_t node;
	odp_tm_queue_params_t queue;
	int n;

	memset(&req, fill, sizeof(req));
	odp_tm_requirements_init(&req);
	CU_ASSERT(req.num_levels == 0);
	CU_ASSERT(!req.tm_queue_shaper_needed);
	CU_ASSERT(!req.tm_queue_wred_needed);
	CU_ASSERT(!req.tm_queue_dual_slope_needed);
	CU_ASSERT(!req.tm_queue_threshold_needed);
	CU_ASSERT(!req.vlan_marking_needed);
	CU_ASSERT(!req.ecn_marking_needed);
	CU_ASSERT(!req.drop_prec_marking_needed);
	for (n = 0; n < ODP_NUM_PACKET_COLORS; n++)
		CU_ASSERT(!req.marking_colors_needed[n]);
	CU_ASSERT(req.pkt_prio_mode == ODP_TM_PKT_PRIO_MODE_PRESERVE);
	for (n = 0; n < ODP_TM_MAX_LEVELS; n++) {
		odp_tm_level_requirements_t *l_req = &req.per_level[n];

		CU_ASSERT(!l_req->tm_node_shaper_needed);
		CU_ASSERT(!l_req->tm_node_wred_needed);
		CU_ASSERT(!l_req->tm_node_dual_slope_needed);
		CU_ASSERT(!l_req->fair_queuing_needed);
		CU_ASSERT(!l_req->weights_needed);
		CU_ASSERT(!l_req->tm_node_threshold_needed);
	}

	memset(&shaper, fill, sizeof(shaper));
	odp_tm_shaper_params_init(&shaper);
	CU_ASSERT(shaper.packet_mode == ODP_TM_SHAPER_RATE_SHAPE);
	CU_ASSERT(shaper.shaper_len_adjust == 0);
	CU_ASSERT(!shaper.dual_rate);
	CU_ASSERT(!shaper.packet_mode);

	memset(&sched, 0xff, sizeof(sched));
	odp_tm_sched_params_init(&sched);
	for (n = 0; n < ODP_TM_MAX_PRIORITIES; n++)
		CU_ASSERT(sched.sched_modes[n] == ODP_TM_BYTE_BASED_WEIGHTS);

	memset(&threshold, fill, sizeof(threshold));
	odp_tm_threshold_params_init(&threshold);
	CU_ASSERT(!threshold.enable_max_pkts);
	CU_ASSERT(!threshold.enable_max_bytes);

	memset(&wred, fill, sizeof(wred));
	odp_tm_wred_params_init(&wred);
	CU_ASSERT(!wred.enable_wred);
	CU_ASSERT(!wred.use_byte_fullness);

	memset(&node, fill, sizeof(node));
	odp_tm_node_params_init(&node);
	CU_ASSERT(node.shaper_profile == ODP_TM_INVALID);
	CU_ASSERT(node.threshold_profile == ODP_TM_INVALID);
	for (n = 0; n < ODP_NUM_PACKET_COLORS; n++)
		CU_ASSERT(node.wred_profile[n] == ODP_TM_INVALID);

	memset(&queue, fill, sizeof(queue));
	odp_tm_queue_params_init(&queue);
	CU_ASSERT(queue.shaper_profile == ODP_TM_INVALID);
	CU_ASSERT(queue.threshold_profile == ODP_TM_INVALID);
	for (n = 0; n < ODP_NUM_PACKET_COLORS; n++)
		CU_ASSERT(queue.wred_profile[n] == ODP_TM_INVALID);
	CU_ASSERT(queue.priority == 0);
	CU_ASSERT(queue.ordered_enqueue);
}

static void traffic_mngr_test_default_values(void)
{
	test_defaults(0);
	test_defaults(0xff);
}

static void traffic_mngr_test_capabilities(void)
{
	CU_ASSERT(test_overall_capabilities() == 0);
}

static void traffic_mngr_test_tm_create(void)
{
	/* Create the first/primary TM system. */
	CU_ASSERT_FATAL(create_tm_system() == 0);
	dump_tm_tree(0);
}

static void traffic_mngr_test_shaper(void)
{
	if ((tm_shaper_min_rate <= 1 * MBPS) &&
	    (tm_shaper_max_rate >= 1 * MBPS)) {
		CU_ASSERT(!odp_cunit_ret(test_shaper_bw("bw1",
							"node_1_1_1",
							0,
							MBPS * 1)));
	}

	if ((tm_shaper_min_rate <= 4 * MBPS) &&
	    (tm_shaper_max_rate >= 4 * MBPS)) {
		CU_ASSERT(!odp_cunit_ret(test_shaper_bw("bw4",
							"node_1_1_1",
							1,
							4   * MBPS)));
	}

	if ((tm_shaper_min_rate <= 10 * MBPS) &&
	    (tm_shaper_max_rate >= 10 * MBPS)) {
		CU_ASSERT(!odp_cunit_ret(test_shaper_bw("bw10",
							"node_1_1_1",
							2,
							10  * MBPS)));
	}

	if ((tm_shaper_min_rate <= 40 * MBPS) &&
	    (tm_shaper_max_rate >= 40 * MBPS)) {
		CU_ASSERT(!odp_cunit_ret(test_shaper_bw("bw40",
							"node_1_1_1",
							3,
							40  * MBPS)));
	}

	if ((tm_shaper_min_rate <= 100 * MBPS) &&
	    (tm_shaper_max_rate >= 100 * MBPS)) {
		CU_ASSERT(!odp_cunit_ret(test_shaper_bw("bw100",
							"node_1_1_2",
							0,
							100 * MBPS)));
	}
}

static void traffic_mngr_test_scheduler(void)
{
	CU_ASSERT(test_sched_queue_priority("que_prio", "node_1_1_3", 10) == 0);
	return;

	/* The following tests are not quite ready for production use. */
	CU_ASSERT(test_sched_node_priority("node_prio", "node_1_3", 4) == 0);

	CU_ASSERT(test_sched_wfq("sched_rr", "shaper_rr", "node_1_3",
				 ODP_TM_FRAME_BASED_WEIGHTS,
				 EQUAL_WEIGHTS) == 0);
	CU_ASSERT(test_sched_wfq("sched_wrr", "shaper_wrr", "node_1_3",
				 ODP_TM_FRAME_BASED_WEIGHTS,
				 INCREASING_WEIGHTS) == 0);
	CU_ASSERT(test_sched_wfq("sched_wfq", "shaper_wfq", "node_1_3",
				 ODP_TM_BYTE_BASED_WEIGHTS,
				 INCREASING_WEIGHTS) == 0);
}

static int traffic_mngr_check_thresholds_byte(void)
{
	/* Check only for TM queue threshold support as we only test queue threshold. */
	if (!tm_capabilities.tm_queue_threshold.byte)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int traffic_mngr_check_thresholds_packet(void)
{
	/* Check only for TM queue threshold support as we only test queue threshold. */
	if (!tm_capabilities.tm_queue_threshold.packet)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int traffic_mngr_check_thresholds_byte_and_packet(void)
{
	/* Check only for TM queue threshold support as we only test queue threshold. */
	if (!tm_capabilities.tm_queue_threshold.byte_and_packet)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void traffic_mngr_test_thresholds_byte(void)
{
	CU_ASSERT(test_threshold("thresh_byte", "shaper_B", "node_1_2_1", 1,
				 0,  6400) == 0);
}

static void traffic_mngr_test_thresholds_packet(void)
{
	CU_ASSERT(test_threshold("thresh_packet", "shaper_A", "node_1_2_1", 0,
				 16, 0) == 0);
}

static void traffic_mngr_test_thresholds_byte_and_packet(void)
{
	CU_ASSERT(test_threshold("thresh_byte_and_packet", "shaper_A", "node_1_2_1", 0,
				 16, 6400) == 0);
}

static int traffic_mngr_check_queue_stats(void)
{
	if (tm_capabilities.queue_stats.all_counters == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void traffic_mngr_test_queue_stats(void)
{
	odp_tm_queue_stats_t stats_start, stats_stop;
	odp_tm_queue_t tm_queue;
	odp_tm_capabilities_t capa;
	pkt_info_t pkt_info;
	uint32_t pkts_sent;
	uint32_t num_pkts = ODPH_MIN(50u, MAX_PKTS);
	uint32_t pkt_len = 256;

	CU_ASSERT_FATAL(odp_tm_capability(odp_tm_systems[0], &capa) == 0);

	/* Reuse threshold test node */
	tm_queue = find_tm_queue(0, "node_1_2_1", 0);
	CU_ASSERT_FATAL(tm_queue != ODP_TM_INVALID);

	init_xmt_pkts(&pkt_info);
	pkt_info.drop_eligible = false;
	pkt_info.pkt_class     = 1;
	CU_ASSERT_FATAL(make_pkts(num_pkts, pkt_len, &pkt_info) == 0);

	CU_ASSERT(odp_tm_queue_stats(tm_queue, &stats_start) == 0);

	pkts_sent = send_pkts(tm_queue, num_pkts);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin, pkts_sent,
				    1 * GBPS);

	odp_tm_stats_print(odp_tm_systems[0]);

	CU_ASSERT(odp_tm_queue_stats(tm_queue, &stats_stop) == 0);

	if (capa.queue_stats.counter.packets)
		CU_ASSERT(stats_stop.packets >= stats_start.packets + num_rcv_pkts);
	if (capa.queue_stats.counter.octets)
		CU_ASSERT(stats_stop.octets >= stats_start.octets + (num_rcv_pkts * pkt_len));
	CU_ASSERT((stats_stop.discards - stats_start.discards) == 0);
	CU_ASSERT((stats_stop.discard_octets - stats_start.discard_octets) == 0);
	CU_ASSERT((stats_stop.errors - stats_start.errors) == 0);

	printf("\nTM queue statistics\n-------------------\n");
	printf("  discards:        %" PRIu64 "\n", stats_stop.discards);
	printf("  discard octets:  %" PRIu64 "\n", stats_stop.discard_octets);
	printf("  errors:          %" PRIu64 "\n", stats_stop.errors);
	printf("  octets:          %" PRIu64 "\n", stats_stop.octets);
	printf("  packets:         %" PRIu64 "\n", stats_stop.packets);

	/* Check that all unsupported counters are still zero */
	if (!capa.queue_stats.counter.discards)
		CU_ASSERT(stats_stop.discards == 0);
	if (!capa.queue_stats.counter.discard_octets)
		CU_ASSERT(stats_stop.discard_octets == 0);
	if (!capa.queue_stats.counter.errors)
		CU_ASSERT(stats_stop.errors == 0);
	if (!capa.queue_stats.counter.octets)
		CU_ASSERT(stats_stop.octets == 0);
	if (!capa.queue_stats.counter.packets)
		CU_ASSERT(stats_stop.packets == 0);

	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
}

static int traffic_mngr_check_node_stats(void)
{
	int i;

	for (i = 0; i < NUM_LEVELS; i++) {
		/* Report test case as active if even one level supports
		 * stats.
		 */
		if (tm_capabilities.per_level[i].node_stats.all_counters)
			return ODP_TEST_ACTIVE;
	}

	return ODP_TEST_INACTIVE;
}

static void traffic_mngr_test_node_stats(void)
{
	odp_tm_node_stats_t stats_start[NUM_LEVELS];
	odp_tm_node_stats_capability_t stats_capa;
	odp_tm_node_t nodes[NUM_LEVELS];
	odp_tm_node_stats_t stats_stop;
	odp_tm_queue_info_t q_info;
	odp_tm_node_info_t n_info;
	odp_tm_queue_t tm_queue;
	odp_tm_capabilities_t capa;
	pkt_info_t pkt_info;
	uint32_t pkts_sent;
	uint32_t num_pkts = ODPH_MIN(50u, MAX_PKTS);
	uint32_t pkt_len = 256;
	int i;

	CU_ASSERT_FATAL(odp_tm_capability(odp_tm_systems[0], &capa) == 0);

	/* Reuse threshold test node */
	tm_queue = find_tm_queue(0, "node_1_2_1", 0);
	CU_ASSERT_FATAL(tm_queue != ODP_TM_INVALID);

	/* Find parent nodes */
	CU_ASSERT_FATAL(odp_tm_queue_info(tm_queue, &q_info) == 0);
	CU_ASSERT_FATAL(q_info.next_tm_node != ODP_TM_INVALID);
	nodes[NUM_LEVELS - 1] = q_info.next_tm_node;

	for (i = NUM_LEVELS - 2; i >= 0; i--) {
		CU_ASSERT_FATAL(odp_tm_node_info(nodes[i + 1], &n_info) == 0);
		CU_ASSERT_FATAL(n_info.level == (i + 1));
		CU_ASSERT_FATAL(n_info.next_tm_node != ODP_TM_INVALID);

		/* Save next TM node */
		nodes[i] = n_info.next_tm_node;
	}

	init_xmt_pkts(&pkt_info);
	pkt_info.drop_eligible = false;
	pkt_info.pkt_class     = 1;
	CU_ASSERT_FATAL(make_pkts(num_pkts, pkt_len, &pkt_info) == 0);

	/* Collect available node stats */
	for (i = 0; i < NUM_LEVELS; i++) {
		if (capa.per_level[i].node_stats.all_counters == 0)
			continue;

		CU_ASSERT(odp_tm_node_stats(nodes[i], &stats_start[i]) == 0);
	}

	pkts_sent = send_pkts(tm_queue, num_pkts);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin, pkts_sent,
				    1 * GBPS);

	/* Collect available node stats and validate */
	for (i = 0; i < NUM_LEVELS; i++) {
		stats_capa = capa.per_level[i].node_stats;

		CU_ASSERT(odp_tm_node_stats(nodes[i], &stats_stop) == 0);

		if (stats_capa.counter.packets)
			CU_ASSERT(stats_stop.packets >= stats_start[i].packets + num_rcv_pkts);
		if (stats_capa.counter.octets)
			CU_ASSERT(stats_stop.octets >= stats_start[i].octets +
				  (num_rcv_pkts * pkt_len));
		CU_ASSERT((stats_stop.discards - stats_start[i].discards) == 0);
		CU_ASSERT((stats_stop.discard_octets - stats_start[i].discard_octets) == 0);

		printf("\nLevel %d TM node statistics\n-------------------\n", i);
		printf("  discards:        %" PRIu64 "\n", stats_stop.discards);
		printf("  discard octets:  %" PRIu64 "\n", stats_stop.discard_octets);
		printf("  octets:          %" PRIu64 "\n", stats_stop.octets);
		printf("  packets:         %" PRIu64 "\n", stats_stop.packets);

		/* Check that all unsupported counters are still zero */
		if (!stats_capa.counter.discards)
			CU_ASSERT(stats_stop.discards == 0);
		if (!stats_capa.counter.discard_octets)
			CU_ASSERT(stats_stop.discard_octets == 0);
		if (!stats_capa.counter.octets)
			CU_ASSERT(stats_stop.octets == 0);
		if (!stats_capa.counter.packets)
			CU_ASSERT(stats_stop.packets == 0);
	}

	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
}

static int traffic_mngr_check_wred(void)
{
	/* Check if wred is part of created odp_tm_t capabilities */
	if (!tm_capabilities.tm_queue_wred_supported)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static int traffic_mngr_check_byte_wred(void)
{
	/* Check if wred is part of created odp_tm_t capabilities */
	if (!tm_capabilities.tm_queue_wred_supported ||
	    !tm_capabilities.tm_queue_threshold.byte)
		return ODP_TEST_INACTIVE;

	if ((tm_shaper_min_rate > 64 * 1000) ||
	    (tm_shaper_max_rate < 64 * 1000) ||
	    (tm_shaper_min_burst > 8 * PKT_BUF_SIZE) ||
	     (tm_shaper_max_burst < 8 * PKT_BUF_SIZE))
		return ODP_TEST_INACTIVE;
	return ODP_TEST_ACTIVE;
}

static int traffic_mngr_check_pkt_wred(void)
{
	/* Check if wred is part of created odp_tm_t capabilities */
	if (!tm_capabilities.tm_queue_wred_supported ||
	    !tm_capabilities.tm_queue_threshold.packet)
		return ODP_TEST_INACTIVE;

	if ((tm_shaper_min_rate > 64 * 1000) ||
	    (tm_shaper_max_rate < 64 * 1000) ||
	    (tm_shaper_min_burst > 1000) ||
	     (tm_shaper_max_burst < 1000))
		return ODP_TEST_INACTIVE;
	return ODP_TEST_ACTIVE;
}

static void traffic_mngr_test_byte_wred(void)
{
	CU_ASSERT(test_byte_wred("byte_wred_30G", "byte_bw_30G",
				 "byte_thresh_30G", "node_1_3_1", 1,
				 ODP_PACKET_GREEN, TM_PERCENT(30), true) == 0);
	CU_ASSERT(test_byte_wred("byte_wred_50Y", "byte_bw_50Y",
				 "byte_thresh_50Y", "node_1_3_1", 2,
				 ODP_PACKET_YELLOW, TM_PERCENT(50), true) == 0);
	CU_ASSERT(test_byte_wred("byte_wred_70R", "byte_bw_70R",
				 "byte_thresh_70R", "node_1_3_1", 3,
				 ODP_PACKET_RED, TM_PERCENT(70), true) == 0);

	CU_ASSERT(test_byte_wred("byte_wred_40G", "byte_bw_40G",
				 "byte_thresh_40G", "node_1_3_1", 1,
				 ODP_PACKET_GREEN, TM_PERCENT(30), false) == 0);
}

static void traffic_mngr_test_pkt_wred(void)
{
	int rc;

	rc = test_pkt_wred("pkt_wred_40G", "pkt_bw_40G",
			   "pkt_thresh_40G", "node_1_3_2", 1,
			   ODP_PACKET_GREEN, TM_PERCENT(30), false);
	if (odp_cunit_ret(rc) != 0)
		CU_FAIL("40G test failed\n");

	if (!tm_capabilities.tm_queue_dual_slope_supported) {
		ODPH_DBG("since tm_capabilities indicates no dual slope "
			 "WRED support  these tests are skipped.\n");
		return;
	}

	rc = test_pkt_wred("pkt_wred_30G", "pkt_bw_30G",
			   "pkt_thresh_30G", "node_1_3_2", 1,
			   ODP_PACKET_GREEN, TM_PERCENT(30), true);
	if (odp_cunit_ret(rc) != 0)
		CU_FAIL("30G test failed\n");

	rc = test_pkt_wred("pkt_wred_50Y", "pkt_bw_50Y",
			   "pkt_thresh_50Y", "node_1_3_2", 2,
			   ODP_PACKET_YELLOW, TM_PERCENT(50), true);
	if (odp_cunit_ret(rc) != 0)
		CU_FAIL("50Y test failed\n");

	rc = test_pkt_wred("pkt_wred_70R", "pkt_bw_70R",
			   "pkt_thresh_70R", "node_1_3_2", 3,
			   ODP_PACKET_RED,    TM_PERCENT(70), true);
	if (odp_cunit_ret(rc) != 0)
		CU_FAIL("70Y test failed\n");
}

static int traffic_mngr_check_query(void)
{
	uint32_t query_flags = (ODP_TM_QUERY_PKT_CNT | ODP_TM_QUERY_BYTE_CNT);

	/* We need both pkt count and byte count query support */
	if ((tm_capabilities.tm_queue_query_flags & query_flags) != query_flags)
		return ODP_TEST_INACTIVE;

	/* This test uses 64 Kbps rate and a 1000 bit burst size */
	if (tm_shaper_min_rate > 64 * 1000 ||
	    tm_shaper_max_rate < 64 * 1000 ||
	    tm_shaper_min_burst > 1000 ||
	    tm_shaper_max_burst < 1000)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void traffic_mngr_test_query(void)
{
	CU_ASSERT(test_query_functions("query_shaper", "node_1_3_3", 3, 10)
		  == 0);
}

static int traffic_mngr_check_vlan_marking(void)
{
	if (!tm_capabilities.vlan_marking_supported)
		return ODP_TEST_INACTIVE;
	return ODP_TEST_ACTIVE;
}

static int traffic_mngr_check_ecn_marking(void)
{
	if (!tm_capabilities.ecn_marking_supported)
		return ODP_TEST_INACTIVE;
	return ODP_TEST_ACTIVE;
}

static int traffic_mngr_check_drop_prec_marking(void)
{
	if (!tm_capabilities.drop_prec_marking_supported)
		return ODP_TEST_INACTIVE;
	return ODP_TEST_ACTIVE;
}

static int traffic_mngr_check_ecn_drop_prec_marking(void)
{
	if (!tm_capabilities.ecn_marking_supported ||
	    !tm_capabilities.drop_prec_marking_supported)
		return ODP_TEST_INACTIVE;
	return ODP_TEST_ACTIVE;
}

static void traffic_mngr_test_vlan_marking(void)
{
	odp_packet_color_t color;

	for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
		/* Tree is 3 level */
		CU_ASSERT(test_vlan_marking("node_1_3_1", color) == 0);
	}
}

static void traffic_mngr_test_ecn_marking(void)
{
	CU_ASSERT(ip_marking_tests("node_1_3_2", true, false) == 0);
}

static void traffic_mngr_test_drop_prec_marking(void)
{
	CU_ASSERT(ip_marking_tests("node_1_4_2", false, true) == 0);
}

static void traffic_mngr_test_ecn_drop_prec_marking(void)
{
	CU_ASSERT(ip_marking_tests("node_1_4_2", true, true) == 0);
}

static int traffic_mngr_check_tx_aging(void)
{
	return xmt_pktio_capa.max_tx_aging_tmo_ns ? ODP_TEST_ACTIVE : ODP_TEST_INACTIVE;
}

static void traffic_mngr_test_tx_aging_no_drop(void)
{
	/* Set very long aging tmo, packets should not be dropped due to aging */
	test_packet_aging(60000000000, 128, false);
}

static void traffic_mngr_test_tx_aging_drop(void)
{
	/* Set very short aging tmo, there should be drops due to aging */
	test_packet_aging(10, MAX_PAYLOAD, true);
}

static void traffic_mngr_test_fanin_info(void)
{
	CU_ASSERT(test_fanin_info("node_1")     == 0);
	CU_ASSERT(test_fanin_info("node_1_2")   == 0);
	CU_ASSERT(test_fanin_info("node_1_3_7") == 0);
}

static int traffic_mngr_check_lso_ipv4(void)
{
	if (xmt_pktio_capa.lso.max_profiles == 0 || xmt_pktio_capa.lso.max_profiles_per_pktio == 0)
		return ODP_TEST_INACTIVE;

	if (xmt_pktio_capa.lso.proto.ipv4 == 0)
		return ODP_TEST_INACTIVE;

	return ODP_TEST_ACTIVE;
}

static void traffic_mngr_test_lso_ipv4(void)
{
	odp_tm_queue_t tm_queue;
	pkt_info_t pkt_info;
	uint32_t pkts_sent;
	int32_t ret, expect;
	uint32_t num_pkts = 20;
	uint32_t pkt_len  = 256;

	/* Reuse shaper test node */
	tm_queue = find_tm_queue(0, "node_1_1_1", 0);
	CU_ASSERT_FATAL(tm_queue != ODP_TM_INVALID);

	/* IPv4 / UDP packets */
	init_xmt_pkts(&pkt_info);
	pkt_info.drop_eligible = false;
	pkt_info.pkt_class     = 1;
	pkt_info.use_ipv6      = 0;
	pkt_info.use_tcp       = 0;
	CU_ASSERT_FATAL(make_pkts(num_pkts, pkt_len, &pkt_info) == 0);

	pkts_sent = send_pkts_lso(tm_queue, num_pkts, ODP_LSO_PROTO_IPV4, pkt_len / 2);
	CU_ASSERT(pkts_sent == num_pkts);

	expect = 2 * pkts_sent;
	ret = receive_loop(odp_tm_systems[0], rcv_pktin, expect, 1000 * ODP_TIME_MSEC_IN_NS);
	CU_ASSERT(ret > 0);

	num_rcv_pkts = ret;

	/* As packet size is small, there should not be a reason to
	 * split each packet into more than two segments. */
	CU_ASSERT(ret == expect)
	if (ret != expect) {
		ODPH_ERR("\nReceived %i packets, expected %i\n", ret, expect);

		if (ret < 0)
			num_rcv_pkts = 0;
	}

	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
}

static void traffic_mngr_test_node_long_name(void)
{
	odp_tm_node_params_t node_params;
	odp_tm_node_t tm_node;
	char name[ODP_TM_NAME_LEN];

	memset(name, 'a', sizeof(name));
	name[sizeof(name) - 1] = 0;

	odp_tm_node_params_init(&node_params);

	tm_node = odp_tm_node_create(odp_tm_systems[0], name, &node_params);
	CU_ASSERT(tm_node != ODP_TM_INVALID);
	CU_ASSERT(tm_node == odp_tm_node_lookup(odp_tm_systems[0], name));
	CU_ASSERT(!odp_tm_node_destroy(tm_node));
}

static void traffic_mngr_test_shaper_long_name(void)
{
	odp_tm_shaper_params_t shaper_params;
	odp_tm_shaper_t profile;
	char name[ODP_TM_NAME_LEN];

	memset(name, 'a', sizeof(name));
	name[sizeof(name) - 1] = 0;

	odp_tm_shaper_params_init(&shaper_params);
	profile = odp_tm_shaper_create(name, &shaper_params);

	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == odp_tm_shaper_lookup(name));
	CU_ASSERT(!odp_tm_shaper_destroy(profile));
}

static void traffic_mngr_test_sched_long_name(void)
{
	odp_tm_sched_params_t sched_params;
	odp_tm_sched_t profile;
	char name[ODP_TM_NAME_LEN];

	memset(name, 'a', sizeof(name));
	name[sizeof(name) - 1] = 0;

	odp_tm_sched_params_init(&sched_params);
	profile = odp_tm_sched_create(name, &sched_params);

	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == odp_tm_sched_lookup(name));
	CU_ASSERT(!odp_tm_sched_destroy(profile));
}

static void traffic_mngr_test_threshold_long_name(void)
{
	odp_tm_threshold_params_t threshold_params;
	odp_tm_threshold_t profile;
	char name[ODP_TM_NAME_LEN];

	memset(name, 'a', sizeof(name));
	name[sizeof(name) - 1] = 0;

	odp_tm_threshold_params_init(&threshold_params);
	threshold_params.enable_max_bytes = true;
	profile = odp_tm_threshold_create(name, &threshold_params);

	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == odp_tm_thresholds_lookup(name));
	CU_ASSERT(!odp_tm_threshold_destroy(profile));
}

static void traffic_mngr_test_wred_long_name(void)
{
	odp_tm_wred_params_t wred_params;
	odp_tm_wred_t profile;
	char name[ODP_TM_NAME_LEN];

	memset(name, 'a', sizeof(name));
	name[sizeof(name) - 1] = 0;

	odp_tm_wred_params_init(&wred_params);
	profile = odp_tm_wred_create(name, &wred_params);

	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == odp_tm_wred_lookup(name));
	CU_ASSERT(!odp_tm_wred_destroy(profile));
}

static void traffic_mngr_test_destroy(void)
{
	CU_ASSERT(destroy_tm_systems() == 0);
}

odp_testinfo_t traffic_mngr_suite[] = {
	ODP_TEST_INFO(traffic_mngr_test_default_values),
	ODP_TEST_INFO(traffic_mngr_test_capabilities),
	ODP_TEST_INFO(traffic_mngr_test_tm_create),
	ODP_TEST_INFO(traffic_mngr_test_shaper_profile),
	ODP_TEST_INFO(traffic_mngr_test_sched_profile),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_threshold_profile_byte,
				  traffic_mngr_check_thresholds_byte),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_threshold_profile_packet,
				  traffic_mngr_check_thresholds_packet),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_threshold_profile_byte_and_packet,
				  traffic_mngr_check_thresholds_byte_and_packet),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_wred_profile,
				  traffic_mngr_check_wred),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_shaper,
				  traffic_mngr_check_shaper),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_scheduler,
				  traffic_mngr_check_scheduler),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_thresholds_byte,
				  traffic_mngr_check_thresholds_byte),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_thresholds_packet,
				  traffic_mngr_check_thresholds_packet),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_thresholds_byte_and_packet,
				  traffic_mngr_check_thresholds_byte_and_packet),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_byte_wred,
				  traffic_mngr_check_byte_wred),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_pkt_wred,
				  traffic_mngr_check_pkt_wred),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_query,
				  traffic_mngr_check_query),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_queue_stats,
				  traffic_mngr_check_queue_stats),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_node_stats,
				  traffic_mngr_check_node_stats),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_vlan_marking,
				  traffic_mngr_check_vlan_marking),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_ecn_marking,
				  traffic_mngr_check_ecn_marking),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_drop_prec_marking,
				  traffic_mngr_check_drop_prec_marking),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_ecn_drop_prec_marking,
				  traffic_mngr_check_ecn_drop_prec_marking),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_tx_aging_no_drop,
				  traffic_mngr_check_tx_aging),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_tx_aging_drop,
				  traffic_mngr_check_tx_aging),
	ODP_TEST_INFO(traffic_mngr_test_fanin_info),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_lso_ipv4, traffic_mngr_check_lso_ipv4),
	ODP_TEST_INFO(traffic_mngr_test_node_long_name),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_shaper_long_name,
				  traffic_mngr_check_shaper),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_sched_long_name,
				  traffic_mngr_check_scheduler),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_threshold_long_name,
				  traffic_mngr_check_thresholds_byte),
	ODP_TEST_INFO_CONDITIONAL(traffic_mngr_test_wred_long_name,
				  traffic_mngr_check_wred),
	ODP_TEST_INFO(traffic_mngr_test_destroy),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t traffic_mngr_suites[] = {
	{ "traffic_mngr tests", traffic_mngr_suite_init,
	  traffic_mngr_suite_term, traffic_mngr_suite },
	ODP_SUITE_INFO_NULL
};

int main(int argc, char *argv[])
{
	/* parse common options: */
	if (odp_cunit_parse_options(&argc, argv))
		return -1;

	int ret = odp_cunit_register(traffic_mngr_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	/* Exit with 77 in order to indicate that test is skipped completely */
	if (!ret && suite_inactive == (ODPH_ARRAY_SIZE(traffic_mngr_suites) - 1))
		return 77;
	return ret;
}

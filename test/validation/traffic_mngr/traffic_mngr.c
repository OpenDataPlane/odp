/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <math.h>
#include <odp.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <test_debug.h>
#include "odp_cunit_common.h"
#include "traffic_mngr.h"

#define MAX_NUM_IFACES           2
#define MAX_TM_SYSTEMS           3
#define NUM_LEVELS               3
#define NUM_PRIORITIES           4
#define NUM_QUEUES_PER_NODE      NUM_PRIORITIES
#define FANIN_RATIO              8
#define NUM_LEVEL0_TM_NODES      1
#define NUM_LEVEL1_TM_NODES      FANIN_RATIO
#define NUM_LEVEL2_TM_NODES      (FANIN_RATIO * FANIN_RATIO)
#define NUM_TM_QUEUES            (NUM_LEVEL2_TM_NODES * NUM_QUEUES_PER_NODE)
#define NUM_SHAPER_PROFILES      FANIN_RATIO
#define NUM_SCHED_PROFILES       FANIN_RATIO
#define NUM_THRESHOLD_PROFILES   NUM_QUEUES_PER_NODE
#define NUM_WRED_PROFILES        NUM_QUEUES_PER_NODE

#define ODP_NUM_PKT_COLORS       ODP_NUM_PACKET_COLORS
#define PKT_GREEN                ODP_PACKET_GREEN
#define PKT_YELLOW               ODP_PACKET_YELLOW
#define PKT_RED                  ODP_PACKET_RED

#define MIN_COMMIT_BW            (64 * 1024)
#define MIN_COMMIT_BURST         8000
#define MIN_PEAK_BW              2000000
#define MIN_PEAK_BURST           16000

#define MIN_PKT_THRESHOLD        10
#define MIN_BYTE_THRESHOLD       2048

#define MIN_WRED_THRESH          5
#define MED_WRED_THRESH          10
#define MED_DROP_PROB            4
#define MAX_DROP_PROB            8

#define MAX_PKTS                 1000
#define PKT_BUF_SIZE             1460
#define MAX_PAYLOAD              1400
#define SHAPER_LEN_ADJ           20
#define CRC_LEN                  4
#define TM_NAME_LEN              32
#define BILLION                  1000000000ULL
#define MS                       1000000  /* Millisecond in units of NS */
#define MBPS                     1000000
#define GBPS                     1000000000

#define MIN(a, b)  (((a) <= (b)) ? (a) : (b))
#define MAX(a, b)  (((a) <= (b)) ? (b) : (a))

#define TM_PERCENT(percent) ((uint32_t)(100 * percent))

typedef enum {
	SHAPER_PROFILE, SCHED_PROFILE, THRESHOLD_PROFILE, WRED_PROFILE
} profile_kind_t;

typedef struct {
	uint32_t       num_queues;
	odp_tm_queue_t tm_queues[0];
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
	tm_node_desc_t  *children[0];
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
	uint16_t       xmt_ident;
	uint8_t        pkt_class;
	uint8_t        was_rcvd;
} xmt_pkt_desc_t;

typedef struct {
	odp_time_t      rcv_time;
	xmt_pkt_desc_t *xmt_pkt_desc;
	uint16_t        rcv_ident;
	uint8_t         pkt_class;
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

static const char ALPHABET[] =
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/* The following constant table determines the minimum and maximum number of
 * pkts that will be received when sending 100 pkts through a system with a
 * drop probability of p% (using a uniform probability distribution), with a
 * confidence of 99.9% 99.99% and 99.999%. The confidence is interepreted as
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

static odp_tm_t        odp_tm_systems[MAX_TM_SYSTEMS];
static tm_node_desc_t *root_node_descs[MAX_TM_SYSTEMS];
static uint32_t        num_odp_tm_systems;

static odp_tm_shaper_t    shaper_profiles[NUM_SHAPER_PROFILES];
static odp_tm_sched_t     sched_profiles[NUM_SCHED_PROFILES];
static odp_tm_threshold_t threshold_profiles[NUM_THRESHOLD_PROFILES];
static odp_tm_wred_t      wred_profiles[NUM_WRED_PROFILES][ODP_NUM_PKT_COLORS];

static uint8_t payload_data[MAX_PAYLOAD];

static odp_packet_t   xmt_pkts[MAX_PKTS];
static xmt_pkt_desc_t xmt_pkt_descs[MAX_PKTS];
static uint32_t       num_pkts_made;
static uint32_t       num_pkts_sent;

static odp_packet_t   rcv_pkts[MAX_PKTS];
static rcv_pkt_desc_t rcv_pkt_descs[MAX_PKTS];
static uint32_t       num_rcv_pkts;

static queues_set_t queues_set;
static uint32_t ip_ident_list[MAX_PKTS];

/* interface names used for testing */
static const char *iface_name[MAX_NUM_IFACES];

/** number of interfaces being used (1=loopback, 2=pair) */
static uint32_t num_ifaces;

static odp_pool_t pools[MAX_NUM_IFACES] = {ODP_POOL_INVALID, ODP_POOL_INVALID};

static odp_pktio_t pktios[MAX_NUM_IFACES];
static odp_pktin_queue_t pktins[MAX_NUM_IFACES];
static odp_pktout_queue_t pktouts[MAX_NUM_IFACES];
static odp_pktin_queue_t rcv_pktin;
static odp_pktout_queue_t xmt_pktout;

static odph_ethaddr_t src_mac;
static odph_ethaddr_t dst_mac;

static odp_atomic_u32_t cpu_ip_ident;

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

static int wait_linkup(odp_pktio_t pktio)
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

	return ret;
}

static int open_pktios(void)
{
	odp_pktio_param_t pktio_param;
	odp_pool_param_t  pool_param;
	odp_pktio_t       pktio;
	odp_pool_t        pkt_pool;
	uint32_t          iface;
	char              pool_name[ODP_POOL_NAME_LEN];
	int               rc, ret;

	odp_pool_param_init(&pool_param);
	pool_param.pkt.num  = 10 * MAX_PKTS;
	pool_param.type     = ODP_POOL_PACKET;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode  = ODP_PKTIN_MODE_DIRECT;
	pktio_param.out_mode = ODP_PKTOUT_MODE_DIRECT;

	for (iface = 0; iface < num_ifaces; iface++) {
		snprintf(pool_name, sizeof(pool_name), "pkt_pool_%s",
			 iface_name[iface]);

		pkt_pool = odp_pool_create(pool_name, &pool_param);
		if (pkt_pool == ODP_POOL_INVALID) {
			CU_FAIL("unable to create pool");
			return -1;
		}

		pools[iface] = pkt_pool;
		pktio = odp_pktio_open(iface_name[iface], pkt_pool,
				       &pktio_param);
		if (pktio == ODP_PKTIO_INVALID)
			pktio = odp_pktio_lookup(iface_name[iface]);

		/* Set defaults for PktIn and PktOut queues */
		odp_pktin_queue_config(pktio, NULL);
		odp_pktout_queue_config(pktio, NULL);

		pktios[iface] = pktio;
		if (pktio == ODP_PKTIO_INVALID) {
			LOG_ERR("%s odp_pktio_open() failed\n", __func__);
			return -1;
		}

		if (odp_pktin_queue(pktio, &pktins[iface], 1) != 1) {
			odp_pktio_close(pktio);
			LOG_ERR("%s odp_pktio_open() failed: no pktin queue\n",
				__func__);
			return -1;
		}

		if (odp_pktout_queue(pktio, &pktouts[iface], 1) != 1) {
			odp_pktio_close(pktio);
			LOG_ERR("%s odp_pktio_open() failed: no pktout queue\n",
				__func__);
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
			LOG_ERR("%s odp_pktio_mac_addr() failed\n", __func__);
			return -1;
		}
	}

	if (2 <= num_ifaces) {
		xmt_pktout = pktouts[0];
		rcv_pktin  = pktins[1];
		ret = odp_pktio_start(pktios[1]);
		if (ret != 0) {
			LOG_ERR("%s odp_pktio_start() failed\n", __func__);
			return -1;
		}
	} else {
		xmt_pktout = pktouts[0];
		rcv_pktin  = pktins[0];
	}

	ret = odp_pktio_start(pktios[0]);
	if (ret != 0) {
		LOG_ERR("%s odp_pktio_start() failed\n", __func__);
		return -1;
	}

	/* Now wait until the link or links are up. */
	rc = wait_linkup(pktios[0]);
	if (rc != 1) {
		LOG_ERR("%s link %" PRIu64 " not up\n", __func__,
			odp_pktio_to_u64(pktios[0]));
		return -1;
	}

	if (num_ifaces < 2)
		return 0;

	/* Wait for 2nd link to be up */
	rc = wait_linkup(pktios[1]);
	if (rc != 1) {
		LOG_ERR("%s link %" PRIu64 " not up\n", __func__,
			odp_pktio_to_u64(pktios[0]));
		return -1;
	}

	return 0;
}

static odp_packet_t make_pkt(odp_pool_t pkt_pool,
			     uint32_t   payload_len,
			     uint16_t   ip_ident,
			     uint8_t    pkt_class)
{
	odph_ipv4hdr_t *ip;
	odph_ethhdr_t  *eth;
	odph_udphdr_t  *udp;
	odp_packet_t    odp_pkt;
	uint32_t        udp_len, ipv4_len, eth_len, l3_offset, l4_offset;
	uint32_t        pkt_len, app_offset;
	uint8_t        *buf, *pkt_class_ptr;
	int             rc;

	udp_len = payload_len + sizeof(odph_udphdr_t);
	ipv4_len = udp_len + ODPH_IPV4HDR_LEN;
	eth_len = ipv4_len + ODPH_ETHHDR_LEN;
	pkt_len = eth_len;

	odp_pkt = odp_packet_alloc(pkt_pool, eth_len);
	if (odp_pkt == ODP_PACKET_INVALID)
		return ODP_PACKET_INVALID;

	buf = odp_packet_data(odp_pkt);

	/* Ethernet Header */
	odp_packet_l2_offset_set(odp_pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy(eth->src.addr, &src_mac, ODPH_ETHADDR_LEN);
	memcpy(eth->dst.addr, &dst_mac, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	/* IPv4 Header */
	l3_offset = ODPH_ETHHDR_LEN;
	odp_packet_l3_offset_set(odp_pkt, l3_offset);
	ip = (odph_ipv4hdr_t *)(buf + l3_offset);
	ip->dst_addr = odp_cpu_to_be_32(0x0a000064);
	ip->src_addr = odp_cpu_to_be_32(0x0a000001);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(pkt_len - ODPH_ETHHDR_LEN);
	ip->ttl = 128;
	ip->proto = ODPH_IPPROTO_UDP;
	ip->id = odp_cpu_to_be_16(ip_ident);

	/* UDP Header */
	l4_offset = l3_offset + ODPH_IPV4HDR_LEN;
	odp_packet_l4_offset_set(odp_pkt, l4_offset);
	udp = (odph_udphdr_t *)(buf + l4_offset);
	udp->src_port = odp_cpu_to_be_16(12049);
	udp->dst_port = odp_cpu_to_be_16(12050);
	udp->length = odp_cpu_to_be_16(pkt_len -
				       ODPH_ETHHDR_LEN - ODPH_IPV4HDR_LEN);

	app_offset = l4_offset + ODPH_UDPHDR_LEN;
	rc = odp_packet_copydata_in(odp_pkt, app_offset, payload_len,
				    payload_data);
	CU_ASSERT_FATAL(rc == 0);

	pkt_class_ptr = odp_packet_offset(odp_pkt, app_offset, NULL, NULL);
	CU_ASSERT_FATAL(pkt_class_ptr != NULL);
	*pkt_class_ptr = pkt_class;

	/* Calculate and insert checksums. */
	ip->chksum = 0;
	udp->chksum = 0;
	odph_ipv4_csum_update(odp_pkt);
	udp->chksum = odph_ipv4_udp_chksum(odp_pkt);
	return odp_pkt;
}

static xmt_pkt_desc_t *find_matching_xmt_pkt_desc(uint16_t ip_ident)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	uint32_t        xmt_pkt_idx;

	for (xmt_pkt_idx = 0; xmt_pkt_idx < num_pkts_sent; xmt_pkt_idx++) {
		xmt_pkt_desc = &xmt_pkt_descs[xmt_pkt_idx];
		if (xmt_pkt_desc->xmt_ident == ip_ident)
			return xmt_pkt_desc;
	}

	return NULL;
}

static int receive_pkts(odp_tm_t          odp_tm,
			odp_pktin_queue_t pktin,
			uint32_t          num_pkts,
			uint64_t          rate_bps)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	odp_packet_t    rcv_pkt;
	odp_time_t      start_time, current_time, duration, xmt_time;
	odp_time_t      rcv_time, delta_time;
	uint64_t        temp1, timeout_ns, duration_ns, delta_ns;
	uint32_t        pkts_rcvd, rcv_idx, ident_offset, l4_offset, app_offset;
	uint16_t        be_ip_ident, ident;
	uint8_t        *pkt_class_ptr, pkt_class;
	int             rc;

	temp1      = (1000000ULL * 10000ULL * (uint64_t)num_pkts) / rate_bps;
	timeout_ns = 1000ULL * ((4ULL * temp1) + 10000ULL);

	pkts_rcvd   = 0;
	start_time  = odp_time_local();
	duration_ns = 0;

	while ((pkts_rcvd < num_pkts) || (!odp_tm_is_idle(odp_tm))) {
		rc = odp_pktin_recv(pktin, &rcv_pkts[pkts_rcvd], 1);
		if (rc < 0)
			return rc;

		current_time = odp_time_local();
		duration     = odp_time_diff(current_time, start_time);
		duration_ns  = odp_time_to_ns(duration);
		if (rc == 1)
			rcv_pkt_descs[pkts_rcvd++].rcv_time = current_time;
		else if (timeout_ns < duration_ns)
			break;
	}

	/* Now go through matching the rcv pkts to the xmt pkts, determining
	 * which xmt_pkts were lost and for the ones that did arrive, how
	 * long did they take. We don't do this work while receiving the pkts
	 * in the loop above because we want to try to get as accurate a
	 * rcv timestamp as possible. */
	for (rcv_idx = 0; rcv_idx < pkts_rcvd; rcv_idx++) {
		rcv_pkt      = rcv_pkts[rcv_idx];
		ident_offset = ODPH_ETHHDR_LEN + offsetof(odph_ipv4hdr_t, id);

		odp_packet_copydata_out(rcv_pkt, ident_offset, 2, &be_ip_ident);
		ident = odp_be_to_cpu_16(be_ip_ident);
		rcv_pkt_descs[rcv_idx].rcv_ident = ident;

		l4_offset     = odp_packet_l4_offset(rcv_pkt);
		app_offset    = l4_offset + ODPH_UDPHDR_LEN;
		pkt_class_ptr = odp_packet_offset(rcv_pkt, app_offset,
						  NULL, NULL);
		CU_ASSERT_FATAL(pkt_class_ptr != NULL);
		rcv_pkt_descs[rcv_idx].pkt_class = *pkt_class_ptr;

		xmt_pkt_desc = find_matching_xmt_pkt_desc(ident);
		if (xmt_pkt_desc != NULL) {
			rcv_pkt_descs[rcv_idx].xmt_pkt_desc = xmt_pkt_desc;
			xmt_time   = xmt_pkt_desc->xmt_time;
			rcv_time   = rcv_pkt_descs[rcv_idx].rcv_time;
			pkt_class  = rcv_pkt_descs[rcv_idx].pkt_class;
			delta_time = odp_time_diff(rcv_time, xmt_time);
			delta_ns   = odp_time_to_ns(delta_time);

			xmt_pkt_desc->rcv_time  = rcv_time;
			xmt_pkt_desc->delta_ns  = delta_ns;
			xmt_pkt_desc->pkt_class = pkt_class;
			xmt_pkt_desc->was_rcvd  = 1;
		}
	}

	return pkts_rcvd;
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

static void init_xmt_pkts(void)
{
	memset(xmt_pkts, 0, sizeof(xmt_pkts));
	memset(xmt_pkt_descs, 0, sizeof(xmt_pkt_descs));
	num_pkts_made = 0;
	num_pkts_sent = 0;

	free_rcvd_pkts();
	memset(rcv_pkts, 0, sizeof(rcv_pkts));
	memset(rcv_pkt_descs, 0, sizeof(rcv_pkt_descs));
	num_rcv_pkts = 0;
}

static int make_pkts(uint32_t   num_pkts,
		     uint32_t   pkt_len,
		     uint8_t    packet_color,
		     odp_bool_t drop_eligible,
		     uint8_t    pkt_class)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	odp_packet_t    odp_pkt;
	uint32_t        hdrs_len, payload_len, idx, ident, xmt_pkt_idx;

	hdrs_len    = ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN + ODPH_UDPHDR_LEN;
	payload_len = pkt_len - (hdrs_len + SHAPER_LEN_ADJ);

	for (idx = 0; idx < num_pkts; idx++) {
		ident        = odp_atomic_fetch_inc_u32(&cpu_ip_ident);
		xmt_pkt_idx  = num_pkts_made++;
		xmt_pkt_desc = &xmt_pkt_descs[xmt_pkt_idx];
		xmt_pkt_desc->pkt_len   = pkt_len;
		xmt_pkt_desc->xmt_ident = ident;
		xmt_pkt_desc->pkt_class = pkt_class;

		odp_pkt = make_pkt(pools[0], payload_len, ident, pkt_class);
		if (odp_pkt == ODP_PACKET_INVALID)
			return -1;

		odp_packet_color_set(odp_pkt, packet_color);
		odp_packet_drop_eligible_set(odp_pkt, drop_eligible);
		odp_packet_shaper_len_adjust_set(odp_pkt, SHAPER_LEN_ADJ);

		xmt_pkts[xmt_pkt_idx] = odp_pkt;
	}

	return 0;
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
		if ((idx & 1) == 0)
			rc = odp_tm_enq(tm_queue, odp_pkt);
		else
			rc = odp_tm_enq_with_cnt(tm_queue, odp_pkt);

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

static int ident_list_idx(uint32_t ip_ident,
			  uint32_t ip_ident_list[],
			  uint32_t ident_list_len)
{
	uint32_t idx;

	for (idx = 0; idx < ident_list_len; idx++)
		if (ip_ident_list[idx] == ip_ident)
			return idx;

	return -1;
}

static uint32_t pkts_rcvd_in_given_order(uint32_t   ip_ident_list[],
					 uint32_t   ident_list_len,
					 uint8_t    pkt_class,
					 odp_bool_t match_pkt_class,
					 odp_bool_t ignore_pkt_class)
{
	rcv_pkt_desc_t *rcv_pkt_desc;
	odp_bool_t      is_match;
	uint32_t        rcv_pkt_idx, pkts_in_order, pkts_out_of_order;
	uint32_t        rcv_ident;
	int             last_pkt_idx, pkt_idx;

	pkts_in_order     = 1;
	pkts_out_of_order = 0;
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
			rcv_ident = rcv_pkt_desc->rcv_ident;
			pkt_idx   = ident_list_idx(rcv_ident, ip_ident_list,
						   ident_list_len);
			if (0 <= pkt_idx) {
				if (0 <= last_pkt_idx) {
					if (last_pkt_idx < pkt_idx)
						pkts_in_order++;
					else
						pkts_out_of_order++;
				}

				last_pkt_idx = pkt_idx;
			}
		}
	}

	return pkts_in_order;
}

static inline void update_rcv_stats(rcv_stats_t *rcv_stats,
				    odp_time_t   rcv_time,
				    odp_time_t   last_rcv_time)
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
	rcv_stats->min_rcv_gap = MIN(rcv_stats->min_rcv_gap, rcv_gap);
	rcv_stats->max_rcv_gap = MAX(rcv_stats->max_rcv_gap, rcv_gap);

	rcv_stats->total_rcv_gap         += rcv_gap;
	rcv_stats->total_rcv_gap_squared += rcv_gap * rcv_gap;
}

static int rcv_rate_stats(rcv_stats_t *rcv_stats,
			  uint8_t      pkt_class,
			  uint32_t     skip_pkt_cnt)
{
	xmt_pkt_desc_t *xmt_pkt_desc;
	odp_time_t      last_rcv_time, rcv_time;
	uint32_t        matching_pkts, pkt_idx, pkts_rcvd;
	uint32_t        avg, variance, std_dev;

	matching_pkts = 0;
	pkts_rcvd     = 0;
	last_rcv_time = ODP_TIME_NULL;
	memset(rcv_stats, 0, sizeof(rcv_stats_t));
	rcv_stats->min_rcv_gap = 1000000000;

	for (pkt_idx = 0; pkt_idx < num_pkts_sent; pkt_idx++) {
		xmt_pkt_desc = &xmt_pkt_descs[pkt_idx];
		if ((xmt_pkt_desc->was_rcvd != 0) &&
		    (xmt_pkt_desc->pkt_class == pkt_class)) {
			rcv_time = xmt_pkt_desc->rcv_time;
			matching_pkts++;
			if (skip_pkt_cnt <= matching_pkts) {
				if (pkts_rcvd != 0)
					update_rcv_stats(rcv_stats, rcv_time,
							 last_rcv_time);
				pkts_rcvd++;
				last_rcv_time = rcv_time;
			}
		}
	}

	if (pkts_rcvd == 0)
		return -1;

	avg      = rcv_stats->total_rcv_gap / pkts_rcvd;
	variance = (rcv_stats->total_rcv_gap_squared / pkts_rcvd) - avg * avg;
	std_dev  = (uint32_t)sqrt((double)variance);

	rcv_stats->num_samples = pkts_rcvd;
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
	}

	tm_queue = odp_tm_queue_create(odp_tm, &queue_params);
	if (tm_queue == ODP_TM_INVALID) {
		LOG_ERR("%s odp_tm_queue_create() failed\n", __func__);
		return -1;
	}

	queue_desc->tm_queues[priority] = tm_queue;
	rc = odp_tm_queue_connect(tm_queue, tm_node);
	if (rc != 0) {
		LOG_ERR("%s odp_tm_queue_connect() failed\n", __func__);
		return -1;
	}

	return 0;
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
	char                  node_name[TM_NAME_LEN];
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
	if (parent_node_desc == NULL)
		snprintf(node_name, sizeof(node_name), "node_%u",
			 node_idx + 1);
	else
		snprintf(node_name, sizeof(node_name), "%s_%u",
			 parent_node_desc->node_name, node_idx + 1);

	tm_node = odp_tm_node_create(odp_tm, node_name, &node_params);
	if (tm_node == ODP_TM_INVALID) {
		LOG_ERR("%s odp_tm_node_create() failed @ level=%u\n",
			__func__, level);
		return NULL;
	}

	/* Now connect this node to the lower level "parent" node. */
	if (level == 0)
		parent_node = ODP_TM_ROOT;
	else
		parent_node = parent_node_desc->node;

	rc = odp_tm_node_connect(tm_node, parent_node);
	if (rc != 0) {
		LOG_ERR("%s odp_tm_node_connect() failed @ level=%u\n",
			__func__, level);
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
			LOG_ERR("%s - create_tm_queue() failed @ level=%u\n",
				__func__, level);
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
		LOG_ERR("%s - create_tm_node() failed @ level=%u\n",
			__func__, level);
		return NULL;
	}

	if (level < (num_levels - 1)) {
		for (child_idx = 0; child_idx < FANIN_RATIO; child_idx++) {
			child_desc = create_tm_subtree(odp_tm, level + 1,
						       num_levels, child_idx,
						       node_desc);
			if (child_desc == NULL) {
				LOG_ERR("%s create_tm_subtree failed lvl=%u\n",
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
		if (strcmp(node_desc->node_name, node_name) == 0)
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

static odp_tm_t create_tm_system(void)
{
	odp_tm_level_requirements_t *per_level;
	odp_tm_requirements_t        requirements;
	odp_tm_capabilities_t        capabilities;
	odp_tm_egress_t              egress;
	tm_node_desc_t              *root_node_desc;
	uint32_t                     level, max_nodes[ODP_TM_MAX_LEVELS];
	odp_tm_t                     odp_tm, found_odp_tm;
	char                         tm_name[TM_NAME_LEN];
	int                          rc;

	odp_tm_requirements_init(&requirements);
	odp_tm_egress_init(&egress);

	requirements.max_tm_queues              = NUM_TM_QUEUES + 1;
	requirements.num_levels                 = NUM_LEVELS;
	requirements.tm_queue_shaper_needed     = true;
	requirements.tm_queue_wred_needed       = true;
	requirements.tm_queue_dual_slope_needed = true;

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
	egress.pktout      = xmt_pktout;

	snprintf(tm_name, sizeof(tm_name), "TM_system_%u", num_odp_tm_systems);
	odp_tm = odp_tm_create(tm_name, &requirements, &egress);
	if (odp_tm == ODP_TM_INVALID) {
		LOG_ERR("%s odp_tm_create() failed\n", __func__);
		return ODP_TM_INVALID;
	}

	odp_tm_systems[num_odp_tm_systems] = odp_tm;

	root_node_desc = create_tm_subtree(odp_tm, 0, NUM_LEVELS, 0, NULL);
	root_node_descs[num_odp_tm_systems] = root_node_desc;
	if (root_node_desc == NULL) {
		LOG_ERR("%s - create_tm_subtree() failed\n", __func__);
		return ODP_TM_INVALID;
	}

	num_odp_tm_systems++;

	/* Test odp_tm_capability and odp_tm_find. */
	rc = odp_tm_capability(odp_tm, &capabilities);
	if (rc != 0) {
		LOG_ERR("%s odp_tm_capability() failed\n", __func__);
		return ODP_TM_INVALID;
	}

	found_odp_tm = odp_tm_find(tm_name, &requirements, &egress);
	if ((found_odp_tm == ODP_TM_INVALID) || (found_odp_tm != odp_tm)) {
		LOG_ERR("%s odp_tm_find() failed\n", __func__);
		return ODP_TM_INVALID;
	}

	return odp_tm;
}

static int unconfig_tm_queue_profiles(odp_tm_queue_t tm_queue)
{
	odp_tm_queue_info_t queue_info;
	odp_tm_wred_t       wred_profile;
	uint32_t            color;
	int                 rc;

	rc = odp_tm_queue_info(tm_queue, &queue_info);
	if (rc != 0) {
		LOG_ERR("odp_tm_queue_info failed code=%d\n", rc);
		return rc;
	}

	if (queue_info.shaper_profile != ODP_TM_INVALID) {
		rc = odp_tm_queue_shaper_config(tm_queue, ODP_TM_INVALID);
		if (rc != 0) {
			LOG_ERR("odp_tm_queue_shaper_config failed code=%d\n",
				rc);
			return rc;
		}
	}

	if (queue_info.threshold_profile != ODP_TM_INVALID) {
		rc = odp_tm_queue_threshold_config(tm_queue, ODP_TM_INVALID);
		if (rc != 0) {
			LOG_ERR("odp_tm_queue_threshold_config failed "
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
				LOG_ERR("odp_tm_queue_wred_config failed "
					"color=%u code=%d\n", color, rc);
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
				LOG_ERR("odp_tm_queue_disconnect failed "
					"idx=%u code=%d\n", queue_idx, rc);
				return rc;
			}

			rc = unconfig_tm_queue_profiles(tm_queue);
			if (rc != 0) {
				LOG_ERR("unconfig_tm_queue_profiles failed "
					"idx=%u code=%d\n", queue_idx, rc);
				return rc;
			}

			rc = odp_tm_queue_destroy(tm_queue);
			if (rc != 0) {
				LOG_ERR("odp_tm_queue_destroy failed "
					"idx=%u code=%d\n", queue_idx, rc);
				return rc;
			}
		}
	}

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
		LOG_ERR("odp_tm_node_info failed code=%d\n", rc);
		return rc;
	}

	if (node_info.shaper_profile != ODP_TM_INVALID) {
		rc = odp_tm_node_shaper_config(tm_node, ODP_TM_INVALID);
		if (rc != 0) {
			LOG_ERR("odp_tm_node_shaper_config failed code=%d\n",
				rc);
			return rc;
		}
	}

	if (node_info.threshold_profile != ODP_TM_INVALID) {
		rc = odp_tm_node_threshold_config(tm_node, ODP_TM_INVALID);
		if (rc != 0) {
			LOG_ERR("odp_tm_node_threshold_config failed "
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
				LOG_ERR("odp_tm_node_wred_config failed "
					"color=%u code=%d\n", color, rc);
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
				LOG_ERR("destroy_tm_subtree failed "
					"child_num=%u code=%d\n",
					child_num, rc);
				return rc;
			}
		}
	}

	queue_desc = node_desc->queue_desc;
	if (queue_desc != NULL) {
		rc = destroy_tm_queues(queue_desc);
		if (rc != 0) {
			LOG_ERR("destroy_tm_queues failed code=%d\n", rc);
			return rc;
		}
	}

	tm_node = node_desc->node;
	rc = odp_tm_node_disconnect(tm_node);
	if (rc != 0) {
		LOG_ERR("odp_tm_node_disconnect failed code=%d\n", rc);
		return rc;
	}

	rc = unconfig_tm_node_profiles(tm_node);
	if (rc != 0) {
		LOG_ERR("unconfig_tm_node_profiles failed code=%d\n", rc);
		return rc;
	}

	rc = odp_tm_node_destroy(tm_node);
	if (rc != 0) {
		LOG_ERR("odp_tm_node_destroy failed code=%d\n", rc);
		return rc;
	}

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
				LOG_ERR("odp_tm_sched_destroy failed "
					"idx=%u code=%d\n", idx, rc);
				return rc;
			}
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
				LOG_ERR("odp_tm_sched_destroy failed "
					"idx=%u code=%d\n", idx, rc);
				return rc;
			}
		}
	}

	return 0;
}

static int destroy_all_threshold_profiles(void)
{
	odp_tm_threshold_t threshold_profile;
	uint32_t           idx;
	int                rc;

	for (idx = 0; idx < NUM_THRESHOLD_PROFILES; idx++) {
		threshold_profile = threshold_profiles[idx];
		if (threshold_profile != ODP_TM_INVALID) {
			rc = odp_tm_threshold_destroy(threshold_profile);
			if (rc != 0) {
				LOG_ERR("odp_tm_threshold_destroy failed "
					"idx=%u code=%d\n", idx, rc);
				return rc;
			}
		}
	}

	return 0;
}

static int destroy_all_wred_profiles(void)
{
	odp_tm_wred_t wred_profile;
	uint32_t      idx, color;
	int           rc;

	for (idx = 0; idx < NUM_WRED_PROFILES; idx++) {
		for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
			wred_profile = wred_profiles[idx][color];
			if (wred_profile != ODP_TM_INVALID) {
				rc = odp_tm_wred_destroy(wred_profile);
				if (rc != 0) {
					LOG_ERR("odp_tm_wred_destroy failed "
						"idx=%u color=%u code=%d\n",
						idx, color, rc);
					return rc;
				}
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
		LOG_ERR("destroy_all_shaper_profiles failed code=%d\n", rc);
		return rc;
	}

	rc = destroy_all_sched_profiles();
	if (rc != 0) {
		LOG_ERR("destroy_all_sched_profiles failed code=%d\n", rc);
		return rc;
	}

	rc = destroy_all_threshold_profiles();
	if (rc != 0) {
		LOG_ERR("destroy_all_threshold_profiles failed code=%d\n", rc);
		return rc;
	}

	rc = destroy_all_wred_profiles();
	if (rc != 0) {
		LOG_ERR("destroy_all_wred_profiles failed code=%d\n", rc);
		return rc;
	}

	return 0;
}

int traffic_mngr_suite_init(void)
{
	uint32_t payload_len, copy_len;

	/* Initialize some global variables. */
	num_pkts_made = 0;
	num_pkts_sent = 0;
	num_rcv_pkts  = 0;
	memset(xmt_pkts, 0, sizeof(xmt_pkts));
	memset(rcv_pkts, 0, sizeof(rcv_pkts));
	odp_atomic_init_u32(&cpu_ip_ident, 1);

	payload_len = 0;
	while (payload_len < MAX_PAYLOAD) {
		copy_len = MIN(MAX_PAYLOAD - payload_len, sizeof(ALPHABET));
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

	if (open_pktios() != 0)
		return -1;

	/* Create the first/primary TM system. */
	create_tm_system();
	return 0;
}

int traffic_mngr_suite_term(void)
{
	uint32_t iface, idx;

	/* Close the pktios and associated packet pools. */
	free_rcvd_pkts();
	for (iface = 0; iface < num_ifaces; iface++) {
		if (odp_pool_destroy(pools[iface]) != 0)
			return -1;

		if (odp_pktio_close(pktios[iface]) != 0)
			return -1;
	}

	/* Close/free the TM systems. */
	for (idx = 0; idx < num_odp_tm_systems; idx++) {
		if (destroy_tm_subtree(root_node_descs[idx]) != 0)
			return -1;

		if (odp_tm_destroy(odp_tm_systems[idx]) != 0)
			return -1;
	}

	/* Close/free the TM profiles. */
	if (destroy_all_profiles() != 0)
		return -1;

	return 0;
}

static void check_shaper_profile(char *shaper_name, uint32_t shaper_idx)
{
	odp_tm_shaper_params_t shaper_params;
	odp_tm_shaper_t        profile;

	profile = odp_tm_shaper_lookup(shaper_name);
	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == shaper_profiles[shaper_idx - 1]);
	if (profile != shaper_profiles[shaper_idx - 1])
		return;

	odp_tm_shaper_params_read(profile, &shaper_params);
	CU_ASSERT(approx_eq64(shaper_params.commit_bps,
			      shaper_idx * MIN_COMMIT_BW));
	CU_ASSERT(approx_eq64(shaper_params.peak_bps,
			      shaper_idx * MIN_PEAK_BW));
	CU_ASSERT(approx_eq32(shaper_params.commit_burst,
			      shaper_idx * MIN_COMMIT_BURST));
	CU_ASSERT(approx_eq32(shaper_params.peak_burst,
			      shaper_idx * MIN_PEAK_BURST));

	CU_ASSERT(shaper_params.shaper_len_adjust == SHAPER_LEN_ADJ);
	CU_ASSERT(shaper_params.dual_rate         == 0);
}

void traffic_mngr_test_shaper_profile(void)
{
	odp_tm_shaper_params_t shaper_params;
	odp_tm_shaper_t        profile;
	uint32_t               idx, shaper_idx, i;
	char                   shaper_name[TM_NAME_LEN];

	odp_tm_shaper_params_init(&shaper_params);
	shaper_params.shaper_len_adjust = SHAPER_LEN_ADJ;
	shaper_params.dual_rate         = 0;

	for (idx = 1; idx <= NUM_SHAPER_PROFILES; idx++) {
		snprintf(shaper_name, sizeof(shaper_name),
			 "shaper_profile_%u", idx);
		shaper_params.commit_bps   = idx * MIN_COMMIT_BW;
		shaper_params.peak_bps     = idx * MIN_PEAK_BW;
		shaper_params.commit_burst = idx * MIN_COMMIT_BURST;
		shaper_params.peak_burst   = idx * MIN_PEAK_BURST;

		profile = odp_tm_shaper_create(shaper_name, &shaper_params);
		CU_ASSERT_FATAL(profile != ODP_TM_INVALID);

		/* Make sure profile handle is unique */
		for (i = 1; i < idx - 1; i++)
			CU_ASSERT(profile != shaper_profiles[i - 1]);

		shaper_profiles[idx - 1] = profile;
	}

	/* Now test odp_tm_shaper_lookup */
	for (idx = 1; idx <= NUM_SHAPER_PROFILES; idx++) {
		/* The following equation is designed is somewhat randomize
		 * the lookup of the profiles to catch any implementations
		 *taking shortcuts. */
		shaper_idx = ((3 + 7 * idx) % NUM_SHAPER_PROFILES) + 1;
		snprintf(shaper_name, sizeof(shaper_name),
			 "shaper_profile_%u", shaper_idx);

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

void traffic_mngr_test_sched_profile(void)
{
	odp_tm_sched_params_t sched_params;
	odp_tm_sched_t        profile;
	uint32_t              idx, priority, sched_idx, i;
	char                  sched_name[TM_NAME_LEN];

	odp_tm_sched_params_init(&sched_params);

	for (idx = 1; idx <= NUM_SCHED_PROFILES; idx++) {
		snprintf(sched_name, sizeof(sched_name),
			 "sched_profile_%u", idx);
		for (priority = 0; priority < 16; priority++) {
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
	}

	/* Now test odp_tm_sched_lookup */
	for (idx = 1; idx <= NUM_SCHED_PROFILES; idx++) {
		/* The following equation is designed is somewhat randomize
		 * the lookup of the profiles to catch any implementations
		 * taking shortcuts. */
		sched_idx = ((3 + 7 * idx) % NUM_SCHED_PROFILES) + 1;
		snprintf(sched_name, sizeof(sched_name), "sched_profile_%u",
			 sched_idx);
		check_sched_profile(sched_name, sched_idx);
	}
}

static void check_threshold_profile(char    *threshold_name,
				    uint32_t threshold_idx)
{
	odp_tm_threshold_params_t threshold_params;
	odp_tm_threshold_t        profile;

	profile = odp_tm_thresholds_lookup(threshold_name);
	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == threshold_profiles[threshold_idx - 1]);

	if (profile == threshold_profiles[threshold_idx - 1])
		return;

	odp_tm_thresholds_params_read(profile, &threshold_params);
	CU_ASSERT(threshold_params.max_pkts  ==
				  threshold_idx * MIN_PKT_THRESHOLD);
	CU_ASSERT(threshold_params.max_bytes ==
				  threshold_idx * MIN_BYTE_THRESHOLD);
	CU_ASSERT(threshold_params.enable_max_pkts  == 1);
	CU_ASSERT(threshold_params.enable_max_bytes == 1);
}

void traffic_mngr_test_threshold_profile(void)
{
	odp_tm_threshold_params_t threshold_params;
	odp_tm_threshold_t        profile;
	uint32_t                  idx, threshold_idx, i;
	char                      threshold_name[TM_NAME_LEN];

	odp_tm_threshold_params_init(&threshold_params);
	threshold_params.enable_max_pkts  = 1;
	threshold_params.enable_max_bytes = 1;

	for (idx = 1; idx <= NUM_THRESHOLD_PROFILES; idx++) {
		snprintf(threshold_name, sizeof(threshold_name),
			 "threshold_profile_%u", idx);
		threshold_params.max_pkts  = idx * MIN_PKT_THRESHOLD;
		threshold_params.max_bytes = idx * MIN_BYTE_THRESHOLD;

		profile = odp_tm_threshold_create(threshold_name,
						  &threshold_params);
		CU_ASSERT_FATAL(profile != ODP_TM_INVALID);

		/* Make sure profile handle is unique */
		for (i = 1; i < idx - 1; i++)
			CU_ASSERT(profile != threshold_profiles[i - 1]);

		threshold_profiles[idx - 1] = profile;
	}

	/* Now test odp_tm_threshold_lookup */
	for (idx = 1; idx <= NUM_THRESHOLD_PROFILES; idx++) {
		/* The following equation is designed is somewhat randomize
		 * the lookup of the profiles to catch any implementations
		 * taking shortcuts. */
		threshold_idx = ((3 + 7 * idx) % NUM_THRESHOLD_PROFILES) + 1;
		snprintf(threshold_name, sizeof(threshold_name),
			 "threshold_profile_%u", threshold_idx);
		check_threshold_profile(threshold_name, threshold_idx);
	}
}

static void check_wred_profile(char    *wred_name,
			       uint32_t wred_idx,
			       uint32_t color)
{
	odp_tm_wred_params_t wred_params;
	odp_tm_wred_t        profile;

	profile = odp_tm_wred_lookup(wred_name);
	CU_ASSERT(profile != ODP_TM_INVALID);
	CU_ASSERT(profile == wred_profiles[wred_idx - 1][color]);
	if (profile != wred_profiles[wred_idx - 1][color])
		return;

	odp_tm_wred_params_read(profile, &wred_params);
	CU_ASSERT(wred_params.min_threshold == wred_idx * MIN_WRED_THRESH);
	CU_ASSERT(wred_params.med_threshold == wred_idx * MED_WRED_THRESH);
	CU_ASSERT(wred_params.med_drop_prob == wred_idx * MED_DROP_PROB);
	CU_ASSERT(wred_params.max_drop_prob == wred_idx * MAX_DROP_PROB);

	CU_ASSERT(wred_params.enable_wred       == 1);
	CU_ASSERT(wred_params.use_byte_fullness == 0);
}

void traffic_mngr_test_wred_profile(void)
{
	odp_tm_wred_params_t wred_params;
	odp_tm_wred_t        profile;
	uint32_t             idx, color, wred_idx, i, c;
	char                 wred_name[TM_NAME_LEN];

	odp_tm_wred_params_init(&wred_params);
	wred_params.enable_wred       = 1;
	wred_params.use_byte_fullness = 0;

	for (idx = 1; idx <= NUM_WRED_PROFILES; idx++) {
		for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
			snprintf(wred_name, sizeof(wred_name),
				 "wred_profile_%u_%u", idx, color);
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
	}

	/* Now test odp_tm_wred_lookup */
	for (idx = 1; idx <= NUM_WRED_PROFILES; idx++) {
		/* The following equation is designed is somewhat randomize
		 * the lookup of the profiles to catch any implementations
		 * taking shortcuts. */
		wred_idx = ((3 + 7 * idx) % NUM_WRED_PROFILES) + 1;

		for (color = 0; color < ODP_NUM_PKT_COLORS; color++) {
			snprintf(wred_name, sizeof(wred_name),
				 "wred_profile_%u_%u", wred_idx, color);
			check_wred_profile(wred_name, wred_idx, color);
		}
	}
}

static int set_shaper(const char    *node_name,
		      const char    *shaper_name,
		      const uint64_t commit_bps,
		      const uint64_t commit_burst_in_bits)
{
	odp_tm_shaper_params_t shaper_params;
	odp_tm_shaper_t        shaper_profile;
	odp_tm_node_t          tm_node;

	tm_node = find_tm_node(0, node_name);
	if (tm_node == ODP_TM_INVALID) {
		LOG_ERR("\n%s find_tm_node(%s) failed\n", __func__, node_name);
		CU_ASSERT_FATAL(tm_node != ODP_TM_INVALID);
		return -1;
	}

	odp_tm_shaper_params_init(&shaper_params);
	shaper_params.commit_bps        = commit_bps;
	shaper_params.peak_bps          = 0;
	shaper_params.commit_burst      = commit_burst_in_bits;
	shaper_params.peak_burst        = 0;
	shaper_params.shaper_len_adjust = 0;
	shaper_params.dual_rate         = 0;

	/* First see if a shaper profile already exists with this name, in
	 * which case we use that profile, else create a new one. */
	shaper_profile = odp_tm_shaper_lookup(shaper_name);
	if (shaper_profile != ODP_TM_INVALID)
		odp_tm_shaper_params_update(shaper_profile, &shaper_params);
	else
		shaper_profile = odp_tm_shaper_create(shaper_name,
						      &shaper_params);

	return odp_tm_node_shaper_config(tm_node, shaper_profile);
}

static int test_shaper_bw(const char *shaper_name,
			  const char *node_name,
			  uint8_t     priority,
			  uint64_t    commit_bps)
{
	odp_tm_queue_t tm_queue;
	rcv_stats_t    rcv_stats;
	uint64_t       expected_rcv_gap_us;
	uint32_t       num_pkts, pkt_len, pkts_rcvd_in_order, avg_rcv_gap;
	uint32_t       min_rcv_gap, max_rcv_gap, pkts_sent, skip_pkt_cnt;
	uint8_t        pkt_class;
	int            rc;

	/* This test can support a commit_bps from 64K to 2 Gbps and possibly
	 * up to a max of 10 Gbps, but no higher. */
	CU_ASSERT_FATAL(commit_bps <= (10ULL * 1000000000ULL));

	/* Pick a tm_queue and set the parent node's shaper BW to be commit_bps
	 * with a small burst tolerance.  Then send the traffic with a pkt_len
	 * of 10,000 bits and measure the average inter arrival receive "gap"
	 * in microseconds. */
	tm_queue = find_tm_queue(0, node_name, priority);
	if (set_shaper(node_name, shaper_name, commit_bps, 10000) != 0)
		return -1;

	num_pkts  = 50;
	pkt_len   = 10000 / 8;
	pkt_class = 1;
	init_xmt_pkts();

	rc = make_pkts(num_pkts, pkt_len, ODP_PACKET_GREEN, false, pkt_class);
	if (rc != 0)
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

	/* First verify that all pkts were received AND in the same order sent.
	 */
	pkts_rcvd_in_order = pkts_rcvd_in_send_order();
	CU_ASSERT(pkts_rcvd_in_order == pkts_sent);
	if (32 <= pkts_rcvd_in_order) {
		/* Next determine the inter arrival receive pkt statistics -
		 * but just for the last 30 pkts. */
		skip_pkt_cnt = pkts_rcvd_in_order - 30;
		rc = rcv_rate_stats(&rcv_stats, pkt_class, skip_pkt_cnt);
		CU_ASSERT(rc == 0);

		/* Next verify that the last 30 pkts have an average
		 * inter-receive gap of "expected_rcv_gap_us" microseconds,
		 *  +/- 10%. */
		avg_rcv_gap = rcv_stats.avg_rcv_gap;
		min_rcv_gap = ((9  * expected_rcv_gap_us) / 10) - 2;
		max_rcv_gap = ((11 * expected_rcv_gap_us) / 10) + 2;
		CU_ASSERT((min_rcv_gap <= avg_rcv_gap) &&
			  (avg_rcv_gap <= max_rcv_gap));
		CU_ASSERT(rcv_stats.std_dev_gap <= expected_rcv_gap_us);
		if ((avg_rcv_gap < min_rcv_gap) ||
		    (max_rcv_gap < avg_rcv_gap) ||
		    (expected_rcv_gap_us < rcv_stats.std_dev_gap)) {
			LOG_ERR("%s min=%u avg_rcv_gap=%u max=%u "
				"std_dev_gap=%u\n", __func__,
				rcv_stats.min_rcv_gap, avg_rcv_gap,
				rcv_stats.max_rcv_gap, rcv_stats.std_dev_gap);
			LOG_ERR("  expected_rcv_gap=%" PRIu64
				" acceptable "
				"rcv_gap range=%u..%u\n",
				expected_rcv_gap_us, min_rcv_gap, max_rcv_gap);
		}
	}

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, shaper_name, 0, 0);
	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
	return 0;
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
	char                  sched_name[TM_NAME_LEN];
	int                   rc;

	node_desc = find_node_desc(0, node_name);
	if (node_desc == NULL)
		return -1;

	fanin_cnt = MIN(node_desc->num_children, FANIN_RATIO);
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
		snprintf(sched_name, sizeof(sched_name), "%s_%u",
			 sched_base_name, fanin);

		/* First see if a sched profile already exists with this name,
		 * in which case we use that profile, else create a new one. */
		sched_profile = odp_tm_sched_lookup(sched_name);
		if (sched_profile != ODP_TM_INVALID)
			odp_tm_sched_params_update(sched_profile,
						   &sched_params);
		else
			sched_profile = odp_tm_sched_create(sched_name,
							    &sched_params);

		/* Apply the weights to the nodes fan-in. */
		child_desc = node_desc->children[fanin];
		tm_node    = node_desc->node;
		fanin_node = child_desc->node;
		rc = odp_tm_node_sched_config(tm_node, fanin_node,
					      sched_profile);
		if (rc != 0)
			return -1;
	}

	return 0;
}

static int test_sched_queue_priority(const char *shaper_name,
				     const char *node_name,
				     uint32_t    num_pkts)
{
	odp_tm_queue_t tm_queues[NUM_PRIORITIES];
	uint32_t       pkt_cnt, pkts_in_order, base_idx;
	uint32_t       idx, ip_ident, pkt_len, pkts_sent;
	uint8_t        pkt_class;
	int            priority, rc;

	memset(ip_ident_list, 0, sizeof(ip_ident_list));
	for (priority = 0; priority < NUM_PRIORITIES; priority++)
		tm_queues[priority] = find_tm_queue(0, node_name, priority);

	/* Enable the shaper to be low bandwidth. */
	pkt_len = 1400;
	set_shaper(node_name, shaper_name, 64 * 1000, 4 * pkt_len);

	/* Make a couple of low priority dummy pkts first. */
	init_xmt_pkts();
	rc = make_pkts(4, pkt_len, ODP_PACKET_GREEN, false, 0);
	CU_ASSERT_FATAL(rc == 0);

	/* Now make "num_pkts" first at the lowest priority, then "num_pkts"
	 * at the second lowest priority, etc until "num_pkts" are made last
	 * at the highest priority (which is always priority 0). */
	pkt_cnt = NUM_PRIORITIES * num_pkts;
	pkt_len = 256;
	for (priority = NUM_PRIORITIES - 1; 0 <= priority; priority--) {
		ip_ident  = odp_atomic_load_u32(&cpu_ip_ident);
		pkt_class = priority + 1;
		rc = make_pkts(num_pkts, pkt_len + 64 * priority,
			       ODP_PACKET_GREEN, false, pkt_class);
		CU_ASSERT_FATAL(rc == 0);

		base_idx = priority * num_pkts;
		for (idx = 0; idx < num_pkts; idx++)
			ip_ident_list[base_idx + idx] = ip_ident++;
	}

	/* Send the low priority dummy pkts first.  The arrival order of
	 * these pkts will be ignored. */
	pkts_sent = send_pkts(tm_queues[NUM_PRIORITIES - 1], 4);

	/* Now send "num_pkts" first at the lowest priority, then "num_pkts"
	 * at the second lowest priority, etc until "num_pkts" are sent last
	 * at the highest priority. */
	for (priority = NUM_PRIORITIES - 1; 0 <= priority; priority--)
		pkts_sent += send_pkts(tm_queues[priority], num_pkts);

	busy_wait(1000000);   /* wait 1 millisecond */

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, shaper_name, 0, 0);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin,
				    pkt_cnt + 4, 64 * 1000);

	/* Check rcvd packet arrivals to make sure that pkts arrived in
	 * priority order, except for perhaps the first few lowest priority
	 * dummy pkts. */
	pkts_in_order = pkts_rcvd_in_given_order(ip_ident_list, pkt_cnt, 0,
						 false, false);
	CU_ASSERT(pkts_in_order == pkt_cnt);

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
	uint32_t        total_num_queues, max_queues, num_queues, pkt_cnt;
	uint32_t        pkts_in_order, base_idx, queue_idx, idx, ip_ident;
	uint32_t        pkt_len, total_pkt_cnt, pkts_sent;
	uint8_t         pkt_class;
	int             priority, rc;

	memset(ip_ident_list, 0, sizeof(ip_ident_list));
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
	init_xmt_pkts();
	rc = make_pkts(4, pkt_len, ODP_PACKET_GREEN, false, 0);
	CU_ASSERT_FATAL(rc == 0);

	/* Now make "num_pkts" for each tm_queue at the lowest priority, then
	 * "num_pkts" for each tm_queue at the second lowest priority, etc.
	 * until "num_pkts" for each tm_queue at the highest priority are made
	 * last.  Note that the highest priority is always priority 0. */
	total_pkt_cnt  = total_num_queues * num_pkts;
	pkt_len        = 256;
	base_idx       = 0;
	for (priority = NUM_PRIORITIES - 1; 0 <= priority; priority--) {
		ip_ident    = odp_atomic_load_u32(&cpu_ip_ident);
		queue_array = &queues_set.queue_array[priority];
		num_queues  = queue_array->num_queues;
		pkt_cnt     = num_queues * num_pkts;
		pkt_class   = priority + 1;
		rc          = make_pkts(pkt_cnt, pkt_len + 64 * priority,
					ODP_PACKET_GREEN, false, pkt_class);
		CU_ASSERT_FATAL(rc == 0);

		base_idx = priority * num_pkts;
		for (idx = 0; idx < pkt_cnt; idx++)
			ip_ident_list[base_idx + idx] = ip_ident++;
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

	busy_wait(1000000);   /* wait 1 millisecond */

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, shaper_name, 0, 0);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin,
				    pkts_sent, 64 * 1000);

	/* Check rcvd packet arrivals to make sure that pkts arrived in
	 * priority order, except for perhaps the first few lowest priority
	 * dummy pkts. */
	pkts_in_order = pkts_rcvd_in_given_order(ip_ident_list, total_pkt_cnt,
						 0, false, false);
	CU_ASSERT(pkts_in_order == total_pkt_cnt);

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
	fanin_cnt = MIN(node_desc->num_children, FANIN_RATIO);
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
	init_xmt_pkts();
	rc = make_pkts(4, pkt_len, ODP_PACKET_GREEN, false, 0);
	CU_ASSERT_FATAL(rc == 0);

	/* Make 100 pkts for each fanin of this node, alternating amongst
	 * the inputs. */
	pkt_cnt = FANIN_RATIO * 100;
	fanin = 0;
	for (pkt_idx = 0; pkt_idx < pkt_cnt; pkt_idx++) {
		pkt_len   = 128 + 128 * fanin;
		pkt_class = 1 + fanin++;
		rc = make_pkts(1, pkt_len, ODP_PACKET_GREEN, false, pkt_class);
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

	busy_wait(1000000);   /* wait 1 millisecond */

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, shaper_name, 0, 0);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin,
				    pkt_cnt + 4, 64 * 1000);

	/* Check rcvd packet arrivals to make sure that pkts arrived in
	 * an order commensurate with their weights, sched mode and pkt_len. */
	for (fanin = 0; fanin < fanin_cnt; fanin++) {
		pkt_class = 1 + fanin;
		CU_ASSERT(rcv_rate_stats(&rcv_stats[fanin], pkt_class, 0) == 0);
	}

	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
	return 0;
}

static int set_queue_thresholds(odp_tm_queue_t             tm_queue,
				const char                *threshold_name,
				odp_tm_threshold_params_t *threshold_params)
{
	odp_tm_threshold_t threshold_profile;

	/* First see if a threshold profile already exists with this name, in
	 * which case we use that profile, else create a new one. */
	threshold_profile = odp_tm_thresholds_lookup(threshold_name);
	if (threshold_profile != ODP_TM_INVALID)
		odp_tm_thresholds_params_update(threshold_profile,
						threshold_params);
	else
		threshold_profile = odp_tm_threshold_create(threshold_name,
							    threshold_params);

	return odp_tm_queue_threshold_config(tm_queue, threshold_profile);
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
	uint32_t                  num_pkts, pkt_len, pkts_sent;

	odp_tm_threshold_params_init(&threshold_params);
	if (max_pkts != 0) {
		max_pkts = MIN(max_pkts, MAX_PKTS / 3);
		threshold_params.max_pkts        = max_pkts;
		threshold_params.enable_max_pkts = true;
		num_pkts = 2 * max_pkts;
		pkt_len  = 256;
	} else if (max_bytes != 0) {
		max_bytes = MIN(max_bytes, MAX_PKTS * MAX_PAYLOAD / 3);
		threshold_params.max_bytes        = max_bytes;
		threshold_params.enable_max_bytes = true;
		num_pkts = 2 * max_bytes / MAX_PAYLOAD;
		pkt_len  = MAX_PAYLOAD;
	} else {
		return -1;
	}

	/* Pick a tm_queue and set the tm_queue's threshold profile and then
	 * send in twice the amount of traffic as suggested by the thresholds
	 * and make sure at least SOME pkts get dropped. */
	tm_queue = find_tm_queue(0, node_name, priority);
	if (set_queue_thresholds(tm_queue, threshold_name,
				 &threshold_params) != 0) {
		LOG_ERR("%s set_queue_thresholds failed\n", __func__);
		return -1;
	}

	/* Enable the shaper to be very low bandwidth. */
	set_shaper(node_name, shaper_name, 256 * 1000, 8 * pkt_len);

	init_xmt_pkts();
	if (make_pkts(num_pkts, pkt_len, ODP_PACKET_GREEN, true, 1) != 0) {
		LOG_ERR("%s make_pkts failed\n", __func__);
		return -1;
	}

	pkts_sent = send_pkts(tm_queue, num_pkts);

	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin, pkts_sent,
				    1 * GBPS);

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, shaper_name, 0, 0);
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
	table_size = sizeof(EXPECTED_PKT_RCVD) / sizeof(wred_pkt_cnts_t);
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

	/* First see if a wred profile already exists with this name, in
	 * which case we use that profile, else create a new one. */
	wred_profile = odp_tm_wred_lookup(wred_name);
	if (wred_profile != ODP_TM_INVALID)
		odp_tm_wred_params_update(wred_profile, &wred_params);
	else
		wred_profile = odp_tm_wred_create(wred_name, &wred_params);

	return odp_tm_queue_wred_config(tm_queue, pkt_color, wred_profile);
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
	uint32_t                  num_fill_pkts, num_test_pkts, pkts_sent;

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
		LOG_ERR("%s set_queue_thresholds failed\n", __func__);
		return -1;
	}

	/* Make and send the first batch of pkts whose job is to set the
	 * queue byte fullness to around 60% for the subsequent test packets.
	 * These packets MUST have drop_eligible false. */
	num_fill_pkts = 120;
	init_xmt_pkts();
	if (make_pkts(num_fill_pkts, PKT_BUF_SIZE, pkt_color, false, 0) != 0)
		return -1;

	send_pkts(tm_queue, num_fill_pkts);

	/* Now send the real test pkts, which are all small so as to try to
	 * keep the byte fullness still close to the 60% point. These pkts
	 * MUST have drop_eligible true. */
	num_test_pkts = 100;
	if (make_pkts(num_test_pkts, 128, pkt_color, true, 1) != 0)
		return -1;

	pkts_sent = send_pkts(tm_queue, num_test_pkts);

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, shaper_name, 0, 0);
	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin,
				    num_fill_pkts + pkts_sent, 64 * 1000);

	/* Search the EXPECTED_PKT_RCVD table to find a matching entry */
	wred_pkt_cnts = search_expected_pkt_rcv_tbl(TM_PERCENT(99.9),
						    drop_percent);
	if (wred_pkt_cnts == NULL)
		return -1;

	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));

	if ((wred_pkt_cnts->min_cnt <= pkts_sent) &&
	    (pkts_sent <= wred_pkt_cnts->max_cnt))
		return 0;

	CU_ASSERT((wred_pkt_cnts->min_cnt <= pkts_sent) &&
		  (pkts_sent <= wred_pkt_cnts->max_cnt));
	return 0;
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
	uint32_t                  num_fill_pkts, num_test_pkts, pkts_sent;

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
	if (set_queue_thresholds(tm_queue, threshold_name,
				 &threshold_params) != 0) {
		LOG_ERR("%s set_queue_thresholds failed\n", __func__);
		return -1;
	}

	/* Make and send the first batch of pkts whose job is to set the
	 * queue pkt fullness to around 60% for the subsequent test packets.
	 * These packets MUST have drop_eligible false. */
	num_fill_pkts = 600;
	init_xmt_pkts();
	if (make_pkts(num_fill_pkts, 80, pkt_color, false, 0) != 0)
		return -1;

	send_pkts(tm_queue, num_fill_pkts);

	/* Now send the real test pkts.  These pkts MUST have drop_eligible
	 * true. */
	num_test_pkts = 100;
	if (make_pkts(num_test_pkts, 80, pkt_color, true, 1) != 0)
		return -1;

	pkts_sent = send_pkts(tm_queue, num_test_pkts);

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, shaper_name, 0, 0);
	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin,
				    num_fill_pkts + pkts_sent, 64 * 1000);

	/* Search the EXPECTED_PKT_RCVD table to find a matching entry */
	wred_pkt_cnts = search_expected_pkt_rcv_tbl(TM_PERCENT(99.9),
						    drop_percent);
	if (wred_pkt_cnts == NULL)
		return -1;

	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));

	if ((wred_pkt_cnts->min_cnt <= pkts_sent) &&
	    (pkts_sent <= wred_pkt_cnts->max_cnt))
		return 0;

	CU_ASSERT((wred_pkt_cnts->min_cnt <= pkts_sent) &&
		  (pkts_sent <= wred_pkt_cnts->max_cnt));
	return 0;
}

static int test_query_functions(const char *shaper_name,
				const char *node_name,
				uint8_t     priority,
				uint32_t    num_pkts)
{
	odp_tm_query_info_t query_info;
	odp_tm_queue_t      tm_queue;
	uint64_t            commit_bps, expected_pkt_cnt, expected_byte_cnt;
	int                 rc;

	/* Pick a tm_queue and set the egress node's shaper BW to be 64K bps
	 * with a small burst tolerance.  Then send the traffic. */
	tm_queue   = find_tm_queue(0, node_name, priority);
	commit_bps = 64 * 1000;
	if (set_shaper(node_name, shaper_name, commit_bps, 1000) != 0)
		return -1;

	init_xmt_pkts();
	if (make_pkts(num_pkts, PKT_BUF_SIZE, ODP_PACKET_GREEN, false, 1) != 0)
		return -1;

	send_pkts(tm_queue, num_pkts);

	/* Assume all but 2 of the pkts are still in the queue.*/
	expected_pkt_cnt  = num_pkts - 2;
	expected_byte_cnt = expected_pkt_cnt * PKT_BUF_SIZE;

	rc = odp_tm_queue_query(tm_queue,
				ODP_TM_QUERY_PKT_CNT | ODP_TM_QUERY_BYTE_CNT,
				&query_info);
	CU_ASSERT(rc == 0);
	CU_ASSERT(query_info.total_pkt_cnt_valid);
	CU_ASSERT(expected_pkt_cnt < query_info.total_pkt_cnt);
	CU_ASSERT(query_info.total_byte_cnt_valid);
	CU_ASSERT(expected_byte_cnt < query_info.total_byte_cnt);

	rc = odp_tm_priority_query(odp_tm_systems[0], priority,
				   ODP_TM_QUERY_PKT_CNT | ODP_TM_QUERY_BYTE_CNT,
				   &query_info);
	CU_ASSERT(rc == 0);
	CU_ASSERT(query_info.total_pkt_cnt_valid);
	CU_ASSERT(expected_pkt_cnt < query_info.total_pkt_cnt);
	CU_ASSERT(query_info.total_byte_cnt_valid);
	CU_ASSERT(expected_byte_cnt < query_info.total_byte_cnt);

	rc = odp_tm_total_query(odp_tm_systems[0],
				ODP_TM_QUERY_PKT_CNT | ODP_TM_QUERY_BYTE_CNT,
				&query_info);
	CU_ASSERT(rc == 0);
	CU_ASSERT(query_info.total_pkt_cnt_valid);
	CU_ASSERT(expected_pkt_cnt < query_info.total_pkt_cnt);
	CU_ASSERT(query_info.total_byte_cnt_valid);
	CU_ASSERT(expected_byte_cnt < query_info.total_byte_cnt);

	/* Disable the shaper, so as to get the pkts out quicker. */
	set_shaper(node_name, shaper_name, 0, 0);
	num_rcv_pkts = receive_pkts(odp_tm_systems[0], rcv_pktin, num_pkts,
				    commit_bps);

	flush_leftover_pkts(odp_tm_systems[0], rcv_pktin);
	CU_ASSERT(odp_tm_is_idle(odp_tm_systems[0]));
	return 0;
}

void traffic_mngr_test_shaper(void)
{
	CU_ASSERT(test_shaper_bw("bw1",   "node_1_1_1", 0, 1   * MBPS) == 0);
	CU_ASSERT(test_shaper_bw("bw4",   "node_1_1_1", 1, 4   * MBPS) == 0);
	CU_ASSERT(test_shaper_bw("bw10",  "node_1_1_1", 2, 10  * MBPS) == 0);
	CU_ASSERT(test_shaper_bw("bw40",  "node_1_1_1", 3, 40  * MBPS) == 0);
	CU_ASSERT(test_shaper_bw("bw100", "node_1_1_2", 0, 100 * MBPS) == 0);
}

void traffic_mngr_test_scheduler(void)
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

void traffic_mngr_test_thresholds(void)
{
	CU_ASSERT(test_threshold("thresh_A", "shaper_A", "node_1_2_1", 0,
				 16, 0)    == 0);
	CU_ASSERT(test_threshold("thresh_B", "shaper_B", "node_1_2_1", 1,
				 0,  6400) == 0);
}

void traffic_mngr_test_byte_wred(void)
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

void traffic_mngr_test_pkt_wred(void)
{
	CU_ASSERT(test_pkt_wred("pkt_wred_30G", "pkt_bw_30G",
				"pkt_thresh_30G", "node_1_3_2", 1,
				ODP_PACKET_GREEN, TM_PERCENT(30), true) == 0);
	CU_ASSERT(test_pkt_wred("pkt_wred_50Y", "pkt_bw_50Y",
				"pkt_thresh_50Y", "node_1_3_2", 2,
				ODP_PACKET_YELLOW, TM_PERCENT(50), true) == 0);
	CU_ASSERT(test_pkt_wred("pkt_wred_70R", "pkt_bw_70R",
				"pkt_thresh_70R", "node_1_3_2", 3,
				ODP_PACKET_RED,    TM_PERCENT(70), true) == 0);

	CU_ASSERT(test_pkt_wred("pkt_wred_40G", "pkt_bw_40G",
				"pkt_thresh_40G", "node_1_3_2", 1,
				ODP_PACKET_GREEN, TM_PERCENT(30), false) == 0);
}

void traffic_mngr_test_query(void)
{
	CU_ASSERT(test_query_functions("query_shaper", "node_1_3_3", 3, 10)
		  == 0);
}

odp_testinfo_t traffic_mngr_suite[] = {
	ODP_TEST_INFO(traffic_mngr_test_shaper_profile),
	ODP_TEST_INFO(traffic_mngr_test_sched_profile),
	ODP_TEST_INFO(traffic_mngr_test_threshold_profile),
	ODP_TEST_INFO(traffic_mngr_test_wred_profile),
	ODP_TEST_INFO(traffic_mngr_test_shaper),
	ODP_TEST_INFO(traffic_mngr_test_scheduler),
	ODP_TEST_INFO(traffic_mngr_test_thresholds),
	ODP_TEST_INFO(traffic_mngr_test_byte_wred),
	ODP_TEST_INFO(traffic_mngr_test_pkt_wred),
	ODP_TEST_INFO(traffic_mngr_test_query),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t traffic_mngr_suites[] = {
	{ "traffic_mngr tests", traffic_mngr_suite_init,
	  traffic_mngr_suite_term, traffic_mngr_suite },
	ODP_SUITE_INFO_NULL
};

int traffic_mngr_main(void)
{
	int ret = odp_cunit_register(traffic_mngr_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

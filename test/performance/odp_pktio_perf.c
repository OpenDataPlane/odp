/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 *
 * ODP Packet IO basic performance test application.
 *
 * Runs a number of transmit and receive workers on separate cores, the
 * transmitters generate packets at a defined rate and the receivers consume
 * them. Generated packets are UDP and each packet is marked with a magic
 * number in the UDP payload allowing receiver to distinguish them from other
 * traffic.
 *
 * Each test iteration runs for a fixed period, at the end of the iteration
 * it is verified that the number of packets transmitted was as expected and
 * that all transmitted packets were received.
 *
 * The default mode is to run multiple test iterations at different rates to
 * determine the maximum rate at which no packet loss occurs. Alternatively
 * a single packet rate can be specified on the command line.
 *
 */

#include <odp_api.h>

#include <odp/helper/odph_api.h>

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#define TEST_SKIP 77

#define PKT_BUF_NUM       (32 * 1024)
#define MAX_NUM_IFACES    2
#define TEST_HDR_MAGIC    0x92749451
#define MAX_WORKERS       (ODP_THREAD_COUNT_MAX - 1)
#define BATCH_LEN_MAX     32

/* Packet rate at which to start when using binary search */
#define RATE_SEARCH_INITIAL_PPS 1000000

/* When using the binary search method to determine the maximum
 * achievable packet rate, this value specifies how close the pass
 * and fail measurements must be before the test is terminated. */
#define RATE_SEARCH_ACCURACY_PPS 100000

/* Amount of time to wait, in nanoseconds, between the transmitter(s)
 * completing and the receiver(s) being shutdown. Any packets not
 * received by this time will be assumed to have been lost. */
#define SHUTDOWN_DELAY_NS (ODP_TIME_MSEC_IN_NS * 100)

#define VPRINT(fmt, ...) \
	do { \
		if (gbl_args->args.verbose) \
			printf(fmt, ##__VA_ARGS__); \
	} while (0)

#define CACHE_ALIGN_ROUNDUP(x)\
	((ODP_CACHE_LINE_SIZE) * \
	 (((x) + ODP_CACHE_LINE_SIZE - 1) / (ODP_CACHE_LINE_SIZE)))

#define PKT_HDR_LEN (sizeof(pkt_head_t) + ODPH_UDPHDR_LEN + \
		     ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN)

/** Parsed command line application arguments */
typedef struct {
	unsigned int cpu_count;	/* CPU count */
	int      num_tx_workers;/* Number of CPUs to use for transmit */
	int      duration;	/* Number of seconds to run each iteration
				   of the test for */
	uint32_t tx_batch_len;	/* Number of packets to send in a single
				   batch */
	int      schedule;	/* 1: receive packets via scheduler
				   0: receive packets via direct deq */
	uint32_t rx_batch_len;	/* Number of packets to receive in a single
				   batch */
	uint64_t pps;		/* Attempted packet rate */
	int      verbose;	/* Print verbose information, such as per
				   thread statistics */
	unsigned pkt_len;	/* Packet payload length in bytes (not
				   including headers) */
	int      search;	/* Set implicitly when pps is not configured.
				   Perform a search at different packet rates
				   to determine the maximum rate at which no
				   packet loss occurs. */

	char     *if_str;
	const char *ifaces[MAX_NUM_IFACES];
	int      num_ifaces;
} test_args_t;

struct rx_stats_s {
	uint64_t rx_cnt;	/* Valid packets received */
	uint64_t rx_ignore;	/* Ignored packets */
};

typedef union rx_stats_u {
	struct rx_stats_s s;
	uint8_t pad[CACHE_ALIGN_ROUNDUP(sizeof(struct rx_stats_s))];
} pkt_rx_stats_t;

struct tx_stats_s {
	uint64_t tx_cnt;	/* Packets transmitted */
	uint64_t alloc_failures;/* Packet allocation failures */
	uint64_t enq_failures;	/* Enqueue failures */
	odp_time_t idle_ticks;	/* Idle ticks count in TX loop */
};

typedef union tx_stats_u {
	struct tx_stats_s s;
	uint8_t pad[CACHE_ALIGN_ROUNDUP(sizeof(struct tx_stats_s))];
} pkt_tx_stats_t;

/* Test global variables */
typedef struct {
	odp_instance_t instance;
	test_args_t args;
	odp_barrier_t rx_barrier;
	odp_barrier_t tx_barrier;
	odp_pktio_t pktio_tx;
	odp_pktio_t pktio_rx;
	/* Pool from which transmitted packets are allocated */
	odp_pool_t transmit_pkt_pool;
	pkt_rx_stats_t *rx_stats;
	pkt_tx_stats_t *tx_stats;
	uint8_t src_mac[ODPH_ETHADDR_LEN];
	uint8_t dst_mac[ODPH_ETHADDR_LEN];
	uint32_t rx_stats_size;
	uint32_t tx_stats_size;
	/* Indicate to the receivers to shutdown */
	odp_atomic_u32_t shutdown;
	/* Sequence number of IP packets */
	odp_atomic_u32_t ODP_ALIGNED_CACHE ip_seq;
} test_globals_t;

/* Status of max rate search */
typedef struct {
	uint64_t pps_curr; /* Current attempted PPS */
	uint64_t pps_pass; /* Highest passing PPS */
	uint64_t pps_fail; /* Lowest failing PPS */
	int      warmup;   /* Warmup stage - ignore results */
} test_status_t;

/* Thread specific arguments */
typedef struct {
	int batch_len; /* Number of packets per transmit batch */
	int duration;  /* Run duration in seconds */
	uint64_t pps;  /* Packets per second for this thread */
} thread_args_t;

typedef struct {
	odp_u32be_t magic; /* Packet header magic number */
} pkt_head_t;

/* Application global data */
static test_globals_t *gbl_args;

/*
 * Generate a single test packet for transmission.
 */
static odp_packet_t pktio_create_packet(uint32_t seq)
{
	odp_packet_t pkt;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	char *buf;
	uint32_t offset;
	pkt_head_t pkt_hdr;
	size_t payload_len;

	payload_len = sizeof(pkt_hdr) + gbl_args->args.pkt_len;

	pkt = odp_packet_alloc(gbl_args->transmit_pkt_pool,
			       payload_len + ODPH_UDPHDR_LEN +
			       ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);

	if (pkt == ODP_PACKET_INVALID)
		return ODP_PACKET_INVALID;

	buf = odp_packet_data(pkt);

	/* Ethernet */
	offset = 0;
	odp_packet_l2_offset_set(pkt, offset);
	eth = (odph_ethhdr_t *)buf;
	memcpy(eth->src.addr, gbl_args->src_mac, ODPH_ETHADDR_LEN);
	memcpy(eth->dst.addr, gbl_args->dst_mac, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	/* IP */
	offset += ODPH_ETHHDR_LEN;
	odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(0);
	ip->src_addr = odp_cpu_to_be_32(0);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(payload_len + ODPH_UDPHDR_LEN +
				       ODPH_IPV4HDR_LEN);
	ip->ttl = 128;
	ip->proto = ODPH_IPPROTO_UDP;
	ip->id = odp_cpu_to_be_16(seq);
	ip->chksum = 0;
	odph_ipv4_csum_update(pkt);

	/* UDP */
	offset += ODPH_IPV4HDR_LEN;
	odp_packet_l4_offset_set(pkt, offset);
	udp = (odph_udphdr_t *)(buf + offset);
	udp->src_port = odp_cpu_to_be_16(0);
	udp->dst_port = odp_cpu_to_be_16(0);
	udp->length = odp_cpu_to_be_16(payload_len + ODPH_UDPHDR_LEN);
	udp->chksum = 0;

	/* payload */
	offset += ODPH_UDPHDR_LEN;
	pkt_hdr.magic = TEST_HDR_MAGIC;
	if (odp_packet_copy_from_mem(pkt, offset, sizeof(pkt_hdr),
				     &pkt_hdr) != 0)
		ODPH_ABORT("Failed to generate test packet.\n");

	return pkt;
}

/*
 * Check if a packet payload contains test payload magic number.
 */
static int pktio_pkt_has_magic(odp_packet_t pkt)
{
	size_t l4_off;
	pkt_head_t pkt_hdr;

	l4_off = ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN;
	int ret = odp_packet_copy_to_mem(pkt,
					 l4_off + ODPH_UDPHDR_LEN,
					 sizeof(pkt_hdr), &pkt_hdr);

	if (ret != 0)
		return 0;

	if (pkt_hdr.magic == TEST_HDR_MAGIC)
		return 1;

	return 0;
}

/*
 * Allocate packets for transmission.
 */
static int alloc_packets(odp_packet_t *pkt_tbl, int num_pkts)
{
	int n;
	uint16_t seq;

	seq = odp_atomic_fetch_add_u32(&gbl_args->ip_seq, num_pkts);
	for (n = 0; n < num_pkts; ++n) {
		pkt_tbl[n] = pktio_create_packet(seq + n);
		if (pkt_tbl[n] == ODP_PACKET_INVALID)
			break;
	}

	return n;
}

static int send_packets(odp_pktout_queue_t pktout,
			odp_packet_t *pkt_tbl, unsigned pkts)
{
	unsigned tx_drops;
	unsigned sent = 0;

	if (pkts == 0)
		return 0;

	while (sent < pkts) {
		int ret;

		ret = odp_pktout_send(pktout, &pkt_tbl[sent], pkts - sent);

		if (odp_likely(ret > 0))
			sent += ret;
		else
			break;
	}

	tx_drops = pkts - sent;

	if (odp_unlikely(tx_drops))
		odp_packet_free_multi(&pkt_tbl[sent], tx_drops);

	return sent;
}

/*
 * Main packet transmit routine. Transmit packets at a fixed rate for
 * specified length of time.
 */
static int run_thread_tx(void *arg)
{
	test_globals_t *globals;
	int thr_id;
	odp_pktout_queue_t pktout;
	pkt_tx_stats_t *stats;
	odp_time_t cur_time, send_time_end, send_duration;
	odp_time_t burst_gap_end, burst_gap;
	uint32_t batch_len;
	int unsent_pkts = 0;
	odp_packet_t tx_packet[BATCH_LEN_MAX];
	odp_time_t idle_start = ODP_TIME_NULL;

	thread_args_t *targs = arg;

	batch_len = targs->batch_len;

	if (batch_len > BATCH_LEN_MAX)
		batch_len = BATCH_LEN_MAX;

	thr_id = odp_thread_id();

	globals = odp_shm_addr(odp_shm_lookup("test_globals"));
	stats = &globals->tx_stats[thr_id];

	if (odp_pktout_queue(globals->pktio_tx, &pktout, 1) != 1)
		ODPH_ABORT("Failed to get output queue for thread %d\n",
			   thr_id);

	burst_gap = odp_time_local_from_ns(
			ODP_TIME_SEC_IN_NS / (targs->pps / targs->batch_len));
	send_duration =
		odp_time_local_from_ns(targs->duration * ODP_TIME_SEC_IN_NS);

	odp_barrier_wait(&globals->tx_barrier);

	cur_time     = odp_time_local();
	send_time_end = odp_time_sum(cur_time, send_duration);
	burst_gap_end = cur_time;
	while (odp_time_cmp(send_time_end, cur_time) > 0) {
		unsigned alloc_cnt = 0, tx_cnt;

		if (odp_time_cmp(burst_gap_end, cur_time) > 0) {
			cur_time = odp_time_local();
			if (!odp_time_cmp(idle_start, ODP_TIME_NULL))
				idle_start = cur_time;
			continue;
		}

		if (odp_time_cmp(idle_start, ODP_TIME_NULL) > 0) {
			odp_time_t diff = odp_time_diff(cur_time, idle_start);

			stats->s.idle_ticks =
				odp_time_sum(diff, stats->s.idle_ticks);

			idle_start = ODP_TIME_NULL;
		}

		burst_gap_end = odp_time_sum(burst_gap_end, burst_gap);

		alloc_cnt = alloc_packets(tx_packet, batch_len - unsent_pkts);
		if (alloc_cnt != batch_len)
			stats->s.alloc_failures++;

		tx_cnt = send_packets(pktout, tx_packet, alloc_cnt);
		unsent_pkts = alloc_cnt - tx_cnt;
		stats->s.enq_failures += unsent_pkts;
		stats->s.tx_cnt += tx_cnt;

		cur_time = odp_time_local();
	}

	VPRINT(" %02d: TxPkts %-8" PRIu64 " EnqFail %-6" PRIu64
	       " AllocFail %-6" PRIu64 " Idle %" PRIu64 "ms\n",
	       thr_id, stats->s.tx_cnt,
	       stats->s.enq_failures, stats->s.alloc_failures,
	       odp_time_to_ns(stats->s.idle_ticks) /
	       (uint64_t)ODP_TIME_MSEC_IN_NS);

	return 0;
}

static int receive_packets(odp_queue_t queue,
			   odp_event_t *event_tbl, unsigned num_pkts)
{
	int n_ev = 0;

	if (num_pkts == 0)
		return 0;

	if (queue != ODP_QUEUE_INVALID) {
		if (num_pkts == 1) {
			event_tbl[0] = odp_queue_deq(queue);
			n_ev = event_tbl[0] != ODP_EVENT_INVALID;
		} else {
			n_ev = odp_queue_deq_multi(queue, event_tbl, num_pkts);
		}
	} else {
		if (num_pkts == 1) {
			event_tbl[0] = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
			n_ev = event_tbl[0] != ODP_EVENT_INVALID;
		} else {
			n_ev = odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT,
						  event_tbl, num_pkts);
		}
	}
	return n_ev;
}

static int run_thread_rx(void *arg)
{
	test_globals_t *globals;
	int thr_id, batch_len;
	odp_queue_t queue = ODP_QUEUE_INVALID;
	odp_packet_t pkt;

	thread_args_t *targs = arg;

	batch_len = targs->batch_len;

	if (batch_len > BATCH_LEN_MAX)
		batch_len = BATCH_LEN_MAX;

	thr_id = odp_thread_id();

	globals = odp_shm_addr(odp_shm_lookup("test_globals"));

	pkt_rx_stats_t *stats = &globals->rx_stats[thr_id];

	if (gbl_args->args.schedule == 0) {
		if (odp_pktin_event_queue(globals->pktio_rx, &queue, 1) != 1)
			ODPH_ABORT("No input queue.\n");
	}

	odp_barrier_wait(&globals->rx_barrier);
	while (1) {
		odp_event_t ev[BATCH_LEN_MAX];
		int i, n_ev;

		n_ev = receive_packets(queue, ev, batch_len);

		for (i = 0; i < n_ev; ++i) {
			if (odp_event_type(ev[i]) == ODP_EVENT_PACKET) {
				pkt = odp_packet_from_event(ev[i]);
				if (pktio_pkt_has_magic(pkt))
					stats->s.rx_cnt++;
				else
					stats->s.rx_ignore++;
			}
			odp_event_free(ev[i]);
		}
		if (n_ev == 0 && odp_atomic_load_u32(&gbl_args->shutdown))
			break;
	}

	return 0;
}

/*
 * Process the results from a single fixed rate test run to determine whether
 * it passed or failed. Pass criteria are that the requested transmit packet
 * rate was achieved and that all of the transmitted packets were received.
 */
static int process_results(uint64_t expected_tx_cnt,
			   test_status_t *status)
{
	int fail = 0;
	uint64_t drops = 0;
	uint64_t rx_pkts = 0;
	uint64_t tx_pkts = 0;
	uint64_t attempted_pps;
	int i;
	char str[512];
	int len = 0;

	for (i = 0; i < odp_thread_count_max(); ++i) {
		rx_pkts += gbl_args->rx_stats[i].s.rx_cnt;
		tx_pkts += gbl_args->tx_stats[i].s.tx_cnt;
	}

	if (rx_pkts == 0) {
		ODPH_ERR("no packets received\n");
		return -1;
	}

	if (tx_pkts < (expected_tx_cnt - (expected_tx_cnt / 100))) {
		/* failed to transmit packets at (99% of) requested rate */
		fail = 1;
	} else if (tx_pkts > rx_pkts) {
		/* failed to receive all of the transmitted packets */
		fail = 1;
		drops = tx_pkts - rx_pkts;
	}

	attempted_pps = status->pps_curr;

	len += snprintf(&str[len], sizeof(str) - 1 - len,
			"PPS: %-8" PRIu64 " ", attempted_pps);
	len += snprintf(&str[len], sizeof(str) - 1 - len,
			"Succeeded: %-4s ", fail ? "No" : "Yes");
	len += snprintf(&str[len], sizeof(str) - 1 - len,
			"TxPkts: %-8" PRIu64 " ", tx_pkts);
	len += snprintf(&str[len], sizeof(str) - 1 - len,
			"RxPkts: %-8" PRIu64 " ", rx_pkts);
	len += snprintf(&str[len], sizeof(str) - 1 - len,
			"DropPkts: %-8" PRIu64 " ", drops);
	printf("%s\n", str);

	if (gbl_args->args.search == 0) {
		printf("Result: %s\n", fail ? "FAILED" : "PASSED");
		return fail ? -1 : 0;
	}

	if (fail && (status->pps_fail == 0 ||
		     attempted_pps < status->pps_fail)) {
		status->pps_fail = attempted_pps;
	} else if (attempted_pps > status->pps_pass) {
		status->pps_pass = attempted_pps;
	}

	if (status->pps_fail == 0) {
		/* ramping up, double the previously attempted pps */
		status->pps_curr *= 2;
	} else {
		/* set the new target to half way between the upper and lower
		 * limits */
		status->pps_curr = status->pps_pass +
				   ((status->pps_fail - status->pps_pass) / 2);
	}

	/* stop once the pass and fail measurements are within range */
	if ((status->pps_fail - status->pps_pass) < RATE_SEARCH_ACCURACY_PPS) {
		unsigned pkt_len = gbl_args->args.pkt_len + PKT_HDR_LEN;
		int mbps = (pkt_len * status->pps_pass * 8) / 1024 / 1024;

		printf("Maximum packet rate: %" PRIu64 " PPS (%d Mbps)\n",
		       status->pps_pass, mbps);

		return 0;
	}

	return 1;
}

static int setup_txrx_masks(odp_cpumask_t *thd_mask_tx,
			    odp_cpumask_t *thd_mask_rx)
{
	odp_cpumask_t cpumask;
	int num_workers, num_tx_workers, num_rx_workers;
	int i, cpu;

	num_workers =
		odp_cpumask_default_worker(&cpumask,
					   gbl_args->args.cpu_count);
	if (num_workers < 2) {
		ODPH_ERR("Need at least two cores\n");
		return TEST_SKIP;
	}

	if (num_workers > MAX_WORKERS) {
		ODPH_DBG("Worker count limited to MAX_WORKERS define (=%d)\n",
			 MAX_WORKERS);
		num_workers = MAX_WORKERS;
	}

	if (gbl_args->args.num_tx_workers) {
		if (gbl_args->args.num_tx_workers > (num_workers - 1)) {
			ODPH_ERR("Invalid TX worker count\n");
			return -1;
		}
		num_tx_workers = gbl_args->args.num_tx_workers;
	} else {
		/* default is to split the available cores evenly into TX and
		 * RX workers, favour TX for odd core count */
		num_tx_workers = (num_workers + 1) / 2;
	}

	odp_cpumask_zero(thd_mask_tx);
	odp_cpumask_zero(thd_mask_rx);

	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; ++i) {
		if (i < num_tx_workers)
			odp_cpumask_set(thd_mask_tx, cpu);
		else
			odp_cpumask_set(thd_mask_rx, cpu);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	num_rx_workers = odp_cpumask_count(thd_mask_rx);

	odp_barrier_init(&gbl_args->rx_barrier, num_rx_workers + 1);
	odp_barrier_init(&gbl_args->tx_barrier, num_tx_workers + 1);

	return 0;
}

/*
 * Run a single instance of the throughput test. When attempting to determine
 * the maximum packet rate this will be invoked multiple times with the only
 * difference between runs being the target PPS rate.
 */
static int run_test_single(odp_cpumask_t *thd_mask_tx,
			   odp_cpumask_t *thd_mask_rx,
			   test_status_t *status)
{
	odph_odpthread_t thd_tbl[MAX_WORKERS];
	thread_args_t args_tx, args_rx;
	uint64_t expected_tx_cnt;
	int num_tx_workers, num_rx_workers;
	odph_odpthread_params_t thr_params;

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = gbl_args->instance;

	odp_atomic_store_u32(&gbl_args->shutdown, 0);

	memset(thd_tbl, 0, sizeof(thd_tbl));
	memset(gbl_args->rx_stats, 0, gbl_args->rx_stats_size);
	memset(gbl_args->tx_stats, 0, gbl_args->tx_stats_size);

	expected_tx_cnt = status->pps_curr * gbl_args->args.duration;

	/* start receiver threads first */
	thr_params.start  = run_thread_rx;
	thr_params.arg    = &args_rx;
	args_rx.batch_len = gbl_args->args.rx_batch_len;
	odph_odpthreads_create(&thd_tbl[0], thd_mask_rx, &thr_params);
	odp_barrier_wait(&gbl_args->rx_barrier);
	num_rx_workers = odp_cpumask_count(thd_mask_rx);

	/* then start transmitters */
	thr_params.start  = run_thread_tx;
	thr_params.arg    = &args_tx;
	num_tx_workers    = odp_cpumask_count(thd_mask_tx);
	args_tx.pps       = status->pps_curr / num_tx_workers;
	args_tx.duration  = gbl_args->args.duration;
	args_tx.batch_len = gbl_args->args.tx_batch_len;
	odph_odpthreads_create(&thd_tbl[num_rx_workers], thd_mask_tx,
			       &thr_params);
	odp_barrier_wait(&gbl_args->tx_barrier);

	/* wait for transmitter threads to terminate */
	odph_odpthreads_join(&thd_tbl[num_rx_workers]);

	/* delay to allow transmitted packets to reach the receivers */
	odp_time_wait_ns(SHUTDOWN_DELAY_NS);

	/* indicate to the receivers to exit */
	odp_atomic_store_u32(&gbl_args->shutdown, 1);

	/* wait for receivers */
	odph_odpthreads_join(&thd_tbl[0]);

	if (!status->warmup)
		return process_results(expected_tx_cnt, status);

	return 1;
}

static int run_test(void)
{
	int ret;
	int i;
	odp_cpumask_t txmask, rxmask;
	test_status_t status = {
		.pps_curr = gbl_args->args.pps,
		.pps_pass = 0,
		.pps_fail = 0,
		.warmup = 1,
	};

	ret = setup_txrx_masks(&txmask, &rxmask);
	if (ret)
		return ret;

	printf("Starting test with params:\n");
	printf("\tTransmit workers:     \t%d\n", odp_cpumask_count(&txmask));
	printf("\tReceive workers:      \t%d\n", odp_cpumask_count(&rxmask));
	printf("\tDuration (seconds):   \t%d\n", gbl_args->args.duration);
	printf("\tTransmit batch length:\t%" PRIu32 "\n",
	       gbl_args->args.tx_batch_len);
	printf("\tReceive batch length: \t%" PRIu32 "\n",
	       gbl_args->args.rx_batch_len);
	printf("\tPacket receive method:\t%s\n",
	       gbl_args->args.schedule ? "schedule" : "plain");
	printf("\tInterface(s):         \t");
	for (i = 0; i < gbl_args->args.num_ifaces; ++i)
		printf("%s ", gbl_args->args.ifaces[i]);
	printf("\n");

	/* first time just run the test but throw away the results */
	run_test_single(&txmask, &rxmask, &status);
	status.warmup = 0;

	while (1) {
		ret = run_test_single(&txmask, &rxmask, &status);
		if (ret <= 0)
			break;
	}

	return ret;
}

static odp_pktio_t create_pktio(const char *iface, int schedule)
{
	odp_pool_t pool;
	odp_pktio_t pktio;
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_param_t params;
	odp_pktio_param_t pktio_param;

	odp_pool_param_init(&params);
	params.pkt.len     = PKT_HDR_LEN + gbl_args->args.pkt_len;
	params.pkt.seg_len = params.pkt.len;
	params.pkt.num     = PKT_BUF_NUM;
	params.type        = ODP_POOL_PACKET;

	snprintf(pool_name, sizeof(pool_name), "pkt_pool_%s", iface);
	pool = odp_pool_create(pool_name, &params);
	if (pool == ODP_POOL_INVALID)
		return ODP_PKTIO_INVALID;

	odp_pktio_param_init(&pktio_param);

	if (schedule)
		pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
	else
		pktio_param.in_mode = ODP_PKTIN_MODE_QUEUE;

	pktio = odp_pktio_open(iface, pool, &pktio_param);

	return pktio;
}

static int test_init(void)
{
	odp_pool_param_t params;
	const char *iface;
	int schedule;
	odp_pktio_config_t cfg;

	odp_pool_param_init(&params);
	params.pkt.len     = PKT_HDR_LEN + gbl_args->args.pkt_len;
	params.pkt.seg_len = params.pkt.len;
	params.pkt.num     = PKT_BUF_NUM;
	params.type        = ODP_POOL_PACKET;

	gbl_args->transmit_pkt_pool = odp_pool_create("pkt_pool_transmit",
						      &params);
	if (gbl_args->transmit_pkt_pool == ODP_POOL_INVALID)
		ODPH_ABORT("Failed to create transmit pool\n");

	odp_atomic_init_u32(&gbl_args->ip_seq, 0);
	odp_atomic_init_u32(&gbl_args->shutdown, 0);

	iface    = gbl_args->args.ifaces[0];
	schedule = gbl_args->args.schedule;

	if (schedule)
		odp_schedule_config(NULL);

	/* create pktios and associate input/output queues */
	gbl_args->pktio_tx = create_pktio(iface, schedule);
	if (gbl_args->args.num_ifaces > 1) {
		iface = gbl_args->args.ifaces[1];
		gbl_args->pktio_rx = create_pktio(iface, schedule);
	} else {
		gbl_args->pktio_rx = gbl_args->pktio_tx;
	}

	odp_pktio_mac_addr(gbl_args->pktio_tx, gbl_args->src_mac,
			   ODPH_ETHADDR_LEN);
	odp_pktio_mac_addr(gbl_args->pktio_rx, gbl_args->dst_mac,
			   ODPH_ETHADDR_LEN);

	if (gbl_args->pktio_rx == ODP_PKTIO_INVALID ||
	    gbl_args->pktio_tx == ODP_PKTIO_INVALID) {
		ODPH_ERR("failed to open pktio\n");
		return -1;
	}

	/* Create single queue with default parameters */
	if (odp_pktout_queue_config(gbl_args->pktio_tx, NULL)) {
		ODPH_ERR("failed to configure pktio_tx queue\n");
		return -1;
	}

	/* Configure also input side (with defaults) */
	if (odp_pktin_queue_config(gbl_args->pktio_tx, NULL)) {
		ODPH_ERR("failed to configure pktio_tx queue\n");
		return -1;
	}

	/* Disable packet parsing as this is done in the driver where it
	 * affects scalability.
	 */
	odp_pktio_config_init(&cfg);
	cfg.parser.layer = ODP_PROTO_LAYER_NONE;
	odp_pktio_config(gbl_args->pktio_rx, &cfg);

	if (gbl_args->args.num_ifaces > 1) {
		if (odp_pktout_queue_config(gbl_args->pktio_rx, NULL)) {
			ODPH_ERR("failed to configure pktio_rx queue\n");
			return -1;
		}

		if (odp_pktin_queue_config(gbl_args->pktio_rx, NULL)) {
			ODPH_ERR("failed to configure pktio_rx queue\n");
			return -1;
		}
	}

	if (odp_pktio_start(gbl_args->pktio_tx) != 0)
		return -1;
	if (gbl_args->args.num_ifaces > 1 &&
	    odp_pktio_start(gbl_args->pktio_rx))
		return -1;

	return 0;
}

static int empty_inq(odp_pktio_t pktio)
{
	odp_queue_t queue;
	odp_event_t ev;
	odp_queue_type_t q_type;

	if (odp_pktin_event_queue(pktio, &queue, 1) != 1)
		return -1;

	q_type = odp_queue_type(queue);

	/* flush any pending events */
	while (1) {
		if (q_type == ODP_QUEUE_TYPE_PLAIN)
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

static int test_term(void)
{
	char pool_name[ODP_POOL_NAME_LEN];
	odp_pool_t pool;
	int i;
	int ret = 0;

	if (gbl_args->pktio_tx != gbl_args->pktio_rx) {
		if (odp_pktio_stop(gbl_args->pktio_tx)) {
			ODPH_ERR("Failed to stop pktio_tx\n");
			return -1;
		}

		if (odp_pktio_close(gbl_args->pktio_tx)) {
			ODPH_ERR("Failed to close pktio_tx\n");
			ret = -1;
		}
	}

	empty_inq(gbl_args->pktio_rx);

	if (odp_pktio_stop(gbl_args->pktio_rx)) {
		ODPH_ERR("Failed to stop pktio_rx\n");
		return -1;
	}

	if (odp_pktio_close(gbl_args->pktio_rx) != 0) {
		ODPH_ERR("Failed to close pktio_rx\n");
		ret = -1;
	}

	for (i = 0; i < gbl_args->args.num_ifaces; ++i) {
		snprintf(pool_name, sizeof(pool_name),
			 "pkt_pool_%s", gbl_args->args.ifaces[i]);
		pool = odp_pool_lookup(pool_name);
		if (pool == ODP_POOL_INVALID)
			continue;

		if (odp_pool_destroy(pool) != 0) {
			ODPH_ERR("Failed to destroy pool %s\n", pool_name);
			ret = -1;
		}
	}

	if (odp_pool_destroy(gbl_args->transmit_pkt_pool) != 0) {
		ODPH_ERR("Failed to destroy transmit pool\n");
		ret = -1;
	}

	free(gbl_args->args.if_str);

	if (odp_shm_free(odp_shm_lookup("test_globals")) != 0) {
		ODPH_ERR("Failed to free test_globals\n");
		ret = -1;
	}
	if (odp_shm_free(odp_shm_lookup("test_globals.rx_stats")) != 0) {
		ODPH_ERR("Failed to free test_globals.rx_stats\n");
		ret = -1;
	}
	if (odp_shm_free(odp_shm_lookup("test_globals.tx_stats")) != 0) {
		ODPH_ERR("Failed to free test_globals.tx_stats\n");
		ret = -1;
	}

	return ret;
}

static void usage(void)
{
	printf("\nUsage: odp_pktio_perf [options]\n\n");
	printf("  -c, --count <number>   CPU count, 0=all available, default=2\n");
	printf("  -t, --txcount <number> Number of CPUs to use for TX\n");
	printf("                         default: cpu_count+1/2\n");
	printf("  -b, --txbatch <length> Number of packets per TX batch\n");
	printf("                         default: %d\n", BATCH_LEN_MAX);
	printf("  -p, --plain            Plain input queue for packet RX\n");
	printf("                         default: disabled (use scheduler)\n");
	printf("  -R, --rxbatch <length> Number of packets per RX batch\n");
	printf("                         default: %d\n", BATCH_LEN_MAX);
	printf("  -l, --length <length>  Additional payload length in bytes\n");
	printf("                         default: 0\n");
	printf("  -r, --rate <number>    Attempted packet rate in PPS\n");
	printf("  -i, --interface <list> List of interface names to use\n");
	printf("  -d, --duration <secs>  Duration of each test iteration\n");
	printf("  -v, --verbose          Print verbose information\n");
	printf("  -h, --help             This help\n");
	printf("\n");
}

static void parse_args(int argc, char *argv[], test_args_t *args)
{
	int opt;
	int long_index;

	static const struct option longopts[] = {
		{"count",     required_argument, NULL, 'c'},
		{"txcount",   required_argument, NULL, 't'},
		{"txbatch",   required_argument, NULL, 'b'},
		{"plain",     no_argument,       NULL, 'p'},
		{"rxbatch",   required_argument, NULL, 'R'},
		{"length",    required_argument, NULL, 'l'},
		{"rate",      required_argument, NULL, 'r'},
		{"interface", required_argument, NULL, 'i'},
		{"duration",  required_argument, NULL, 'd'},
		{"verbose",   no_argument,       NULL, 'v'},
		{"help",      no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:t:b:pR:l:r:i:d:vh";

	args->cpu_count      = 2;
	args->num_tx_workers = 0; /* defaults to cpu_count+1/2 */
	args->tx_batch_len   = BATCH_LEN_MAX;
	args->rx_batch_len   = BATCH_LEN_MAX;
	args->duration       = 1;
	args->pps            = RATE_SEARCH_INITIAL_PPS;
	args->search         = 1;
	args->schedule       = 1;
	args->verbose        = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts,
				  longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			usage();
			exit(EXIT_SUCCESS);
		case 'c':
			args->cpu_count = atoi(optarg);
			break;
		case 't':
			args->num_tx_workers = atoi(optarg);
			break;
		case 'd':
			args->duration = atoi(optarg);
			break;
		case 'r':
			args->pps     = atoi(optarg);
			args->search  = 0;
			args->verbose = 1;
			break;
		case 'i':
		{
			char *token;

			args->if_str = malloc(strlen(optarg) + 1);

			if (!args->if_str)
				ODPH_ABORT("Failed to alloc iface storage\n");

			strcpy(args->if_str, optarg);
			for (token = strtok(args->if_str, ",");
			     token != NULL && args->num_ifaces < MAX_NUM_IFACES;
			     token = strtok(NULL, ","))
				args->ifaces[args->num_ifaces++] = token;
		}
			break;
		case 'p':
			args->schedule = 0;
			break;
		case 'b':
			args->tx_batch_len = atoi(optarg);
			break;
		case 'R':
			args->rx_batch_len = atoi(optarg);
			break;
		case 'v':
			args->verbose = 1;
			break;
		case 'l':
			args->pkt_len = atoi(optarg);
			break;
		}
	}

	if (args->num_ifaces == 0) {
		args->ifaces[0] = "loop";
		args->num_ifaces = 1;
	}
}

int main(int argc, char **argv)
{
	int ret;
	odp_shm_t shm;
	int max_thrs;
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init_param;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (odp_init_global(&instance, &init_param, NULL) != 0)
		ODPH_ABORT("Failed global init.\n");

	if (odp_init_local(instance, ODP_THREAD_CONTROL) != 0)
		ODPH_ABORT("Failed local init.\n");

	shm = odp_shm_reserve("test_globals",
			      sizeof(test_globals_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID)
		ODPH_ABORT("Shared memory reserve failed.\n");

	gbl_args = odp_shm_addr(shm);
	if (gbl_args == NULL)
		ODPH_ABORT("Shared memory reserve failed.\n");
	memset(gbl_args, 0, sizeof(test_globals_t));

	max_thrs = odp_thread_count_max();

	gbl_args->instance = instance;
	gbl_args->rx_stats_size = max_thrs * sizeof(pkt_rx_stats_t);
	gbl_args->tx_stats_size = max_thrs * sizeof(pkt_tx_stats_t);

	shm = odp_shm_reserve("test_globals.rx_stats",
			      gbl_args->rx_stats_size,
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID)
		ODPH_ABORT("Shared memory reserve failed.\n");

	gbl_args->rx_stats = odp_shm_addr(shm);

	if (gbl_args->rx_stats == NULL)
		ODPH_ABORT("Shared memory reserve failed.\n");

	memset(gbl_args->rx_stats, 0, gbl_args->rx_stats_size);

	shm = odp_shm_reserve("test_globals.tx_stats",
			      gbl_args->tx_stats_size,
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID)
		ODPH_ABORT("Shared memory reserve failed.\n");

	gbl_args->tx_stats = odp_shm_addr(shm);

	if (gbl_args->tx_stats == NULL)
		ODPH_ABORT("Shared memory reserve failed.\n");

	memset(gbl_args->tx_stats, 0, gbl_args->tx_stats_size);

	parse_args(argc, argv, &gbl_args->args);

	ret = test_init();

	if (ret == 0) {
		ret = run_test();
		test_term();
	}

	odp_term_local();
	odp_term_global(instance);

	return ret;
}

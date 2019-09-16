/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* enable strtok */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

/* Maximum number of worker threads */
#define MAX_WORKERS            (ODP_THREAD_COUNT_MAX - 1)

/* Size of the shared memory block */
#define POOL_PKT_NUM           (16 * 1024)

/* Buffer size of the packet pool buffer */
#define POOL_PKT_LEN           1536

/* Maximum number of packet in a burst */
#define MAX_PKT_BURST          32

/* Maximum number of pktio queues per interface */
#define MAX_QUEUES             32

/* Maximum number of pktio interfaces */
#define MAX_PKTIOS             8

/* Maximum pktio index table size */
#define MAX_PKTIO_INDEXES      1024

/* Packet input mode */
typedef enum pktin_mode_t {
	DIRECT_RECV,
	PLAIN_QUEUE,
	SCHED_PARALLEL,
	SCHED_ATOMIC,
	SCHED_ORDERED,
} pktin_mode_t;

/* Packet output modes */
typedef enum pktout_mode_t {
	PKTOUT_DIRECT,
	PKTOUT_QUEUE
} pktout_mode_t;

static inline int sched_mode(pktin_mode_t in_mode)
{
	return (in_mode == SCHED_PARALLEL) ||
	       (in_mode == SCHED_ATOMIC)   ||
	       (in_mode == SCHED_ORDERED);
}

/* Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))
/*
 * Parsed command line application arguments
 */
typedef struct {
	int extra_check;        /* Some extra checks have been enabled */
	unsigned int cpu_count;
	int if_count;		/* Number of interfaces to be used */
	int addr_count;		/* Number of dst addresses to be used */
	int num_workers;	/* Number of worker threads */
	char **if_names;	/* Array of pointers to interface names */
	odph_ethaddr_t addrs[MAX_PKTIOS]; /* Array of dst addresses */
	pktin_mode_t in_mode;	/* Packet input mode */
	pktout_mode_t out_mode; /* Packet output mode */
	int time;		/* Time in seconds to run. */
	int accuracy;		/* Number of seconds to get and print stats */
	char *if_str;		/* Storage for interface names */
	int dst_change;		/* Change destination eth addresses */
	int src_change;		/* Change source eth addresses */
	int error_check;        /* Check packet errors */
	int chksum;             /* Checksum offload */
	int sched_mode;         /* Scheduler mode */
	int num_groups;         /* Number of scheduling groups */
	int burst_rx;           /* Receive burst size */
	int verbose;		/* Verbose output */
} appl_args_t;

/* Statistics */
typedef union ODP_ALIGNED_CACHE {
	struct {
		/* Number of forwarded packets */
		uint64_t packets;
		/* Packets dropped due to receive error */
		uint64_t rx_drops;
		/* Packets dropped due to transmit error */
		uint64_t tx_drops;
	} s;

	uint8_t padding[ODP_CACHE_LINE_SIZE];
} stats_t;

/* Thread specific data */
typedef struct thread_args_t {
	stats_t stats;

	struct {
		odp_pktin_queue_t pktin;
		odp_pktout_queue_t pktout;
		odp_queue_t rx_queue;
		odp_queue_t tx_queue;
		int rx_idx;
		int tx_idx;
		int rx_queue_idx;
		int tx_queue_idx;
	} pktio[MAX_PKTIOS];

	/* Groups to join */
	odp_schedule_group_t group[MAX_PKTIOS];

	int thr_idx;
	int num_pktio;
	int num_groups;
} thread_args_t;

/*
 * Grouping of all global data
 */
typedef struct {
	/* Thread table */
	odph_thread_t thread_tbl[MAX_WORKERS];
	/* Thread specific arguments */
	thread_args_t thread_args[MAX_WORKERS];
	/* Barriers to synchronize main and workers */
	odp_barrier_t init_barrier;
	odp_barrier_t term_barrier;
	/* Application (parsed) arguments */
	appl_args_t appl;
	/* Table of port ethernet addresses */
	odph_ethaddr_t port_eth_addr[MAX_PKTIOS];
	/* Table of dst ethernet addresses */
	odph_ethaddr_t dst_eth_addr[MAX_PKTIOS];
	/* Table of dst ports. This is used by non-sched modes. */
	int dst_port[MAX_PKTIOS];
	/* Table of pktio handles */
	struct {
		odp_pktio_t pktio;
		odp_pktin_queue_t pktin[MAX_QUEUES];
		odp_pktout_queue_t pktout[MAX_QUEUES];
		odp_queue_t rx_q[MAX_QUEUES];
		odp_queue_t tx_q[MAX_QUEUES];
		int num_rx_thr;
		int num_tx_thr;
		int num_rx_queue;
		int num_tx_queue;
		int next_rx_queue;
		int next_tx_queue;
	} pktios[MAX_PKTIOS];

	/* Destination port lookup table.
	 * Table index is pktio_index of the API. This is used by the sched
	 * mode. */
	uint8_t dst_port_from_idx[MAX_PKTIO_INDEXES];
	/* Break workers loop if set to 1 */
	int exit_threads;

} args_t;

/* Global pointer to args */
static args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	gbl_args->exit_threads = 1;
}

/*
 * Drop packets which input parsing marked as containing errors.
 *
 * Frees packets with error and modifies pkt_tbl[] to only contain packets with
 * no detected errors.
 *
 * pkt_tbl  Array of packets
 * num      Number of packets in pkt_tbl[]
 *
 * Returns number of packets dropped
 */
static inline int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned num)
{
	odp_packet_t pkt;
	unsigned dropped = 0;
	unsigned i, j;

	for (i = 0, j = 0; i < num; ++i) {
		pkt = pkt_tbl[i];

		if (odp_unlikely(odp_packet_has_error(pkt))) {
			odp_packet_free(pkt); /* Drop */
			dropped++;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j - 1] = pkt;
		}
	}

	return dropped;
}

/*
 * Fill packets' eth addresses according to the destination port
 *
 * pkt_tbl  Array of packets
 * num      Number of packets in the array
 * dst_port Destination port
 */
static inline void fill_eth_addrs(odp_packet_t pkt_tbl[],
				  unsigned num, int dst_port)
{
	odp_packet_t pkt;
	odph_ethhdr_t *eth;
	unsigned i;

	if (!gbl_args->appl.dst_change && !gbl_args->appl.src_change)
		return;

	for (i = 0; i < num; ++i) {
		pkt = pkt_tbl[i];

		odp_packet_prefetch(pkt, 0, ODPH_ETHHDR_LEN);

		eth = odp_packet_data(pkt);

		if (gbl_args->appl.src_change)
			eth->src = gbl_args->port_eth_addr[dst_port];

		if (gbl_args->appl.dst_change)
			eth->dst = gbl_args->dst_eth_addr[dst_port];
	}
}

static inline int event_queue_send(odp_queue_t queue, odp_packet_t *pkt_tbl,
				   unsigned pkts)
{
	int ret;
	unsigned sent = 0;
	odp_event_t ev_tbl[pkts];

	odp_packet_to_event_multi(pkt_tbl, ev_tbl, pkts);

	while (sent < pkts) {
		ret = odp_queue_enq_multi(queue, &ev_tbl[sent], pkts - sent);

		if (ret < 0) {
			ODPH_ERR("Failed to send packet as events\n");
			break;
		}

		sent += ret;
	}

	return sent;
}

static inline void chksum_insert(odp_packet_t *pkt_tbl, int pkts)
{
	odp_packet_t pkt;
	int i;

	for (i = 0; i < pkts; i++) {
		pkt = pkt_tbl[i];
		odp_packet_l3_chksum_insert(pkt, 1);
		odp_packet_l4_chksum_insert(pkt, 1);
	}
}

/*
 * Packet IO worker thread using scheduled queues
 *
 * arg  thread arguments of type 'thread_args_t *'
 */
static int run_worker_sched_mode(void *arg)
{
	int pkts;
	int thr;
	int dst_idx;
	int i;
	int pktio, num_pktio;
	uint16_t max_burst;
	odp_pktout_queue_t pktout[MAX_PKTIOS];
	odp_queue_t tx_queue[MAX_PKTIOS];
	thread_args_t *thr_args = arg;
	stats_t *stats = &thr_args->stats;
	int use_event_queue = gbl_args->appl.out_mode;
	pktin_mode_t in_mode = gbl_args->appl.in_mode;

	thr = odp_thread_id();
	max_burst = gbl_args->appl.burst_rx;

	if (gbl_args->appl.num_groups) {
		odp_thrmask_t mask;

		odp_thrmask_zero(&mask);
		odp_thrmask_set(&mask, thr);

		/* Join non-default groups */
		for (i = 0; i < thr_args->num_groups; i++) {
			if (odp_schedule_group_join(thr_args->group[i],
						    &mask)) {
				ODPH_ERR("Join failed\n");
				return -1;
			}
		}
	}

	num_pktio = thr_args->num_pktio;

	if (num_pktio > MAX_PKTIOS) {
		ODPH_ERR("Too many pktios %i\n", num_pktio);
		return -1;
	}

	for (pktio = 0; pktio < num_pktio; pktio++) {
		tx_queue[pktio] = thr_args->pktio[pktio].tx_queue;
		pktout[pktio]   = thr_args->pktio[pktio].pktout;
	}

	printf("[%02i] PKTIN_SCHED_%s, %s\n", thr,
	       (in_mode == SCHED_PARALLEL) ? "PARALLEL" :
	       ((in_mode == SCHED_ATOMIC) ? "ATOMIC" : "ORDERED"),
	       (use_event_queue) ? "PKTOUT_QUEUE" : "PKTOUT_DIRECT");

	odp_barrier_wait(&gbl_args->init_barrier);

	/* Loop packets */
	while (!gbl_args->exit_threads) {
		odp_event_t  ev_tbl[MAX_PKT_BURST];
		odp_packet_t pkt_tbl[MAX_PKT_BURST];
		int sent;
		unsigned tx_drops;
		int src_idx;

		pkts = odp_schedule_multi_no_wait(NULL, ev_tbl, max_burst);

		if (pkts <= 0)
			continue;

		odp_packet_from_event_multi(pkt_tbl, ev_tbl, pkts);

		if (odp_unlikely(gbl_args->appl.extra_check)) {
			if (gbl_args->appl.chksum)
				chksum_insert(pkt_tbl, pkts);

			if (gbl_args->appl.error_check) {
				int rx_drops;

				/* Drop packets with errors */
				rx_drops = drop_err_pkts(pkt_tbl, pkts);

				if (odp_unlikely(rx_drops)) {
					stats->s.rx_drops += rx_drops;
					if (pkts == rx_drops)
						continue;

					pkts -= rx_drops;
				}
			}
		}

		/* packets from the same queue are from the same interface */
		src_idx = odp_packet_input_index(pkt_tbl[0]);
		ODPH_ASSERT(src_idx >= 0);
		dst_idx = gbl_args->dst_port_from_idx[src_idx];
		fill_eth_addrs(pkt_tbl, pkts, dst_idx);

		if (odp_unlikely(use_event_queue))
			sent = event_queue_send(tx_queue[dst_idx], pkt_tbl,
						pkts);
		else
			sent = odp_pktout_send(pktout[dst_idx], pkt_tbl, pkts);

		sent     = odp_unlikely(sent < 0) ? 0 : sent;
		tx_drops = pkts - sent;

		if (odp_unlikely(tx_drops)) {
			stats->s.tx_drops += tx_drops;

			/* Drop rejected packets */
			for (i = sent; i < pkts; i++)
				odp_packet_free(pkt_tbl[i]);
		}

		stats->s.packets += pkts;
	}

	/* Make sure that latest stat writes are visible to other threads */
	odp_mb_full();

	/* Wait until pktio devices are stopped */
	odp_barrier_wait(&gbl_args->term_barrier);

	/* Free remaining events in queues */
	while (1) {
		odp_event_t  ev;

		ev = odp_schedule(NULL,
				  odp_schedule_wait_time(ODP_TIME_SEC_IN_NS));

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}

	return 0;
}

/*
 * Packet IO worker thread using plain queues
 *
 * arg  thread arguments of type 'thread_args_t *'
 */
static int run_worker_plain_queue_mode(void *arg)
{
	int thr;
	int pkts;
	uint16_t max_burst;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int dst_idx, num_pktio;
	odp_queue_t queue;
	odp_pktout_queue_t pktout;
	odp_queue_t tx_queue;
	int pktio = 0;
	thread_args_t *thr_args = arg;
	stats_t *stats = &thr_args->stats;
	int use_event_queue = gbl_args->appl.out_mode;
	int i;

	thr = odp_thread_id();
	max_burst = gbl_args->appl.burst_rx;

	num_pktio = thr_args->num_pktio;
	dst_idx   = thr_args->pktio[pktio].tx_idx;
	queue     = thr_args->pktio[pktio].rx_queue;
	pktout    = thr_args->pktio[pktio].pktout;
	tx_queue  = thr_args->pktio[pktio].tx_queue;

	printf("[%02i] num pktios %i, PKTIN_QUEUE, %s\n", thr, num_pktio,
	       (use_event_queue) ? "PKTOUT_QUEUE" : "PKTOUT_DIRECT");

	odp_barrier_wait(&gbl_args->init_barrier);

	/* Loop packets */
	while (!gbl_args->exit_threads) {
		int sent;
		unsigned tx_drops;
		odp_event_t event[MAX_PKT_BURST];

		if (num_pktio > 1) {
			dst_idx   = thr_args->pktio[pktio].tx_idx;
			queue     = thr_args->pktio[pktio].rx_queue;
			pktout    = thr_args->pktio[pktio].pktout;
			if (odp_unlikely(use_event_queue))
				tx_queue = thr_args->pktio[pktio].tx_queue;

			pktio++;
			if (pktio == num_pktio)
				pktio = 0;
		}

		pkts = odp_queue_deq_multi(queue, event, max_burst);
		if (odp_unlikely(pkts <= 0))
			continue;

		odp_packet_from_event_multi(pkt_tbl, event, pkts);

		if (odp_unlikely(gbl_args->appl.extra_check)) {
			if (gbl_args->appl.chksum)
				chksum_insert(pkt_tbl, pkts);

			if (gbl_args->appl.error_check) {
				int rx_drops;

				/* Drop packets with errors */
				rx_drops = drop_err_pkts(pkt_tbl, pkts);

				if (odp_unlikely(rx_drops)) {
					stats->s.rx_drops += rx_drops;
					if (pkts == rx_drops)
						continue;

					pkts -= rx_drops;
				}
			}
		}

		fill_eth_addrs(pkt_tbl, pkts, dst_idx);

		if (odp_unlikely(use_event_queue))
			sent = event_queue_send(tx_queue, pkt_tbl, pkts);
		else
			sent = odp_pktout_send(pktout, pkt_tbl, pkts);

		sent     = odp_unlikely(sent < 0) ? 0 : sent;
		tx_drops = pkts - sent;

		if (odp_unlikely(tx_drops)) {
			int i;

			stats->s.tx_drops += tx_drops;

			/* Drop rejected packets */
			for (i = sent; i < pkts; i++)
				odp_packet_free(pkt_tbl[i]);
		}

		stats->s.packets += pkts;
	}

	/* Make sure that latest stat writes are visible to other threads */
	odp_mb_full();

	/* Wait until pktio devices are stopped */
	odp_barrier_wait(&gbl_args->term_barrier);

	/* Free remaining events in queues */
	for (i = 0; i < num_pktio; i++) {
		odp_time_t recv_last = odp_time_local();
		odp_time_t since_last;

		queue = thr_args->pktio[i].rx_queue;
		do {
			odp_event_t  ev = odp_queue_deq(queue);

			if (ev != ODP_EVENT_INVALID) {
				recv_last = odp_time_local();
				odp_event_free(ev);
			}

			since_last = odp_time_diff(odp_time_local(), recv_last);
		} while (odp_time_to_ns(since_last) < ODP_TIME_SEC_IN_NS);
	}

	return 0;
}

/*
 * Packet IO worker thread accessing IO resources directly
 *
 * arg  thread arguments of type 'thread_args_t *'
 */
static int run_worker_direct_mode(void *arg)
{
	int thr;
	int pkts;
	uint16_t max_burst;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int dst_idx, num_pktio;
	odp_pktin_queue_t pktin;
	odp_pktout_queue_t pktout;
	odp_queue_t tx_queue;
	int pktio = 0;
	thread_args_t *thr_args = arg;
	stats_t *stats = &thr_args->stats;
	int use_event_queue = gbl_args->appl.out_mode;

	thr = odp_thread_id();
	max_burst = gbl_args->appl.burst_rx;

	num_pktio = thr_args->num_pktio;
	dst_idx   = thr_args->pktio[pktio].tx_idx;
	pktin     = thr_args->pktio[pktio].pktin;
	pktout    = thr_args->pktio[pktio].pktout;
	tx_queue  = thr_args->pktio[pktio].tx_queue;

	printf("[%02i] num pktios %i, PKTIN_DIRECT, %s\n", thr, num_pktio,
	       (use_event_queue) ? "PKTOUT_QUEUE" : "PKTOUT_DIRECT");

	odp_barrier_wait(&gbl_args->init_barrier);

	/* Loop packets */
	while (!gbl_args->exit_threads) {
		int sent;
		unsigned tx_drops;

		if (num_pktio > 1) {
			dst_idx   = thr_args->pktio[pktio].tx_idx;
			pktin     = thr_args->pktio[pktio].pktin;
			pktout    = thr_args->pktio[pktio].pktout;
			if (odp_unlikely(use_event_queue))
				tx_queue = thr_args->pktio[pktio].tx_queue;

			pktio++;
			if (pktio == num_pktio)
				pktio = 0;
		}

		pkts = odp_pktin_recv(pktin, pkt_tbl, max_burst);
		if (odp_unlikely(pkts <= 0))
			continue;

		if (odp_unlikely(gbl_args->appl.extra_check)) {
			if (gbl_args->appl.chksum)
				chksum_insert(pkt_tbl, pkts);

			if (gbl_args->appl.error_check) {
				int rx_drops;

				/* Drop packets with errors */
				rx_drops = drop_err_pkts(pkt_tbl, pkts);

				if (odp_unlikely(rx_drops)) {
					stats->s.rx_drops += rx_drops;
					if (pkts == rx_drops)
						continue;

					pkts -= rx_drops;
				}
			}
		}

		fill_eth_addrs(pkt_tbl, pkts, dst_idx);

		if (odp_unlikely(use_event_queue))
			sent = event_queue_send(tx_queue, pkt_tbl, pkts);
		else
			sent = odp_pktout_send(pktout, pkt_tbl, pkts);

		sent     = odp_unlikely(sent < 0) ? 0 : sent;
		tx_drops = pkts - sent;

		if (odp_unlikely(tx_drops)) {
			int i;

			stats->s.tx_drops += tx_drops;

			/* Drop rejected packets */
			for (i = sent; i < pkts; i++)
				odp_packet_free(pkt_tbl[i]);
		}

		stats->s.packets += pkts;
	}

	/* Make sure that latest stat writes are visible to other threads */
	odp_mb_full();

	return 0;
}

/*
 * Create a pktio handle, optionally associating a default input queue.
 *
 * dev   Name of device to open
 * index Pktio index
 * pool  Pool to associate with device for packet RX/TX
 *
 * Returns 0 on success, -1 on failure
 */
static int create_pktio(const char *dev, int idx, int num_rx, int num_tx,
			odp_pool_t pool, odp_schedule_group_t group)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	odp_schedule_sync_t  sync_mode;
	odp_pktio_capability_t pktio_capa;
	odp_pktio_config_t config;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_pktio_op_mode_t mode_rx;
	odp_pktio_op_mode_t mode_tx;
	pktin_mode_t in_mode = gbl_args->appl.in_mode;
	odp_pktio_info_t info;

	odp_pktio_param_init(&pktio_param);

	if (in_mode == PLAIN_QUEUE)
		pktio_param.in_mode = ODP_PKTIN_MODE_QUEUE;
	else if (in_mode != DIRECT_RECV) /* pktin_mode SCHED_* */
		pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	if (gbl_args->appl.out_mode != PKTOUT_DIRECT)
		pktio_param.out_mode = ODP_PKTOUT_MODE_QUEUE;

	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		ODPH_ERR("Error: failed to open %s\n", dev);
		return -1;
	}

	if (odp_pktio_info(pktio, &info)) {
		ODPH_ERR("Error: pktio info failed %s\n", dev);
		return -1;
	}

	printf("created pktio %" PRIu64 ", dev: %s, drv: %s\n",
	       odp_pktio_to_u64(pktio), dev, info.drv_name);

	if (gbl_args->appl.verbose)
		odp_pktio_print(pktio);

	if (odp_pktio_capability(pktio, &pktio_capa)) {
		ODPH_ERR("Error: pktio capability query failed %s\n", dev);
		return -1;
	}

	odp_pktio_config_init(&config);
	config.parser.layer = gbl_args->appl.extra_check ?
			ODP_PROTO_LAYER_ALL :
			ODP_PROTO_LAYER_NONE;

	if (gbl_args->appl.chksum) {
		printf("Checksum offload enabled\n");
		config.pktout.bit.ipv4_chksum_ena = 1;
		config.pktout.bit.udp_chksum_ena  = 1;
		config.pktout.bit.tcp_chksum_ena  = 1;
	}

	odp_pktio_config(pktio, &config);

	odp_pktin_queue_param_init(&pktin_param);
	odp_pktout_queue_param_init(&pktout_param);

	/* By default use a queue per worker. Sched mode ignores rx side
	 * setting. */
	mode_rx = ODP_PKTIO_OP_MT_UNSAFE;
	mode_tx = ODP_PKTIO_OP_MT_UNSAFE;

	if (gbl_args->appl.sched_mode) {
		if (gbl_args->appl.in_mode == SCHED_ATOMIC)
			sync_mode = ODP_SCHED_SYNC_ATOMIC;
		else if (gbl_args->appl.in_mode == SCHED_ORDERED)
			sync_mode = ODP_SCHED_SYNC_ORDERED;
		else
			sync_mode = ODP_SCHED_SYNC_PARALLEL;

		pktin_param.queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		pktin_param.queue_param.sched.sync  = sync_mode;
		pktin_param.queue_param.sched.group = group;
	}

	if (num_rx > (int)pktio_capa.max_input_queues) {
		printf("Sharing %i input queues between %i workers\n",
		       pktio_capa.max_input_queues, num_rx);
		num_rx  = pktio_capa.max_input_queues;
		mode_rx = ODP_PKTIO_OP_MT;
	}

	if (num_tx > (int)pktio_capa.max_output_queues) {
		printf("Sharing %i output queues between %i workers\n",
		       pktio_capa.max_output_queues, num_tx);
		num_tx  = pktio_capa.max_output_queues;
		mode_tx = ODP_PKTIO_OP_MT;
	}

	pktin_param.hash_enable = 1;
	pktin_param.hash_proto.proto.ipv4_udp = 1;
	pktin_param.num_queues  = num_rx;
	pktin_param.op_mode     = mode_rx;

	pktout_param.op_mode    = mode_tx;
	pktout_param.num_queues = num_tx;

	if (odp_pktin_queue_config(pktio, &pktin_param)) {
		ODPH_ERR("Error: input queue config failed %s\n", dev);
		return -1;
	}

	if (odp_pktout_queue_config(pktio, &pktout_param)) {
		ODPH_ERR("Error: output queue config failed %s\n", dev);
		return -1;
	}

	if (gbl_args->appl.in_mode == DIRECT_RECV) {
		if (odp_pktin_queue(pktio, gbl_args->pktios[idx].pktin,
				    num_rx) != num_rx) {
			ODPH_ERR("Error: pktin queue query failed %s\n", dev);
			return -1;
		}
	} else {
		if (odp_pktin_event_queue(pktio,
					  gbl_args->pktios[idx].rx_q,
					  num_rx) != num_rx) {
			ODPH_ERR("Error: pktin event queue query failed %s\n",
				 dev);
			return -1;
		}
	}

	if (gbl_args->appl.out_mode == PKTOUT_DIRECT) {
		if (odp_pktout_queue(pktio,
				     gbl_args->pktios[idx].pktout,
				     num_tx) != num_tx) {
			ODPH_ERR("Error: pktout queue query failed %s\n", dev);
			return -1;
		}
	} else {
		if (odp_pktout_event_queue(pktio,
					   gbl_args->pktios[idx].tx_q,
					   num_tx) != num_tx) {
			ODPH_ERR("Error: event queue query failed %s\n", dev);
			return -1;
		}
	}

	printf("created %i input and %i output queues on (%s)\n",
	       num_rx, num_tx, dev);

	gbl_args->pktios[idx].num_rx_queue = num_rx;
	gbl_args->pktios[idx].num_tx_queue = num_tx;
	gbl_args->pktios[idx].pktio        = pktio;

	return 0;
}

/*
 * Print statistics
 *
 * num_workers Number of worker threads
 * thr_stats   Pointers to stats storage
 * duration    Number of seconds to loop in
 * timeout     Number of seconds for stats calculation
 */
static int print_speed_stats(int num_workers, stats_t **thr_stats,
			     int duration, int timeout)
{
	uint64_t pkts = 0;
	uint64_t pkts_prev = 0;
	uint64_t pps;
	uint64_t rx_drops, tx_drops;
	uint64_t maximum_pps = 0;
	int i;
	int elapsed = 0;
	int stats_enabled = 1;
	int loop_forever = (duration == 0);

	if (timeout <= 0) {
		stats_enabled = 0;
		timeout = 1;
	}
	/* Wait for all threads to be ready*/
	odp_barrier_wait(&gbl_args->init_barrier);

	do {
		pkts = 0;
		rx_drops = 0;
		tx_drops = 0;

		sleep(timeout);

		for (i = 0; i < num_workers; i++) {
			pkts += thr_stats[i]->s.packets;
			rx_drops += thr_stats[i]->s.rx_drops;
			tx_drops += thr_stats[i]->s.tx_drops;
		}
		if (stats_enabled) {
			pps = (pkts - pkts_prev) / timeout;
			if (pps > maximum_pps)
				maximum_pps = pps;
			printf("%" PRIu64 " pps, %" PRIu64 " max pps, ",  pps,
			       maximum_pps);

			printf(" %" PRIu64 " rx drops, %" PRIu64 " tx drops\n",
			       rx_drops, tx_drops);

			pkts_prev = pkts;
		}
		elapsed += timeout;
	} while (!gbl_args->exit_threads && (loop_forever ||
		 (elapsed < duration)));

	if (stats_enabled)
		printf("TEST RESULT: %" PRIu64 " maximum packets per second.\n",
		       maximum_pps);

	return pkts > 100 ? 0 : -1;
}

static void print_port_mapping(void)
{
	int if_count;
	int pktio;

	if_count    = gbl_args->appl.if_count;

	printf("\nPort config\n--------------------\n");

	for (pktio = 0; pktio < if_count; pktio++) {
		const char *dev = gbl_args->appl.if_names[pktio];

		printf("Port %i (%s)\n", pktio, dev);
		printf("  rx workers %i\n",
		       gbl_args->pktios[pktio].num_rx_thr);
		printf("  tx workers %i\n",
		       gbl_args->pktios[pktio].num_tx_thr);
		printf("  rx queues %i\n",
		       gbl_args->pktios[pktio].num_rx_queue);
		printf("  tx queues %i\n",
		       gbl_args->pktios[pktio].num_tx_queue);
	}

	printf("\n");
}

/*
 * Find the destination port for a given input port
 *
 * port  Input port index
 */
static int find_dest_port(int port)
{
	/* Even number of ports */
	if (gbl_args->appl.if_count % 2 == 0)
		return (port % 2 == 0) ? port + 1 : port - 1;

	/* Odd number of ports */
	if (port == gbl_args->appl.if_count - 1)
		return 0;
	else
		return port + 1;
}

/*
 * Bind worker threads to interfaces and calculate number of queues needed
 *
 * less workers (N) than interfaces (M)
 *  - assign each worker to process every Nth interface
 *  - workers process inequal number of interfaces, when M is not divisible by N
 *  - needs only single queue per interface
 * otherwise
 *  - assign an interface to every Mth worker
 *  - interfaces are processed by inequal number of workers, when N is not
 *    divisible by M
 *  - tries to configure a queue per worker per interface
 *  - shares queues, if interface capability does not allows a queue per worker
 */
static void bind_workers(void)
{
	int if_count, num_workers;
	int rx_idx, tx_idx, thr, pktio, i;
	thread_args_t *thr_args;

	if_count    = gbl_args->appl.if_count;
	num_workers = gbl_args->appl.num_workers;

	if (gbl_args->appl.sched_mode) {
		/* all threads receive and send on all pktios */
		for (i = 0; i < if_count; i++) {
			gbl_args->pktios[i].num_rx_thr = num_workers;
			gbl_args->pktios[i].num_tx_thr = num_workers;
		}

		for (thr = 0; thr < num_workers; thr++) {
			thr_args = &gbl_args->thread_args[thr];
			thr_args->num_pktio = if_count;

			/* In sched mode, pktios are not cross connected with
			 * local pktio indexes */
			for (i = 0; i < if_count; i++) {
				thr_args->pktio[i].rx_idx = i;
				thr_args->pktio[i].tx_idx = i;
			}
		}
	} else {
		/* initialize port forwarding table */
		for (rx_idx = 0; rx_idx < if_count; rx_idx++)
			gbl_args->dst_port[rx_idx] = find_dest_port(rx_idx);

		if (if_count > num_workers) {
			/* Less workers than pktios. Assign single worker per
			 * pktio. */
			thr = 0;

			for (rx_idx = 0; rx_idx < if_count; rx_idx++) {
				thr_args = &gbl_args->thread_args[thr];
				pktio    = thr_args->num_pktio;
				/* Cross connect rx to tx */
				tx_idx   = gbl_args->dst_port[rx_idx];
				thr_args->pktio[pktio].rx_idx = rx_idx;
				thr_args->pktio[pktio].tx_idx = tx_idx;
				thr_args->num_pktio++;

				gbl_args->pktios[rx_idx].num_rx_thr++;
				gbl_args->pktios[tx_idx].num_tx_thr++;

				thr++;
				if (thr >= num_workers)
					thr = 0;
			}
		} else {
			/* More workers than pktios. Assign at least one worker
			 * per pktio. */
			rx_idx = 0;

			for (thr = 0; thr < num_workers; thr++) {
				thr_args = &gbl_args->thread_args[thr];
				pktio    = thr_args->num_pktio;
				/* Cross connect rx to tx */
				tx_idx   = gbl_args->dst_port[rx_idx];
				thr_args->pktio[pktio].rx_idx = rx_idx;
				thr_args->pktio[pktio].tx_idx = tx_idx;
				thr_args->num_pktio++;

				gbl_args->pktios[rx_idx].num_rx_thr++;
				gbl_args->pktios[tx_idx].num_tx_thr++;

				rx_idx++;
				if (rx_idx >= if_count)
					rx_idx = 0;
			}
		}
	}
}

/*
 * Bind queues to threads and fill in missing thread arguments (handles)
 */
static void bind_queues(void)
{
	int num_workers;
	int thr, i;

	num_workers = gbl_args->appl.num_workers;

	printf("\nQueue binding (indexes)\n-----------------------\n");

	for (thr = 0; thr < num_workers; thr++) {
		int rx_idx, tx_idx;
		thread_args_t *thr_args = &gbl_args->thread_args[thr];
		int num = thr_args->num_pktio;

		printf("worker %i\n", thr);

		for (i = 0; i < num; i++) {
			int rx_queue, tx_queue;

			rx_idx   = thr_args->pktio[i].rx_idx;
			tx_idx   = thr_args->pktio[i].tx_idx;
			rx_queue = gbl_args->pktios[rx_idx].next_rx_queue;
			tx_queue = gbl_args->pktios[tx_idx].next_tx_queue;

			thr_args->pktio[i].rx_queue_idx = rx_queue;
			thr_args->pktio[i].tx_queue_idx = tx_queue;
			thr_args->pktio[i].pktin =
				gbl_args->pktios[rx_idx].pktin[rx_queue];
			thr_args->pktio[i].rx_queue =
				gbl_args->pktios[rx_idx].rx_q[rx_queue];
			thr_args->pktio[i].pktout =
				gbl_args->pktios[tx_idx].pktout[tx_queue];
			thr_args->pktio[i].tx_queue =
				gbl_args->pktios[tx_idx].tx_q[tx_queue];

			if (!gbl_args->appl.sched_mode)
				printf("  rx: pktio %i, queue %i\n",
				       rx_idx, rx_queue);

			printf("  tx: pktio %i, queue %i\n",
			       tx_idx, tx_queue);

			rx_queue++;
			tx_queue++;

			if (rx_queue >= gbl_args->pktios[rx_idx].num_rx_queue)
				rx_queue = 0;
			if (tx_queue >= gbl_args->pktios[tx_idx].num_tx_queue)
				tx_queue = 0;

			gbl_args->pktios[rx_idx].next_rx_queue = rx_queue;
			gbl_args->pktios[tx_idx].next_tx_queue = tx_queue;
		}
	}

	printf("\n");
}

static void init_port_lookup_tbl(void)
{
	int rx_idx, if_count;

	if_count = gbl_args->appl.if_count;

	for (rx_idx = 0; rx_idx < if_count; rx_idx++) {
		odp_pktio_t pktio = gbl_args->pktios[rx_idx].pktio;
		int pktio_idx     = odp_pktio_index(pktio);
		int dst_port      = find_dest_port(rx_idx);

		if (pktio_idx < 0 || pktio_idx >= MAX_PKTIO_INDEXES) {
			ODPH_ERR("Bad pktio index %i\n", pktio_idx);
			exit(EXIT_FAILURE);
		}

		gbl_args->dst_port_from_idx[pktio_idx] = dst_port;
	}
}

/*
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane L2 forwarding application.\n"
	       "\n"
	       "Usage: %s [options]\n"
	       "\n"
	       "  E.g. %s -i eth0,eth1,eth2,eth3 -m 0 -t 1\n"
	       "  In the above example,\n"
	       "  eth0 will send pkts to eth1 and vice versa\n"
	       "  eth2 will send pkts to eth3 and vice versa\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface <name>  Eth interfaces (comma-separated, no spaces)\n"
	       "                          Interface count min 1, max %i\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -m, --mode <arg>        Packet input mode\n"
	       "                          0: Direct mode: PKTIN_MODE_DIRECT (default)\n"
	       "                          1: Scheduler mode with parallel queues:\n"
	       "                             PKTIN_MODE_SCHED + SCHED_SYNC_PARALLEL\n"
	       "                          2: Scheduler mode with atomic queues:\n"
	       "                             PKTIN_MODE_SCHED + SCHED_SYNC_ATOMIC\n"
	       "                          3: Scheduler mode with ordered queues:\n"
	       "                             PKTIN_MODE_SCHED + SCHED_SYNC_ORDERED\n"
	       "                          4: Plain queue mode: PKTIN_MODE_QUEUE\n"
	       "  -o, --out_mode <arg>    Packet output mode\n"
	       "                          0: Direct mode: PKTOUT_MODE_DIRECT (default)\n"
	       "                          1: Queue mode:  PKTOUT_MODE_QUEUE\n"
	       "  -c, --count <num>       CPU count, 0=all available, default=1\n"
	       "  -t, --time <sec>        Time in seconds to run.\n"
	       "  -a, --accuracy <sec>    Time in seconds get print statistics\n"
	       "                          (default is 1 second).\n"
	       "  -d, --dst_change <arg>  0: Don't change packets' dst eth addresses\n"
	       "                          1: Change packets' dst eth addresses (default)\n"
	       "  -s, --src_change <arg>  0: Don't change packets' src eth addresses\n"
	       "                          1: Change packets' src eth addresses (default)\n"
	       "  -r, --dst_addr <addr>   Destination addresses (comma-separated, no spaces)\n"
	       "                          Requires also the -d flag to be set\n"
	       "  -e, --error_check <arg> 0: Don't check packet errors (default)\n"
	       "                          1: Check packet errors\n"
	       "  -k, --chksum <arg>      0: Don't use checksum offload (default)\n"
	       "                          1: Use checksum offload\n"
	       "  -g, --groups <num>      Number of groups to use: 0 ... num\n"
	       "                          0: SCHED_GROUP_ALL (default)\n"
	       "                          num: must not exceed number of interfaces or workers\n"
	       "  -b, --burst_rx <num>    0:   Use max burst size (default)\n"
	       "                          num: Max number of packets per receive call\n"
	       "  -v, --verbose           Verbose output.\n"
	       "  -h, --help              Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname), MAX_PKTIOS
	    );
}

/*
 * Parse and store the command line arguments
 *
 * argc       argument count
 * argv[]     argument vector
 * appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *token;
	char *addr_str;
	size_t len;
	int i;
	static const struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"time", required_argument, NULL, 't'},
		{"accuracy", required_argument, NULL, 'a'},
		{"interface", required_argument, NULL, 'i'},
		{"mode", required_argument, NULL, 'm'},
		{"out_mode", required_argument, NULL, 'o'},
		{"dst_addr", required_argument, NULL, 'r'},
		{"dst_change", required_argument, NULL, 'd'},
		{"src_change", required_argument, NULL, 's'},
		{"error_check", required_argument, NULL, 'e'},
		{"chksum", required_argument, NULL, 'k'},
		{"groups", required_argument, NULL, 'g'},
		{"burst_rx", required_argument, NULL, 'b'},
		{"verbose", no_argument, NULL, 'v'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:t:a:i:m:o:r:d:s:e:k:g:b:vh";

	appl_args->time = 0; /* loop forever if time to run is 0 */
	appl_args->accuracy = 1; /* get and print pps stats second */
	appl_args->cpu_count = 1; /* use one worker by default */
	appl_args->dst_change = 1; /* change eth dst address by default */
	appl_args->src_change = 1; /* change eth src address by default */
	appl_args->num_groups = 0; /* use default group */
	appl_args->error_check = 0; /* don't check packet errors by default */
	appl_args->burst_rx = 0;
	appl_args->verbose = 0;
	appl_args->chksum = 0; /* don't use checksum offload by default */

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 't':
			appl_args->time = atoi(optarg);
			break;
		case 'a':
			appl_args->accuracy = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'r':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			addr_str = malloc(len);
			if (addr_str == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* store the mac addresses names */
			strcpy(addr_str, optarg);
			for (token = strtok(addr_str, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				if (i >= MAX_PKTIOS) {
					printf("too many MAC addresses\n");
					usage(argv[0]);
					exit(EXIT_FAILURE);
				}
				if (odph_eth_addr_parse(&appl_args->addrs[i],
							token) != 0) {
					printf("invalid MAC address\n");
					usage(argv[0]);
					exit(EXIT_FAILURE);
				}
			}
			appl_args->addr_count = i;
			if (appl_args->addr_count < 1) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			free(addr_str);
			break;
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->if_str = malloc(len);
			if (appl_args->if_str == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL;
			     token = strtok(NULL, ","), i++)
				;

			appl_args->if_count = i;

			if (appl_args->if_count < 1 ||
			    appl_args->if_count > MAX_PKTIOS) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
			    calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				appl_args->if_names[i] = token;
			}
			break;
		case 'm':
			i = atoi(optarg);
			if (i == 1)
				appl_args->in_mode = SCHED_PARALLEL;
			else if (i == 2)
				appl_args->in_mode = SCHED_ATOMIC;
			else if (i == 3)
				appl_args->in_mode = SCHED_ORDERED;
			else if (i == 4)
				appl_args->in_mode = PLAIN_QUEUE;
			else
				appl_args->in_mode = DIRECT_RECV;
			break;
		case 'o':
			i = atoi(optarg);
			if (i != 0)
				appl_args->out_mode = PKTOUT_QUEUE;
			break;
		case 'd':
			appl_args->dst_change = atoi(optarg);
			break;
		case 's':
			appl_args->src_change = atoi(optarg);
			break;
		case 'e':
			appl_args->error_check = atoi(optarg);
			break;
		case 'k':
			appl_args->chksum = atoi(optarg);
			break;
		case 'g':
			appl_args->num_groups = atoi(optarg);
			break;
		case 'b':
			appl_args->burst_rx = atoi(optarg);
			break;
		case 'v':
			appl_args->verbose = 1;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	if (appl_args->if_count == 0) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if (appl_args->addr_count != 0 &&
	    appl_args->addr_count != appl_args->if_count) {
		printf("Number of destination addresses differs from number"
		       " of interfaces\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (appl_args->burst_rx > MAX_PKT_BURST) {
		printf("Error: Burst size (%i) too large. Maximum is %i.\n",
		       appl_args->burst_rx, MAX_PKT_BURST);
		exit(EXIT_FAILURE);
	}

	if (appl_args->burst_rx == 0)
		appl_args->burst_rx = MAX_PKT_BURST;

	appl_args->extra_check = appl_args->error_check || appl_args->chksum;

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/*
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

	odp_sys_info_print();

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n"
	       "Mode:            ");
	if (appl_args->in_mode == DIRECT_RECV)
		printf("PKTIN_DIRECT, ");
	else if (appl_args->in_mode == PLAIN_QUEUE)
		printf("PKTIN_QUEUE, ");
	else if (appl_args->in_mode == SCHED_PARALLEL)
		printf("PKTIN_SCHED_PARALLEL, ");
	else if (appl_args->in_mode == SCHED_ATOMIC)
		printf("PKTIN_SCHED_ATOMIC, ");
	else if (appl_args->in_mode == SCHED_ORDERED)
		printf("PKTIN_SCHED_ORDERED, ");

	if (appl_args->out_mode)
		printf("PKTOUT_QUEUE\n");
	else
		printf("PKTOUT_DIRECT\n");

	printf("Burst size:      %i\n", appl_args->burst_rx);

	printf("\n");
	fflush(NULL);
}

static void gbl_args_init(args_t *args)
{
	int pktio, queue;

	memset(args, 0, sizeof(args_t));

	for (pktio = 0; pktio < MAX_PKTIOS; pktio++) {
		args->pktios[pktio].pktio = ODP_PKTIO_INVALID;

		for (queue = 0; queue < MAX_QUEUES; queue++)
			args->pktios[pktio].rx_q[queue] = ODP_QUEUE_INVALID;
	}
}

static void create_groups(int num, odp_schedule_group_t *group)
{
	int i;
	odp_thrmask_t zero;

	odp_thrmask_zero(&zero);

	/* Create groups */
	for (i = 0; i < num; i++) {
		group[i] = odp_schedule_group_create(NULL, &zero);

		if (group[i] == ODP_SCHED_GROUP_INVALID) {
			ODPH_ERR("Group create failed\n");
			exit(EXIT_FAILURE);
		}
	}
}

/*
 * L2 forwarding main function
 */
int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	odph_thread_param_t thr_param[MAX_WORKERS];
	odph_thread_common_param_t thr_common;
	odp_pool_t pool;
	int i;
	int num_workers, num_thr;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odph_ethaddr_t new_addr;
	odp_pool_param_t params;
	int ret;
	stats_t *stats[MAX_WORKERS];
	int if_count;
	int (*thr_run_func)(void *);
	odp_instance_t instance;
	int num_groups;
	odp_schedule_group_t group[MAX_PKTIOS];
	odp_init_t init;
	odp_pool_capability_t pool_capa;
	uint32_t pkt_len, pkt_num;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init);

	/* List features not to be used (may optimize performance) */
	init.not_used.feat.cls    = 1;
	init.not_used.feat.crypto = 1;
	init.not_used.feat.ipsec  = 1;
	init.not_used.feat.timer  = 1;
	init.not_used.feat.tm     = 1;

	init.mem_model = helper_options.mem_model;

	/* Signal handler has to be registered before global init in case ODP
	 * implementation creates internal threads/processes. */
	signal(SIGINT, sig_handler);

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	gbl_args = odp_shm_addr(shm);

	if (gbl_args == NULL) {
		ODPH_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	gbl_args_init(gbl_args);

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	if (sched_mode(gbl_args->appl.in_mode))
		gbl_args->appl.sched_mode = 1;

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &gbl_args->appl);

	num_workers = MAX_WORKERS;
	if (gbl_args->appl.cpu_count && gbl_args->appl.cpu_count < MAX_WORKERS)
		num_workers = gbl_args->appl.cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	gbl_args->appl.num_workers = num_workers;

	for (i = 0; i < num_workers; i++)
		gbl_args->thread_args[i].thr_idx = i;

	if_count = gbl_args->appl.if_count;

	num_groups = gbl_args->appl.num_groups;

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	if (num_groups)
		printf("num groups:         %i\n", num_groups);

	printf("\n");

	if (num_groups > if_count || num_groups > num_workers) {
		ODPH_ERR("Too many groups. Number of groups may not exceed "
			 "number of interfaces or workers.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Error: pool capability failed\n");
		return -1;
	}

	pkt_len = POOL_PKT_LEN;
	pkt_num = POOL_PKT_NUM;

	if (pool_capa.pkt.max_len && pkt_len > pool_capa.pkt.max_len)
		pkt_len = pool_capa.pkt.max_len;

	if (pool_capa.pkt.max_num && pkt_num > pool_capa.pkt.max_num)
		pkt_num = pool_capa.pkt.max_num;

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = pkt_len;
	params.pkt.len     = pkt_len;
	params.pkt.num     = pkt_num;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &params);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	if (odp_pktio_max_index() >= MAX_PKTIO_INDEXES)
		ODPH_DBG("Warning: max pktio index (%u) is too large\n",
			 odp_pktio_max_index());

	bind_workers();

	odp_schedule_config(NULL);

	/* Default */
	if (num_groups == 0) {
		group[0]   = ODP_SCHED_GROUP_ALL;
		num_groups = 1;
	} else {
		create_groups(num_groups, group);
	}

	for (i = 0; i < if_count; ++i) {
		const char *dev = gbl_args->appl.if_names[i];
		int num_rx, num_tx;
		odp_schedule_group_t grp;

		/* A queue per worker in scheduled mode */
		num_rx = num_workers;
		num_tx = num_workers;

		if (!gbl_args->appl.sched_mode) {
			/* A queue per assigned worker */
			num_rx = gbl_args->pktios[i].num_rx_thr;
			num_tx = gbl_args->pktios[i].num_tx_thr;
		}

		/* Round robin pktios to groups */
		grp = group[i % num_groups];

		if (create_pktio(dev, i, num_rx, num_tx, pool, grp))
			exit(EXIT_FAILURE);

		/* Save interface ethernet address */
		if (odp_pktio_mac_addr(gbl_args->pktios[i].pktio,
				       gbl_args->port_eth_addr[i].addr,
				       ODPH_ETHADDR_LEN) != ODPH_ETHADDR_LEN) {
			ODPH_ERR("Error: interface ethernet address unknown\n");
			exit(EXIT_FAILURE);
		}

		/* Save destination eth address */
		if (gbl_args->appl.dst_change) {
			/* 02:00:00:00:00:XX */
			memset(&new_addr, 0, sizeof(odph_ethaddr_t));
			if (gbl_args->appl.addr_count) {
				memcpy(&new_addr, &gbl_args->appl.addrs[i],
				       sizeof(odph_ethaddr_t));
			} else {
				new_addr.addr[0] = 0x02;
				new_addr.addr[5] = i;
			}
			gbl_args->dst_eth_addr[i] = new_addr;
		}
	}

	gbl_args->pktios[i].pktio = ODP_PKTIO_INVALID;

	bind_queues();

	init_port_lookup_tbl();

	if (!gbl_args->appl.sched_mode)
		print_port_mapping();

	odp_barrier_init(&gbl_args->init_barrier, num_workers + 1);
	odp_barrier_init(&gbl_args->term_barrier, num_workers + 1);

	if (gbl_args->appl.in_mode == DIRECT_RECV)
		thr_run_func = run_worker_direct_mode;
	else if (gbl_args->appl.in_mode == PLAIN_QUEUE)
		thr_run_func = run_worker_plain_queue_mode;
	else /* SCHED_PARALLEL / SCHED_ATOMIC / SCHED_ORDERED */
		thr_run_func = run_worker_sched_mode;

	/* Create worker threads */
	memset(thr_param, 0, sizeof(thr_param));
	memset(&thr_common, 0, sizeof(thr_common));

	thr_common.instance = instance;
	thr_common.cpumask  = &cpumask;
	/* Synchronize thread start up. Test runs are more repeatable when
	 * thread / thread ID / CPU ID mapping stays constant. */
	thr_common.sync     = 1;

	for (i = 0; i < num_workers; ++i) {
		thr_param[i].start    = thr_run_func;
		thr_param[i].arg      = &gbl_args->thread_args[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;

		/* Round robin threads to groups */
		gbl_args->thread_args[i].num_groups = 1;
		gbl_args->thread_args[i].group[0] = group[i % num_groups];

		stats[i] = &gbl_args->thread_args[i].stats;
	}

	num_thr = odph_thread_create(gbl_args->thread_tbl, &thr_common,
				     thr_param, num_workers);

	if (num_thr != num_workers) {
		ODPH_ERR("Error: worker create failed %i\n", num_thr);
		exit(EXIT_FAILURE);
	}

	/* Start packet receive and transmit */
	for (i = 0; i < if_count; ++i) {
		odp_pktio_t pktio;

		pktio = gbl_args->pktios[i].pktio;
		ret   = odp_pktio_start(pktio);
		if (ret) {
			ODPH_ERR("Error: unable to start %s\n",
				 gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	ret = print_speed_stats(num_workers, stats, gbl_args->appl.time,
				gbl_args->appl.accuracy);

	for (i = 0; i < if_count; ++i) {
		if (odp_pktio_stop(gbl_args->pktios[i].pktio)) {
			ODPH_ERR("Error: unable to stop %s\n",
				 gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	gbl_args->exit_threads = 1;
	if (gbl_args->appl.in_mode != DIRECT_RECV)
		odp_barrier_wait(&gbl_args->term_barrier);

	/* Master thread waits for other threads to exit */
	num_thr = odph_thread_join(gbl_args->thread_tbl, num_workers);
	if (num_thr != num_workers) {
		ODPH_ERR("Error: worker join failed %i\n", num_thr);
			 exit(EXIT_FAILURE);
	}

	for (i = 0; i < if_count; ++i) {
		if (odp_pktio_close(gbl_args->pktios[i].pktio)) {
			ODPH_ERR("Error: unable to close %s\n",
				 gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	free(gbl_args->appl.if_names);
	free(gbl_args->appl.if_str);
	gbl_args = NULL;
	odp_mb_full();

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Error: pool destroy\n");
		exit(EXIT_FAILURE);
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Error: shm free\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Error: term local\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: term global\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}

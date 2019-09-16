/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_pktio_ordered.c  ODP ordered pktio test application
 */

/** enable strtok */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#include "dummy_crc.h"

#include <odp_api.h>
#include <odp/helper/odph_api.h>

/** Jenkins hash support.
  *
  * Copyright (C) 2006 Bob Jenkins (bob_jenkins@burtleburtle.net)
  *
  * http://burtleburtle.net/bob/hash/
  *
  * These are the credits from Bob's sources:
  *
  * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
  *
  * These are functions for producing 32-bit hashes for hash table lookup.
  * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
  * are externally useful functions.  Routines to test the hash are included
  * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
  * the public domain.  It has no warranty.
  *
  * $FreeBSD$
  */
#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define mix(a, b, c) \
{ \
	a -= c; a ^= rot(c, 4); c += b; \
	b -= a; b ^= rot(a, 6); a += c; \
	c -= b; c ^= rot(b, 8); b += a; \
	a -= c; a ^= rot(c, 16); c += b; \
	b -= a; b ^= rot(a, 19); a += c; \
	c -= b; c ^= rot(b, 4); b += a; \
}

#define final(a, b, c) \
{ \
	c ^= b; c -= rot(b, 14); \
	a ^= c; a -= rot(c, 11); \
	b ^= a; b -= rot(a, 25); \
	c ^= b; c -= rot(b, 16); \
	a ^= c; a -= rot(c, 4);  \
	b ^= a; b -= rot(a, 14); \
	c ^= b; c -= rot(b, 24); \
}

#define JHASH_GOLDEN_RATIO	0x9e3779b9

/* Maximum pool and queue size */
#define MAX_NUM_PKT             (8 * 1024)

/** Maximum number of worker threads */
#define MAX_WORKERS		(ODP_THREAD_COUNT_MAX - 1)

/** Buffer size of the packet pool buffer in bytes*/
#define PKT_POOL_BUF_SIZE	1856

/** Packet user area size in bytes */
#define PKT_UAREA_SIZE		32

/** Maximum number of packets in a burst */
#define MAX_PKT_BURST		32

/** Maximum number of pktio queues per interface */
#define MAX_QUEUES		32

/** Maximum number of pktio interfaces */
#define MAX_PKTIOS		8

/** Maximum number of packet flows */
#define MAX_FLOWS		128

ODP_STATIC_ASSERT(MAX_PKTIOS < MAX_FLOWS,
		  "MAX_FLOWS must be greater than MAX_PKTIOS\n");

/** Minimum valid packet length */
#define MIN_PACKET_LEN (ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN + ODPH_UDPHDR_LEN)

/** Default number of input queues */
#define DEF_NUM_RX_QUEUES	1

/** Default number of flows */
#define DEF_NUM_FLOWS		12

/** Default number of extra processing rounds */
#define DEF_EXTRA_ROUNDS	15

/** Default statistics print interval in seconds */
#define DEF_STATS_INT		1

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

/**
 * Packet input mode
 */
typedef enum pktin_mode_t {
	SCHED_ORDERED = 0,
	SCHED_ATOMIC,
	SCHED_PARALLEL
} pktin_mode_t;

/**
 * Parsed command line application arguments
 */
typedef struct {
	unsigned int cpu_count; /**< CPU count */
	int if_count;		/**< Number of interfaces to be used */
	int addr_count;		/**< Number of dst addresses to be used */
	int num_rx_q;		/**< Number of input queues per interface */
	int num_flows;		/**< Number of packet flows */
	int extra_rounds;	/**< Number of extra input processing rounds */
	char **if_names;	/**< Array of pointers to interface names */
	odph_ethaddr_t addrs[MAX_PKTIOS]; /**< Array of dst addresses */
	pktin_mode_t in_mode;	/**< Packet input mode */
	int time;		/**< Time in seconds to run. */
	int accuracy;		/**< Statistics print interval */
	char *if_str;		/**< Storage for interface names */
} appl_args_t;

/**
 * Queue context
 */
typedef struct {
	odp_bool_t input_queue;		/**< Input queue */
	uint64_t idx;			/**< Queue index  */
	uint64_t seq[MAX_FLOWS];	/**< Per flow sequence numbers */
} qcontext_t;

/**
 * Flow info stored in the packet user area
 */
typedef struct {
	uint64_t seq;		/**< Sequence number */
	uint32_t crc;		/**< CRC hash */
	uint16_t idx;		/**< Flow index */
	uint8_t src_idx;	/**< Source port index */
	uint8_t dst_idx;	/**< Destination port index */

} flow_t;
ODP_STATIC_ASSERT(sizeof(flow_t) <= PKT_UAREA_SIZE,
		  "Flow data doesn't fit in the packet user area\n");

/**
 * Statistics
 */
typedef union ODP_ALIGNED_CACHE {
	struct {
		/** Number of forwarded packets */
		uint64_t packets;
		/** Packets dropped due to a receive error */
		uint64_t rx_drops;
		/** Packets dropped due to a transmit error */
		uint64_t tx_drops;
		/** Packets with invalid sequence number */
		uint64_t invalid_seq;
	} s;

	uint8_t padding[ODP_CACHE_LINE_SIZE];
} stats_t;

/**
 * IPv4 5-tuple
 */
typedef struct {
	int32_t src_ip;
	int32_t dst_ip;
	int16_t src_port;
	int16_t dst_port;
	int8_t  proto;
	int8_t  pad0;
	int16_t pad1;
} ipv4_tuple5_t;

/**
 * Packet headers
 */
typedef struct {
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ipv4;
	odph_udphdr_t *udp;
} packet_hdr_t;

/**
 * Thread specific arguments
 */
typedef struct thread_args_t {
	stats_t *stats;	/**< Pointer to per thread statistics */
} thread_args_t;

/**
 * Grouping of all global data
 */
typedef struct {
	/** Per thread packet stats */
	stats_t stats[MAX_WORKERS];
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
	/** Table of port ethernet addresses */
	odph_ethaddr_t port_eth_addr[MAX_PKTIOS];
	/** Table of dst ethernet addresses */
	odph_ethaddr_t dst_eth_addr[MAX_PKTIOS];
	/** Table of dst ports */
	int dst_port[MAX_PKTIOS];
	/** Table of atomic queues for flows */
	odp_queue_t fqueue[MAX_PKTIOS][MAX_FLOWS];
	/** Table of flow queue contexts */
	qcontext_t flow_qcontext[MAX_PKTIOS][MAX_FLOWS];
	/** Table of input queue contexts */
	qcontext_t input_qcontext[MAX_PKTIOS][MAX_QUEUES];
	/** Table of pktio handles */
	struct {
		odp_pktio_t pktio;
		odp_pktout_queue_t pktout[MAX_FLOWS];
		odp_queue_t pktin[MAX_QUEUES];
		int num_rx_queue;
		int num_tx_queue;
	} pktios[MAX_PKTIOS];
	/** Global barrier to synchronize main and workers */
	odp_barrier_t barrier;
	/** Break workers loop if set to 1 */
	int exit_threads;
} args_t;

/** Global pointer to args */
static args_t *gbl_args;

/**
 * Lookup the destination port for a given packet
 *
 * @param pkt  ODP packet handle
 */
static inline int lookup_dest_port(odp_packet_t pkt)
{
	int i, src_idx;
	odp_pktio_t pktio_src;

	pktio_src = odp_packet_input(pkt);

	for (src_idx = -1, i = 0; gbl_args->pktios[i].pktio
				  != ODP_PKTIO_INVALID; i++)
		if (gbl_args->pktios[i].pktio == pktio_src)
			src_idx = i;

	if (src_idx == -1)
		ODPH_ABORT("Failed to determine pktio input\n");

	return gbl_args->dst_port[src_idx];
}

/**
 * Map required packet headers
 *
 * @param pkt      Packet handle
 * @param hdr[out] Packet headers
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
static inline int packet_hdr(odp_packet_t pkt, packet_hdr_t *hdr)
{
	uint8_t *udp;
	uint16_t eth_type;
	uint8_t ihl;

	if (odp_unlikely(odp_packet_seg_len(pkt) < MIN_PACKET_LEN))
		return -1;

	if (odp_unlikely(!odp_packet_has_eth(pkt)))
		return -1;

	hdr->eth = odp_packet_l2_ptr(pkt, NULL);
	eth_type = odp_be_to_cpu_16(hdr->eth->type);
	if (odp_unlikely(eth_type != ODPH_ETHTYPE_IPV4))
		return -1;

	hdr->ipv4 = (odph_ipv4hdr_t *)(hdr->eth + 1);
	if (odp_unlikely(hdr->ipv4->proto != ODPH_IPPROTO_UDP))
		return -1;

	ihl = ODPH_IPV4HDR_IHL(hdr->ipv4->ver_ihl);
	if (odp_unlikely(ihl < ODPH_IPV4HDR_IHL_MIN))
		return -1;

	udp = (uint8_t *)hdr->ipv4 +  (ihl * 4);

	hdr->udp = (odph_udphdr_t *)udp;

	return 0;
}

/**
 * Compute hash from a 5-tuple
 *
 * @param key      IPv4 5-tuple
 *
 * @return 32-bit hash value
 */
static inline uint64_t calc_ipv4_5tuple_hash(ipv4_tuple5_t *tuple)
{
	uint32_t a, b, c;

	a = tuple->proto + JHASH_GOLDEN_RATIO;
	b = tuple->src_ip + JHASH_GOLDEN_RATIO;
	c = tuple->dst_ip + JHASH_GOLDEN_RATIO;

	mix(a, b, c);

	a += (tuple->src_port << 16) +  tuple->dst_port + JHASH_GOLDEN_RATIO;
	final(a, b, c);

	return c;
}

/**
 * Compute packet flow index
 *
 * @param hdr      Packet headers
 *
 * @return Flow index
 */
static inline uint64_t calc_flow_idx(packet_hdr_t *hdr)
{
	ipv4_tuple5_t tuple;
	uint64_t idx;

	tuple.dst_ip = odp_be_to_cpu_32(hdr->ipv4->dst_addr);
	tuple.src_ip = odp_be_to_cpu_32(hdr->ipv4->src_addr);
	tuple.proto = hdr->ipv4->proto;
	tuple.src_port = odp_be_to_cpu_16(hdr->udp->src_port);
	tuple.dst_port = odp_be_to_cpu_16(hdr->udp->dst_port);
	tuple.pad0 = 0;
	tuple.pad1 = 0;
	idx = calc_ipv4_5tuple_hash(&tuple);

	return idx % gbl_args->appl.num_flows;
}

/**
 * Fill packet's eth addresses according to the destination port
 *
 * @param hdr[out] Packet headers
 * @param dst_port Destination port
 */
static inline void fill_eth_addrs(packet_hdr_t *hdr, int dst_port)
{
	hdr->eth->src = gbl_args->port_eth_addr[dst_port];
	hdr->eth->dst = gbl_args->dst_eth_addr[dst_port];
}

/**
 * Process flow queue
 *
 * @param ev_tbl   Array of events
 * @param num      Number of events in the array
 * @param stats    Pointer for storing thread statistics
 * @param qcontext Source queue context
 * @param pktout   Arrays of output queues
 */
static inline void process_flow(odp_event_t ev_tbl[], int num, stats_t *stats,
				qcontext_t *qcontext,
				odp_pktout_queue_t pktout[][MAX_FLOWS])
{
	odp_packet_t pkt;
	flow_t *flow;
	uint64_t queue_seq;
	int dst_if;
	int i;
	int sent;

	for (i = 0; i < num; i++) {
		pkt = odp_packet_from_event(ev_tbl[i]);

		flow = odp_packet_user_area(pkt);

		queue_seq = qcontext->seq[flow->src_idx];

		/* Check sequence number */
		if (gbl_args->appl.in_mode != SCHED_PARALLEL &&
		    odp_unlikely(flow->seq != queue_seq)) {
			printf("Invalid sequence number: packet_seq=%" PRIu64 ""
			       " queue_seq=%" PRIu64 ", src_if=%" PRIu8 ", "
			       "dst_if=%" PRIu8 ", flow=%" PRIu16 "\n",
			       flow->seq, queue_seq, flow->src_idx,
			       flow->dst_idx, flow->idx);
			qcontext->seq[flow->src_idx] = flow->seq + 1;
			stats->s.invalid_seq++;
		} else {
			qcontext->seq[flow->src_idx]++;
		}

		dst_if = flow->dst_idx;
		sent = odp_pktout_send(pktout[dst_if][flow->idx], &pkt, 1);

		if (odp_unlikely(sent != 1)) {
			stats->s.tx_drops++;
			odp_packet_free(pkt);
		}
		stats->s.packets++;
	}
}

/**
 * Process input queue
 *
 * @param ev_tbl   Array of events
 * @param num      Number of events in the array
 * @param stats    Pointer for storing thread statistics
 * @param qcontext Source queue context
 */
static inline void process_input(odp_event_t ev_tbl[], int num, stats_t *stats,
				 qcontext_t *qcontext)
{
	flow_t *flow;
	flow_t *flow_tbl[MAX_PKT_BURST];
	int ret;
	int i, j;
	int pkts = 0;

	for (i = 0; i < num; i++) {
		odp_packet_t pkt;
		packet_hdr_t hdr;
		int  flow_idx;

		pkt = odp_packet_from_event(ev_tbl[i]);

		odp_packet_prefetch(pkt, 0, MIN_PACKET_LEN);

		ret = packet_hdr(pkt, &hdr);
		if (odp_unlikely(ret)) {
			odp_packet_free(pkt);
			stats->s.rx_drops++;
			continue;
		}

		flow_idx = calc_flow_idx(&hdr);

		fill_eth_addrs(&hdr, flow_idx);

		flow = odp_packet_user_area(pkt);
		flow->idx = flow_idx;
		flow->src_idx = qcontext->idx;
		flow->dst_idx = lookup_dest_port(pkt);
		flow_tbl[pkts] = flow;

		/* Simulate "fat pipe" processing by generating extra work */
		for (j = 0; j < gbl_args->appl.extra_rounds; j++)
			flow->crc = dummy_hash_crc32c(odp_packet_data(pkt),
						      odp_packet_len(pkt), 0);
		pkts++;
	}

	if (odp_unlikely(!pkts))
		return;

	/* Set sequence numbers */
	if (gbl_args->appl.in_mode == SCHED_ORDERED)
		odp_schedule_order_lock(0);

	for (i = 0; i < pkts; i++) {
		flow = flow_tbl[i];
		flow->seq = qcontext->seq[flow->idx]++;
	}

	if (gbl_args->appl.in_mode == SCHED_ORDERED)
		odp_schedule_order_unlock(0);

	for (i = 0; i < pkts; i++) {
		flow = flow_tbl[i];
		ret = odp_queue_enq(gbl_args->fqueue[flow->dst_idx][flow->idx],
				    ev_tbl[i]);

		if (odp_unlikely(ret != 0)) {
			ODPH_ERR("odp_queue_enq() failed\n");
			stats->s.tx_drops++;
			odp_event_free(ev_tbl[i]);
		} else {
			stats->s.packets++;
		}
	}
}

/**
 * Worker thread
 *
 * @param arg      Thread arguments of type 'thread_args_t *'
 */
static int run_worker(void *arg)
{
	odp_event_t  ev_tbl[MAX_PKT_BURST];
	odp_queue_t queue;
	odp_pktout_queue_t pktout[MAX_PKTIOS][MAX_FLOWS];
	qcontext_t *qcontext;
	thread_args_t *thr_args = arg;
	stats_t *stats = thr_args->stats;
	int pkts;
	int i, j;

	memset(pktout, 0, sizeof(pktout));

	for (i = 0; i < gbl_args->appl.if_count; i++) {
		for (j = 0; j < gbl_args->appl.num_flows; j++) {
			pktout[i][j] = gbl_args->pktios[i].pktout[j %
					gbl_args->pktios[i].num_tx_queue];
		}
	}
	odp_barrier_wait(&gbl_args->barrier);

	/* Loop packets */
	while (!gbl_args->exit_threads) {
		pkts = odp_schedule_multi(&queue, ODP_SCHED_NO_WAIT, ev_tbl,
					  MAX_PKT_BURST);
		if (pkts <= 0)
			continue;

		qcontext = odp_queue_context(queue);

		if (qcontext->input_queue)
			process_input(ev_tbl, pkts, stats, qcontext);
		else
			process_flow(ev_tbl, pkts, stats, qcontext, pktout);
	}

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

/**
 * Create a pktio handle and associate with input queues
 *
 * @param dev      Name of device to open
 * @param index    Pktio index
 * @param num_rx   Number of input queues
 * @param num_tx   Number of output queues
 * @param pool     Pool to associate with device for packet RX/TX
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
static int create_pktio(const char *dev, int idx, int num_rx, int num_tx,
			odp_pool_t pool)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	odp_pktio_capability_t capa;
	odp_pktio_config_t config;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_pktio_op_mode_t mode_rx;
	odp_pktio_op_mode_t mode_tx;
	int i;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		ODPH_ERR("Error: failed to open %s\n", dev);
		return -1;
	}

	printf("Created pktio %" PRIu64 " (%s)\n",
	       odp_pktio_to_u64(pktio), dev);

	if (odp_pktio_capability(pktio, &capa)) {
		ODPH_ERR("Error: capability query failed %s\n", dev);
		odp_pktio_close(pktio);
		return -1;
	}

	odp_pktio_config_init(&config);
	config.parser.layer = ODP_PROTO_LAYER_L2;
	odp_pktio_config(pktio, &config);

	odp_pktin_queue_param_init(&pktin_param);
	odp_pktout_queue_param_init(&pktout_param);

	mode_tx = ODP_PKTIO_OP_MT;
	mode_rx = ODP_PKTIO_OP_MT;

	if (gbl_args->appl.in_mode == SCHED_ATOMIC) {
		pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
	} else if (gbl_args->appl.in_mode == SCHED_PARALLEL) {
		pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	} else {
		pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ORDERED;
		pktin_param.queue_param.sched.lock_count = 1;
	}
	pktin_param.queue_param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	pktin_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	if (num_rx > (int)capa.max_input_queues) {
		printf("Allocating %i shared input queues, %i requested\n",
		       capa.max_input_queues, num_rx);
		num_rx  = capa.max_input_queues;
		mode_rx = ODP_PKTIO_OP_MT;
	}

	if (num_tx > (int)capa.max_output_queues) {
		printf("Allocating %i shared output queues, %i requested\n",
		       capa.max_output_queues, num_tx);
		num_tx  = capa.max_output_queues;
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

	if (odp_pktin_event_queue(pktio, gbl_args->pktios[idx].pktin,
				  num_rx) != num_rx) {
		ODPH_ERR("Error: pktin event queue query failed %s\n", dev);
		return -1;
	}

	/* Set queue contexts */
	for (i = 0; i < num_rx; i++) {
		gbl_args->input_qcontext[idx][i].idx = idx;
		gbl_args->input_qcontext[idx][i].input_queue = 1;

		if (odp_queue_context_set(gbl_args->pktios[idx].pktin[i],
					  &gbl_args->input_qcontext[idx][i],
					  sizeof(qcontext_t))) {
			ODPH_ERR("Error: pktin queue context set failed %s\n",
				 dev);
			return -1;
		}
	}

	if (odp_pktout_queue(pktio,
			     gbl_args->pktios[idx].pktout,
			     num_tx) != num_tx) {
		ODPH_ERR("Error: pktout queue query failed %s\n", dev);
		return -1;
	}

	printf("Created %i input and %i output queues on (%s)\n",
	       num_rx, num_tx, dev);

	gbl_args->pktios[idx].num_rx_queue = num_rx;
	gbl_args->pktios[idx].num_tx_queue = num_tx;
	gbl_args->pktios[idx].pktio        = pktio;

	return 0;
}

/**
 *  Print statistics
 *
 * @param num_workers Number of worker threads
 * @param thr_stats   Pointer to stats storage
 * @param duration    Number of seconds to loop in
 * @param timeout     Number of seconds for stats calculation
 *
 */
static int print_speed_stats(int num_workers, stats_t *thr_stats,
			     int duration, int timeout)
{
	uint64_t pkts = 0;
	uint64_t pkts_prev = 0;
	uint64_t pps;
	uint64_t rx_drops, tx_drops, invalid_seq;
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
	odp_barrier_wait(&gbl_args->barrier);

	do {
		pkts = 0;
		rx_drops = 0;
		tx_drops = 0;
		invalid_seq = 0;

		sleep(timeout);

		for (i = 0; i < num_workers; i++) {
			pkts += thr_stats[i].s.packets;
			rx_drops += thr_stats[i].s.rx_drops;
			tx_drops += thr_stats[i].s.tx_drops;
			invalid_seq += thr_stats[i].s.invalid_seq;
		}
		if (stats_enabled) {
			pps = (pkts - pkts_prev) / timeout;
			if (pps > maximum_pps)
				maximum_pps = pps;
			printf("%" PRIu64 " pps, %" PRIu64 " max pps, ",  pps,
			       maximum_pps);

			printf("%" PRIu64 " rx drops, %" PRIu64 " tx drops, ",
			       rx_drops, tx_drops);

			printf("%" PRIu64 " invalid seq\n", invalid_seq);

			pkts_prev = pkts;
		}
		elapsed += timeout;
	} while (loop_forever || (elapsed < duration));

	if (stats_enabled)
		printf("TEST RESULT: %" PRIu64 " maximum packets per second.\n",
		       maximum_pps);

	return (pkts > 100 && !invalid_seq) ? 0 : -1;
}

/**
 * Find the destination port for a given input port
 *
 * @param port  Input port index
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

/**
 * Initialize port forwarding table
 */
static void init_forwarding_tbl(void)
{
	int rx_idx;

	for (rx_idx = 0; rx_idx < gbl_args->appl.if_count; rx_idx++)
		gbl_args->dst_port[rx_idx] = find_dest_port(rx_idx);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane ordered pktio application.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth0,eth1\n"
	       " In the above example,\n"
	       " eth0 will send pkts to eth1 and vice versa\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "                  Interface count min 1, max %i\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -m, --mode      Packet input mode\n"
	       "                  0: Scheduled ordered queues (default)\n"
	       "                  1: Scheduled atomic queues\n"
	       "                  2: Scheduled parallel queues (packet order not maintained)\n"
	       "  -r, --num_rx_q    Number of RX queues per interface\n"
	       "  -f, --num_flows   Number of packet flows\n"
	       "  -e, --extra_input <number>  Number of extra input processing rounds\n"
	       "  -c, --count <number>        CPU count, 0=all available, default=1\n"
	       "  -t, --time  <number>        Time in seconds to run.\n"
	       "  -a, --accuracy <number>     Statistics print interval in seconds\n"
	       "                              (default is 1 second).\n"
	       "  -d, --dst_addr  Destination addresses (comma-separated, no spaces)\n"
	       "  -h, --help      Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname), MAX_PKTIOS
	    );
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
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
		{"dst_addr", required_argument, NULL, 'd'},
		{"num_rx_q", required_argument, NULL, 'r'},
		{"num_flows", required_argument, NULL, 'f'},
		{"extra_input", required_argument, NULL, 'e'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "+c:t:a:i:m:d:r:f:e:h";

	appl_args->time = 0; /* loop forever if time to run is 0 */
	appl_args->accuracy = DEF_STATS_INT;
	appl_args->cpu_count = 1; /* use one worker by default */
	appl_args->num_rx_q = DEF_NUM_RX_QUEUES;
	appl_args->num_flows = DEF_NUM_FLOWS;
	appl_args->extra_rounds = DEF_EXTRA_ROUNDS;

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
		case 'd':
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
				appl_args->in_mode = SCHED_ATOMIC;
			else if (i == 2)
				appl_args->in_mode = SCHED_PARALLEL;
			else
				appl_args->in_mode = SCHED_ORDERED;
			break;
		case 'r':
			appl_args->num_rx_q = atoi(optarg);
			break;
		case 'f':
			appl_args->num_flows = atoi(optarg);
			break;
		case 'e':
			appl_args->extra_rounds = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	if (appl_args->num_flows > MAX_FLOWS) {
		printf("Too many flows requested %d, max: %d\n",
		       appl_args->num_flows, MAX_FLOWS);
		exit(EXIT_FAILURE);
	}

	if (appl_args->if_count == 0 || appl_args->num_flows == 0 ||
	    appl_args->num_rx_q == 0) {
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

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
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
	printf("\n\n");
	fflush(NULL);
}

static void gbl_args_init(args_t *args)
{
	int pktio, queue;

	memset(args, 0, sizeof(args_t));

	for (pktio = 0; pktio < MAX_PKTIOS; pktio++) {
		args->pktios[pktio].pktio = ODP_PKTIO_INVALID;

		for (queue = 0; queue < MAX_QUEUES; queue++)
			args->pktios[pktio].pktin[queue] = ODP_QUEUE_INVALID;
	}
}

/**
 * ODP ordered pktio application
 */
int main(int argc, char *argv[])
{
	odp_cpumask_t cpumask;
	odp_instance_t instance;
	odp_init_t init_param;
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_shm_t shm;
	odp_schedule_capability_t schedule_capa;
	odp_schedule_config_t schedule_config;
	odp_pool_capability_t pool_capa;
	odph_ethaddr_t new_addr;
	odph_helper_options_t helper_options;
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	stats_t *stats;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	int cpu;
	int i, j;
	int if_count;
	int ret;
	int num_workers;
	int in_mode;
	uint32_t queue_size, pool_size;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_schedule_capability(&schedule_capa)) {
		printf("Error: Schedule capa failed.\n");
		return -1;
	}

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Error: Pool capa failed\n");
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
		odp_shm_free(shm);
		exit(EXIT_FAILURE);
	}
	gbl_args_init(gbl_args);

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	odp_schedule_config_init(&schedule_config);
	odp_schedule_config(&schedule_config);

	if (gbl_args->appl.in_mode == SCHED_ORDERED) {
		/* At least one ordered lock required  */
		if (schedule_capa.max_ordered_locks < 1) {
			ODPH_ERR("Error: Ordered locks not available.\n");
			exit(EXIT_FAILURE);
		}
	}
	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &gbl_args->appl);

	num_workers = MAX_WORKERS;
	if (gbl_args->appl.cpu_count && gbl_args->appl.cpu_count < MAX_WORKERS)
		num_workers = gbl_args->appl.cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	if_count = gbl_args->appl.if_count;

	printf("Num worker threads: %i\n", num_workers);
	printf("First CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("CPU mask:           %s\n\n", cpumaskstr);

	pool_size = MAX_NUM_PKT;
	if (pool_capa.pkt.max_num && pool_capa.pkt.max_num < MAX_NUM_PKT)
		pool_size = pool_capa.pkt.max_num;

	queue_size = MAX_NUM_PKT;
	if (schedule_config.queue_size &&
	    schedule_config.queue_size < MAX_NUM_PKT)
		queue_size = schedule_config.queue_size;

	/* Pool should not be larger than queue, otherwise queue enqueues at
	 * packet input may fail. */
	if (pool_size > queue_size)
		pool_size = queue_size;

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = PKT_POOL_BUF_SIZE;
	params.pkt.len     = PKT_POOL_BUF_SIZE;
	params.pkt.num     = pool_size;
	params.pkt.uarea_size = PKT_UAREA_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &params);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	init_forwarding_tbl();

	for (i = 0; i < if_count; ++i) {
		const char *dev = gbl_args->appl.if_names[i];
		int num_rx, num_tx;

		num_rx = gbl_args->appl.num_rx_q;
		num_tx = gbl_args->appl.num_flows;

		if (create_pktio(dev, i, num_rx, num_tx, pool))
			exit(EXIT_FAILURE);

		/* Save interface ethernet address */
		if (odp_pktio_mac_addr(gbl_args->pktios[i].pktio,
				       gbl_args->port_eth_addr[i].addr,
				       ODPH_ETHADDR_LEN) != ODPH_ETHADDR_LEN) {
			ODPH_ERR("Error: interface ethernet address unknown\n");
			exit(EXIT_FAILURE);
		}

		odp_pktio_print(gbl_args->pktios[i].pktio);

		/* Save destination eth address */
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

	gbl_args->pktios[i].pktio = ODP_PKTIO_INVALID;

	/* Allocate the same number of flows to each interface */
	for (i = 0; i < if_count; i++) {
		odp_pktio_capability_t capa;

		if (odp_pktio_capability(gbl_args->pktios[i].pktio, &capa)) {
			ODPH_ERR("Error: pktio capability failed.\n");
			exit(EXIT_FAILURE);
		}

		if ((unsigned)gbl_args->appl.num_flows > capa.max_output_queues)
			gbl_args->appl.num_flows = capa.max_output_queues;
	}

	/* Create atomic queues for packet tagging */
	for (i = 0; i < if_count; i++) {
		for (j = 0; j < gbl_args->appl.num_flows; j++) {
			odp_queue_t queue;
			odp_queue_param_t qparam;
			char qname[ODP_QUEUE_NAME_LEN];

			snprintf(qname, sizeof(qname), "flow_%d_%d", i, j);

			odp_queue_param_init(&qparam);
			qparam.type       = ODP_QUEUE_TYPE_SCHED;
			qparam.sched.prio = ODP_SCHED_PRIO_DEFAULT;
			qparam.sched.sync = ODP_SCHED_SYNC_ATOMIC;
			qparam.sched.group = ODP_SCHED_GROUP_ALL;
			qparam.size	  = queue_size;

			gbl_args->flow_qcontext[i][j].idx = i;
			gbl_args->flow_qcontext[i][j].input_queue = 0;
			qparam.context = &gbl_args->flow_qcontext[i][j];
			qparam.context_len =  sizeof(qcontext_t);

			queue = odp_queue_create(qname, &qparam);
			if (queue == ODP_QUEUE_INVALID) {
				ODPH_ERR("Error: flow queue create failed.\n");
				exit(EXIT_FAILURE);
			}

			gbl_args->fqueue[i][j] = queue;
		}
	}

	in_mode = gbl_args->appl.in_mode;
	printf("\nApplication parameters\n"
	       "----------------------\n"
	       "Input queues: %d\n"
	       "Mode:         %s\n"
	       "Flows:        %d\n"
	       "Extra rounds: %d\n\n", gbl_args->appl.num_rx_q,
	       (in_mode == SCHED_ATOMIC) ? "PKTIN_SCHED_ATOMIC" :
	       (in_mode == SCHED_PARALLEL ? "PKTIN_SCHED_PARALLEL" :
	       "PKTIN_SCHED_ORDERED"), gbl_args->appl.num_flows,
	       gbl_args->appl.extra_rounds);

	memset(thread_tbl, 0, sizeof(thread_tbl));

	stats = gbl_args->stats;

	odp_barrier_init(&gbl_args->barrier, num_workers + 1);

	/* Create worker threads */
	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; ++i) {
		odp_cpumask_t thd_mask;
		odph_odpthread_params_t thr_params;

		memset(&thr_params, 0, sizeof(thr_params));
		thr_params.start    = run_worker;
		thr_params.arg      = &gbl_args->thread[i];
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;

		gbl_args->thread[i].stats = &stats[i];

		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);
		odph_odpthreads_create(&thread_tbl[i], &thd_mask,
				       &thr_params);
		cpu = odp_cpumask_next(&cpumask, cpu);
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

	/* Stop receiving new packet */
	for (i = 0; i < if_count; i++)
		odp_pktio_stop(gbl_args->pktios[i].pktio);

	gbl_args->exit_threads = 1;

	/* Master thread waits for other threads to exit */
	for (i = 0; i < num_workers; ++i)
		odph_odpthreads_join(&thread_tbl[i]);

	for (i = 0; i < if_count; i++) {
		odp_pktio_close(gbl_args->pktios[i].pktio);

		for (j = 0; j < gbl_args->appl.num_flows; j++)
			odp_queue_destroy(gbl_args->fqueue[i][j]);
	}

	free(gbl_args->appl.if_names);
	free(gbl_args->appl.if_str);

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

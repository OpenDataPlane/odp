/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2020 Nokia
 */

/**
 * @example odp_switch.c
 *
 * Minimal learning Ethernet switch example application
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <signal.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

/** Maximum number of worker threads */
#define MAX_WORKERS            (ODP_THREAD_COUNT_MAX - 1)

/** Size of the shared memory block */
#define SHM_PKT_POOL_SIZE      8192

/** Buffer size of the packet pool buffer */
#define SHM_PKT_POOL_BUF_SIZE  1856

/** Maximum number of packet in a burst */
#define MAX_PKT_BURST          32

/** Maximum number of pktio queues per interface */
#define MAX_QUEUES             32

/** Maximum number of pktio interfaces. Must be <= UINT8_MAX. */
#define MAX_PKTIOS             8

/** Number of MAC table entries. Must match to hash length. */
#define MAC_TBL_SIZE           UINT16_MAX

/** Aging time for MAC table entries in minutes. Must be <= UINT8_MAX. */
#define AGING_TIME 5

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

/** Local copy of MAC forwarding table entry */
typedef union {
	struct {
		odph_ethaddr_t mac; /**< Ethernet MAC address */
		uint8_t port;	    /**< Port index */
		uint8_t tick;	    /**< Tick of the latest received packet */
	} s;

	uint64_t u64;
} mac_tbl_entry_t;

/**
 * Parsed command line application arguments
 */
typedef struct {
	unsigned int cpu_count; /**< Number of CPUs to be used */
	unsigned int if_count;  /**< Number of interfaces to be used */
	int num_workers;   /**< Number of worker threads */
	char **if_names;   /**< Array of pointers to interface names */
	int time;	   /**< Time in seconds to run */
	int accuracy;	   /**< Statistics get and print interval in seconds */
	char *if_str;	   /**< Storage for interface names */
} appl_args_t;

typedef enum frame_type_t {
	FRAME_UNICAST,
	FRAME_BROADCAST,
	FRAME_INVALID
} frame_type_t;

/**
 * Statistics
 */
typedef union ODP_ALIGNED_CACHE {
	struct {
		/** Number of received packets */
		uint64_t rx_packets;
		/** Number of transmitted packets */
		uint64_t tx_packets;
		/** Packets dropped due to receive error */
		uint64_t rx_drops;
		/** Packets dropped due to transmit error */
		uint64_t tx_drops;
	} s;

	uint8_t padding[ODP_CACHE_LINE_SIZE];
} stats_t;

/**
 * Packet buffer
 */
typedef struct pkt_buf_t {
	odp_packet_t pkt[MAX_PKT_BURST]; /**< Array of packet handles */
	unsigned int len;		 /**< Number of packets in buffer */
} pkt_buf_t;

/**
 * Thread specific arguments
 */
typedef struct thread_args_t {
	 /** Number of interfaces from which to receive packets */
	int num_rx_pktio;
	struct {
		odp_pktin_queue_t pktin;   /**< Packet input queue */
		uint8_t port_idx;	   /**< Port index */
		int queue_idx;		   /**< Queue index */
	} rx_pktio[MAX_PKTIOS];
	struct {
		odp_pktout_queue_t pktout; /**< Packet output queue */
		int queue_idx;		   /**< Queue index */
		pkt_buf_t buf;		   /**< Packet TX buffer */
	} tx_pktio[MAX_PKTIOS];

	stats_t *stats[MAX_PKTIOS];	   /**< Interface statistics */
} thread_args_t;

/**
 * Grouping of all global data
 */
typedef struct {
	/** Per thread interface statistics */
	stats_t stats[MAX_WORKERS][MAX_PKTIOS];
	appl_args_t appl;		   /**< Parsed application arguments */
	thread_args_t thread[MAX_WORKERS]; /**< Thread specific arguments */
	odp_pool_t pool;		   /**< Packet pool */
	/** Global barrier to synchronize main and workers */
	odp_barrier_t barrier;
	/** Break workers loop if set to 1 */
	odp_atomic_u32_t exit_threads;
	/** Table of pktio handles */
	struct {
		odp_pktio_t pktio;
		odp_pktin_queue_t pktin[MAX_QUEUES];
		odp_pktout_queue_t pktout[MAX_QUEUES];
		int num_rx_thr;
		int num_rx_queue;
		int num_tx_queue;
		int next_rx_queue;
		int next_tx_queue;
	} pktios[MAX_PKTIOS];

	odp_atomic_u64_t mac_tbl[MAC_TBL_SIZE]; /**< MAC forwarding table */
} args_t;

/** Global pointer to args */
static args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	odp_atomic_store_u32(&gbl_args->exit_threads, 1);
}

/**
 * Calculate MAC table index using Ethernet address hash
 *
 * @param mac        Pointer to Ethernet address
 *
 * @retval MAC table index
 */
static inline uint16_t calc_mac_tbl_idx(odph_ethaddr_t *mac)
{
	uint32_t hash;

	hash = odp_hash_crc32c(mac->addr, ODPH_ETHADDR_LEN, 0);

	return (uint16_t)(hash & 0xFFFF);
}

/**
 * Calculate diff between ticks and take care of value wrap
 */
static inline uint8_t diff_ticks(uint8_t t2, uint8_t t1)
{
	if (t1 < t2)
		return t2 - t1;
	else if (t1 > t2)
		return UINT8_MAX + t2 - t1;
	return 0;
}

/**
 * Get Ethernet address port index from MAC table
 *
 * @param mac        Pointer to Ethernet address
 * @param port[out]  Pointer to port index for output
 * @param cur_tick   Current tick
 *
 * @retval 1 on entry found
 * @retval 0 on entry not found or expired
 */
static inline int mac_table_get(odph_ethaddr_t *mac, uint8_t *port,
				uint8_t cur_tick)
{
	mac_tbl_entry_t entry;
	uint16_t idx;

	idx = calc_mac_tbl_idx(mac);

	entry.u64 = odp_atomic_load_u64(&gbl_args->mac_tbl[idx]);

	if (memcmp(mac->addr, entry.s.mac.addr, ODPH_ETHADDR_LEN))
		return 0;

	if (odp_unlikely(diff_ticks(cur_tick, entry.s.tick) > AGING_TIME))
		return 0;

	*port = entry.s.port;
	return 1;
}

/**
 * Put Ethernet address port index to MAC table
 *
 * @param mac        Pointer to Ethernet address
 * @param port       Pointer to port index
 * @param cur_tick   Current tick
 */
static inline void mac_table_update(odph_ethaddr_t *mac, uint8_t port,
				    uint8_t cur_tick)
{
	mac_tbl_entry_t entry;
	uint16_t idx;

	idx = calc_mac_tbl_idx(mac);
	entry.u64 = odp_atomic_load_u64(&gbl_args->mac_tbl[idx]);

	if (memcmp(entry.s.mac.addr, mac->addr, ODPH_ETHADDR_LEN) ||
	    entry.s.port != port || entry.s.tick != cur_tick) {
		entry.s.mac = *mac;
		entry.s.port = port;
		entry.s.tick = cur_tick;
		odp_atomic_store_u64(&gbl_args->mac_tbl[idx], entry.u64);
	}
}

/**
 * Create a pktio handle
 *
 * @param dev        Name of device to open
 * @param index      Pktio index
 * @param num_rx     Number of RX queues
 * @param num_tx     Number of TX queues
 * @param pool       Pool to associate with device for packet RX/TX
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

	odp_pktio_param_init(&pktio_param);

	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		printf("Error: failed to open %s\n", dev);
		return -1;
	}

	printf("created pktio %" PRIu64 " (%s)\n", odp_pktio_to_u64(pktio),
	       dev);

	if (odp_pktio_capability(pktio, &capa)) {
		printf("Error: capability query failed %s\n", dev);
		return -1;
	}

	odp_pktio_config_init(&config);
	config.parser.layer = ODP_PROTO_LAYER_L2;
	odp_pktio_config(pktio, &config);

	odp_pktin_queue_param_init(&pktin_param);
	odp_pktout_queue_param_init(&pktout_param);

	mode_tx = ODP_PKTIO_OP_MT_UNSAFE;
	mode_rx = ODP_PKTIO_OP_MT_UNSAFE;

	if (num_rx > (int)capa.max_input_queues) {
		printf("Sharing %i input queues between %i workers\n",
		       capa.max_input_queues, num_rx);
		num_rx  = capa.max_input_queues;
		mode_rx = ODP_PKTIO_OP_MT;
	}

	if (num_tx > (int)capa.max_output_queues) {
		printf("Sharing %i output queues between %i workers\n",
		       capa.max_output_queues, num_tx);
		num_tx  = capa.max_output_queues;
		mode_tx = ODP_PKTIO_OP_MT;
	}

	pktin_param.hash_enable = (num_rx > 1) ? 1 : 0;
	pktin_param.hash_proto.proto.ipv4_tcp = 1;
	pktin_param.hash_proto.proto.ipv4_udp = 1;
	pktin_param.num_queues  = num_rx;
	pktin_param.op_mode     = mode_rx;

	pktout_param.op_mode    = mode_tx;
	pktout_param.num_queues = num_tx;

	if (odp_pktin_queue_config(pktio, &pktin_param)) {
		printf("Error: input queue config failed %s\n", dev);
		return -1;
	}
	if (odp_pktout_queue_config(pktio, &pktout_param)) {
		printf("Error: output queue config failed %s\n", dev);
		return -1;
	}
	if (odp_pktin_queue(pktio, gbl_args->pktios[idx].pktin,
			    num_rx) != num_rx) {
		printf("Error: pktin queue query failed %s\n", dev);
		return -1;
	}
	if (odp_pktout_queue(pktio, gbl_args->pktios[idx].pktout,
			     num_tx) != num_tx) {
		printf("Error: pktout queue query failed %s\n", dev);
		return -1;
	}

	printf("created %i input and %i output queues on (%s)\n", num_rx,
	       num_tx, dev);

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
 * @retval 0 on success
 * @retval -1 on failure
 */
static int print_speed_stats(int num_workers, stats_t (*thr_stats)[MAX_PKTIOS],
			     int duration, int timeout)
{
	uint64_t rx_pkts_prev[MAX_PKTIOS] = {0};
	uint64_t tx_pkts_prev[MAX_PKTIOS] = {0};
	uint64_t rx_pkts_tot;
	uint64_t tx_pkts_tot;
	uint64_t rx_drops_tot;
	uint64_t tx_drops_tot;
	uint64_t rx_pps;
	uint64_t tx_pps;
	int i, j;
	int elapsed = 0;
	int stats_enabled = 1;
	int loop_forever = (duration == 0);
	int num_ifaces = gbl_args->appl.if_count;

	if (timeout <= 0) {
		stats_enabled = 0;
		timeout = 1;
	}
	/* Wait for all threads to be ready*/
	odp_barrier_wait(&gbl_args->barrier);

	do {
		uint64_t rx_pkts[MAX_PKTIOS] = {0};
		uint64_t tx_pkts[MAX_PKTIOS] = {0};
		uint64_t rx_drops[MAX_PKTIOS] = {0};
		uint64_t tx_drops[MAX_PKTIOS] = {0};

		rx_pkts_tot = 0;
		tx_pkts_tot = 0;
		rx_drops_tot = 0;
		tx_drops_tot = 0;

		sleep(timeout);
		elapsed += timeout;

		for (i = 0; i < num_workers; i++) {
			for (j = 0; j < num_ifaces; j++) {
				rx_pkts[j] += thr_stats[i][j].s.rx_packets;
				tx_pkts[j] += thr_stats[i][j].s.tx_packets;
				rx_drops[j] += thr_stats[i][j].s.rx_drops;
				tx_drops[j] += thr_stats[i][j].s.tx_drops;
			}
		}

		if (!stats_enabled)
			continue;

		for (j = 0; j < num_ifaces; j++) {
			rx_pps = (rx_pkts[j] - rx_pkts_prev[j]) / timeout;
			tx_pps = (tx_pkts[j] - tx_pkts_prev[j]) / timeout;
			printf("  Port %d: %" PRIu64 " rx pps, %" PRIu64
			       " tx pps, %" PRIu64 " rx pkts, %" PRIu64
			       " tx pkts, %" PRIu64 " rx drops, %" PRIu64
			       " tx drops\n", j, rx_pps, tx_pps, rx_pkts[j],
			       tx_pkts[j], rx_drops[j], tx_drops[j]);

			rx_pkts_prev[j] = rx_pkts[j];
			tx_pkts_prev[j] = tx_pkts[j];
			rx_pkts_tot += rx_pkts[j];
			tx_pkts_tot += tx_pkts[j];
			rx_drops_tot += rx_drops[j];
			tx_drops_tot += tx_drops[j];
		}

		printf("Total: %" PRIu64 " rx pkts, %" PRIu64 " tx pkts, %"
		       PRIu64 " rx drops, %" PRIu64 " tx drops\n", rx_pkts_tot,
		       tx_pkts_tot, rx_drops_tot, tx_drops_tot);

	} while (!odp_atomic_load_u32(&gbl_args->exit_threads) &&
		 (loop_forever || (elapsed < duration)));

	return rx_pkts_tot >= 100 ? 0 : -1;
}

/**
 *  Print switch worker mappings and port configuration
 */
static void print_port_mapping(void)
{
	int if_count, num_workers;
	int thr, pktio;

	if_count    = gbl_args->appl.if_count;
	num_workers = gbl_args->appl.num_workers;

	printf("\nWorker mapping table (port[queue])\n--------------------\n");

	for (thr = 0; thr < num_workers; thr++) {
		uint8_t port_idx;
		int queue_idx;
		thread_args_t *thr_args = &gbl_args->thread[thr];
		int num = thr_args->num_rx_pktio;

		printf("Worker %i\n", thr);

		for (pktio = 0; pktio < num; pktio++) {
			port_idx = thr_args->rx_pktio[pktio].port_idx;
			queue_idx =  thr_args->rx_pktio[pktio].queue_idx;
			printf("  %i[%i]\n", port_idx, queue_idx);
		}
	}

	printf("\nPort config\n--------------------\n");

	for (pktio = 0; pktio < if_count; pktio++) {
		const char *dev = gbl_args->appl.if_names[pktio];

		printf("Port %i (%s)\n", pktio, dev);
		printf("  rx workers %i\n",
		       gbl_args->pktios[pktio].num_rx_thr);
		printf("  rx queues %i\n",
		       gbl_args->pktios[pktio].num_rx_queue);
		printf("  tx queues %i\n",
		       gbl_args->pktios[pktio].num_tx_queue);
	}

	printf("\n");
}

/**
 * Broadcast packet to all ports except ingress
 *
 * @param pkt        Packet handle
 * @param thr_arg    Thread arguments
 * @param port_in    Input port index
 */
static inline void broadcast_packet(odp_packet_t pkt, thread_args_t *thr_arg,
				    uint8_t port_in)
{
	odp_bool_t first = 1;
	uint8_t port_out;
	unsigned int buf_len;

	for (port_out = 0; port_out < gbl_args->appl.if_count; port_out++) {
		if (port_out == port_in)
			continue;

		buf_len = thr_arg->tx_pktio[port_out].buf.len;

		if (first) { /* No need to copy for the first interface */
			thr_arg->tx_pktio[port_out].buf.pkt[buf_len] = pkt;
			first = 0;
		} else {
			odp_packet_t pkt_cp;

			pkt_cp = odp_packet_copy(pkt, gbl_args->pool);
			if (pkt_cp == ODP_PACKET_INVALID) {
				printf("Error: packet copy failed\n");
				continue;
			}
			thr_arg->tx_pktio[port_out].buf.pkt[buf_len] = pkt_cp;
		}
		thr_arg->tx_pktio[port_out].buf.len++;
	}
}

/**
 * Check Ethernet frame for broadcast/invalid addresses
 *
 * @param eth  Pointer to an Ethernet header
 *
 * @retval Ethernet frame_type_t
 */
static frame_type_t check_frame(odph_ethhdr_t *eth)
{
	static uint8_t broadcast_addr[ODPH_ETHADDR_LEN] = {0xff, 0xff, 0xff,
							   0xff, 0xff, 0xff};
	static uint8_t null_addr[ODPH_ETHADDR_LEN] = {0, 0, 0, 0, 0, 0};

	/* Drop invalid frames */
	if (odp_unlikely(!memcmp(eth->src.addr, broadcast_addr,
				 ODPH_ETHADDR_LEN) ||
			 !memcmp(eth->dst.addr, null_addr,
				 ODPH_ETHADDR_LEN) ||
			 !memcmp(eth->src.addr, null_addr,
				 ODPH_ETHADDR_LEN))) {
		return FRAME_INVALID;
	}
	if (!memcmp(eth->dst.addr, broadcast_addr, ODPH_ETHADDR_LEN))
		return FRAME_BROADCAST;

	return FRAME_UNICAST;
}

/**
 * Forward packets to correct output buffers
 *
 * Packets, whose destination MAC address is already known from previously
 * received packets, are forwarded to the matching switch ports. Packets
 * destined to unknown addresses are broadcasted to all switch ports (except
 * the ingress port).
 *
 * @param pkt_tbl    Array of packets
 * @param num        Number of packets in the array
 * @param thr_arg    Thread arguments
 * @param port_in    Input port index
 * @param cur_tick   Current tick
 */
static inline void forward_packets(odp_packet_t pkt_tbl[], unsigned int num,
				   thread_args_t *thr_arg, uint8_t port_in,
				   uint8_t cur_tick)
{
	odp_packet_t pkt;
	odph_ethhdr_t *eth;
	unsigned int i;
	unsigned int buf_id;
	uint8_t port_out = 0;
	int frame_type;

	for (i = 0; i < num; i++) {
		pkt = pkt_tbl[i];

		if (!odp_packet_has_eth(pkt)) {
			thr_arg->stats[port_in]->s.rx_drops++;
			odp_packet_free(pkt);
			continue;
		}

		eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);

		/* Check Ethernet frame type */
		frame_type = check_frame(eth);
		if (odp_unlikely(frame_type == FRAME_INVALID)) {
			thr_arg->stats[port_in]->s.rx_drops++;
			odp_packet_free(pkt);
			continue;
		}

		/* Update source address MAC table entry */
		mac_table_update(&eth->src, port_in, cur_tick);

		/* Broadcast frame is necessary */
		if (frame_type == FRAME_BROADCAST ||
		    !mac_table_get(&eth->dst, &port_out, cur_tick)) {
			broadcast_packet(pkt, thr_arg, port_in);
			continue;
		}
		buf_id = thr_arg->tx_pktio[port_out].buf.len;

		thr_arg->tx_pktio[port_out].buf.pkt[buf_id] = pkt;
		thr_arg->tx_pktio[port_out].buf.len++;
	}
}

/*
 * Bind worker threads to switch ports and calculate number of queues needed
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
	int rx_idx, thr, pktio;
	thread_args_t *thr_args;

	if_count    = gbl_args->appl.if_count;
	num_workers = gbl_args->appl.num_workers;

	if (if_count > num_workers) {
		thr = 0;

		for (rx_idx = 0; rx_idx < if_count; rx_idx++) {
			thr_args = &gbl_args->thread[thr];
			pktio    = thr_args->num_rx_pktio;
			thr_args->rx_pktio[pktio].port_idx = rx_idx;
			thr_args->num_rx_pktio++;

			gbl_args->pktios[rx_idx].num_rx_thr++;

			thr++;
			if (thr >= num_workers)
				thr = 0;
		}
	} else {
		rx_idx = 0;

		for (thr = 0; thr < num_workers; thr++) {
			thr_args = &gbl_args->thread[thr];
			pktio    = thr_args->num_rx_pktio;
			thr_args->rx_pktio[pktio].port_idx = rx_idx;
			thr_args->num_rx_pktio++;

			gbl_args->pktios[rx_idx].num_rx_thr++;

			rx_idx++;
			if (rx_idx >= if_count)
				rx_idx = 0;
		}
	}
}

/**
 * Switch worker thread
 *
 * @param arg  Thread arguments of type 'thread_args_t *'
 */
static int run_worker(void *arg)
{
	thread_args_t *thr_args = arg;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	odp_pktin_queue_t pktin;
	odp_pktout_queue_t pktout;
	odp_time_t time_prev;
	odp_time_t minute;
	uint8_t cur_tick;
	unsigned int num_pktio;
	unsigned int pktio = 0;
	uint8_t port_in;
	uint8_t port_out;
	int pkts;

	num_pktio = thr_args->num_rx_pktio;
	pktin     = thr_args->rx_pktio[pktio].pktin;
	port_in  = thr_args->rx_pktio[pktio].port_idx;

	odp_barrier_wait(&gbl_args->barrier);

	minute = odp_time_local_from_ns(ODP_TIME_MIN_IN_NS);
	time_prev = odp_time_local();
	cur_tick = (odp_time_to_ns(time_prev) / ODP_TIME_MIN_IN_NS) % UINT8_MAX;

	while (!odp_atomic_load_u32(&gbl_args->exit_threads)) {
		odp_time_t time_cur;
		odp_time_t time_diff;
		int sent;
		unsigned int drops;

		if (num_pktio > 1) {
			pktin     = thr_args->rx_pktio[pktio].pktin;
			port_in = thr_args->rx_pktio[pktio].port_idx;
			pktio++;
			if (pktio == num_pktio)
				pktio = 0;
		}

		pkts = odp_pktin_recv(pktin, pkt_tbl, MAX_PKT_BURST);
		if (odp_unlikely(pkts <= 0))
			continue;

		time_cur = odp_time_local();
		time_diff = odp_time_diff(time_cur, time_prev);

		if (odp_unlikely(odp_time_cmp(time_diff, minute))) {
			/* Tick stored as 8 bit value */
			cur_tick = (odp_time_to_ns(time_cur) /
					ODP_TIME_MIN_IN_NS) % UINT8_MAX;
			time_prev = time_cur;
		}

		thr_args->stats[port_in]->s.rx_packets += pkts;

		/* Sort packets to thread local tx buffers */
		forward_packets(pkt_tbl, pkts, thr_args, port_in, cur_tick);

		/* Empty all thread local tx buffers */
		for (port_out = 0; port_out < gbl_args->appl.if_count;
				port_out++) {
			unsigned int tx_pkts;
			odp_packet_t *tx_pkt_tbl;

			if (port_out == port_in ||
			    thr_args->tx_pktio[port_out].buf.len == 0)
				continue;

			tx_pkts = thr_args->tx_pktio[port_out].buf.len;
			thr_args->tx_pktio[port_out].buf.len = 0;

			tx_pkt_tbl = thr_args->tx_pktio[port_out].buf.pkt;

			pktout = thr_args->tx_pktio[port_out].pktout;

			sent = odp_pktout_send(pktout, tx_pkt_tbl, tx_pkts);
			sent = odp_unlikely(sent < 0) ? 0 : sent;

			thr_args->stats[port_out]->s.tx_packets += sent;

			drops = tx_pkts - sent;

			if (odp_unlikely(drops)) {
				unsigned int i;

				thr_args->stats[port_out]->s.tx_drops += drops;

				/* Drop rejected packets */
				for (i = sent; i < tx_pkts; i++)
					odp_packet_free(tx_pkt_tbl[i]);
			}
		}
	}

	/* Make sure that latest stat writes are visible to other threads */
	odp_mb_full();

	return 0;
}

/*
 * Bind queues to threads and fill in missing thread arguments (handles)
 */
static void bind_queues(void)
{
	int num_workers;
	int thr, pktio;

	num_workers = gbl_args->appl.num_workers;

	for (thr = 0; thr < num_workers; thr++) {
		int rx_idx;
		thread_args_t *thr_args = &gbl_args->thread[thr];
		int num = thr_args->num_rx_pktio;

		/* Receive only from selected ports */
		for (pktio = 0; pktio < num; pktio++) {
			int rx_queue;

			rx_idx   = thr_args->rx_pktio[pktio].port_idx;
			rx_queue = gbl_args->pktios[rx_idx].next_rx_queue;

			thr_args->rx_pktio[pktio].pktin =
				gbl_args->pktios[rx_idx].pktin[rx_queue];
			thr_args->rx_pktio[pktio].queue_idx = rx_queue;

			rx_queue++;
			if (rx_queue >= gbl_args->pktios[rx_idx].num_rx_queue)
				rx_queue = 0;
			gbl_args->pktios[rx_idx].next_rx_queue = rx_queue;
		}
		/* Send to all ports */
		for (pktio = 0; pktio < (int)gbl_args->appl.if_count; pktio++) {
			int tx_queue;

			tx_queue = gbl_args->pktios[pktio].next_tx_queue;

			thr_args->tx_pktio[pktio].pktout =
				gbl_args->pktios[pktio].pktout[tx_queue];
			thr_args->tx_pktio[pktio].queue_idx = tx_queue;

			tx_queue++;
			if (tx_queue >= gbl_args->pktios[pktio].num_tx_queue)
				tx_queue = 0;
			gbl_args->pktios[pktio].next_tx_queue = tx_queue;
		}
	}
}

/**
 * Print usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane learning switch example.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth0,eth1,eth2,eth3\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "                  Interface count min 2, max %i\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -c, --count <number> CPU count, 0=all available, default=1\n"
	       "  -t, --time  <number> Time in seconds to run.\n"
	       "  -a, --accuracy <number> Statistics print interval in seconds\n"
	       "                          (default is 10 second).\n"
	       "  -h, --help           Display help and exit.\n\n"
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
	size_t len;
	unsigned int i;
	static const struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"time", required_argument, NULL, 't'},
		{"accuracy", required_argument, NULL, 'a'},
		{"interface", required_argument, NULL, 'i'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:t:a:i:h";

	appl_args->cpu_count = 1; /* use one worker by default */
	appl_args->time = 0; /* loop forever if time to run is 0 */
	appl_args->accuracy = 10; /* get and print pps stats second */

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

			if (appl_args->if_count < 2 ||
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

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	unsigned int i;

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
	int pktio;

	memset(args, 0, sizeof(args_t));
	odp_atomic_init_u32(&args->exit_threads, 0);

	for (pktio = 0; pktio < MAX_PKTIOS; pktio++)
		args->pktios[pktio].pktio = ODP_PKTIO_INVALID;
}

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odph_thread_t thread_tbl[MAX_WORKERS];
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param[MAX_WORKERS];
	int i, j;
	int num_workers;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	int ret;
	stats_t (*stats)[MAX_PKTIOS];
	int if_count;
	odp_instance_t instance;
	odp_init_t init_param;

	signal(SIGINT, sig_handler);

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		printf("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		printf("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		printf("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	gbl_args = odp_shm_addr(shm);

	if (gbl_args == NULL) {
		printf("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	gbl_args_init(gbl_args);

	for (i = 0; (unsigned int)i < MAC_TBL_SIZE; i++)
		odp_atomic_init_u64(&gbl_args->mac_tbl[i], 0);

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &gbl_args->appl);

	num_workers = MAX_WORKERS;
	if (gbl_args->appl.cpu_count && gbl_args->appl.cpu_count < MAX_WORKERS)
		num_workers = gbl_args->appl.cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	gbl_args->appl.num_workers = num_workers;

	if_count = gbl_args->appl.if_count;

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE;
	params.type        = ODP_POOL_PACKET;

	gbl_args->pool = odp_pool_create("packet pool", &params);
	if (gbl_args->pool == ODP_POOL_INVALID) {
		printf("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(gbl_args->pool);

	bind_workers();

	for (i = 0; i < if_count; ++i) {
		const char *dev = gbl_args->appl.if_names[i];
		int num_rx;

		/* An RX queue per assigned worker and a private TX queue for
		 * each worker */
		num_rx = gbl_args->pktios[i].num_rx_thr;

		if (create_pktio(dev, i, num_rx, num_workers, gbl_args->pool))
			exit(EXIT_FAILURE);

		if (odp_pktio_promisc_mode(gbl_args->pktios[i].pktio) != 1) {
			ret = odp_pktio_promisc_mode_set(gbl_args->pktios[i].pktio, 1);
			if (ret != 0) {
				printf("Error: failed to set %s to promiscuous mode.\n", dev);
				exit(EXIT_FAILURE);
			}
		}
	}
	gbl_args->pktios[i].pktio = ODP_PKTIO_INVALID;

	bind_queues();

	print_port_mapping();

	memset(thread_tbl, 0, sizeof(thread_tbl));

	odp_barrier_init(&gbl_args->barrier, num_workers + 1);

	stats = gbl_args->stats;

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;

	/* Create worker threads */
	for (i = 0; i < num_workers; ++i) {
		for (j = 0; j < MAX_PKTIOS; j++)
			gbl_args->thread[i].stats[j] = &stats[i][j];

		odph_thread_param_init(&thr_param[i]);
		thr_param[i].start = run_worker;
		thr_param[i].arg = &gbl_args->thread[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;
	}

	odph_thread_create(thread_tbl, &thr_common, thr_param, num_workers);

	/* Start packet receive and transmit */
	for (i = 0; i < if_count; ++i) {
		odp_pktio_t pktio;

		pktio = gbl_args->pktios[i].pktio;
		ret   = odp_pktio_start(pktio);
		if (ret) {
			printf("Error: unable to start %s\n",
			       gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	ret = print_speed_stats(num_workers, gbl_args->stats,
				gbl_args->appl.time, gbl_args->appl.accuracy);
	odp_atomic_store_u32(&gbl_args->exit_threads, 1);

	/* Master thread waits for other threads to exit */
	odph_thread_join(thread_tbl, num_workers);

	/* Stop and close used pktio devices */
	for (i = 0; i < if_count; i++) {
		odp_pktio_t pktio = gbl_args->pktios[i].pktio;

		if (odp_pktio_stop(pktio) || odp_pktio_close(pktio)) {
			printf("Error: failed to close pktio\n");
			exit(EXIT_FAILURE);
		}
	}

	free(gbl_args->appl.if_names);
	free(gbl_args->appl.if_str);

	if (odp_pool_destroy(gbl_args->pool)) {
		printf("Error: pool destroy\n");
		exit(EXIT_FAILURE);
	}

	if (odp_shm_free(shm)) {
		printf("Error: shm free\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		printf("Error: term local\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		printf("Error: term global\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}

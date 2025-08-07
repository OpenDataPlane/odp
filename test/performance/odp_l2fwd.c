/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2019-2025 Nokia
 * Copyright (c) 2020-2021 Marvell
 */

/**
 * @example odp_l2fwd.c
 *
 * This L2 forwarding application can be used as example as well as performance
 * test for different ODP packet I/O modes (direct, queue or scheduled).
 *
 * Note that this example is tuned for performance. As a result, when using
 * scheduled packet input mode with direct or queued output mode and multiple
 * output queues, packet order is not guaranteed. To maintain packet order,
 * use a single worker thread or output interfaces with one output queue.
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
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

/* Default number of packets per pool */
#define DEFAULT_NUM_PKT        (16 * 1024)

/* Packet length to pool create */
#define POOL_PKT_LEN           1536

/* Maximum number of packet in a burst */
#define MAX_PKT_BURST          32

/* Maximum number of pktio queues per interface */
#define MAX_QUEUES             32

/* Maximum number of schedule groups */
#define MAX_GROUPS             32

/* Maximum number of pktio interfaces */
#define MAX_PKTIOS             8

/* Default vector size */
#define DEFAULT_VEC_SIZE       MAX_PKT_BURST

/* Default vector timeout */
#define DEFAULT_VEC_TMO        ODP_TIME_MSEC_IN_NS

/* Maximum thread info string length */
#define EXTRA_STR_LEN          32

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
	/* Some extra features (e.g. error checks) have been enabled */
	uint8_t extra_feat;

	/* Has some state that needs to be maintained across tx and/or rx */
	uint8_t has_state;

	/* Prefetch packet data */
	uint8_t prefetch;

	/* Change destination eth addresses */
	uint8_t dst_change;

	/* Change source eth addresses */
	uint8_t src_change;

	/* Read packet data in uint64_t words */
	uint16_t data_rd;

	/* Check packet errors */
	uint8_t error_check;

	/* Packet copy */
	uint8_t packet_copy;

	/* Checksum offload */
	uint8_t chksum;

	/* Print debug info on every packet */
	uint8_t verbose_pkt;

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
	int sched_mode;         /* Scheduler mode */
	int num_groups;         /* Number of scheduling groups */
	int group_mode;         /* How threads join groups */
	int burst_rx;           /* Receive burst size */
	int rx_queues;          /* RX queues per interface */
	int pool_per_if;        /* Create pool per interface */
	uint32_t num_pkt;       /* Number of packets per pool */
	int flow_control;       /* Flow control mode */
	bool pause_rx;          /* Reception of pause frames enabled */
	bool pause_tx;          /* Transmission of pause frames enabled */
	bool vector_mode;       /* Vector mode enabled */
	uint32_t num_vec;       /* Number of vectors per pool */
	uint64_t vec_tmo_ns;    /* Vector formation timeout in ns */
	uint32_t vec_size;      /* Vector size */
	uint64_t wait_ns;       /* Extra wait in ns */
	uint64_t memcpy_bytes;  /* Extra memcpy bytes */
	int verbose;            /* Verbose output */
	uint32_t packet_len;    /* Maximum packet length supported */
	uint32_t seg_len;       /* Pool segment length */
	int promisc_mode;       /* Promiscuous mode enabled */
	int flow_aware;         /* Flow aware scheduling enabled */
	uint8_t input_ts;       /* Packet input timestamping enabled */
	int mtu;                /* Interface MTU */
	int num_om;
	int num_prio;

	struct {
		odp_packet_tx_compl_mode_t mode;
		uint32_t nth;
		uint32_t thr_compl_id;
		uint32_t tot_compl_id;
	} tx_compl;

	char *output_map[MAX_PKTIOS]; /* Destination port mappings for interfaces */
	odp_schedule_prio_t prio[MAX_PKTIOS]; /* Priority of input queues of an interface */

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
		/* Number of transmit completion start misses (previous incomplete) */
		uint64_t tx_c_misses;
		/* Number of transmit completion start failures */
		uint64_t tx_c_fails;
		/* Number of failed packet copies */
		uint64_t copy_fails;
		/* Dummy sum of packet data */
		uint64_t dummy_sum;
	} s;

	uint8_t padding[ODP_CACHE_LINE_SIZE];
} stats_t;

/* Transmit completion specific state data */
typedef struct {
	/* Options that are passed to transmit completion requests */
	odp_packet_tx_compl_opt_t opt;
	/* Thread specific initial value for transmit completion IDs */
	uint32_t init;
	/* Thread specific maximum value for transmit completion IDs */
	uint32_t max;
	/* Next free completion ID to be used for a transmit completion request */
	uint32_t free_head;
	/* Next completion ID to be polled for transmit completion readiness */
	uint32_t poll_head;
	/* Number of active requests */
	uint32_t num_act;
	/* Maximum number of active requests */
	uint32_t max_act;
	/* Transmit completion request interval for packets */
	int interval;
	/* Next packet in a send burst for which to request transmit completion */
	int next_req;
} tx_compl_t;

/* Thread specific state data */
typedef struct {
	tx_compl_t tx_compl;
} state_t;

/* Thread specific data */
typedef struct thread_args_t {
	stats_t stats;
	state_t state;

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
	odp_schedule_group_t group[MAX_GROUPS];

	int thr_idx;
	int num_pktio;
	int num_grp_join;

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
		odp_queue_t compl_q;
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
	uint8_t dst_port_from_idx[ODP_PKTIO_MAX_INDEX + 1];
	/* Break workers loop if set to 1 */
	odp_atomic_u32_t exit_threads;

	uint32_t pkt_len;
	uint32_t num_pkt;
	uint32_t seg_len;
	uint32_t vector_num;
	uint32_t vector_max_size;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_shm_t memcpy_shm; /* Shared memory block for memcpy */
	uint8_t *memcpy_data; /* Data for memcpy */

} args_t;

/* Global pointer to args */
static args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	odp_atomic_store_u32(&gbl_args->exit_threads, 1);
}

static int setup_sig_handler(void)
{
	struct sigaction action = { .sa_handler = sig_handler };

	if (sigemptyset(&action.sa_mask) || sigaction(SIGINT, &action, NULL))
		return -1;

	return 0;
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

static inline void prefetch_data(uint8_t prefetch, odp_packet_t pkt_tbl[], uint32_t num)
{
	if (prefetch == 0)
		return;

	for (uint32_t i = 0; i < num; i++)
		odp_packet_prefetch(pkt_tbl[i], 0, prefetch * 64);
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

		if (odp_unlikely(ret <= 0)) {
			if (ret < 0 || odp_atomic_load_u32(&gbl_args->exit_threads))
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

static void print_packets(odp_packet_t *pkt_tbl, int num)
{
	odp_packet_t pkt;
	uintptr_t data_ptr;
	uint32_t bit, align;

	for (int i = 0; i < num; i++) {
		pkt = pkt_tbl[i];
		data_ptr = (uintptr_t)odp_packet_data(pkt);

		for (bit = 0, align = 1; bit < 32; bit++, align *= 2)
			if (data_ptr & (0x1 << bit))
				break;

		printf("  Packet data:    0x%" PRIxPTR "\n"
		       "  Packet len:     %u\n"
		       "  Packet seg len: %u\n"
		       "  Data align:     %u\n"
		       "  Num segments:   %i\n"
		       "  Headroom size:  %u\n"
		       "  User area size: %u\n\n",
		       data_ptr, odp_packet_len(pkt), odp_packet_seg_len(pkt), align,
		       odp_packet_num_segs(pkt), odp_packet_headroom(pkt),
		       odp_packet_user_area_size(pkt));
	}
}

static inline void data_rd(odp_packet_t *pkt_tbl, int num, uint16_t rd_words, stats_t *stats)
{
	odp_packet_t pkt;
	uint64_t *data;
	int i;
	uint32_t len, words, j;
	uint64_t sum = 0;

	for (i = 0; i < num; i++) {
		pkt  = pkt_tbl[i];
		data = odp_packet_data(pkt);
		len  = odp_packet_seg_len(pkt);

		words = rd_words;
		if (rd_words * 8 > len)
			words = len / 8;

		for (j = 0; j < words; j++)
			sum += data[j];
	}

	stats->s.dummy_sum += sum;
}

static inline int copy_packets(odp_packet_t *pkt_tbl, int pkts)
{
	odp_packet_t old_pkt, new_pkt;
	odp_pool_t pool;
	int i;
	int copy_fails = 0;

	for (i = 0; i < pkts; i++) {
		old_pkt = pkt_tbl[i];
		pool    = odp_packet_pool(old_pkt);
		new_pkt = odp_packet_copy(old_pkt, pool);
		if (odp_likely(new_pkt != ODP_PACKET_INVALID)) {
			pkt_tbl[i] = new_pkt;
			odp_packet_free(old_pkt);
		} else {
			copy_fails++;
		}
	}

	return copy_fails;
}

/*
 * Return number of packets remaining in the pkt_tbl
 */
static inline int process_extra_features(const appl_args_t *appl_args, odp_packet_t *pkt_tbl,
					 int pkts, stats_t *stats, uint8_t *const memcpy_src)
{
	if (odp_unlikely(appl_args->extra_feat)) {
		uint16_t rd_words = appl_args->data_rd;

		if (appl_args->verbose_pkt)
			print_packets(pkt_tbl, pkts);

		if (rd_words)
			data_rd(pkt_tbl, pkts, rd_words, stats);

		if (appl_args->packet_copy) {
			int fails;

			fails = copy_packets(pkt_tbl, pkts);
			stats->s.copy_fails += fails;
		}

		if (appl_args->chksum)
			chksum_insert(pkt_tbl, pkts);

		if (appl_args->error_check) {
			int rx_drops;

			/* Drop packets with errors */
			rx_drops = drop_err_pkts(pkt_tbl, pkts);

			if (odp_unlikely(rx_drops)) {
				stats->s.rx_drops += rx_drops;
				if (pkts == rx_drops)
					return 0;

				pkts -= rx_drops;
			}
		}

		if (appl_args->wait_ns)
			odp_time_wait_ns(appl_args->wait_ns);

		if (appl_args->memcpy_bytes) {
			const uint64_t bytes = appl_args->memcpy_bytes;
			uint8_t *memcpy_dst = memcpy_src + bytes;

			memcpy(memcpy_dst, memcpy_src, bytes);
		}
	}
	return pkts;
}

static inline void handle_tx_event_compl(tx_compl_t *tx_c, odp_packet_t pkts[], int num,
					 int tx_idx, stats_t *stats)
{
	odp_packet_t pkt;
	int next_req = tx_c->next_req;
	const int interval = tx_c->interval;

	tx_c->opt.queue = gbl_args->pktios[tx_idx].compl_q;

	while (next_req <= num) {
		pkt = pkts[next_req - 1];

		if (odp_packet_tx_compl_request(pkt, &tx_c->opt) < 0) {
			stats->s.tx_c_fails++;
			/* Missed one, try requesting for the first packet of next burst. */
			next_req = num + 1;
			break;
		}

		next_req += interval;
	}

	tx_c->next_req = next_req - num;
}

static inline void handle_tx_poll_compl(tx_compl_t *tx_c, odp_packet_t pkts[], int num, int tx_idx,
					stats_t *stats)
{
	uint32_t num_act = tx_c->num_act, poll_head = tx_c->poll_head, free_head = tx_c->free_head;
	const uint32_t max = tx_c->max, init = tx_c->init, max_act = tx_c->max_act;
	odp_pktio_t pktio = gbl_args->pktios[tx_idx].pktio;
	int next_req = tx_c->next_req;
	odp_packet_t pkt;
	const int interval = tx_c->interval;

	while (num_act > 0) {
		if (odp_packet_tx_compl_done(pktio, poll_head) < 1)
			break;

		--num_act;

		if (++poll_head > max)
			poll_head = init;
	}

	while (next_req <= num) {
		pkt = pkts[next_req - 1];

		if (num_act == max_act) {
			stats->s.tx_c_misses++;
			/* Missed one, try requesting for the first packet of next burst. */
			next_req = num + 1;
			break;
		}

		tx_c->opt.compl_id = free_head;

		if (odp_packet_tx_compl_request(pkt, &tx_c->opt) < 0) {
			stats->s.tx_c_fails++;
			/* Missed one, try requesting for the first packet of next burst. */
			next_req = num + 1;
			break;
		}

		if (++free_head > max)
			free_head = init;

		++num_act;
		next_req += interval;
	}

	tx_c->free_head = free_head;
	tx_c->poll_head = poll_head;
	tx_c->num_act = num_act;
	tx_c->next_req = next_req - num;
}

static inline void handle_tx_state(state_t *state, odp_packet_t pkts[], int num, int tx_idx,
				   stats_t *stats)
{
	tx_compl_t *tx_c = &state->tx_compl;

	if (tx_c->opt.mode == ODP_PACKET_TX_COMPL_EVENT)
		handle_tx_event_compl(tx_c, pkts, num, tx_idx, stats);
	else if (tx_c->opt.mode == ODP_PACKET_TX_COMPL_POLL)
		handle_tx_poll_compl(tx_c, pkts, num, tx_idx, stats);
}

static inline void handle_state_failure(state_t *state, odp_packet_t packet)
{
	if (odp_packet_has_tx_compl_request(packet) != 0) {
		--state->tx_compl.num_act;
		--state->tx_compl.free_head;

		if (state->tx_compl.free_head == UINT32_MAX ||
		    state->tx_compl.free_head < state->tx_compl.init)
			state->tx_compl.free_head = state->tx_compl.max;
	}
}

static inline void send_packets(odp_packet_t *pkt_tbl,
				int pkts,
				int use_event_queue,
				int tx_idx,
				odp_queue_t tx_queue,
				odp_pktout_queue_t pktout_queue,
				state_t *state,
				stats_t *stats)
{
	int sent;
	unsigned int tx_drops;
	int i;
	odp_packet_t pkt;

	if (odp_unlikely(state != NULL))
		handle_tx_state(state, pkt_tbl, pkts, tx_idx, stats);

	if (odp_unlikely(use_event_queue))
		sent = event_queue_send(tx_queue, pkt_tbl, pkts);
	else
		sent = odp_pktout_send(pktout_queue, pkt_tbl, pkts);

	sent = odp_unlikely(sent < 0) ? 0 : sent;
	tx_drops = pkts - sent;

	if (odp_unlikely(tx_drops)) {
		stats->s.tx_drops += tx_drops;

		/* Drop rejected packets */
		for (i = sent; i < pkts; i++) {
			pkt = pkt_tbl[i];
			handle_state_failure(state, pkt);
			odp_packet_free(pkt);
		}
	}

	stats->s.packets += pkts;
}

static int handle_rx_state(state_t *state, odp_event_t evs[], int num)
{
	if (state->tx_compl.opt.mode != ODP_PACKET_TX_COMPL_EVENT ||
	    odp_event_type(evs[0]) != ODP_EVENT_PACKET_TX_COMPL)
		return num;

	odp_event_free_multi(evs, num);

	return 0;
}

/*
 * Packet IO worker thread using scheduled queues and vector mode.
 *
 * arg  thread arguments of type 'thread_args_t *'
 */
static int run_worker_sched_mode_vector(void *arg)
{
	const int thr = odp_thread_id();
	int i;
	int pktio, num_pktio;
	uint16_t max_burst;
	odp_thrmask_t mask;
	odp_pktout_queue_t pktout[MAX_PKTIOS];
	odp_queue_t tx_queue[MAX_PKTIOS];
	thread_args_t *thr_args = arg;
	const int thr_idx = thr_args->thr_idx;
	stats_t *stats = &thr_args->stats;
	const appl_args_t *appl_args = &gbl_args->appl;
	uint8_t *const memcpy_src = appl_args->memcpy_bytes ?
		&gbl_args->memcpy_data[thr_idx * 2 * appl_args->memcpy_bytes] : NULL;
	state_t *state = appl_args->has_state ? &thr_args->state : NULL;
	int use_event_queue = gbl_args->appl.out_mode;
	pktin_mode_t in_mode = gbl_args->appl.in_mode;

	max_burst = gbl_args->appl.burst_rx;

	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr);

	/* Join non-default groups */
	for (i = 0; i < thr_args->num_grp_join; i++) {
		if (odp_schedule_group_join(thr_args->group[i], &mask)) {
			ODPH_ERR("Join failed: %i\n", i);
			return -1;
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

	printf("[%02i] PKTIN_SCHED_%s_VECTOR, %s\n", thr,
	       (in_mode == SCHED_PARALLEL) ? "PARALLEL" :
	       ((in_mode == SCHED_ATOMIC) ? "ATOMIC" : "ORDERED"),
	       (use_event_queue) ? "PKTOUT_QUEUE" : "PKTOUT_DIRECT");

	odp_barrier_wait(&gbl_args->init_barrier);

	/* Loop packets */
	while (!odp_atomic_load_u32(&gbl_args->exit_threads)) {
		odp_event_t  ev_tbl[MAX_PKT_BURST];
		int events;

		events = odp_schedule_multi_no_wait(NULL, ev_tbl, max_burst);

		if (events <= 0)
			continue;

		for (i = 0; i < events; i++) {
			odp_packet_vector_t pkt_vec = ODP_PACKET_VECTOR_INVALID;
			odp_packet_t *pkt_tbl = NULL;
			odp_packet_t pkt;
			int src_idx, dst_idx;
			int pkts = 0;

			if (odp_event_type(ev_tbl[i]) == ODP_EVENT_PACKET) {
				pkt = odp_packet_from_event(ev_tbl[i]);
				pkt_tbl = &pkt;
				pkts = 1;
			} else if (odp_event_type(ev_tbl[i]) == ODP_EVENT_PACKET_VECTOR) {
				pkt_vec = odp_packet_vector_from_event(ev_tbl[i]);
				pkts = odp_packet_vector_tbl(pkt_vec, &pkt_tbl);
			} else if (state != NULL) {
				pkts = handle_rx_state(state, ev_tbl, events);

				if (pkts <= 0)
					continue;
			}

			prefetch_data(appl_args->prefetch, pkt_tbl, pkts);

			pkts = process_extra_features(appl_args, pkt_tbl, pkts, stats, memcpy_src);

			if (odp_unlikely(pkts == 0)) {
				if (pkt_vec != ODP_PACKET_VECTOR_INVALID)
					odp_packet_vector_free(pkt_vec);
				continue;
			}

			/* packets from the same queue are from the same interface */
			src_idx = odp_packet_input_index(pkt_tbl[0]);
			ODPH_ASSERT(src_idx >= 0);
			dst_idx = gbl_args->dst_port_from_idx[src_idx];
			fill_eth_addrs(pkt_tbl, pkts, dst_idx);

			send_packets(pkt_tbl, pkts, use_event_queue, dst_idx, tx_queue[dst_idx],
				     pktout[dst_idx], state, stats);

			if (pkt_vec != ODP_PACKET_VECTOR_INVALID)
				odp_packet_vector_free(pkt_vec);
		}
	}

	/*
	 * Free prefetched packets before entering the thread barrier.
	 * Such packets can block sending of later packets in other threads
	 * that then would never enter the thread barrier and we would
	 * end up in a dead-lock.
	 */
	odp_schedule_pause();
	while (1) {
		odp_event_t  ev;

		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}

	/* Make sure that latest stat writes are visible to other threads */
	odp_mb_full();

	/* Wait until pktio devices are stopped */
	odp_barrier_wait(&gbl_args->term_barrier);

	/* Free remaining events in queues */
	odp_schedule_resume();
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
 * Packet IO worker thread using scheduled queues
 *
 * arg  thread arguments of type 'thread_args_t *'
 */
static int run_worker_sched_mode(void *arg)
{
	int pkts;
	const int thr = odp_thread_id();
	int dst_idx;
	int i;
	int pktio, num_pktio;
	uint16_t max_burst;
	odp_thrmask_t mask;
	odp_pktout_queue_t pktout[MAX_PKTIOS];
	odp_queue_t tx_queue[MAX_PKTIOS];
	char extra_str[EXTRA_STR_LEN];
	thread_args_t *thr_args = arg;
	const int thr_idx = thr_args->thr_idx;
	stats_t *stats = &thr_args->stats;
	const appl_args_t *appl_args = &gbl_args->appl;
	uint8_t *const memcpy_src = appl_args->memcpy_bytes ?
		&gbl_args->memcpy_data[thr_idx * 2 * appl_args->memcpy_bytes] : NULL;
	state_t *state = appl_args->has_state ? &thr_args->state : NULL;
	int use_event_queue = gbl_args->appl.out_mode;
	pktin_mode_t in_mode = gbl_args->appl.in_mode;

	max_burst = gbl_args->appl.burst_rx;

	memset(extra_str, 0, EXTRA_STR_LEN);
	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, thr);

	/* Join non-default groups */
	for (i = 0; i < thr_args->num_grp_join; i++) {
		if (odp_schedule_group_join(thr_args->group[i], &mask)) {
			ODPH_ERR("Join failed: %i\n", i);
			return -1;
		}

		if (gbl_args->appl.verbose) {
			uint64_t tmp = (uint64_t)(uintptr_t)thr_args->group[i];

			printf("[%02i] Joined group 0x%" PRIx64 "\n", thr, tmp);
		}
	}

	if (thr_args->num_grp_join)
		snprintf(extra_str, EXTRA_STR_LEN, ", joined %i groups", thr_args->num_grp_join);
	else if (gbl_args->appl.num_groups == 0)
		snprintf(extra_str, EXTRA_STR_LEN, ", GROUP_ALL");
	else if (gbl_args->appl.num_groups)
		snprintf(extra_str, EXTRA_STR_LEN, ", GROUP_WORKER");

	num_pktio = thr_args->num_pktio;

	if (num_pktio > MAX_PKTIOS) {
		ODPH_ERR("Too many pktios %i\n", num_pktio);
		return -1;
	}

	for (pktio = 0; pktio < num_pktio; pktio++) {
		tx_queue[pktio] = thr_args->pktio[pktio].tx_queue;
		pktout[pktio]   = thr_args->pktio[pktio].pktout;
	}

	printf("[%02i] PKTIN_SCHED_%s, %s%s\n", thr,
	       (in_mode == SCHED_PARALLEL) ? "PARALLEL" :
	       ((in_mode == SCHED_ATOMIC) ? "ATOMIC" : "ORDERED"),
	       (use_event_queue) ? "PKTOUT_QUEUE" : "PKTOUT_DIRECT", extra_str);

	odp_barrier_wait(&gbl_args->init_barrier);

	/* Loop packets */
	while (!odp_atomic_load_u32(&gbl_args->exit_threads)) {
		odp_event_t  ev_tbl[MAX_PKT_BURST];
		odp_packet_t pkt_tbl[MAX_PKT_BURST];
		int src_idx;

		pkts = odp_schedule_multi_no_wait(NULL, ev_tbl, max_burst);

		if (pkts <= 0)
			continue;

		if (odp_unlikely(state != NULL)) {
			pkts = handle_rx_state(state, ev_tbl, pkts);

			if (pkts <= 0)
				continue;
		}

		odp_packet_from_event_multi(pkt_tbl, ev_tbl, pkts);

		prefetch_data(appl_args->prefetch, pkt_tbl, pkts);

		pkts = process_extra_features(appl_args, pkt_tbl, pkts, stats, memcpy_src);

		if (odp_unlikely(pkts == 0))
			continue;

		/* packets from the same queue are from the same interface */
		src_idx = odp_packet_input_index(pkt_tbl[0]);
		ODPH_ASSERT(src_idx >= 0);
		dst_idx = gbl_args->dst_port_from_idx[src_idx];
		fill_eth_addrs(pkt_tbl, pkts, dst_idx);

		send_packets(pkt_tbl, pkts, use_event_queue, dst_idx, tx_queue[dst_idx],
			     pktout[dst_idx], state, stats);
	}

	/*
	 * Free prefetched packets before entering the thread barrier.
	 * Such packets can block sending of later packets in other threads
	 * that then would never enter the thread barrier and we would
	 * end up in a dead-lock.
	 */
	odp_schedule_pause();
	while (1) {
		odp_event_t  ev;

		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
		if (ev == ODP_EVENT_INVALID)
			break;
		odp_event_free(ev);
	}

	/* Make sure that latest stat writes are visible to other threads */
	odp_mb_full();

	/* Wait until pktio devices are stopped */
	odp_barrier_wait(&gbl_args->term_barrier);

	/* Free remaining events in queues */
	odp_schedule_resume();
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
	const int thr = odp_thread_id();
	int pkts;
	uint16_t max_burst;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int dst_idx, num_pktio;
	odp_queue_t queue;
	odp_pktout_queue_t pktout;
	odp_queue_t tx_queue;
	int pktio = 0;
	thread_args_t *thr_args = arg;
	const int thr_idx = thr_args->thr_idx;
	stats_t *stats = &thr_args->stats;
	const appl_args_t *appl_args = &gbl_args->appl;
	uint8_t *const memcpy_src = appl_args->memcpy_bytes ?
		&gbl_args->memcpy_data[thr_idx * 2 * appl_args->memcpy_bytes] : NULL;
	state_t *state = appl_args->has_state ? &thr_args->state : NULL;
	int use_event_queue = gbl_args->appl.out_mode;
	int i;

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
	while (!odp_atomic_load_u32(&gbl_args->exit_threads)) {
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

		prefetch_data(appl_args->prefetch, pkt_tbl, pkts);

		pkts = process_extra_features(appl_args, pkt_tbl, pkts, stats, memcpy_src);

		if (odp_unlikely(pkts == 0))
			continue;

		fill_eth_addrs(pkt_tbl, pkts, dst_idx);

		send_packets(pkt_tbl, pkts, use_event_queue, dst_idx, tx_queue, pktout, state,
			     stats);
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
	const int thr = odp_thread_id();
	int pkts;
	uint16_t max_burst;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int dst_idx, num_pktio;
	odp_pktin_queue_t pktin;
	odp_pktout_queue_t pktout;
	odp_queue_t tx_queue;
	int pktio = 0;
	thread_args_t *thr_args = arg;
	const int thr_idx = thr_args->thr_idx;
	stats_t *stats = &thr_args->stats;
	const appl_args_t *appl_args = &gbl_args->appl;
	uint8_t *const memcpy_src = appl_args->memcpy_bytes ?
		&gbl_args->memcpy_data[thr_idx * 2 * appl_args->memcpy_bytes] : NULL;
	state_t *state = appl_args->has_state ? &thr_args->state : NULL;
	int use_event_queue = gbl_args->appl.out_mode;

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
	while (!odp_atomic_load_u32(&gbl_args->exit_threads)) {
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

		prefetch_data(appl_args->prefetch, pkt_tbl, pkts);

		pkts = process_extra_features(appl_args, pkt_tbl, pkts, stats, memcpy_src);

		if (odp_unlikely(pkts == 0))
			continue;

		fill_eth_addrs(pkt_tbl, pkts, dst_idx);

		send_packets(pkt_tbl, pkts, use_event_queue, dst_idx, tx_queue, pktout, state,
			     stats);
	}

	/* Make sure that latest stat writes are visible to other threads */
	odp_mb_full();

	return 0;
}

static int set_pktin_vector_params(odp_pktin_queue_param_t *pktin_param, odp_pool_t vec_pool,
				   const odp_pktio_capability_t *pktio_capa)
{
	uint64_t vec_tmo_ns;
	uint32_t vec_size;

	pktin_param->vector.enable = true;
	pktin_param->vector.pool = vec_pool;

	if (gbl_args->appl.vec_size == 0)
		vec_size = DEFAULT_VEC_SIZE;
	else
		vec_size = gbl_args->appl.vec_size;

	if (vec_size > pktio_capa->vector.max_size || vec_size < pktio_capa->vector.min_size) {
		if (gbl_args->appl.vec_size == 0) {
			vec_size = (vec_size > pktio_capa->vector.max_size) ?
				pktio_capa->vector.max_size : pktio_capa->vector.min_size;
			printf("\nWarning: Modified vector size to %u\n\n", vec_size);
		} else {
			ODPH_ERR("Invalid pktio vector size %u, valid range [%u, %u]\n",
				 vec_size, pktio_capa->vector.min_size,
				 pktio_capa->vector.max_size);
			return -1;
		}
	}
	pktin_param->vector.max_size = vec_size;

	if (gbl_args->appl.vec_tmo_ns == 0)
		vec_tmo_ns = DEFAULT_VEC_TMO;
	else
		vec_tmo_ns = gbl_args->appl.vec_tmo_ns;

	if (vec_tmo_ns > pktio_capa->vector.max_tmo_ns ||
	    vec_tmo_ns < pktio_capa->vector.min_tmo_ns) {
		if (gbl_args->appl.vec_tmo_ns == 0) {
			vec_tmo_ns = (vec_tmo_ns > pktio_capa->vector.max_tmo_ns) ?
				pktio_capa->vector.max_tmo_ns : pktio_capa->vector.min_tmo_ns;
			printf("\nWarning: Modified vector timeout to %" PRIu64 "\n\n", vec_tmo_ns);
		} else {
			ODPH_ERR("Invalid vector timeout %" PRIu64 ", valid range [%" PRIu64
				 ", %" PRIu64 "]\n", vec_tmo_ns,
				 pktio_capa->vector.min_tmo_ns, pktio_capa->vector.max_tmo_ns);
			return -1;
		}
	}
	pktin_param->vector.max_tmo_ns = vec_tmo_ns;

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
static int create_pktio(const char *dev, int idx, int num_rx, int num_tx, odp_pool_t pool,
			odp_pool_t vec_pool, odp_schedule_group_t group)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	odp_schedule_sync_t  sync_mode;
	odp_pktio_capability_t pktio_capa;
	odp_pktio_config_t config;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_queue_param_t compl_queue;
	odp_pktio_op_mode_t mode_rx;
	odp_pktio_op_mode_t mode_tx;
	pktin_mode_t in_mode = gbl_args->appl.in_mode;
	odp_pktio_info_t info;
	uint8_t *addr;

	odp_pktio_param_init(&pktio_param);

	if (in_mode == PLAIN_QUEUE)
		pktio_param.in_mode = ODP_PKTIN_MODE_QUEUE;
	else if (in_mode != DIRECT_RECV) /* pktin_mode SCHED_* */
		pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	if (gbl_args->appl.out_mode != PKTOUT_DIRECT)
		pktio_param.out_mode = ODP_PKTOUT_MODE_QUEUE;

	if (num_rx == 0)
		pktio_param.in_mode = ODP_PKTIN_MODE_DISABLED;

	if (num_tx == 0)
		pktio_param.out_mode = ODP_PKTOUT_MODE_DISABLED;

	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		ODPH_ERR("Pktio open failed: %s\n", dev);
		return -1;
	}

	if (odp_pktio_info(pktio, &info)) {
		ODPH_ERR("Pktio info failed: %s\n", dev);
		return -1;
	}

	if (odp_pktio_capability(pktio, &pktio_capa)) {
		ODPH_ERR("Pktio capability query failed: %s\n", dev);
		return -1;
	}

	odp_pktio_config_init(&config);

	if (gbl_args->appl.input_ts) {
		if (!pktio_capa.config.pktin.bit.ts_all) {
			ODPH_ERR("Packet input timestamping not supported: %s\n", dev);
			return -1;
		}
		config.pktin.bit.ts_all = 1;
	}

	config.parser.layer = ODP_PROTO_LAYER_NONE;
	if (gbl_args->appl.error_check || gbl_args->appl.chksum)
		config.parser.layer = ODP_PROTO_LAYER_ALL;

	if (gbl_args->appl.chksum) {
		config.pktout.bit.ipv4_chksum_ena = 1;
		config.pktout.bit.udp_chksum_ena  = 1;
		config.pktout.bit.tcp_chksum_ena  = 1;
	}

	if (gbl_args->appl.tx_compl.mode != ODP_PACKET_TX_COMPL_DISABLED) {
		if (gbl_args->appl.tx_compl.mode == ODP_PACKET_TX_COMPL_EVENT &&
		    !(pktio_capa.tx_compl.mode_event && pktio_capa.tx_compl.queue_type_sched)) {
			ODPH_ERR("Transmit event completion not supported: %s\n", dev);
			return -1;
		}

		if (gbl_args->appl.tx_compl.mode == ODP_PACKET_TX_COMPL_POLL &&
		    !(pktio_capa.tx_compl.mode_poll &&
		      pktio_capa.tx_compl.max_compl_id >= gbl_args->appl.tx_compl.tot_compl_id)) {
			ODPH_ERR("Transmit poll completion not supported: %s\n", dev);
			return -1;
		}

		if (gbl_args->appl.tx_compl.mode == ODP_PACKET_TX_COMPL_EVENT)
			config.tx_compl.mode_event = 1;

		if (gbl_args->appl.tx_compl.mode == ODP_PACKET_TX_COMPL_POLL) {
			config.tx_compl.mode_poll = 1;
			config.tx_compl.max_compl_id = gbl_args->appl.tx_compl.tot_compl_id;
		}
	}

	/* Provide hint to pktio that packet references are not used */
	config.pktout.bit.no_packet_refs = 1;

	if (gbl_args->appl.pause_rx) {
		if (!pktio_capa.flow_control.pause_rx) {
			ODPH_ERR("Reception of pause frames not supported: %s\n", dev);
			return -1;
		}
		config.flow_control.pause_rx = ODP_PKTIO_LINK_PAUSE_ON;
	}

	if (gbl_args->appl.pause_tx) {
		if (!pktio_capa.flow_control.pause_tx) {
			ODPH_ERR("Transmission of pause frames not supported: %s\n", dev);
			return -1;
		}
		config.flow_control.pause_tx = ODP_PKTIO_LINK_PAUSE_ON;
	}

	odp_pktio_config(pktio, &config);

	if (gbl_args->appl.promisc_mode && odp_pktio_promisc_mode(pktio) != 1) {
		if (!pktio_capa.set_op.op.promisc_mode) {
			ODPH_ERR("Promisc mode set not supported: %s\n", dev);
			return -1;
		}

		/* Enable promisc mode */
		if (odp_pktio_promisc_mode_set(pktio, true)) {
			ODPH_ERR("Promisc mode enable failed: %s\n", dev);
			return -1;
		}
	}

	if (gbl_args->appl.mtu) {
		uint32_t maxlen_input = pktio_capa.maxlen.max_input ? gbl_args->appl.mtu : 0;
		uint32_t maxlen_output = pktio_capa.maxlen.max_output ? gbl_args->appl.mtu : 0;

		if (!pktio_capa.set_op.op.maxlen) {
			ODPH_ERR("Modifying interface MTU not supported: %s\n", dev);
			return -1;
		}

		if (maxlen_input &&
		    (maxlen_input < pktio_capa.maxlen.min_input ||
		     maxlen_input > pktio_capa.maxlen.max_input)) {
			ODPH_ERR("Unsupported MTU value %" PRIu32 " for %s "
				 "(min %" PRIu32 ", max %" PRIu32 ")\n", maxlen_input, dev,
				 pktio_capa.maxlen.min_input, pktio_capa.maxlen.max_input);
			return -1;
		}
		if (maxlen_output &&
		    (maxlen_output < pktio_capa.maxlen.min_output ||
		     maxlen_output > pktio_capa.maxlen.max_output)) {
			ODPH_ERR("Unsupported MTU value %" PRIu32 " for %s "
				 "(min %" PRIu32 ", max %" PRIu32 ")\n", maxlen_output, dev,
				 pktio_capa.maxlen.min_output, pktio_capa.maxlen.max_output);
			return -1;
		}

		if (odp_pktio_maxlen_set(pktio, maxlen_input, maxlen_output)) {
			ODPH_ERR("Setting MTU failed: %s\n", dev);
			return -1;
		}
	}

	odp_pktin_queue_param_init(&pktin_param);
	odp_pktout_queue_param_init(&pktout_param);

	/* By default use a queue per worker. Sched mode ignores rx side
	 * setting. */
	mode_rx = ODP_PKTIO_OP_MT_UNSAFE;
	mode_tx = ODP_PKTIO_OP_MT_UNSAFE;

	if (gbl_args->appl.sched_mode) {
		odp_schedule_prio_t prio;

		if (gbl_args->appl.num_prio) {
			prio = gbl_args->appl.prio[idx];
		} else {
			prio = odp_schedule_default_prio();
			gbl_args->appl.prio[idx] = prio;
		}

		if (gbl_args->appl.in_mode == SCHED_ATOMIC)
			sync_mode = ODP_SCHED_SYNC_ATOMIC;
		else if (gbl_args->appl.in_mode == SCHED_ORDERED)
			sync_mode = ODP_SCHED_SYNC_ORDERED;
		else
			sync_mode = ODP_SCHED_SYNC_PARALLEL;

		pktin_param.queue_param.sched.prio  = prio;
		pktin_param.queue_param.sched.sync  = sync_mode;
		pktin_param.queue_param.sched.group = group;

		if (gbl_args->appl.tx_compl.mode == ODP_PACKET_TX_COMPL_EVENT) {
			odp_queue_param_init(&compl_queue);
			compl_queue.type = ODP_QUEUE_TYPE_SCHED;
			compl_queue.sched.prio = prio;
			compl_queue.sched.sync = ODP_SCHED_SYNC_PARALLEL;
			compl_queue.sched.group = group;
			gbl_args->pktios[idx].compl_q = odp_queue_create(NULL, &compl_queue);

			if (gbl_args->pktios[idx].compl_q == ODP_QUEUE_INVALID) {
				ODPH_ERR("Creating completion queue failed: %s\n", dev);
				return -1;
			}
		}
	}

	if (num_rx > (int)pktio_capa.max_input_queues) {
		num_rx  = pktio_capa.max_input_queues;
		mode_rx = ODP_PKTIO_OP_MT;
		printf("Warning: %s: maximum number of input queues: %i\n", dev, num_rx);
	}

	if (num_rx < gbl_args->appl.num_workers)
		printf("Warning: %s: sharing %i input queues between %i workers\n",
		       dev, num_rx, gbl_args->appl.num_workers);

	if (num_tx > (int)pktio_capa.max_output_queues) {
		printf("Warning: %s: sharing %i output queues between %i workers\n",
		       dev, pktio_capa.max_output_queues, num_tx);
		num_tx  = pktio_capa.max_output_queues;
		mode_tx = ODP_PKTIO_OP_MT;
	}

	pktin_param.hash_enable = (num_rx > 1 || gbl_args->appl.flow_aware) ? 1 : 0;
	pktin_param.hash_proto.proto.ipv4_udp = 1;
	pktin_param.num_queues  = num_rx;
	pktin_param.op_mode     = mode_rx;

	pktout_param.op_mode    = mode_tx;
	pktout_param.num_queues = num_tx;

	if (gbl_args->appl.vector_mode) {
		if (!pktio_capa.vector.supported) {
			ODPH_ERR("Packet vector input not supported: %s\n", dev);
			return -1;
		}
		if (set_pktin_vector_params(&pktin_param, vec_pool, &pktio_capa))
			return -1;
	}

	if (num_rx > 0 && odp_pktin_queue_config(pktio, &pktin_param)) {
		ODPH_ERR("Input queue config failed: %s\n", dev);
		return -1;
	}

	if (num_tx > 0 && odp_pktout_queue_config(pktio, &pktout_param)) {
		ODPH_ERR("Output queue config failed: %s\n", dev);
		return -1;
	}

	if (num_rx > 0) {
		if (gbl_args->appl.in_mode == DIRECT_RECV) {
			if (odp_pktin_queue(pktio, gbl_args->pktios[idx].pktin, num_rx)
			    != num_rx) {
				ODPH_ERR("Pktin queue query failed: %s\n", dev);
				return -1;
			}
		} else {
			if (odp_pktin_event_queue(pktio, gbl_args->pktios[idx].rx_q, num_rx)
			    != num_rx) {
				ODPH_ERR("Pktin event queue query failed: %s\n", dev);
				return -1;
			}
		}
	}

	if (num_tx > 0) {
		if (gbl_args->appl.out_mode == PKTOUT_DIRECT) {
			if (odp_pktout_queue(pktio, gbl_args->pktios[idx].pktout, num_tx)
			    != num_tx) {
				ODPH_ERR("Pktout queue query failed: %s\n", dev);
				return -1;
			}
		} else {
			if (odp_pktout_event_queue(pktio, gbl_args->pktios[idx].tx_q, num_tx)
			    != num_tx) {
				ODPH_ERR("Event queue query failed: %s\n", dev);
				return -1;
			}
		}
	}

	if (odp_pktio_mac_addr(pktio, gbl_args->port_eth_addr[idx].addr,
			       ODPH_ETHADDR_LEN) != ODPH_ETHADDR_LEN) {
		ODPH_ERR("Reading interface Ethernet address failed: %s\n", dev);
		return -1;
	}
	addr = gbl_args->port_eth_addr[idx].addr;

	printf("  dev: %s, drv: %s, rx_queues: %i, tx_queues: %i, mac: "
	       "%02x:%02x:%02x:%02x:%02x:%02x\n", dev, info.drv_name, num_rx, num_tx,
	       addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	if (gbl_args->appl.verbose)
		odp_pktio_print(pktio);

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
	uint64_t rx_drops, tx_drops, tx_c_misses, tx_c_fails, copy_fails;
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
		tx_c_misses = 0;
		tx_c_fails = 0;
		copy_fails = 0;

		sleep(timeout);

		for (i = 0; i < num_workers; i++) {
			pkts += thr_stats[i]->s.packets;
			rx_drops += thr_stats[i]->s.rx_drops;
			tx_drops += thr_stats[i]->s.tx_drops;
			tx_c_misses += thr_stats[i]->s.tx_c_misses;
			tx_c_fails += thr_stats[i]->s.tx_c_fails;
			copy_fails += thr_stats[i]->s.copy_fails;
		}
		if (stats_enabled) {
			pps = (pkts - pkts_prev) / timeout;
			if (pps > maximum_pps)
				maximum_pps = pps;
			printf("%" PRIu64 " pps, %" PRIu64 " max pps, ",  pps,
			       maximum_pps);

			if (gbl_args->appl.packet_copy)
				printf("%" PRIu64 " copy fails, ", copy_fails);

			if (gbl_args->appl.tx_compl.mode != ODP_PACKET_TX_COMPL_DISABLED)
				printf("%" PRIu64 " tx compl misses, %" PRIu64 " tx compl fails, ",
				       tx_c_misses, tx_c_fails);

			printf("%" PRIu64 " rx drops, %" PRIu64 " tx drops\n",
			       rx_drops, tx_drops);

			pkts_prev = pkts;
		}
		elapsed += timeout;
	} while (!odp_atomic_load_u32(&gbl_args->exit_threads) && (loop_forever ||
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
	const char *output = gbl_args->appl.output_map[port];

	/* Check output mappings first */
	if (output != NULL)
		for (int i = 0; i < gbl_args->appl.if_count; i++)
			if (strcmp(output, gbl_args->appl.if_names[i]) == 0)
				return i;

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

static void init_state(const appl_args_t *args, state_t *state, int thr_idx)
{
	const uint32_t cnt = args->tx_compl.thr_compl_id + 1;

	state->tx_compl.opt.mode = args->tx_compl.mode;
	state->tx_compl.init = thr_idx * cnt;
	state->tx_compl.max = state->tx_compl.init + cnt - 1;
	state->tx_compl.free_head = state->tx_compl.init;
	state->tx_compl.poll_head = state->tx_compl.init;
	state->tx_compl.num_act = 0;
	state->tx_compl.max_act = state->tx_compl.max - state->tx_compl.init + 1;
	state->tx_compl.interval = args->tx_compl.nth;
	state->tx_compl.next_req = state->tx_compl.interval;
}

static void init_port_lookup_tbl(void)
{
	int rx_idx, if_count;

	if_count = gbl_args->appl.if_count;

	for (rx_idx = 0; rx_idx < if_count; rx_idx++) {
		odp_pktio_t pktio = gbl_args->pktios[rx_idx].pktio;
		int pktio_idx     = odp_pktio_index(pktio);
		int dst_port      = find_dest_port(rx_idx);

		if (pktio_idx < 0) {
			ODPH_ERR("Reading pktio (%s) index failed: %i\n",
				 gbl_args->appl.if_names[rx_idx], pktio_idx);

			exit(EXIT_FAILURE);
		}

		gbl_args->dst_port_from_idx[pktio_idx] = dst_port;
	}
}

/*
 * Print usage information
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
	       "  -i, --interface <name>         Eth interfaces (comma-separated, no spaces)\n"
	       "                                 Interface count min 1, max %i\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -m, --mode <arg>               Packet input mode\n"
	       "                                 0: Direct mode: PKTIN_MODE_DIRECT (default)\n"
	       "                                 1: Scheduler mode with parallel queues:\n"
	       "                                    PKTIN_MODE_SCHED + SCHED_SYNC_PARALLEL\n"
	       "                                 2: Scheduler mode with atomic queues:\n"
	       "                                    PKTIN_MODE_SCHED + SCHED_SYNC_ATOMIC\n"
	       "                                 3: Scheduler mode with ordered queues:\n"
	       "                                    PKTIN_MODE_SCHED + SCHED_SYNC_ORDERED\n"
	       "                                 4: Plain queue mode: PKTIN_MODE_QUEUE\n"
	       "  -o, --out_mode <arg>           Packet output mode\n"
	       "                                 0: Direct mode: PKTOUT_MODE_DIRECT (default)\n"
	       "                                 1: Queue mode:  PKTOUT_MODE_QUEUE\n"
	       "  -O, --output_map <list>        List of destination ports for passed interfaces\n"
	       "                                 (comma-separated, no spaces). Ordering follows\n"
	       "                                 the '--interface' option, e.g. passing\n"
	       "                                 '-i eth0,eth1' and '-O eth0,eth1' would result\n"
	       "                                 in eth0 and eth1 looping packets back.\n"
	       "  -c, --count <num>              CPU count, 0=all available, default=1\n"
	       "  -t, --time <sec>               Time in seconds to run.\n"
	       "  -a, --accuracy <sec>           Time in seconds get print statistics\n"
	       "                                 (default is 1 second).\n"
	       "  -d, --dst_change <arg>         0: Don't change packets' dst eth addresses\n"
	       "                                 1: Change packets' dst eth addresses (default)\n"
	       "  -s, --src_change <arg>         0: Don't change packets' src eth addresses\n"
	       "                                 1: Change packets' src eth addresses (default)\n"
	       "  -r, --dst_addr <addr>          Destination addresses (comma-separated, no\n"
	       "                                 spaces) Requires also the -d flag to be set\n"
	       "  -e, --error_check <arg>        0: Don't check packet errors (default)\n"
	       "                                 1: Check packet errors\n"
	       "  -k, --chksum <arg>             0: Don't use checksum offload (default)\n"
	       "                                 1: Use checksum offload\n",
	       NO_PATH(progname), NO_PATH(progname), MAX_PKTIOS);

	printf("  -g, --groups <num>             Number of new groups to create (1 ... num).\n"
	       "                                 Interfaces are placed into the groups in round\n"
	       "                                 robin.\n"
	       "                                  0: Use SCHED_GROUP_ALL (default)\n"
	       "                                 -1: Use SCHED_GROUP_WORKER\n"
	       "  -G, --group_mode <arg>         Select how threads join new groups\n"
	       "                                 (when -g > 0)\n"
	       "                                 0: All threads join all created groups\n"
	       "                                    (default)\n"
	       "                                 1: All threads join first N created groups.\n"
	       "                                    N is number of interfaces (== active\n"
	       "                                    groups).\n"
	       "                                 2: Each thread joins a part of the first N\n"
	       "                                    groups (in round robin).\n"
	       "  -I, --prio <prio list>         Schedule priority of packet input queues.\n"
	       "                                 Comma separated list of priorities (no spaces).\n"
	       "                                 A value per interface. All queues of an\n"
	       "                                 interface have the same priority. Values must\n"
	       "                                 be between odp_schedule_min_prio and\n"
	       "                                 odp_schedule_max_prio.\n"
	       "                                 odp_schedule_default_prio is used by default.\n"
	       "  -b, --burst_rx <num>           0:   Use max burst size (default)\n"
	       "                                 num: Max number of packets per receive call\n"
	       "  -q, --rx_queues <num>          Number of RX queues per interface in scheduler\n"
	       "                                 mode\n"
	       "                                 0: RX queue per worker CPU (default)\n"
	       "  -p, --packet_copy              0: Don't copy packet (default)\n"
	       "                                 1: Create and send copy of the received packet.\n"
	       "                                    Free the original packet.\n"
	       "  -R, --data_rd <num>            Number of packet data words (uint64_t) to read\n"
	       "                                 from every received packet. Number of words is\n"
	       "                                 rounded down to fit into the first segment of a\n"
	       "                                 packet. Default is 0.\n"
	       "  -E, --memcpy <num>             Number of bytes to memcpy per RX burst before\n"
	       "                                 forwarding packets. Default: 0.\n"
	       "  -W, --wait_ns <ns>             Number of nsecs to wait per receive burst before\n"
	       "                                 forwarding packets. Default: 0.\n"
	       "  -y, --pool_per_if              Create a packet (and packet vector) pool per\n"
	       "                                 interface.\n"
	       "                                 0: Share a single pool between all interfaces\n"
	       "                                    (default)\n"
	       "                                 1: Create a pool per interface\n"
	       "  -n, --num_pkt <num>            Number of packets per pool. Default is 16k or\n"
	       "                                 the maximum capability. Use 0 for the default.\n"
	       "  -u, --vector_mode              Enable vector mode.\n"
	       "                                 Supported only with scheduler packet input\n"
	       "                                 modes (1-3).\n"
	       "  -w, --num_vec <num>            Number of vectors per pool.\n"
	       "                                 Default is num_pkts divided by vec_size.\n"
	       "  -x, --vec_size <num>           Vector size (default %i).\n"
	       "  -z, --vec_tmo_ns <ns>          Vector timeout in ns (default %llu ns).\n"
	       "  -M, --mtu <len>                Interface MTU in bytes.\n"
	       "  -P, --promisc_mode             Enable promiscuous mode.\n"
	       "  -l, --packet_len <len>         Maximum length of packets supported\n"
	       "                                 (default %d).\n"
	       "  -L, --seg_len <len>            Packet pool segment length\n"
	       "                                 (default equal to packet length).\n"
	       "  -F, --prefetch <num>           Prefetch packet data in 64 byte multiples\n"
	       "                                 (default 1).\n"
	       "  -f, --flow_aware               Enable flow aware scheduling.\n"
	       "  -T, --input_ts                 Enable packet input timestamping.\n",
	       DEFAULT_VEC_SIZE, DEFAULT_VEC_TMO, POOL_PKT_LEN);

	printf("  -C, --tx_compl <mode,n,max_id> Enable transmit completion with a specified\n"
	       "                                 completion mode for nth packet, with maximum\n"
	       "                                 completion ID per worker thread in case of poll\n"
	       "                                 completion (comma-separated, no spaces).\n"
	       "                                 0: Event completion mode\n"
	       "                                 1: Poll completion mode\n"
	       "  -X, --flow_control <mode>      Ethernet flow control mode.\n"
	       "                                 0: Flow control disabled (default)\n"
	       "                                 1: Enable reception of pause frames\n"
	       "                                 2: Enable transmission of pause frames\n"
	       "                                 3: Enable reception and transmission of pause\n"
	       "                                    frames\n"
	       "  -v, --verbose                  Verbose output.\n"
	       "  -V, --verbose_pkt              Print debug information on every received\n"
	       "                                 packet.\n"
	       "  -h, --help                     Display help and exit.\n\n"
	       "\n");
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
	char *token;
	char *tmp_str, *tmp;
	size_t str_len, len;
	int i;
	static const struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"time", required_argument, NULL, 't'},
		{"accuracy", required_argument, NULL, 'a'},
		{"interface", required_argument, NULL, 'i'},
		{"mode", required_argument, NULL, 'm'},
		{"memcpy", required_argument, NULL, 'E'},
		{"out_mode", required_argument, NULL, 'o'},
		{"output_map", required_argument, NULL, 'O'},
		{"dst_addr", required_argument, NULL, 'r'},
		{"dst_change", required_argument, NULL, 'd'},
		{"src_change", required_argument, NULL, 's'},
		{"error_check", required_argument, NULL, 'e'},
		{"chksum", required_argument, NULL, 'k'},
		{"groups", required_argument, NULL, 'g'},
		{"group_mode", required_argument, NULL, 'G'},
		{"prio", required_argument, NULL, 'I'},
		{"burst_rx", required_argument, NULL, 'b'},
		{"rx_queues", required_argument, NULL, 'q'},
		{"packet_copy", required_argument, NULL, 'p'},
		{"data_rd", required_argument, NULL, 'R'},
		{"pool_per_if", required_argument, NULL, 'y'},
		{"num_pkt", required_argument, NULL, 'n'},
		{"num_vec", required_argument, NULL, 'w'},
		{"wait_ns", required_argument, NULL, 'W'},
		{"vec_size", required_argument, NULL, 'x'},
		{"vec_tmo_ns", required_argument, NULL, 'z'},
		{"vector_mode", no_argument, NULL, 'u'},
		{"mtu", required_argument, NULL, 'M'},
		{"promisc_mode", no_argument, NULL, 'P'},
		{"packet_len", required_argument, NULL, 'l'},
		{"seg_len", required_argument, NULL, 'L'},
		{"prefetch", required_argument, NULL, 'F'},
		{"flow_aware", no_argument, NULL, 'f'},
		{"input_ts", no_argument, NULL, 'T'},
		{"tx_compl", required_argument, NULL, 'C'},
		{"flow_control", required_argument, NULL, 'X'},
		{"verbose", no_argument, NULL, 'v'},
		{"verbose_pkt", no_argument, NULL, 'V'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:t:a:i:m:o:O:r:d:s:e:E:k:g:G:I:"
				       "b:q:p:R:y:n:l:L:w:W:x:X:z:M:F:uPfTC:vVh";

	appl_args->time = 0; /* loop forever if time to run is 0 */
	appl_args->accuracy = 1; /* get and print pps stats second */
	appl_args->cpu_count = 1; /* use one worker by default */
	appl_args->dst_change = 1; /* change eth dst address by default */
	appl_args->src_change = 1; /* change eth src address by default */
	appl_args->num_groups = 0; /* use default group */
	appl_args->group_mode = 0;
	appl_args->error_check = 0; /* don't check packet errors by default */
	appl_args->packet_copy = 0;
	appl_args->burst_rx = 0;
	appl_args->rx_queues = 0;
	appl_args->verbose = 0;
	appl_args->verbose_pkt = 0;
	appl_args->chksum = 0; /* don't use checksum offload by default */
	appl_args->pool_per_if = 0;
	appl_args->num_pkt = 0;
	appl_args->packet_len = POOL_PKT_LEN;
	appl_args->seg_len = UINT32_MAX;
	appl_args->mtu = 0;
	appl_args->promisc_mode = 0;
	appl_args->vector_mode = 0;
	appl_args->num_vec = 0;
	appl_args->vec_size = 0;
	appl_args->vec_tmo_ns = 0;
	appl_args->flow_aware = 0;
	appl_args->input_ts = 0;
	appl_args->num_prio = 0;
	appl_args->prefetch = 1;
	appl_args->data_rd = 0;
	appl_args->flow_control = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

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
		case 'r':
			len = strlen(optarg);
			if (len == 0) {
				ODPH_ERR("Bad dest address string\n");
				exit(EXIT_FAILURE);
			}

			str_len = len + 1;

			tmp_str = malloc(str_len);
			if (tmp_str == NULL) {
				ODPH_ERR("Dest address malloc() failed\n");
				exit(EXIT_FAILURE);
			}

			/* store the mac addresses names */
			memcpy(tmp_str, optarg, str_len);
			for (token = strtok(tmp_str, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				if (i >= MAX_PKTIOS) {
					ODPH_ERR("Too many MAC addresses\n");
					exit(EXIT_FAILURE);
				}
				if (odph_eth_addr_parse(&appl_args->addrs[i], token) != 0) {
					ODPH_ERR("Invalid MAC address\n");
					exit(EXIT_FAILURE);
				}
			}
			appl_args->addr_count = i;
			if (appl_args->addr_count < 1) {
				ODPH_ERR("Bad dest address count\n");
				exit(EXIT_FAILURE);
			}
			free(tmp_str);
			break;
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				ODPH_ERR("Bad pktio interface string\n");
				exit(EXIT_FAILURE);
			}

			str_len = len + 1;

			appl_args->if_str = malloc(str_len);
			if (appl_args->if_str == NULL) {
				ODPH_ERR("Pktio interface malloc() failed\n");
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			memcpy(appl_args->if_str, optarg, str_len);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL;
			     token = strtok(NULL, ","), i++)
				;

			appl_args->if_count = i;

			if (appl_args->if_count < 1 || appl_args->if_count > MAX_PKTIOS) {
				ODPH_ERR("Bad pktio interface count: %i\n", appl_args->if_count);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names = calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			memcpy(appl_args->if_str, optarg, str_len);
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
		case 'O':
			if (strlen(optarg) == 0) {
				ODPH_ERR("Bad output map string\n");
				exit(EXIT_FAILURE);
			}

			tmp_str = strdup(optarg);

			if (tmp_str == NULL) {
				ODPH_ERR("Output map string duplication failed\n");
				exit(EXIT_FAILURE);
			}

			token = strtok(tmp_str, ",");

			while (token) {
				if (appl_args->num_om >= MAX_PKTIOS) {
					ODPH_ERR("Bad output map element count\n");
					exit(EXIT_FAILURE);
				}

				appl_args->output_map[appl_args->num_om] = strdup(token);

				if (appl_args->output_map[appl_args->num_om] == NULL) {
					ODPH_ERR("Output map element duplication failed\n");
					exit(EXIT_FAILURE);
				}

				appl_args->num_om++;
				token = strtok(NULL, ",");
			}

			free(tmp_str);
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
		case 'E':
			appl_args->memcpy_bytes = atoll(optarg);
			break;
		case 'k':
			appl_args->chksum = atoi(optarg);
			break;
		case 'g':
			appl_args->num_groups = atoi(optarg);
			break;
		case 'G':
			appl_args->group_mode = atoi(optarg);
			break;
		case 'I':
			len = strlen(optarg);
			if (len == 0) {
				ODPH_ERR("Bad priority list\n");
				exit(EXIT_FAILURE);
			}

			str_len = len + 1;

			tmp_str = malloc(str_len);
			if (tmp_str == NULL) {
				ODPH_ERR("Priority list malloc() failed\n");
				exit(EXIT_FAILURE);
			}

			memcpy(tmp_str, optarg, str_len);
			token = strtok(tmp_str, ",");

			for (i = 0; token != NULL; token = strtok(NULL, ","), i++) {
				if (i >= MAX_PKTIOS) {
					ODPH_ERR("Too many priorities\n");
					exit(EXIT_FAILURE);
				}

				appl_args->prio[i] = atoi(token);
				appl_args->num_prio++;
			}

			if (appl_args->num_prio == 0) {
				ODPH_ERR("Bad priority list\n");
				exit(EXIT_FAILURE);
			}

			free(tmp_str);
			break;
		case 'b':
			appl_args->burst_rx = atoi(optarg);
			break;
		case 'q':
			appl_args->rx_queues = atoi(optarg);
			break;
		case 'p':
			appl_args->packet_copy = atoi(optarg);
			break;
		case 'R':
			appl_args->data_rd = atoi(optarg);
			break;
		case 'y':
			appl_args->pool_per_if = atoi(optarg);
			break;
		case 'n':
			appl_args->num_pkt = atoi(optarg);
			break;
		case 'l':
			appl_args->packet_len = atoi(optarg);
			break;
		case 'L':
			appl_args->seg_len = atoi(optarg);
			break;
		case 'M':
			appl_args->mtu = atoi(optarg);
			break;
		case 'P':
			appl_args->promisc_mode = 1;
			break;
		case 'u':
			appl_args->vector_mode = 1;
			break;
		case 'w':
			appl_args->num_vec = atoi(optarg);
			break;
		case 'W':
			appl_args->wait_ns = atoll(optarg);
			break;
		case 'x':
			appl_args->vec_size = atoi(optarg);
			break;
		case 'X':
			appl_args->flow_control = atoi(optarg);
			if (appl_args->flow_control == 1 || appl_args->flow_control == 3)
				appl_args->pause_rx = true;
			if (appl_args->flow_control == 2 || appl_args->flow_control == 3)
				appl_args->pause_tx = true;
			break;
		case 'z':
			appl_args->vec_tmo_ns = atoi(optarg);
			break;
		case 'F':
			appl_args->prefetch = atoi(optarg);
			break;
		case 'f':
			appl_args->flow_aware = 1;
			break;
		case 'T':
			appl_args->input_ts = 1;
			break;
		case 'C':
			if (strlen(optarg) == 0) {
				ODPH_ERR("Bad transmit completion parameter string\n");
				exit(EXIT_FAILURE);
			}

			tmp_str = strdup(optarg);

			if (tmp_str == NULL) {
				ODPH_ERR("Transmit completion parameter string duplication"
					 " failed\n");
				exit(EXIT_FAILURE);
			}

			tmp = strtok(tmp_str, ",");

			if (tmp == NULL) {
				ODPH_ERR("Invalid transmit completion parameter format\n");
				exit(EXIT_FAILURE);
			}

			i = atoi(tmp);

			if (i == 0)
				appl_args->tx_compl.mode = ODP_PACKET_TX_COMPL_EVENT;
			else if (i == 1)
				appl_args->tx_compl.mode = ODP_PACKET_TX_COMPL_POLL;

			tmp = strtok(NULL, ",");

			if (tmp == NULL) {
				ODPH_ERR("Invalid transmit completion parameter format\n");
				exit(EXIT_FAILURE);
			}

			appl_args->tx_compl.nth = atoi(tmp);

			if (appl_args->tx_compl.mode == ODP_PACKET_TX_COMPL_POLL) {
				tmp = strtok(NULL, ",");

				if (tmp == NULL) {
					ODPH_ERR("Invalid transmit completion parameter format\n");
					exit(EXIT_FAILURE);
				}

				appl_args->tx_compl.thr_compl_id = atoi(tmp);
			}

			free(tmp_str);
			break;
		case 'v':
			appl_args->verbose = 1;
			break;
		case 'V':
			appl_args->verbose_pkt = 1;
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
		ODPH_ERR("No pktio interfaces\n");
		exit(EXIT_FAILURE);
	}

	if (appl_args->num_om && appl_args->num_om != appl_args->if_count) {
		ODPH_ERR("Different number of output mappings and pktio interfaces\n");
		exit(EXIT_FAILURE);
	}

	if (appl_args->num_prio && appl_args->num_prio != appl_args->if_count) {
		ODPH_ERR("Different number of priorities and pktio interfaces\n");
		exit(EXIT_FAILURE);
	}

	if (appl_args->addr_count != 0 && appl_args->addr_count != appl_args->if_count) {
		ODPH_ERR("Number of dest addresses differs from number of interfaces\n");
		exit(EXIT_FAILURE);
	}

	if (appl_args->burst_rx > MAX_PKT_BURST) {
		ODPH_ERR("Burst size (%i) too large. Maximum is %i.\n",
			 appl_args->burst_rx, MAX_PKT_BURST);
		exit(EXIT_FAILURE);
	}

	if (appl_args->tx_compl.mode != ODP_PACKET_TX_COMPL_DISABLED &&
	    appl_args->tx_compl.nth == 0) {
		ODPH_ERR("Invalid packet interval for transmit completion: %u\n",
			 appl_args->tx_compl.nth);
		exit(EXIT_FAILURE);
	}

	if (appl_args->tx_compl.mode == ODP_PACKET_TX_COMPL_EVENT &&
	    (appl_args->in_mode == PLAIN_QUEUE || appl_args->in_mode == DIRECT_RECV)) {
		ODPH_ERR("Transmit event completion mode not supported with plain queue or direct "
			 "input modes\n");
		exit(EXIT_FAILURE);
	}

	appl_args->tx_compl.tot_compl_id = (appl_args->tx_compl.thr_compl_id + 1) *
					   appl_args->cpu_count - 1;

	if (appl_args->burst_rx == 0)
		appl_args->burst_rx = MAX_PKT_BURST;

	appl_args->extra_feat = 0;
	if (appl_args->error_check || appl_args->chksum || appl_args->packet_copy ||
	    appl_args->data_rd || appl_args->verbose_pkt || appl_args->wait_ns ||
	    appl_args->memcpy_bytes)
		appl_args->extra_feat = 1;

	appl_args->has_state = 0;
	if (appl_args->tx_compl.mode != ODP_PACKET_TX_COMPL_DISABLED)
		appl_args->has_state = 1;

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

static void print_options(void)
{
	int i;
	appl_args_t *appl_args = &gbl_args->appl;

	printf("\n"
	       "odp_l2fwd options\n"
	       "-----------------\n"
	       "IF-count:           %i\n"
	       "Using IFs:         ", appl_args->if_count);

	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n"
	       "Mode:               ");
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

	if (appl_args->num_om > 0) {
		printf("Output mappings:   ");

		for (i = 0; i < appl_args->num_om; ++i)
			printf(" %s", appl_args->output_map[i]);

		printf("\n");
	}

	printf("MTU:                ");
	if (appl_args->mtu)
		printf("%i bytes\n", appl_args->mtu);
	else
		printf("interface default\n");
	printf("Promisc mode:       %s\n", appl_args->promisc_mode ?
					   "enabled" : "disabled");
	if (appl_args->flow_control)
		printf("Flow control:       %s%s\n",
		       appl_args->pause_rx ? "rx " : "",
		       appl_args->pause_tx ? "tx" : "");
	printf("Flow aware:         %s\n", appl_args->flow_aware ?
					   "yes" : "no");
	printf("Input TS:           %s\n", appl_args->input_ts ? "yes" : "no");
	printf("Burst size:         %i\n", appl_args->burst_rx);
	printf("RX queues per IF:   %i\n", appl_args->rx_queues);
	printf("Number of pools:    %i\n", appl_args->pool_per_if ?
					   appl_args->if_count : 1);

	if (appl_args->extra_feat || appl_args->has_state) {
		printf("Extra features:     %s%s%s%s%s%s%s%s\n",
		       appl_args->error_check ? "error_check " : "",
		       appl_args->chksum ? "chksum " : "",
		       appl_args->packet_copy ? "packet_copy " : "",
		       appl_args->data_rd ? "data_rd" : "",
		       appl_args->tx_compl.mode != ODP_PACKET_TX_COMPL_DISABLED ? "tx_compl" : "",
		       appl_args->verbose_pkt ? "verbose_pkt" : "",
		       appl_args->wait_ns ? "wait_ns" : "",
		       appl_args->memcpy_bytes ? "memcpy" : "");

		if (appl_args->memcpy_bytes)
			printf("  Memcpy:           %" PRIu64 " bytes\n", appl_args->memcpy_bytes);
		if (appl_args->wait_ns)
			printf("  Wait:             %" PRIu64 " ns\n", appl_args->wait_ns);
	}

	printf("Num worker threads: %i\n", appl_args->num_workers);
	printf("CPU mask:           %s\n", gbl_args->cpumaskstr);

	if (appl_args->num_groups > 0)
		printf("num groups:         %i\n", appl_args->num_groups);
	else if (appl_args->num_groups == 0)
		printf("group:              ODP_SCHED_GROUP_ALL\n");
	else
		printf("group:              ODP_SCHED_GROUP_WORKER\n");

	printf("Packets per pool:   %u\n", appl_args->num_pkt);
	printf("Packet length:      %u\n", appl_args->packet_len);
	printf("Segment length:     %u\n", appl_args->seg_len == UINT32_MAX ? 0 :
	       appl_args->seg_len);
	printf("Read data:          %u bytes\n", appl_args->data_rd * 8);
	printf("Prefetch data       %u bytes\n", appl_args->prefetch * 64);
	printf("Vectors per pool:   %u\n", appl_args->num_vec);
	printf("Vector size:        %u\n", appl_args->vec_size);
	printf("Priority per IF:   ");

	for (i = 0; i < appl_args->if_count; i++)
		printf(" %i", appl_args->prio[i]);

	printf("\n\n");
}

static void gbl_args_init(args_t *args)
{
	int pktio, queue;

	memset(args, 0, sizeof(args_t));
	odp_atomic_init_u32(&args->exit_threads, 0);
	args->memcpy_shm = ODP_SHM_INVALID;

	for (pktio = 0; pktio < MAX_PKTIOS; pktio++) {
		args->pktios[pktio].pktio = ODP_PKTIO_INVALID;

		for (queue = 0; queue < MAX_QUEUES; queue++)
			args->pktios[pktio].rx_q[queue] = ODP_QUEUE_INVALID;

		args->pktios[pktio].compl_q = ODP_QUEUE_INVALID;
	}

	args->appl.tx_compl.mode = ODP_PACKET_TX_COMPL_DISABLED;
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

static int set_vector_pool_params(odp_pool_param_t *params, const odp_pool_capability_t *pool_capa)
{
	uint32_t num_vec, vec_size;

	if (gbl_args->appl.vec_size == 0)
		vec_size = DEFAULT_VEC_SIZE;
	else
		vec_size = gbl_args->appl.vec_size;

	ODPH_ASSERT(pool_capa->vector.max_size > 0);
	if (vec_size > pool_capa->vector.max_size) {
		if (gbl_args->appl.vec_size == 0) {
			vec_size = pool_capa->vector.max_size;
			printf("\nWarning: Vector size reduced to %u\n\n", vec_size);
		} else {
			ODPH_ERR("Vector size too big %u. Maximum is %u.\n",
				 vec_size, pool_capa->vector.max_size);
			return -1;
		}
	}

	if (gbl_args->appl.num_vec == 0) {
		uint32_t num_pkt =  gbl_args->appl.num_pkt ?
			gbl_args->appl.num_pkt : DEFAULT_NUM_PKT;

		num_vec = (num_pkt + vec_size - 1) / vec_size;
	} else {
		num_vec = gbl_args->appl.num_vec;
	}

	if (pool_capa->vector.max_num && num_vec > pool_capa->vector.max_num) {
		if (gbl_args->appl.num_vec == 0) {
			num_vec = pool_capa->vector.max_num;
			printf("\nWarning: number of vectors reduced to %u\n\n", num_vec);
		} else {
			ODPH_ERR("Too many vectors (%u) per pool. Maximum is %u.\n",
				 num_vec, pool_capa->vector.max_num);
			return -1;
		}
	}

	params->vector.num = num_vec;
	params->vector.max_size = vec_size;
	params->type = ODP_POOL_VECTOR;

	return 0;
}

static int reserve_memcpy_memory(args_t *args)
{
	uint64_t total_bytes;

	if (args->appl.memcpy_bytes == 0)
		return 0;

	/* Private memory area (read + write) for each worker */
	total_bytes = 2 * args->appl.memcpy_bytes * args->appl.num_workers;

	args->memcpy_shm = odp_shm_reserve("memcpy_shm", total_bytes, ODP_CACHE_LINE_SIZE, 0);
	if (args->memcpy_shm == ODP_SHM_INVALID) {
		ODPH_ERR("Reserving %" PRIu64 " bytes for memcpy failed.\n", total_bytes);
		return -1;
	}
	args->memcpy_data = odp_shm_addr(args->memcpy_shm);
	if (args->memcpy_data == NULL) {
		ODPH_ERR("Shared mem addr for memcpy failed.\n");
		return -1;
	}

	return 0;
}

/*
 * L2 forwarding main function
 */
int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	odph_thread_param_t thr_param[MAX_WORKERS];
	odph_thread_common_param_t thr_common;
	int i;
	int num_workers, num_thr;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	odph_ethaddr_t new_addr;
	odp_pool_param_t params;
	int ret;
	stats_t *stats[MAX_WORKERS];
	int if_count, num_pools, num_vec_pools;
	int (*thr_run_func)(void *);
	odp_instance_t instance;
	int num_groups, max_groups;
	odp_schedule_group_t group[MAX_GROUPS];
	odp_pool_t pool_tbl[MAX_PKTIOS], vec_pool_tbl[MAX_PKTIOS];
	odp_pool_t pool, vec_pool;
	odp_init_t init;
	odp_pool_capability_t pool_capa;
	odp_schedule_config_t sched_config;
	odp_schedule_capability_t sched_capa;
	uint32_t pkt_len, num_pkt, seg_len;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init);

	/* List features not to be used (may optimize performance) */
	init.not_used.feat.cls      = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.timer    = 1;
	init.not_used.feat.tm       = 1;

	init.mem_model = helper_options.mem_model;

	if (setup_sig_handler()) {
		ODPH_ERR("Signal handler setup failed\n");
		exit(EXIT_FAILURE);
	}

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	gbl_args = odp_shm_addr(shm);

	if (gbl_args == NULL) {
		ODPH_ERR("Shared mem addr failed.\n");
		exit(EXIT_FAILURE);
	}
	gbl_args_init(gbl_args);

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	odp_sys_info_print();

	if (sched_mode(gbl_args->appl.in_mode))
		gbl_args->appl.sched_mode = 1;

	num_workers = MAX_WORKERS;
	if (gbl_args->appl.cpu_count && gbl_args->appl.cpu_count < MAX_WORKERS)
		num_workers = gbl_args->appl.cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, gbl_args->cpumaskstr, sizeof(gbl_args->cpumaskstr));

	gbl_args->appl.num_workers = num_workers;

	print_options();

	if (reserve_memcpy_memory(gbl_args))
		exit(EXIT_FAILURE);

	if_count = gbl_args->appl.if_count;

	num_pools = 1;
	if (gbl_args->appl.pool_per_if)
		num_pools = if_count;

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Pool capability failed\n");
		return -1;
	}

	if (num_pools > (int)pool_capa.pkt.max_pools) {
		ODPH_ERR("Too many pools %i\n", num_pools);
		return -1;
	}

	pkt_len = gbl_args->appl.packet_len;

	if (pool_capa.pkt.max_len && pkt_len > pool_capa.pkt.max_len) {
		pkt_len = pool_capa.pkt.max_len;
		printf("\nWarning: packet length reduced to %u\n\n", pkt_len);
	}

	if (gbl_args->appl.seg_len == UINT32_MAX)
		seg_len = gbl_args->appl.packet_len;
	else
		seg_len = gbl_args->appl.seg_len;

	/* Check whether we have sufficient segments to support requested packet
	 * length, if not adjust to bigger segment size */
	if (seg_len < (pkt_len / pool_capa.pkt.max_segs_per_pkt))
		seg_len = pkt_len / pool_capa.pkt.max_segs_per_pkt;

	if (pool_capa.pkt.min_seg_len && seg_len < pool_capa.pkt.min_seg_len)
		seg_len = pool_capa.pkt.min_seg_len;

	if (pool_capa.pkt.max_seg_len && seg_len > pool_capa.pkt.max_seg_len)
		seg_len = pool_capa.pkt.max_seg_len;

	if ((gbl_args->appl.seg_len != UINT32_MAX) && (seg_len != gbl_args->appl.seg_len))
		printf("\nWarning: Segment length requested %d configured %d\n",
		       gbl_args->appl.seg_len, seg_len);

	if (seg_len < gbl_args->appl.data_rd * 8) {
		ODPH_ERR("Requested data read length %u exceeds maximum segment length %u\n",
			 gbl_args->appl.data_rd * 8, seg_len);
			return -1;
	}

	/* zero means default number of packets */
	if (gbl_args->appl.num_pkt == 0)
		num_pkt = DEFAULT_NUM_PKT;
	else
		num_pkt = gbl_args->appl.num_pkt;

	if (pool_capa.pkt.max_num && num_pkt > pool_capa.pkt.max_num) {
		if (gbl_args->appl.num_pkt == 0) {
			num_pkt = pool_capa.pkt.max_num;
			printf("\nWarning: number of packets reduced to %u\n\n",
			       num_pkt);
		} else {
			ODPH_ERR("Too many packets %u. Maximum is %u.\n",
				 num_pkt, pool_capa.pkt.max_num);
			return -1;
		}
	}

	gbl_args->num_pkt = num_pkt;
	gbl_args->pkt_len = pkt_len;
	gbl_args->seg_len = seg_len;

	printf("Resulting pool parameter values:\n");
	printf("Packets per pool:   %u\n", num_pkt);
	printf("Packet length:      %u\n", pkt_len);
	printf("Segment length:     %u\n", seg_len);

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = seg_len;
	params.pkt.len     = pkt_len;
	params.pkt.num     = num_pkt;
	params.type        = ODP_POOL_PACKET;

	for (i = 0; i < num_pools; i++) {
		pool_tbl[i] = odp_pool_create("packet pool", &params);

		if (pool_tbl[i] == ODP_POOL_INVALID) {
			ODPH_ERR("Pool create failed %i\n", i);
			exit(EXIT_FAILURE);
		}

		if (gbl_args->appl.verbose)
			odp_pool_print(pool_tbl[i]);
	}

	/* Create vector pool */
	num_vec_pools = 0;
	if (gbl_args->appl.vector_mode) {
		if (!sched_mode(gbl_args->appl.in_mode)) {
			ODPH_ERR("Vector mode only supports scheduler pktin modes (1-3)\n");
			return -1;
		}

		num_vec_pools = gbl_args->appl.pool_per_if ? if_count : 1;
		if (num_vec_pools > (int)pool_capa.vector.max_pools) {
			ODPH_ERR("Too many vector pools %i\n", num_vec_pools);
			return -1;
		}

		odp_pool_param_init(&params);
		if (set_vector_pool_params(&params, &pool_capa))
			return -1;

		gbl_args->vector_num = params.vector.num;
		gbl_args->vector_max_size = params.vector.max_size;

		/* Print resulting values */
		printf("Vectors per pool:   %u\n", gbl_args->vector_num);
		printf("Vector size:        %u\n", gbl_args->vector_max_size);

		for (i = 0; i < num_vec_pools; i++) {
			vec_pool_tbl[i] = odp_pool_create("vector pool", &params);

			if (vec_pool_tbl[i] == ODP_POOL_INVALID) {
				ODPH_ERR("Vector pool create failed %i\n", i);
				exit(EXIT_FAILURE);
			}

			if (gbl_args->appl.verbose)
				odp_pool_print(vec_pool_tbl[i]);
		}
	}

	printf("\n");

	bind_workers();

	odp_schedule_config_init(&sched_config);

	if (odp_schedule_capability(&sched_capa)) {
		ODPH_ERR("Schedule capability failed\n");
		exit(EXIT_FAILURE);
	}

	if (gbl_args->appl.flow_aware) {
		if (sched_capa.max_flow_id) {
			sched_config.max_flow_id = sched_capa.max_flow_id;
		} else {
			ODPH_ERR("Flow aware mode not supported\n");
			exit(EXIT_FAILURE);
		}
	}

	num_groups = gbl_args->appl.num_groups;
	/* Predefined groups are enabled by default */
	max_groups = sched_capa.max_groups - 3;
	if (max_groups > MAX_GROUPS)
		max_groups = MAX_GROUPS;

	if (num_groups > max_groups) {
		ODPH_ERR("Too many groups. Maximum is %i.\n", max_groups);
		exit(EXIT_FAILURE);
	}

	odp_schedule_config(&sched_config);

	/* Default */
	if (num_groups == 0) {
		group[0]   = ODP_SCHED_GROUP_ALL;
		num_groups = 1;
	} else if (num_groups == -1) {
		group[0]   = ODP_SCHED_GROUP_WORKER;
		num_groups = 1;
	} else {
		create_groups(num_groups, group);
	}

	pool = pool_tbl[0];
	vec_pool = vec_pool_tbl[0];

	printf("\nInterfaces\n----------\n");

	for (i = 0; i < if_count; ++i) {
		const char *dev = gbl_args->appl.if_names[i];
		int num_rx, num_tx;
		odp_schedule_group_t grp;

		/* A queue per worker in scheduled mode */
		num_rx = gbl_args->appl.rx_queues > 0 ? gbl_args->appl.rx_queues : num_workers;
		num_tx = num_workers;

		if (!gbl_args->appl.sched_mode) {
			/* A queue per assigned worker */
			num_rx = gbl_args->pktios[i].num_rx_thr;
			num_tx = gbl_args->pktios[i].num_tx_thr;
		}

		/* Round robin pktios to groups */
		grp = group[i % num_groups];

		if (gbl_args->appl.pool_per_if) {
			pool = pool_tbl[i];
			vec_pool = vec_pool_tbl[i];
		}

		if (create_pktio(dev, i, num_rx, num_tx, pool, vec_pool, grp))
			exit(EXIT_FAILURE);

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
		thr_run_func = gbl_args->appl.vector_mode ?
			run_worker_sched_mode_vector : run_worker_sched_mode;

	/* Create worker threads */
	odph_thread_common_param_init(&thr_common);

	thr_common.instance = instance;
	thr_common.cpumask  = &cpumask;
	/* Synchronize thread start up. Test runs are more repeatable when
	 * thread / thread ID / CPU ID mapping stays constant. */
	thr_common.sync     = 1;

	for (i = 0; i < num_workers; ++i) {
		int j;
		int num_join;
		int mode = gbl_args->appl.group_mode;

		init_state(&gbl_args->appl, &gbl_args->thread_args[i].state, i);
		odph_thread_param_init(&thr_param[i]);
		thr_param[i].start    = thr_run_func;
		thr_param[i].arg      = &gbl_args->thread_args[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;

		gbl_args->thread_args[i].num_grp_join = 0;
		gbl_args->thread_args[i].thr_idx = i;

		/* Fill in list of groups to join */
		if (gbl_args->appl.num_groups > 0) {
			num_join = if_count < num_groups ? if_count : num_groups;

			if (mode == 0 || mode == 1) {
				/* All threads join all groups */
				if (mode == 0)
					num_join = num_groups;

				gbl_args->thread_args[i].num_grp_join = num_join;

				for (j = 0; j < num_join; j++)
					gbl_args->thread_args[i].group[j] = group[j];
			} else {
				/* Thread joins first groups in round robin */
				if (num_workers >= num_join) {
					gbl_args->thread_args[i].num_grp_join = 1;
					gbl_args->thread_args[i].group[0] = group[i % num_join];
				} else {
					int cnt = 0;

					for (j = 0; i + j < num_join; j += num_workers) {
						gbl_args->thread_args[i].group[cnt] = group[i + j];
						cnt++;
					}

					gbl_args->thread_args[i].num_grp_join = cnt;
				}
			}
		}

		stats[i] = &gbl_args->thread_args[i].stats;
	}

	num_thr = odph_thread_create(gbl_args->thread_tbl, &thr_common,
				     thr_param, num_workers);

	if (num_thr != num_workers) {
		ODPH_ERR("Worker create failed: %i\n", num_thr);
		exit(EXIT_FAILURE);
	}

	if (gbl_args->appl.verbose)
		odp_shm_print_all();

	/* Start packet receive and transmit */
	for (i = 0; i < if_count; ++i) {
		odp_pktio_t pktio;

		pktio = gbl_args->pktios[i].pktio;
		ret   = odp_pktio_start(pktio);
		if (ret) {
			ODPH_ERR("Pktio start failed: %s\n", gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	ret = print_speed_stats(num_workers, stats, gbl_args->appl.time,
				gbl_args->appl.accuracy);

	for (i = 0; i < if_count; ++i) {
		if (odp_pktio_stop(gbl_args->pktios[i].pktio)) {
			ODPH_ERR("Pktio stop failed: %s\n", gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	odp_atomic_store_u32(&gbl_args->exit_threads, 1);
	if (gbl_args->appl.in_mode != DIRECT_RECV)
		odp_barrier_wait(&gbl_args->term_barrier);

	odph_thread_join_result_t res[num_workers];

	/* Master thread waits for other threads to exit */
	if (odph_thread_join_result(gbl_args->thread_tbl, res, num_workers) != num_workers) {
		ODPH_ERR("Worker join failed\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < num_workers; i++) {
		if (res[i].is_sig || res[i].ret != 0) {
			ODPH_ERR("Worker thread failure%s: %d\n", res[i].is_sig ?
					" (signaled)" : "", res[i].ret);
			exit(EXIT_FAILURE);
		}
	}

	for (i = 0; i < if_count; ++i) {
		odp_pktio_t pktio = gbl_args->pktios[i].pktio;

		if (gbl_args->appl.verbose && odp_pktio_extra_stat_info(pktio, NULL, 0) > 0) {
			printf("Pktio %s extra statistics:\n", gbl_args->appl.if_names[i]);
			odp_pktio_extra_stats_print(pktio);
		}

		if (gbl_args->pktios[i].compl_q != ODP_QUEUE_INVALID)
			(void)odp_queue_destroy(gbl_args->pktios[i].compl_q);

		if (odp_pktio_close(pktio)) {
			ODPH_ERR("Pktio close failed: %s\n", gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	free(gbl_args->appl.if_names);
	free(gbl_args->appl.if_str);

	if (gbl_args->memcpy_shm != ODP_SHM_INVALID && odp_shm_free(gbl_args->memcpy_shm)) {
		ODPH_ERR("Shared mem free failed\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < gbl_args->appl.num_om; i++)
		free(gbl_args->appl.output_map[i]);

	gbl_args = NULL;
	odp_mb_full();

	for (i = 0; i < num_pools; i++) {
		if (odp_pool_destroy(pool_tbl[i])) {
			ODPH_ERR("Pool destroy failed: %i\n", i);
			exit(EXIT_FAILURE);
		}
	}

	for (i = 0; i < num_vec_pools; i++) {
		if (odp_pool_destroy(vec_pool_tbl[i])) {
			ODPH_ERR("Vector pool destroy failed: %i\n", i);
			exit(EXIT_FAILURE);
		}
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Shm free failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Term local failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Term global failed\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}

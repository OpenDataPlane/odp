/* Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define POOL_PKT_NUM 8192
#define POOL_PKT_LEN 1536
#define MAX_PKT_BURST 32
/* Three threads required for RX, TX and statistics */
#define MAX_WORKERS (ODP_THREAD_COUNT_MAX - 3)
#define QUEUE_SIZE 1024
#define MAX_PKTIOS 2
#define DUMMY_HASH 1234567890

/* Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

/* Statistics */
typedef union ODP_ALIGNED_CACHE {
	struct {
		uint64_t pps;		/* Packet per second */
		uint64_t rx_cnt;	/* RX packets */
		uint64_t tx_cnt;	/* TX packets */
		uint64_t rx_drops;	/* Dropped packets on RX */
		uint64_t tx_drops;	/* Dropped packets on TX */
	} s;
	uint8_t padding[ODP_CACHE_LINE_SIZE];
} stats_t;

/* Thread specific data */
typedef struct thread_args_t {
	odp_queue_t rx_queue;
	odp_queue_t tx_queue;
	stats_t stats;
} thread_args_t;

/* Parsed command line application arguments */
typedef struct {
	char **if_names;	 /* Array of pointers to interface names */
	odph_ethaddr_t dst_addr; /* Destination MAC address */
	int accuracy;		 /* Statistics print interval in seconds */
	int extra_work;		 /* Add extra processing to worker stage */
	int dst_change;		 /* Change destination eth address */
	int src_change;		 /* Change source eth address */
	int dst_set;		 /* Custom destination eth address given */
	int time;		 /* Time in seconds to run. */
	int num_workers;	 /* Number of pipeline worker stages */
	char *if_str;		 /* Storage for interface names */
} appl_args_t;

/* Global application data */
typedef struct {
	odp_queue_t queue[ODP_THREAD_COUNT_MAX];
	/* Thread specific arguments */
	thread_args_t thread[ODP_THREAD_COUNT_MAX];
	/* Barriers to synchronize main and workers */
	odp_barrier_t init_barrier;
	odp_barrier_t term_barrier;
	/* Pktio interfaces */
	odp_pktio_t if0, if1;
	odp_pktin_queue_t if0in, if1in;
	odp_pktout_queue_t if0out, if1out;
	odph_ethaddr_t src_addr; /* Source MAC address */
	odph_ethaddr_t dst_addr; /* Destination MAC address */
	int exit_threads;
	/* Application (parsed) arguments */
	appl_args_t appl;
} global_data_t;

static global_data_t *global;

static void sig_handler(int signo ODP_UNUSED)
{
	global->exit_threads = 1;
}

static odp_pktio_t create_pktio(const char *name, odp_pool_t pool,
				odp_pktin_queue_t *pktin,
				odp_pktout_queue_t *pktout)
{
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t in_param;
	odp_pktout_queue_param_t out_param;
	odp_pktio_t pktio;
	odp_pktio_config_t config;

	odp_pktio_param_init(&pktio_param);

	pktio = odp_pktio_open(name, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		printf("Error: failed to open %s\n", name);
		exit(1);
	}

	odp_pktio_config_init(&config);
	config.parser.layer = ODP_PROTO_LAYER_L2;
	odp_pktio_config(pktio, &config);

	odp_pktin_queue_param_init(&in_param);
	odp_pktout_queue_param_init(&out_param);

	in_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;

	if (odp_pktin_queue_config(pktio, &in_param)) {
		printf("Error: failed to config input queue for %s\n", name);
		exit(1);
	}

	out_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;

	if (odp_pktout_queue_config(pktio, &out_param)) {
		printf("Error: failed to config output queue for %s\n", name);
		exit(1);
	}

	if (odp_pktin_queue(pktio, pktin, 1) != 1) {
		printf("Error: pktin queue query failed for %s\n", name);
		exit(1);
	}
	if (odp_pktout_queue(pktio, pktout, 1) != 1) {
		printf("Error: pktout queue query failed for %s\n", name);
		exit(1);
	}
	return pktio;
}

/*
 * Fill packets' eth addresses and convert packets to events
 *
 * pkt_tbl        Array of packets
 * event_tbl[out] Array of events
 * num            Number of packets in the array
 */
static inline unsigned int prep_events(odp_packet_t pkt_tbl[],
				       odp_event_t event_tbl[],
				       unsigned int num)
{
	unsigned int i;
	unsigned int events = 0;

	if (!global->appl.dst_change && !global->appl.src_change) {
		odp_packet_to_event_multi(pkt_tbl, event_tbl, num);
		return num;
	}

	for (i = 0; i < num; ++i) {
		odp_packet_t pkt = pkt_tbl[i];
		odph_ethhdr_t *eth;

		odp_packet_prefetch(pkt, 0, ODPH_ETHHDR_LEN);

		if (odp_unlikely(!odp_packet_has_eth(pkt))) {
			odp_packet_free(pkt);
			continue;
		}

		eth = odp_packet_data(pkt);

		if (global->appl.src_change)
			eth->src = global->src_addr;

		if (global->appl.dst_change)
			eth->dst = global->dst_addr;

		event_tbl[events++] = odp_packet_to_event(pkt);
	}
	return events;
}

static inline int rx_thread(void *arg)
{
	thread_args_t *thr_args = arg;
	odp_event_t event_tbl[MAX_PKT_BURST];
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	odp_pktin_queue_t pktin_queue = global->if0in;
	odp_queue_t out_queue = thr_args->tx_queue;
	stats_t *stats = &thr_args->stats;
	int pkts, events, sent, drops;

	odp_barrier_wait(&global->init_barrier);

	while (!global->exit_threads) {
		pkts = odp_pktin_recv(pktin_queue, pkt_tbl, MAX_PKT_BURST);
		if (odp_unlikely(pkts <= 0))
			continue;

		stats->s.rx_cnt += pkts;

		events = prep_events(pkt_tbl, event_tbl, pkts);
		drops = events - pkts;
		if (odp_unlikely(drops))
			stats->s.rx_drops += pkts - events;

		sent = odp_queue_enq_multi(out_queue, event_tbl, events);
		if (odp_unlikely(sent < 0))
			sent = 0;

		stats->s.tx_cnt += sent;

		drops = events - sent;
		if (odp_unlikely(drops)) {
			stats->s.tx_drops += drops;
			odp_packet_free_multi(&pkt_tbl[sent], drops);
		}
	}

	/* Wait until pktio devices are stopped */
	odp_barrier_wait(&global->term_barrier);

	return 0;
}

static inline int tx_thread(void *arg)
{
	thread_args_t *thr_args = arg;
	odp_event_t event_tbl[MAX_PKT_BURST];
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	odp_queue_t rx_queue = thr_args->rx_queue;
	odp_pktout_queue_t pktout_queue = global->if1out;
	stats_t *stats = &thr_args->stats;
	int events, sent, tx_drops;

	odp_barrier_wait(&global->init_barrier);

	while (!global->exit_threads) {
		events = odp_queue_deq_multi(rx_queue, event_tbl,
					     MAX_PKT_BURST);
		if (odp_unlikely(events <= 0))
			continue;

		stats->s.rx_cnt += events;

		odp_packet_from_event_multi(pkt_tbl, event_tbl, events);

		sent = odp_pktout_send(pktout_queue, pkt_tbl, events);
		if (odp_unlikely(sent < 0))
			sent = 0;

		stats->s.tx_cnt += sent;

		tx_drops = events - sent;
		if (odp_unlikely(tx_drops)) {
			stats->s.tx_drops += tx_drops;
			odp_packet_free_multi(&pkt_tbl[sent], tx_drops);
		}
	}

	/* Wait until pktio devices are stopped */
	odp_barrier_wait(&global->term_barrier);

	/* Empty queue before exiting */
	events = 1;
	while (events > 0) {
		events = odp_queue_deq_multi(rx_queue, event_tbl,
					     MAX_PKT_BURST);

		if (events > 0)
			odp_event_free_multi(event_tbl, events);
	}

	return 0;
}

/*
 * Work on packets
 */
static inline void work_on_events(odp_event_t event_tbl[], unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		odp_packet_t pkt = odp_packet_from_event(event_tbl[i]);

		if (odp_hash_crc32c(odp_packet_data(pkt),
				    odp_packet_seg_len(pkt), 123) == DUMMY_HASH)
			printf("Dummy hash match\n");
	}
}

static inline int worker_thread(void *arg ODP_UNUSED)
{
	thread_args_t *thr_args = arg;
	odp_event_t event_tbl[MAX_PKT_BURST];
	stats_t *stats = &thr_args->stats;
	odp_queue_t rx_queue = thr_args->rx_queue;
	odp_queue_t tx_queue = thr_args->tx_queue;
	int events, sent, tx_drops;
	int extra_work = global->appl.extra_work;

	odp_barrier_wait(&global->init_barrier);

	while (!global->exit_threads) {
		events = odp_queue_deq_multi(rx_queue, event_tbl,
					     MAX_PKT_BURST);

		if (odp_unlikely(events <= 0))
			continue;

		stats->s.rx_cnt += events;

		if (extra_work)
			work_on_events(event_tbl, events);

		sent = odp_queue_enq_multi(tx_queue, event_tbl, events);
		if (odp_unlikely(sent < 0))
			sent = 0;

		stats->s.tx_cnt += sent;

		tx_drops = events - sent;
		if (odp_unlikely(tx_drops)) {
			stats->s.tx_drops += tx_drops;
			odp_event_free_multi(&event_tbl[sent], tx_drops);
		}
	}

	/* Wait until pktio devices are stopped */
	odp_barrier_wait(&global->term_barrier);

	/* Empty queue before exiting */
	events = 1;
	while (events > 0) {
		events = odp_queue_deq_multi(rx_queue, event_tbl,
					     MAX_PKT_BURST);

		if (events > 0)
			odp_event_free_multi(event_tbl, events);
	}

	return 0;
}

static int setup_thread_masks(odp_cpumask_t *thr_mask_rx,
			      odp_cpumask_t *thr_mask_tx,
			      odp_cpumask_t *thr_mask_workers,
			      int num_workers)
{
	odp_cpumask_t cpumask;
	int num_threads = 0;
	int i, cpu;

	if (num_workers > MAX_WORKERS) {
		printf("Worker count limited to MAX_WORKERS define (=%d)\n",
		       MAX_WORKERS);
		num_workers = MAX_WORKERS;
	}

	/* Two threads required for RX and TX*/
	num_threads = num_workers + 2;

	num_workers = odp_cpumask_default_worker(&cpumask, num_threads);
	if (num_workers != num_threads) {
		printf("Error: Not enough available CPU cores: %d/%d\n",
		       num_workers, num_threads);
		exit(1);
	}

	odp_cpumask_zero(thr_mask_rx);
	odp_cpumask_zero(thr_mask_tx);
	odp_cpumask_zero(thr_mask_workers);

	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_threads; i++) {
		if (i == 0)
			odp_cpumask_set(thr_mask_rx, cpu);
		else if (i == 1)
			odp_cpumask_set(thr_mask_tx, cpu);
		else
			odp_cpumask_set(thr_mask_workers, cpu);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	return num_threads;
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
	uint64_t total_pkts = 0;
	uint64_t pkts_prev = 0;
	uint64_t maximum_pps = 0;
	stats_t thr_stats_prev[num_workers];
	int i;
	int elapsed = 0;
	int stats_enabled = 1;
	int loop_forever = (duration == 0);

	memset(thr_stats_prev, 0, sizeof(thr_stats_prev));

	if (timeout <= 0) {
		stats_enabled = 0;
		timeout = 1;
	}

	/* Wait for all threads to be ready*/
	odp_barrier_wait(&global->init_barrier);

	do {
		uint64_t total_rx_drops = 0;
		uint64_t total_tx_drops = 0;
		uint64_t pps;

		sleep(timeout);

		for (i = 0; i < num_workers; i++) {
			uint64_t rx_cnt = thr_stats[i]->s.rx_cnt;
			uint64_t tx_cnt = thr_stats[i]->s.tx_cnt;
			uint64_t rx_drops = thr_stats[i]->s.rx_drops;
			uint64_t tx_drops = thr_stats[i]->s.tx_drops;

			/* Count only transmitted packets */
			if (i == (num_workers - 1))
				total_pkts = tx_cnt;

			total_rx_drops += rx_drops;
			total_tx_drops += tx_drops;

			pps = (tx_cnt - thr_stats_prev[i].s.tx_cnt) / timeout;
			thr_stats_prev[i].s.pps = pps;
			thr_stats_prev[i].s.rx_cnt = rx_cnt;
			thr_stats_prev[i].s.tx_cnt = tx_cnt;
			thr_stats_prev[i].s.rx_drops = rx_drops;
			thr_stats_prev[i].s.tx_drops = tx_drops;
		}
		if (stats_enabled) {
			printf("----------------------------------------\n");
			for (i = 0; i < num_workers; i++) {
				if (i == 0)
					printf("RX thread: ");
				else if (i == (num_workers - 1))
					printf("TX thread: ");
				else
					printf("Worker %d:  ", i - 1);

				printf("%" PRIu64 " pps, "
				       "%" PRIu64 " rx drops, "
				       "%" PRIu64 " tx drops\n",
				       thr_stats_prev[i].s.pps,
				       thr_stats_prev[i].s.rx_drops,
				       thr_stats_prev[i].s.tx_drops);
			}
			pps = (total_pkts - pkts_prev) / timeout;
			if (pps > maximum_pps)
				maximum_pps = pps;
			printf("TOTAL:     %" PRIu64 " pps, "
			       "%" PRIu64 " rx drops, "
			       "%" PRIu64 " tx drops, "
			       "%" PRIu64 " max pps\n",
			       pps, total_rx_drops, total_tx_drops,
			       maximum_pps);

			pkts_prev = total_pkts;
		}
		elapsed += timeout;
	} while (!global->exit_threads && (loop_forever ||
		 (elapsed < duration)));

	if (stats_enabled)
		printf("TEST RESULT: %" PRIu64 " maximum packets per second.\n",
		       maximum_pps);

	return total_pkts > 0 ? 0 : -1;
}

/*
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	odp_sys_info_print();

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "Using IFs:     %s %s\n"
	       "Worker stages: %d\n"
	       "Extra work:    %d\n\n",
	       progname, appl_args->if_names[0], appl_args->if_names[1],
	       appl_args->num_workers, appl_args->extra_work);

	fflush(NULL);
}

/*
 * Print usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane simple pipeline example application.\n"
	       "\n"
	       "Usage: %s [options]\n"
	       "\n"
	       "  E.g. %s -i eth0,eth1 -e -w 3\n\n"
	       "   ----      ----      ----      ----      ----\n"
	       "  | RX | -> | W1 | -> | W2 | -> | W3 | -> | TX |\n"
	       "   ----      ----      ----      ----      ----\n\n"
	       "  In the above example,\n"
	       "  each application stage is executed by a separate CPU thread and the stages\n"
	       "  are connected using plain queues. The RX stage receives packets from eth0 and\n"
	       "  enqueues them to the first worker stage (W1). The workers stages calculate\n"
	       "  CRC-32C over packet data. After the final worker stage (W3) has processed\n"
	       "  packets they are enqueued to the TX stage, which transmits the packets out\n"
	       "  from interface eth1.\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface <name>  Two eth interfaces (comma-separated, no spaces)\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -a, --accuracy <sec>    Time in seconds get print statistics\n"
	       "                          (default is 10 seconds).\n"
	       "  -d, --dst_change <arg>  0: Don't change packets' dst eth addresses\n"
	       "                          1: Change packets' dst eth addresses (default)\n"
	       "  -s, --src_change <arg>  0: Don't change packets' src eth addresses\n"
	       "                          1: Change packets' src eth addresses (default)\n"
	       "  -r, --dst_addr <addr>   Destination address\n"
	       "                          Requires also the -d flag to be set\n"
	       "  -t, --time <sec>        Time in seconds to run\n"
	       "  -w, --workers <num>     Number of worker stages (default 0)\n"
	       "  -e, --extra-work        Calculate CRC-32C over packet data in worker stage\n"
	       "  -h, --help              Display help and exit\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}

/*
 * Parse and store the command line arguments
 *
 * argc           Argument count
 * argv           Argument vector
 * appl_args[out] Storage for application arguments
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	char *token;
	size_t len;
	int opt;
	int long_index;
	int i;
	int if_count = 0;
	static const struct option longopts[] = {
		{"accuracy", required_argument, NULL, 'a'},
		{"extra-work", no_argument, NULL, 'e'},
		{"dst_addr", required_argument, NULL, 'r'},
		{"dst_change", required_argument, NULL, 'd'},
		{"src_change", required_argument, NULL, 's'},
		{"interface", required_argument, NULL, 'i'},
		{"time", required_argument, NULL, 't'},
		{"workers", required_argument, NULL, 'w'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "+a:d:er:s:t:i:w:h";

	appl_args->accuracy = 10; /* get and print pps stats second */
	appl_args->dst_change = 1; /* change eth dst address by default */
	appl_args->src_change = 1; /* change eth src address by default */
	appl_args->time = 0; /* loop forever if time to run is 0 */
	appl_args->extra_work = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'a':
			appl_args->accuracy = atoi(optarg);
			break;
		case 'd':
			appl_args->dst_change = atoi(optarg);
			break;
		case 'e':
			appl_args->extra_work = 1;
			break;
		case 'r':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			if (odph_eth_addr_parse(&appl_args->dst_addr,
						optarg) != 0) {
				printf("invalid MAC address\n");
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			appl_args->dst_set = 1;

			break;
		case 's':
			appl_args->src_change = atoi(optarg);
			break;
		case 't':
			appl_args->time = atoi(optarg);
			break;
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1; /* add room for '\0' */

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

			if_count = i;

			if (if_count != 2) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names = calloc(if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				appl_args->if_names[i] = token;
			}
			break;
		case 'w':
			appl_args->num_workers = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	if (if_count != 2) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1; /* reset 'extern optind' from the getopt lib */
}

int main(int argc, char **argv)
{
	odp_cpumask_t thr_mask_rx;
	odp_cpumask_t thr_mask_tx;
	odp_cpumask_t thr_mask_worker;
	odp_init_t init_param;
	odp_instance_t instance;
	odp_pool_t pool;
	odp_pool_capability_t pool_capa;
	odp_pool_param_t pool_param;
	odp_queue_capability_t queue_capa;
	odp_queue_param_t queue_param;
	odp_shm_t shm;
	odph_helper_options_t helper_options;
	odph_thread_t thr_tbl[ODP_THREAD_COUNT_MAX];
	odph_thread_param_t thr_param[ODP_THREAD_COUNT_MAX];
	odph_thread_common_param_t thr_common;
	odph_ethaddr_t new_addr;
	stats_t *stats[ODP_THREAD_COUNT_MAX];
	thread_args_t *thr_args;
	uint32_t pkt_len, seg_len, pkt_num;
	int num_threads, num_workers;
	int i;
	int ret;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		printf("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (odp_init_global(&instance, &init_param, NULL)) {
		printf("Error: ODP global init failed.\n");
		exit(1);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: ODP local init failed.\n");
		exit(1);
	}

	/* Reserve memory for global data */
	shm = odp_shm_reserve("simple_pipeline", sizeof(global_data_t),
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		printf("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	global = odp_shm_addr(shm);
	if (global == NULL) {
		printf("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	memset(global, 0, sizeof(global_data_t));

	signal(SIGINT, sig_handler);

	/* Parse and store the application arguments */
	parse_args(argc, argv, &global->appl);

	num_threads = setup_thread_masks(&thr_mask_rx, &thr_mask_tx,
					 &thr_mask_worker,
					 global->appl.num_workers);
	num_workers = num_threads - 2;

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &global->appl);

	/* Create queues for pipeline */
	if (odp_queue_capability(&queue_capa)) {
		printf("Error: reading queue capability failed.\n");
		exit(EXIT_FAILURE);
	}
	if (queue_capa.plain.max_num < (unsigned int)num_threads) {
		printf("Error: insufficient number of queues supported.\n");
		exit(EXIT_FAILURE);
	}

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_PLAIN;
	queue_param.enq_mode = ODP_QUEUE_OP_MT_UNSAFE;
	queue_param.deq_mode = ODP_QUEUE_OP_MT_UNSAFE;
	queue_param.size = QUEUE_SIZE;
	if (queue_capa.plain.max_size &&
	    queue_param.size > queue_capa.plain.max_size)
		queue_param.size = queue_capa.plain.max_size;
	for (i = 0; i < num_threads; i++) {
		odp_queue_t queue = odp_queue_create("plain_queue",
						     &queue_param);

		if (queue == ODP_QUEUE_INVALID) {
			printf("Error: queue create failed.\n");
			exit(EXIT_FAILURE);
		}
		global->queue[i] = queue;
	}

	/* Create packet pool */
	if (odp_pool_capability(&pool_capa)) {
		printf("Error: reading pool capability failed.\n");
		exit(EXIT_FAILURE);
	}

	pkt_len = POOL_PKT_LEN;
	seg_len = POOL_PKT_LEN;
	pkt_num = POOL_PKT_NUM;

	if (pool_capa.pkt.max_len && pkt_len > pool_capa.pkt.max_len)
		pkt_len = pool_capa.pkt.max_len;

	if (pool_capa.pkt.max_seg_len && seg_len > pool_capa.pkt.max_seg_len)
		seg_len = pool_capa.pkt.max_seg_len;

	if (pool_capa.pkt.max_num && pkt_num > pool_capa.pkt.max_num)
		pkt_num = pool_capa.pkt.max_num;

	odp_pool_param_init(&pool_param);
	pool_param.pkt.seg_len = seg_len;
	pool_param.pkt.len     = pkt_len;
	pool_param.pkt.num     = pkt_num;
	pool_param.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &pool_param);
	if (pool == ODP_POOL_INVALID) {
		printf("Error: packet pool create failed.\n");
		exit(1);
	}

	global->if0 = create_pktio(global->appl.if_names[0], pool,
				   &global->if0in, &global->if0out);
	global->if1 = create_pktio(global->appl.if_names[1], pool,
				   &global->if1in, &global->if1out);

	/* Save TX interface Ethernet address */
	if (odp_pktio_mac_addr(global->if1, global->src_addr.addr,
			       ODPH_ETHADDR_LEN) != ODPH_ETHADDR_LEN) {
		printf("Error: TX interface Ethernet address unknown\n");
		exit(EXIT_FAILURE);
	}

	/* Save destination Ethernet address */
	if (global->appl.dst_change) {
		/* 02:00:00:00:00:XX */
		memset(&new_addr, 0, sizeof(odph_ethaddr_t));
		if (global->appl.dst_set) {
			memcpy(&new_addr, &global->appl.dst_addr,
			       sizeof(odph_ethaddr_t));
		} else {
			new_addr.addr[0] = 0x02;
			new_addr.addr[5] = 1;
		}
		global->dst_addr = new_addr;
	}

	if (odp_pktio_start(global->if0)) {
		printf("Error: unable to start input interface\n");
		exit(1);
	}
	if (odp_pktio_start(global->if1)) {
		printf("Error: unable to start output interface\n");
		exit(1);
	}

	odp_barrier_init(&global->init_barrier, num_threads + 1);
	odp_barrier_init(&global->term_barrier, num_threads + 1);

	for (i = 0; i < num_threads; i++)
		stats[i] = &global->thread[i].stats;

	memset(thr_tbl, 0, sizeof(thr_tbl));
	memset(thr_param, 0, sizeof(thr_param));
	memset(&thr_common, 0, sizeof(thr_common));

	thr_common.instance = instance;

	/* RX thread */
	thr_args = &global->thread[0];
	thr_args->tx_queue = global->queue[0];
	thr_param[0].start = rx_thread;
	thr_param[0].arg = thr_args;
	thr_param[0].thr_type = ODP_THREAD_WORKER;
	thr_common.cpumask = &thr_mask_rx;
	odph_thread_create(thr_tbl, &thr_common, thr_param, 1);

	/* Worker threads */
	for (i = 0; i < num_workers; i++) {
		thr_args = &global->thread[i + 1];
		thr_args->rx_queue = global->queue[i];
		thr_args->tx_queue = global->queue[i + 1];

		thr_param[i].start    = worker_thread;
		thr_param[i].arg      = thr_args;
		thr_param[i].thr_type = ODP_THREAD_WORKER;
	}

	if (num_workers) {
		thr_common.cpumask = &thr_mask_worker;
		odph_thread_create(&thr_tbl[1], &thr_common, thr_param,
				   num_workers);
	}

	/* TX thread */
	thr_args = &global->thread[num_threads - 1];
	thr_args->rx_queue = global->queue[num_workers];
	thr_param[0].start = tx_thread;
	thr_param[0].arg = thr_args;
	thr_param[0].thr_type = ODP_THREAD_WORKER;
	thr_common.cpumask = &thr_mask_tx;
	odph_thread_create(&thr_tbl[num_threads - 1], &thr_common, thr_param,
			   1);

	ret = print_speed_stats(num_threads, stats, global->appl.time,
				global->appl.accuracy);

	if (odp_pktio_stop(global->if0)) {
		printf("Error: failed to stop interface %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}
	if (odp_pktio_stop(global->if1)) {
		printf("Error: failed to stop interface %s\n", argv[2]);
		exit(EXIT_FAILURE);
	}

	global->exit_threads = 1;
	odp_barrier_wait(&global->term_barrier);

	odph_thread_join(thr_tbl, num_threads);

	if (odp_pktio_close(global->if0)) {
		printf("Error: failed to close interface %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}
	if (odp_pktio_close(global->if1)) {
		printf("Error: failed to close interface %s\n", argv[2]);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < num_threads; i++) {
		if (odp_queue_destroy(global->queue[i])) {
			printf("Error: failed to destroy queue %d\n", i);
			exit(EXIT_FAILURE);
		}
	}

	if (odp_pool_destroy(pool)) {
		printf("Error: pool destroy\n");
		exit(EXIT_FAILURE);
	}

	if (odp_shm_free(shm)) {
		printf("Error: shm free global data\n");
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

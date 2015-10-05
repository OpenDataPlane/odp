/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_l2fwd.c  ODP basic forwarding application
 */

/** enable strtok */
#define _POSIX_C_SOURCE 200112L

#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>

#include <test_debug.h>

#include <odp.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

/** @def MAX_WORKERS
 * @brief Maximum number of worker threads
 */
#define MAX_WORKERS            32

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      (512*2048)

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  1856

/** @def MAX_PKT_BURST
 * @brief Maximum number of packet bursts
 */
#define MAX_PKT_BURST          16

/** @def APPL_MODE_PKT_BURST
 * @brief The application will handle pakcets in bursts
 */
#define APPL_MODE_PKT_BURST    0

/** @def APPL_MODE_PKT_QUEUE
 * @brief The application will handle packets in queues
 */
#define APPL_MODE_PKT_QUEUE    1

/** @def PRINT_APPL_MODE(x)
 * @brief Macro to print the current status of how the application handles
 * packets.
 */
#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))
/**
 * Parsed command line application arguments
 */
typedef struct {
	int cpu_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	int mode;		/**< Packet IO mode */
	int time;		/**< Time in seconds to run. */
	int accuracy;		/**< Number of seconds to get and print statistics */
	char *if_str;		/**< Storage for interface names */
} appl_args_t;

static int exit_threads;	/**< Break workers loop if set to 1 */

/**
 * Statistics
 */
typedef struct {
	uint64_t packets;	/**< Number of forwarded packets. */
	uint64_t drops;		/**< Number of dropped packets. */
} stats_t;

/**
 * Thread specific arguments
 */
typedef struct {
	int src_idx;            /**< Source interface identifier */
	stats_t **stats;	/**< Per thread packet stats */
} thread_args_t;

/**
 * Grouping of all global data
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
	/** Table of pktio handles */
	odp_pktio_t pktios[ODP_CONFIG_PKTIO_ENTRIES];
	/** Table of port ethernet addresses */
	odph_ethaddr_t port_eth_addr[ODP_CONFIG_PKTIO_ENTRIES];
	/** Table of port default output queues */
	odp_queue_t outq_def[ODP_CONFIG_PKTIO_ENTRIES];
} args_t;

/** Global pointer to args */
static args_t *gbl_args;
/** Global barrier to synchronize main and workers */
static odp_barrier_t barrier;

/* helper funcs */
static inline int lookup_dest_port(odp_packet_t pkt);
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len);
static void fill_src_eth_addrs(odp_packet_t pkt_tbl[], unsigned num,
			       int dst_port);
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

/**
 * Packet IO worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_queue_thread(void *arg)
{
	int thr, dst_port;
	odp_queue_t outq_def;
	odp_packet_t pkt;
	odp_event_t ev;
	thread_args_t *thr_args = arg;

	stats_t *stats = calloc(1, sizeof(stats_t));
	*thr_args->stats = stats;

	thr = odp_thread_id();

	printf("[%02i] QUEUE mode\n", thr);
	odp_barrier_wait(&barrier);

	/* Loop packets */
	while (!exit_threads) {
		/* Use schedule to get buf from any input queue */
		ev  = odp_schedule(NULL, ODP_SCHED_WAIT);
		pkt = odp_packet_from_event(ev);

		/* Drop packets with errors */
		if (odp_unlikely(drop_err_pkts(&pkt, 1) == 0)) {
			stats->drops += 1;
			continue;
		}

		dst_port = lookup_dest_port(pkt);

		fill_src_eth_addrs(&pkt, 1, dst_port);

		/* Enqueue the packet for output */
		outq_def = gbl_args->outq_def[dst_port];
		if (odp_queue_enq(outq_def, ev)) {
			printf("  [%i] Queue enqueue failed.\n", thr);
			odp_packet_free(pkt);
			continue;
		}

		stats->packets += 1;
	}

	free(stats);
	return NULL;
}

/**
 * Lookup the destination port for a given packet
 */
static inline int lookup_dest_port(odp_packet_t pkt)
{
	int i, src_idx;
	odp_pktio_t pktio_src;

	pktio_src = odp_packet_input(pkt);

	for (src_idx = -1, i = 0; gbl_args->pktios[i] != ODP_PKTIO_INVALID; ++i)
		if (gbl_args->pktios[i] == pktio_src)
			src_idx = i;

	if (src_idx == -1)
		LOG_ABORT("Failed to determine pktio input\n");

	return (src_idx % 2 == 0) ? src_idx + 1 : src_idx - 1;
}

/**
 * Packet IO worker thread using bursts from/to IO resources
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_ifburst_thread(void *arg)
{
	int thr;
	thread_args_t *thr_args;
	int pkts, pkts_ok;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int src_idx, dst_idx;
	odp_pktio_t pktio_src, pktio_dst;

	thr = odp_thread_id();
	thr_args = arg;

	stats_t *stats = calloc(1, sizeof(stats_t));
	*thr_args->stats = stats;

	src_idx = thr_args->src_idx;
	dst_idx = (src_idx % 2 == 0) ? src_idx+1 : src_idx-1;
	pktio_src = gbl_args->pktios[src_idx];
	pktio_dst = gbl_args->pktios[dst_idx];

	printf("[%02i] srcif:%s dstif:%s spktio:%02" PRIu64
	       " dpktio:%02" PRIu64 " BURST mode\n",
	       thr,
	       gbl_args->appl.if_names[src_idx],
	       gbl_args->appl.if_names[dst_idx],
	       odp_pktio_to_u64(pktio_src), odp_pktio_to_u64(pktio_dst));
	odp_barrier_wait(&barrier);

	/* Loop packets */
	while (!exit_threads) {
		pkts = odp_pktio_recv(pktio_src, pkt_tbl, MAX_PKT_BURST);
		if (pkts <= 0)
			continue;

		/* Drop packets with errors */
		pkts_ok = drop_err_pkts(pkt_tbl, pkts);
		if (pkts_ok > 0) {
			fill_src_eth_addrs(pkt_tbl, pkts_ok, dst_idx);

			int sent = odp_pktio_send(pktio_dst, pkt_tbl, pkts_ok);

			sent = sent > 0 ? sent : 0;
			if (odp_unlikely(sent < pkts_ok)) {
				stats->drops += pkts_ok - sent;
				do
					odp_packet_free(pkt_tbl[sent]);
				while (++sent < pkts_ok);
			}
		}

		if (odp_unlikely(pkts_ok != pkts))
			stats->drops += pkts - pkts_ok;

		if (pkts_ok == 0)
			continue;

		stats->packets += pkts_ok;
	}

	free(stats);
	return NULL;
}

/**
 * Create a pktio handle, optionally associating a default input queue.
 *
 * @param dev Name of device to open
 * @param pool Pool to associate with device for packet RX/TX
 * @param mode Packet processing mode for this device (BURST or QUEUE)
 *
 * @return The handle of the created pktio object.
 * @retval ODP_PKTIO_INVALID if the create fails.
 */
static odp_pktio_t create_pktio(const char *dev, odp_pool_t pool,
				int mode)
{
	char inq_name[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	odp_queue_t inq_def;
	odp_pktio_t pktio;
	int ret;
	odp_pktio_param_t pktio_param;

	memset(&pktio_param, 0, sizeof(pktio_param));

	if (mode == APPL_MODE_PKT_BURST)
		pktio_param.in_mode = ODP_PKTIN_MODE_RECV;
	else
		pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		LOG_ERR("Error: failed to open %s\n", dev);
		return ODP_PKTIO_INVALID;
	}

	printf("created pktio %" PRIu64 " (%s)\n",
	       odp_pktio_to_u64(pktio), dev);

	/* no further setup needed for burst mode */
	if (mode == APPL_MODE_PKT_BURST)
		return pktio;

	odp_queue_param_init(&qparam);
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	snprintf(inq_name, sizeof(inq_name), "%" PRIu64 "-pktio_inq_def",
		 odp_pktio_to_u64(pktio));
	inq_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	inq_def = odp_queue_create(inq_name, ODP_QUEUE_TYPE_PKTIN, &qparam);
	if (inq_def == ODP_QUEUE_INVALID) {
		LOG_ERR("Error: pktio queue creation failed\n");
		return ODP_PKTIO_INVALID;
	}

	ret = odp_pktio_inq_setdef(pktio, inq_def);
	if (ret != 0) {
		LOG_ERR("Error: default input-Q setup\n");
		return ODP_PKTIO_INVALID;
	}

	return pktio;
}

/**
 *  Print statistics
 *
 * @param num_workers Number of worker threads
 * @param thr_stats Pointer to stats storage
 * @param duration Number of seconds to loop in
 * @param timeout Number of seconds for stats calculation
 *
 */
static int print_speed_stats(int num_workers, stats_t **thr_stats,
			      int duration, int timeout)
{
	uint64_t pkts, pkts_prev = 0, pps, drops, maximum_pps = 0;
	int i, elapsed = 0;
	int loop_forever = (duration == 0);

	/* Wait for all threads to be ready*/
	odp_barrier_wait(&barrier);

	do {
		pkts = 0;
		drops = 0;

		sleep(timeout);

		for (i = 0; i < num_workers; i++) {
			pkts += thr_stats[i]->packets;
			drops += thr_stats[i]->drops;
		}
		pps = (pkts - pkts_prev) / timeout;
		if (pps > maximum_pps)
			maximum_pps = pps;
		printf("%" PRIu64 " pps, %" PRIu64 " max pps, ",  pps,
		       maximum_pps);

		printf(" %" PRIu64 " total drops\n", drops);

		elapsed += timeout;
		pkts_prev = pkts;
	} while (loop_forever || (elapsed < duration));

	printf("TEST RESULT: %" PRIu64 " maximum packets per second.\n",
	       maximum_pps);

	return pkts > 100 ? 0 : -1;
}

/**
 * ODP L2 forwarding main function
 */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	odp_pool_t pool;
	int i;
	int cpu;
	int num_workers;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pktio_t pktio;
	odp_pool_param_t params;
	int ret;

	/* Init ODP before calling anything else */
	if (odp_init_global(NULL, NULL)) {
		LOG_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(ODP_THREAD_CONTROL)) {
		LOG_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);
	gbl_args = odp_shm_addr(shm);

	if (gbl_args == NULL) {
		LOG_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(gbl_args, 0, sizeof(*gbl_args));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &gbl_args->appl);

	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	if (gbl_args->appl.cpu_count)
		num_workers = gbl_args->appl.cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_def_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	if (num_workers < gbl_args->appl.if_count) {
		LOG_ERR("Error: CPU count %d less than interface count\n",
			num_workers);
		exit(EXIT_FAILURE);
	}
	if (gbl_args->appl.if_count % 2 != 0) {
		LOG_ERR("Error: interface count %d is odd in fwd appl.\n",
			gbl_args->appl.if_count);
		exit(EXIT_FAILURE);
	}

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &params);

	if (pool == ODP_POOL_INVALID) {
		LOG_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	for (i = 0; i < gbl_args->appl.if_count; ++i) {
		pktio = create_pktio(gbl_args->appl.if_names[i],
				     pool, gbl_args->appl.mode);
		if (pktio == ODP_PKTIO_INVALID)
			exit(EXIT_FAILURE);
		gbl_args->pktios[i] = pktio;

		/* Save interface ethernet address */
		if (odp_pktio_mac_addr(pktio, gbl_args->port_eth_addr[i].addr,
				       ODPH_ETHADDR_LEN) != ODPH_ETHADDR_LEN) {
			LOG_ERR("Error: interface ethernet address unknown\n");
			exit(EXIT_FAILURE);
		}

		/* Save interface default output queue */
		if (gbl_args->appl.mode == APPL_MODE_PKT_QUEUE)
			gbl_args->outq_def[i] = odp_pktio_outq_getdef(pktio);

		ret = odp_pktio_start(pktio);
		if (ret) {
			LOG_ERR("Error: unable to start %s\n",
				gbl_args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}

	}
	gbl_args->pktios[i] = ODP_PKTIO_INVALID;

	memset(thread_tbl, 0, sizeof(thread_tbl));

	stats_t **stats = calloc(1, sizeof(stats_t) * num_workers);

	odp_barrier_init(&barrier, num_workers + 1);

	/* Create worker threads */
	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; ++i) {
		odp_cpumask_t thd_mask;
		void *(*thr_run_func) (void *);

		if (gbl_args->appl.mode == APPL_MODE_PKT_BURST)
			thr_run_func = pktio_ifburst_thread;
		else /* APPL_MODE_PKT_QUEUE */
			thr_run_func = pktio_queue_thread;

		gbl_args->thread[i].src_idx = i % gbl_args->appl.if_count;
		gbl_args->thread[i].stats = &stats[i];

		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);
		odph_linux_pthread_create(&thread_tbl[i], &thd_mask,
					  thr_run_func,
					  &gbl_args->thread[i]);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	ret = print_speed_stats(num_workers, stats, gbl_args->appl.time,
				gbl_args->appl.accuracy);
	free(stats);
	exit_threads = 1;

	/* Master thread waits for other threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);

	free(gbl_args->appl.if_names);
	free(gbl_args->appl.if_str);
	printf("Exit\n\n");

	return ret;
}

/**
 * Drop packets which input parsing marked as containing errors.
 *
 * Frees packets with error and modifies pkt_tbl[] to only contain packets with
 * no detected errors.
 *
 * @param pkt_tbl  Array of packet
 * @param len      Length of pkt_tbl[]
 *
 * @return Number of packets with no detected error
 */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	unsigned pkt_cnt = len;
	unsigned i, j;

	for (i = 0, j = 0; i < len; ++i) {
		pkt = pkt_tbl[i];

		if (odp_unlikely(odp_packet_has_error(pkt))) {
			odp_packet_free(pkt); /* Drop */
			pkt_cnt--;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j-1] = pkt;
		}
	}

	return pkt_cnt;
}

/**
 * Fill packets' eth src addresses according to the destination port
 *
 * @param pkt_tbl  Array of packets
 * @param num      Number of packets in the array
 * @param dst_port Destination port
 */
static void fill_src_eth_addrs(odp_packet_t pkt_tbl[], unsigned num,
			       int dst_port)
{
	odp_packet_t pkt;
	odph_ethhdr_t *eth;
	unsigned i;

	for (i = 0; i < num; ++i) {
		pkt = pkt_tbl[i];
		if (odp_packet_has_eth(pkt)) {
			eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
			eth->src = gbl_args->port_eth_addr[dst_port];
		}
	}
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
	int i;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"time", required_argument, NULL, 't'},
		{"accuracy", required_argument, NULL, 'a'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	appl_args->time = 0; /* loop forever if time to run is 0 */
	appl_args->accuracy = 1; /* get and print pps stats second */
	appl_args->mode = -1; /* Invalid, must be changed by parsing */

	while (1) {
		opt = getopt_long(argc, argv, "+c:+t:+a:i:m:h",
				  longopts, &long_index);

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

			if (appl_args->if_count == 0) {
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
			if (i == 0)
				appl_args->mode = APPL_MODE_PKT_BURST;
			else
				appl_args->mode = APPL_MODE_PKT_QUEUE;
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0 || appl_args->mode == -1) {
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

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %"PRIu64"\n"
	       "Cache line size: %i\n"
	       "CPU count:       %i\n"
	       "\n",
	       odp_version_api_str(), odp_sys_cpu_model_str(), odp_sys_cpu_hz(),
	       odp_sys_cache_line_size(), odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n"
	       "Mode:            ");
	if (appl_args->mode == APPL_MODE_PKT_BURST)
		PRINT_APPL_MODE(APPL_MODE_PKT_BURST);
	else
		PRINT_APPL_MODE(APPL_MODE_PKT_QUEUE);
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane L2 forwarding application.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth0,eth1,eth2,eth3 -m 0 -t 1\n"
	       " In the above example,\n"
	       " eth0 will send pkts to eth1 and vice versa\n"
	       " eth2 will send pkts to eth3 and vice versa\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "  -m, --mode      0: Burst send&receive packets (no queues)\n"
	       "                  1: Send&receive packets through ODP queues.\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -c, --count <number> CPU count.\n"
	       "  -t, --time  <number> Time in seconds to run.\n"
	       "  -a, --accuracy <number> Time in seconds get print statistics\n"
	       "                          (default is 1 second).\n"
	       "  -h, --help           Display help and exit.\n\n"
	       " environment variables: ODP_PKTIO_DISABLE_NETMAP\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_MMAP\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_MMSG\n"
	       " can be used to advanced pkt I/O selection for linux-generic\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}

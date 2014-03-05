/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_example_pktio.c  ODP basic packet IO loopback test application
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <odp.h>
#include <helper/odp_linux.h>
#include <helper/odp_packet_helper.h>
#include <helper/odp_eth.h>
#include <helper/odp_ip.h>

#define MAX_WORKERS            32
#define SHM_PKT_POOL_SIZE      (512*2048)
#define SHM_PKT_POOL_BUF_SIZE  1856
#define MAX_PKT_BURST          16

#define APPL_MODE_PKT_BURST    0
#define APPL_MODE_PKT_QUEUE    1

#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))
/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	int mode;		/**< Packet IO mode */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
} appl_args_t;

/**
 * Thread specific arguments
 */
typedef struct {
	char *pktio_dev;	/**< Interface name to use */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
	int mode;		/**< Thread mode */
} thread_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
} args_t;

/** Global pointer to args */
static args_t *args;

/* helper funcs */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len);
static void swap_pkt_addrs(odp_packet_t pkt_tbl[], unsigned len);
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

/**
 * Packet IO loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_queue_thread(void *arg)
{
	int thr;
	odp_buffer_pool_t pkt_pool;
	odp_pktio_t pktio;
	thread_args_t *thr_args;
	odp_queue_t outq_def;
	odp_queue_t inq_def;
	char inq_name[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	odp_packet_t pkt;
	odp_buffer_t buf;
	int ret;
	unsigned long pkt_cnt = 0;
	unsigned long err_cnt = 0;
	odp_pktio_params_t params;
	socket_params_t *sock_params = &params.sock_params;

	thr = odp_thread_id();
	thr_args = arg;

	printf("Pktio thread [%02i] starts, pktio_dev:%s\n", thr,
	       thr_args->pktio_dev);

	/* Lookup the packet pool */
	pkt_pool = odp_buffer_pool_lookup("packet_pool");
	if (pkt_pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("  [%02i] Error: pkt_pool not found\n", thr);
		return NULL;
	}

	/* Open a packet IO instance for this thread */
	sock_params->type = ODP_PKTIO_TYPE_SOCKET;
	pktio = odp_pktio_open(thr_args->pktio_dev, thr_args->pool, &params);
	if (pktio == ODP_PKTIO_INVALID) {
		ODP_ERR("  [%02i] Error: pktio create failed\n", thr);
		return NULL;
	}

	/*
	 * Create and set the default INPUT queue associated with the 'pktio'
	 * resource
	 */
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
	snprintf(inq_name, sizeof(inq_name), "%i-pktio_inq_def", (int)pktio);
	inq_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	inq_def = odp_queue_create(inq_name, ODP_QUEUE_TYPE_PKTIN, &qparam);
	if (inq_def == ODP_QUEUE_INVALID) {
		ODP_ERR("  [%02i] Error: pktio queue creation failed\n", thr);
		return NULL;
	}

	ret = odp_pktio_inq_setdef(pktio, inq_def);
	if (ret != 0) {
		ODP_ERR("  [%02i] Error: default input-Q setup\n", thr);
		return NULL;
	}

	printf("  [%02i] created pktio:%02i, queue mode (ATOMIC queues)\n"
	       "          default pktio%02i-INPUT queue:%u\n",
		thr, pktio, pktio, inq_def);

	/* Loop packets */
	for (;;) {
		odp_pktio_t pktio_tmp;

#if 1
		/* Use schedule to get buf from any input queue */
		buf = odp_schedule(NULL);
#else
		/* Always dequeue from the same input queue */
		buf = odp_queue_deq(inq_def);
		if (!odp_buffer_is_valid(buf))
			continue;
#endif

		pkt = odp_packet_from_buffer(buf);

		/* Drop packets with errors */
		if (odp_unlikely(drop_err_pkts(&pkt, 1) == 0)) {
			ODP_ERR("Drop frame - err_cnt:%lu\n", ++err_cnt);
			continue;
		}

		pktio_tmp = odp_pktio_get_input(pkt);
		outq_def = odp_pktio_outq_getdef(pktio_tmp);

		if (outq_def == ODP_QUEUE_INVALID) {
			ODP_ERR("  [%02i] Error: def output-Q query\n", thr);
			return NULL;
		}

		/* Swap Eth MACs and possibly IP-addrs before sending back */
		swap_pkt_addrs(&pkt, 1);

		/* Enqueue the packet for output */
		odp_queue_enq(outq_def, buf);

		/* Print packet counts every once in a while */
		if (odp_unlikely(pkt_cnt++ % 100000 == 0)) {
			printf("  [%02i] pkt_cnt:%lu\n", thr, pkt_cnt);
			fflush(NULL);
		}
	}

/* unreachable */
}

/**
 * Packet IO loopback worker thread using bursts from/to IO resources
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_ifburst_thread(void *arg)
{
	int thr;
	odp_buffer_pool_t pkt_pool;
	odp_pktio_t pktio;
	thread_args_t *thr_args;
	int pkts, pkts_ok;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	unsigned long pkt_cnt = 0;
	unsigned long err_cnt = 0;
	unsigned long tmp = 0;
	odp_pktio_params_t params;
	socket_params_t *sock_params = &params.sock_params;

	thr = odp_thread_id();
	thr_args = arg;

	printf("Pktio thread [%02i] starts, pktio_dev:%s\n", thr,
	       thr_args->pktio_dev);

	/* Lookup the packet pool */
	pkt_pool = odp_buffer_pool_lookup("packet_pool");
	if (pkt_pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("  [%02i] Error: pkt_pool not found\n", thr);
		return NULL;
	}

	/* Open a packet IO instance for this thread */
	sock_params->type = ODP_PKTIO_TYPE_SOCKET;
	pktio = odp_pktio_open(thr_args->pktio_dev, thr_args->pool, &params);
	if (pktio == ODP_PKTIO_INVALID) {
		ODP_ERR("  [%02i] Error: pktio create failed.\n", thr);
		return NULL;
	}

	printf("  [%02i] created pktio:%02i, burst mode\n",
	       thr, pktio);

	/* Loop packets */
	for (;;) {
		pkts = odp_pktio_recv(pktio, pkt_tbl, MAX_PKT_BURST);
		if (pkts > 0) {
			/* Drop packets with errors */
			pkts_ok = drop_err_pkts(pkt_tbl, pkts);
			if (pkts_ok > 0) {
				/* Swap Eth MACs and IP-addrs */
				swap_pkt_addrs(pkt_tbl, pkts_ok);
				odp_pktio_send(pktio, pkt_tbl, pkts_ok);
			}

			if (odp_unlikely(pkts_ok != pkts))
				ODP_ERR("Dropped frames:%u - err_cnt:%lu\n",
					pkts-pkts_ok, ++err_cnt);

			/* Print packet counts every once in a while */
			tmp += pkts_ok;
			if (odp_unlikely((tmp >= 100000) || /* OR first print:*/
			    ((pkt_cnt == 0) && ((tmp-1) < MAX_PKT_BURST)))) {
				pkt_cnt += tmp;
				printf("  [%02i] pkt_cnt:%lu\n", thr, pkt_cnt);
				fflush(NULL);
				tmp = 0;
			}
		}
	}

/* unreachable */
}

/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odp_linux_pthread_t thread_tbl[MAX_WORKERS];
	odp_buffer_pool_t pool;
	int thr_id;
	int num_workers;
	void *pool_base;
	int i;
	int first_core;
	int core_count;

	/* Init ODP before calling anything else */
	if (odp_init_global()) {
		ODP_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	args = odp_shm_reserve("shm_args", sizeof(args_t), ODP_CACHE_LINE_SIZE);
	if (args == NULL) {
		ODP_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(args, 0, sizeof(*args));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	core_count  = odp_sys_core_count();
	num_workers = core_count;

	if (args->appl.core_count)
		num_workers = args->appl.core_count;

	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	printf("Num worker threads: %i\n", num_workers);

	/*
	 * By default core #0 runs Linux kernel background tasks.
	 * Start mapping thread from core #1
	 */
	first_core = 1;

	if (core_count == 1)
		first_core = 0;

	printf("First core:         %i\n\n", first_core);

	/* Init this thread */
	thr_id = odp_thread_create(0);
	odp_init_local(thr_id);

	/* Create packet pool */
	pool_base = odp_shm_reserve("shm_packet_pool",
				    SHM_PKT_POOL_SIZE, ODP_CACHE_LINE_SIZE);
	if (pool_base == NULL) {
		ODP_ERR("Error: packet pool mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	pool = odp_buffer_pool_create("packet_pool", pool_base,
				      SHM_PKT_POOL_SIZE,
				      SHM_PKT_POOL_BUF_SIZE,
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_PACKET);
	if (pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_buffer_pool_print(pool);

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	for (i = 0; i < num_workers; ++i) {
		void *(*thr_run_func) (void *);
		int core;
		int if_idx;

		core = (first_core + i) % core_count;

		if_idx = i % args->appl.if_count;

		args->thread[i].pktio_dev = args->appl.if_names[if_idx];
		args->thread[i].pool = pool;
		args->thread[i].mode = args->appl.mode;

		if (args->appl.mode == APPL_MODE_PKT_BURST)
			thr_run_func = pktio_ifburst_thread;
		else /* APPL_MODE_PKT_QUEUE */
			thr_run_func = pktio_queue_thread;
		/*
		 * Create threads one-by-one instead of all-at-once,
		 * because each thread might get different arguments.
		 * Calls odp_thread_create(cpu) for each thread
		 */
		odp_linux_pthread_create(thread_tbl, 1, core, thr_run_func,
					 &args->thread[i]);
	}

	/* Master thread waits for other threads to exit */
	odp_linux_pthread_join(thread_tbl, num_workers);

	printf("Exit\n\n");

	return 0;
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

		if (odp_unlikely(odp_packet_error(pkt))) {
			odp_packet_free(pkt); /* Drop */
			pkt_cnt--;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j] = pkt;
		}
	}

	return pkt_cnt;
}

/**
 * Swap eth src<->dst and IP src<->dst addresses
 *
 * @param pkt_tbl  Array of packets
 * @param len      Length of pkt_tbl[]
 */

static void swap_pkt_addrs(odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	odp_ethhdr_t *eth;
	odp_ethaddr_t tmp_addr;
	odp_ipv4hdr_t *ip;
	uint32be_t ip_tmp_addr; /* tmp ip addr */
	unsigned i;

	for (i = 0; i < len; ++i) {
		pkt = pkt_tbl[i];
		if (odp_packet_inflag_eth(pkt)) {
			eth = (odp_ethhdr_t *)odp_packet_l2(pkt);

			tmp_addr = eth->dst;
			eth->dst = eth->src;
			eth->src = tmp_addr;

			if (odp_packet_inflag_ipv4(pkt)) {
				/* IPv4 */
				ip = (odp_ipv4hdr_t *)odp_packet_l3(pkt);

				ip_tmp_addr  = ip->src_addr;
				ip->src_addr = ip->dst_addr;
				ip->dst_addr = ip_tmp_addr;
			}
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
	char *names, *str, *token, *save;
	size_t len;
	int i;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	appl_args->mode = -1; /* Invalid, must be changed by parsing */

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:m:h",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->core_count = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			names = malloc(len);
			if (names == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
			}
			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
			    calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
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
	       "Core count:      %i\n"
	       "\n",
	       odp_version_api_str(), odp_sys_cpu_model_str(), odp_sys_cpu_hz(),
	       odp_sys_cache_line_size(), odp_sys_core_count());

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
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth1,eth2,eth3 -m 0\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "  -m, --mode      0: Burst send&receive packets (no queues)\n"
	       "                  1: Send&receive packets through ODP queues.\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -c, --count <number> Core count.\n"
	       "  -h, --help           Display help and exit.\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}

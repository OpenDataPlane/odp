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

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <example_debug.h>

#include <odp.h>
#include <odph_linux.h>
#include <odph_packet.h>
#include <odph_eth.h>
#include <odph_ip.h>

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
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	int mode;		/**< Packet IO mode */
	int type;		/**< Packet IO type */
	int fanout;		/**< Packet IO fanout */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
} appl_args_t;

/**
 * Thread specific arguments
 */
typedef struct {
	char *srcif;		/**< Source Interface */
	char *dstif;		/**< Dest Interface */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
	odp_pktio_t srcpktio;	/**< Source pktio handle */
	odp_pktio_t dstpktio;	/**< Destination pktio handle */
	int mode;		/**< Thread mode */
	int type;		/**< Thread i/o type */
	int fanout;		/**< Thread i/o fanout */
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
static args_t *gbl_args;
/** Number of worker threads */
static int num_workers;

/* helper funcs */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len);
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

/**
 * @fn static burst_mode_init_params(void *arg, odp_buffer_pool_t pool)
 *
 * Burst mode: pktio for each thread will be created with either same or
 * different params
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 * @param pool is the packet pool from where buffers should be taken
 *
 * @return odp_pktio_t ODP packet IO handle
 */
static odp_pktio_t burst_mode_init_params(void *arg, odp_buffer_pool_t pool)
{
	thread_args_t *args;
	odp_pktio_t pktio;

	args = arg;
	/* Open a packet IO instance for this thread */
	pktio = odp_pktio_open(args->srcif, pool);
	if (pktio == ODP_PKTIO_INVALID)
		EXAMPLE_ERR("  Error: pktio create failed");

	return pktio;
}

/**
 * @fn queue_mode_init_params(void *arg, odp_buffer_pool_t pool)
 *
 * Queue mode: pktio for each thread will be created with either same or
 * different params. Queues are created and attached to the pktio.
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 * @param pool is the packet pool from where buffers should be taken
 *
 * @return odp_pktio_t ODP packet IO handle
 */
static odp_pktio_t queue_mode_init_params(void *arg, odp_buffer_pool_t pool)
{
	char inq_name[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	odp_queue_t inq_def;
	int ret;
	odp_pktio_t pktio = ODP_PKTIO_INVALID;

	pktio = burst_mode_init_params(arg, pool);
	if (pktio == ODP_PKTIO_INVALID)
		return pktio;
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
		EXAMPLE_ERR("  Error: pktio queue creation failed");
		return ODP_PKTIO_INVALID;
	}

	ret = odp_pktio_inq_setdef(pktio, inq_def);
	if (ret != 0) {
		EXAMPLE_ERR("  Error: default input-Q setup");
		return ODP_PKTIO_INVALID;
	}

	return pktio;
}

/**
 * Packet IO worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_queue_thread(void *arg)
{
	int thr, i;
	thread_args_t *thr_args;
	char dstpktio[MAX_WORKERS+1];
	odp_queue_t outq_def;
	odp_packet_t pkt;
	odp_buffer_t buf;
	unsigned long pkt_cnt = 0;
	unsigned long err_cnt = 0;

	thr = odp_thread_id();
	thr_args = arg;

	if (thr_args->srcpktio == 0 || thr_args->dstpktio == 0) {
		EXAMPLE_ERR("Invalid srcpktio:%d dstpktio:%d\n",
			    thr_args->srcpktio, thr_args->dstpktio);
		return NULL;
	}
	printf("[%02i] srcif:%s dstif:%s spktio:%02i dpktio:%02i QUEUE mode\n",
	       thr, thr_args->srcif, thr_args->dstif, thr_args->srcpktio,
	       thr_args->dstpktio);

	/* Populate an array of destination pktio's in all threads as the
	 * scheduler can take packets from any input queue
	 */
	for (i = 0; i < num_workers; i++)
		dstpktio[i+1] = gbl_args->thread[i].dstpktio;

	/* Loop packets */
	for (;;) {
		odp_pktio_t pktio_tmp;

		/* Use schedule to get buf from any input queue */
		buf = odp_schedule(NULL, ODP_SCHED_WAIT);

		pkt = odp_packet_from_buffer(buf);
		/* Drop packets with errors */
		if (odp_unlikely(drop_err_pkts(&pkt, 1) == 0)) {
			EXAMPLE_ERR("Drop frame - err_cnt:%lu\n", ++err_cnt);
			continue;
		}

		pktio_tmp = odp_pktio_get_input(pkt);
		outq_def = odp_pktio_outq_getdef(dstpktio[pktio_tmp]);
		if (outq_def == ODP_QUEUE_INVALID) {
			EXAMPLE_ERR("  [%02i] Error: def output-Q query\n",
				    thr);
			return NULL;
		}

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
	unsigned long pkt_cnt = 0;
	unsigned long err_cnt = 0;
	unsigned long tmp = 0;

	thr = odp_thread_id();
	thr_args = arg;

	if (thr_args->srcpktio == 0 || thr_args->dstpktio == 0) {
		EXAMPLE_ERR("Invalid srcpktio:%d dstpktio:%d\n",
			    thr_args->srcpktio, thr_args->dstpktio);
		return NULL;
	}
	printf("[%02i] srcif:%s dstif:%s spktio:%02i dpktio:%02i BURST mode\n",
	       thr, thr_args->srcif, thr_args->dstif, thr_args->srcpktio,
	       thr_args->dstpktio);

	/* Loop packets */
	for (;;) {
		pkts = odp_pktio_recv(thr_args->srcpktio, pkt_tbl,
					MAX_PKT_BURST);
		if (pkts > 0) {
			/* Drop packets with errors */
			pkts_ok = drop_err_pkts(pkt_tbl, pkts);
			if (pkts_ok > 0)
				odp_pktio_send(thr_args->dstpktio, pkt_tbl,
					       pkts_ok);
			if (odp_unlikely(pkts_ok != pkts))
				EXAMPLE_ERR("Dropped frames:%u - err_cnt:%lu\n",
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
 * ODP L2 forwarding main function
 */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	odp_buffer_pool_t pool;
	int i;
	int first_core;
	int core_count;
	odp_pktio_t pktio;
	odp_shm_t shm;
	odp_buffer_pool_param_t params;

	/* Init ODP before calling anything else */
	if (odp_init_global(NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local()) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);
	gbl_args = odp_shm_addr(shm);

	if (gbl_args == NULL) {
		EXAMPLE_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(gbl_args, 0, sizeof(*gbl_args));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &gbl_args->appl);

	core_count  = odp_sys_core_count();
	num_workers = core_count;

	if (gbl_args->appl.core_count)
		num_workers = gbl_args->appl.core_count;

	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	printf("Num worker threads: %i\n", num_workers);

	if (num_workers < gbl_args->appl.if_count) {
		EXAMPLE_ERR("Error: core count %d is less than interface "
			    "count\n", num_workers);
		exit(EXIT_FAILURE);
	}
	if (gbl_args->appl.if_count % 2 != 0) {
		EXAMPLE_ERR("Error: interface count %d is odd in fwd appl.\n",
			    gbl_args->appl.if_count);
		exit(EXIT_FAILURE);
	}
	/*
	 * By default core #0 runs Linux kernel background tasks.
	 * Start mapping thread from core #1
	 */
	first_core = 1;

	if (core_count == 1)
		first_core = 0;

	printf("First core:         %i\n\n", first_core);

	/* Create packet pool */
	params.buf_size  = SHM_PKT_POOL_BUF_SIZE;
	params.buf_align = 0;
	params.num_bufs  = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
	params.buf_type  = ODP_BUFFER_TYPE_PACKET;

	pool = odp_buffer_pool_create("packet pool", ODP_SHM_NULL, &params);

	if (pool == ODP_BUFFER_POOL_INVALID) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_buffer_pool_print(pool);

	memset(thread_tbl, 0, sizeof(thread_tbl));
	/* initialize threads params */
	for (i = 0; i < num_workers; ++i) {
		int if_idx;

		if_idx = i % gbl_args->appl.if_count;

		gbl_args->thread[i].srcif = gbl_args->appl.if_names[if_idx];
		if (if_idx % 2 == 0)
			gbl_args->thread[i].dstif = gbl_args->appl.if_names[if_idx+1];
		else
			gbl_args->thread[i].dstif = gbl_args->appl.if_names[if_idx-1];
		gbl_args->thread[i].pool = pool;
		gbl_args->thread[i].mode = gbl_args->appl.mode;

		if (gbl_args->appl.mode == APPL_MODE_PKT_BURST) {
			pktio = burst_mode_init_params(&gbl_args->thread[i], pool);
			if (pktio == ODP_PKTIO_INVALID) {
				EXAMPLE_ERR("  for thread:%02i\n", i);
				exit(EXIT_FAILURE);
			}
		} else { /* APPL_MODE_PKT_QUEUE */
			pktio = queue_mode_init_params(&gbl_args->thread[i], pool);
			if (pktio == ODP_PKTIO_INVALID) {
				EXAMPLE_ERR("  for thread:%02i\n", i);
				exit(EXIT_FAILURE);
			}
		}
		gbl_args->thread[i].srcpktio = pktio;
	}
	for (i = 0; i < num_workers; ++i) {
		if (i % 2 == 0)
			gbl_args->thread[i].dstpktio = gbl_args->thread[i+1].srcpktio;
		else
			gbl_args->thread[i].dstpktio = gbl_args->thread[i-1].srcpktio;
	}
	/* Create worker threads */
	for (i = 0; i < num_workers; ++i) {
		void *(*thr_run_func) (void *);
		int core;

		core = (first_core + i) % core_count;

		if (gbl_args->appl.mode == APPL_MODE_PKT_BURST)
			thr_run_func = pktio_ifburst_thread;
		else /* APPL_MODE_PKT_QUEUE */
			thr_run_func = pktio_queue_thread;
		odph_linux_pthread_create(&thread_tbl[i], 1, core, thr_run_func,
					  &gbl_args->thread[i]);
	}

	/* Master thread waits for other threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);

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
			odph_packet_free(pkt); /* Drop */
			pkt_cnt--;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j-1] = pkt;
		}
	}

	return pkt_cnt;
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
	       "  -c, --count <number> Core count.\n"
	       "  -h, --help           Display help and exit.\n\n"
	       " environment variables: ODP_PKTIO_DISABLE_SOCKET_MMAP\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_MMSG\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_BASIC\n"
	       " can be used to advanced pkt I/O selection for linux-generic\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}

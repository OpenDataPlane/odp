/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP basic packet IO loopback test application
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include <odp.h>
#include <odp_debug.h>
#include <helper/odp_linux.h>
#include <helper/odp_eth.h>
#include <helper/odp_ip.h>

#include <odp_pktio_netmap.h>

#define MAX_WORKERS            32
#define SHM_PKT_POOL_SIZE      (512*2048)
#define SHM_PKT_POOL_BUF_SIZE  1856
#define MAX_PKT_BURST          16

#define PKTIO_MODE_SOCK        0
#define PKTIO_MODE_NETMAP      1

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

/**
 * Interface parameters obatained from app arguments
 */
typedef struct {
	char if_name[32];
	int pktio_mode;         /**< Socket mode or netmap mode */
} if_info_t;

/**
 * Parsed command line application arguments
 */
typedef struct {
	int if_count;		/**< Number of interfaces to be used */
	if_info_t *ifs;		/**< Array of interface config options */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
} appl_args_t;

/**
 * Thread specific arguments
 * In this netmap example, there is a thread polling a network interface
 * and another thread polling the ring that is used by the software stack
 * to send packets to the same network interface. Each of the two threads
 * needs to know which is the output queue corresponding to the other thread
 * to be able to pass packets between the stack and the nic. This queue is
 * defined by bridge_q below.
 */
typedef struct {
	odp_pktio_t pktio;
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
	char *pktio_dev;	/**< Interface name to use */
	int netmap_mode;	/**< Either poll the hardware rings or the
				     rings associated with the host stack */
	odp_queue_t bridge_q;   /**< Related pktio_entry */
} thread_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
	/** Lookup table */
	unsigned char pktio_tbl[ODP_CONFIG_PKTIO_ENTRIES];
} args_t;

/** Global pointer to args */
static args_t *args;

/* helper funcs */
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
	thread_args_t *thr_args;
	odp_packet_t pkt;
	odp_buffer_t buf;
	unsigned long pkt_cnt = 0;

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

	/* Loop packets */
	for (;;) {
		odp_pktio_t pktio_tmp;
		odp_queue_t outq_def;
		int pktio_nr;

		/* Use schedule to get buf from any input queue */
		buf = odp_schedule(NULL);

		pkt = odp_packet_from_buffer(buf);
		pktio_tmp = odp_pktio_get_input(pkt);
		if (pktio_tmp == ODP_PKTIO_INVALID) {
			ODP_ERR("[%02i] Error: invalid pktio\n", thr);
			return NULL;
		}

		outq_def = odp_pktio_outq_getdef(pktio_tmp);

		if (outq_def == ODP_QUEUE_INVALID) {
			ODP_ERR("  [%02i] Error: def output-Q query\n",
				thr);
			return NULL;
		}

		/* Lookup the thread associated with the entry */
		pktio_nr = args->pktio_tbl[pktio_tmp];
		odp_queue_enq(args->thread[pktio_nr].bridge_q, buf);

		/* Send back packets arrived on physical interface */
		if (args->thread[pktio_nr].netmap_mode == ODP_NETMAP_MODE_HW) {
			odp_packet_t pkt_copy;
			odp_buffer_t buf_copy;
			size_t frame_len = odp_packet_get_len(pkt);
			size_t l2_offset = odp_packet_l2_offset(pkt);
			size_t l3_offset = odp_packet_l3_offset(pkt);

			buf_copy = odp_buffer_alloc(pkt_pool);
			pkt_copy = odp_packet_from_buffer(buf_copy);

			odp_packet_init(pkt_copy);
			odp_packet_set_len(pkt_copy, frame_len);
			odp_packet_set_l2_offset(pkt_copy, l2_offset);
			odp_packet_set_l3_offset(pkt_copy, l3_offset);

			memcpy(odp_buffer_addr(pkt_copy),
			       odp_buffer_addr(pkt), frame_len);

			swap_pkt_addrs(&pkt_copy, 1);

			buf_copy = odp_buffer_from_packet(pkt_copy);
			odp_queue_enq(outq_def, buf_copy);
		}

		/* Print packet counts every once in a while */
		if (odp_unlikely(pkt_cnt++ % 100000 == 0)) {
			printf("  [%02i] pkt_cnt:%lu\n", thr, pkt_cnt);
			fflush(NULL);
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

	num_workers = odp_sys_core_count();
	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

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
		odp_pktio_params_t params;
		netmap_params_t *nm_params = &params.nm_params;
		char inq_name[ODP_QUEUE_NAME_LEN];
		odp_queue_t inq_def;
		odp_queue_param_t qparam;
		odp_pktio_t pktio;
		int ret;
		int if_idx;

		if (i == 2)
			break;

		/* In netmap mode there will be one thread polling the physical
		 * interface and one polling the host stack for that interface
		 */
		if_idx = i < 2 * args->appl.if_count ? i / 2 : -1;

		if (if_idx == -1) {
			args->thread[i].pktio_dev = NULL;
			continue;
		}
		args->thread[i].pktio_dev = args->appl.ifs[if_idx].if_name;
		memset(nm_params, 0, sizeof(*nm_params));
		nm_params->type = ODP_PKTIO_TYPE_NETMAP;
		if (i % 2) {
			nm_params->netmap_mode = ODP_NETMAP_MODE_SW;
			nm_params->ringid = 0;
		} else {
			nm_params->netmap_mode = ODP_NETMAP_MODE_HW;
			nm_params->ringid = 0;
		}
		pktio = odp_pktio_open(args->thread[i].pktio_dev,
				       pool, &params);
		/* Open a packet IO instance for this thread */
		if (pktio == ODP_PKTIO_INVALID) {
			ODP_ERR("  [%02i] Err: pktio create\n", i);
			return -1;
		}

		args->thread[i].pktio = pktio;
		/* Save pktio id in the lookup table */
		args->pktio_tbl[pktio] = i;
		/*
		 * Create and set the default INPUT queue associated with the
		 * 'pktio' resource
		 */
		qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		qparam.sched.sync  = ODP_SCHED_SYNC_NONE;
		qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
		snprintf(inq_name, sizeof(inq_name), "%i-pktio_inq_def",
			 (int)pktio);
		inq_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

		inq_def = odp_queue_create(inq_name, ODP_QUEUE_TYPE_PKTIN,
					   &qparam);
		if (inq_def == ODP_QUEUE_INVALID) {
			ODP_ERR("  [%02i] Err: pktio q create\n", i);
			return -1;
		}

		ret = odp_pktio_inq_setdef(pktio, inq_def);
		if (ret != 0) {
			ODP_ERR("  [%02i] Err: default input-Q setup\n"
				, i);
			return -1;
		}

		printf("  [%02i] created pktio:%02i, queue mode\n"
		       "          default pktio%02i-INPUT queue:%u\n",
		       i, pktio, pktio, inq_def);

		/* Prepare for bridging: set bridge_q queue ids */
		if (i % 2) {
			odp_pktio_t pktio_bridge;
			odp_queue_t outq_def;

			pktio_bridge = args->thread[i-1].pktio;
			outq_def = odp_pktio_outq_getdef(pktio_bridge);
			args->thread[i].bridge_q = outq_def;

			pktio_bridge = args->thread[i].pktio;
			outq_def = odp_pktio_outq_getdef(pktio_bridge);
			args->thread[i-1].bridge_q = outq_def;
		}

		args->thread[i].pool = pool;
	}

	for (i = 0; i < num_workers; ++i) {
		if (i == 2)
			break;

		/*
		 * Create threads one-by-one instead of all-at-once,
		 * because each thread might get different arguments
		 */
		odp_linux_pthread_create(thread_tbl, 1, i, pktio_queue_thread,
					 &args->thread[i]);
	}

	/* Master thread waits for other threads to exit */
	odp_linux_pthread_join(thread_tbl, num_workers);

	printf("Exit\n\n");

	return 0;
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
		eth = (odp_ethhdr_t *)odp_packet_l2(pkt);

		if (odp_be_to_cpu_16(eth->type) == ODP_ETHTYPE_IPV4) {
			tmp_addr = eth->dst;
			eth->dst = eth->src;
			eth->src = tmp_addr;

			/* IPv4 */
			ip = (odp_ipv4hdr_t *)odp_packet_l3(pkt);

			ip_tmp_addr  = ip->src_addr;
			ip->src_addr = ip->dst_addr;
			ip->dst_addr = ip_tmp_addr;
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
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	while (1) {
		opt = getopt_long(argc, argv, "+i:h", longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
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
			appl_args->ifs =
			    calloc(appl_args->if_count, sizeof(if_info_t));

			/* store the if names (reset names string) */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
				strncpy(appl_args->ifs[i].if_name, token,
					sizeof(appl_args->ifs[i].if_name));
				appl_args->ifs[i].pktio_mode =
					PKTIO_MODE_NETMAP;
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
	       odp_sys_cache_line_size(), odp_sys_core_count()
	      );
	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->ifs[i].if_name);
	printf("\n"
	       "Mode:            ");
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
	       "  E.g. %s -i eth1,eth2,eth3\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -h, --help       Display help and exit.\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}

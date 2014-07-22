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
#include <helper/odp_linux.h>
#include <helper/odp_packet_helper.h>
#include <helper/odp_eth.h>
#include <helper/odp_ip.h>
#include <helper/odp_packet_helper.h>

#include <odp_pktio_netmap.h>

#define MAX_WORKERS            32
#define MAX_IFS                16
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
	odp_queue_t bridge_q;   /**< Connect the network stack with the NIC */
} pktio_info_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** pktio entries: one for SW ring and one for HW ring */
	pktio_info_t pktios[2 * MAX_IFS];
	/** TODO: find a way to associate private data with pktios */
	/** Lookup table: find pktio_info_t based on pktio id */
	pktio_info_t *pktio_lt[ODP_CONFIG_PKTIO_ENTRIES];
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
	odp_packet_t pkt;
	odp_buffer_t buf;
	unsigned long pkt_cnt = 0;
	unsigned long err_cnt = 0;

	(void)arg;

	thr = odp_thread_id();
	printf("Pktio thread [%02i] starts\n", thr);

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
		pktio_info_t *pktio_info;

		/* Use schedule to get buf from any input queue */
		buf = odp_schedule(NULL, ODP_SCHED_WAIT);

		pkt = odp_packet_from_buffer(buf);

		/* Drop packets with errors */
		if (odp_unlikely(drop_err_pkts(&pkt, 1) == 0)) {
			ODP_ERR("Drop frame - err_cnt:%lu\n", ++err_cnt);
			continue;
		}

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
		pktio_info = args->pktio_lt[pktio_tmp];

		/* Send back packets arrived on physical interface */
		if (pktio_info->netmap_mode == ODP_NETMAP_MODE_HW) {
			odp_packet_t pkt_copy;

			pkt_copy = odp_packet_alloc(pkt_pool);

			if (odp_packet_copy(pkt_copy, pkt) != 0) {
				ODP_ERR("Packet copy failed!\n");
				odp_packet_free(pkt_copy);
			} else {
				swap_pkt_addrs(&pkt_copy, 1);
				odp_queue_enq(outq_def,
					      odp_buffer_from_packet(pkt_copy));
			}
		}

		odp_queue_enq(pktio_info->bridge_q, buf);

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

	for (i = 0; i < 2 * args->appl.if_count; ++i) {
		odp_pktio_params_t params;
		netmap_params_t *nm_params = &params.nm_params;
		char inq_name[ODP_QUEUE_NAME_LEN];
		odp_queue_t inq_def;
		odp_queue_param_t qparam;
		odp_pktio_t pktio;
		int ret;

		/* Create a pktio polling the hardware rings and one that polls
		 * the software ring associated with the physical interface
		 */

		args->pktios[i].pktio_dev = args->appl.ifs[i / 2].if_name;
		memset(nm_params, 0, sizeof(*nm_params));
		nm_params->type = ODP_PKTIO_TYPE_NETMAP;
		if (i % 2) {
			nm_params->netmap_mode = ODP_NETMAP_MODE_SW;
			nm_params->ringid = 0;
		} else {
			nm_params->netmap_mode = ODP_NETMAP_MODE_HW;
			nm_params->ringid = 0;
		}
		pktio = odp_pktio_open(args->pktios[i].pktio_dev,
				       pool, &params);
		/* Open a packet IO instance for this thread */
		if (pktio == ODP_PKTIO_INVALID) {
			ODP_ERR("  [%02i] Err: pktio create\n", i);
			return -1;
		}

		args->pktios[i].pktio = pktio;
		args->pktios[i].pool = pool;
		args->pktios[i].netmap_mode = nm_params->netmap_mode;
		/* Save pktio_info in the lookup table */
		args->pktio_lt[pktio] = &args->pktios[i];
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

			pktio_bridge = args->pktios[i-1].pktio;
			outq_def = odp_pktio_outq_getdef(pktio_bridge);
			args->pktios[i].bridge_q = outq_def;

			pktio_bridge = args->pktios[i].pktio;
			outq_def = odp_pktio_outq_getdef(pktio_bridge);
			args->pktios[i-1].bridge_q = outq_def;
		}
	}

	memset(thread_tbl, 0, sizeof(thread_tbl));
	for (i = 0; i < num_workers; ++i) {

		/*
		 * Create threads one-by-one instead of all-at-once,
		 * because each thread might get different arguments
		 */
		odp_linux_pthread_create(thread_tbl, 1, i, pktio_queue_thread,
					 NULL);
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
			pkt_tbl[j-1] = pkt;
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

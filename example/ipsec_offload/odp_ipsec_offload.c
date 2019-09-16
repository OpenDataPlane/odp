/* Copyright (c) 2017-2018, Linaro Limited
 * Copyright (C) 2017 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_ipsec_offload.c  ODP basic packet IO cross connect with IPsec
 * test application
 */

#define _DEFAULT_SOURCE
/* enable strtok */
#define _POSIX_C_SOURCE 200112L
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdbool.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <odp_ipsec_offload_misc.h>
#include <odp_ipsec_offload_sa_db.h>
#include <odp_ipsec_offload_sp_db.h>
#include <odp_ipsec_offload_fwd_db.h>
#include <odp_ipsec_offload_cache.h>

/* maximum number of worker threads */
#define MAX_WORKERS     (ODP_THREAD_COUNT_MAX - 1)

#define MAX_COMPL_QUEUES 32

/**
 * Parsed command line application arguments
 */
typedef struct {
	unsigned int cpu_count;
	int flows;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *if_str;		/**< Storage for interface names */
	int queue_type;		/**< Queue synchronization type*/
} appl_args_t;

/**
 * Grouping of both parsed CL args and global application data
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	odp_pool_t pkt_pool;
	/** Atomic queue IPSEC completion events */
	odp_queue_t completionq[MAX_COMPL_QUEUES];
	/** Synchronize threads before packet processing begins */
	odp_barrier_t sync_barrier;
	int num_compl_queues;
	int num_workers;
} global_data_t;

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

/** Global pointer to args */
static global_data_t *global;

/**
 * Buffer pool for packet IO
 */
#define SHM_PKT_POOL_BUF_COUNT 1024
#define SHM_PKT_POOL_BUF_SIZE  4096
#define SHM_PKT_POOL_SIZE      (SHM_PKT_POOL_BUF_COUNT * SHM_PKT_POOL_BUF_SIZE)

/**
 * Packet processing result codes
 */
typedef enum {
	PKT_CONTINUE,    /**< No events posted, keep processing */
	PKT_POSTED,      /**< Event posted, stop processing */
	PKT_DROP,        /**< Reason to drop detected, stop processing */
	PKT_DONE         /**< Finished with packet, stop processing */
} pkt_disposition_e;

#define GET_THR_QUEUE_ID(x)		((odp_thread_id() - 1) % (x))

/**
 * Calculate hash value on given 2-tuple i.e. sip, dip
 *
 * @param ip_src	Source IP Address
 * @param ip_dst	Destination IP Address
 *
 * @return Resultant hash value
 */
static inline uint64_t calculate_flow_hash(uint32_t ip_src, uint32_t ip_dst)
{
	uint64_t hash = 0;

	ip_dst += JHASH_GOLDEN_RATIO;
	BJ3_MIX(ip_src, ip_dst, hash);
	return hash;
}

/**
 * IPsec pre argument processing initialization
 */
static
void ipsec_init_pre(void)
{
	/* Initialize our data bases */
	init_sp_db();
	init_sa_db();
	init_tun_db();
	init_ipsec_cache();
}

/**
 * IPsec post argument processing initialization
 *
 * Resolve SP DB with SA DB and create corresponding IPsec cache entries
 */
static
void ipsec_init_post(void)
{
	sp_db_entry_t *entry;
	int queue_id = 0;

	/* Attempt to find appropriate SA for each SP */
	for (entry = sp_db->list; NULL != entry; entry = entry->next) {
		sa_db_entry_t *cipher_sa = NULL;
		sa_db_entry_t *auth_sa = NULL;
		tun_db_entry_t *tun = NULL;

		queue_id %= global->num_workers;
		if (global->num_compl_queues < global->num_workers)
			global->num_compl_queues++;
		queue_id++;
		if (entry->esp) {
			cipher_sa = find_sa_db_entry(&entry->src_subnet,
						     &entry->dst_subnet, 1);
			tun = find_tun_db_entry(cipher_sa->src_ip,
						cipher_sa->dst_ip);
		}
		if (entry->ah) {
			auth_sa = find_sa_db_entry(&entry->src_subnet,
						   &entry->dst_subnet, 0);
			tun = find_tun_db_entry(auth_sa->src_ip,
						auth_sa->dst_ip);
		}

		if (cipher_sa && auth_sa) {
			odp_queue_t queue = global->completionq[queue_id - 1];

			if (create_ipsec_cache_entry(cipher_sa,
						     auth_sa,
						     tun,
						     entry->input,
						     queue)
			    ) {
				ODPH_ABORT("Error: IPSec cache entry failed\n");
			}
		} else {
			printf(" WARNING: SA not found for SP\n");
			dump_sp_db_entry(entry);
		}
	}
}

/**
 * Initialize interface
 *
 * Initialize ODP pktio and queues, query MAC address and update
 * forwarding database.
 *
 * @param intf		Interface name string
 * @param queue_type	Type of queue to configure.
 */
static void initialize_intf(char *intf, int queue_type)
{
	odp_pktio_t pktio;
	odp_pktout_queue_t pktout;
	int ret;
	uint8_t src_mac[ODPH_ETHADDR_LEN];
	odp_pktio_param_t pktio_param;
	odp_pktio_capability_t capa;
	odp_pktin_queue_param_t pktin_param;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	/*
	 * Open a packet IO instance for thread and get default output queue
	 */
	pktio = odp_pktio_open(intf, global->pkt_pool, &pktio_param);
	if (ODP_PKTIO_INVALID == pktio)
		ODPH_ABORT("Error: pktio create failed for %s\n", intf);

	odp_pktin_queue_param_init(&pktin_param);

	ret = odp_pktio_capability(pktio, &capa);
	if (ret != 0)
		ODPH_ABORT("Error: Unable to get pktio capability %s\n",
			   intf);

	pktin_param.queue_param.type = ODP_QUEUE_TYPE_SCHED;
	pktin_param.queue_param.sched.sync = queue_type;
	pktin_param.queue_param.sched.prio = ODP_SCHED_PRIO_DEFAULT;
	pktin_param.num_queues = capa.max_input_queues;

	if (pktin_param.num_queues > 1)
		pktin_param.hash_enable = 1;

	if (odp_pktin_queue_config(pktio, &pktin_param))
		ODPH_ABORT("Error: pktin config failed for %s\n", intf);

	if (odp_pktout_queue_config(pktio, NULL))
		ODPH_ABORT("Error: pktout config failed for %s\n", intf);

	if (odp_pktout_queue(pktio, &pktout, 1) != 1)
		ODPH_ABORT("Error: failed to get pktout queue for %s\n",
			   intf);

	ret = odp_pktio_start(pktio);
	if (ret)
		ODPH_ABORT("Error: unable to start %s\n", intf);

	/* Read the source MAC address for this interface */
	ret = odp_pktio_mac_addr(pktio, src_mac, sizeof(src_mac));
	if (ret < 0) {
		ODPH_ABORT("Error: failed during MAC address get for %s\n",
			   intf);
	}

	printf("Created pktio:%02" PRIu64 "\n", odp_pktio_to_u64(pktio));

	/* Resolve any routes using this interface for output */
	resolve_fwd_db(intf, pktout, src_mac);
}

/**
 * Packet Processing - Input verification
 *
 * @param pkt  Packet to inspect
 *
 * @return PKT_CONTINUE if good, supported packet else PKT_DROP
 */
static pkt_disposition_e do_input_verify(odp_packet_t pkt)
{
	if (odp_unlikely(odp_packet_has_error(pkt))) {
		odp_packet_free(pkt);
		return PKT_DROP;
	}

	if (!odp_packet_has_eth(pkt)) {
		odp_packet_free(pkt);
		return PKT_DROP;
	}

	if (!odp_packet_has_ipv4(pkt)) {
		odp_packet_free(pkt);
		return PKT_DROP;
	}

	return PKT_CONTINUE;
}

/**
 * Packet Processing - Route lookup in forwarding database
 *
 * @param pkt  Packet to route
 *
 * @return PKT_CONTINUE if route found else PKT_DROP
 */
static
pkt_disposition_e do_route_fwd_db(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	fwd_db_entry_t *fwd_entry;
	ipsec_cache_entry_t *ipsec_entry;
	odp_ipsec_out_param_t params;
	uint32_t	sip, dip;
	uint64_t	hash;
	flow_entry_t	*flow;

	if (ip->ttl > 1) {
		ip->ttl -= 1;
		if (ip->chksum >= odp_cpu_to_be_16(0xffff - 0x100))
			ip->chksum += odp_cpu_to_be_16(0x100) + 1;
		else
			ip->chksum += odp_cpu_to_be_16(0x100);
	} else {
		odp_packet_free(pkt);
		return PKT_DROP;
	}

	sip = odp_be_to_cpu_32(ip->src_addr);
	dip = odp_be_to_cpu_32(ip->dst_addr);

	hash = calculate_flow_hash(sip, dip);

	flow = route_flow_lookup_in_bucket(sip, dip,
					   &flow_table[hash &
					   (bucket_count - 1)]);
	if (!flow) {
		/*Check into Routing table*/
		fwd_entry = find_fwd_db_entry(dip);
		if (!fwd_entry) {
			ODPH_DBG("No flow match found. Packet is dropped.\n");
			odp_packet_free(pkt);
			return PKT_DROP;
		}

		/*Entry found. Updated in Flow table first.*/
		flow = calloc(1, sizeof(flow_entry_t));
		if (!flow) {
			ODPH_ABORT("Failure to allocate memory");
			return PKT_DROP;
		}
		flow->l3_src = sip;
		flow->l3_dst = dip;
		flow->out_port.pktout = fwd_entry->pktout;
		memcpy(flow->out_port.addr.addr,
		       fwd_entry->src_mac,
		       ODPH_ETHADDR_LEN);
		memcpy(flow->out_port.next_hop_addr.addr,
		       fwd_entry->dst_mac,
		       ODPH_ETHADDR_LEN);
		ipsec_entry = find_ipsec_cache_entry_out(sip, dip);
		if (ipsec_entry)
			flow->out_port.sa = ipsec_entry->sa;
		else
			flow->out_port.sa = ODP_IPSEC_SA_INVALID;
		flow->next = NULL;
		/*Insert new flow into flow cache table*/
		route_flow_insert_in_bucket(flow, &flow_table[hash &
					    (bucket_count - 1)]);
	}

	odp_packet_user_ptr_set(pkt, &flow->out_port);
	if (flow->out_port.sa == ODP_IPSEC_SA_INVALID)
		return PKT_CONTINUE;

	/* Initialize parameters block */
	params.sa = &flow->out_port.sa;
	params.opt = NULL;
	params.num_sa = 1;
	params.num_opt = 1;

	/* Issue ipsec request */
	if (odp_unlikely(odp_ipsec_out_enq(&pkt, 1, &params) < 0)) {
		ODPH_DBG("Unable to out enqueue\n");
		odp_packet_free(pkt);
		return PKT_DROP;
	}
	return PKT_POSTED;
}

/**
 * Packet Processing - Input IPsec packet classification
 *
 * Verify the received packet has IPsec headers,
 * if so issue ipsec request else skip.
 *
 * @param pkt   Packet to classify
 *
 * @return PKT_CONTINUE if done else PKT_POSTED
 */
static
pkt_disposition_e do_ipsec_in_classify(odp_packet_t pkt)
{
	odp_ipsec_in_param_t params;

	if (!odp_packet_has_ipsec(pkt))
		return PKT_CONTINUE;

	/* Initialize parameters block */
	params.num_sa = 0;
	params.sa = NULL;

	/* Issue ipsec request */
	if (odp_unlikely(odp_ipsec_in_enq(&pkt, 1, &params) < 0)) {
		ODPH_DBG("Unable to in enqueue\n");
		odp_packet_free(pkt);
		return PKT_DROP;
	}
	return PKT_POSTED;
}

/**
 * Packet IO worker thread
 *
 * Loop calling odp_schedule to obtain packet from the two sources,
 * and continue processing the packet.
 *
 *  - Input interfaces (i.e. new work)
 *  - Per packet ipsec API completion queue
 *
 * @param arg  Required by "odph_linux_pthread_create", unused
 *
 * @return NULL (should never return)
 */
static
int pktio_thread(void *arg ODP_UNUSED)
{
	int thr = odp_thread_id();
	odp_packet_t pkt;
	odp_pktout_queue_t out_queue;
	ipsec_out_entry_t	*out_port;
	odp_event_t ev = ODP_EVENT_INVALID;

	printf("Pktio thread [%02i] starts\n", thr);
	odp_barrier_wait(&global->sync_barrier);

	/* Loop packets */
	for (;;) {
		pkt_disposition_e rc;
		odp_event_subtype_t subtype;

		ev = odp_schedule(NULL, ODP_SCHED_WAIT);
		/* Use schedule to get event from any input queue */
		/* Determine new work versus IPsec result */
		if (ODP_EVENT_PACKET == odp_event_types(ev, &subtype)) {
			pkt = odp_packet_from_event(ev);

			if (ODP_EVENT_PACKET_IPSEC == subtype) {
				odp_ipsec_packet_result_t res;

				if (odp_unlikely(odp_ipsec_result(&res,
								  pkt) < 0)) {
					ODPH_DBG("Error Event\n");
					odp_event_free((odp_event_t)ev);
					continue;
				}

				if (odp_unlikely(res.status.error.all)) {
					odp_packet_free(pkt);
					continue;
				}
			} else {
				rc = do_input_verify(pkt);
				if (odp_unlikely(rc))
					continue;

				rc = do_ipsec_in_classify(pkt);
				if (rc)
					continue;
			}

			rc = do_route_fwd_db(pkt);
			if (rc)
				continue;

			out_port = odp_packet_user_ptr(pkt);
			out_queue = out_port->pktout;

			if (odp_unlikely(odp_pktout_send(out_queue,
							 &pkt, 1) < 0))
				odp_packet_free(pkt);

		} else {
			ODPH_DBG("Invalid Event\n");
			odp_event_free(ev);
			continue;
		}
	}

	/* unreachable */
	return 0;
}

/**
 * ODP ipsec proto example main function
 */
int
main(int argc, char *argv[])
{
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	int i;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	odp_queue_param_t qparam;
	odp_instance_t instance;
	odph_odpthread_params_t thr_params;
	odp_ipsec_config_t config;
	odp_ipsec_capability_t capa;

	/*Validate if user has passed only help option*/
	if (argc == 2) {
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		}
	}

	/* Initialize ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL))
		ODPH_ABORT("Error: ODP global init failed.\n");
	/* Initialize this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL))
		ODPH_ABORT("Error: ODP local init failed.\n");
	/* Reserve memory for arguments from shared memory */
	shm = odp_shm_reserve("shm_args", sizeof(global_data_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID)
		ODPH_ABORT("Error: shared mem reserve failed.\n");

	global = odp_shm_addr(shm);

	if (NULL == global)
		ODPH_ABORT("Error: shared mem alloc failed.\n");
	memset(global, 0, sizeof(global_data_t));

	/* Must init our databases before parsing args */
	ipsec_init_pre();
	init_fwd_db();

	/* Parse and store the application arguments */
	parse_args(argc, argv, &global->appl);

	/*Initialize route table for user given parameter*/
	init_routing_table();

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &global->appl);

	if (odp_ipsec_capability(&capa))
		ODPH_ABORT("Error: Capability not configured.\n");

	odp_ipsec_config_init(&config);

	if (capa.op_mode_async && (capa.op_mode_async >= capa.op_mode_sync)) {
		config.inbound_mode = ODP_IPSEC_OP_MODE_ASYNC;
		config.outbound_mode = ODP_IPSEC_OP_MODE_ASYNC;
	} else {
		ODPH_ABORT("Error: Sync mode not supported.\n");
	}

	if (odp_ipsec_config(&config))
		ODPH_ABORT("Error: IPSec not configured.\n");

	global->num_workers = MAX_WORKERS;
	if (global->appl.cpu_count && global->appl.cpu_count < MAX_WORKERS)
		global->num_workers = global->appl.cpu_count;

	/*
	 * By default CPU #0 runs Linux kernel background tasks.
	 * Start mapping thread from CPU #1
	 */
	global->num_workers = odp_cpumask_default_worker(&cpumask,
							 global->num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	/*
	 * Create completion queues
	 */
	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio  = ODP_SCHED_PRIO_HIGHEST;
	qparam.sched.sync  = global->appl.queue_type;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	for (i = 0; i < global->num_workers; i++) {
		global->completionq[i] = odp_queue_create("completion",
							  &qparam);
		if (ODP_QUEUE_INVALID == global->completionq[i])
			ODPH_ABORT("Error: completion queue creation failed\n");
	}
	printf("num worker threads: %i\n", global->num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/* Create a barrier to synchronize thread startup */
	odp_barrier_init(&global->sync_barrier, global->num_workers);

	/* Create packet buffer pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_BUF_COUNT;
	params.type        = ODP_POOL_PACKET;

	global->pkt_pool = odp_pool_create("packet_pool", &params);

	if (ODP_POOL_INVALID == global->pkt_pool)
		ODPH_ABORT("Error: packet pool create failed.\n");

	ipsec_init_post();

	/* Configure scheduler */
	odp_schedule_config(NULL);

	/* Initialize interfaces (which resolves FWD DB entries */
	for (i = 0; i < global->appl.if_count; i++)
		initialize_intf(global->appl.if_names[i],
				global->appl.queue_type);

	printf("  Configured queues SYNC type: [%s]\n",
	       (global->appl.queue_type == 0) ?
	       "PARALLEL" :
	       (global->appl.queue_type == 1) ?
	       "ATOMIC" : "ORDERED");
	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.start    = pktio_thread;
	thr_params.arg      = NULL;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;

	/* Create and initialize worker threads */
	odph_odpthreads_create(thread_tbl, &cpumask,
			       &thr_params);
	odph_odpthreads_join(thread_tbl);

	/* Stop and close used pktio devices */
	for (i = 0; i < global->appl.if_count; i++) {
		odp_pktio_t pktio = odp_pktio_lookup(global->appl.if_names[i]);

		if (pktio == ODP_PKTIO_INVALID)
			continue;

		if (odp_pktio_stop(pktio) || odp_pktio_close(pktio)) {
			ODPH_ERR("Error: failed to close pktio %s\n",
				 global->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	free(global->appl.if_names);
	free(global->appl.if_str);

	if (odp_shm_free(shm)) {
		ODPH_ERR("Error: shm free global data\n");
		exit(EXIT_FAILURE);
	}

	printf("Exit\n\n");
	return 0;
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
	int rc = 0;
	int i;

	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"route", required_argument, NULL, 'r'},	/* return 'r' */
		{"policy", required_argument, NULL, 'p'},	/* return 'p' */
		{"ah", required_argument, NULL, 'a'},		/* return 'a' */
		{"esp", required_argument, NULL, 'e'},		/* return 'e' */
		{"tunnel", required_argument, NULL, 't'},       /* return 't' */
		{"flows", no_argument, NULL, 'f'},		/* return 'f' */
		{"queue type", required_argument, NULL, 'q'},	/* return 'q' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	appl_args->cpu_count = 1; /* use one worker by default */
	appl_args->flows = 1;
	appl_args->queue_type = ODP_SCHED_SYNC_ATOMIC;

	while (!rc) {
		opt = getopt_long(argc, argv, "+c:i:h:r:p:a:e:t:s:q:f:",
				  longopts, &long_index);
		if (opt < 0)
			break;	/* No more options */
		switch (opt) {
		case 'f':
			appl_args->flows = atoi(optarg);
			if (appl_args->flows > 256) {
				printf("Maximum acceptable value for -f is 256\n");
				rc = -1;
			}
			if (optind != 3) {
				printf("-f must be the 1st argument of the command\n");
				rc = -1;
			}
			ODPH_DBG("Bucket count = %d\n", bucket_count);
			break;
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 'i':
			/* parse packet-io interface names */
			len = strlen(optarg);
			if (0 == len) {
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
			     token;
			     token = strtok(NULL, ","), i++)
				;
			appl_args->if_count = i;
			if (!appl_args->if_count) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			/* Allocate storage for the if names */
			appl_args->if_names =
				calloc(appl_args->if_count, sizeof(char *));
			if (!appl_args->if_names)
				ODPH_ABORT("Memory allocation failure\n");
			/* Store the if names (reset names string) */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token; token = strtok(NULL, ","), i++) {
				appl_args->if_names[i] = token;
			}
			break;
		case 'r':
			rc = create_fwd_db_entry(optarg, appl_args->if_names,
						 appl_args->if_count,
						 appl_args->flows);
			break;
		case 'p':
			rc = create_sp_db_entry(optarg, appl_args->flows);
			break;
		case 'a':
			rc = create_sa_db_entry(optarg, FALSE,
						appl_args->flows);
			break;
		case 'e':
			rc = create_sa_db_entry(optarg, TRUE, appl_args->flows);
			break;
		case 't':
			rc = create_tun_db_entry(optarg, appl_args->flows);
			break;
		case 'q':
			i = atoi(optarg);
			if (i > ODP_SCHED_SYNC_ORDERED ||
			    i < ODP_SCHED_SYNC_PARALLEL) {
				printf("Invalid queue type: setting default to atomic");
				break;
			}
			appl_args->queue_type = i;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	if (rc) {
		printf("ERROR: failed parsing -%c option\n", opt);
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (0 == appl_args->if_count) {
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
	       "CPU freq (hz):   %" PRIu64 "\n"
	       "Cache line size: %i\n"
	       "CPU count:       %i\n"
	       "\n",
	       odp_version_api_str(), odp_cpu_model_str(), odp_cpu_hz_max(),
	       odp_sys_cache_line_size(), odp_cpu_count());
	printf("Running ODP application: \"%s\"\n"
	       "------------------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n");
	dump_fwd_db();
	dump_sp_db();
	dump_sa_db();
	dump_tun_db();
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
	       " -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "Routing / IPSec OPTIONS:\n"
	       " -r, --route SubNet:Intf:NextHopMAC\n"
	       " -p, --policy SrcSubNet:DstSubNet:(in|out):(ah|esp|both)\n"
	       " -e, --esp SrcIP:DstIP:(3des|null):SPI:Key192\n"
	       " -a, --ah SrcIP:DstIP:(md5|null):SPI:Key128\n"
	       " -t, --tun SrcIP:DstIP:TunSrcIP:TunDstIP\n"
	       "\n"
	       "  Where: NextHopMAC is raw hex/dot notation, i.e. 03.BA.44.9A.CE.02\n"
	       "         IP is decimal/dot notation, i.e. 192.168.1.1\n"
	       "         SubNet is decimal/dot/slash notation, i.e 192.168.0.0/16\n"
	       "         SPI is raw hex, 32 bits\n"
	       "         KeyXXX is raw hex, XXX bits long\n"
	       "\n"
	       "  Examples:\n"
	       "     -r 192.168.222.0/24:p8p1:08.00.27.F5.8B.DB\n"
	       "     -p 192.168.111.0/24:192.168.222.0/24:out:esp\n"
	       "     -e 192.168.111.2:192.168.222.2:3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224\n"
	       "     -a 192.168.111.2:192.168.222.2:md5:201:a731649644c5dee92cbd9c2e7e188ee6\n"
	       "     -t 192.168.111.2:192.168.222.2:192.168.150.1:192.168.150.2\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -f, --flows <number> routes count.\n"
	       "  -c, --count <number> CPU count, 0=all available, default=1\n"
	       "  -q		specify the queue type\n"
	       "		0:	ODP_SCHED_SYNC_PARALLEL\n"
	       "		1:	ODP_SCHED_SYNC_ATOMIC\n"
	       "		2:	ODP_SCHED_SYNC_ORDERED\n"
	       "			default is ODP_SCHED_SYNC_ATOMIC\n"
	       "  -h, --help           Display help and exit.\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
		);
}

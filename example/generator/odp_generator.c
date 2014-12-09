/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_generator.c ODP loopback demo application
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/time.h>

#include <example_debug.h>

#include <odp.h>

#include <odph_linux.h>
#include <odph_packet.h>
#include <odph_eth.h>
#include <odph_ip.h>
#include <odph_udp.h>
#include <odph_icmp.h>

#define MAX_WORKERS            32		/**< max number of works */
#define SHM_PKT_POOL_SIZE      (512*2048)	/**< pkt pool size */
#define SHM_PKT_POOL_BUF_SIZE  1856		/**< pkt pool buf size */

#define APPL_MODE_UDP    0			/**< UDP mode */
#define APPL_MODE_PING   1			/**< ping mode */
#define APPL_MODE_RCV    2			/**< receive mode */

/** print appl mode */
#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))
/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;		/**< system core count */
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
	odph_ethaddr_t srcmac;	/**< src mac addr */
	odph_ethaddr_t dstmac;	/**< dest mac addr */
	unsigned int srcip;	/**< src ip addr */
	unsigned int dstip;	/**< dest ip addr */
	int mode;		/**< work mode */
	int number;		/**< packets number to be sent */
	int payload;		/**< data len */
	int timeout;		/**< wait time */
	int interval;		/**< wait interval ms between sending
				     each packet */
} appl_args_t;

/**
 * counters
*/
static struct {
	odp_atomic_u64_t seq;	/**< ip seq to be send */
	odp_atomic_u64_t ip;	/**< ip packets */
	odp_atomic_u64_t udp;	/**< udp packets */
	odp_atomic_u64_t icmp;	/**< icmp packets */
} counters;

/** * Thread specific arguments
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
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);
static int scan_ip(char *buf, unsigned int *paddr);
static int scan_mac(char *in, odph_ethaddr_t *des);
static void tv_sub(struct timeval *recvtime, struct timeval *sendtime);

/**
 * Scan ip
 * Parse ip address.
 *
 * @param buf ip address string xxx.xxx.xxx.xx
 * @param paddr ip address for odp_packet
 * @return 1 success, 0 failed
*/
static int scan_ip(char *buf, unsigned int *paddr)
{
	int part1, part2, part3, part4;
	char tail = 0;
	int field;

	if (buf == NULL)
		return 0;

	field = sscanf(buf, "%d . %d . %d . %d %c",
		       &part1, &part2, &part3, &part4, &tail);

	if (field < 4 || field > 5) {
		printf("expect 4 field,get %d/n", field);
		return 0;
	}

	if (tail != 0) {
		printf("ip address mixed with non number/n");
		return 0;
	}

	if ((part1 >= 0 && part1 <= 255) && (part2 >= 0 && part2 <= 255) &&
	    (part3 >= 0 && part3 <= 255) && (part4 >= 0 && part4 <= 255)) {
		if (paddr)
			*paddr = part1 << 24 | part2 << 16 | part3 << 8 | part4;
		return 1;
	} else {
		printf("not good ip %d:%d:%d:%d/n", part1, part2, part3, part4);
	}

	return 0;
}

/**
 * Scan mac addr form string
 *
 * @param  in mac string
 * @param  des mac for odp_packet
 * @return 1 success, 0 failed
 */
static int scan_mac(char *in, odph_ethaddr_t *des)
{
	int field;
	int i;
	unsigned int mac[7];

	field = sscanf(in, "%2x:%2x:%2x:%2x:%2x:%2x",
		       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

	for (i = 0; i < 6; i++)
		des->addr[i] = mac[i];

	if (field != 6)
		return 0;
	return 1;
}

/**
 * set up an udp packet
 *
 * @param obuf packet buffer
*/
static void pack_udp_pkt(odp_buffer_t obuf)
{
	char *buf;
	int max;
	odp_packet_t pkt;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	unsigned short seq;

	buf = odp_buffer_addr(obuf);
	if (buf == NULL)
		return;
	max = odp_buffer_size(obuf);
	if (max <= 0)
		return;

	pkt = odp_packet_from_buffer(obuf);
	/* ether */
	odp_packet_set_l2_offset(pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy((char *)eth->src.addr, args->appl.srcmac.addr, ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, args->appl.dstmac.addr, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);
	/* ip */
	odp_packet_set_l3_offset(pkt, ODPH_ETHHDR_LEN);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(args->appl.dstip);
	ip->src_addr = odp_cpu_to_be_32(args->appl.srcip);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(args->appl.payload + ODPH_UDPHDR_LEN +
				       ODPH_IPV4HDR_LEN);
	ip->proto = ODPH_IPPROTO_UDP;
	seq = odp_atomic_fetch_add_u64(&counters.seq, 1) % 0xFFFF;
	ip->id = odp_cpu_to_be_16(seq);
	ip->chksum = 0;
	odph_ipv4_csum_update(pkt);
	/* udp */
	odp_packet_set_l4_offset(pkt, ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp = (odph_udphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp->src_port = 0;
	udp->dst_port = 0;
	udp->length = odp_cpu_to_be_16(args->appl.payload + ODPH_UDPHDR_LEN);
	udp->chksum = 0;
	udp->chksum = odp_cpu_to_be_16(odph_ipv4_udp_chksum(pkt));
	odp_packet_set_len(pkt, args->appl.payload + ODPH_UDPHDR_LEN +
			   ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);
}

/**
 * Set up an icmp packet
 *
 * @param obuf packet buffer
*/
static void pack_icmp_pkt(odp_buffer_t obuf)
{
	char *buf;
	int max;
	odp_packet_t pkt;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_icmphdr_t *icmp;
	struct timeval tval;
	uint8_t *tval_d;
	unsigned short seq;

	buf = odp_buffer_addr(obuf);
	if (buf == NULL)
		return;
	max = odp_buffer_size(obuf);
	if (max <= 0)
		return;

	args->appl.payload = 56;
	pkt = odp_packet_from_buffer(obuf);
	/* ether */
	odp_packet_set_l2_offset(pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy((char *)eth->src.addr, args->appl.srcmac.addr, ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, args->appl.dstmac.addr, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);
	/* ip */
	odp_packet_set_l3_offset(pkt, ODPH_ETHHDR_LEN);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(args->appl.dstip);
	ip->src_addr = odp_cpu_to_be_32(args->appl.srcip);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(args->appl.payload + ODPH_ICMPHDR_LEN +
				       ODPH_IPV4HDR_LEN);
	ip->proto = ODPH_IPPROTO_ICMP;
	seq = odp_atomic_fetch_add_u64(&counters.seq, 1) % 0xffff;
	ip->id = odp_cpu_to_be_16(seq);
	ip->chksum = 0;
	odph_ipv4_csum_update(pkt);
	/* icmp */
	icmp = (odph_icmphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = 0;
	icmp->un.echo.sequence = ip->id;
	tval_d = (uint8_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN +
				  ODPH_ICMPHDR_LEN);
	/* TODO This should be changed to use an
	 * ODP timer API once one exists. */
	gettimeofday(&tval, NULL);
	memcpy(tval_d, &tval, sizeof(struct timeval));
	icmp->chksum = 0;
	icmp->chksum = odp_chksum(icmp, args->appl.payload +
				  ODPH_ICMPHDR_LEN);

	odp_packet_set_len(pkt, args->appl.payload + ODPH_ICMPHDR_LEN +
			   ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);
}

/**
 * Packet IO loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */

static void *gen_send_thread(void *arg)
{
	int thr;
	odp_pktio_t pktio;
	thread_args_t *thr_args;
	odp_queue_t outq_def;

	odp_buffer_t buf;

	thr = odp_thread_id();
	thr_args = arg;

	/* Open a packet IO instance for this thread */
	pktio = odp_pktio_open(thr_args->pktio_dev, thr_args->pool);
	if (pktio == ODP_PKTIO_INVALID) {
		EXAMPLE_ERR("  [%02i] Error: pktio create failed\n", thr);
		return NULL;
	}

	outq_def = odp_pktio_outq_getdef(pktio);
	if (outq_def == ODP_QUEUE_INVALID) {
		EXAMPLE_ERR("  [%02i] Error: def output-Q query\n", thr);
		return NULL;
	}

	printf("  [%02i] created mode: SEND\n", thr);
	for (;;) {
		int err;
		buf = odp_buffer_alloc(thr_args->pool);
		if (!odp_buffer_is_valid(buf)) {
			EXAMPLE_ERR("  [%2i] alloc_single failed\n", thr);
			return NULL;
		}

		if (args->appl.mode == APPL_MODE_UDP)
			pack_udp_pkt(buf);
		else if (args->appl.mode == APPL_MODE_PING)
			pack_icmp_pkt(buf);

		err = odp_queue_enq(outq_def, buf);
		if (err != 0) {
			EXAMPLE_ERR("  [%02i] send pkt err!\n", thr);
			return NULL;
		}

		if (args->appl.interval != 0) {
			printf("  [%02i] send pkt no:%ju seq %ju\n",
			       thr,
			       odp_atomic_load_u64(&counters.seq),
			       odp_atomic_load_u64(&counters.seq)%0xffff);
			/* TODO use odp timer */
			usleep(args->appl.interval * 1000);
		}
		if (args->appl.number != -1 &&
		    odp_atomic_load_u64(&counters.seq)
		    >= (unsigned int)args->appl.number) {
			break;
		}
	}

	/* receive number of reply pks until timeout */
	if (args->appl.mode == APPL_MODE_PING && args->appl.number > 0) {
		while (args->appl.timeout >= 0) {
			if (odp_atomic_load_u64(&counters.icmp) >=
			    (unsigned int)args->appl.number)
				break;
			/* TODO use odp timer */
			sleep(1);
			args->appl.timeout--;
		}
	}

	/* print info */
	if (args->appl.mode == APPL_MODE_UDP) {
		printf("  [%02i] total send: %ju\n",
		       thr, odp_atomic_load_u64(&counters.seq));
	} else if (args->appl.mode == APPL_MODE_PING) {
		printf("  [%02i] total send: %ju total receive: %ju\n",
		       thr, odp_atomic_load_u64(&counters.seq),
		       odp_atomic_load_u64(&counters.icmp));
	}
	return arg;
}

/**
 * Print odp packets
 *
 * @param  thr worker id
 * @param  pkt_tbl packets to be print
 * @param  len packet number
 */
static void print_pkts(int thr, odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	char *buf;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	odph_icmphdr_t *icmp;
	struct timeval tvrecv;
	struct timeval tvsend;
	double rtt;
	unsigned i;
	size_t offset;
	char msg[1024];
	int rlen;
	for (i = 0; i < len; ++i) {
		pkt = pkt_tbl[i];
		rlen = 0;

		/* only ip pkts */
		if (!odp_packet_has_ipv4(pkt))
			continue;

		odp_atomic_inc_u64(&counters.ip);
		rlen += sprintf(msg, "receive Packet proto:IP ");
		buf = odp_buffer_addr(odp_packet_to_buffer(pkt));
		ip = (odph_ipv4hdr_t *)(buf + odp_packet_l3_offset(pkt));
		rlen += sprintf(msg + rlen, "id %d ",
				odp_be_to_cpu_16(ip->id));
		offset = odp_packet_l4_offset(pkt);

		/* udp */
		if (ip->proto == ODPH_IPPROTO_UDP) {
			odp_atomic_inc_u64(&counters.udp);
			udp = (odph_udphdr_t *)(buf + offset);
			rlen += sprintf(msg + rlen, "UDP payload %d ",
					odp_be_to_cpu_16(udp->length) -
					ODPH_UDPHDR_LEN);
		}

		/* icmp */
		if (ip->proto == ODPH_IPPROTO_ICMP) {
			icmp = (odph_icmphdr_t *)(buf + offset);
			/* echo reply */
			if (icmp->type == ICMP_ECHOREPLY) {
				odp_atomic_inc_u64(&counters.icmp);
				memcpy(&tvsend, buf + offset + ODPH_ICMPHDR_LEN,
				       sizeof(struct timeval));
				/* TODO This should be changed to use an
				 * ODP timer API once one exists. */
				gettimeofday(&tvrecv, NULL);
				tv_sub(&tvrecv, &tvsend);
				rtt = tvrecv.tv_sec*1000 + tvrecv.tv_usec/1000;
				rlen += sprintf(msg + rlen,
					"ICMP Echo Reply seq %d time %.1f ",
					odp_be_to_cpu_16(icmp->un.echo.sequence)
					, rtt);
			} else if (icmp->type == ICMP_ECHO) {
				rlen += sprintf(msg + rlen,
						"Icmp Echo Request");
			}
		}

		msg[rlen] = '\0';
		printf("  [%02i] %s\n", thr, msg);
	}
}

/**
 * Main receive funtion
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *gen_recv_thread(void *arg)
{
	int thr;
	odp_pktio_t pktio;
	thread_args_t *thr_args;
	odp_queue_t inq_def;
	char inq_name[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;

	odp_packet_t pkt;
	odp_buffer_t buf;

	thr = odp_thread_id();
	thr_args = arg;

	/* Open a packet IO instance for this thread */
	pktio = odp_pktio_open(thr_args->pktio_dev, thr_args->pool);
	if (pktio == ODP_PKTIO_INVALID) {
		EXAMPLE_ERR("  [%02i] Error: pktio create failed\n", thr);
		return NULL;
	}

	int ret;
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
	snprintf(inq_name, sizeof(inq_name), "%i-pktio_inq_def", (int)pktio);
	inq_name[ODP_QUEUE_NAME_LEN - 1] = '\0';
	inq_def = odp_queue_create(inq_name, ODP_QUEUE_TYPE_PKTIN, &qparam);
	if (inq_def == ODP_QUEUE_INVALID) {
		EXAMPLE_ERR("  [%02i] Error: pktio queue creation failed\n",
			    thr);
		return NULL;
	}

	ret = odp_pktio_inq_setdef(pktio, inq_def);
	if (ret != 0) {
		EXAMPLE_ERR("  [%02i] Error: default input-Q setup\n", thr);
		return NULL;
	}

	printf("  [%02i] created mode: RECEIVE\n", thr);
	for (;;) {
		/* Use schedule to get buf from any input queue */
		buf = odp_schedule(NULL, ODP_SCHED_WAIT);

		pkt = odp_packet_from_buffer(buf);
		/* Drop packets with errors */
		if (odp_unlikely(odp_packet_error(pkt))) {
			odph_packet_free(pkt);
			continue;
		}

		print_pkts(thr, &pkt, 1);

		odph_packet_free(pkt);
	}

	return arg;
}
/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	odp_buffer_pool_t pool;
	int num_workers;
	void *pool_base;
	int i;
	int first_core;
	int core_count;
	odp_shm_t shm;

	/* Init ODP before calling anything else */
	if (odp_init_global(NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local()) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* init counters */
	odp_atomic_init_u64(&counters.seq, 0);
	odp_atomic_init_u64(&counters.ip, 0);
	odp_atomic_init_u64(&counters.udp, 0);
	odp_atomic_init_u64(&counters.icmp, 0);

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);
	args = odp_shm_addr(shm);

	if (args == NULL) {
		EXAMPLE_ERR("Error: shared mem alloc failed.\n");
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

	/* ping mode need two worker */
	if (args->appl.mode == APPL_MODE_PING)
		num_workers = 2;

	printf("Num worker threads: %i\n", num_workers);

	/*
	 * By default core #0 runs Linux kernel background tasks.
	 * Start mapping thread from core #1
	 */
	first_core = 1;

	if (core_count == 1)
		first_core = 0;

	printf("First core:         %i\n\n", first_core);

	/* Create packet pool */
	shm = odp_shm_reserve("shm_packet_pool",
			      SHM_PKT_POOL_SIZE, ODP_CACHE_LINE_SIZE, 0);
	pool_base = odp_shm_addr(shm);

	if (pool_base == NULL) {
		EXAMPLE_ERR("Error: packet pool mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	pool = odp_buffer_pool_create("packet_pool", pool_base,
				      SHM_PKT_POOL_SIZE,
				      SHM_PKT_POOL_BUF_SIZE,
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_PACKET);
	if (pool == ODP_BUFFER_POOL_INVALID) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_buffer_pool_print(pool);

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));

	if (args->appl.mode == APPL_MODE_PING) {
		args->thread[1].pktio_dev = args->appl.if_names[0];
		args->thread[1].pool = pool;
		args->thread[1].mode = args->appl.mode;
		odph_linux_pthread_create(&thread_tbl[1], 1, 0,
					  gen_recv_thread, &args->thread[1]);

		args->thread[0].pktio_dev = args->appl.if_names[0];
		args->thread[0].pool = pool;
		args->thread[0].mode = args->appl.mode;
		odph_linux_pthread_create(&thread_tbl[0], 1, 0,
					  gen_send_thread, &args->thread[0]);

		/* only wait send thread to join */
		num_workers = 1;
	} else {
		for (i = 0; i < num_workers; ++i) {
			void *(*thr_run_func) (void *);
			int core;
			int if_idx;

			core = (first_core + i) % core_count;

			if_idx = i % args->appl.if_count;

			args->thread[i].pktio_dev = args->appl.if_names[if_idx];
			args->thread[i].pool = pool;
			args->thread[i].mode = args->appl.mode;

			if (args->appl.mode == APPL_MODE_UDP) {
				thr_run_func = gen_send_thread;
			} else if (args->appl.mode == APPL_MODE_RCV) {
				thr_run_func = gen_recv_thread;
			} else {
				EXAMPLE_ERR("ERR MODE\n");
				exit(EXIT_FAILURE);
			}
			/*
			 * Create threads one-by-one instead of all-at-once,
			 * because each thread might get different arguments.
			 * Calls odp_thread_create(cpu) for each thread
			 */
			odph_linux_pthread_create(&thread_tbl[i], 1,
						  core, thr_run_func,
						  &args->thread[i]);
		}
	}

	/* Master thread waits for other threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);
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
	char *names, *str, *token, *save;
	size_t len;
	int i;
	static struct option longopts[] = {
		{"interface", required_argument, NULL, 'I'},
		{"workers", required_argument, NULL, 'w'},
		{"srcmac", required_argument, NULL, 'a'},
		{"dstmac", required_argument, NULL, 'b'},
		{"srcip", required_argument, NULL, 'c'},
		{"dstip", required_argument, NULL, 'd'},
		{"packetsize", required_argument, NULL, 's'},
		{"mode", required_argument, NULL, 'm'},
		{"count", required_argument, NULL, 'n'},
		{"timeout", required_argument, NULL, 't'},
		{"interval", required_argument, NULL, 'i'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	appl_args->mode = -1; /* Invalid, must be changed by parsing */
	appl_args->number = -1;
	appl_args->payload = 56;
	appl_args->timeout = -1;

	while (1) {
		opt = getopt_long(argc, argv, "+I:a:b:c:d:s:i:m:n:t:w:h",
					longopts, &long_index);
		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'w':
			appl_args->core_count = atoi(optarg);
			break;
		/* parse packet-io interface names */
		case 'I':
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
			if (optarg[0] == 'u') {
				appl_args->mode = APPL_MODE_UDP;
			} else if (optarg[0] == 'p') {
				appl_args->mode = APPL_MODE_PING;
			} else if (optarg[0] == 'r') {
				appl_args->mode = APPL_MODE_RCV;
			} else {
				EXAMPLE_ERR("wrong mode!\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'a':
			if (scan_mac(optarg, &appl_args->srcmac) != 1) {
				EXAMPLE_ERR("wrong src mac:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'b':
			if (scan_mac(optarg, &appl_args->dstmac) != 1) {
				EXAMPLE_ERR("wrong dst mac:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'c':
			if (scan_ip(optarg, &appl_args->srcip) != 1) {
				EXAMPLE_ERR("wrong src ip:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'd':
			if (scan_ip(optarg, &appl_args->dstip) != 1) {
				EXAMPLE_ERR("wrong dst ip:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 's':
			appl_args->payload = atoi(optarg);
			break;

		case 'n':
			appl_args->number = atoi(optarg);
			break;

		case 't':
			appl_args->timeout = atoi(optarg);
			break;

		case 'i':
			appl_args->interval = atoi(optarg);
			if (appl_args->interval <= 200 && geteuid() != 0) {
				EXAMPLE_ERR("should be root user\n");
				exit(EXIT_FAILURE);
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
	if (appl_args->mode == 0)
		PRINT_APPL_MODE(0);
	else
		PRINT_APPL_MODE(0);
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
	       "  E.g. %s -I eth1 -r\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "  Work mode:\n"
	       "    1.send udp packets\n"
	       "      odp_generator -I eth0 --srcmac fe:0f:97:c9:e0:44  --dstmac 32:cb:9b:27:2f:1a --srcip 192.168.0.1 --dstip 192.168.0.2 -m u\n"
	       "    2.receive udp packets\n"
	       "      odp_generator -I eth0 -m r\n"
	       "    3.work likes ping\n"
	       "      odp_generator -I eth0 --srcmac fe:0f:97:c9:e0:44  --dstmac 32:cb:9b:27:2f:1a --srcip 192.168.0.1 --dstip 192.168.0.2 -m p\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -I, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "  -a, --srcmac src mac address\n"
	       "  -b, --dstmac dst mac address\n"
	       "  -c, --srcip src ip address\n"
	       "  -d, --dstip dst ip address\n"
	       "  -s, --packetsize payload length of the packets\n"
	       "  -m, --mode work mode: send udp(u), receive(r), send icmp(p)\n"
	       "  -n, --count the number of packets to be send\n"
	       "  -t, --timeout only for ping mode, wait ICMP reply timeout seconds\n"
	       "  -i, --interval wait interval ms between sending each packet\n"
	       "                 default is 1000ms. 0 for flood mode\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -h, --help       Display help and exit.\n"
	       " environment variables: ODP_PKTIO_DISABLE_SOCKET_MMAP\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_MMSG\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_BASIC\n"
	       " can be used to advanced pkt I/O selection for linux-generic\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	      );
}
/**
 * calc time period
 *
 *@param recvtime start time
 *@param sendtime end time
*/
static void tv_sub(struct timeval *recvtime, struct timeval *sendtime)
{
	long sec = recvtime->tv_sec - sendtime->tv_sec;
	long usec = recvtime->tv_usec - sendtime->tv_usec;
	if (usec >= 0) {
		recvtime->tv_sec = sec;
		recvtime->tv_usec = usec;
	} else {
		recvtime->tv_sec = sec - 1;
		recvtime->tv_usec = -usec;
	}
}

/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/** enable strtok */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <time.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <signal.h>

#include <odp_api.h>

#include <odp/helper/odph_api.h>

/* Max number of workers */
#define MAX_WORKERS            (ODP_THREAD_COUNT_MAX - 1)
#define POOL_NUM_PKT           2048  /* Number of packets in packet pool */
#define POOL_PKT_LEN           1856  /* Max packet length */
#define DEFAULT_PKT_INTERVAL   1000  /* Interval between each packet */
#define DEFAULT_UDP_TX_BURST	16
#define MAX_UDP_TX_BURST	512
#define DEFAULT_RX_BURST	32
#define MAX_RX_BURST		512
#define STATS_INTERVAL		10   /* Interval between stats prints (sec) */

#define APPL_MODE_UDP    0			/**< UDP mode */
#define APPL_MODE_PING   1			/**< ping mode */
#define APPL_MODE_RCV    2			/**< receive mode */
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define PING_THR_TX 0
#define PING_THR_RX 1

/** print appl mode */
#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

/**
 * Interfaces
 */

typedef struct {
	odp_pktio_t pktio;
	odp_pktio_config_t config;
	odp_pktout_queue_t pktout[MAX_WORKERS];
	unsigned pktout_count;
	odp_pktin_queue_t pktin[MAX_WORKERS];
	unsigned pktin_count;
} interface_t;

/**
 * Parsed command line application arguments
 */
typedef struct {
	int num_workers;	/**< Number of worker thread */
	const char *mask;	/**< CPU mask */
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *if_str;		/**< Storage for interface names */
	odp_pool_t pool;	/**< Pool for packet IO */
	odph_ethaddr_t srcmac;	/**< src mac addr */
	odph_ethaddr_t dstmac;	/**< dest mac addr */
	unsigned int srcip;	/**< src ip addr */
	unsigned int dstip;	/**< dest ip addr */
	uint16_t srcport;	/**< src udp port */
	uint16_t srcport_end;	/**< src udp end port */
	uint16_t dstport;	/**< dest udp port */
	uint16_t dstport_end;	/**< dest udp end port */
	int mode;		/**< work mode */
	int number;		/**< packets number to be sent */
	int payload;		/**< data len */
	int timeout;		/**< wait time */
	int interval;		/**< wait interval ms between sending
				     each packet */
	int udp_tx_burst;	/**< number of udp packets to send with one
				      API call */
	int rx_burst;	/**< number of packets to receive with one
				      API call */
	odp_bool_t csum;	/**< use platform csum support if available */
	odp_bool_t sched;	/**< use scheduler API to receive packets */
} appl_args_t;

/**
 * counters
*/
typedef struct {
	uint64_t ctr_pkt_snd;	/**< sent packets*/
	uint64_t ctr_pkt_snd_drop; /**< packets dropped in transmit */

	uint64_t ctr_pkt_rcv;	/**< recv packets */
	uint64_t ctr_seq;	/**< ip seq to be send */
	uint64_t ctr_udp_rcv;	/**< udp packets */
	uint64_t ctr_icmp_reply_rcv;	/**< icmp reply packets */
} counters_t;

/** UDP Packet processing function argument */
typedef struct {
	odp_bool_t multi_flow;
	uint16_t srcport_crt;
	uint16_t srcport_start;
	uint16_t srcport_end;
	uint16_t dstport_crt;
	uint16_t dstport_start;
	uint16_t dstport_end;
} udp_args_t;

/** * Thread specific arguments
 */
typedef struct {
	counters_t counters;	/**< Packet conters */
	odp_bool_t stop; /**< Stop packet processing */
	union {
		struct {
			odp_pktout_queue_t pktout; /**< Packet output queue */
			odp_pktout_config_opt_t *pktout_cfg; /**< Packet output config*/
			udp_args_t udp_param;  /**< UDP configuration */
		} tx;
		struct {
			odp_pktin_queue_t pktin; /**< Packet input queue */
		} rx;
	};
	odp_pool_t pool;	/**< Pool for packet IO */
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
	/** Global arguments */
	int thread_cnt;
	int tx_burst_size;
	int rx_burst_size;
	/** Barrier to sync threads execution */
	odp_barrier_t barrier;
} args_t;

/** Global pointer to args */
static args_t *args;

/** Packet processing function types */
typedef odp_packet_t (*setup_pkt_ref_fn_t)(odp_pool_t,
					   odp_pktout_config_opt_t *);
typedef int (*setup_pkt_fn_t)(odp_packet_t, odp_pktout_config_opt_t *,
			      counters_t *, void *);

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);
static int scan_ip(char *buf, unsigned int *paddr);
static void print_global_stats(int num_workers);

static void sig_handler(int signo ODP_UNUSED)
{
	int i;
	if (args == NULL)
		return;
	for (i = 0; i < args->thread_cnt; i++)
		args->thread[i].stop = 1;
}

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
 * Setup array of reference packets
 *
 * @param pool Packet pool
 * @param pktout_cfg Interface output configuration
 * @param pkt_ref_array Packet array
 * @param pkt_ref_array_size Packet array size
 * @param setup_ref Packet setup function
 * @return 0 success, -1 failed
*/
static int setup_pkt_ref_array(odp_pool_t pool,
			       odp_pktout_config_opt_t *pktout_cfg,
			       odp_packet_t *pkt_ref_array,
			       int pkt_ref_array_size,
			       setup_pkt_ref_fn_t setup_ref)
{
	int i;

	for (i = 0; i < pkt_ref_array_size; i++) {
		pkt_ref_array[i] = (*setup_ref)(pool, pktout_cfg);
		if (pkt_ref_array[i] == ODP_PACKET_INVALID)
			break;
	}

	if (i < pkt_ref_array_size) {
		odp_packet_free_multi(pkt_ref_array, i);
		return -1;
	}
	return 0;
}

/**
 * Setup array of packets
 *
 * @param pktout_cfg Interface output configuration
 * @param pkt_ref_array Reference packet array
 * @param pkt_array Packet array
 * @param pkt_array_size Packet array size
 * @param setup_pkt Packet setup function
 * @return 0 success, -1 failed
*/
static int setup_pkt_array(odp_pktout_config_opt_t *pktout_cfg,
			   counters_t *counters,
			   odp_packet_t *pkt_ref_array,
			   odp_packet_t  *pkt_array,
			   int pkt_array_size,
			   setup_pkt_fn_t setup_pkt,
			   void *setup_pkt_arg)
{
	int i;

	for (i = 0; i < pkt_array_size; i++) {
		if ((*setup_pkt)(pkt_ref_array[i], pktout_cfg, counters,
				 setup_pkt_arg))
			break;

		pkt_array[i] = odp_packet_ref_static(pkt_ref_array[i]);
		if (pkt_array[i] == ODP_PACKET_INVALID)
			break;
	}
	if (i < pkt_array_size) {
		if (i)
			odp_packet_free_multi(pkt_array, i - 1);

		return -1;
	}
	return 0;
}

/**
 * set up an udp packet reference
 *
 * @param pool Buffer pool to create packet in
 * @param pktout_cfg Interface output configuration
 *
 *
 * @retval Handle of created packet
 * @retval ODP_PACKET_INVALID  Packet could not be created
 *
 */
static odp_packet_t setup_udp_pkt_ref(odp_pool_t pool,
				      odp_pktout_config_opt_t *pktout_cfg)
{
	odp_packet_t pkt;
	char *buf;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;

	pkt = odp_packet_alloc(pool, args->appl.payload + ODPH_UDPHDR_LEN +
			       ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);

	if (pkt == ODP_PACKET_INVALID)
		return pkt;

	buf = odp_packet_data(pkt);

	/* ether */
	odp_packet_l2_offset_set(pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy((char *)eth->src.addr, args->appl.srcmac.addr, ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, args->appl.dstmac.addr, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	/* ip */
	odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
	odp_packet_has_ipv4_set(pkt, 1);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(args->appl.dstip);
	ip->src_addr = odp_cpu_to_be_32(args->appl.srcip);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(args->appl.payload + ODPH_UDPHDR_LEN +
				       ODPH_IPV4HDR_LEN);
	ip->proto = ODPH_IPPROTO_UDP;
	ip->id = 0;
	ip->ttl = 64;
	ip->chksum = 0;

	/* udp */
	odp_packet_l4_offset_set(pkt, ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	odp_packet_has_udp_set(pkt, 1);
	udp = (odph_udphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	udp->src_port = odp_cpu_to_be_16(args->appl.srcport);
	udp->dst_port = odp_cpu_to_be_16(args->appl.dstport);
	udp->length = odp_cpu_to_be_16(args->appl.payload + ODPH_UDPHDR_LEN);
	if (!pktout_cfg->bit.udp_chksum) {
		udp->chksum = 0;
		udp->chksum = odph_ipv4_udp_chksum(pkt);
	}

	return pkt;
}

/**
 * set up an udp packet
 *
 * @param pkt Reference UDP packet
 * @param pktout_cfg Interface output configuration
 *
 * @return Success/Failed
 * @retval 0 on success, -1 on fail
 */
static int setup_udp_pkt(odp_packet_t pkt, odp_pktout_config_opt_t *pktout_cfg,
			 counters_t *counters, void *arg)
{
	char *buf;
	odph_ipv4hdr_t *ip;
	unsigned short seq;
	udp_args_t *udp_arg = (udp_args_t *)arg;

	buf = (char *)odp_packet_data(pkt);

	/*Update IP ID and checksum*/
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	seq = counters->ctr_seq % 0xFFFF;
	counters->ctr_seq++;
	ip->id = odp_cpu_to_be_16(seq);
	if (!pktout_cfg->bit.ipv4_chksum) {
		ip->chksum = 0;
		ip->chksum = ~odp_chksum_ones_comp16(ip, ODPH_IPV4HDR_LEN);
	}

	if (udp_arg->multi_flow) {
		odph_udphdr_t *udp = (odph_udphdr_t *)(buf + ODPH_ETHHDR_LEN +
						       ODPH_IPV4HDR_LEN);

		if (udp_arg->srcport_start != udp_arg->srcport_end) {
			udp->src_port = odp_cpu_to_be_16(udp_arg->srcport_crt);
			if (udp_arg->srcport_crt >= udp_arg->srcport_end)
				udp_arg->srcport_crt = udp_arg->srcport_start;
			else
				udp_arg->srcport_crt++;
		}
		if (udp_arg->dstport_start != udp_arg->dstport_end) {
			udp->dst_port = odp_cpu_to_be_16(udp_arg->dstport_crt);
			if (udp_arg->dstport_crt >= udp_arg->dstport_end)
				udp_arg->dstport_crt = udp_arg->dstport_start;
			else
				udp_arg->dstport_crt++;
		}

		udp->chksum = 0;
	}

	if (pktout_cfg->bit.ipv4_chksum || pktout_cfg->bit.udp_chksum) {
		odp_packet_l2_offset_set(pkt, 0);
		odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
		odp_packet_l4_offset_set(pkt, ODPH_ETHHDR_LEN +
					 ODPH_IPV4HDR_LEN);
	}
	return 0;
}

/**
 * Set up an icmp packet reference
 *
 * @param pool Buffer pool to create packet in
 * @param pktout_cfg Interface output configuration
 *
 * @return Handle of created packet
 * @retval ODP_PACKET_INVALID  Packet could not be created
 */
static odp_packet_t setup_icmp_pkt_ref(odp_pool_t pool,
				       odp_pktout_config_opt_t *pktout_cfg)
{
	odp_packet_t pkt;
	char *buf;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_icmphdr_t *icmp;

	(void)pktout_cfg;

	args->appl.payload = 56;
	pkt = odp_packet_alloc(pool, args->appl.payload + ODPH_ICMPHDR_LEN +
		ODPH_IPV4HDR_LEN + ODPH_ETHHDR_LEN);

	if (pkt == ODP_PACKET_INVALID)
		return pkt;

	buf = odp_packet_data(pkt);

	/* ether */
	odp_packet_l2_offset_set(pkt, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy((char *)eth->src.addr, args->appl.srcmac.addr, ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, args->appl.dstmac.addr, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);
	/* ip */
	odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(args->appl.dstip);
	ip->src_addr = odp_cpu_to_be_32(args->appl.srcip);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->ttl = 64;
	ip->tot_len = odp_cpu_to_be_16(args->appl.payload + ODPH_ICMPHDR_LEN +
				       ODPH_IPV4HDR_LEN);
	ip->proto = ODPH_IPPROTO_ICMPV4;
	ip->id = 0;
	ip->chksum = 0;

	/* icmp */
	icmp = (odph_icmphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = 0;
	icmp->un.echo.sequence = 0;
	icmp->chksum = 0;

	return pkt;
}

/**
 * Set up an icmp packet
 *
 * @param pkt Reference ICMP packet
 * @param pktout_cfg Interface output configuration
 *
 * @return Success/Failed
 * @retval 0 on success, -1 on fail
 */
static int setup_icmp_pkt(odp_packet_t pkt,
			  odp_pktout_config_opt_t *pktout_cfg,
			  counters_t *counters, void *arg ODP_UNUSED)
{
	char *buf;
	odph_ipv4hdr_t *ip;
	odph_icmphdr_t *icmp;
	uint64_t tval;
	uint8_t *tval_d;
	unsigned short seq;

	buf = (char *)odp_packet_data(pkt);

	/* ip */
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	seq = counters->ctr_seq % 0xffff;
	counters->ctr_seq++;
	ip->id = odp_cpu_to_be_16(seq);
	if (!pktout_cfg->bit.ipv4_chksum) {
		ip->chksum = 0;
		ip->chksum = ~odp_chksum_ones_comp16(ip, ODPH_IPV4HDR_LEN);
	}

	/* icmp */
	icmp = (odph_icmphdr_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN);
	icmp->un.echo.sequence = ip->id;

	tval_d = (uint8_t *)(buf + ODPH_ETHHDR_LEN + ODPH_IPV4HDR_LEN +
				  ODPH_ICMPHDR_LEN);
	tval = odp_time_to_ns(odp_time_local());
	memcpy(tval_d, &tval, sizeof(uint64_t));

	icmp->chksum = 0;
	icmp->chksum = ~odp_chksum_ones_comp16(icmp, args->appl.payload +
					       ODPH_ICMPHDR_LEN);

	if (pktout_cfg->bit.ipv4_chksum) {
		odp_packet_l2_offset_set(pkt, 0);
		odp_packet_l3_offset_set(pkt, ODPH_ETHHDR_LEN);
		odp_packet_l4_offset_set(pkt, ODPH_ETHHDR_LEN +
					 ODPH_IPV4HDR_LEN);
	}

	return 0;
}

/**
 * Create a pktio object
 *
 * @param dev Name of device to open
 * @param pool Pool to associate with device for packet RX/TX
 *
 * @return The handle of the created pktio object.
 * @warning This routine aborts if the create is unsuccessful.
 */
static int create_pktio(const char *dev, odp_pool_t pool,
			unsigned num_rx_queues,
			unsigned num_tx_queues,
			interface_t *itf)
{
	odp_pktio_capability_t capa;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_pktio_op_mode_t pktout_mode, pktin_mode;
	odp_bool_t sched = args->appl.sched;

	odp_pktio_param_init(&pktio_param);
	pktio_param.in_mode = num_rx_queues ?
		(sched ? ODP_PKTIN_MODE_SCHED : ODP_PKTIN_MODE_DIRECT) :
		ODP_PKTIN_MODE_DISABLED;
	pktio_param.out_mode = num_tx_queues ? ODP_PKTOUT_MODE_DIRECT :
		ODP_PKTOUT_MODE_DISABLED;

	/* Open a packet IO instance */
	itf->pktio = odp_pktio_open(dev, pool, &pktio_param);

	if (itf->pktio == ODP_PKTIO_INVALID) {
		ODPH_ERR("Error: pktio create failed for %s\n", dev);
		return -1;
	}

	if (odp_pktio_capability(itf->pktio, &capa)) {
		ODPH_ERR("Error: Failed to get interface capabilities %s\n",
			 dev);
		return -1;
	}
	odp_pktio_config_init(&itf->config);
	if (args->appl.csum) {
		itf->config.pktin.bit.ipv4_chksum =
			capa.config.pktin.bit.ipv4_chksum;
		itf->config.pktin.bit.udp_chksum =
			capa.config.pktin.bit.udp_chksum;
		itf->config.pktin.bit.drop_ipv4_err =
			capa.config.pktin.bit.drop_ipv4_err;
		itf->config.pktin.bit.drop_udp_err =
			capa.config.pktin.bit.drop_udp_err;

		itf->config.pktout.bit.ipv4_chksum_ena =
			capa.config.pktout.bit.ipv4_chksum_ena;
		itf->config.pktout.bit.udp_chksum_ena =
			capa.config.pktout.bit.udp_chksum_ena;
		itf->config.pktout.bit.ipv4_chksum =
			capa.config.pktout.bit.ipv4_chksum;
		itf->config.pktout.bit.udp_chksum =
			capa.config.pktout.bit.udp_chksum;
	} else { /* explicit disable */
		itf->config.pktin.bit.ipv4_chksum = 0;
		itf->config.pktin.bit.udp_chksum = 0;
		itf->config.pktout.bit.ipv4_chksum_ena = 0;
		itf->config.pktout.bit.udp_chksum_ena = 0;
		itf->config.pktout.bit.ipv4_chksum = 0;
		itf->config.pktout.bit.udp_chksum = 0;
	}

	itf->config.parser.layer = ODP_PROTO_LAYER_L2;
	if (itf->config.pktin.bit.udp_chksum)
		itf->config.parser.layer = ODP_PROTO_LAYER_L4;
	else if (itf->config.pktin.bit.ipv4_chksum)
		itf->config.parser.layer = ODP_PROTO_LAYER_L3;

	if (odp_pktio_config(itf->pktio, &itf->config)) {
		ODPH_ERR("Error: Failed to set interface configuration %s\n",
			 dev);
		return -1;
	}

	if (num_rx_queues) {
		pktin_mode = ODP_PKTIO_OP_MT_UNSAFE;
		if (num_rx_queues > capa.max_input_queues) {
			num_rx_queues = capa.max_input_queues;
			pktin_mode = ODP_PKTIO_OP_MT;
			ODPH_DBG("Warning: Force RX multithread safe mode "
				 "(slower)on %s\n",	dev);
		}

		odp_pktin_queue_param_init(&pktin_param);
		pktin_param.num_queues = num_rx_queues;
		pktin_param.op_mode = pktin_mode;
		if (sched)
			pktin_param.queue_param.sched.sync =
				ODP_SCHED_SYNC_ATOMIC;

		if (odp_pktin_queue_config(itf->pktio, &pktin_param)) {
			ODPH_ERR("Error: pktin queue config failed for %s\n",
				 dev);
			return -1;
		}
	}

	if (num_tx_queues) {
		pktout_mode = ODP_PKTIO_OP_MT_UNSAFE;
		if (num_tx_queues > capa.max_output_queues) {
			num_tx_queues = capa.max_output_queues;
			pktout_mode = ODP_PKTIO_OP_MT;
			ODPH_DBG("Warning: Force TX multithread safe mode "
				 "(slower) on %s\n", dev);
		}

		odp_pktout_queue_param_init(&pktout_param);
		pktout_param.num_queues = num_tx_queues;
		pktout_param.op_mode = pktout_mode;

		if (odp_pktout_queue_config(itf->pktio, &pktout_param)) {
			ODPH_ERR("Error: pktout queue config failed for %s\n",
				 dev);
			return -1;
		}
	}

	ret = odp_pktio_start(itf->pktio);
	if (ret)
		ODPH_ABORT("Error: unable to start %s\n", dev);

	itf->pktout_count = num_tx_queues;
	if (itf->pktout_count &&
	    odp_pktout_queue(itf->pktio, itf->pktout, itf->pktout_count) !=
	    (int)itf->pktout_count) {
		ODPH_ERR("Error: failed to get output queues for %s\n", dev);
		return -1;
	}

	itf->pktin_count = num_rx_queues;
	if (!sched && itf->pktin_count &&
	    odp_pktin_queue(itf->pktio, itf->pktin, itf->pktin_count) !=
	    (int)itf->pktin_count) {
		ODPH_ERR("Error: failed to get input queues for %s\n", dev);
		return -1;
	}

	printf("  created pktio:%02" PRIu64
	       ", dev:%s, queue mode (ATOMIC queues)\n"
	       "          default pktio%02" PRIu64 "\n",
	       odp_pktio_to_u64(itf->pktio), dev,
	       odp_pktio_to_u64(itf->pktio));
	fflush(NULL);

	return 0;
}

/**
 * Packet IO loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */

static int gen_send_thread(void *arg)
{
	int thr;
	int ret = 0;
	thread_args_t *thr_args;
	odp_pktout_queue_t pktout;
	odp_pktout_config_opt_t *pktout_cfg;
	odp_packet_t pkt_ref_array[MAX_UDP_TX_BURST];
	odp_packet_t pkt_array[MAX_UDP_TX_BURST];
	int pkt_array_size, seq_step;
	int burst_start, burst_size;
	setup_pkt_ref_fn_t setup_pkt_ref = NULL;
	setup_pkt_fn_t setup_pkt = NULL;
	void *setup_pkt_arg = NULL;
	counters_t *counters;
	uint64_t pkt_count_max = 0;

	thr = odp_thread_id();
	thr_args = arg;
	pktout = thr_args->tx.pktout;
	pktout_cfg = thr_args->tx.pktout_cfg;
	counters = &thr_args->counters;

	/* Create reference packets*/
	if (args->appl.mode == APPL_MODE_UDP) {
		setup_pkt_ref = setup_udp_pkt_ref;
		setup_pkt = setup_udp_pkt;
		seq_step = args->tx_burst_size * (args->thread_cnt - 1);
		if (args->appl.number != -1)
			pkt_count_max = args->appl.number / args->thread_cnt +
				(args->appl.number % args->thread_cnt ? 1 : 0);
		setup_pkt_arg = &thr_args->tx.udp_param;
	} else if (args->appl.mode == APPL_MODE_PING) {
		setup_pkt_ref = setup_icmp_pkt_ref;
		setup_pkt = setup_icmp_pkt;
		seq_step = 0;
		if (args->appl.number != -1)
			pkt_count_max = args->appl.number;
	} else {
		ODPH_ERR("  [%02i] Error: invalid processing mode %d\n", thr,
			 args->appl.mode);
		return -1;
	}
	pkt_array_size = args->tx_burst_size;

	if (setup_pkt_ref_array(thr_args->pool, pktout_cfg,
				pkt_ref_array, pkt_array_size,
				setup_pkt_ref)) {
		ODPH_ERR("[%02i] Error: failed to create reference packets\n",
			 thr);
		return -1;
	}

	printf("  [%02i] created mode: SEND\n", thr);

	odp_barrier_wait(&args->barrier);

	for (;;) {
		if (thr_args->stop)
			break;

		if (pkt_count_max && counters->ctr_pkt_snd > pkt_count_max) {
			sleep(1); /* wait for stop command */
			continue;
		}

		/* Setup TX burst*/
		if (setup_pkt_array(pktout_cfg, counters,
				    pkt_ref_array, pkt_array,
				    pkt_array_size, setup_pkt, setup_pkt_arg)) {
			ODPH_ERR("[%02i] Error: failed to setup packets\n",
				 thr);
			break;
		}

		/* Send TX burst*/
		for (burst_start = 0, burst_size = pkt_array_size;;) {
			ret = odp_pktout_send(pktout, &pkt_array[burst_start],
					      burst_size);
			if (ret == burst_size) {
				burst_size = 0;
				break;
			} else if (ret >= 0 && ret < burst_size) {
				thr_args->counters.ctr_pkt_snd_drop +=
					burst_size - ret;

				burst_start += ret;
				burst_size -= ret;
				continue;
			}
			ODPH_ERR("  [%02i] packet send failed\n", thr);
			odp_packet_free_multi(&pkt_array[burst_start],
					      burst_size);
			break;
		}

		counters->ctr_pkt_snd += pkt_array_size - burst_size;

		if (args->appl.interval != 0)
			odp_time_wait_ns((uint64_t)args->appl.interval *
					 ODP_TIME_MSEC_IN_NS);
		counters->ctr_seq += seq_step;
	}

	odp_packet_free_multi(pkt_ref_array, pkt_array_size);

	return 0;
}

/**
 * Process icmp packets
 *
 * @param  thr worker id
 * @param  thr_args worker argument
 * @param  icmp icmp header address
 */

static void process_icmp_pkt(int thr, thread_args_t *thr_args,
			     uint8_t *_icmp)
{
	uint64_t trecv;
	uint64_t tsend;
	uint64_t rtt_ms, rtt_us;
	odph_icmphdr_t *icmp = (odph_icmphdr_t *)_icmp;

	if (icmp->type == ICMP_ECHOREPLY) {
		thr_args->counters.ctr_icmp_reply_rcv++;

		memcpy(&tsend, (uint8_t *)icmp + ODPH_ICMPHDR_LEN,
		       sizeof(uint64_t));
		trecv = odp_time_to_ns(odp_time_local());
		rtt_ms = (trecv - tsend) / ODP_TIME_MSEC_IN_NS;
		rtt_us = (trecv - tsend) / ODP_TIME_USEC_IN_NS -
				1000 * rtt_ms;
		printf("  [%02i] ICMP Echo Reply seq %d time %"
			PRIu64 ".%.03" PRIu64" ms\n", thr,
			odp_be_to_cpu_16(icmp->un.echo.sequence),
			rtt_ms, rtt_us);
	} else if (icmp->type == ICMP_ECHO) {
		printf("  [%02i] ICMP Echo Request\n", thr);
	}
}

/**
 * Process odp packets
 *
 * @param  thr worker id
 * @param  thr_args worker argument
 * @param  pkt_tbl packets to be print
 * @param  len packet number
 */
static void process_pkts(int thr, thread_args_t *thr_args,
			 odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	uint32_t left, offset, i;
	odph_ipv4hdr_t *ip;

	for (i = 0; i < len; ++i) {
		pkt = pkt_tbl[i];

		/* Drop packets with errors */
		if (odp_unlikely(odp_packet_has_error(pkt)))
			continue;

		offset = odp_packet_l3_offset(pkt);
		left = odp_packet_len(pkt) - offset;

		if (left < sizeof(odph_ipv4hdr_t))
			continue;

		ip = (odph_ipv4hdr_t *)((uint8_t *)odp_packet_data(pkt) +
					offset);

		/* only ip pkts */
		if (ODPH_IPV4HDR_VER(ip->ver_ihl) != ODPH_IPV4)
			continue;

		thr_args->counters.ctr_pkt_rcv++;

		/* udp */
		if (ip->proto == ODPH_IPPROTO_UDP) {
			thr_args->counters.ctr_udp_rcv++;
		} else if (ip->proto == ODPH_IPPROTO_ICMPV4) {
			uint32_t l3_size = ODPH_IPV4HDR_IHL(ip->ver_ihl) * 4;

			offset += l3_size;
			left -=  l3_size;

			if (left < sizeof(odph_icmphdr_t))
				continue;

			process_icmp_pkt(thr, thr_args,
					 (uint8_t *)odp_packet_data(pkt) +
					 offset);
		}
	}
}

/**
 * Scheduler receive function
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static int gen_recv_thread(void *arg)
{
	int thr;
	thread_args_t *thr_args;
	odp_packet_t pkts[MAX_RX_BURST];
	odp_event_t events[MAX_RX_BURST], ev;
	int pkt_cnt, ev_cnt, i;
	int burst_size;

	thr = odp_thread_id();
	thr_args = (thread_args_t *)arg;
	burst_size = args->rx_burst_size;

	printf("  [%02i] created mode: RECEIVE SCHEDULER\n", thr);
	odp_barrier_wait(&args->barrier);

	for (;;) {
		if (thr_args->stop)
			break;

		/* Use schedule to get buf from any input queue */
		ev_cnt = odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT,
					    events, burst_size);
		if (ev_cnt == 0)
			continue;

		for (i = 0, pkt_cnt = 0; i < ev_cnt; i++) {
			ev = events[i];

			if (odp_event_type(ev) == ODP_EVENT_PACKET)
				pkts[pkt_cnt++] = odp_packet_from_event(ev);
			else
				odp_event_free(ev);
		}

		if (pkt_cnt) {
			process_pkts(thr, thr_args, pkts, pkt_cnt);

			odp_packet_free_multi(pkts, pkt_cnt);
		}
	}

	return 0;
}

/**
 * Direct receive function
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static int gen_recv_direct_thread(void *arg)
{
	int thr;
	thread_args_t *thr_args;
	odp_packet_t pkts[MAX_RX_BURST];
	int pkt_cnt, burst_size;
	odp_pktin_queue_t pktin;
	uint64_t wait = odp_pktin_wait_time(ODP_TIME_SEC_IN_NS);

	thr = odp_thread_id();
	thr_args = (thread_args_t *)arg;
	pktin = thr_args->rx.pktin;
	burst_size = args->rx_burst_size;

	printf("  [%02i] created mode: RECEIVE\n", thr);
	odp_barrier_wait(&args->barrier);

	for (;;) {
		if (thr_args->stop)
			break;

		pkt_cnt = odp_pktin_recv_tmo(pktin, pkts, burst_size, wait);

		if (pkt_cnt > 0) {
			process_pkts(thr, thr_args, pkts, pkt_cnt);

			odp_packet_free_multi(pkts, pkt_cnt);
		} else if (pkt_cnt == 0) {
			continue;
		} else {
			break;
		}
	}

	return 0;
}

#define COUNTER_SUM(_c, _nw)						\
({									\
	int _itr;							\
	uint64_t _result = 0;						\
									\
	for (_itr = 0; _itr < _nw; _itr++)				\
		_result += args->thread[_itr].counters.ctr_ ## _c;	\
									\
	_result;							\
})

static void garceful_stop_ping(void)
{
	uint64_t snd, rcv;

	if (args->appl.mode != APPL_MODE_PING)
		return;

	while (args->appl.timeout >= 0) {
		snd = COUNTER_SUM(pkt_snd, 2);
		rcv = COUNTER_SUM(icmp_reply_rcv, 2);
		if (rcv >= snd)
			break;

		sleep(1);
		args->appl.timeout--;
	}
}

/**
 * printing verbose statistics
 *
 */
static void print_global_stats(int num_workers)
{
	odp_time_t cur, wait, next, left;
	uint64_t pkts_snd = 0, pkts_snd_prev = 0;
	uint64_t pps_snd = 0, maximum_pps_snd = 0;
	uint64_t pkts_rcv = 0, pkts_rcv_prev = 0;
	uint64_t pps_rcv = 0, maximum_pps_rcv = 0;
	uint64_t stall, pkts_snd_drop;
	int verbose_interval = STATS_INTERVAL, i;
	odp_thrmask_t thrd_mask;

	odp_barrier_wait(&args->barrier);

	wait = odp_time_local_from_ns(verbose_interval * ODP_TIME_SEC_IN_NS);
	next = odp_time_sum(odp_time_local(), wait);

	while (odp_thrmask_worker(&thrd_mask) == num_workers) {
		if (args->appl.mode != APPL_MODE_RCV &&
		    args->appl.number != -1) {
			uint64_t cnt = COUNTER_SUM(pkt_snd, num_workers);

			if (cnt >= (unsigned int)args->appl.number) {
				garceful_stop_ping();
				break;
			}
		}
		cur = odp_time_local();
		if (odp_time_cmp(next, cur) > 0) {
			left = odp_time_diff(next, cur);
			stall = odp_time_to_ns(left);
			if (stall / ODP_TIME_SEC_IN_NS)
				sleep(1);
			else
				usleep(stall / ODP_TIME_USEC_IN_NS);
			continue;
		}
		next = odp_time_sum(cur, wait);

		switch (args->appl.mode) {
		case APPL_MODE_RCV:
			pkts_rcv = COUNTER_SUM(pkt_rcv, num_workers);
			pkts_snd = 0;
			pkts_snd_drop = 0;
			break;
		case APPL_MODE_PING:
			pkts_snd = COUNTER_SUM(pkt_snd, num_workers);
			pkts_snd_drop = COUNTER_SUM(pkt_snd_drop, num_workers);
			pkts_rcv = COUNTER_SUM(icmp_reply_rcv, num_workers);
			break;
		case APPL_MODE_UDP:
			pkts_snd = COUNTER_SUM(pkt_snd, num_workers);
			pkts_snd_drop = COUNTER_SUM(pkt_snd_drop, num_workers);
			break;
		default:
			continue;
		}

		pps_snd = (pkts_snd - pkts_snd_prev) / verbose_interval;
		pkts_snd_prev = pkts_snd;
		if (pps_snd > maximum_pps_snd)
			maximum_pps_snd = pps_snd;

		pps_rcv = (pkts_rcv - pkts_rcv_prev) / verbose_interval;
		pkts_rcv_prev = pkts_rcv;
		if (pps_rcv > maximum_pps_rcv)
			maximum_pps_rcv = pps_rcv;

		printf("sent: %" PRIu64 ", drops: %" PRIu64 ", "
			"send rate: %" PRIu64 " pps, "
			"max send rate: %" PRIu64 " pps, "
			"rcv: %" PRIu64 ", "
			"recv rate: %" PRIu64 " pps, "
			"max recv rate: %" PRIu64 " pps\n",
			pkts_snd, pkts_snd_drop,
			pps_snd, maximum_pps_snd,
			pkts_rcv, pps_rcv, maximum_pps_rcv);
		fflush(NULL);
	}

	for (i = 0; i < num_workers; i++)
		args->thread[i].stop = 1;
}

/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	odph_thread_t thread_tbl[MAX_WORKERS];
	odp_pool_t pool;
	int num_workers;
	unsigned num_rx_queues, num_tx_queues;
	int i;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	interface_t *ifs;
	odp_instance_t instance;
	odp_init_t init_param;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;

	/* Signal handler has to be registered before global init in case ODP
	 * implementation creates internal threads/processes. */
	signal(SIGINT, sig_handler);

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	args = odp_shm_addr(shm);

	if (args == NULL) {
		ODPH_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(args, 0, sizeof(*args));

	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	num_workers = 1;
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);

	if (args->appl.num_workers) {
		/* -w option: number of workers */
		num_workers = args->appl.num_workers;
		num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	} else if (args->appl.mask) {
		/* -c option: cpumask */
		odp_cpumask_from_str(&cpumask, args->appl.mask);
		num_workers = odp_cpumask_count(&cpumask);
	}

	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);
	fflush(NULL);

	/* ping mode need two workers */
	if (args->appl.mode == APPL_MODE_PING) {
		if (num_workers < 2) {
			ODPH_ERR("Need at least two worker threads\n");
			exit(EXIT_FAILURE);
		} else {
			num_workers = 2;
		}
	}
	args->thread_cnt = num_workers;

	/* Burst size */
	if (args->appl.mode == APPL_MODE_PING) {
		args->tx_burst_size = 1;
		args->rx_burst_size = 1;
	} else if (args->appl.mode == APPL_MODE_UDP) {
		args->tx_burst_size = args->appl.udp_tx_burst;
		args->rx_burst_size = 0;
	} else {
		args->tx_burst_size = 0;
		args->rx_burst_size = args->appl.rx_burst;
	}

	/* Configure scheduler */
	odp_schedule_config(NULL);

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = POOL_PKT_LEN;
	params.pkt.len     = POOL_PKT_LEN;
	params.pkt.num     = POOL_NUM_PKT;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	ifs = malloc(sizeof(interface_t) * args->appl.if_count);

	for (i = 0; i < args->appl.if_count; ++i) {
		if (args->appl.mode == APPL_MODE_PING) {
			num_rx_queues = 1;
			num_tx_queues = 1;
		} else if (args->appl.mode == APPL_MODE_UDP) {
			num_rx_queues = 0;
			num_tx_queues = num_workers / args->appl.if_count;
			if (i < num_workers % args->appl.if_count)
				num_tx_queues++;
		} else { /* APPL_MODE_RCV*/
			num_rx_queues = num_workers / args->appl.if_count;
			if (i < num_workers % args->appl.if_count)
				num_rx_queues++;
			num_tx_queues = 0;
		}

		if (create_pktio(args->appl.if_names[i], pool, num_rx_queues,
				 num_tx_queues, &ifs[i])) {
			ODPH_ERR("Error: create interface %s failed.\n",
				 args->appl.if_names[i]);
			exit(EXIT_FAILURE);
		}
	}

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));

	/* Init threads params */
	memset(&thr_param, 0, sizeof(thr_param));
	thr_param.thr_type = ODP_THREAD_WORKER;

	memset(&thr_common, 0, sizeof(thr_common));
	thr_common.instance = instance;

	/* num workers + print thread */
	odp_barrier_init(&args->barrier, num_workers + 1);

	if (args->appl.mode == APPL_MODE_PING) {
		odp_cpumask_t cpu_mask;
		int cpu_first, cpu_next;
		thread_args_t *thr_args;

		odp_cpumask_zero(&cpu_mask);
		cpu_first = odp_cpumask_first(&cpumask);
		odp_cpumask_set(&cpu_mask, cpu_first);

		thr_args = &args->thread[PING_THR_RX];
		if (!args->appl.sched)
			thr_args->rx.pktin = ifs[0].pktin[0];
		thr_args->pool = pool;
		thr_args->mode = args->appl.mode;

		if (args->appl.sched)
			thr_param.start = gen_recv_thread;
		else
			thr_param.start = gen_recv_direct_thread;

		thr_param.arg = thr_args;

		thr_common.cpumask = &cpu_mask;

		odph_thread_create(&thread_tbl[PING_THR_RX], &thr_common,
				   &thr_param, 1);

		thr_args = &args->thread[PING_THR_TX];
		thr_args->tx.pktout = ifs[0].pktout[0];
		thr_args->tx.pktout_cfg = &ifs[0].config.pktout;
		thr_args->pool = pool;
		thr_args->mode = args->appl.mode;
		cpu_next = odp_cpumask_next(&cpumask, cpu_first);
		odp_cpumask_zero(&cpu_mask);
		odp_cpumask_set(&cpu_mask, cpu_next);

		thr_param.start = gen_send_thread;
		thr_param.arg   = thr_args;

		odph_thread_create(&thread_tbl[PING_THR_TX], &thr_common,
				   &thr_param, 1);

	} else {
		int cpu = odp_cpumask_first(&cpumask);
		udp_args_t *udp_param = NULL;
		uint16_t sport_range = args->appl.srcport_end -
			args->appl.srcport + 1;
		uint16_t dport_range = args->appl.dstport_end -
			args->appl.dstport + 1;
		float sport_step = (float)(sport_range) / num_workers;
		float dport_step = (float)(dport_range) / num_workers;
		odp_bool_t multi_flow = false;

		if (sport_range > 1 || dport_range > 1)
			multi_flow = true;

		for (i = 0; i < num_workers; ++i) {
			odp_cpumask_t thd_mask;
			int (*thr_run_func)(void *);
			int if_idx, pktq_idx;
			uint64_t start_seq;

			if_idx = i % args->appl.if_count;

			if (args->appl.mode == APPL_MODE_RCV) {
				pktq_idx = (i / args->appl.if_count) %
					ifs[if_idx].pktin_count;
				if (!args->appl.sched)
					args->thread[i].rx.pktin =
						ifs[if_idx].pktin[pktq_idx];
			} else {
				udp_param = &args->thread[i].tx.udp_param;

				pktq_idx = (i / args->appl.if_count) %
					ifs[if_idx].pktout_count;
				start_seq = i * args->tx_burst_size;

				args->thread[i].tx.pktout =
					ifs[if_idx].pktout[pktq_idx];
				args->thread[i].tx.pktout_cfg =
					&ifs[if_idx].config.pktout;

				udp_param->multi_flow = multi_flow;
				udp_param->srcport_start = args->appl.srcport;
				udp_param->srcport_end = args->appl.srcport_end;
				udp_param->srcport_crt = args->appl.srcport;
				if (sport_range > 1)
					udp_param->srcport_crt +=
						(uint16_t)(i * sport_step);

				udp_param->dstport_start = args->appl.dstport;
				udp_param->dstport_end = args->appl.dstport_end;
				udp_param->dstport_crt = args->appl.dstport;
				if (dport_range > 1)
					udp_param->dstport_crt +=
						(uint16_t)(i * dport_step);

				args->thread[i].counters.ctr_seq = start_seq;
			}
			args->thread[i].pool = pool;
			args->thread[i].mode = args->appl.mode;

			if (args->appl.mode == APPL_MODE_UDP) {
				thr_run_func = gen_send_thread;
			} else if (args->appl.mode == APPL_MODE_RCV) {
				if (args->appl.sched)
					thr_run_func = gen_recv_thread;
				else
					thr_run_func = gen_recv_direct_thread;
			} else {
				ODPH_ERR("ERR MODE\n");
				exit(EXIT_FAILURE);
			}
			/*
			 * Create threads one-by-one instead of all-at-once,
			 * because each thread might get different arguments.
			 * Calls odp_thread_create(cpu) for each thread
			 */
			odp_cpumask_zero(&thd_mask);
			odp_cpumask_set(&thd_mask, cpu);

			thr_param.start = thr_run_func;
			thr_param.arg   = &args->thread[i];

			thr_common.cpumask = &thd_mask;

			odph_thread_create(&thread_tbl[i], &thr_common,
					   &thr_param, 1);
			cpu = odp_cpumask_next(&cpumask, cpu);
		}
	}

	print_global_stats(num_workers);

	/* Master thread waits for other threads to exit */
	odph_thread_join(thread_tbl, num_workers);

	for (i = 0; i < args->appl.if_count; ++i)
		odp_pktio_stop(ifs[i].pktio);

	for (i = 0; i < args->appl.if_count; ++i)
		odp_pktio_close(ifs[i].pktio);
	free(ifs);
	free(args->appl.if_names);
	free(args->appl.if_str);
	args = NULL;
	odp_mb_full();
	if (0 != odp_pool_destroy(pool))
		fprintf(stderr, "unable to destroy pool \"pool\"\n");
	if (0 != odp_shm_free(shm))
		fprintf(stderr, "unable to free \"shm\"\n");
	odp_term_local();
	odp_term_global(instance);
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
	odp_cpumask_t cpumask, cpumask_args, cpumask_and;
	int i, num_workers;
	static const struct option longopts[] = {
		{"interface", required_argument, NULL, 'I'},
		{"workers", required_argument, NULL, 'w'},
		{"cpumask", required_argument, NULL, 'c'},
		{"srcmac", required_argument, NULL, 'a'},
		{"dstmac", required_argument, NULL, 'b'},
		{"srcip", required_argument, NULL, 's'},
		{"dstip", required_argument, NULL, 'd'},
		{"srcport", required_argument, NULL, 'e'},
		{"srcport_end", required_argument, NULL, 'j'},
		{"dstport", required_argument, NULL, 'f'},
		{"dstport_end", required_argument, NULL, 'k'},
		{"packetsize", required_argument, NULL, 'p'},
		{"mode", required_argument, NULL, 'm'},
		{"count", required_argument, NULL, 'n'},
		{"timeout", required_argument, NULL, 't'},
		{"interval", required_argument, NULL, 'i'},
		{"help", no_argument, NULL, 'h'},
		{"udp_tx_burst", required_argument, NULL, 'x'},
		{"rx_burst", required_argument, NULL, 'r'},
		{"csum", no_argument, NULL, 'y'},
		{"sched", no_argument, NULL, 'z'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+I:a:b:s:d:p:i:m:n:t:w:c:x:he:j:f:k"
					":yr:z";

	appl_args->mode = -1; /* Invalid, must be changed by parsing */
	appl_args->number = -1;
	appl_args->payload = 56;
	appl_args->timeout = -1;
	appl_args->interval = DEFAULT_PKT_INTERVAL;
	appl_args->udp_tx_burst = DEFAULT_UDP_TX_BURST;
	appl_args->rx_burst = DEFAULT_RX_BURST;
	appl_args->srcport = 0;
	appl_args->srcport_end = 0;
	appl_args->dstport = 0;
	appl_args->dstport_end = 0;
	appl_args->csum = 0;
	appl_args->sched = 0;
	appl_args->num_workers = -1;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);
		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'w':
			appl_args->num_workers = atoi(optarg);
			break;
		case 'c':
			appl_args->mask = optarg;
			odp_cpumask_from_str(&cpumask_args, args->appl.mask);
			num_workers = odp_cpumask_default_worker(&cpumask, 0);
			odp_cpumask_and(&cpumask_and, &cpumask_args, &cpumask);
			if (odp_cpumask_count(&cpumask_and) <
			    odp_cpumask_count(&cpumask_args) ||
			    odp_cpumask_count(&cpumask_args) > MAX_WORKERS) {
				ODPH_ERR("Wrong cpu mask, max cpu's:%d\n",
					 num_workers < MAX_WORKERS ?
					 num_workers : MAX_WORKERS);
				exit(EXIT_FAILURE);
			}
			break;
		/* parse packet-io interface names */
		case 'I':
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
			if (optarg[0] == 'u') {
				appl_args->mode = APPL_MODE_UDP;
			} else if (optarg[0] == 'p') {
				appl_args->mode = APPL_MODE_PING;
			} else if (optarg[0] == 'r') {
				appl_args->mode = APPL_MODE_RCV;
			} else {
				ODPH_ERR("wrong mode!\n");
				exit(EXIT_FAILURE);
			}
			break;

		case 'a':
			if (odph_eth_addr_parse(&appl_args->srcmac, optarg)) {
				ODPH_ERR("wrong src mac:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'b':
			if (odph_eth_addr_parse(&appl_args->dstmac, optarg)) {
				ODPH_ERR("wrong dst mac:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 's':
			if (scan_ip(optarg, &appl_args->srcip) != 1) {
				ODPH_ERR("wrong src ip:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'd':
			if (scan_ip(optarg, &appl_args->dstip) != 1) {
				ODPH_ERR("wrong dst ip:%s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		case 'e':
			appl_args->srcport = (unsigned short)atoi(optarg);
			break;
		case 'j':
			appl_args->srcport_end = (unsigned short)atoi(optarg);
			break;
		case 'f':
			appl_args->dstport = (unsigned short)atoi(optarg);
			break;
		case 'k':
			appl_args->dstport_end = (unsigned short)atoi(optarg);
			break;
		case 'p':
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
				ODPH_ERR("should be root user\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'x':
			appl_args->udp_tx_burst = atoi(optarg);
			if (appl_args->udp_tx_burst >  MAX_UDP_TX_BURST) {
				ODPH_ERR("wrong UDP Tx burst size (max %d)\n",
					 MAX_UDP_TX_BURST);
				exit(EXIT_FAILURE);
			}
			break;
		case 'r':
			appl_args->rx_burst = atoi(optarg);
			if (appl_args->rx_burst >  MAX_RX_BURST) {
				ODPH_ERR("wrong Rx burst size (max %d)\n",
					 MAX_RX_BURST);
				exit(EXIT_FAILURE);
			}
			break;

		case 'y':
			appl_args->csum = 1;
			break;
		case 'z':
			appl_args->sched = 1;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	if (appl_args->num_workers < 0)
		appl_args->num_workers = 0;
	else if (appl_args->num_workers == 0 ||
		 appl_args->num_workers > MAX_WORKERS)
		appl_args->num_workers =  MAX_WORKERS;

	if (appl_args->if_count == 0 || appl_args->mode == -1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if ((appl_args->srcport != 0 && appl_args->srcport_end == 0) ||
	    (appl_args->srcport_end < appl_args->srcport))
		appl_args->srcport_end = appl_args->srcport;

	if ((appl_args->dstport != 0 && appl_args->dstport_end == 0) ||
	    (appl_args->dstport_end < appl_args->dstport))
		appl_args->dstport_end = appl_args->dstport;

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

	odp_sys_info_print();

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
		PRINT_APPL_MODE(APPL_MODE_UDP);
	else if (appl_args->mode == 1)
		PRINT_APPL_MODE(APPL_MODE_PING);
	else
		PRINT_APPL_MODE(APPL_MODE_RCV);
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
	       "    1.send ipv4 udp packets\n"
	       "      odp_generator -I eth0 --srcmac fe:0f:97:c9:e0:44  --dstmac 32:cb:9b:27:2f:1a --srcip 192.168.0.1 --dstip 192.168.0.2 -m u\n"
	       "    2.receive ipv4 packets\n"
	       "      odp_generator -I eth0 -m r\n"
	       "    3.work likes ping\n"
	       "      odp_generator -I eth0 --srcmac fe:0f:97:c9:e0:44  --dstmac 32:cb:9b:27:2f:1a --srcip 192.168.0.1 --dstip 192.168.0.2 --cpumask 0xc -m p\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -I, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "  -a, --srcmac src mac address\n"
	       "  -b, --dstmac dst mac address\n"
	       "  -s, --srcip src ip address\n"
	       "  -d, --dstip dst ip address\n"
	       "  -m, --mode work mode: send udp(u), receive(r), send icmp(p)\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -h, --help       Display help and exit.\n"
	       "  -e, --srcport udp source port start value\n"
	       "                 default is 0\n"
	       "  -j, --srcport_end udp source port end value\n"
	       "                 default is udp source port start value\n"
	       "  -f, --dstport udp destination port start value\n"
	       "                 default is 0\n"
	       "  -k, --dstport_end udp destination port end value\n"
	       "                 default is udp destination port start value\n"
	       "  -p, --packetsize payload length of the packets\n"
	       "  -t, --timeout only for ping mode, wait ICMP reply timeout seconds\n"
	       "  -i, --interval wait interval ms between sending each packet\n"
	       "                 default is 1000ms. 0 for flood mode\n"
	       "  -w, --workers specify number of workers need to be assigned to application\n"
	       "	         default is 1, 0 for all available\n"
	       "  -n, --count the number of packets to be send\n"
	       "  -c, --cpumask to set on cores\n"
	       "  -x, --udp_tx_burst size of UDP TX burst\n"
	       "  -r, --rx_burst size of RX burst\n"
	       "  -y, --csum use platform checksum support if available\n"
	       "	         default is disabled\n"
	       "  -z, --sched use scheduler API to receive packets\n"
	       "                 default is direct mode API\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	      );
}

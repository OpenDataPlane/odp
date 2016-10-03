/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>

#include <test_debug.h>

#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <odp/helper/tcp.h>

#include "odp_l3fwd_db.h"
#include "odp_l3fwd_lpm.h"

#define POOL_NUM_PKT	8192
#define POOL_SEG_LEN	1856
#define MAX_PKT_BURST	32

#define MAX_NB_WORKER	32
#define MAX_NB_PKTIO	32
#define MAX_NB_QUEUE	32
#define MAX_NB_QCONFS	1024
#define MAX_NB_ROUTE	32

#define INVALID_ID	(-1)
#define PRINT_INTERVAL	10	/* interval seconds of printing stats */

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

struct l3fwd_pktio_s {
	odp_pktio_t pktio;
	odph_ethaddr_t mac_addr;
	odp_pktin_queue_t ifin[MAX_NB_QUEUE];
	odp_pktout_queue_t ifout[MAX_NB_QUEUE];
	int nb_rxq;	/* capa max */
	int nb_txq;	/* capa max */
	int rxq_idx;	/* requested, maybe greater than nb_rxq */
	int txq_idx;	/* requested, maybe greater than nb_txq */
};

struct l3fwd_qconf_s {
	uint8_t if_idx;		/* port index */
	uint8_t rxq_idx;	/* recv queue index in a port */
	uint8_t core_idx;	/* this core should handle traffic */
};

struct thread_arg_s {
	uint64_t packets;
	uint64_t rx_drops;
	uint64_t tx_drops;
	struct {
		int nb_rxq;	/* number of rxq this thread will access */
		int rxq[MAX_NB_QUEUE];	/* rxq[i] is index in pktio.ifin[] */
		int txq_idx;	/* index in pktio.ifout[] */
	} pktio[MAX_NB_PKTIO];
	int nb_pktio;
	int thr_idx;
};

typedef struct {
	char *if_names[MAX_NB_PKTIO];
	int if_count;
	char *route_str[MAX_NB_ROUTE];
	int worker_count;
	struct l3fwd_qconf_s qconf_config[MAX_NB_QCONFS];
	int qconf_count;
	uint32_t duration; /* seconds to run */
	uint8_t hash_mode; /* 1:hash, 0:lpm */
	uint8_t dest_mac_changed[MAX_NB_PKTIO]; /* 1: dest mac from cmdline */
} app_args_t;

struct {
	app_args_t		cmd_args;
	struct l3fwd_pktio_s	l3fwd_pktios[MAX_NB_PKTIO];
	odph_odpthread_t	l3fwd_workers[MAX_NB_WORKER];
	struct thread_arg_s	worker_args[MAX_NB_WORKER];
	odph_ethaddr_t		eth_dest_mac[MAX_NB_PKTIO];

	/* forward func, hash or lpm */
	int (*fwd_func)(odp_packet_t pkt, int sif);
} global;

/** Global barrier to synchronize main and workers */
static odp_barrier_t barrier;
static int exit_threads;	/**< Break workers loop if set to 1 */

static int create_pktio(const char *name, odp_pool_t pool,
			struct l3fwd_pktio_s *fwd_pktio)
{
	odp_pktio_param_t pktio_param;
	odp_pktio_t pktio;
	odp_pktio_capability_t capa;
	int rc;

	odp_pktio_param_init(&pktio_param);

	pktio = odp_pktio_open(name, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		printf("Failed to open %s\n", name);
		return -1;
	}
	fwd_pktio->pktio = pktio;

	rc = odp_pktio_capability(pktio, &capa);
	if (rc) {
		printf("Error: pktio %s: unable to read capabilities!\n",
		       name);

		return -1;
	}

	fwd_pktio->nb_rxq = (int)capa.max_input_queues;
	fwd_pktio->nb_txq = (int)capa.max_output_queues;

	if (fwd_pktio->nb_rxq > MAX_NB_QUEUE)
		fwd_pktio->nb_rxq = MAX_NB_QUEUE;

	if (fwd_pktio->nb_txq > MAX_NB_QUEUE)
		fwd_pktio->nb_txq = MAX_NB_QUEUE;

	return 0;
}

static void setup_fwd_db(void)
{
	fwd_db_entry_t *entry;
	int if_idx;
	app_args_t *args;

	args = &global.cmd_args;
	if (args->hash_mode)
		init_fwd_hash_cache();
	else
		fib_tbl_init();

	for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
		if_idx = entry->oif_id;
		if (!args->hash_mode)
			fib_tbl_insert(entry->subnet.addr, if_idx,
				       entry->subnet.depth);
		if (args->dest_mac_changed[if_idx])
			global.eth_dest_mac[if_idx] = entry->dst_mac;
		else
			entry->dst_mac = global.eth_dest_mac[if_idx];
	}
}

/**
 * Decrement TTL and incrementally update checksum
 *
 * @param ip  IPv4 header
 */
static inline void ipv4_dec_ttl_csum_update(odph_ipv4hdr_t *ip)
{
	uint16_t a = ~odp_cpu_to_be_16(1 << 8);

	ip->ttl--;
	if (ip->chksum >= a)
		ip->chksum -= a;
	else
		ip->chksum += odp_cpu_to_be_16(1 << 8);
}

static int l3fwd_pkt_hash(odp_packet_t pkt, int sif)
{
	fwd_db_entry_t *entry;
	ipv4_tuple5_t key;
	odph_ethhdr_t *eth;
	odph_udphdr_t  *udp;
	odph_ipv4hdr_t *ip;
	uint32_t len;
	int dif;

	ip = odp_packet_l3_ptr(pkt, &len);
	key.dst_ip = odp_be_to_cpu_32(ip->dst_addr);
	key.src_ip = odp_be_to_cpu_32(ip->src_addr);
	key.proto = ip->proto;

	if (odp_packet_has_udp(pkt) ||
	    odp_packet_has_tcp(pkt)) {
		/* UDP or TCP*/
		void *ptr = odp_packet_l4_ptr(pkt, NULL);

		udp = (odph_udphdr_t *)ptr;
		key.src_port = odp_be_to_cpu_16(udp->src_port);
		key.dst_port = odp_be_to_cpu_16(udp->dst_port);
	} else {
		key.src_port = 0;
		key.dst_port = 0;
	}
	entry = find_fwd_db_entry(&key);
	ipv4_dec_ttl_csum_update(ip);
	eth = odp_packet_l2_ptr(pkt, NULL);
	if (entry) {
		eth->src = entry->src_mac;
		eth->dst = entry->dst_mac;
		dif = entry->oif_id;
	} else {
		/* no route, send by src port */
		eth->dst = eth->src;
		dif = sif;
	}

	return dif;
}

static int l3fwd_pkt_lpm(odp_packet_t pkt, int sif)
{
	odph_ipv4hdr_t *ip;
	odph_ethhdr_t *eth;
	uint32_t len;
	int dif;
	int ret;

	ip = odp_packet_l3_ptr(pkt, &len);
	ipv4_dec_ttl_csum_update(ip);
	eth = odp_packet_l2_ptr(pkt, NULL);

	/* network byte order maybe different from host */
	ret = fib_tbl_lookup(odp_be_to_cpu_32(ip->dst_addr), &dif);
	if (ret)
		dif = sif;

	eth->dst = global.eth_dest_mac[dif];
	eth->src = global.l3fwd_pktios[dif].mac_addr;

	return dif;
}

/**
 * Drop packets which input parsing marked as containing errors.
 *
 * Frees packets with error and modifies pkt_tbl[] to only contain packets with
 * no detected errors.
 *
 * @param pkt_tbl  Array of packets
 * @param num      Number of packets in pkt_tbl[]
 *
 * @return Number of packets dropped
 */
static inline int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned num)
{
	odp_packet_t pkt;
	unsigned dropped = 0;
	unsigned i, j;

	for (i = 0, j = 0; i < num; ++i) {
		pkt = pkt_tbl[i];

		if (odp_unlikely(odp_packet_has_error(pkt) ||
				 !odp_packet_has_ipv4(pkt))) {
			odp_packet_free(pkt);
			dropped++;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j - 1] = pkt;
		}
	}

	return dropped;
}

static void l3fwd_one_queue(uint32_t sif, int rxq_idx, void *thr_arg)
{
	odp_packet_t *tbl;
	odp_pktout_queue_t outq;
	odp_pktin_queue_t inq;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	struct thread_arg_s *arg;
	int pkts, drop, sent;
	int dst_port, dif;
	int i;

	arg = thr_arg;
	inq = global.l3fwd_pktios[sif].ifin[rxq_idx];
	pkts = odp_pktin_recv(inq, pkt_tbl, MAX_PKT_BURST);
	if (pkts <= 0)
		return;

	arg->packets += pkts;
	drop = drop_err_pkts(pkt_tbl, pkts);
	pkts -= drop;
	arg->rx_drops += drop;

	dif = global.fwd_func(pkt_tbl[0], sif);
	tbl = &pkt_tbl[0];
	while (pkts) {
		int txq_idx;

		dst_port = dif;
		for (i = 1; i < pkts; i++) {
			dif = global.fwd_func(tbl[i], sif);
			if (dif != dst_port)
				break;
		}

		txq_idx = arg->pktio[dst_port].txq_idx;
		outq = global.l3fwd_pktios[dst_port].ifout[txq_idx];
		sent = odp_pktout_send(outq, tbl, i);
		if (odp_unlikely(sent < i)) {
			sent = sent < 0 ? 0 : sent;
			odp_packet_free_multi(&tbl[sent], i - sent);
			arg->tx_drops += i - sent;
		}

		if (i < pkts)
			tbl += i;

		pkts -= i;
	}
}

static int run_worker(void *arg)
{
	int if_idx, rxq, nb_rxq;
	struct thread_arg_s *thr_arg = arg;

	odp_barrier_wait(&barrier);

	while (!exit_threads) {
		for (if_idx = 0; if_idx < thr_arg->nb_pktio; if_idx++) {
			nb_rxq = thr_arg->pktio[if_idx].nb_rxq;
			if (!nb_rxq || thr_arg->thr_idx == INVALID_ID)
				continue;

			for (rxq = 0; rxq < nb_rxq; rxq++) {
				int rxq_idx;

				rxq_idx = thr_arg->pktio[if_idx].rxq[rxq];
				l3fwd_one_queue(if_idx, rxq_idx, arg);
			}
		}
	}

	/* Make sure that latest stat writes are visible to other threads */
	odp_mb_full();

	return 0;
}

static int find_port_id_by_name(char *name, app_args_t *args)
{
	int i;

	if (!name)
		return -1;

	for (i = 0; i < args->if_count; i++) {
		if (!strcmp(name, args->if_names[i]))
			return i;
	}

	return -1;
}

/* split string into tokens */
static int split_string(char *str, int stringlen,
			char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (str == NULL || tokens == NULL)
		goto einval_error;

	for (i = 0; i < stringlen; i++) {
		if (str[i] == '\0' || tok >= maxtokens)
			break;
		if (tokstart) {
			tokstart = 0;
			tokens[tok++] = &str[i];
		}
		if (str[i] == delim) {
			str[i] = '\0';
			tokstart = 1;
		}
	}
	return tok;

einval_error:
	errno = EINVAL;
	return -1;
}

static int parse_config(char *cfg_str, app_args_t *args)
{
	char s[256];
	const char *p, *p0 = cfg_str;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_QUEUE,
		FLD_LCORE,
		FLD_LAST
	};
	unsigned long int_fld[FLD_LAST];
	char *str_fld[FLD_LAST];
	int i;
	unsigned size;
	int nb_qconfs = 0;
	struct l3fwd_qconf_s *qconf_array = &args->qconf_config[0];

	p = strchr(p0, '(');
	while (p != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		i = split_string(s, sizeof(s), str_fld, FLD_LAST, ',');
		if (i != FLD_LAST)
			return -1;
		for (i = 0; i < FLD_LAST; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}
		if (nb_qconfs >= MAX_NB_QCONFS) {
			printf("exceeded max number of queue params: %d\n",
			       nb_qconfs);
			return -1;
		}
		qconf_array[nb_qconfs].if_idx = (uint8_t)int_fld[FLD_PORT];
		qconf_array[nb_qconfs].rxq_idx = (uint8_t)int_fld[FLD_QUEUE];
		qconf_array[nb_qconfs].core_idx = (uint8_t)int_fld[FLD_LCORE];
		++nb_qconfs;

		p = strchr(p0, '(');
	}
	args->qconf_count = nb_qconfs;

	return 0;
}

static void print_usage(char *progname)
{
	printf("\n"
	       "ODP L3 forwarding application.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth0,eth1 -r 1.1.1.0/24,eth0 -r 2.2.2.0/24,eth1\n"
	       " In the above example,\n"
	       " eth0 will send pkts to eth1 and vice versa\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface eth interfaces (comma-separated, no spaces)\n"
	       "  -r, --route SubNet,Intf[,NextHopMAC]\n"
	       "	NextHopMAC can be optional\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -s, --style [lpm|hash], ip lookup method\n"
	       "	optional, default as lpm\n"
	       "  -d, --duration Seconds to run and print stats\n"
	       "	optional, default as 0, run forever\n"
	       "  -t, --thread Number of threads to do forwarding\n"
	       "	optional, default as availbe worker cpu count\n"
	       "  -q, --queue  Configure rx queue(s) for port\n"
	       "	optional, format: [(port, queue, thread),...]\n"
	       "	for example: -q '(0, 0, 1),(1,0,2)'\n"
	       "  -h, --help   Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}

static void parse_cmdline_args(int argc, char *argv[], app_args_t *args)
{
	int opt;
	int long_index;
	char *token, *local;
	size_t len, route_index = 0;
	int i, mem_failure = 0;

	static struct option longopts[] = {
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"route", required_argument, NULL, 'r'},	/* return 'r' */
		{"style", optional_argument, NULL, 's'},	/* return 's' */
		{"duration", optional_argument, NULL, 'd'},	/* return 'd' */
		{"thread", optional_argument, NULL, 't'},	/* return 't' */
		{"queue", optional_argument, NULL, 'q'},	/* return 'q' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	while (1) {
		opt = getopt_long(argc, argv, "+s:t:d:i:r:q:h",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		/* parse ip lookup method */
		case 's':
			if (!strcmp(optarg, "hash"))
				args->hash_mode = 1;
			break;
		/* parse number of worker threads to be run*/
		case 't':
			i = odp_cpu_count();
			args->worker_count = atoi(optarg);
			if (args->worker_count > i) {
				printf("Too many threads,"
				       "truncate to cpu count: %d\n", i);
				args->worker_count = i;
			}

			break;

		/* parse seconds to run */
		case 'd':
			args->duration = atoi(optarg);
			break;

		/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			local = malloc(len);
			if (!local) {
				print_usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(local, optarg);
			for (token = strtok(local, ","), i = 0;
			     token != NULL;
			     token = strtok(NULL, ","), i++)
				;

			if (i == 0) {
				print_usage(argv[0]);
				free(local);
				exit(EXIT_FAILURE);
			} else if (i > MAX_NB_PKTIO) {
				printf("too many ports specified, "
				       "truncated to %d", MAX_NB_PKTIO);
			}
			args->if_count = i;

			/* store the if names (reset names string) */
			strcpy(local, optarg);
			for (token = strtok(local, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				args->if_names[i] = token;
			}
			break;

		/*Configure Route in forwarding database*/
		case 'r':
			if (route_index >= MAX_NB_ROUTE) {
				printf("No more routes can be added\n");
				break;
			}
			local = calloc(1, strlen(optarg) + 1);
			if (!local) {
				mem_failure = 1;
				break;
			}
			memcpy(local, optarg, strlen(optarg));
			local[strlen(optarg)] = '\0';
			args->route_str[route_index++] = local;
			break;

		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		case 'q':
			parse_config(optarg, args);
			break;

		default:
			break;
		}
	}

	/* checking arguments */
	if (args->if_count == 0) {
		printf("\nNo option -i specified.\n");
		goto out;
	}

	if (args->route_str[0] == NULL) {
		printf("\nNo option -r specified.\n");
		goto out;
	}

	if (mem_failure == 1) {
		printf("\nAllocate memory failure.\n");
		goto out;
	}
	optind = 1;		/* reset 'extern optind' from the getopt lib */
	return;

out:
	print_usage(argv[0]);
	exit(EXIT_FAILURE);
}

static void print_info(char *progname, app_args_t *args)
{
	int i;

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "ODP impl name:	 %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %" PRIu64 "\n"
	       "Cache line size: %i\n"
	       "CPU count:       %i\n"
	       "\n",
	       odp_version_api_str(), odp_version_impl_name(),
	       odp_cpu_model_str(), odp_cpu_hz_max(),
	       odp_sys_cache_line_size(), odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IP Lookup:	 %s\n"
	       "IF Count:        %i\n"
	       "Using IFs:      ",
	       progname,
	       args->hash_mode ? "hash" : "lpm",
	       args->if_count);

	for (i = 0; i < args->if_count; ++i)
		printf(" %s", args->if_names[i]);

	printf("\n\n");
	fflush(NULL);
}

/**
 * Setup rx and tx queues, distribute them among threads.
 *
 * If no q argument, the queues are distribute among threads as default.
 * The thread take one rx queue of a port one time as round-robin order.
 * One txq for each thread on each port
 */
static void setup_worker_qconf(app_args_t *args)
{
	int nb_worker, if_count;
	int i, j, rxq_idx;
	struct thread_arg_s *arg;
	struct l3fwd_pktio_s *port;
	uint8_t queue_mask[MAX_NB_PKTIO][MAX_NB_QUEUE];

	nb_worker = args->worker_count;
	if_count = args->if_count;

	/* distribute rx queues among threads as round-robin */
	if (!args->qconf_count) {
		if (nb_worker > if_count) {
			for (i = 0; i < nb_worker; i++) {
				arg = &global.worker_args[i];
				arg->thr_idx = i;
				j = i % if_count;
				port = &global.l3fwd_pktios[j];
				rxq_idx = arg->pktio[j].nb_rxq;
				arg->pktio[j].rxq[rxq_idx] =
					port->rxq_idx % port->nb_rxq;
				arg->pktio[j].nb_rxq++;
				port->rxq_idx++;
			}
		} else {
			for (i = 0; i < if_count; i++) {
				j = i % nb_worker;
				arg = &global.worker_args[j];
				arg->thr_idx = j;
				port = &global.l3fwd_pktios[i];
				rxq_idx = arg->pktio[i].nb_rxq;
				arg->pktio[i].rxq[rxq_idx] =
					port->rxq_idx % port->nb_rxq;
				arg->pktio[i].nb_rxq++;
				port->rxq_idx++;
			}
		}
	}

	/* distribute rx queues among threads as q argument */
	memset(queue_mask, 0, sizeof(queue_mask));
	for (i = 0; i < args->qconf_count; i++) {
		struct l3fwd_qconf_s *q;

		q = &args->qconf_config[i];
		if (q->core_idx >= nb_worker || q->if_idx >= if_count)
			LOG_ABORT("Error queue (%d, %d, %d), max port: "
				  "%d, max core: %d\n", q->if_idx, q->rxq_idx,
				  q->core_idx, args->if_count - 1,
				  args->worker_count - 1);

		/* check if one queue is configured twice or more */
		if (queue_mask[q->if_idx][q->rxq_idx])
			LOG_ABORT("Error queue (%d, %d, %d), reconfig queue\n",
				  q->if_idx, q->rxq_idx, q->core_idx);
		queue_mask[q->if_idx][q->rxq_idx] = 1;

		port = &global.l3fwd_pktios[q->if_idx];
		if (port->rxq_idx < q->rxq_idx)
			LOG_ABORT("Error queue (%d, %d, %d), queue should be"
				  " in sequence and start from 0, queue %d\n",
				  q->if_idx, q->rxq_idx, q->core_idx,
				  q->rxq_idx);

		if (q->rxq_idx > port->nb_rxq) {
			LOG_ABORT("Error queue (%d, %d, %d), max queue %d\n",
				  q->if_idx, q->rxq_idx, q->core_idx,
				  port->nb_rxq - 1);
		}
		port->rxq_idx = q->rxq_idx + 1;

		/* put the queue into worker_args */
		arg = &global.worker_args[q->core_idx];
		rxq_idx =  arg->pktio[q->if_idx].nb_rxq;
		arg->pktio[q->if_idx].rxq[rxq_idx] = q->rxq_idx;
		arg->pktio[q->if_idx].nb_rxq++;
		arg->thr_idx = q->core_idx;
	}

	/* distribute tx queues among threads */
	for (i = 0; i < args->worker_count; i++) {
		arg = &global.worker_args[i];
		for (j = 0; j < args->if_count; j++) {
			port = &global.l3fwd_pktios[j];
			arg->pktio[j].txq_idx =
				port->txq_idx % port->nb_txq;
			port->txq_idx++;
		}
	}

	/* config and initialize rx and tx queues. */
	for (i = 0; i < if_count; i++) {
		odp_pktin_queue_param_t in_queue_param;
		odp_pktout_queue_param_t out_queue_param;
		odp_pktin_queue_t *inq;
		odp_pktout_queue_t *outq;
		const char *name;
		int nb_rxq, nb_txq;

		port = &global.l3fwd_pktios[i];
		name = args->if_names[i];
		odp_pktin_queue_param_init(&in_queue_param);
		odp_pktout_queue_param_init(&out_queue_param);

		in_queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
		out_queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;

		in_queue_param.hash_enable = 1;
		in_queue_param.hash_proto.proto.ipv4 = 1;
		in_queue_param.hash_proto.proto.ipv4_tcp = 1;
		in_queue_param.hash_proto.proto.ipv4_udp = 1;

		in_queue_param.num_queues = port->rxq_idx;
		if (port->rxq_idx > port->nb_rxq) {
			in_queue_param.num_queues = port->nb_rxq;
			in_queue_param.op_mode = ODP_PKTIO_OP_MT;
		}

		if (odp_pktin_queue_config(port->pktio, &in_queue_param))
			LOG_ABORT("Fail to config input queue for port %s\n",
				  name);

		out_queue_param.num_queues = port->txq_idx;
		if (port->txq_idx > port->nb_txq) {
			out_queue_param.num_queues = port->nb_txq;
			out_queue_param.op_mode = ODP_PKTIO_OP_MT;
		}
		if (odp_pktout_queue_config(port->pktio, &out_queue_param))
			LOG_ABORT("Fail to config output queue for port %s\n",
				  name);

		inq = port->ifin;
		nb_rxq = in_queue_param.num_queues;
		if (odp_pktin_queue(port->pktio, inq, nb_rxq) != nb_rxq)
			LOG_ABORT("Fail to set pktin queue for port %s\n",
				  name);

		outq = port->ifout;
		nb_txq = out_queue_param.num_queues;
		if (odp_pktout_queue(port->pktio, outq, nb_txq) != nb_txq)
			LOG_ABORT("Fail to set pktout queue for port %s\n",
				  name);
	}
}

static void print_qconf_table(app_args_t *args)
{
	int i, j, k, qid;
	char buf[32];
	struct thread_arg_s *thr_arg;

	printf("Rx Queue table\n"
	       "-----------------\n"
	       "%-32s%-16s%-16s\n",
	       "port/id", "rxq", "thread");

	for (i = 0; i < args->worker_count; i++) {
		thr_arg = &global.worker_args[i];
		for (j = 0; j < args->if_count; j++) {
			if (!thr_arg->pktio[j].nb_rxq)
				continue;

			snprintf(buf, 32, "%s/%d", args->if_names[j], j);
			for (k = 0; k < MAX_NB_QUEUE; k++) {
				qid = thr_arg->pktio[j].rxq[k];
				if (qid != INVALID_ID)
					printf("%-32s%-16d%-16d\n", buf, qid,
					       thr_arg->thr_idx);
			}
		}
	}
	printf("\n");
	fflush(NULL);
}

/**
 *  Print statistics
 *
 * @param num_workers Number of worker threads
 * @param duration Number of seconds to loop in
 * @param timeout Number of seconds for stats calculation
 *
 */
static int print_speed_stats(int num_workers, int duration, int timeout)
{
	uint64_t pkts = 0;
	uint64_t pkts_prev = 0;
	uint64_t pps;
	uint64_t rx_drops, tx_drops;
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
	odp_barrier_wait(&barrier);

	do {
		pkts = 0;
		rx_drops = 0;
		tx_drops = 0;
		sleep(timeout);

		for (i = 0; i < num_workers; i++) {
			pkts += global.worker_args[i].packets;
			rx_drops += global.worker_args[i].rx_drops;
			tx_drops += global.worker_args[i].tx_drops;
		}
		if (stats_enabled) {
			pps = (pkts - pkts_prev) / timeout;
			if (pps > maximum_pps)
				maximum_pps = pps;
			printf("%" PRIu64 " pps, %" PRIu64 " max pps, ",  pps,
			       maximum_pps);

			printf(" %" PRIu64 " rx drops, %" PRIu64 " tx drops\n",
			       rx_drops, tx_drops);

			pkts_prev = pkts;
		}
		elapsed += timeout;
	} while (loop_forever || (elapsed < duration));

	if (stats_enabled)
		printf("TEST RESULT: %" PRIu64 " maximum packets per second.\n",
		       maximum_pps);

	return pkts > 100 ? 0 : -1;
}

int main(int argc, char **argv)
{
	odph_odpthread_t thread_tbl[MAX_NB_WORKER];
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_instance_t instance;
	odph_odpthread_params_t thr_params;
	odp_cpumask_t cpumask;
	int cpu, i, j, nb_worker;
	uint8_t mac[ODPH_ETHADDR_LEN];
	uint8_t *dst_mac;
	app_args_t *args;
	struct thread_arg_s *thr_arg;
	char *oif;

	if (odp_init_global(&instance, NULL, NULL)) {
		printf("Error: ODP global init failed.\n");
		exit(1);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: ODP local init failed.\n");
		exit(1);
	}

	/* Clear global argument and initialize the dest mac as 2:0:0:0:0:x */
	memset(&global, 0, sizeof(global));
	mac[0] = 2;
	for (i = 0; i < MAX_NB_PKTIO; i++) {
		mac[ODPH_ETHADDR_LEN - 1] = (uint8_t)i;
		memcpy(global.eth_dest_mac[i].addr, mac, ODPH_ETHADDR_LEN);
	}

	/* Initialize the thread arguments */
	for (i = 0; i < MAX_NB_WORKER; i++) {
		thr_arg = &global.worker_args[i];
		for (j = 0; j < MAX_NB_PKTIO; j++) {
			thr_arg->thr_idx = INVALID_ID;
			thr_arg->pktio[j].txq_idx = INVALID_ID;
			memset(thr_arg->pktio[j].rxq, INVALID_ID,
			       sizeof(thr_arg->pktio[j].rxq));
		}
	}

	/* Parse cmdline arguments */
	args = &global.cmd_args;
	parse_cmdline_args(argc, argv, args);

	/* Init l3fwd table */
	init_fwd_db();

	/* Add route into table */
	for (i = 0; i < MAX_NB_ROUTE; i++) {
		if (args->route_str[i]) {
			create_fwd_db_entry(args->route_str[i], &oif, &dst_mac);
			if (oif == NULL) {
				printf("Error: fail to create route entry.\n");
				exit(1);
			}

			j = find_port_id_by_name(oif, args);
			if (j == -1) {
				printf("Error: port %s not used.\n", oif);
				exit(1);
			}

			if (dst_mac)
				args->dest_mac_changed[j] = 1;
		}
	}

	print_info(NO_PATH(argv[0]), args);

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = POOL_SEG_LEN;
	params.pkt.len     = POOL_SEG_LEN;
	params.pkt.num     = POOL_NUM_PKT;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &params);

	if (pool == ODP_POOL_INVALID) {
		printf("Error: packet pool create failed.\n");
		exit(1);
	}

	/* Resolve fwd db*/
	for (i = 0; i < args->if_count; i++) {
		struct l3fwd_pktio_s *port;
		char *if_name;

		if_name = args->if_names[i];
		port = &global.l3fwd_pktios[i];
		if (create_pktio(if_name, pool, port)) {
			printf("Error: create pktio %s\n", if_name);
			exit(1);
		}
		odp_pktio_mac_addr(port->pktio, mac, ODPH_ETHADDR_LEN);
		resolve_fwd_db(if_name, i, mac);
		memcpy(port->mac_addr.addr, mac, ODPH_ETHADDR_LEN);
	}
	setup_fwd_db();
	dump_fwd_db();

	/* Dicide available workers */
	nb_worker = MAX_NB_WORKER;
	if (args->worker_count)
		nb_worker = args->worker_count;
	nb_worker = odp_cpumask_default_worker(&cpumask, nb_worker);
	args->worker_count = nb_worker;

	/* Setup rx and tx queues for each port */
	setup_worker_qconf(args);
	print_qconf_table(args);

	/* Decide ip lookup method */
	if (args->hash_mode)
		global.fwd_func = l3fwd_pkt_hash;
	else
		global.fwd_func = l3fwd_pkt_lpm;

	/* Start all the available ports */
	for (i = 0; i < args->if_count; i++) {
		struct l3fwd_pktio_s *port;
		char *if_name;
		char buf[32];

		if_name = args->if_names[i];
		port = &global.l3fwd_pktios[i];
		/* start pktio */
		if (odp_pktio_start(port->pktio)) {
			printf("unable to start pktio: %s\n", if_name);
			exit(1);
		}

		sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
			port->mac_addr.addr[0],
			port->mac_addr.addr[1],
			port->mac_addr.addr[2],
			port->mac_addr.addr[3],
			port->mac_addr.addr[4],
			port->mac_addr.addr[5]);
		printf("start pktio: %s, mac %s\n", if_name, buf);
	}

	odp_barrier_init(&barrier, nb_worker + 1);

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.start    = run_worker;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;

	memset(thread_tbl, 0, sizeof(thread_tbl));
	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < nb_worker; i++) {
		struct thread_arg_s *arg;
		odp_cpumask_t thr_mask;

		arg = &global.worker_args[i];
		arg->nb_pktio = args->if_count;
		odp_cpumask_zero(&thr_mask);
		odp_cpumask_set(&thr_mask, cpu);
		thr_params.arg = arg;
		odph_odpthreads_create(&thread_tbl[i], &thr_mask,
				       &thr_params);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	print_speed_stats(nb_worker, args->duration, PRINT_INTERVAL);
	exit_threads = 1;

	/* wait for other threads to join */
	for (i = 0; i < nb_worker; i++)
		odph_odpthreads_join(&thread_tbl[i]);

	/* if_names share a single buffer, so only one free */
	free(args->if_names[0]);

	for (i = 0; i < MAX_NB_ROUTE; i++)
		free(args->route_str[i]);

	if (odp_pool_destroy(pool)) {
		printf("Error: pool destroy\n");
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

	return 0;
}

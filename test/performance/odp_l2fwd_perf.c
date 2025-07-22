/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

/**
 * @example odp_l2fwd_perf.c
 *
 * Simple L2 forwarding benchmark. Receives packets from a set of interfaces and forwards them
 * according to configuration. Can work in direct and scheduling modes. Existing fast path handling
 * functions should be kept as is, new features should be handled in new separate functions in
 * order for the tester to provide more comparable results.
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define PROG_NAME "odp_l2fwd_perf"
#define PAIR_DELIMITER "@"
#define IF_DELIMITER ","
#define MAC_COMMON 0x2

#define MAX_IFS 8U
#define MAX_QS 32U
#define MAX_WORKERS ((uint32_t)(ODP_THREAD_COUNT_MAX - 1))

enum {
	DIRECT,
	SCHED_PARALLEL,
	SCHED_ATOMIC,
	SCHED_ORDERED
};

#define DEF_MODE DIRECT
#define DEF_BURST 32U
#define DEF_CNT 32768U
#define DEF_LEN 1536U
#define DEF_RUNTIME 0U
#define DEF_WORKERS 1U

#define GIGAS 1000000000U
#define MEGAS 1000000U
#define KILOS 1000U

typedef struct {
	uint32_t num_pkts;
	uint32_t pkt_len;
} dynamic_defs_t;

typedef enum {
	PRS_OK,
	PRS_NOK,
	PRS_TERM
} parse_result_t;

typedef struct {
	uint64_t tm_ns;
	uint64_t tx;
	uint64_t tx_drops;
} stats_t;

typedef struct pktio_s pktio_t;

typedef struct pktio_s {
	odp_pktin_queue_t in_qs[MAX_QS];
	odp_pktout_queue_t out_qs[MAX_QS];
	odp_pktio_t handle;
	pktio_t *dst;
	odph_ethaddr_t src_mac;
	odph_ethaddr_t dst_mac;
	char *name;
	char *dst_name;
	uint8_t num_in_qs;
	uint8_t num_out_qs;
} pktio_t;

typedef struct {
	pktio_t *pktio;
	/* Poll ID to determine which input queue this worker will use for this packet I/O. */
	uint8_t rx_poll;
	/* Poll ID to determine which output queue this worker will use for the destination of this
	 * packet I/O. */
	uint8_t tx_poll;
} worker_pktio_t;

typedef struct prog_config_s prog_config_t;

typedef struct ODP_ALIGNED_CACHE {
	worker_pktio_t pktios[MAX_IFS];
	stats_t stats;
	prog_config_t *prog_config;
	uint8_t num_ifs;
} worker_config_t;

typedef struct prog_config_s {
	odph_thread_t thread_tbl[MAX_WORKERS];
	worker_config_t worker_config[MAX_WORKERS];
	pktio_t pktios[MAX_IFS];
	dynamic_defs_t dyn_defs;
	odp_instance_t odp_instance;
	odp_cpumask_t worker_mask;
	odp_barrier_t init_barrier;
	odp_barrier_t term_barrier;
	odp_atomic_u32_t is_running;
	odp_pool_t pool;
	uint32_t burst_size;
	uint32_t num_pkts;
	uint32_t pkt_len;
	uint32_t orig_in_mtu;
	uint32_t orig_out_mtu;
	uint32_t mtu;
	uint32_t runtime;
	uint32_t num_workers;
	uint8_t num_ifs;
	uint8_t mode;
	uint8_t orig_is_promisc;
	uint8_t is_promisc;
	uint8_t is_mac_mod;
} prog_config_t;

typedef struct {
	struct {
		odp_pktin_queue_t pktin;
		odp_pktout_queue_t pktout;
		odph_ethaddr_t src_mac;
		odph_ethaddr_t dst_mac;
	} tbl[MAX_IFS];
} dir_fwd_tbl_t;

typedef struct {
	struct {
		odp_pktout_queue_t pktout;
		odph_ethaddr_t src_mac;
		odph_ethaddr_t dst_mac;
	 } tbl[ODP_PKTIO_MAX_INDEX + 1];
} scd_fwd_tbl_t;

typedef int (*run_func_t)(void *arg);

static prog_config_t *prog_conf;

static void terminate(int signal ODP_UNUSED)
{
	odp_atomic_store_u32(&prog_conf->is_running, 0U);
}

static void init_config(prog_config_t *config)
{
	odp_pool_capability_t pool_capa;
	pktio_t *pktio;

	if (odp_pool_capability(&pool_capa) == 0) {
		config->dyn_defs.num_pkts = pool_capa.pkt.max_num > 0U ?
						ODPH_MIN(pool_capa.pkt.max_num, DEF_CNT) : DEF_CNT;
		config->dyn_defs.pkt_len = pool_capa.pkt.max_len > 0U ?
						ODPH_MIN(pool_capa.pkt.max_len, DEF_LEN) : DEF_LEN;
	}

	config->pool = ODP_POOL_INVALID;
	config->burst_size = DEF_BURST;
	config->num_pkts = config->dyn_defs.num_pkts;
	config->pkt_len = config->dyn_defs.pkt_len;
	config->runtime = DEF_RUNTIME;
	config->num_workers = DEF_WORKERS;
	config->mode = DEF_MODE;
	config->is_mac_mod = 1U;

	for (uint32_t i = 0U; i < MAX_IFS; ++i) {
		pktio = &config->pktios[i];

		pktio->handle = ODP_PKTIO_INVALID;
		pktio->dst = pktio;
		pktio->dst_mac.addr[0U] = MAC_COMMON;
		pktio->dst_mac.addr[5U] = i + 1U;
	}
}

static void parse_interfaces(prog_config_t *config, const char *optarg)
{
	char *tmp_str = strdup(optarg), *tmp;

	if (tmp_str == NULL)
		ODPH_ABORT("Out of memory\n");

	tmp = strtok(tmp_str, IF_DELIMITER);

	while (tmp && config->num_ifs < MAX_IFS) {
		tmp = strdup(tmp);

		if (tmp == NULL)
			ODPH_ABORT("Out of memory\n");

		config->pktios[config->num_ifs].name = tmp;
		++config->num_ifs;
		tmp = strtok(NULL, IF_DELIMITER);
	}

	free(tmp_str);
}

static odp_bool_t parse_mac_and_port(pktio_t *pktio, const char *pair)
{
	const char *pos = strstr(pair, PAIR_DELIMITER);
	uint32_t size;

	if (pos == NULL)
		return false;

	size = pos - pair + 1U;
	pktio->dst_name = strdup(pair + size);

	if (pktio->dst_name == NULL)
		ODPH_ABORT("Out of memory\n");

	char mac[size];

	odph_strcpy(mac, pair, size);

	/* Temporarily save to 'src_mac' until destination binding. */
	if (odph_eth_addr_parse(&pktio->src_mac, mac) < 0) {
		ODPH_ERR("Warning: unable to parse portmap entry (%s)\n", pktio->dst_name);
		free(pktio->dst_name);
		pktio->dst_name = NULL;
		return false;
	}

	return true;
}

static void parse_portmap(prog_config_t *config, const char *optarg)
{
	char *tmp_str = strdup(optarg);
	const char *tmp;
	uint32_t i = 0U;

	if (tmp_str == NULL)
		ODPH_ABORT("Out of memory\n");

	tmp = strtok(tmp_str, IF_DELIMITER);

	while (tmp && i < MAX_IFS) {
		if (parse_mac_and_port(&config->pktios[i], tmp))
			++i;

		tmp = strtok(NULL, IF_DELIMITER);
	}

	free(tmp_str);
}

static void print_usage(const dynamic_defs_t *dyn_defs)
{
	printf("\n"
	       "Simple L2 forwarder.\n"
	       "\n"
	       "Usage: %s [OPTIONS]\n", PROG_NAME);
	printf("\n"
	       "  E.g. %s -i eth0\n"
	       "       %s -i eth0,eth1 -p 11:22:33:44:55:66@eth1,66:55:44:33:22:11@eth0 -b 16\n",
	       PROG_NAME, PROG_NAME);
	printf("\n"
	       "Mandatory OPTIONS:\n"
	       "\n"
	       "  -i, --interfaces   Ethernet interfaces for packet I/O, '%s'-separated, no\n"
	       "                     whitespaces anywhere. By default, packets are looped back.\n"
	       "                     This can be overridden with '--portmap'. Maximum\n"
	       "                     interface count is %u.\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "\n"
	       "  -m, --mode         Packet input mode. %u by default.\n"
	       "                         0: direct\n"
	       "                         1: scheduled with parallel queues\n"
	       "                         2: scheduled with atomic queues\n"
	       "                         3: scheduled with ordered queues\n"
	       "                     Queue per direction per worker is always attempted. Output\n"
	       "                     is always in direct mode.\n"
	       "  -p, --portmap      List of destination MAC address and port pairs for passed\n"
	       "                     interfaces, MAC address and the port should be\n"
	       "                     '%s'-separated, the pairs '%s'-separated, no whitespaces\n"
	       "                     anywhere. Ordering follows the '--interface' option, e.g.\n"
	       "                     passing '-i eth0%seth1' and\n"
	       "                     '-p 11:22:33:44:55:66%seth1%s66:55:44:33:22:11%seth0' would\n"
	       "                     result in eth0 sending packets to eth1 with source MAC of\n"
	       "                     port eth0 and destination MAC of '11:22:33:44:55:66' and\n"
	       "                     eth1 to eth0 with source MAC of eth1 and destination MAC of\n"
	       "                     '66:55:44:33:22:11'.\n"
	       "  -b, --burst_rx     Receive burst size. %u by default.\n"
	       "  -n, --num_pkts     Number of packet buffers allocated for packet I/O pool.\n"
	       "                     %u by default.\n"
	       "  -l, --pkt_len      Maximum size of packet buffers in packet I/O pool. %u by\n"
	       "                     default.\n"
	       "  -M, --mtu          Interface MTU in bytes. Interface specific by default.\n"
	       "  -P, --promisc_mode Enable promiscuous mode.\n"
	       "  -t, --time         Time in seconds to run. 0 means infinite. %u by default.\n"
	       "  -s, --no_mac_mod   Disable source and destination MAC address modification.\n"
	       "  -c, --worker_count Number of workers. Workers are assigned to handle\n"
	       "                     interfaces in round-robin fashion. E.g. with two interfaces\n"
	       "                     eth0 and eth1 and with 5 workers, eth0 would be handled by\n"
	       "                     worker indexes 0, 2 and 4 and eth1 by worker indexes 1 and\n"
	       "                     3. Assignment may be affected by '--portmap'. %u workers by\n"
	       "                     default.\n"
	       "  -h, --help         This help.\n"
	       "\n", IF_DELIMITER, MAX_IFS, DEF_MODE, PAIR_DELIMITER, IF_DELIMITER, IF_DELIMITER,
	       PAIR_DELIMITER, IF_DELIMITER, PAIR_DELIMITER, DEF_BURST, dyn_defs->num_pkts,
	       dyn_defs->pkt_len, DEF_RUNTIME, DEF_WORKERS);
}

static parse_result_t check_options(prog_config_t *config)
{
	odp_pool_capability_t pool_capa;
	uint32_t max_workers;

	if (config->num_ifs == 0U) {
		ODPH_ERR("Invalid number of interfaces: %u (min: 1, max: %u)\n", config->num_ifs,
			 MAX_IFS);
		return PRS_NOK;
	}

	if (config->mode != DIRECT && config->mode != SCHED_PARALLEL &&
	    config->mode != SCHED_ATOMIC && config->mode != SCHED_ORDERED) {
		ODPH_ERR("Invalid packet input mode: %u\n", config->mode);
		return PRS_NOK;
	}

	if (config->burst_size == 0U) {
		ODPH_ERR("Invalid burst size: %u (min: 1)\n", config->burst_size);
		return PRS_NOK;
	}

	if (odp_pool_capability(&pool_capa) < 0) {
		ODPH_ERR("Error querying pool capabilities\n");
		return PRS_NOK;
	}

	if (config->num_pkts == 0U ||
	    (pool_capa.pkt.max_num > 0U && config->num_pkts > pool_capa.pkt.max_num)) {
		ODPH_ERR("Invalid pool packet count: %u (min: 1, max: %u)\n", config->num_pkts,
			 pool_capa.pkt.max_num);
		return PRS_NOK;
	}

	if (config->pkt_len == 0U ||
	    (pool_capa.pkt.max_len > 0U && config->pkt_len > pool_capa.pkt.max_len)) {
		ODPH_ERR("Invalid pool packet length: %u (min: 1, max: %u)\n", config->pkt_len,
			 pool_capa.pkt.max_len);
		return PRS_NOK;
	}

	max_workers = ODPH_MIN(MAX_WORKERS, (uint32_t)odp_cpumask_default_worker(NULL, 0));

	if (config->num_workers == 0U || config->num_workers > max_workers) {
		ODPH_ERR("Invalid worker count: %u (min: 1, max: %u)\n", config->num_workers,
			 max_workers);
		return PRS_NOK;
	}

	(void)odp_cpumask_default_worker(&config->worker_mask, config->num_workers);

	return PRS_OK;
}

static parse_result_t parse_options(int argc, char **argv, prog_config_t *config)
{
	int opt;

	static const struct option longopts[] = {
		{ "interfaces", required_argument, NULL, 'i' },
		{ "mode", required_argument, NULL, 'm' },
		{ "portmap", required_argument, NULL, 'p' },
		{ "burst_rx", required_argument, NULL, 'b' },
		{ "num_pkts", required_argument, NULL, 'n' },
		{ "pkt_len", required_argument, NULL, 'l' },
		{ "mtu", required_argument, NULL, 'M' },
		{ "promisc_mode", no_argument, NULL, 'P' },
		{ "time", required_argument, NULL, 't' },
		{ "no_mac_mod", no_argument, NULL, 's' },
		{ "worker_count", required_argument, NULL, 'c' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "i:m:p:b:n:l:M:Pt:sc:h";

	init_config(config);

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'i':
			parse_interfaces(config, optarg);
			break;
		case 'm':
			config->mode = atoi(optarg);
			break;
		case 'p':
			parse_portmap(config, optarg);
			break;
		case 'b':
			config->burst_size = atoi(optarg);
			break;
		case 'n':
			config->num_pkts = atoi(optarg);
			break;
		case 'l':
			config->pkt_len = atoi(optarg);
			break;
		case 'M':
			config->mtu = atoi(optarg);
			break;
		case 'P':
			config->is_promisc = 1U;
			break;
		case 't':
			config->runtime = atoi(optarg);
			break;
		case 's':
			config->is_mac_mod = false;
			break;
		case 'c':
			config->num_workers = atoi(optarg);
			break;
		case 'h':
			print_usage(&config->dyn_defs);
			return PRS_TERM;
		case '?':
		default:
			print_usage(&config->dyn_defs);
			return PRS_NOK;
		}
	}

	return check_options(config);
}

static parse_result_t setup_program(int argc, char **argv, prog_config_t *config)
{
	struct sigaction action = { .sa_handler = terminate };

	odp_atomic_init_u32(&config->is_running, 1U);

	if (sigemptyset(&action.sa_mask) == -1 || sigaddset(&action.sa_mask, SIGINT) == -1 ||
	    sigaddset(&action.sa_mask, SIGTERM) == -1 ||
	    sigaddset(&action.sa_mask, SIGHUP) == -1 || sigaction(SIGINT, &action, NULL) == -1 ||
	    sigaction(SIGTERM, &action, NULL) == -1 || sigaction(SIGHUP, &action, NULL) == -1) {
		ODPH_ERR("Error installing signal handler\n");
		return PRS_NOK;
	}

	return parse_options(argc, argv, config);
}

static void bind_destinations(pktio_t *pktios, uint8_t num)
{
	pktio_t *pktio_src, *pktio_dst;

	for (uint8_t i = 0U; i < num; ++i) {
		pktio_src = &pktios[i];

		for (uint8_t j = 0U; j < num; ++j) {
			pktio_dst = &pktios[j];

			if (pktio_src->dst_name != NULL &&
			    strcmp(pktio_src->dst_name, pktio_dst->name) == 0) {
				pktio_src->dst = pktio_dst;
				/* Copy the actual destination MAC as the 'dst_mac' that was
				 * earlier saved to source's 'src_mac'. */
				pktio_dst->dst_mac = pktio_src->src_mac;
				break;
			}
		}
	}
}

static worker_pktio_t *get_destination(const pktio_t *pktio, worker_pktio_t *pktios, uint8_t num)
{
	worker_pktio_t *w_pktio;

	for (uint8_t i = 0U; i < num; ++i) {
		w_pktio = &pktios[i];

		if (pktio == w_pktio->pktio->dst)
			return w_pktio;
	}

	return NULL;
}

static void bind_workers(prog_config_t *config)
{
	const uint32_t num_workers = config->num_workers, num_ifs = config->num_ifs;
	uint32_t max, min, i = 0U, j = 0U, *work_idx_ptr, *pktio_idx_ptr;
	worker_config_t *worker;
	worker_pktio_t *w_pktio;
	pktio_t *pktio;

	if (num_workers >= num_ifs) {
		max = num_workers;
		min = num_ifs;
		work_idx_ptr = &i;
		pktio_idx_ptr = &j;
	} else {
		max = num_ifs;
		min = num_workers;
		work_idx_ptr = &j;
		pktio_idx_ptr = &i;
	}

	/* Assign workers to packet I/Os. Based on worker and packet I/O counts, the outer loop
	 * will be looping the one with greater count and the inner with lesser count. */
	for (; i < max; ++i) {
		if (j == min)
			j = 0U;

		worker = &config->worker_config[*work_idx_ptr];
		worker->pktios[worker->num_ifs++].pktio = &config->pktios[*pktio_idx_ptr];
		++j;
	}

	/* Check how many workers will end up polling a certain packet I/O input and increase input
	 * queue count for that packet I/O accordingly. */
	for (i = 0U; i < num_workers; ++i) {
		worker = &config->worker_config[i];

		for (j = 0U; j < worker->num_ifs; ++j) {
			w_pktio = &worker->pktios[j];
			++w_pktio->pktio->num_in_qs;
			w_pktio->rx_poll = w_pktio->pktio->num_in_qs;
		}
	}

	/* Check how many workers will end up outputting through a certain packet I/O and increase
	 * output queue count for that packet I/O accordingly. */
	for (i = 0U; i < num_ifs; ++i) {
		pktio = &config->pktios[i];

		for (j = 0U; j < num_workers; ++j) {
			worker = &config->worker_config[j];
			w_pktio = get_destination(pktio, worker->pktios, worker->num_ifs);

			if (w_pktio != NULL) {
				++pktio->num_out_qs;
				w_pktio->tx_poll = pktio->num_out_qs;
			}
		}
	}
}

static odp_bool_t setup_config(prog_config_t *config)
{
	if (config->mode != DIRECT) {
		if (odp_schedule_config(NULL) < 0) {
			ODPH_ERR("Error initializing scheduler\n");
			return false;
		}
	}

	bind_destinations(config->pktios, config->num_ifs);
	bind_workers(config);

	for (uint32_t i = 0U; i < config->num_workers; ++i)
		config->worker_config[i].prog_config = config;

	return true;
}

static odp_schedule_sync_t get_odp_sync(uint8_t mode)
{
	switch (mode) {
	case SCHED_PARALLEL:
		return ODP_SCHED_SYNC_PARALLEL;
	case SCHED_ATOMIC:
		return ODP_SCHED_SYNC_ATOMIC;
	case SCHED_ORDERED:
		return ODP_SCHED_SYNC_ORDERED;
	default:
		return ODP_SCHED_SYNC_PARALLEL;
	}
}

static odp_bool_t setup_pktios(prog_config_t *config)
{
	odp_pool_param_t pool_param;
	pktio_t *pktio;
	odp_pktio_param_t pktio_param;
	odp_pktio_config_t pktio_config;
	odp_pktio_capability_t capa;
	uint32_t num_input_qs, num_output_qs;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	int ret;

	odp_pool_param_init(&pool_param);
	pool_param.pkt.seg_len = config->pkt_len;
	pool_param.pkt.len = config->pkt_len;
	pool_param.pkt.num = config->num_pkts;
	pool_param.type = ODP_POOL_PACKET;
	config->pool = odp_pool_create(PROG_NAME, &pool_param);

	if (config->pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error creating packet I/O pool\n");
		return false;
	}

	for (uint8_t i = 0U; i < config->num_ifs; ++i) {
		pktio = &config->pktios[i];
		odp_pktio_param_init(&pktio_param);
		pktio_param.in_mode = config->mode == DIRECT ?
					ODP_PKTIN_MODE_DIRECT : ODP_PKTIN_MODE_SCHED;
		pktio_param.out_mode = pktio->num_out_qs > 0U ?
					ODP_PKTOUT_MODE_DIRECT : ODP_PKTOUT_MODE_DISABLED;
		pktio->handle = odp_pktio_open(pktio->name, config->pool, &pktio_param);

		if (pktio->handle == ODP_PKTIO_INVALID) {
			ODPH_ERR("Error opening packet I/O (%s)\n", pktio->name);
			return false;
		}

		odp_pktio_config_init(&pktio_config);
		pktio_config.parser.layer = ODP_PROTO_LAYER_NONE;

		if (odp_pktio_config(pktio->handle, &pktio_config) < 0) {
			ODPH_ERR("Error configuring packet I/O (%s)\n", pktio->name);
			return false;
		}

		if (odp_pktio_capability(pktio->handle, &capa) < 0) {
			ODPH_ERR("Error querying packet I/O capabilities (%s)\n", pktio->name);
			return false;
		}

		odp_pktin_queue_param_init(&pktin_param);
		num_input_qs = config->mode == DIRECT ? pktio->num_in_qs : config->num_workers;
		num_input_qs = ODPH_MIN(num_input_qs, capa.max_input_queues);
		num_input_qs = ODPH_MIN(num_input_qs, MAX_QS);

		if (num_input_qs > 1) {
			pktin_param.hash_enable = true;
			pktin_param.hash_proto.proto.ipv4_udp = 1U;
		}

		if (config->mode == DIRECT) {
			if (num_input_qs == pktio->num_in_qs)
				pktin_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
			else
				ODPH_ERR("Warning: not enough input queues supported for MT "
					 "unsafe operation (%s)\n", pktio->name);
		}

		pktin_param.num_queues = num_input_qs;
		pktin_param.queue_param.sched.prio = odp_schedule_default_prio();
		pktin_param.queue_param.sched.sync = get_odp_sync(config->mode);
		pktio->num_in_qs = num_input_qs;

		if (odp_pktin_queue_config(pktio->handle, &pktin_param) < 0) {
			ODPH_ERR("Error configuring packet I/O input queues (%s)\n", pktio->name);
			return false;
		}

		if (config->mode == DIRECT &&
		    odp_pktin_queue(pktio->handle, pktio->in_qs, num_input_qs) !=
		    (int)num_input_qs) {
			ODPH_ERR("Error querying packet I/O input queues (%s)\n", pktio->name);
			return false;
		}

		num_output_qs = pktio->num_out_qs;

		if (num_output_qs > 0U) {
			odp_pktout_queue_param_init(&pktout_param);
			num_output_qs = config->mode == DIRECT ?
						num_output_qs : config->num_workers;
			num_output_qs = ODPH_MIN(num_output_qs, capa.max_output_queues);
			num_output_qs = ODPH_MIN(num_output_qs, MAX_QS);

			if (num_output_qs >= pktio->num_out_qs)
				pktout_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;
			else
				ODPH_ERR("Warning: not enough output queues supported for MT "
					 "unsafe operation (%s)\n", pktio->name);

			pktout_param.num_queues = num_output_qs;
			pktio->num_out_qs = num_output_qs;

			if (odp_pktout_queue_config(pktio->handle, &pktout_param) < 0) {
				ODPH_ERR("Error configuring packet I/O output queues (%s)\n",
					 pktio->name);
				return false;
			}

			if (odp_pktout_queue(pktio->handle, pktio->out_qs, num_output_qs) !=
			(int)num_output_qs) {
				ODPH_ERR("Error querying packet I/O output queues (%s)\n",
					 pktio->name);
				return false;
			}
		}

		if (config->mtu > 0U) {
			if (capa.set_op.op.maxlen == 0U) {
				config->mtu = 0U;
				ODPH_ERR("MTU setting not supported (%s)\n", pktio->name);
				return false;
			}

			if (config->mtu < capa.maxlen.min_input ||
			    config->mtu > capa.maxlen.max_input ||
			    config->mtu < capa.maxlen.min_output ||
			    config->mtu > capa.maxlen.max_output) {
				config->mtu = 0U;
				ODPH_ERR("Invalid MTU requested: %u (input min: %u, input max: %u,"
					 " output min: %u, output max: %u, %s)\n",
					 config->mtu, capa.maxlen.min_input, capa.maxlen.max_input,
					 capa.maxlen.min_output, capa.maxlen.max_output,
					 pktio->name);
				return false;
			}

			config->orig_in_mtu = odp_pktin_maxlen(pktio->handle);
			config->orig_out_mtu = odp_pktout_maxlen(pktio->handle);

			if (odp_pktio_maxlen_set(pktio->handle, config->mtu, config->mtu) < 0) {
				config->mtu = 0U;
				ODPH_ERR("Error setting MTU (%s)\n", pktio->name);
				return false;
			}
		}

		if (config->is_promisc) {
			if (capa.set_op.op.promisc_mode == 0U) {
				config->is_promisc = 0U;
				ODPH_ERR("Promiscuous mode setting not supported (%s)\n",
					 pktio->name);
				return false;
			}

			ret = odp_pktio_promisc_mode(pktio->handle);

			if (odp_pktio_promisc_mode_set(pktio->handle, true) < 0) {
				config->is_promisc = 0U;
				ODPH_ERR("Error setting promiscuous mode (%s)\n", pktio->name);
				return false;
			}

			config->orig_is_promisc = ret < 0 ? 1U : (uint8_t)ret;
		}

		if (odp_pktio_mac_addr(pktio->handle, pktio->src_mac.addr, ODPH_ETHADDR_LEN) < 0) {
			ODPH_ERR("Error querying MAC address (%s)\n", pktio->name);
			return false;
		}

		if (odp_pktio_start(pktio->handle) < 0) {
			ODPH_ERR("Error starting packet I/O (%s)\n", pktio->name);
			return false;
		}
	}

	return true;
}

static void print_mac(odph_ethaddr_t mac)
{
	for (int i = 0; i < ODPH_ETHADDR_LEN; ++i)
		printf("%02x%s", mac.addr[i], i < ODPH_ETHADDR_LEN - 1 ? ":" : "");

	printf("\n");
}

static void print_rx_workers(pktio_t *pktio, prog_config_t *config)
{
	worker_config_t *worker;
	const uint32_t num_workers = config->num_workers;
	uint32_t ids[num_workers], num_ids = 0U;

	if (config->mode != DIRECT) {
		printf("(scheduled)\n");
		return;
	}

	for (uint32_t i = 0U; i < num_workers; ++i) {
		worker = &config->worker_config[i];

		for (uint8_t j = 0U; j < worker->num_ifs; ++j) {
			if (pktio == worker->pktios[j].pktio) {
				ids[num_ids++] = i;
				break;
			}
		}
	}

	for (uint32_t i = 0U; i < num_ids; ++i)
		printf("%u%s", ids[i], i < num_ids - 1U ? ", " : "");

	printf("\n");
}

static void print_tx_workers(pktio_t *pktio, prog_config_t *config)
{
	worker_config_t *worker;
	const uint32_t num_workers = config->num_workers;
	uint32_t ids[num_workers], num_ids = 0U;

	if (config->mode != DIRECT) {
		printf("(scheduled)\n");
		return;
	}

	for (uint32_t i = 0U; i < num_workers; ++i) {
		worker = &config->worker_config[i];

		if (get_destination(pktio, worker->pktios, worker->num_ifs) != NULL)
			ids[num_ids++] = i;
	}

	if (num_ids == 0U)
		printf("-");
	else
		for (uint32_t i = 0U; i < num_ids; ++i)
			printf("%u%s", ids[i], i < num_ids - 1U ? ", " : "");

	printf("\n");
}

static odp_bool_t print_summary(prog_config_t *config)
{
	pktio_t *pktio;

	printf("\nprogram options:\n================\n\n"
	       "  interfaces:\n\n");

	for (uint8_t i = 0U; i < config->num_ifs; ++i) {
		pktio = &config->pktios[i];
		printf("    %s:\n\n"
		       "      handle:        0x%" PRIx64 "\n"
		       "      src MAC:       ", pktio->name, odp_pktio_to_u64(pktio->handle));
		print_mac(pktio->src_mac);
		printf("      dst MAC:       ");
		print_mac(pktio->dst_mac);
		printf("      dst name:      %s\n"
		       "      input queues:  %u\n"
		       "      output queues: %u\n", pktio->dst->name, pktio->num_in_qs,
		       pktio->num_out_qs);
		printf("      rx worker IDs: ");
		print_rx_workers(pktio, config);
		printf("      tx worker IDs: ");
		print_tx_workers(pktio, config);
		printf("\n");
	}

	printf("  mode:             %s\n"
	       "  burst size:       %u\n"
	       "  pool size:        %u\n"
	       "  packet length:    %u\n", config->mode == DIRECT ?
			"direct" : config->mode == SCHED_PARALLEL ?
			"scheduled-parallel" : config->mode == SCHED_ATOMIC ?
			"scheduled-atomic" : "scheduled-ordered",
	       config->burst_size, config->num_pkts, config->pkt_len);

	if (config->mtu > 0U)
		printf("  MTU:              %u\n", config->mtu);

	printf("  promiscuous mode: %s\n", config->is_promisc ? "enabled" : "disabled");

	if (config->runtime > 0U)
		printf("  runtime:          %u sec\n", config->runtime);
	else
		printf("  runtime:          infinite\n");

	printf("  MAC modification: %s\n"
	       "  workers:          %u\n\n", config->is_mac_mod ? "enabled" : "disabled",
	       config->num_workers);

	return true;
}

static dir_fwd_tbl_t build_dir_fwd_tbl(worker_pktio_t *pktios, uint8_t num_ifs)
{
	worker_pktio_t *w_pktio;
	pktio_t *pktio;
	dir_fwd_tbl_t tbl;

	for (uint8_t i = 0U; i < num_ifs; ++i) {
		w_pktio = &pktios[i];
		pktio = w_pktio->pktio;
		tbl.tbl[i].pktin = pktio->in_qs[w_pktio->rx_poll % pktio->num_in_qs];
		tbl.tbl[i].pktout = pktio->dst->out_qs[w_pktio->tx_poll % pktio->dst->num_out_qs];
		tbl.tbl[i].src_mac = pktio->dst->src_mac;
		tbl.tbl[i].dst_mac = pktio->dst->dst_mac;
	}

	return tbl;
}

static int run_direct_single_if(void *args)
{
	worker_config_t *config = args;
	prog_config_t *prog_config = config->prog_config;
	const uint32_t burst_size = prog_config->burst_size;
	const dir_fwd_tbl_t tbl = build_dir_fwd_tbl(config->pktios, config->num_ifs);
	odp_time_t start;
	odp_atomic_u32_t *is_running = &prog_config->is_running;
	const odp_pktin_queue_t pktin = tbl.tbl[0U].pktin;
	odp_packet_t pkts[burst_size];
	int num_recv, num_sent, diff;
	const odp_pktout_queue_t pktout = tbl.tbl[0U].pktout;
	uint64_t tx = 0U, tx_drops = 0U;
	stats_t *stats = &config->stats;

	odp_barrier_wait(&prog_config->init_barrier);
	start = odp_time_local_strict();

	while (odp_atomic_load_u32(is_running)) {
		num_recv = odp_pktin_recv(pktin, pkts, burst_size);

		if (odp_unlikely(num_recv <= 0))
			continue;

		num_sent = odp_pktout_send(pktout, pkts, num_recv);

		if (odp_unlikely(num_sent < num_recv)) {
			num_sent = num_sent < 0 ? 0 : num_sent;
			diff = num_recv - num_sent;
			odp_packet_free_multi(&pkts[num_sent], diff);
			tx_drops += diff;
		}

		tx += num_sent;
	}

	stats->tm_ns = odp_time_diff_ns(odp_time_local_strict(), start);
	stats->tx = tx;
	stats->tx_drops = tx_drops;
	odp_barrier_wait(&prog_config->term_barrier);

	return 0;
}

static int run_direct_single_if_mac_mod(void *args)
{
	worker_config_t *config = args;
	prog_config_t *prog_config = config->prog_config;
	const uint32_t burst_size = prog_config->burst_size;
	const dir_fwd_tbl_t tbl = build_dir_fwd_tbl(config->pktios, config->num_ifs);
	odp_time_t start;
	odp_atomic_u32_t *is_running = &prog_config->is_running;
	const odp_pktin_queue_t pktin = tbl.tbl[0U].pktin;
	odp_packet_t pkts[burst_size];
	int num_recv, num_sent, diff;
	const odph_ethaddr_t src_mac = tbl.tbl[0U].src_mac, dst_mac = tbl.tbl[0U].dst_mac;
	odph_ethhdr_t *eth;
	const odp_pktout_queue_t pktout = tbl.tbl[0U].pktout;
	uint64_t tx = 0U, tx_drops = 0U;
	stats_t *stats = &config->stats;

	odp_barrier_wait(&prog_config->init_barrier);
	start = odp_time_local_strict();

	while (odp_atomic_load_u32(is_running)) {
		num_recv = odp_pktin_recv(pktin, pkts, burst_size);

		if (odp_unlikely(num_recv <= 0))
			continue;

		for (int i = 0U; i < num_recv; ++i) {
			eth = odp_packet_data(pkts[i]);
			eth->src = src_mac;
			eth->dst = dst_mac;
		}

		num_sent = odp_pktout_send(pktout, pkts, num_recv);

		if (odp_unlikely(num_sent < num_recv)) {
			num_sent = num_sent < 0 ? 0 : num_sent;
			diff = num_recv - num_sent;
			odp_packet_free_multi(&pkts[num_sent], diff);
			tx_drops += diff;
		}

		tx += num_sent;
	}

	stats->tm_ns = odp_time_diff_ns(odp_time_local_strict(), start);
	stats->tx = tx;
	stats->tx_drops = tx_drops;
	odp_barrier_wait(&prog_config->term_barrier);

	return 0;
}

static int run_direct_multi_if(void *args)
{
	worker_config_t *config = args;
	prog_config_t *prog_config = config->prog_config;
	const uint8_t num_ifs = config->num_ifs;
	const uint32_t burst_size = prog_config->burst_size;
	const dir_fwd_tbl_t tbl = build_dir_fwd_tbl(config->pktios, num_ifs);
	odp_time_t start;
	odp_atomic_u32_t *is_running = &prog_config->is_running;
	uint8_t i = 0U;
	odp_pktin_queue_t pktin;
	odp_packet_t pkts[burst_size];
	int num_recv, num_sent, diff;
	odp_pktout_queue_t pktout;
	uint64_t tx = 0U, tx_drops = 0U;
	stats_t *stats = &config->stats;

	odp_barrier_wait(&prog_config->init_barrier);
	start = odp_time_local_strict();

	while (odp_atomic_load_u32(is_running)) {
		pktin = tbl.tbl[i].pktin;
		pktout = tbl.tbl[i].pktout;

		if (++i == num_ifs)
			i = 0U;

		num_recv = odp_pktin_recv(pktin, pkts, burst_size);

		if (odp_unlikely(num_recv <= 0))
			continue;

		num_sent = odp_pktout_send(pktout, pkts, num_recv);

		if (odp_unlikely(num_sent < num_recv)) {
			num_sent = num_sent < 0 ? 0 : num_sent;
			diff = num_recv - num_sent;
			odp_packet_free_multi(&pkts[num_sent], diff);
			tx_drops += diff;
		}

		tx += num_sent;
	}

	stats->tm_ns = odp_time_diff_ns(odp_time_local_strict(), start);
	stats->tx = tx;
	stats->tx_drops = tx_drops;
	odp_barrier_wait(&prog_config->term_barrier);

	return 0;
}

static int run_direct_multi_if_mac_mod(void *args)
{
	worker_config_t *config = args;
	prog_config_t *prog_config = config->prog_config;
	const uint8_t num_ifs = config->num_ifs;
	const uint32_t burst_size = prog_config->burst_size;
	const dir_fwd_tbl_t tbl = build_dir_fwd_tbl(config->pktios, num_ifs);
	odp_time_t start;
	odp_atomic_u32_t *is_running = &prog_config->is_running;
	uint8_t i = 0U;
	odp_pktin_queue_t pktin;
	odp_packet_t pkts[burst_size];
	int num_recv, num_sent, diff;
	odph_ethaddr_t src_mac, dst_mac;
	odph_ethhdr_t *eth;
	odp_pktout_queue_t pktout;
	uint64_t tx = 0U, tx_drops = 0U;
	stats_t *stats = &config->stats;

	odp_barrier_wait(&prog_config->init_barrier);
	start = odp_time_local_strict();

	while (odp_atomic_load_u32(is_running)) {
		pktin = tbl.tbl[i].pktin;
		pktout = tbl.tbl[i].pktout;
		src_mac = tbl.tbl[i].src_mac;
		dst_mac = tbl.tbl[i].dst_mac;

		if (++i == num_ifs)
			i = 0U;

		num_recv = odp_pktin_recv(pktin, pkts, burst_size);

		if (odp_unlikely(num_recv <= 0))
			continue;

		for (int j = 0U; j < num_recv; ++j) {
			eth = odp_packet_data(pkts[j]);
			eth->src = src_mac;
			eth->dst = dst_mac;
		}

		num_sent = odp_pktout_send(pktout, pkts, num_recv);

		if (odp_unlikely(num_sent < num_recv)) {
			num_sent = num_sent < 0 ? 0 : num_sent;
			diff = num_recv - num_sent;
			odp_packet_free_multi(&pkts[num_sent], diff);
			tx_drops += diff;
		}

		tx += num_sent;
	}

	stats->tm_ns = odp_time_diff_ns(odp_time_local_strict(), start);
	stats->tx = tx;
	stats->tx_drops = tx_drops;
	odp_barrier_wait(&prog_config->term_barrier);

	return 0;
}

static scd_fwd_tbl_t build_scd_fwd_tbl(const pktio_t *pktios, uint8_t num_ifs, int thread_idx)
{
	const pktio_t *pktio;
	int idx;
	scd_fwd_tbl_t tbl;

	for (uint8_t i = 0U; i < num_ifs; ++i) {
		pktio = &pktios[i];
		idx = odp_pktio_index(pktio->handle);
		tbl.tbl[idx].pktout = pktio->dst->out_qs[thread_idx % pktio->dst->num_out_qs];
		tbl.tbl[idx].src_mac = pktio->dst->src_mac;
		tbl.tbl[idx].dst_mac = pktio->dst->dst_mac;
	}

	return tbl;
}

static void drain_events(void)
{
	while (true) {
		odp_event_t  ev;

		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}
}

static int run_scheduled(void *args)
{
	worker_config_t *config = args;
	prog_config_t *prog_config = config->prog_config;
	odp_time_t start;
	odp_atomic_u32_t *is_running = &prog_config->is_running;
	const uint8_t num_ifs = prog_config->num_ifs;
	const uint32_t burst_size = prog_config->burst_size;
	odp_event_t evs[burst_size];
	int num_recv, num_sent, diff;
	odp_packet_t pkts[burst_size];
	const scd_fwd_tbl_t tbl = build_scd_fwd_tbl(prog_config->pktios, num_ifs, odp_thread_id());
	odp_pktout_queue_t pktout;
	uint64_t tx = 0U, tx_drops = 0U;
	stats_t *stats = &config->stats;

	odp_barrier_wait(&config->prog_config->init_barrier);
	start = odp_time_local_strict();

	while (odp_atomic_load_u32(is_running)) {
		num_recv = odp_schedule_multi_no_wait(NULL, evs, burst_size);

		if (odp_unlikely(num_recv <= 0))
			continue;

		odp_packet_from_event_multi(pkts, evs, num_recv);
		pktout = tbl.tbl[odp_packet_input_index(pkts[0U])].pktout;
		num_sent = odp_pktout_send(pktout, pkts, num_recv);

		if (odp_unlikely(num_sent < num_recv)) {
			num_sent = num_sent < 0 ? 0 : num_sent;
			diff = num_recv - num_sent;
			odp_packet_free_multi(&pkts[num_sent], diff);
			tx_drops += diff;
		}

		tx += num_sent;
	}

	stats->tm_ns = odp_time_diff_ns(odp_time_local_strict(), start);
	stats->tx = tx;
	stats->tx_drops = tx_drops;
	/* With certain feature combo that involves HW prefetching, the prefetched events may block
	 * other threads from forward progress, so drain them before termination barrier and the
	 * potential rest after the barrier. */
	odp_schedule_pause();
	drain_events();
	odp_barrier_wait(&config->prog_config->term_barrier);
	odp_schedule_resume();
	drain_events();

	return 0;
}

static int run_scheduled_mac_mod(void *args)
{
	worker_config_t *config = args;
	prog_config_t *prog_config = config->prog_config;
	odp_time_t start;
	odp_atomic_u32_t *is_running = &prog_config->is_running;
	const uint8_t num_ifs = prog_config->num_ifs;
	const uint32_t burst_size = prog_config->burst_size;
	odp_event_t evs[burst_size];
	int num_recv, num_sent, idx, diff;
	odp_packet_t pkts[burst_size];
	const scd_fwd_tbl_t tbl = build_scd_fwd_tbl(prog_config->pktios, num_ifs, odp_thread_id());
	odph_ethaddr_t src_mac, dst_mac;
	odph_ethhdr_t *eth;
	odp_pktout_queue_t pktout;
	uint64_t tx = 0U, tx_drops = 0U;
	stats_t *stats = &config->stats;

	odp_barrier_wait(&config->prog_config->init_barrier);
	start = odp_time_local_strict();

	while (odp_atomic_load_u32(is_running)) {
		num_recv = odp_schedule_multi_no_wait(NULL, evs, burst_size);

		if (odp_unlikely(num_recv <= 0))
			continue;

		odp_packet_from_event_multi(pkts, evs, num_recv);
		idx = odp_packet_input_index(pkts[0U]);
		src_mac = tbl.tbl[idx].src_mac;
		dst_mac = tbl.tbl[idx].dst_mac;
		pktout = tbl.tbl[idx].pktout;

		for (int i = 0U; i < num_recv; ++i) {
			eth = odp_packet_data(pkts[i]);
			eth->src = src_mac;
			eth->dst = dst_mac;
		}

		num_sent = odp_pktout_send(pktout, pkts, num_recv);

		if (odp_unlikely(num_sent < num_recv)) {
			num_sent = num_sent < 0 ? 0 : num_sent;
			diff = num_recv - num_sent;
			odp_packet_free_multi(&pkts[num_sent], diff);
			tx_drops += diff;
		}

		tx += num_sent;
	}

	stats->tm_ns = odp_time_diff_ns(odp_time_local_strict(), start);
	stats->tx = tx;
	stats->tx_drops = tx_drops;
	/* With certain feature combo that involves HW prefetching, the prefetched events may block
	 * other threads from forward progress, so drain them before termination barrier and the
	 * potential rest after the barrier. */
	odp_schedule_pause();
	drain_events();
	odp_barrier_wait(&config->prog_config->term_barrier);
	odp_schedule_resume();
	drain_events();

	return 0;
}

static run_func_t get_run_func(const prog_config_t *config, const worker_config_t *worker)
{
	if (config->mode == DIRECT) {
		if (config->is_mac_mod)
			return worker->num_ifs == 1U ?
				run_direct_single_if_mac_mod : run_direct_multi_if_mac_mod;
		else
			return worker->num_ifs == 1U ?
				run_direct_single_if : run_direct_multi_if;
	} else {
		return config->is_mac_mod ? run_scheduled_mac_mod : run_scheduled;
	}
}

static odp_bool_t setup_workers(prog_config_t *config)
{
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_params[config->num_workers], *thr_param;
	worker_config_t *worker;

	odp_barrier_init(&config->init_barrier, config->num_workers + 1);
	odp_barrier_init(&config->term_barrier, config->num_workers + 1);
	odph_thread_common_param_init(&thr_common);
	thr_common.instance = config->odp_instance;
	thr_common.cpumask = &config->worker_mask;

	for (uint32_t i = 0; i < config->num_workers; ++i) {
		thr_param = &thr_params[i];
		worker = &config->worker_config[i];
		odph_thread_param_init(thr_param);
		thr_param->start = get_run_func(config, worker);
		thr_param->thr_type = ODP_THREAD_WORKER;
		thr_param->arg = worker;
	}

	if ((uint32_t)odph_thread_create(config->thread_tbl, &thr_common, thr_params,
					 config->num_workers) != config->num_workers) {
		ODPH_ERR("Error configuring worker threads\n");
		return false;
	}

	odp_barrier_wait(&config->init_barrier);

	return true;
}

static odp_bool_t setup_test(prog_config_t *config)
{
	return setup_config(config) && setup_pktios(config) && print_summary(config) &&
	       setup_workers(config);
}

static void run_control(prog_config_t *config)
{
	if (config->runtime > 0U) {
		sleep(config->runtime);
		odp_atomic_store_u32(&config->is_running, 0U);
	} else {
		while (odp_atomic_load_u32(&config->is_running))
			sleep(1U);
	}
}

static void stop_test(prog_config_t *config)
{
	const pktio_t *pktio;

	for (uint8_t i = 0U; i < config->num_ifs; ++i) {
		pktio = &config->pktios[i];

		if (pktio->handle != ODP_PKTIO_INVALID)
			(void)odp_pktio_stop(pktio->handle);
	}

	odp_barrier_wait(&config->term_barrier);
	(void)odph_thread_join(config->thread_tbl, config->num_workers);
}

static void print_humanised(uint64_t value)
{
	if (value > GIGAS)
		printf("(%.2f Gpps)", (double)value / GIGAS);
	else if (value > MEGAS)
		printf("(%.2f Mpps)", (double)value / MEGAS);
	else if (value > KILOS)
		printf("(%.2f kpps)", (double)value / KILOS);
	else
		printf("(%" PRIu64 " pps)", value);
}

static void print_stats(const prog_config_t *config)
{
	const stats_t *stats;
	uint64_t tot_tx = 0U, tot_tx_drops = 0U, pps, tot_pps = 0U;

	printf("L2 forwarding done:\n"
	       "===================\n\n");

	for (uint32_t i = 0U; i < config->num_workers; ++i) {
		stats = &config->worker_config[i].stats;
		tot_tx += stats->tx;
		tot_tx_drops += stats->tx_drops;
		pps = stats->tx / ((double)stats->tm_ns / ODP_TIME_SEC_IN_NS);
		tot_pps += pps;

		printf("  worker %u:\n\n"
		       "    packets sent:       %" PRIu64 "\n"
		       "    packets dropped:    %" PRIu64 "\n"
		       "    packets per second: %" PRIu64 " ", i, stats->tx, stats->tx_drops,
		       pps);
		print_humanised(pps);
		printf("\n\n");
	}

	printf("  total packets sent:       %" PRIu64 "\n"
	       "  total packets dropped:    %" PRIu64 "\n"
	       "  total packets per second: %" PRIu64 " ", tot_tx, tot_tx_drops, tot_pps);
	print_humanised(tot_pps);
	printf("\n\n");

	/* TODO: Results exporting can go here. */
}

static void teardown(const prog_config_t *config)
{
	const pktio_t *pktio;

	for (uint8_t i = 0U; i < config->num_ifs; ++i) {
		pktio = &config->pktios[i];

		if (config->pktios[i].handle != ODP_PKTIO_INVALID) {
			if (config->is_promisc != config->orig_is_promisc)
				(void)odp_pktio_promisc_mode_set(pktio->handle,
								 config->orig_is_promisc);

			if (config->mtu > 0U && config->orig_in_mtu > 0U &&
			    config->orig_out_mtu > 0U)
				(void)odp_pktio_maxlen_set(pktio->handle, config->orig_in_mtu,
							   config->orig_out_mtu);

			(void)odp_pktio_close(pktio->handle);
		}

		free(pktio->name);
		free(pktio->dst_name);
	}

	if (config->pool != ODP_POOL_INVALID)
		(void)odp_pool_destroy(config->pool);
}

int main(int argc, char **argv)
{
	odph_helper_options_t odph_opts;
	odp_init_t init_param;
	odp_instance_t odp_instance;
	odp_shm_t shm_cfg = ODP_SHM_INVALID;
	int ret = EXIT_SUCCESS;
	parse_result_t parse_res;

	argc = odph_parse_options(argc, argv);

	if (odph_options(&odph_opts) == -1) {
		ODPH_ERR("Error while reading ODP helper options, exiting\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = odph_opts.mem_model;

	if (odp_init_global(&odp_instance, &init_param, NULL)) {
		ODPH_ERR("ODP global init failed, exiting\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(odp_instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("ODP local init failed, exiting\n");
		exit(EXIT_FAILURE);
	}

	shm_cfg = odp_shm_reserve(PROG_NAME "_cfg", sizeof(prog_config_t), ODP_CACHE_LINE_SIZE,
				  0U);

	if (shm_cfg == ODP_SHM_INVALID) {
		ODPH_ERR("Error reserving shared memory\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	prog_conf = odp_shm_addr(shm_cfg);

	if (prog_conf == NULL) {
		ODPH_ERR("Error resolving shared memory address\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	memset(prog_conf, 0, sizeof(*prog_conf));
	prog_conf->odp_instance = odp_instance;
	parse_res = setup_program(argc, argv, prog_conf);

	if (parse_res == PRS_NOK) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (parse_res == PRS_TERM) {
		ret = EXIT_SUCCESS;
		goto out;
	}

	if (!setup_test(prog_conf)) {
		ret = EXIT_FAILURE;
		goto out;
	}

	run_control(prog_conf);
	stop_test(prog_conf);
	print_stats(prog_conf);

out:
	teardown(prog_conf);

	if (shm_cfg != ODP_SHM_INVALID)
		(void)odp_shm_free(shm_cfg);

	if (odp_term_local()) {
		ODPH_ERR("ODP local terminate failed, exiting\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(odp_instance)) {
		ODPH_ERR("ODP global terminate failed, exiting\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}

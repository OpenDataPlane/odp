/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <signal.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define POOL_NUM_PKT 8192
#define POOL_SEG_LEN 1856
#define MAX_PKT_BURST 32
#define MAX_WORKERS 1

typedef struct {
	odp_pktio_t if0, if1;
	odp_pktin_queue_t if0in, if1in;
	odp_pktout_queue_t if0out, if1out;
	odph_ethaddr_t src, dst;
	odp_shm_t shm;
	int exit_thr;
	int wait_sec;
} global_data_t;

static global_data_t *global;

static void sig_handler(int signo ODP_UNUSED)
{
	printf("sig_handler!\n");
	if (global == NULL)
		return;
	global->exit_thr = 1;
}

static odp_pktio_t create_pktio(const char *name, odp_pool_t pool,
				odp_pktin_queue_t *pktin,
				odp_pktout_queue_t *pktout)
{
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t in_queue_param;
	odp_pktout_queue_param_t out_queue_param;
	odp_pktio_t pktio;
	odp_pktio_config_t config;

	odp_pktio_param_init(&pktio_param);

	pktio = odp_pktio_open(name, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		printf("Failed to open %s\n", name);
		exit(1);
	}

	odp_pktio_config_init(&config);
	config.parser.layer = ODP_PROTO_LAYER_L2;
	odp_pktio_config(pktio, &config);

	odp_pktin_queue_param_init(&in_queue_param);
	odp_pktout_queue_param_init(&out_queue_param);

	in_queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;

	if (odp_pktin_queue_config(pktio, &in_queue_param)) {
		printf("Failed to config input queue for %s\n", name);
		exit(1);
	}

	out_queue_param.op_mode = ODP_PKTIO_OP_MT_UNSAFE;

	if (odp_pktout_queue_config(pktio, &out_queue_param)) {
		printf("Failed to config output queue for %s\n", name);
		exit(1);
	}

	if (odp_pktin_queue(pktio, pktin, 1) != 1) {
		printf("pktin queue query failed for %s\n", name);
		exit(1);
	}
	if (odp_pktout_queue(pktio, pktout, 1) != 1) {
		printf("pktout queue query failed for %s\n", name);
		exit(1);
	}
	return pktio;
}

static int run_worker(void *arg ODP_UNUSED)
{
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int pkts, sent, tx_drops, i;
	uint64_t wait_time = odp_pktin_wait_time(ODP_TIME_SEC_IN_NS);

	if (odp_pktio_start(global->if0)) {
		printf("unable to start input interface\n");
		exit(1);
	}
	printf("started input interface\n");
	if (odp_pktio_start(global->if1)) {
		printf("unable to start output interface\n");
		exit(1);
	}
	printf("started output interface\n");
	printf("started all\n");

	while (!global->exit_thr) {
		pkts = odp_pktin_recv_tmo(global->if0in, pkt_tbl, MAX_PKT_BURST,
					  wait_time);

		if (odp_unlikely(pkts <= 0)) {
			if (global->wait_sec > 0)
				if (!(--global->wait_sec))
					break;
			continue;
		}

		for (i = 0; i < pkts; i++) {
			odp_packet_t pkt = pkt_tbl[i];
			odph_ethhdr_t *eth;

			if (odp_unlikely(!odp_packet_has_eth(pkt))) {
				printf("warning: packet has no eth header\n");
				return 0;
			}
			eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
			eth->src = global->src;
			eth->dst = global->dst;
		}
		sent = odp_pktout_send(global->if1out, pkt_tbl, pkts);
		if (sent < 0)
			sent = 0;
		tx_drops = pkts - sent;
		if (odp_unlikely(tx_drops))
			odp_packet_free_multi(&pkt_tbl[sent], tx_drops);
	}

	return 0;
}

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_cpumask_t cpumask;
	odph_thread_t thd[MAX_WORKERS];
	odp_instance_t instance;
	odp_init_t init_param;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	odph_ethaddr_t correct_src;
	uint32_t mtu1, mtu2;
	odp_shm_t shm;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		printf("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (odp_init_global(&instance, &init_param, NULL)) {
		printf("Error: ODP global init failed.\n");
		exit(1);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: ODP local init failed.\n");
		exit(1);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("_appl_global_data", sizeof(global_data_t),
			      ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		printf("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	global = odp_shm_addr(shm);
	if (global == NULL) {
		printf("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	memset(global, 0, sizeof(global_data_t));
	global->shm = shm;

	if (argc > 7 ||
	    odph_eth_addr_parse(&global->dst, argv[3]) != 0 ||
	    odph_eth_addr_parse(&global->src, argv[4]) != 0) {
		printf("Usage: odp_l2fwd_simple eth0 eth1 01:02:03:04:05:06"
		       " 07:08:09:0a:0b:0c [-t sec]\n");
		printf("Where eth0 and eth1 are the used interfaces"
		       " (must have 2 of them)\n");
		printf("And the hexadecimal numbers are destination MAC address"
		       " and source MAC address\n");
		exit(1);
	}
	if (argc == 7 && !strncmp(argv[5], "-t", 2))
		global->wait_sec = atoi(argv[6]);

	if (global->wait_sec)
		printf("running test for %d sec\n", global->wait_sec);

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

	global->if0 = create_pktio(argv[1], pool, &global->if0in,
				   &global->if0out);
	global->if1 = create_pktio(argv[2], pool, &global->if1in,
				   &global->if1out);

	/* Do some operations to increase code coverage in tests */
	if (odp_pktio_mac_addr(global->if0, &correct_src, sizeof(correct_src))
	    != sizeof(correct_src))
		printf("Warning: can't get MAC address\n");
	else if (memcmp(&correct_src, &global->src, sizeof(correct_src)) != 0)
		printf("Warning: src MAC invalid\n");

	odp_pktio_promisc_mode_set(global->if0, true);
	odp_pktio_promisc_mode_set(global->if1, true);
	(void)odp_pktio_promisc_mode(global->if0);
	(void)odp_pktio_promisc_mode(global->if1);

	mtu1 = odp_pktin_maxlen(global->if0);
	mtu2 = odp_pktout_maxlen(global->if1);
	if (mtu1 && mtu2 && mtu1 > mtu2)
		printf("Warning: input MTU bigger than output MTU\n");

	odp_cpumask_default_worker(&cpumask, MAX_WORKERS);

	memset(&thr_common, 0, sizeof(thr_common));
	memset(&thr_param, 0, sizeof(thr_param));

	thr_param.start    = run_worker;
	thr_param.thr_type = ODP_THREAD_WORKER;

	thr_common.instance    = instance;
	thr_common.cpumask     = &cpumask;
	thr_common.share_param = 1;

	signal(SIGINT, sig_handler);

	if (odph_thread_create(thd, &thr_common, &thr_param, MAX_WORKERS) !=
	    MAX_WORKERS) {
		printf("Error: failed to create threads\n");
		exit(EXIT_FAILURE);
	}

	if (odph_thread_join(thd, MAX_WORKERS) != MAX_WORKERS) {
		printf("Error: failed to join threads\n");
		exit(EXIT_FAILURE);
	}

	if (odp_pktio_stop(global->if0) || odp_pktio_close(global->if0)) {
		printf("Error: failed to close interface %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}
	if (odp_pktio_stop(global->if1) || odp_pktio_close(global->if1)) {
		printf("Error: failed to close interface %s\n", argv[2]);
		exit(EXIT_FAILURE);
	}

	if (odp_pool_destroy(pool)) {
		printf("Error: pool destroy\n");
		exit(EXIT_FAILURE);
	}

	global = NULL;
	odp_mb_full();
	if (odp_shm_free(shm)) {
		printf("Error: shm free global data\n");
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

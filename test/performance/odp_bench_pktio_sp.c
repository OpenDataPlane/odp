/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Needed for sigaction */
#endif

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include "bench_common.h"

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

/* Default number of rounds per test case */
#define ROUNDS 100u

/* Maximum interface name length */
#define MAX_NAME_LEN 128

#define BENCH_INFO(run_fn, init_fn, term_fn, rounds) \
	{.name = #run_fn, .run = run_fn, .init = init_fn, .term = term_fn, \
	 .max_rounds = rounds}

typedef struct {
	/* Command line options */
	struct {
		/* Rounds per test case */
		uint32_t rounds;

		/* Test case index to run */
		uint32_t case_idx;

		/* Interface name */
		char name[MAX_NAME_LEN];

		/* Packet input mode */
		odp_pktin_mode_t in_mode;

		/* Packet output mode */
		odp_pktout_mode_t out_mode;

		/* Number of packet input queues */
		uint32_t num_input_queues;

		/* Number of packet output queues */
		uint32_t num_output_queues;
	} opt;

	/* Packet IO device */
	odp_pktio_t pktio;

	/* Packet IO capability*/
	odp_pktio_capability_t capa;

	/* Packet pool */
	odp_pool_t pool;

	/* Packet IO statistics */
	odp_pktio_stats_t stats;

	/* Input queue statistics */
	odp_pktin_queue_stats_t pktin_queue_stats;

	/* Output queue statistics */
	odp_pktout_queue_stats_t pktout_queue_stats;

	/* Common benchmark suite data */
	bench_tm_suite_t suite;

	/* CPU mask as string */
	char cpumask_str[ODP_CPUMASK_STR_SIZE];

} appl_args_t;

static appl_args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	odp_atomic_store_u32(&gbl_args->suite.exit_worker, 1);
}

static int setup_sig_handler(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = sig_handler;

	/* No additional signals blocked. By default, the signal which triggered
	 * the handler is blocked. */
	if (sigemptyset(&action.sa_mask))
		return -1;

	if (sigaction(SIGINT, &action, NULL))
		return -1;

	return 0;
}

static void clean_pending_events(appl_args_t *appl_args)
{
	if (appl_args->opt.in_mode != ODP_PKTIN_MODE_SCHED)
		return;

	while (1) {
		odp_event_t event = odp_schedule(NULL, odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS));

		if (event != ODP_EVENT_INVALID) {
			odp_event_free(event);
			continue;
		}
		break;
	};
}

static odp_pool_t create_packet_pool(void)
{
	odp_pool_capability_t capa;
	odp_pool_param_t param;
	odp_pool_t pool;

	if (odp_pool_capability(&capa))
		ODPH_ABORT("Reading pool capabilities failed\n");

	odp_pool_param_init(&param);
	param.type = ODP_POOL_PACKET;
	param.pkt.num = 512;
	param.pkt.len = 2048;

	if (capa.pkt.max_num && capa.pkt.max_num < param.pkt.num)
		param.pkt.num = capa.pkt.max_num;

	if (capa.pkt.max_len && capa.pkt.max_len < param.pkt.len)
		param.pkt.len = capa.pkt.max_len;

	pool = odp_pool_create("pktio_pool", &param);
	if (pool == ODP_POOL_INVALID)
		ODPH_ABORT("Creating packet pool failed\n");

	return pool;
}

static void pktio_setup(void)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktio_param_t param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_pktio_t pktio;
	odp_pool_t pool;
	int ret;

	pool = create_packet_pool();

	odp_pktio_param_init(&param);
	param.in_mode = appl_args->opt.in_mode;
	param.out_mode = appl_args->opt.out_mode;

	pktio = odp_pktio_open(appl_args->opt.name, pool, &param);
	if (pktio == ODP_PKTIO_INVALID)
		ODPH_ABORT("Opening pktio failed\n");

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.num_queues = appl_args->opt.num_input_queues;
	if (pktin_param.num_queues > 1) {
		pktin_param.hash_enable = true;
		pktin_param.hash_proto.proto.ipv4_udp = 1;
	}

	odp_pktout_queue_param_init(&pktout_param);
	pktout_param.num_queues = appl_args->opt.num_output_queues;

	ret = odp_pktin_queue_config(pktio, &pktin_param);
	if (ret)
		ODPH_ABORT("Configuring packet input queues failed: %d\n", ret);

	ret = odp_pktout_queue_config(pktio, &pktout_param);
	if (ret)
		ODPH_ABORT("Configuring packet output queues failed: %d\n", ret);

	ret = odp_pktio_start(pktio);
	if (ret)
		ODPH_ABORT("Starting pktio failed: %d\n", ret);

	appl_args->pool = pool;
	appl_args->pktio = pktio;
}

static void pktio_setup_direct_rx(void)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktin_mode_t mode_orig = appl_args->opt.in_mode;

	appl_args->opt.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_setup();
	appl_args->opt.in_mode = mode_orig;
}

static void pktio_setup_sched_rx(void)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktin_mode_t mode_orig = appl_args->opt.in_mode;

	appl_args->opt.in_mode = ODP_PKTIN_MODE_SCHED;
	pktio_setup();
	appl_args->opt.in_mode = mode_orig;
}

static void pktio_setup_direct_tx(void)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktout_mode_t mode_orig = appl_args->opt.out_mode;

	appl_args->opt.out_mode = ODP_PKTOUT_MODE_DIRECT;
	pktio_setup();
	appl_args->opt.out_mode = mode_orig;
}

static void pktio_setup_queue_tx(void)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktout_mode_t mode_orig = appl_args->opt.out_mode;

	appl_args->opt.out_mode = ODP_PKTOUT_MODE_QUEUE;
	pktio_setup();
	appl_args->opt.out_mode = mode_orig;
}

static void pktio_clean(void)
{
	appl_args_t *appl_args = gbl_args;
	int ret;

	ret = odp_pktio_stop(appl_args->pktio);
	if (ret)
		ODPH_ABORT("Stopping pktio failed: %d\n", ret);

	/* Clean possible pre-scheduled packets */
	clean_pending_events(appl_args);

	ret = odp_pktio_close(appl_args->pktio);
	if (ret)
		ODPH_ABORT("Closing pktio failed: %d\n", ret);

	ret = odp_pool_destroy(appl_args->pool);
	if (ret)
		ODPH_ABORT("Destroying pktio pool failed: %d\n", ret);
}

static void pktio_clean_direct_rx(void)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktin_mode_t mode_orig = appl_args->opt.in_mode;

	appl_args->opt.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_clean();
	appl_args->opt.in_mode = mode_orig;
}

static void pktio_clean_sched_rx(void)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktin_mode_t mode_orig = appl_args->opt.in_mode;

	appl_args->opt.in_mode = ODP_PKTIN_MODE_SCHED;
	pktio_clean();
	appl_args->opt.in_mode = mode_orig;
}

static void pktio_clean_direct_tx(void)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktout_mode_t mode_orig = appl_args->opt.out_mode;

	appl_args->opt.out_mode = ODP_PKTOUT_MODE_DIRECT;
	pktio_clean();
	appl_args->opt.out_mode = mode_orig;
}

static void pktio_clean_queue_tx(void)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktout_mode_t mode_orig = appl_args->opt.out_mode;

	appl_args->opt.out_mode = ODP_PKTOUT_MODE_QUEUE;
	pktio_clean();
	appl_args->opt.out_mode = mode_orig;
}

static int pktio_capability(bench_tm_result_t *res, int repeat_count)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktio_capability_t *capa = &appl_args->capa;
	odp_pktio_t pktio = appl_args->pktio;
	odp_time_t t1, t2;
	int ret;
	uint8_t id1 = bench_tm_func_register(res, "odp_pktio_capability()");

	for (int i = 0; i < repeat_count; i++) {
		t1 = odp_time_local_strict();
		ret = odp_pktio_capability(pktio, capa);
		t2 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Reading pktio capa failed: %d\n", ret);
			return -1;
		}

		bench_tm_func_record(t2, t1, res, id1);
	}
	return 0;
}

static int pktio_lookup(bench_tm_result_t *res, int repeat_count)
{
	appl_args_t *appl_args = gbl_args;
	const char *name = appl_args->opt.name;
	odp_pktio_t pktio;
	odp_time_t t1, t2;
	uint8_t id1 = bench_tm_func_register(res, "odp_pktio_lookup()");

	for (int i = 0; i < repeat_count; i++) {
		t1 = odp_time_local_strict();
		pktio = odp_pktio_lookup(name);
		t2 = odp_time_local_strict();

		if (pktio == ODP_PKTIO_INVALID) {
			ODPH_ERR("Pktio lookup failed\n");
			return -1;
		}

		bench_tm_func_record(t2, t1, res, id1);
	}
	return 0;
}

static int pktio_open_start_stop_close(bench_tm_result_t *res, int repeat_count)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktio_param_t param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktout_queue_param_t pktout_param;
	odp_pktio_t pktio;
	odp_pool_t pool;
	odp_time_t t1, t2, t3, t4, t5, t6, t7, t8;
	int ret;
	uint8_t id1 = bench_tm_func_register(res, "odp_pktio_open()");
	uint8_t id2 = bench_tm_func_register(res, "odp_pktin_queue_config()");
	uint8_t id3 = bench_tm_func_register(res, "odp_pktout_queue_config()");
	uint8_t id4 = bench_tm_func_register(res, "odp_pktio_start()");
	uint8_t id5 = bench_tm_func_register(res, "odp_pktio_stop()");
	uint8_t id6 = bench_tm_func_register(res, "odp_pktio_close()");

	pool = create_packet_pool();

	odp_pktio_param_init(&param);
	param.in_mode = appl_args->opt.in_mode;
	param.out_mode = appl_args->opt.out_mode;

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.num_queues = appl_args->opt.num_input_queues;
	if (pktin_param.num_queues > 1) {
		pktin_param.hash_enable = true;
		pktin_param.hash_proto.proto.ipv4_udp = 1;
	}

	odp_pktout_queue_param_init(&pktout_param);
	pktout_param.num_queues = appl_args->opt.num_output_queues;

	for (int i = 0; i < repeat_count; i++) {
		t1 = odp_time_local_strict();
		pktio = odp_pktio_open(appl_args->opt.name, pool, &param);
		t2 = odp_time_local_strict();

		if (pktio == ODP_PKTIO_INVALID) {
			ODPH_ERR("Opening pktio failed\n");
			return -1;
		}

		ret = odp_pktin_queue_config(pktio, &pktin_param);
		t3 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Configuring packet input queues failed: %d\n", ret);
			return -1;
		}

		ret = odp_pktout_queue_config(pktio, &pktout_param);
		t4 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Configuring packet output queues failed: %d\n", ret);
			return -1;
		}

		ret = odp_pktio_start(pktio);
		t5 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Starting pktio failed: %d\n", ret);
			return -1;
		}

		ret = odp_pktio_stop(pktio);
		t6 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Stopping pktio failed: %d\n", ret);
			return -1;
		}

		/* Clean possible pre-scheduled packets */
		clean_pending_events(appl_args);

		t7 = odp_time_local_strict();
		ret = odp_pktio_close(pktio);
		t8 = odp_time_local_strict();
		if (ret) {
			ODPH_ERR("Closing pktio failed: %d\n", ret);
			return -1;
		}

		bench_tm_func_record(t2, t1, res, id1);
		bench_tm_func_record(t3, t2, res, id2);
		bench_tm_func_record(t4, t3, res, id3);
		bench_tm_func_record(t5, t4, res, id4);
		bench_tm_func_record(t6, t5, res, id5);
		bench_tm_func_record(t8, t7, res, id6);
	}

	ret = odp_pool_destroy(pool);
	if (ret) {
		ODPH_ERR("Destroying pktio pool failed: %d\n", ret);
		return -1;
	}
	return 0;
}

static int pktio_stats(bench_tm_result_t *res, int repeat_count)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktio_stats_t *stats = &appl_args->stats;
	odp_pktio_t pktio = appl_args->pktio;
	odp_time_t t1, t2;
	int ret;
	uint8_t id1 = bench_tm_func_register(res, "odp_pktio_stats()");

	for (int i = 0; i < repeat_count; i++) {
		t1 = odp_time_local_strict();
		ret = odp_pktio_stats(pktio, stats);
		t2 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Reading pktio stats failed\n");
			return -1;
		}

		bench_tm_func_record(t2, t1, res, id1);
	}
	return 0;
}

static int pktio_stats_reset(bench_tm_result_t *res, int repeat_count)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktio_t pktio = appl_args->pktio;
	odp_time_t t1, t2;
	int ret;
	int id1 = bench_tm_func_register(res, "odp_pktio_stats_reset()");

	for (int i = 0; i < repeat_count; i++) {
		t1 = odp_time_local_strict();
		ret = odp_pktio_stats_reset(pktio);
		t2 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Resetting pktio stats failed\n");
			return -1;
		}

		bench_tm_func_record(t2, t1, res, id1);
	}
	return 0;
}

static int pktin_queue_stats(bench_tm_result_t *res, int repeat_count)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktin_queue_stats_t *stats = &appl_args->pktin_queue_stats;
	odp_pktio_t pktio = appl_args->pktio;
	odp_pktin_queue_t queue;
	odp_time_t t1, t2;
	int ret;
	uint8_t id1 = bench_tm_func_register(res, "odp_pktin_queue_stats()");

	ret = odp_pktin_queue(pktio, &queue, 1);
	if (ret < 1) {
		ODPH_ERR("Reading pktio input queue failed\n");
		return -1;
	}

	for (int i = 0; i < repeat_count; i++) {
		t1 = odp_time_local_strict();
		ret = odp_pktin_queue_stats(queue, stats);
		t2 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Reading pktio stats failed\n");
			return -1;
		}

		bench_tm_func_record(t2, t1, res, id1);
	}
	return 0;
}

static int pktin_event_queue_stats(bench_tm_result_t *res, int repeat_count)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktin_queue_stats_t *stats = &appl_args->pktin_queue_stats;
	odp_pktio_t pktio = appl_args->pktio;
	odp_queue_t queue;
	odp_time_t t1, t2;
	int ret;
	uint8_t id1 = bench_tm_func_register(res, "odp_pktin_event_queue_stats()");

	ret = odp_pktin_event_queue(pktio, &queue, 1);
	if (ret < 1) {
		ODPH_ERR("Reading pktio input queue failed\n");
		return -1;
	}

	for (int i = 0; i < repeat_count; i++) {
		t1 = odp_time_local_strict();
		ret = odp_pktin_event_queue_stats(pktio, queue, stats);
		t2 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Reading pktio stats failed\n");
			return -1;
		}

		bench_tm_func_record(t2, t1, res, id1);
	}
	return 0;
}

static int pktout_queue_stats(bench_tm_result_t *res, int repeat_count)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktout_queue_stats_t *stats = &appl_args->pktout_queue_stats;
	odp_pktio_t pktio = appl_args->pktio;
	odp_pktout_queue_t queue;
	odp_time_t t1, t2;
	int ret;
	uint8_t id1 = bench_tm_func_register(res, "odp_pktout_queue_stats()");

	ret = odp_pktout_queue(pktio, &queue, 1);
	if (ret < 1) {
		ODPH_ERR("Reading pktio input queue failed\n");
		return -1;
	}

	for (int i = 0; i < repeat_count; i++) {
		t1 = odp_time_local_strict();
		ret = odp_pktout_queue_stats(queue, stats);
		t2 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Reading pktio stats failed\n");
			return -1;
		}

		bench_tm_func_record(t2, t1, res, id1);
	}
	return 0;
}

static int pktout_event_queue_stats(bench_tm_result_t *res, int repeat_count)
{
	appl_args_t *appl_args = gbl_args;
	odp_pktout_queue_stats_t *stats = &appl_args->pktout_queue_stats;
	odp_pktio_t pktio = appl_args->pktio;
	odp_queue_t queue;
	odp_time_t t1, t2;
	int ret;
	uint8_t id1 = bench_tm_func_register(res, "odp_pktout_event_queue_stats()");

	ret = odp_pktout_event_queue(pktio, &queue, 1);
	if (ret < 1) {
		ODPH_ERR("Reading pktio input queue failed\n");
		return -1;
	}

	for (int i = 0; i < repeat_count; i++) {
		t1 = odp_time_local_strict();
		ret = odp_pktout_event_queue_stats(pktio, queue, stats);
		t2 = odp_time_local_strict();

		if (ret) {
			ODPH_ERR("Reading pktio stats failed\n");
			return -1;
		}

		bench_tm_func_record(t2, t1, res, id1);
	}
	return 0;
}

bench_tm_info_t test_suite[] = {
	BENCH_INFO(pktio_capability, pktio_setup, pktio_clean, 0),
	BENCH_INFO(pktio_lookup, pktio_setup, pktio_clean, 0),
	BENCH_INFO(pktio_open_start_stop_close, NULL, NULL, 0),
	BENCH_INFO(pktio_stats, pktio_setup, pktio_clean, 0),
	BENCH_INFO(pktin_queue_stats, pktio_setup_direct_rx, pktio_clean_direct_rx, 0),
	BENCH_INFO(pktin_event_queue_stats, pktio_setup_sched_rx, pktio_clean_sched_rx, 0),
	BENCH_INFO(pktout_queue_stats, pktio_setup_direct_tx, pktio_clean_direct_tx, 0),
	BENCH_INFO(pktout_event_queue_stats, pktio_setup_queue_tx, pktio_clean_queue_tx, 0),
	BENCH_INFO(pktio_stats_reset, pktio_setup, pktio_clean, 0)
};

/* Print usage information */
static void usage(void)
{
	printf("\n"
	       "ODP pktio API slow path micro benchmarks\n"
	       "\n"
	       "Options:\n"
	       "  -i, --interface <name>  Ethernet interface name (default loop).\n"
	       "  -m, --in_mode <arg>     Packet input mode\n"
	       "                          0: Direct mode: PKTIN_MODE_DIRECT (default)\n"
	       "                          1: Scheduler mode with parallel queues:\n"
	       "                             PKTIN_MODE_SCHED + SCHED_SYNC_PARALLEL\n"
	       "  -o, --out_mode <arg>    Packet output mode\n"
	       "                          0: Direct mode: PKTOUT_MODE_DIRECT (default)\n"
	       "                          1: Queue mode:  PKTOUT_MODE_QUEUE\n"
	       "  -q, --rx_queues <num>   Number of packet input queues (default 1)\n"
	       "  -t, --tx_queues <num>   Number of packet output queues (default 1)\n"
	       "  -r, --rounds <num>      Run each test case 'num' times (default %u).\n"
	       "  -s, --select <idx>      Run only selected test case.\n"
	       "  -h, --help              Display help and exit.\n\n"
	       "\n", ROUNDS);
}

static int parse_interface(appl_args_t *appl_args, const char *optarg)
{
	if (strlen(optarg) + 1 > MAX_NAME_LEN) {
		ODPH_ERR("Unable to store interface name (MAX_NAME_LEN=%d)\n", MAX_NAME_LEN);
		return -1;
	}
	strncpy(appl_args->opt.name, optarg, MAX_NAME_LEN);
	return 0;
}

/* Parse command line arguments */
static int parse_args(int argc, char *argv[])
{
	int i;
	int opt;
	int long_index;
	static const struct option longopts[] = {
		{"interface", required_argument, NULL, 'i'},
		{"in_mode", required_argument, NULL, 'm'},
		{"out_mode", required_argument, NULL, 'o'},
		{"rx_queues", required_argument, NULL, 'q'},
		{"tx_queues", required_argument, NULL, 't'},
		{"rounds", required_argument, NULL, 'r'},
		{"select", required_argument, NULL, 's'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "i:m:o:q:r:s:t:h";

	strncpy(gbl_args->opt.name, "loop", MAX_NAME_LEN);
	gbl_args->opt.rounds = ROUNDS;
	gbl_args->opt.in_mode = ODP_PKTIN_MODE_DIRECT;
	gbl_args->opt.out_mode = ODP_PKTOUT_MODE_DIRECT;
	gbl_args->opt.num_input_queues = 1;
	gbl_args->opt.num_output_queues = 1;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'i':
			if (parse_interface(gbl_args, optarg))
				return -1;
			break;
		case 'm':
			i = atoi(optarg);
			if (i == 1)
				gbl_args->opt.in_mode = ODP_PKTIN_MODE_SCHED;
			else
				gbl_args->opt.in_mode = ODP_PKTIN_MODE_DIRECT;
			break;
		case 'o':
			i = atoi(optarg);
			if (i == 1)
				gbl_args->opt.out_mode = ODP_PKTOUT_MODE_QUEUE;
			else
				gbl_args->opt.out_mode = ODP_PKTOUT_MODE_DIRECT;
			break;
		case 'q':
			gbl_args->opt.num_input_queues = atoi(optarg);
			break;
		case 'r':
			gbl_args->opt.rounds = atoi(optarg);
			break;
		case 's':
			gbl_args->opt.case_idx = atoi(optarg);
			break;
		case 't':
			gbl_args->opt.num_output_queues = atoi(optarg);
			break;
		case 'h':
			usage();
			return 1;
		default:
			ODPH_ERR("Bad option. Use -h for help.\n");
			return -1;
		}
	}

	return 0;
}

static int check_args(appl_args_t *appl_args)
{
	odp_pktio_param_t param;
	odp_pktio_capability_t capa;
	odp_pktio_t pktio;
	odp_pool_t pool;
	int ret;

	if (gbl_args->opt.rounds < 1) {
		ODPH_ERR("Invalid test repeat count: %u\n", gbl_args->opt.rounds);
		return -1;
	}

	if (gbl_args->opt.case_idx > sizeof(test_suite) / sizeof(test_suite[0])) {
		ODPH_ERR("Invalid test case index: %u\n", gbl_args->opt.case_idx);
		return -1;
	}

	pool = create_packet_pool();

	odp_pktio_param_init(&param);
	param.in_mode = appl_args->opt.in_mode;
	param.out_mode = appl_args->opt.out_mode;

	pktio = odp_pktio_open(appl_args->opt.name, pool, &param);
	if (pktio == ODP_PKTIO_INVALID) {
		ODPH_ERR("Opening pktio failed\n");
		return -1;
	}

	ret = odp_pktio_capability(pktio, &capa);
	if (ret) {
		ODPH_ERR("Reading pktio capa failed\n");
		return -1;
	}

	if (appl_args->opt.num_input_queues > capa.max_input_queues) {
		ODPH_ERR("Too many input queues: %u/%u\n", appl_args->opt.num_input_queues,
			 capa.max_input_queues);
		return -1;
	}

	if (appl_args->opt.num_output_queues > capa.max_output_queues) {
		ODPH_ERR("Too many output queues: %u/%u\n", appl_args->opt.num_output_queues,
			 capa.max_output_queues);
		return -1;
	}

	ret = odp_pktio_close(pktio);
	if (ret) {
		ODPH_ERR("Closing pktio failed: %d\n", ret);
		return -1;
	}

	ret = odp_pool_destroy(pool);
	if (ret) {
		ODPH_ERR("Destroying pktio pool failed: %d\n", ret);
		return -1;
	}

	return 0;
}

/* Print application info */
static void print_info(appl_args_t *appl_args)
{
	odp_sys_info_print();

	printf("\n"
	       "odp_bench_pktio_sp options\n"
	       "--------------------------\n");

	printf("CPU mask:          %s\n", gbl_args->cpumask_str);
	printf("Interface:         %s\n", gbl_args->opt.name);

	printf("Input mode:        ");
	if (appl_args->opt.in_mode == ODP_PKTIN_MODE_SCHED)
		printf("sched\n");
	else
		printf("direct\n");

	printf("Output mode:       ");
	if (appl_args->opt.out_mode == ODP_PKTOUT_MODE_QUEUE)
		printf("plain\n");
	else
		printf("direct\n");

	printf("Input queues:      %u\n", gbl_args->opt.num_input_queues);
	printf("Output queues:     %u\n", gbl_args->opt.num_output_queues);
	printf("Test rounds:       %d\n", gbl_args->opt.rounds);
	printf("\n");
}

int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	odph_thread_t worker_thread;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	odp_shm_t shm;
	odp_cpumask_t cpumask, default_mask;
	odp_instance_t instance;
	odp_init_t init_param;
	int cpu;
	int ret;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Reading ODP helper options failed\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("Global init failed\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed\n");
		exit(EXIT_FAILURE);
	}

	ret = odp_schedule_config(NULL);
	if (ret) {
		ODPH_ERR("Schedule config failed: %d\n", ret);
		exit(EXIT_FAILURE);
	}

	if (setup_sig_handler()) {
		ODPH_ERR("Signal handler setup failed\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(appl_args_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared mem reserve failed\n");
		exit(EXIT_FAILURE);
	}

	gbl_args = odp_shm_addr(shm);
	if (gbl_args == NULL) {
		ODPH_ERR("Shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}

	memset(gbl_args, 0, sizeof(appl_args_t));

	/* Parse and store the application arguments */
	ret = parse_args(argc, argv);
	if (ret)
		goto exit;

	if (check_args(gbl_args))
		goto exit;

	bench_tm_suite_init(&gbl_args->suite);
	gbl_args->suite.bench = test_suite;
	gbl_args->suite.num_bench = sizeof(test_suite) / sizeof(test_suite[0]);
	gbl_args->suite.rounds = gbl_args->opt.rounds;
	gbl_args->suite.bench_idx = gbl_args->opt.case_idx;

	/* Get default worker cpumask */
	if (odp_cpumask_default_worker(&default_mask, 1) != 1) {
		ODPH_ERR("Unable to allocate worker thread\n");
		ret = -1;
		goto exit;
	}

	(void)odp_cpumask_to_str(&default_mask, gbl_args->cpumask_str,
				 sizeof(gbl_args->cpumask_str));

	print_info(gbl_args);

	memset(&worker_thread, 0, sizeof(odph_thread_t));

	/* Create worker thread */
	cpu = odp_cpumask_first(&default_mask);

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, cpu);

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;

	odph_thread_param_init(&thr_param);
	thr_param.start = bench_tm_run;
	thr_param.arg = &gbl_args->suite;
	thr_param.thr_type = ODP_THREAD_WORKER;

	odph_thread_create(&worker_thread, &thr_common, &thr_param, 1);

	odph_thread_join(&worker_thread, 1);

	ret = gbl_args->suite.retval;

exit:
	if (odp_shm_free(shm)) {
		ODPH_ERR("Shared mem free failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Local term failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Global term failed\n");
		exit(EXIT_FAILURE);
	}

	if (ret < 0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2019-2025 Nokia
 */

/**
 * @example odp_pool_perf.c
 *
 * Performance test application for pool APIs
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <export_results.h>

#define STAT_AVAILABLE  0x1
#define STAT_CACHE      0x2
#define STAT_THR_CACHE  0x4
#define STAT_ALLOC_OPS  0x10
#define STAT_FREE_OPS   0x20
#define STAT_TOTAL_OPS  0x40

typedef struct test_options_t {
	uint32_t num_cpu;
	uint32_t num_event;
	uint32_t num_round;
	uint32_t max_burst;
	uint32_t num_burst;
	uint32_t data_size;
	uint32_t cache_size;
	uint32_t stats_mode;
	int      pool_type;

} test_options_t;

typedef struct test_stat_t {
	uint64_t rounds;
	uint64_t frees;
	uint64_t events;
	uint64_t nsec;
	uint64_t cycles;

} test_stat_t;

typedef struct test_global_t {
	test_options_t test_options;

	odp_barrier_t barrier;
	odp_pool_t pool;
	odp_cpumask_t cpumask;
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_stat_t stat[ODP_THREAD_COUNT_MAX];
	test_common_options_t common_options;

} test_global_t;

static void print_usage(void)
{
	printf("\n"
	       "Pool performance test\n"
	       "\n"
	       "Usage: odp_pool_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs. Default 1.\n"
	       "  -e, --num_event        Number of events\n"
	       "  -r, --num_round        Number of rounds\n"
	       "  -b, --burst            Maximum number of events per operation\n"
	       "  -n, --num_burst        Number of bursts allocated/freed back-to-back\n"
	       "  -s, --data_size        Data size in bytes\n"
	       "  -S, --stats_mode       Pool statistics usage. Enable counters with combination of these flags:\n"
	       "                              0: no pool statistics (default)\n"
	       "                            0x1: available\n"
	       "                            0x2: cache_available\n"
	       "                            0x4: thread_cache_available\n"
	       "                           0x10: alloc_ops\n"
	       "                           0x20: free_ops\n"
	       "                           0x40: total_ops\n"
	       "  -t, --pool_type        0: Buffer pool (default)\n"
	       "                         1: Packet pool\n"
	       "  -C, --cache_size       Pool cache size (per thread)\n"
	       "  -h, --help             This help\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt;
	int ret = 0;

	static const struct option longopts[] = {
		{"num_cpu",    required_argument, NULL, 'c'},
		{"num_event",  required_argument, NULL, 'e'},
		{"num_round",  required_argument, NULL, 'r'},
		{"burst",      required_argument, NULL, 'b'},
		{"num_burst",  required_argument, NULL, 'n'},
		{"data_size",  required_argument, NULL, 's'},
		{"stats_mode", required_argument, NULL, 'S'},
		{"pool_type",  required_argument, NULL, 't'},
		{"cache_size", required_argument, NULL, 'C'},
		{"help",       no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:e:r:b:n:s:S:t:C:h";

	test_options->num_cpu    = 1;
	test_options->num_event  = 1000;
	test_options->num_round  = 100000;
	test_options->max_burst  = 100;
	test_options->num_burst  = 1;
	test_options->data_size  = 64;
	test_options->stats_mode = 0;
	test_options->pool_type  = 0;
	test_options->cache_size = UINT32_MAX;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 'e':
			test_options->num_event = atoi(optarg);
			break;
		case 'r':
			test_options->num_round = atoi(optarg);
			break;
		case 'b':
			test_options->max_burst = atoi(optarg);
			break;
		case 'n':
			test_options->num_burst = atoi(optarg);
			break;
		case 's':
			test_options->data_size = atoi(optarg);
			break;
		case 'S':
			test_options->stats_mode = strtoul(optarg, NULL, 0);
			break;
		case 't':
			test_options->pool_type = atoi(optarg);
			break;
		case 'C':
			test_options->cache_size = atoi(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_options->num_burst * test_options->max_burst >
	    test_options->num_event) {
		printf("Not enough events (%u) for the burst configuration.\n"
		       "Use smaller burst size (%u) or less bursts (%u)\n",
		       test_options->num_event, test_options->max_burst,
		       test_options->num_burst);
		ret = -1;
	}

	return ret;
}

static int set_num_cpu(test_global_t *global)
{
	int ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;

	/* One thread used for the main thread */
	if (num_cpu > ODP_THREAD_COUNT_MAX - 1) {
		printf("Error: Too many workers. Maximum is %i.\n",
		       ODP_THREAD_COUNT_MAX - 1);
		return -1;
	}

	ret = odp_cpumask_default_worker(&global->cpumask, num_cpu);

	if (num_cpu && ret != num_cpu) {
		printf("Error: Too many workers. Max supported %i.\n", ret);
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	odp_barrier_init(&global->barrier, num_cpu);

	return 0;
}

static int create_pool(test_global_t *global)
{
	odp_pool_capability_t pool_capa;
	odp_pool_param_t pool_param;
	odp_pool_t pool;
	odp_pool_stats_opt_t stats, stats_capa;
	uint32_t max_num, max_size, min_cache_size, max_cache_size;
	test_options_t *test_options = &global->test_options;
	uint32_t num_event  = test_options->num_event;
	uint32_t num_round  = test_options->num_round;
	uint32_t max_burst  = test_options->max_burst;
	uint32_t num_burst  = test_options->num_burst;
	uint32_t num_cpu    = test_options->num_cpu;
	uint32_t data_size  = test_options->data_size;
	uint32_t cache_size = test_options->cache_size;
	uint32_t stats_mode = test_options->stats_mode;
	int packet_pool = test_options->pool_type;

	stats.all = 0;

	odp_pool_param_init(&pool_param);

	if (cache_size == UINT32_MAX)
		cache_size = packet_pool ? pool_param.pkt.cache_size :
				pool_param.buf.cache_size;

	if (stats_mode & STAT_AVAILABLE)
		stats.bit.available = 1;
	if (stats_mode & STAT_CACHE)
		stats.bit.cache_available = 1;
	if (stats_mode & STAT_THR_CACHE)
		stats.bit.thread_cache_available = 1;
	if (stats_mode & STAT_ALLOC_OPS)
		stats.bit.alloc_ops = 1;
	if (stats_mode & STAT_FREE_OPS)
		stats.bit.free_ops = 1;
	if (stats_mode & STAT_TOTAL_OPS)
		stats.bit.total_ops = 1;

	printf("\nPool performance test\n");
	printf("  num cpu    %u\n", num_cpu);
	printf("  num rounds %u\n", num_round);
	printf("  num events %u\n", num_event);
	printf("  max burst  %u\n", max_burst);
	printf("  num bursts %u\n", num_burst);
	printf("  data size  %u\n", data_size);
	printf("  cache size %u\n", cache_size);
	printf("  stats mode 0x%x\n", stats_mode);
	printf("  pool type  %s\n\n", packet_pool ? "packet" : "buffer");

	if (odp_pool_capability(&pool_capa)) {
		printf("Error: Pool capa failed.\n");
		return -1;
	}

	if (packet_pool) {
		max_num        = pool_capa.pkt.max_num;
		max_size       = pool_capa.pkt.max_len;
		max_cache_size = pool_capa.pkt.max_cache_size;
		min_cache_size = pool_capa.pkt.min_cache_size;
		stats_capa     = pool_capa.pkt.stats;
	} else {
		max_num        = pool_capa.buf.max_num;
		max_size       = pool_capa.buf.max_size;
		max_cache_size = pool_capa.buf.max_cache_size;
		min_cache_size = pool_capa.buf.min_cache_size;
		stats_capa     = pool_capa.buf.stats;
	}

	if ((stats_capa.all & stats.all) != stats.all) {
		printf("Error: requested statistics not supported (0x%" PRIx64 " / 0x%" PRIx64 ")\n",
		       stats.all, stats_capa.all);
		return -1;
	}

	if (cache_size < min_cache_size) {
		printf("Error: min cache size supported %u\n", min_cache_size);
		return -1;
	}

	if (cache_size > max_cache_size) {
		printf("Error: max cache size supported %u\n", max_cache_size);
		return -1;
	}

	if (max_num && num_event > max_num) {
		printf("Error: max events supported %u\n", max_num);
		return -1;
	}

	if (max_size && data_size > max_size) {
		printf("Error: max data size supported %u\n", max_size);
		return -1;
	}

	if (packet_pool) {
		pool_param.type           = ODP_POOL_PACKET;
		pool_param.pkt.num        = num_event;
		pool_param.pkt.len        = data_size;
		pool_param.pkt.max_num    = num_event;
		pool_param.pkt.max_len    = data_size;
		pool_param.pkt.cache_size = cache_size;
	} else {
		pool_param.type           = ODP_POOL_BUFFER;
		pool_param.buf.num        = num_event;
		pool_param.buf.size       = data_size;
		pool_param.buf.cache_size = cache_size;
	}

	pool_param.stats.all = stats.all;

	pool = odp_pool_create("pool perf", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		printf("Error: Pool create failed.\n");
		return -1;
	}

	global->pool = pool;

	return 0;
}

static int test_buffer_pool(void *arg)
{
	int ret, thr;
	uint32_t num, num_free, num_freed, i, rounds;
	uint64_t c1, c2, cycles, nsec;
	uint64_t events, frees;
	odp_time_t t1, t2;
	test_global_t *global = arg;
	test_options_t *test_options = &global->test_options;
	uint32_t num_round = test_options->num_round;
	uint32_t max_burst = test_options->max_burst;
	uint32_t num_burst = test_options->num_burst;
	uint32_t max_num = num_burst * max_burst;
	odp_pool_t pool = global->pool;
	odp_buffer_t buf[max_num];

	thr = odp_thread_id();

	for (i = 0; i < max_num; i++)
		buf[i] = ODP_BUFFER_INVALID;

	events = 0;
	frees = 0;
	ret = 0;

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();
	c1 = odp_cpu_cycles();

	for (rounds = 0; rounds < num_round; rounds++) {
		num = 0;

		for (i = 0; i < num_burst; i++) {
			ret = odp_buffer_alloc_multi(pool, &buf[num],
						     max_burst);
			if (odp_unlikely(ret < 0)) {
				printf("Error: Alloc failed. Round %u\n",
				       rounds);
				if (num)
					odp_buffer_free_multi(buf, num);

				return -1;
			}

			num += ret;
		}

		if (odp_unlikely(num == 0))
			continue;

		events += num;
		num_freed = 0;

		while (num_freed < num) {
			num_free = num - num_freed;
			if (num_free > max_burst)
				num_free = max_burst;

			odp_buffer_free_multi(&buf[num_freed], num_free);
			frees++;
			num_freed += num_free;
		}
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local();

	nsec   = odp_time_diff_ns(t2, t1);
	cycles = odp_cpu_cycles_diff(c2, c1);

	/* Update stats*/
	global->stat[thr].rounds = rounds;
	global->stat[thr].frees  = frees;
	global->stat[thr].events = events;
	global->stat[thr].nsec   = nsec;
	global->stat[thr].cycles = cycles;

	return 0;
}

static int test_packet_pool(void *arg)
{
	int ret, thr;
	uint32_t num, num_free, num_freed, i, rounds;
	uint64_t c1, c2, cycles, nsec;
	uint64_t events, frees;
	odp_time_t t1, t2;
	test_global_t *global = arg;
	test_options_t *test_options = &global->test_options;
	uint32_t num_round = test_options->num_round;
	uint32_t max_burst = test_options->max_burst;
	uint32_t num_burst = test_options->num_burst;
	uint32_t max_num = num_burst * max_burst;
	uint32_t data_size = test_options->data_size;
	odp_pool_t pool = global->pool;
	odp_packet_t pkt[max_num];

	thr = odp_thread_id();

	for (i = 0; i < max_num; i++)
		pkt[i] = ODP_PACKET_INVALID;

	events = 0;
	frees = 0;
	ret = 0;

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();
	c1 = odp_cpu_cycles();

	for (rounds = 0; rounds < num_round; rounds++) {
		num = 0;

		for (i = 0; i < num_burst; i++) {
			ret = odp_packet_alloc_multi(pool, data_size, &pkt[num],
						     max_burst);
			if (odp_unlikely(ret < 0)) {
				printf("Error: Alloc failed. Round %u\n",
				       rounds);

				if (num)
					odp_packet_free_multi(pkt, num);

				return -1;
			}

			num += ret;
		}

		if (odp_unlikely(num == 0))
			continue;

		events += num;
		num_freed = 0;

		while (num_freed < num) {
			num_free = num - num_freed;
			if (num_free > max_burst)
				num_free = max_burst;

			odp_packet_free_multi(&pkt[num_freed], num_free);
			frees++;
			num_freed += num_free;
		}
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local();

	nsec   = odp_time_diff_ns(t2, t1);
	cycles = odp_cpu_cycles_diff(c2, c1);

	/* Update stats*/
	global->stat[thr].rounds = rounds;
	global->stat[thr].frees  = frees;
	global->stat[thr].events = events;
	global->stat[thr].nsec   = nsec;
	global->stat[thr].cycles = cycles;

	return 0;
}

static int start_workers(test_global_t *global, odp_instance_t instance)
{
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	int packet_pool = test_options->pool_type;

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &global->cpumask;
	thr_common.share_param = 1;

	odph_thread_param_init(&thr_param);
	thr_param.arg = global;
	thr_param.thr_type = ODP_THREAD_WORKER;

	if (packet_pool)
		thr_param.start = test_packet_pool;
	else
		thr_param.start = test_buffer_pool;

	if (odph_thread_create(global->thread_tbl, &thr_common, &thr_param,
			       num_cpu) != num_cpu)
		return -1;

	return 0;
}

static void test_stats_perf(test_global_t *global)
{
	odp_pool_stats_t stats;
	odp_time_t t1, t2;
	uint64_t nsec;
	int i;
	int num_thr = global->test_options.num_cpu + 1; /* workers + main thread */
	odp_pool_t pool = global->pool;
	double nsec_ave = 0.0;
	const int rounds = 1000;

	if (num_thr > ODP_POOL_MAX_THREAD_STATS)
		num_thr = ODP_POOL_MAX_THREAD_STATS;

	memset(&stats, 0, sizeof(odp_pool_stats_t));
	stats.thread.first = 0;
	stats.thread.last  = num_thr - 1;

	t1 = odp_time_local_strict();

	for (i = 0; i < rounds; i++) {
		if (odp_pool_stats(pool, &stats)) {
			printf("Error: Stats request failed on round %i\n", i);
			break;
		}
	}

	t2 = odp_time_local_strict();
	nsec = odp_time_diff_ns(t2, t1);

	if (i > 0)
		nsec_ave = (double)nsec / i;

	printf("Pool statistics:\n");
	printf("  odp_pool_stats() calls   %i\n", i);
	printf("  ave call latency         %.2f nsec\n", nsec_ave);
	printf("  num threads              %i\n", num_thr);
	printf("  alloc_ops                %" PRIu64 "\n", stats.alloc_ops);
	printf("  free_ops                 %" PRIu64 "\n", stats.free_ops);
	printf("  total_ops                %" PRIu64 "\n", stats.total_ops);
	printf("  available                %" PRIu64 "\n", stats.available);
	printf("  cache_available          %" PRIu64 "\n", stats.cache_available);
	for (i = 0; i < num_thr; i++) {
		printf("  thr[%2i] cache_available  %" PRIu64 "\n",
		       i, stats.thread.cache_available[i]);
	}

	printf("\n");
}

static int output_results(test_global_t *global)
{
	int i, num;
	double rounds_ave, allocs_ave, frees_ave;
	double events_ave, nsec_ave, cycles_ave;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	uint32_t num_burst = test_options->num_burst;
	uint64_t rounds_sum = 0;
	uint64_t frees_sum = 0;
	uint64_t events_sum = 0;
	uint64_t nsec_sum = 0;
	uint64_t cycles_sum = 0;

	/* Averages */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		rounds_sum += global->stat[i].rounds;
		frees_sum  += global->stat[i].frees;
		events_sum += global->stat[i].events;
		nsec_sum   += global->stat[i].nsec;
		cycles_sum += global->stat[i].cycles;
	}

	if (rounds_sum == 0) {
		printf("No results.\n");
		return 0;
	}

	rounds_ave = rounds_sum / num_cpu;
	allocs_ave = (num_burst * rounds_sum) / num_cpu;
	frees_ave  = frees_sum / num_cpu;
	events_ave = events_sum / num_cpu;
	nsec_ave   = nsec_sum / num_cpu;
	cycles_ave = cycles_sum / num_cpu;
	num = 0;

	printf("RESULTS - per thread (Million events per sec):\n");
	printf("----------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->stat[i].rounds) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%6.1f ", (1000.0 * global->stat[i].events) /
			       global->stat[i].nsec);
			num++;
		}
	}
	printf("\n\n");

	printf("RESULTS - average over %i threads:\n", num_cpu);
	printf("----------------------------------\n");
	printf("  alloc calls:          %.3f\n", allocs_ave);
	printf("  free calls:           %.3f\n", frees_ave);
	printf("  duration:             %.3f msec\n", nsec_ave / 1000000);
	printf("  num cycles:           %.3f M\n", cycles_ave / 1000000);
	printf("  cycles per round:     %.3f\n",
	       cycles_ave / rounds_ave);
	printf("  cycles per event:     %.3f\n",
	       cycles_ave / events_ave);
	printf("  ave events allocated: %.3f\n",
	       events_ave / allocs_ave);
	printf("  allocs per sec:       %.3f M\n",
	       (1000.0 * allocs_ave) / nsec_ave);
	printf("  frees per sec:        %.3f M\n",
	       (1000.0 * frees_ave) / nsec_ave);
	printf("  events per sec:       %.3f M\n\n",
	       (1000.0 * events_ave) / nsec_ave);

	printf("TOTAL events per sec:	%.3f M\n\n",
	       (1000.0 * events_sum) / nsec_ave);

	if (global->common_options.is_export) {
		if (test_common_write("alloc calls,free calls,duration (msec),"
				      "num cycles (M),cycles per round,cycles per event,"
				      "ave events allocated,allocs per sec (M),frees per sec (M),"
				      "events per sec (M),total events per sec (M)\n")) {
			ODPH_ERR("Export failed\n");
			test_common_write_term();
			return -1;
		}

		if (test_common_write("%f,%f,%f,%f,%f,%f,%f,%f,%f,%f,%f\n",
				      allocs_ave, frees_ave, nsec_ave / 1000000,
				      cycles_ave / 1000000, cycles_ave / rounds_ave,
				      cycles_ave / events_ave, events_ave / allocs_ave,
				      (1000.0 * allocs_ave) / nsec_ave,
				      (1000.0 * frees_ave) / nsec_ave,
				      (1000.0 * events_ave) / nsec_ave,
				      (1000.0 * events_sum) / nsec_ave)) {
			ODPH_ERR("Export failed\n");
			test_common_write_term();
			return -1;
		}

		test_common_write_term();
	}

	return 0;
}

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm;
	test_global_t *global;
	test_common_options_t common_options;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	argc = test_common_parse_options(argc, argv);
	if (test_common_options(&common_options)) {
		ODPH_ERR("Error: Reading test options failed\n");
		exit(EXIT_FAILURE);
	}

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.schedule = 1;
	init.not_used.feat.timer    = 1;
	init.not_used.feat.tm       = 1;

	init.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		printf("Error: Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		printf("Error: Local init failed.\n");
		return -1;
	}

	shm = odp_shm_reserve("pool_perf_global", sizeof(test_global_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: Shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	global = odp_shm_addr(shm);
	if (global == NULL) {
		ODPH_ERR("Error: Shared mem alloc failed\n");
		exit(EXIT_FAILURE);
	}

	memset(global, 0, sizeof(test_global_t));
	global->pool = ODP_POOL_INVALID;

	global->common_options = common_options;

	if (parse_options(argc, argv, &global->test_options))
		return -1;

	odp_sys_info_print();

	if (set_num_cpu(global))
		return -1;

	if (create_pool(global))
		return -1;

	/* Start workers */
	start_workers(global, instance);

	/* Wait workers to exit */
	odph_thread_join(global->thread_tbl, global->test_options.num_cpu);

	if (global->test_options.stats_mode)
		test_stats_perf(global);

	if (output_results(global))
		return -1;

	if (odp_pool_destroy(global->pool)) {
		printf("Error: Pool destroy failed.\n");
		return -1;
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Error: Shared mem free failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		printf("Error: term local failed.\n");
		return -1;
	}

	if (odp_term_global(instance)) {
		printf("Error: term global failed.\n");
		return -1;
	}

	return 0;
}

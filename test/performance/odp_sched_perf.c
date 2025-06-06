/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2020-2025 Nokia
 */

/**
 * @example odp_sched_perf.c
 *
 * Performance test application for scheduling
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Needed for sigaction */
#endif

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <export_results.h>

#define MAX_QUEUES  (256 * 1024)
#define MAX_GROUPS  256

/* Limit data values to 16 bits. Large data values are costly on square root calculation. */
#define DATA_MASK   0xffff

/* Max time to wait for new events in nanoseconds */
#define MAX_SCHED_WAIT_NS (10 * ODP_TIME_SEC_IN_NS)

/* Scheduling round interval to check for MAX_SCHED_WAIT_NS */
#define TIME_CHECK_INTERVAL  (1024 * 1024)

typedef struct test_options_t {
	uint32_t num_cpu;
	uint32_t num_queue; /* Active queues (excludes dummy queues) */
	uint32_t num_def;
	uint32_t num_low;
	uint32_t num_high;
	uint32_t num_dummy;
	uint32_t num_event;
	uint32_t num_sched;
	int      num_group;
	uint32_t num_join;
	uint32_t max_burst;
	odp_pool_type_t pool_type;
	int      queue_type;
	int      forward;
	int      fairness;
	uint32_t event_size;
	uint32_t queue_size;
	uint32_t forward_group_size;
	uint32_t tot_queue; /* All queues (includes dummy queues) */
	uint32_t tot_event;
	int      touch_data;
	uint32_t stress;
	uint32_t rd_words;
	uint32_t rw_words;
	uint32_t ctx_size;
	uint32_t ctx_rd_words;
	uint32_t ctx_rw_words;
	uint32_t tot_rd_size;
	uint32_t tot_rw_size;
	uint32_t uarea_rd;
	uint32_t uarea_rw;
	uint32_t uarea_size;
	uint64_t wait_ns;
	int      verbose;

} test_options_t;

typedef struct test_stat_t {
	uint64_t rounds;
	uint64_t enqueues;
	uint64_t events;
	uint64_t nsec;
	uint64_t cycles;
	uint64_t waits;
	uint64_t dummy_sum;
	uint8_t  failed;

} test_stat_t;

typedef struct thread_arg_t {
	void *global;
	int first_group;

} thread_arg_t;

typedef struct test_global_t {
	test_options_t test_options;
	odp_schedule_config_t schedule_config;
	odp_barrier_t barrier;
	odp_pool_t pool;
	odp_cpumask_t cpumask;
	odp_shm_t ctx_shm;
	struct {
		odp_queue_t dummy[MAX_QUEUES];
		odp_queue_t def_prio[MAX_QUEUES];
		odp_queue_t low_prio[MAX_QUEUES];
		odp_queue_t high_prio[MAX_QUEUES];
		odp_queue_t all[MAX_QUEUES];
	} queue;
	odp_schedule_group_t group[MAX_GROUPS];
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_stat_t stat[ODP_THREAD_COUNT_MAX];
	thread_arg_t thread_arg[ODP_THREAD_COUNT_MAX];
	odp_atomic_u32_t num_worker;
	odp_atomic_u32_t exit_threads;
	test_common_options_t common_options;

} test_global_t;

typedef struct {
	odp_queue_t next;
	odp_atomic_u64_t count;
} queue_context_t;

static test_global_t *test_globals;

static void sig_handler(int signum ODP_UNUSED)
{
	odp_atomic_store_u32(&test_globals->exit_threads, 1);
}

static int setup_sig_handler(void)
{
	struct sigaction action = { .sa_handler = sig_handler };

	if (sigemptyset(&action.sa_mask) || sigaction(SIGINT, &action, NULL))
		return -1;

	return 0;
}

static void print_usage(void)
{
	printf("\n"
	       "Scheduler performance test\n"
	       "\n"
	       "Usage: odp_sched_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs. Default: 1.\n"
	       "  -q, --num_def          Number of default priority queues. Default: 1.\n"
	       "  -L, --num_low          Number of lowest priority queues. Default: 0.\n"
	       "  -H, --num_high         Number of highest priority queues. Default: 0.\n"
	       "  -d, --num_dummy        Number of empty queues. Default: 0.\n"
	       "  -e, --num_event        Number of events per queue. Default: 100.\n"
	       "  -s, --num_sched        Number of events to schedule per thread. If zero, the application runs\n"
	       "                         until SIGINT is received. Default: 100 000.\n"
	       "  -g, --num_group        Number of schedule groups. Round robins threads and queues into groups.\n"
	       "                         -1: SCHED_GROUP_WORKER\n"
	       "                         0:  SCHED_GROUP_ALL (default)\n"
	       "  -j, --num_join         Number of groups a thread joins. Threads are divide evenly into groups,\n"
	       "                         if num_cpu is multiple of num_group and num_group is multiple of num_join.\n"
	       "                         0: join all groups (default)\n"
	       "  -b, --burst            Maximum number of events per operation. Default: 100.\n"
	       "  -t, --type             Queue type. 0: parallel, 1: atomic, 2: ordered. Default: 0.\n"
	       "  -f, --forward          0: Keep event in the original queue (default)\n"
	       "                         1: Forward event between all queues\n"
	       "                         N: Forward events between queues of N identical queue sets. In this mode 'num_def',\n"
	       "                            'num_low', and 'num_high' options are per set, so the total number of active\n"
	       "                            queues is N * (num_def + num_low + num_high).\n"
	       "  -F, --fairness         0: Don't count events per queue, 1: Count and report events relative to average. Default: 0.\n"
	       "  -w, --wait_ns          Number of nsec to wait before enqueueing events. Default: 0.\n"
	       "  -S, --stress           CPU stress function(s) to be called for each event data word (requires -n or -m).\n"
	       "                         Data is processed as uint32_t words. Multiple flags may be selected.\n"
	       "                         0:   No extra data processing (default)\n"
	       "                         0x1: Calculate square of each uint32_t\n"
	       "                         0x2: Calculate log2 of each uint32_t\n"
	       "                         0x4: Calculate square root of each uint32_t\n"
	       "                         0x8: Calculate square root of each uint32_t in floating point\n"
	       "  -k, --ctx_rd_words     Number of queue context words (uint64_t) to read on every event. Default: 0.\n"
	       "  -l, --ctx_rw_words     Number of queue context words (uint64_t) to modify on every event. Default: 0.\n"
	       "  -n, --rd_words         Number of event data words (uint64_t) to read before enqueueing it. Default: 0.\n"
	       "  -m, --rw_words         Number of event data words (uint64_t) to modify before enqueueing it. Default: 0.\n"
	       "  -u, --uarea_rd         Number of user area words (uint64_t) to read on every event. Default: 0.\n"
	       "  -U, --uarea_rw         Number of user area words (uint64_t) to modify on every event. Default: 0.\n"
	       "  -p, --pool_type        Pool type. 0: buffer, 1: packet. Default: 0.\n"
	       "  -v, --verbose          Verbose output.\n"
	       "  -h, --help             This help\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt, num_group, num_join;
	int ret = 0;
	uint32_t ctx_size = 0;
	int pool_type = 0;

	static const struct option longopts[] = {
		{"num_cpu",      required_argument, NULL, 'c'},
		{"num_def",      required_argument, NULL, 'q'},
		{"num_low",      required_argument, NULL, 'L'},
		{"num_high",     required_argument, NULL, 'H'},
		{"num_dummy",    required_argument, NULL, 'd'},
		{"num_event",    required_argument, NULL, 'e'},
		{"num_sched",    required_argument, NULL, 's'},
		{"num_group",    required_argument, NULL, 'g'},
		{"num_join",     required_argument, NULL, 'j'},
		{"burst",        required_argument, NULL, 'b'},
		{"type",         required_argument, NULL, 't'},
		{"forward",      required_argument, NULL, 'f'},
		{"fairness",     required_argument, NULL, 'F'},
		{"wait_ns",      required_argument, NULL, 'w'},
		{"stress",       required_argument, NULL, 'S'},
		{"ctx_rd_words", required_argument, NULL, 'k'},
		{"ctx_rw_words", required_argument, NULL, 'l'},
		{"rd_words",     required_argument, NULL, 'n'},
		{"rw_words",     required_argument, NULL, 'm'},
		{"uarea_rd",     required_argument, NULL, 'u'},
		{"uarea_rw",     required_argument, NULL, 'U'},
		{"pool_type",    required_argument, NULL, 'p'},
		{"verbose",      no_argument,       NULL, 'v'},
		{"help",         no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:q:L:H:d:e:s:g:j:b:t:f:F:w:S:k:l:n:m:p:u:U:vh";

	test_options->num_cpu    = 1;
	test_options->num_def    = 1;
	test_options->num_low    = 0;
	test_options->num_high   = 0;
	test_options->num_dummy  = 0;
	test_options->num_event  = 100;
	test_options->num_sched  = 100000;
	test_options->num_group  = 0;
	test_options->num_join   = 0;
	test_options->max_burst  = 100;
	test_options->queue_type = 0;
	test_options->forward    = 0;
	test_options->fairness   = 0;
	test_options->stress     = 0;
	test_options->ctx_rd_words = 0;
	test_options->ctx_rw_words = 0;
	test_options->rd_words   = 0;
	test_options->rw_words   = 0;
	test_options->uarea_rd   = 0;
	test_options->uarea_rw   = 0;
	test_options->wait_ns    = 0;
	test_options->verbose    = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 'q':
			test_options->num_def = atoi(optarg);
			break;
		case 'L':
			test_options->num_low = atoi(optarg);
			break;
		case 'H':
			test_options->num_high = atoi(optarg);
			break;
		case 'd':
			test_options->num_dummy = atoi(optarg);
			break;
		case 'e':
			test_options->num_event = atoi(optarg);
			break;
		case 's':
			test_options->num_sched = atoi(optarg);
			break;
		case 'g':
			test_options->num_group = atoi(optarg);
			break;
		case 'j':
			test_options->num_join = atoi(optarg);
			break;
		case 'b':
			test_options->max_burst = atoi(optarg);
			break;
		case 't':
			test_options->queue_type = atoi(optarg);
			break;
		case 'f':
			test_options->forward = atoi(optarg);
			break;
		case 'F':
			test_options->fairness = atoi(optarg);
			break;
		case 'S':
			test_options->stress = strtoul(optarg, NULL, 0);
			break;
		case 'k':
			test_options->ctx_rd_words = atoi(optarg);
			break;
		case 'l':
			test_options->ctx_rw_words = atoi(optarg);
			break;
		case 'n':
			test_options->rd_words = atoi(optarg);
			break;
		case 'm':
			test_options->rw_words = atoi(optarg);
			break;
		case 'u':
			test_options->uarea_rd = atoi(optarg);
			break;
		case 'U':
			test_options->uarea_rw = atoi(optarg);
			break;
		case 'p':
			pool_type = atoi(optarg);
			break;
		case 'w':
			test_options->wait_ns = atoll(optarg);
			break;
		case 'v':
			test_options->verbose = 1;
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}
	if (pool_type == 0) {
		test_options->pool_type = ODP_POOL_BUFFER;
	} else if (pool_type == 1) {
		test_options->pool_type = ODP_POOL_PACKET;
	} else {
		ODPH_ERR("Invalid pool type: %d.\n", pool_type);
		ret = -1;
	}

	test_options->touch_data = test_options->rd_words ||
				   test_options->rw_words;

	if (test_options->stress && test_options->touch_data == 0) {
		ODPH_ERR("Use -n or/and -m to select event data size with a stress function\n");
		ret = -1;
	}

	test_options->forward_group_size = test_options->num_def + test_options->num_low +
						test_options->num_high;
	/* In queue group forward mode the queue count options are per group */
	if (test_options->forward > 1) {
		test_options->num_def *= test_options->forward;
		test_options->num_low *= test_options->forward;
		test_options->num_high *= test_options->forward;
	} else if (test_options->forward < 0) {
		ODPH_ERR("Invalid forward mode %i.\n", test_options->forward);
		ret = -1;
	}

	test_options->num_queue = test_options->num_def + test_options->num_low +
					test_options->num_high;
	if ((test_options->num_queue + test_options->num_dummy) > MAX_QUEUES) {
		ODPH_ERR("Too many queues. Max supported %i.\n", MAX_QUEUES);
		ret = -1;
	}

	num_group = test_options->num_group;
	num_join  = test_options->num_join;
	if (num_group > MAX_GROUPS) {
		ODPH_ERR("Too many groups. Max supported %i.\n", MAX_GROUPS);
		ret = -1;
	}

	if (num_group > 0 && num_join > num_group) {
		ODPH_ERR("num_join (%i) larger than num_group (%i).\n", num_join, num_group);
		ret = -1;
	}

	if (num_join && num_group > (int)(test_options->num_cpu * num_join)) {
		printf("WARNING: Too many groups (%i). Some groups (%i) are not served.\n\n",
		       num_group, num_group - (test_options->num_cpu * num_join));

		if (test_options->forward) {
			ODPH_ERR("Cannot forward when some queues are not served.\n");
			ret = -1;
		}
	}

	test_options->tot_queue = test_options->num_queue +
				  test_options->num_dummy;
	test_options->tot_event = test_options->num_queue *
				  test_options->num_event;

	test_options->queue_size = test_options->num_event;

	if (test_options->forward) {
		/* When forwarding, events may accumulate into a single queue. */
		test_options->queue_size *= test_options->forward_group_size;
	}

	if (test_options->forward || test_options->fairness)
		ctx_size = sizeof(queue_context_t);

	if (test_options->ctx_rd_words || test_options->ctx_rw_words) {
		/* Round up queue handle size to a multiple of 8 for correct
		 * context data alignment */
		ctx_size = ODPH_ROUNDUP_MULTIPLE(ctx_size, 8);
		ctx_size += 8 * test_options->ctx_rd_words;
		ctx_size += 8 * test_options->ctx_rw_words;
	}

	/* When context data is modified, round up to cache line size to avoid
	 * false sharing */
	if (test_options->fairness || test_options->ctx_rw_words)
		ctx_size = ODP_CACHE_LINE_ROUNDUP(ctx_size);

	test_options->ctx_size = ctx_size;
	test_options->uarea_size = 8 * (test_options->uarea_rd + test_options->uarea_rw);
	test_options->tot_rd_size = 8 * (test_options->ctx_rd_words + test_options->uarea_rd +
					 test_options->rd_words);
	test_options->tot_rw_size = 8 * (test_options->ctx_rw_words + test_options->uarea_rw +
					 test_options->rw_words);

	return ret;
}

static int set_num_cpu(test_global_t *global)
{
	int ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;

	/* One thread used for the main thread */
	if (num_cpu > ODP_THREAD_COUNT_MAX - 1) {
		ODPH_ERR("Too many workers. Maximum is %i.\n", ODP_THREAD_COUNT_MAX - 1);
		return -1;
	}

	ret = odp_cpumask_default_worker(&global->cpumask, num_cpu);

	if (num_cpu && ret != num_cpu) {
		ODPH_ERR("Too many workers. Max supported %i\n.", ret);
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

static uint64_t init_data(uint64_t init, uint64_t *data, uint32_t words)
{
	uint32_t i;
	uint64_t val = init;

	for (i = 0; i < words; i++) {
		data[i] = val;
		val = (val + 1) & DATA_MASK;
	}

	return val;
}

static void print_options(test_options_t *options)
{
	printf("\nScheduler performance test\n");
	printf("  num sched                 %u\n", options->num_sched);
	printf("  num cpu                   %u\n", options->num_cpu);
	printf("  num default prio queues   %u\n", options->num_def);
	printf("  num lowest prio queues    %u\n", options->num_low);
	printf("  num highest prio queues   %u\n", options->num_high);
	printf("  num empty queues          %u\n", options->num_dummy);
	printf("  total queues              %u\n", options->tot_queue);
	printf("  num groups                %i", options->num_group);

	if (options->num_group == -1)
		printf(" (ODP_SCHED_GROUP_WORKER)\n");
	else if (options->num_group == 0)
		printf(" (ODP_SCHED_GROUP_ALL)\n");
	else
		printf("\n");

	printf("  num join                  %u\n", options->num_join);
	printf("  forward events            %i\n", options->forward);
	printf("  wait                      %" PRIu64 " nsec\n", options->wait_ns);
	printf("  events per queue          %u\n", options->num_event);
	printf("  queue size                %u\n", options->queue_size);
	printf("  max burst size            %u\n", options->max_burst);
	printf("  total events              %u\n", options->tot_event);
	printf("  stress                    0x%x\n", options->stress);

	printf("  event size                %u bytes", options->event_size);
	if (options->touch_data)
		printf(" (rd: %u, rw: %u)", 8 * options->rd_words, 8 * options->rw_words);
	printf("\n");

	printf("  queue context size        %u bytes", options->ctx_size);
	if (options->ctx_rd_words || options->ctx_rw_words) {
		printf(" (rd: %u, rw: %u)",
		       8 * options->ctx_rd_words,
		       8 * options->ctx_rw_words);
	}
	printf("\n");

	printf("  user area size            %u bytes", options->uarea_size);
	if (options->uarea_size)
		printf(" (rd: %u, rw: %u)", 8 * options->uarea_rd, 8 * options->uarea_rw);
	printf("\n");

	printf("  pool type                 %s\n", options->pool_type == ODP_POOL_BUFFER ?
						   "buffer" : "packet");

	printf("  queue type                %s\n\n", options->queue_type == 0 ? "parallel" :
						     options->queue_type == 1 ? "atomic" :
						     "ordered");

	printf("Extra rd/rw ops per event (queue context + user area + event data)\n");
	printf("  read                      %u bytes\n", options->tot_rd_size);
	printf("  write                     %u bytes\n\n", options->tot_rw_size);
}

static int create_pool(test_global_t *global)
{
	odp_pool_capability_t pool_capa;
	odp_pool_param_t pool_param;
	odp_pool_t pool;
	uint32_t max_num, max_size, max_uarea;
	test_options_t *test_options = &global->test_options;
	uint32_t tot_event = test_options->tot_event;
	uint32_t event_size = 16;
	uint32_t uarea_size = test_options->uarea_size;

	if (test_options->touch_data) {
		event_size = test_options->rd_words + test_options->rw_words;
		event_size = 8 * event_size;
	}
	test_options->event_size = event_size;

	if (odp_pool_capability(&pool_capa)) {
		ODPH_ERR("Pool capa failed\n");
		return -1;
	}

	if (test_options->pool_type == ODP_POOL_BUFFER) {
		max_num = pool_capa.buf.max_num;
		max_size = pool_capa.buf.max_size;
		max_uarea = pool_capa.buf.max_uarea_size;
	} else {
		max_num = pool_capa.pkt.max_num;
		max_size = pool_capa.pkt.max_seg_len;
		max_uarea = pool_capa.pkt.max_uarea_size;
	}

	if (max_num && tot_event > max_num) {
		ODPH_ERR("Max events supported %u\n", max_num);
		return -1;
	}

	if (max_size && event_size > max_size) {
		ODPH_ERR("Max supported event size %u\n", max_size);
		return -1;
	}

	if (uarea_size > max_uarea) {
		ODPH_ERR("Max supported user area size %u\n", max_uarea);
		return -1;
	}

	odp_pool_param_init(&pool_param);
	if (test_options->pool_type == ODP_POOL_BUFFER) {
		pool_param.type = ODP_POOL_BUFFER;
		pool_param.buf.num = tot_event;
		pool_param.buf.size = event_size;
		pool_param.buf.align = 8;
		pool_param.buf.uarea_size = uarea_size;
	} else {
		pool_param.type = ODP_POOL_PACKET;
		pool_param.pkt.num = tot_event;
		pool_param.pkt.len = event_size;
		pool_param.pkt.seg_len = event_size;
		pool_param.pkt.align = 8;
		pool_param.pkt.uarea_size = uarea_size;
	}

	pool = odp_pool_create("sched perf", &pool_param);
	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Pool create failed\n");
		return -1;
	}

	global->pool = pool;

	return 0;
}

static int create_groups(test_global_t *global)
{
	odp_schedule_capability_t sched_capa;
	odp_thrmask_t thrmask;
	uint32_t i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_group = test_options->num_group;

	if (test_options->num_group <= 0)
		return 0;

	if (odp_schedule_capability(&sched_capa)) {
		ODPH_ERR("Schedule capability failed\n");
		return -1;
	}

	if (num_group > sched_capa.max_groups) {
		ODPH_ERR("Too many sched groups (max_groups capa %u)\n", sched_capa.max_groups);
		return -1;
	}

	odp_thrmask_zero(&thrmask);

	for (i = 0; i < num_group; i++) {
		odp_schedule_group_t group;

		group = odp_schedule_group_create("test_group", &thrmask);

		if (group == ODP_SCHED_GROUP_INVALID) {
			ODPH_ERR("Group create failed %u\n", i);
			return -1;
		}

		global->group[i] = group;
	}

	return 0;
}

static void setup_forwarding(test_global_t *global)
{
	const test_options_t *test_options = &global->test_options;
	const uint32_t forward_group_size = test_options->forward_group_size;
	const uint32_t num_groups = test_options->forward;
	uint32_t num_low = test_options->num_low;
	uint32_t num_high = test_options->num_high;
	uint32_t num_def = test_options->num_def;
	const uint32_t num_high_per_group = num_high / num_groups;
	const uint32_t num_low_per_group = num_low / num_groups;
	const uint32_t num_def_per_group = num_def / num_groups;
	odp_queue_t cur_queue, first_queue;

	for (uint32_t i = 0; i < num_groups; i++) {
		uint32_t num_group_low = num_low_per_group;
		uint32_t num_group_high = num_high_per_group;
		uint32_t num_group_def = num_def_per_group;

		if (num_group_low) {
			first_queue = global->queue.low_prio[--num_low];
			num_group_low--;
		} else if (num_group_high) {
			first_queue = global->queue.high_prio[--num_high];
			num_group_high--;
		} else {
			first_queue = global->queue.def_prio[--num_def];
			num_group_def--;
		}
		cur_queue = first_queue;

		for (uint32_t j = 0; j < forward_group_size; j++) {
			queue_context_t *qc = (queue_context_t *)odp_queue_context(cur_queue);
			odp_queue_t *next_queue = &qc->next;
			const uint32_t next_id = j + 1;

			if (next_id == forward_group_size) {
				/* Last queue points to the first one */
				*next_queue = first_queue;
				break;
			}

			/* Mix low, high and default priority queues */
			switch (next_id % 3) {
			case 0:
				if (num_group_low) {
					*next_queue = global->queue.low_prio[--num_low];
					num_group_low--;
				} else if (num_group_high) {
					*next_queue = global->queue.high_prio[--num_high];
					num_group_high--;
				} else {
					*next_queue = global->queue.def_prio[--num_def];
					num_group_def--;
				}
				break;
			case 1:
				if (num_group_high) {
					*next_queue = global->queue.high_prio[--num_high];
					num_group_high--;
				} else if (num_group_low) {
					*next_queue = global->queue.low_prio[--num_low];
					num_group_low--;
				} else {
					*next_queue = global->queue.def_prio[--num_def];
					num_group_def--;
				}
				break;
			default:
				if (num_group_def) {
					*next_queue = global->queue.def_prio[--num_def];
					num_group_def--;
				} else if (num_group_high) {
					*next_queue = global->queue.high_prio[--num_high];
					num_group_high--;
				} else {
					*next_queue = global->queue.low_prio[--num_low];
					num_group_low--;
				}
				break;
			}
			cur_queue = *next_queue;
		}
	}
}

static int set_queue_contexts(test_global_t *global, uint8_t *ctx)
{
	test_options_t *test_options = &global->test_options;
	uint32_t tot_queue = test_options->tot_queue;
	uint32_t ctx_size = test_options->ctx_size;
	uint32_t first = test_options->num_dummy;

	if (ctx_size == 0)
		return 0;

	for (uint32_t i = first; i < tot_queue; i++) {
		if (test_options->fairness) {
			/* Cast increases alignment, but it's ok, since ctx and ctx_size are both
			 * cache line aligned. */
			queue_context_t *qc = (queue_context_t *)(uintptr_t)ctx;

			odp_atomic_init_u64(&qc->count, 0);
		}

		if (odp_queue_context_set(global->queue.all[i], ctx, ctx_size)) {
			ODPH_ERR("Context set failed %u\n", i);
			return -1;
		}

		ctx += ctx_size;
	}

	if (test_options->forward)
		setup_forwarding(global);

	return 0;
}

static int create_queues(test_global_t *global, odp_queue_param_t *queue_param, int num_groups,
			 odp_queue_t queue[], uint32_t num)
{
	static uint32_t total_queues;

	for (uint32_t i = 0; i < num; i++) {
		if (num_groups > 0) /* Divide all queues evenly into groups */
			queue_param->sched.group = global->group[(total_queues + i) % num_groups];

		queue[i] = odp_queue_create(NULL, queue_param);

		if (queue[i] == ODP_QUEUE_INVALID) {
			ODPH_ERR("Queue create failed %u\n", i);
			return -1;
		}
	}

	/* Copy all queue handles to a single array for simpler initialization and clean-up */
	for (uint32_t i = 0; i < num; i++)
		global->queue.all[total_queues + i] = queue[i];
	total_queues += num;

	return 0;
}

static int create_all_queues(test_global_t *global)
{
	odp_queue_param_t queue_param;
	odp_queue_t queue;
	odp_schedule_sync_t sync;
	uint32_t i, j, first;
	test_options_t *test_options = &global->test_options;
	uint32_t event_size = test_options->event_size;
	uint32_t num_event = test_options->num_event;
	uint32_t queue_size = test_options->queue_size;
	uint32_t tot_queue = test_options->tot_queue;
	uint32_t num_low = test_options->num_low;
	uint32_t num_high = test_options->num_high;
	uint32_t num_default = test_options->num_def;
	int num_group = test_options->num_group;
	int type = test_options->queue_type;
	odp_pool_t pool = global->pool;
	uint8_t *ctx = NULL;
	uint32_t ctx_size = test_options->ctx_size;
	uint64_t init_val = 0;

	if (type == 0)
		sync = ODP_SCHED_SYNC_PARALLEL;
	else if (type == 1)
		sync = ODP_SCHED_SYNC_ATOMIC;
	else
		sync = ODP_SCHED_SYNC_ORDERED;

	if (tot_queue > global->schedule_config.num_queues) {
		ODPH_ERR("Max queues supported %u\n", global->schedule_config.num_queues);
		return -1;
	}

	if (global->schedule_config.queue_size &&
	    queue_size > global->schedule_config.queue_size) {
		ODPH_ERR("Max queue size %u\n", global->schedule_config.queue_size);
		return -1;
	}

	if (ctx_size) {
		ctx = odp_shm_addr(global->ctx_shm);
		if (ctx == NULL) {
			ODPH_ERR("Bad queue context\n");
			return -1;
		}
	}

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.sync  = sync;
	queue_param.sched.prio = odp_schedule_default_prio();
	queue_param.size = queue_size;
	if (num_group == -1)
		queue_param.sched.group = ODP_SCHED_GROUP_WORKER;
	else
		queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	first = test_options->num_dummy;

	/* Dummy queues */
	if (create_queues(global, &queue_param, num_group, global->queue.dummy,
			  test_options->num_dummy)) {
		ODPH_ERR("Dummy queue create failed\n");
		return -1;
	}

	/* Lowest priority queues */
	queue_param.sched.prio = odp_schedule_min_prio();
	if (create_queues(global, &queue_param, num_group, global->queue.low_prio, num_low)) {
		ODPH_ERR("Lowest priority queue create failed\n");
		return -1;
	}

	/* Highest priority queues */
	queue_param.sched.prio = odp_schedule_max_prio();
	if (create_queues(global, &queue_param, num_group, global->queue.high_prio, num_high)) {
		ODPH_ERR("Highest priority queue create failed\n");
		return -1;
	}

	/* Default priority queues */
	queue_param.sched.prio = odp_schedule_default_prio();
	if (create_queues(global, &queue_param, num_group, global->queue.def_prio, num_default)) {
		ODPH_ERR("Default priority queue create failed\n");
		return -1;
	}

	if (set_queue_contexts(global, ctx)) {
		ODPH_ERR("Set queue context failed\n");
		return -1;
	}

	/* Store events into queues. Dummy queues are allocated from
	 * the beginning of the array, so that usage of those affect allocation
	 * of active queues. Dummy queues are left empty. */
	for (i = first; i < tot_queue; i++) {
		queue = global->queue.all[i];

		for (j = 0; j < num_event; j++) {
			odp_event_t ev;
			uint64_t *data;
			uint32_t words;

			if (test_options->pool_type == ODP_POOL_BUFFER) {
				odp_buffer_t buf = odp_buffer_alloc(pool);

				if (buf == ODP_BUFFER_INVALID) {
					ODPH_ERR("Alloc failed %u/%u\n", i, j);
					return -1;
				}
				ev = odp_buffer_to_event(buf);

				data  = odp_buffer_addr(buf);
				words = odp_buffer_size(buf) / 8;
			} else {
				odp_packet_t pkt = odp_packet_alloc(pool, event_size);

				if (pkt == ODP_PACKET_INVALID) {
					ODPH_ERR("Alloc failed %u/%u\n", i, j);
					return -1;
				}
				ev = odp_packet_to_event(pkt);

				data  = odp_packet_data(pkt);
				words = odp_packet_seg_len(pkt) / 8;
			}

			init_val = init_data(init_val, data, words);

			if (odp_queue_enq(queue, ev)) {
				ODPH_ERR("Enqueue failed %u/%u\n", i, j);
				return -1;
			}
		}
	}

	return 0;
}

static int join_group(test_global_t *global, int grp_index, int thr)
{
	odp_thrmask_t thrmask;
	odp_schedule_group_t group;

	odp_thrmask_zero(&thrmask);
	odp_thrmask_set(&thrmask, thr);
	group = global->group[grp_index];

	if (odp_schedule_group_join(group, &thrmask)) {
		ODPH_ERR("Group %i join failed (thr %i)\n", grp_index, thr);
		return -1;
	}

	return 0;
}

static int join_all_groups(test_global_t *global, int thr)
{
	int i;
	test_options_t *test_options = &global->test_options;
	int num_group = test_options->num_group;

	if (num_group <= 0)
		return 0;

	for (i = 0; i < num_group; i++) {
		if (join_group(global, i, thr)) {
			ODPH_ERR("Group %u join failed (thr %i)\n", i, thr);
			return -1;
		}
	}

	return 0;
}

static void print_queue_fairness(test_global_t *global)
{
	uint32_t i;
	queue_context_t *ctx;
	test_options_t *test_options = &global->test_options;
	uint32_t first = test_options->num_dummy;
	uint32_t num_queue = test_options->num_queue;
	uint32_t tot_queue = test_options->tot_queue;
	uint64_t total = 0;
	double average;

	if (!test_options->fairness)
		return;

	for (i = first; i < tot_queue; i++) {
		ctx = odp_queue_context(global->queue.all[i]);
		total += odp_atomic_load_u64(&ctx->count);
	}

	average = (double)total / (double)num_queue;

	printf("\n");
	printf("RESULTS - events per queue (percent of average):\n");
	printf("------------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = first; i < tot_queue; i++) {
		ctx = odp_queue_context(global->queue.all[i]);

		if ((i % 10) == 0)
			printf("\n   ");

		printf("%6.1f ", (double)odp_atomic_load_u64(&ctx->count) /
					 average * 100.0);
	}

	printf("\n");
}

static int destroy_queues(test_global_t *global)
{
	uint32_t i;
	odp_event_t ev;
	uint64_t wait;
	test_options_t *test_options = &global->test_options;
	uint32_t tot_queue = test_options->tot_queue;
	int thr = odp_thread_id();

	if (join_all_groups(global, thr))
		return -1;

	wait = odp_schedule_wait_time(200 * ODP_TIME_MSEC_IN_NS);

	while ((ev = odp_schedule(NULL, wait)) != ODP_EVENT_INVALID)
		odp_event_free(ev);

	for (i = 0; i < tot_queue; i++) {
		if (global->queue.all[i] != ODP_QUEUE_INVALID) {
			if (odp_queue_destroy(global->queue.all[i])) {
				ODPH_ERR("Queue destroy failed %u\n", i);
				return -1;
			}
		}
	}

	return 0;
}

static int destroy_groups(test_global_t *global)
{
	int i;
	test_options_t *test_options = &global->test_options;
	int num_group = test_options->num_group;

	if (num_group <= 0)
		return 0;

	for (i = 0; i < num_group; i++) {
		odp_schedule_group_t group = global->group[i];

		if (odp_schedule_group_destroy(group)) {
			ODPH_ERR("Group destroy failed %u\n", i);
			return -1;
		}
	}

	return 0;
}

static uint64_t rw_uarea(odp_event_t ev[], int num, uint32_t rd_words, uint32_t rw_words)
{
	uint64_t *data;
	int i;
	uint32_t j;
	uint64_t sum = 0;

	for (i = 0; i < num; i++) {
		data = odp_event_user_area(ev[i]);

		for (j = 0; j < rd_words; j++)
			sum += data[j];

		for (; j < rd_words + rw_words; j++) {
			sum += data[j];
			data[j] += 1;
		}
	}

	return sum;
}

static inline uint64_t rw_ctx_data(void *ctx, uint32_t offset,
				   uint32_t rd_words, uint32_t rw_words)
{
	uint64_t *data;
	uint32_t i;
	uint64_t sum = 0;

	data = (uint64_t *)(uintptr_t)((uint8_t *)ctx + offset);

	for (i = 0; i < rd_words; i++)
		sum += data[i];

	for (; i < rd_words + rw_words; i++) {
		sum += data[i];
		data[i] += 1;
	}

	return sum;
}

static uint64_t rw_data(odp_event_t ev[], int num, uint32_t rd_words, uint32_t rw_words,
			odp_pool_type_t pool_type)
{
	uint64_t *data;
	uint32_t j;
	uint64_t sum = 0;

	for (int i = 0; i < num; i++) {
		if (pool_type == ODP_POOL_BUFFER)
			data = odp_buffer_addr(odp_buffer_from_event(ev[i]));
		else
			data = odp_packet_data(odp_packet_from_event(ev[i]));

		for (j = 0; j < rd_words; j++)
			sum += data[j];

		for (; j < rd_words + rw_words; j++) {
			sum += data[j];
			data[j] += 1;
		}
	}

	return sum;
}

static uint64_t rw_data_stress(odp_event_t ev[], int num, uint32_t rd_words, uint32_t rw_words,
			       uint32_t stress, odp_pool_type_t pool_type)
{
	uint64_t *data;
	uint64_t word;
	uint32_t j;
	uint64_t sum = 0;

	for (int i = 0; i < num; i++) {
		if (pool_type == ODP_POOL_BUFFER)
			data = odp_buffer_addr(odp_buffer_from_event(ev[i]));
		else
			data = odp_packet_data(odp_packet_from_event(ev[i]));

		for (j = 0; j < rd_words + rw_words; j++) {
			word = data[j];

			if (stress & 0x1)
				sum += odph_stress_pow2_u32(word);
			if (stress & 0x2)
				sum += odph_stress_log2_u32(word);
			if (stress & 0x4)
				sum += odph_stress_sqrt_u32(word);
			if (stress & 0x8)
				sum += odph_stress_sqrt_f32(word);

			if (j >= rd_words)
				data[j] = (word + 1) & DATA_MASK;
		}
	}

	return sum;
}

static int test_sched(void *arg)
{
	int num, num_enq, ret, thr;
	uint32_t i, rounds;
	uint64_t c1, c2, cycles, nsec;
	uint64_t events, enqueues, waits, events_prev;
	odp_time_t t1, t2, last_retry_ts;
	odp_queue_t queue;
	thread_arg_t *thread_arg = arg;
	test_global_t *global = thread_arg->global;
	test_options_t *test_options = &global->test_options;
	uint32_t num_sched = test_options->num_sched;
	uint32_t max_burst = test_options->max_burst;
	int num_group = test_options->num_group;
	int forward = test_options->forward;
	int fairness = test_options->fairness;
	const int touch_data = test_options->touch_data;
	const uint32_t stress = test_options->stress;
	const uint32_t rd_words = test_options->rd_words;
	const uint32_t rw_words = test_options->rw_words;
	uint32_t ctx_size = test_options->ctx_size;
	uint32_t ctx_rd_words = test_options->ctx_rd_words;
	uint32_t ctx_rw_words = test_options->ctx_rw_words;
	const uint32_t uarea_size = test_options->uarea_size;
	const uint32_t uarea_rd = test_options->uarea_rd;
	const uint32_t uarea_rw = test_options->uarea_rw;
	const odp_pool_type_t pool_type = test_options->pool_type;
	int touch_ctx = ctx_rd_words || ctx_rw_words;
	odp_atomic_u32_t *exit_threads = &global->exit_threads;
	uint32_t ctx_offset = 0;
	uint32_t sched_retries = 0;
	uint64_t data_sum = 0;
	uint64_t ctx_sum = 0;
	uint64_t uarea_sum = 0;
	uint64_t wait_ns = test_options->wait_ns;
	odp_event_t ev[max_burst];

	thr = odp_thread_id();

	if (forward || fairness)
		ctx_offset = ODPH_ROUNDUP_MULTIPLE(sizeof(queue_context_t), 8);

	if (num_group > 0) {
		uint32_t num_join = test_options->num_join;

		if (num_join) {
			int pos = 0;
			int n = 512;
			char str[n];
			int group_index = thread_arg->first_group;

			pos += snprintf(&str[pos], n - pos,
					"Thread %i joined groups:", thr);

			for (i = 0; i < num_join; i++) {
				if (join_group(global, group_index, thr))
					return -1;

				pos += snprintf(&str[pos], n - pos, " %i",
						group_index);

				group_index = (group_index + 1) % num_group;
			}

			printf("%s\n", str);

		} else {
			if (join_all_groups(global, thr))
				return -1;
		}
	}

	for (i = 0; i < max_burst; i++)
		ev[i] = ODP_EVENT_INVALID;

	enqueues = 0;
	events = 0;
	events_prev = 0;
	waits = 0;
	ret = 0;

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();
	c1 = odp_cpu_cycles();
	last_retry_ts = t1;

	for (rounds = 0; odp_likely(!odp_atomic_load_u32(exit_threads)); rounds++) {
		if (odp_unlikely(num_sched && events >= num_sched))
			break;

		num = odp_schedule_multi(&queue, ODP_SCHED_NO_WAIT,
					 ev, max_burst);

		if (odp_likely(num > 0)) {
			sched_retries = 0;
			events += num;
			i = 0;

			if (odp_unlikely(uarea_size))
				uarea_sum += rw_uarea(ev, num, uarea_rd, uarea_rw);

			if (odp_unlikely(ctx_size)) {
				queue_context_t *ctx = odp_queue_context(queue);

				if (forward)
					queue = ctx->next;

				if (fairness)
					odp_atomic_add_u64(&ctx->count, num);

				if (odp_unlikely(touch_ctx))
					ctx_sum += rw_ctx_data(ctx, ctx_offset,
							       ctx_rd_words,
							       ctx_rw_words);
			}

			if (odp_unlikely(touch_data)) {
				if (stress) {
					data_sum += rw_data_stress(ev, num, rd_words, rw_words,
								   stress, pool_type);
				} else {
					data_sum += rw_data(ev, num, rd_words, rw_words, pool_type);
				}
			}

			if (odp_unlikely(wait_ns)) {
				waits++;
				odp_time_wait_ns(wait_ns);
			}

			while (num) {
				num_enq = odp_queue_enq_multi(queue, &ev[i],
							      num);

				if (num_enq < 0) {
					ODPH_ERR("Enqueue failed. Round %u\n", rounds);
					odp_event_free_multi(&ev[i], num);
					ret = -1;
					break;
				}

				num -= num_enq;
				i   += num_enq;
				enqueues++;
			}

			if (odp_unlikely(ret))
				break;

			continue;
		} else if (num == 0) {
			sched_retries++;
			if (odp_unlikely(sched_retries > TIME_CHECK_INTERVAL)) {
				odp_time_t cur_time = odp_time_local();

				/* Measure time from the last received event and
				 * break if MAX_SCHED_WAIT_NS is exceeded */
				sched_retries = 0;
				if (events_prev != events) {
					events_prev = events;
					last_retry_ts = cur_time;
				} else if (odp_time_diff_ns(cur_time,
							    last_retry_ts) >
						MAX_SCHED_WAIT_NS) {
					ODPH_ERR("Scheduling timed out\n");
					ret = -1;
					break;
				}
			}
		}

		/* <0 not specified as an error but checking anyway */
		if (num < 0) {
			ODPH_ERR("Sched failed. Round %u\n", rounds);
			ret = -1;
			break;
		}
	}

	c2 = odp_cpu_cycles();
	t2 = odp_time_local();

	nsec   = odp_time_diff_ns(t2, t1);
	cycles = odp_cpu_cycles_diff(c2, c1);

	/* Update stats*/
	global->stat[thr].rounds   = rounds;
	global->stat[thr].enqueues = enqueues;
	global->stat[thr].events   = events;
	global->stat[thr].nsec     = nsec;
	global->stat[thr].cycles   = cycles;
	global->stat[thr].waits    = waits;
	global->stat[thr].dummy_sum = data_sum + ctx_sum + uarea_sum;
	global->stat[thr].failed = ret;

	if (odp_atomic_fetch_dec_u32(&global->num_worker) == 1) {
		/* The last worker frees all events. This is needed when the main
		 * thread cannot do the clean up (ODP_SCHED_GROUP_WORKER). */
		odp_event_t event;
		uint64_t sched_wait = odp_schedule_wait_time(200 * ODP_TIME_MSEC_IN_NS);

		/* Print queue and scheduler status at the end of the test, before any queues
		 * are emptied or destroyed. */
		if (test_options->verbose) {
			odp_queue_print_all();
			odp_schedule_print();
		}

		while ((event = odp_schedule(NULL, sched_wait)) != ODP_EVENT_INVALID)
			odp_event_free(event);
	}

	/* Pause scheduling before thread exit */
	odp_schedule_pause();

	while (1) {
		ev[0] = odp_schedule(&queue, ODP_SCHED_NO_WAIT);

		if (ev[0] == ODP_EVENT_INVALID)
			break;

		if (odp_unlikely(forward))
			queue = ((queue_context_t *)odp_queue_context(queue))->next;

		if (odp_queue_enq(queue, ev[0])) {
			ODPH_ERR("Queue enqueue failed\n");
			odp_event_free(ev[0]);
			ret = -1;
		}
	}

	return ret;
}

static int start_workers(test_global_t *global, odp_instance_t instance)
{
	odph_thread_common_param_t thr_common;
	int i, ret;
	test_options_t *test_options = &global->test_options;
	int num_group = test_options->num_group;
	uint32_t num_join  = test_options->num_join;
	int num_cpu   = test_options->num_cpu;
	odph_thread_param_t thr_param[num_cpu];

	odp_atomic_init_u32(&global->num_worker, num_cpu);

	memset(global->thread_tbl, 0, sizeof(global->thread_tbl));
	odph_thread_common_param_init(&thr_common);

	thr_common.instance = instance;
	thr_common.cpumask  = &global->cpumask;

	for (i = 0; i < num_cpu; i++) {
		odph_thread_param_init(&thr_param[i]);
		thr_param[i].start    = test_sched;
		thr_param[i].arg      = &global->thread_arg[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;

		global->thread_arg[i].global = global;
		global->thread_arg[i].first_group = 0;

		if (num_group > 0 && num_join) {
			/* Each thread joins only num_join groups, starting
			 * from this group index and wrapping around the group
			 * table. */
			int first_group = (i * num_join) % num_group;

			global->thread_arg[i].first_group = first_group;
		}
	}

	ret = odph_thread_create(global->thread_tbl, &thr_common, thr_param,
				 num_cpu);

	if (ret != num_cpu) {
		ODPH_ERR("Thread create failed %i\n", ret);
		return -1;
	}

	return 0;
}

static double measure_wait_time_cycles(uint64_t wait_ns)
{
	uint64_t i, c1, c2, diff;
	uint64_t rounds;
	double wait_cycles;

	if (wait_ns == 0)
		return 0.0;

	/* Run measurement for 100msec or at least two times, so that effect
	 * from CPU frequency scaling is minimized. */
	rounds = (100 * ODP_TIME_MSEC_IN_NS) / wait_ns;
	if (rounds == 0)
		rounds = 2;

	c1 = odp_cpu_cycles();

	for (i = 0; i < rounds; i++)
		odp_time_wait_ns(wait_ns);

	c2 = odp_cpu_cycles();
	diff = odp_cpu_cycles_diff(c2, c1);
	wait_cycles = (double)diff / rounds;

	printf("\nMeasured wait cycles: %.3f\n", wait_cycles);

	return wait_cycles;
}

static int output_results(test_global_t *global)
{
	int i, num;
	double rounds_ave, enqueues_ave, events_ave, events_per_sec, nsec_ave, cycles_ave;
	double waits_ave, wait_cycles, wait_cycles_ave;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	uint64_t wait_ns = test_options->wait_ns;
	uint64_t rounds_sum = 0;
	uint64_t enqueues_sum = 0;
	uint64_t events_sum = 0;
	uint64_t nsec_sum = 0;
	uint64_t cycles_sum = 0;
	uint64_t waits_sum = 0;
	uint32_t tot_rd = test_options->tot_rd_size;
	uint32_t tot_rw = test_options->tot_rw_size;

	wait_cycles = measure_wait_time_cycles(wait_ns);

	/* Averages */
	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->stat[i].failed) {
			num_cpu--;
			continue;
		}
		rounds_sum   += global->stat[i].rounds;
		enqueues_sum += global->stat[i].enqueues;
		events_sum   += global->stat[i].events;
		nsec_sum     += global->stat[i].nsec;
		cycles_sum   += global->stat[i].cycles;
		waits_sum    += global->stat[i].waits;
	}

	if (rounds_sum == 0 || num_cpu <= 0) {
		printf("No results.\n");
		return 0;
	}

	rounds_ave   = rounds_sum / num_cpu;
	enqueues_ave = enqueues_sum / num_cpu;
	events_ave   = events_sum / num_cpu;
	nsec_ave     = nsec_sum / num_cpu;
	cycles_ave   = cycles_sum / num_cpu;
	waits_ave    = waits_sum / num_cpu;
	wait_cycles_ave = waits_ave * wait_cycles;
	num = 0;

	printf("\n");
	printf("RESULTS - per thread (Million events per sec):\n");
	printf("----------------------------------------------\n");
	printf("        1      2      3      4      5      6      7      8      9     10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->stat[i].rounds) {
			if ((num % 10) == 0)
				printf("\n   ");

			if (global->stat[i].failed)
				printf("   n/a ");
			else
				printf("%6.1f ",
				       (1000.0 * global->stat[i].events) /
				       global->stat[i].nsec);

			num++;
		}
	}
	printf("\n\n");

	printf("RESULTS - average over %i threads:\n", num_cpu);
	printf("----------------------------------\n");
	printf("  schedule calls:           %.3f\n", rounds_ave);
	printf("  enqueue calls:            %.3f\n", enqueues_ave);
	printf("  duration:                 %.3f msec\n", nsec_ave / 1000000);
	printf("  num cycles:               %.3f M\n", cycles_ave / 1000000);
	printf("  cycles per round:         %.3f\n",
	       cycles_ave / rounds_ave);
	printf("  cycles per event:         %.3f\n",
	       cycles_ave / events_ave);
	if (wait_ns) {
		printf("    without wait_ns cycles: %.3f\n",
		       (cycles_ave - wait_cycles_ave) / events_ave);
	}
	printf("  ave events received:      %.3f\n",
	       events_ave / rounds_ave);
	printf("  rounds per sec:           %.3f M\n",
	       (1000.0 * rounds_ave) / nsec_ave);

	events_per_sec = (1000.0 * events_ave) / nsec_ave;
	printf("  events per sec:           %.3f M\n", events_per_sec);

	printf("  extra reads per sec:      %.3f MB\n", tot_rd * events_per_sec);
	printf("  extra writes per sec:     %.3f MB\n", tot_rw * events_per_sec);

	printf("TOTAL events per sec:       %.3f M\n\n",
	       (1000.0 * events_sum) / nsec_ave);

	if (global->common_options.is_export) {
		if (test_common_write("schedule calls,enqueue calls,duration (msec),"
				      "num cycles (M),cycles per round,cycles per event,"
				      "ave events received,rounds per sec (M),"
				      "events per sec (M),total events per sec (M)\n")) {
			ODPH_ERR("Export failed\n");
			test_common_write_term();
			return -1;
		}

		if (test_common_write("%f,%f,%f,%f,%f,%f,%f,%f,%f,%f\n",
				      rounds_ave, enqueues_ave, nsec_ave / 1000000,
				      cycles_ave / 1000000, cycles_ave / rounds_ave,
				      cycles_ave / events_ave, events_ave / rounds_ave,
				      (1000.0 * rounds_ave) / nsec_ave,
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
		ODPH_ERR("Reading ODP helper options failed\n");
		exit(EXIT_FAILURE);
	}

	argc = test_common_parse_options(argc, argv);
	if (test_common_options(&common_options)) {
		ODPH_ERR("Reading test options failed\n");
		exit(EXIT_FAILURE);
	}

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.timer    = 1;
	init.not_used.feat.tm       = 1;

	init.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Global init failed\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed\n");
		return -1;
	}

	shm = odp_shm_reserve("sched_perf_global", sizeof(test_global_t), ODP_CACHE_LINE_SIZE, 0);
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("SHM reserve failed\n");
		exit(EXIT_FAILURE);
	}

	global = odp_shm_addr(shm);
	if (global == NULL) {
		ODPH_ERR("SHM alloc failed\n");
		exit(EXIT_FAILURE);
	}
	test_globals = global;

	memset(global, 0, sizeof(test_global_t));
	global->pool = ODP_POOL_INVALID;
	global->ctx_shm = ODP_SHM_INVALID;
	odp_atomic_init_u32(&global->exit_threads, 0);

	global->common_options = common_options;

	if (setup_sig_handler()) {
		ODPH_ERR("Signal handler setup failed\n");
		exit(EXIT_FAILURE);
	}

	if (parse_options(argc, argv, &global->test_options))
		return -1;

	odp_sys_info_print();

	if (global->test_options.ctx_size) {
		uint64_t size = (uint64_t)global->test_options.ctx_size *
				global->test_options.tot_queue;

		global->ctx_shm = odp_shm_reserve("queue contexts", size,
						  ODP_CACHE_LINE_SIZE, 0);
		if (global->ctx_shm == ODP_SHM_INVALID) {
			ODPH_ERR("SHM reserve %" PRIu64 " bytes failed\n", size);
			return -1;
		}
	}

	odp_schedule_config_init(&global->schedule_config);
	odp_schedule_config(&global->schedule_config);

	if (set_num_cpu(global))
		return -1;

	if (create_pool(global))
		return -1;

	if (create_groups(global))
		return -1;

	if (create_all_queues(global))
		return -1;

	if (global->test_options.verbose)
		odp_shm_print_all();

	print_options(&global->test_options);

	/* Start workers */
	start_workers(global, instance);

	/* Wait workers to exit */
	odph_thread_join(global->thread_tbl, global->test_options.num_cpu);

	print_queue_fairness(global);

	if (destroy_queues(global))
		return -1;

	if (destroy_groups(global))
		return -1;

	if (output_results(global))
		return -1;

	if (odp_pool_destroy(global->pool)) {
		ODPH_ERR("Pool destroy failed\n");
		return -1;
	}

	if (global->ctx_shm != ODP_SHM_INVALID)
		odp_shm_free(global->ctx_shm);

	if (odp_shm_free(shm)) {
		ODPH_ERR("SHM free failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Term local failed\n");
		return -1;
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Term global failed\n");
		return -1;
	}

	return 0;
}

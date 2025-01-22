/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2018 Linaro Limited
 * Copyright (c) 2019-2025 Nokia
 */

/**
 * @example odp_timer_accuracy.c
 *
 * ODP timer accuracy test application
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

#include <unistd.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <export_results.h>

#define MAX_WORKERS (ODP_THREAD_COUNT_MAX - 1)
#define MAX_QUEUES 1024
#define MAX_FILENAME 128

enum mode_e {
	MODE_ONESHOT = 0,
	MODE_RESTART_ABS,
	MODE_RESTART_REL,
	MODE_PERIODIC,
	MODE_CONCURRENCY,
};

typedef struct test_opt_t {
	int cpu_count;
	unsigned long long period_ns;
	long long res_ns;
	unsigned long long res_hz;
	unsigned long long offset_ns;
	unsigned long long max_tmo_ns;
	unsigned long long num;
	unsigned long long num_warmup;
	unsigned long long burst;
	unsigned long long burst_gap;
	odp_fract_u64_t freq;
	unsigned long long max_multiplier;
	unsigned long long multiplier;
	enum mode_e mode;
	int clk_src;
	odp_queue_type_t queue_type;
	int num_queue;
	int groups;
	int init;
	int output;
	int early_retry;
	int interval;
	int max_diff;
	int cancel;
	int switch_timer;
	int switch_event;
	int cancel_start;
	int exit_on_error;
	uint64_t warmup_timers;
	uint64_t tot_timers;
	uint64_t alloc_timers;
	char filename[MAX_FILENAME];
} test_opt_t;

typedef struct ODP_ALIGNED_CACHE {
	odp_timer_t timer;
	odp_event_t event;
	uint64_t    nsec;
	int64_t     nsec_final;
	odp_ticketlock_t lock;
	uint64_t    events;
	uint64_t    starts;
	uint64_t    first_period;
	int64_t     first_tmo_diff;
	int         tmo_tick;

} timer_ctx_t;

typedef struct ODP_ALIGNED_CACHE {
	uint64_t nsec_before_sum;
	uint64_t nsec_before_min;
	uint64_t nsec_before_min_idx;
	uint64_t nsec_before_max;
	uint64_t nsec_before_max_idx;

	uint64_t nsec_after_sum;
	uint64_t nsec_after_min;
	uint64_t nsec_after_min_idx;
	uint64_t nsec_after_max;
	uint64_t nsec_after_max_idx;

	uint64_t num_before;
	uint64_t num_exact;
	uint64_t num_after;

	uint64_t num_too_near;

} test_stat_t;

typedef struct test_log_t {
	uint64_t tmo_ns;
	int64_t  diff_ns;
	int      tid;

} test_log_t;

typedef struct test_global_t {
	test_opt_t opt;

	test_stat_t stat[MAX_WORKERS];

	odp_queue_t      queue[MAX_QUEUES];
	odp_schedule_group_t group[MAX_WORKERS];
	odp_timer_pool_t timer_pool;
	odp_pool_t       timeout_pool;
	timer_ctx_t     *timer_ctx;
	double           res_ns;
	uint64_t         start_tick;
	uint64_t         start_ns;
	uint64_t         period_tick;
	double           period_dbl;
	odp_fract_u64_t  base_freq;
	test_log_t	*log;
	FILE            *file;
	odp_barrier_t    barrier;
	odp_atomic_u64_t events;
	odp_atomic_u64_t last_events;
	test_common_options_t common_options;
} test_global_t;

static void print_usage(void)
{
	printf("\n"
	       "Timer accuracy test application.\n"
	       "\n"
	       "OPTIONS:\n"
	       "  -c, --count <num>       CPU count, 0=all available, default=1\n"
	       "  -p, --period <nsec>     Timeout period in nsec. Not used in periodic mode. Default: 200 msec\n"
	       "  -r, --res_ns <nsec>     Timeout resolution in nsec. Default value is 0. Special values:\n"
	       "                          0:  Use period / 10 as the resolution\n"
	       "                          -1: In periodic mode, use resolution from capabilities\n"
	       "  -R, --res_hz <hertz>    Timeout resolution in hertz. Set resolution either with -r (nsec) or -R (hertz),\n"
	       "                          and leave other to 0. Default: 0 (not used)\n"
	       "  -f, --first <nsec>      First timer offset in nsec. Not used in concurrency mode. Default: 0 for\n"
	       "                          periodic mode, otherwise 300 msec\n"
	       "  -x, --max_tmo <nsec>    Maximum timeout in nsec. Not used in periodic mode.\n"
	       "                          When 0, max tmo is calculated from other options. Default: 0\n"
	       "  -n, --num <number>      Number of timeout periods. Default: 50\n"
	       "  -w, --warmup <number>   Number of warmup periods. Default: 0\n"
	       "  -b, --burst <number>    Number of timers per a timeout period. Default: 1\n"
	       "  -g, --burst_gap <nsec>  Gap (in nsec) between timers within a burst. Default: 0\n"
	       "                          In periodic mode, first + burst * burst_gap must be less than period length.\n"
	       "  -m, --mode <number>     Test mode select (default: 0):\n"
	       "                            0: One-shot. Start all timers at init phase.\n"
	       "                            1: One-shot. Each period, restart timers with absolute time.\n"
	       "                            2: One-shot. Each period, restart timers with relative time.\n"
	       "                            3: Periodic.\n"
	       "                            4: Concurrency.\n"
	       "  -o, --output <file>     Output file for measurement logs\n"
	       "  -s, --clk_src           Clock source select (default 0):\n"
	       "                            0: ODP_CLOCK_DEFAULT\n"
	       "                            1: ODP_CLOCK_SRC_1, ...\n"
	       "  -t, --queue_type        Queue sync type. Default is 0 (PARALLEL).\n"
	       "                            0: PARALLEL\n"
	       "                            1: ATOMIC\n"
	       "                            2: ORDERED\n"
	       "  -q, --num_queue         Number of queues. Default is 1.\n"
	       "  -G, --sched_groups      Use dedicated schedule group for each worker.\n"
	       "  -i, --init              Set global init parameters. Default: init params not set.\n"
	       "  -h, --help              Display help and exit.\n"
	       "\n"
	       "ONE-SHOT MODE OPTIONS:\n"
	       "  -e, --early_retry <num> When timer restart fails due to ODP_TIMER_TOO_NEAR, retry this many times\n"
	       "                          with expiration time incremented by the period. Default: 0\n"
	       "\n"
	       "PERIODIC MODE OPTIONS:\n"
	       "  -P, --periodic <freq_integer:freq_numer:freq_denom:max_multiplier>\n"
	       "                          Periodic timer pool parameters. Default: 5:0:0:1 (5 Hz)\n"
	       "  -M, --multiplier        Periodic timer multiplier. Default: 1\n"
	       "\n"
	       "CONCURRENCY MODE OPTIONS:\n"
	       "  -I, --interval <sec>    Print interval information every <sec> seconds. Default: 1\n"
	       "  -D, --max_diff <nsec>   Print error if event is more than <nsec> nanoseconds late. Default: 0 (disabled)\n"
	       "  -C, --cancel <n>        Every <n> events, cancel the timer. Default: 0 (disabled)\n"
	       "  -E, --switch_event <n>  Every <n> events, free the received event and allocate a new one.\n"
	       "                          Default: 0 (disabled)\n"
	       "  -T, --switch_timer <n>  Every <n> events, free the timer and allocate a new one. Default: 0 (disabled)\n"
	       "  -S, --cancel_start <n>  Every <n> events, after starting a timer, immediately cancel and start again.\n"
	       "                          Default: 0 (disabled)\n"
	       "  -X, --exit_on_error     Exit on duplicate events and late timeouts.\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_opt_t *test_opt)
{
	int opt;
	const struct option longopts[] = {
		{"count",        required_argument, NULL, 'c'},
		{"period",       required_argument, NULL, 'p'},
		{"res_ns",       required_argument, NULL, 'r'},
		{"res_hz",       required_argument, NULL, 'R'},
		{"first",        required_argument, NULL, 'f'},
		{"max_tmo",      required_argument, NULL, 'x'},
		{"num",          required_argument, NULL, 'n'},
		{"warmup",       required_argument, NULL, 'w'},
		{"burst",        required_argument, NULL, 'b'},
		{"burst_gap",    required_argument, NULL, 'g'},
		{"mode",         required_argument, NULL, 'm'},
		{"periodic",     required_argument, NULL, 'P'},
		{"multiplier",   required_argument, NULL, 'M'},
		{"output",       required_argument, NULL, 'o'},
		{"early_retry",  required_argument, NULL, 'e'},
		{"clk_src",      required_argument, NULL, 's'},
		{"queue_type",   required_argument, NULL, 't'},
		{"num_queue",    required_argument, NULL, 'q'},
		{"interval",     required_argument, NULL, 'I'},
		{"max_diff",     required_argument, NULL, 'D'},
		{"cancel",       required_argument, NULL, 'C'},
		{"switch_event", required_argument, NULL, 'E'},
		{"switch_timer", required_argument, NULL, 'T'},
		{"cancel_start", required_argument, NULL, 'S'},
		{"exit_on_error", no_argument,      NULL, 'X'},
		{"sched_groups", no_argument,       NULL, 'G'},
		{"init",         no_argument,       NULL, 'i'},
		{"help",         no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	const char *shortopts =  "+c:p:r:R:f:x:n:w:b:g:m:P:M:o:e:s:t:q:I:D:C:E:T:S:XGih";
	int ret = 0;

	memset(test_opt, 0, sizeof(*test_opt));

	test_opt->cpu_count      = 1;
	test_opt->period_ns      = 200 * ODP_TIME_MSEC_IN_NS;
	test_opt->offset_ns      = UINT64_MAX;
	test_opt->num            = 50;
	test_opt->burst          = 1;
	test_opt->mode           = MODE_ONESHOT;
	test_opt->freq.integer   = ODP_TIME_SEC_IN_NS / test_opt->period_ns;
	test_opt->max_multiplier = 1;
	test_opt->multiplier     = 1;
	test_opt->clk_src        = ODP_CLOCK_DEFAULT;
	test_opt->queue_type     = ODP_SCHED_SYNC_PARALLEL;
	test_opt->num_queue      = 1;
	test_opt->interval       = 1;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			test_opt->cpu_count = atoi(optarg);
			break;
		case 'p':
			test_opt->period_ns = strtoull(optarg, NULL, 0);
			break;
		case 'r':
			test_opt->res_ns = strtoll(optarg, NULL, 0);
			break;
		case 'R':
			test_opt->res_hz = strtoull(optarg, NULL, 0);
			break;
		case 'f':
			test_opt->offset_ns = strtoull(optarg, NULL, 0);
			break;
		case 'x':
			test_opt->max_tmo_ns = strtoull(optarg, NULL, 0);
			break;
		case 'n':
			test_opt->num = strtoull(optarg, NULL, 0);
			break;
		case 'w':
			test_opt->num_warmup = strtoull(optarg, NULL, 0);
			break;
		case 'b':
			test_opt->burst = strtoull(optarg, NULL, 0);
			break;
		case 'g':
			test_opt->burst_gap = strtoull(optarg, NULL, 0);
			break;
		case 'm':
			test_opt->mode = atoi(optarg);
			break;
		case 'P':
			sscanf(optarg, "%" SCNu64 ":%" SCNu64 ":%" SCNu64 ":%llu",
			       &test_opt->freq.integer, &test_opt->freq.numer,
			       &test_opt->freq.denom, &test_opt->max_multiplier);
			break;
		case 'M':
			test_opt->multiplier = strtoull(optarg, NULL, 0);
			break;
		case 'o':
			test_opt->output = 1;
			if (strlen(optarg) >= MAX_FILENAME) {
				ODPH_ERR("Filename too long\n");
				return -1;
			}
			odph_strcpy(test_opt->filename, optarg, MAX_FILENAME);
			break;
		case 'e':
			test_opt->early_retry = atoi(optarg);
			break;
		case 's':
			test_opt->clk_src = atoi(optarg);
			break;
		case 't':
			switch (atoi(optarg)) {
			case 1:
				test_opt->queue_type = ODP_SCHED_SYNC_ATOMIC;
				break;
			case 2:
				test_opt->queue_type = ODP_SCHED_SYNC_ORDERED;
				break;
			default:
				test_opt->queue_type = ODP_SCHED_SYNC_PARALLEL;
				break;
			}
			break;
		case 'q':
			test_opt->num_queue = atoi(optarg);
			break;
		case 'I':
			test_opt->interval = atoi(optarg);
			break;
		case 'D':
			test_opt->max_diff = atoi(optarg);
			break;
		case 'C':
			test_opt->cancel = atoi(optarg);
			break;
		case 'E':
			test_opt->switch_event = atoi(optarg);
			break;
		case 'T':
			test_opt->switch_timer = atoi(optarg);
			break;
		case 'S':
			test_opt->cancel_start = atoi(optarg);
			break;
		case 'X':
			test_opt->exit_on_error = 1;
			break;
		case 'G':
			test_opt->groups = 1;
			break;
		case 'i':
			test_opt->init = 1;
			break;
		case 'h':
			print_usage();
			ret = -1;
			break;
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_opt->mode == MODE_PERIODIC) {
		if ((test_opt->freq.integer == 0 && test_opt->freq.numer == 0) ||
		    (test_opt->freq.numer != 0 && test_opt->freq.denom == 0)) {
			ODPH_ERR("Bad frequency\n");
			return -1;
		}

		test_opt->period_ns =
			ODP_TIME_SEC_IN_NS / odp_fract_u64_to_dbl(&test_opt->freq);

		if (test_opt->offset_ns == UINT64_MAX)
			test_opt->offset_ns = 0;
	} else {
		if (test_opt->res_ns < 0) {
			ODPH_ERR("Resolution (res_ns) must be >= 0 with single shot timer\n");
			return -1;
		}

		if (test_opt->offset_ns == UINT64_MAX)
			test_opt->offset_ns = 300 * ODP_TIME_MSEC_IN_NS;

		if (test_opt->mode == MODE_CONCURRENCY)
			test_opt->offset_ns = 0;
	}

	test_opt->warmup_timers = test_opt->num_warmup * test_opt->burst;
	test_opt->tot_timers =
		test_opt->warmup_timers + test_opt->num * test_opt->burst;

	if (test_opt->mode == MODE_ONESHOT)
		test_opt->alloc_timers = test_opt->tot_timers;
	else
		test_opt->alloc_timers = test_opt->burst;

	return ret;
}

static int single_shot_params(test_global_t *test_global, odp_timer_pool_param_t *timer_param,
			      odp_timer_capability_t *timer_capa)
{
	uint64_t res_ns, res_hz;
	uint64_t max_res_ns, max_res_hz;
	uint64_t period_ns = test_global->opt.period_ns;
	uint64_t num_tmo = test_global->opt.num + test_global->opt.num_warmup;
	uint64_t offset_ns = test_global->opt.offset_ns;
	enum mode_e mode = test_global->opt.mode;

	max_res_ns = timer_capa->max_res.res_ns;
	max_res_hz = timer_capa->max_res.res_hz;

	/* Default resolution */
	if (test_global->opt.res_ns == 0 && test_global->opt.res_hz == 0) {
		res_ns = test_global->opt.period_ns / 10;
		res_hz = 0;
	} else if (test_global->opt.res_ns) {
		res_ns = test_global->opt.res_ns;
		res_hz = 0;
	} else {
		res_ns = 0;
		res_hz = test_global->opt.res_hz;
	}

	if (res_ns && res_ns < max_res_ns) {
		ODPH_ERR("Resolution %" PRIu64 " nsec too high.\n"
			 "Highest resolution %" PRIu64
			 " nsec. Default resolution is period / 10.\n\n",
			 res_ns, max_res_ns);
		return -1;
	}

	if (res_hz && res_hz > max_res_hz) {
		ODPH_ERR("Resolution %" PRIu64 " hz too high.\n"
			 "Highest resolution %" PRIu64
			 " hz. Default resolution is period / 10.\n\n",
			 res_hz, max_res_hz);
		return -1;
	}

	if (res_ns)
		timer_param->res_ns = res_ns;
	else
		timer_param->res_hz = res_hz;

	if (mode == MODE_ONESHOT) {
		timer_param->min_tmo = offset_ns / 2;
		timer_param->max_tmo = offset_ns + ((num_tmo + 1) * period_ns);
	} else {
		if (mode == MODE_RESTART_ABS)
			timer_param->min_tmo = period_ns / 10;
		else
			timer_param->min_tmo = period_ns;
		timer_param->max_tmo = offset_ns + (2 * period_ns);
	}

	if (test_global->opt.max_tmo_ns) {
		if (test_global->opt.max_tmo_ns < timer_param->max_tmo) {
			ODPH_ERR("Max tmo is too small. Must be at least %" PRIu64 " nsec.\n",
				 timer_param->max_tmo);
			return -1;
		}

		timer_param->max_tmo = test_global->opt.max_tmo_ns;
	}

	printf("  period:          %" PRIu64 " nsec\n", period_ns);
	printf("  max res nsec:    %" PRIu64 "\n", max_res_ns);
	printf("  max res hertz:   %" PRIu64 "\n", max_res_hz);

	test_global->period_dbl = period_ns;

	return 0;
}

static int periodic_params(test_global_t *test_global, odp_timer_pool_param_t *timer_param,
			   odp_timer_capability_t *timer_capa)
{
	int ret;
	uint64_t res_ns;
	odp_timer_periodic_capability_t capa;
	double freq_dbl, min_freq, max_freq;
	double opt_freq = odp_fract_u64_to_dbl(&test_global->opt.freq);
	odp_fract_u64_t freq = test_global->opt.freq;
	uint64_t res_hz = test_global->opt.res_hz;
	uint64_t max_multiplier = test_global->opt.max_multiplier;
	uint64_t multiplier = test_global->opt.multiplier;

	if (res_hz) {
		res_ns = ODP_TIME_SEC_IN_NS / res_hz;
	} else {
		res_ns = test_global->opt.res_ns;

		/* Default resolution */
		if (res_ns == 0)
			res_ns = ODP_TIME_SEC_IN_NS / (10 * multiplier * opt_freq);
	}

	if (res_ns == 0) {
		ODPH_ERR("Resolution too high\n");
		return -1;
	}

	/* Resolution from capa */
	if (test_global->opt.res_ns < 0)
		res_ns = 0;

	min_freq = odp_fract_u64_to_dbl(&timer_capa->periodic.min_base_freq_hz);
	max_freq = odp_fract_u64_to_dbl(&timer_capa->periodic.max_base_freq_hz);

	capa.base_freq_hz = freq;
	capa.max_multiplier = max_multiplier;
	capa.res_ns = res_ns;

	ret = odp_timer_periodic_capability(test_global->opt.clk_src, &capa);

	if (ret < 0) {
		ODPH_ERR("Requested periodic timer capabilities are not supported.\n"
			 "Capabilities: min base freq %g Hz, max base freq %g Hz, "
			 "max res %" PRIu64 " Hz\n",
			 min_freq, max_freq, timer_capa->max_res.res_hz);
		return -1;
	}

	if (ret == 0) {
		printf("Requested base frequency is not met. Using %.2f Hz instead of %.2f Hz.\n",
		       odp_fract_u64_to_dbl(&capa.base_freq_hz), opt_freq);

		freq = capa.base_freq_hz;
	}

	if (res_ns == 0)
		res_ns = capa.res_ns;

	freq_dbl = odp_fract_u64_to_dbl(&freq);
	test_global->base_freq  = freq;
	test_global->period_dbl = ODP_TIME_SEC_IN_NS / (multiplier * freq_dbl);

	/* Min/max tmo are ignored, leave those to default values */
	timer_param->timer_type = ODP_TIMER_TYPE_PERIODIC;
	timer_param->periodic.base_freq_hz = freq;
	timer_param->periodic.max_multiplier = max_multiplier;

	if (res_hz)
		timer_param->res_hz = res_hz;
	else
		timer_param->res_ns = res_ns;

	printf("  min freq capa:   %.2f hz\n", min_freq);
	printf("  max freq capa:   %.2f hz\n", max_freq);
	printf("  freq option:     %.2f hz\n", opt_freq);
	printf("  freq:            %.2f hz\n", freq_dbl);
	printf("  freq integer:    %" PRIu64 "\n", freq.integer);
	printf("  freq numer:      %" PRIu64 "\n", freq.numer);
	printf("  freq denom:      %" PRIu64 "\n", freq.denom);
	printf("  max_multiplier:  %" PRIu64 "\n", max_multiplier);
	printf("  multiplier:      %" PRIu64 "\n", multiplier);
	printf("  timer freq:      %.2f hz\n", multiplier * freq_dbl);
	printf("  timer period:    %.2f nsec\n", test_global->period_dbl);
	printf("  resolution capa: %" PRIu64 " nsec\n", capa.res_ns);

	return 0;
}

static int create_timers(test_global_t *test_global)
{
	odp_pool_t pool;
	odp_pool_param_t pool_param;
	odp_timer_pool_t timer_pool;
	odp_timer_pool_param_t timer_param;
	odp_timer_capability_t timer_capa;
	odp_timer_t timer;
	odp_queue_t *queue;
	odp_schedule_group_t *group;
	odp_queue_param_t queue_param;
	uint64_t offset_ns;
	uint32_t max_timers;
	odp_event_t event;
	odp_timeout_t timeout;
	uint64_t i, num_tmo, num_warmup, burst, burst_gap;
	uint64_t tot_timers, alloc_timers;
	enum mode_e mode;
	odp_timer_clk_src_t clk_src;
	int ret;

	mode = test_global->opt.mode;
	alloc_timers = test_global->opt.alloc_timers;
	tot_timers = test_global->opt.tot_timers;
	num_warmup = test_global->opt.num_warmup;
	num_tmo = num_warmup + test_global->opt.num;
	burst = test_global->opt.burst;
	burst_gap = test_global->opt.burst_gap;
	offset_ns = test_global->opt.offset_ns;
	queue = test_global->queue;
	group = test_global->group;

	/* Always init globals for destroy calls */
	test_global->timer_pool = ODP_TIMER_POOL_INVALID;
	test_global->timeout_pool = ODP_POOL_INVALID;

	for (i = 0; i < alloc_timers; i++) {
		test_global->timer_ctx[i].timer = ODP_TIMER_INVALID;
		test_global->timer_ctx[i].event = ODP_EVENT_INVALID;
	}

	if (test_global->opt.groups) {
		/* Create groups */

		odp_thrmask_t zero;

		odp_thrmask_zero(&zero);

		for (i = 0; i < (uint64_t)test_global->opt.cpu_count; i++) {
			group[i] = odp_schedule_group_create(NULL, &zero);

			if (group[i] == ODP_SCHED_GROUP_INVALID) {
				ODPH_ERR("Group create failed.\n");
				return -1;
			}
		}
	}

	odp_queue_param_init(&queue_param);
	queue_param.type        = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.prio  = odp_schedule_default_prio();
	queue_param.sched.sync  = test_global->opt.queue_type;
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;

	for (i = 0; i < (uint64_t)test_global->opt.num_queue; i++) {
		if (test_global->opt.groups)
			queue_param.sched.group = group[i % test_global->opt.cpu_count];

		queue[i] = odp_queue_create(NULL, &queue_param);
		if (queue[i] == ODP_QUEUE_INVALID) {
			ODPH_ERR("Queue create failed.\n");
			return -1;
		}
	}

	odp_pool_param_init(&pool_param);
	pool_param.type    = ODP_POOL_TIMEOUT;
	pool_param.tmo.num = alloc_timers + pool_param.tmo.cache_size * test_global->opt.cpu_count;
	if (mode == MODE_CONCURRENCY)
		pool_param.tmo.num += test_global->opt.cpu_count;

	pool = odp_pool_create("timeout pool", &pool_param);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Timeout pool create failed.\n");
		return -1;
	}

	test_global->timeout_pool = pool;
	clk_src = test_global->opt.clk_src;

	if (odp_timer_capability(clk_src, &timer_capa)) {
		ODPH_ERR("Timer capa failed\n");
		return -1;
	}

	max_timers = timer_capa.max_timers;

	if (mode == MODE_PERIODIC) {
		if (timer_capa.periodic.max_pools < 1) {
			ODPH_ERR("Periodic timers not supported.\n");
			return -1;
		}
		max_timers = timer_capa.periodic.max_timers;
	}

	printf("\nTest parameters:\n");
	printf("  clock source:    %i\n", clk_src);
	printf("  max timers capa: %" PRIu32 "\n", max_timers);
	printf("  mode:            %i\n", mode);
	printf("  queue type:      %i\n", test_global->opt.queue_type);
	printf("  num queue:       %i\n", test_global->opt.num_queue);
	printf("  sched groups:    %s\n", test_global->opt.groups ? "yes" : "no");

	odp_timer_pool_param_init(&timer_param);

	if (mode == MODE_PERIODIC)
		ret = periodic_params(test_global, &timer_param, &timer_capa);
	else
		ret = single_shot_params(test_global, &timer_param, &timer_capa);

	if (ret)
		return ret;

	if (timer_param.res_hz) {
		test_global->res_ns = 1000000000.0 / timer_param.res_hz;
		printf("  resolution:      %" PRIu64 " Hz\n", timer_param.res_hz);
	} else {
		test_global->res_ns = timer_param.res_ns;
		printf("  resolution:      %" PRIu64 " nsec\n", timer_param.res_ns);
	}

	timer_param.num_timers = alloc_timers;
	if (mode == MODE_CONCURRENCY)
		timer_param.num_timers += test_global->opt.cpu_count;

	if (max_timers && timer_param.num_timers > max_timers) {
		ODPH_ERR("Too many timers: %" PRIu64 " (max %u)\n", test_global->opt.alloc_timers,
			 max_timers);
		return -1;
	}

	timer_param.clk_src    = clk_src;

	printf("  restart retries: %i\n", test_global->opt.early_retry);
	if (test_global->opt.output)
		printf("  log file:        %s\n", test_global->opt.filename);
	printf("  start offset:    %" PRIu64 " nsec\n", offset_ns);
	printf("  min timeout:     %" PRIu64 " nsec\n", timer_param.min_tmo);
	printf("  max timeout:     %" PRIu64 " nsec\n", timer_param.max_tmo);
	printf("  num timeout:     %" PRIu64 "\n", num_tmo);
	printf("  num warmup:      %" PRIu64 "\n", num_warmup);
	printf("  burst size:      %" PRIu64 "\n", burst);
	printf("  burst gap:       %" PRIu64 "\n", burst_gap);
	printf("  total timers:    %" PRIu64 "\n", tot_timers);
	printf("  warmup timers:   %" PRIu64 "\n", test_global->opt.warmup_timers);
	printf("  alloc timers:    %" PRIu64 "\n", alloc_timers);
	printf("  warmup time:     %.2f sec\n",
	       (offset_ns + (num_warmup * test_global->period_dbl)) / 1000000000.0);
	printf("  test run time:   %.2f sec\n\n",
	       (offset_ns + (num_tmo * test_global->period_dbl)) / 1000000000.0);

	timer_pool = odp_timer_pool_create("timer_accuracy", &timer_param);

	if (timer_pool == ODP_TIMER_POOL_INVALID) {
		ODPH_ERR("Timer pool create failed\n");
		return -1;
	}

	if (odp_timer_pool_start_multi(&timer_pool, 1) != 1) {
		ODPH_ERR("Timer pool start failed\n");
		return -1;
	}

	odp_timer_pool_print(timer_pool);

	/* Spend some time so that current tick would not be zero */
	odp_time_wait_ns(100 * ODP_TIME_MSEC_IN_NS);

	test_global->timer_pool = timer_pool;

	for (i = 0; i < alloc_timers; i++) {
		timer_ctx_t *ctx = &test_global->timer_ctx[i];

		timer = odp_timer_alloc(timer_pool, queue[i % test_global->opt.num_queue], ctx);

		if (timer == ODP_TIMER_INVALID) {
			ODPH_ERR("Timer alloc failed.\n");
			return -1;
		}

		ctx->timer = timer;

		timeout = odp_timeout_alloc(pool);
		if (timeout == ODP_TIMEOUT_INVALID) {
			ODPH_ERR("Timeout alloc failed\n");
			return -1;
		}

		ctx->event = odp_timeout_to_event(timeout);

		odp_ticketlock_init(&ctx->lock);
	}

	/* Run scheduler few times to ensure that (software) timer is active */
	for (i = 0; i < 1000; i++) {
		event = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (event != ODP_EVENT_INVALID) {
			ODPH_ERR("Spurious event received\n");
			odp_event_free(event);
			return -1;
		}
	}

	return 0;
}

static int start_timers(test_global_t *test_global)
{
	odp_timer_pool_t timer_pool;
	uint64_t start_tick;
	uint64_t period_ns, start_ns, nsec, offset_ns;
	odp_time_t time;
	uint64_t i, j, idx, num_tmo, num_warmup, burst, burst_gap;
	enum mode_e mode;

	mode = test_global->opt.mode;
	num_warmup = test_global->opt.num_warmup;
	num_tmo = num_warmup + test_global->opt.num;
	burst = test_global->opt.burst;
	burst_gap = test_global->opt.burst_gap;
	period_ns = test_global->opt.period_ns;
	offset_ns = test_global->opt.offset_ns;
	timer_pool = test_global->timer_pool;
	idx = 0;

	/* Record test start time and tick. Memory barriers forbid compiler and out-of-order
	 * CPU to move samples apart. */
	odp_mb_full();
	start_tick = odp_timer_current_tick(timer_pool);
	time       = odp_time_global();
	odp_mb_full();

	start_ns = odp_time_to_ns(time);
	test_global->start_tick = start_tick;
	test_global->start_ns = start_ns;
	test_global->period_tick = odp_timer_ns_to_tick(timer_pool, period_ns);

	/* When mode is not one-shot, set only one burst of timers initially */
	if (mode != MODE_ONESHOT)
		num_tmo = 1;

	for (i = 0; i < num_tmo; i++) {
		odp_timer_retval_t retval;

		for (j = 0; j < burst; j++) {
			timer_ctx_t *ctx = &test_global->timer_ctx[idx];
			odp_timer_start_t start_param;

			if (mode == MODE_PERIODIC) {
				odp_timer_periodic_start_t periodic_start;

				nsec = offset_ns + (j * burst_gap);

				/* By default, timer starts one period after current time. Round
				 * floating point to closest integer number. */
				ctx->nsec = start_ns + test_global->period_dbl + 0.5;
				if (nsec)
					ctx->nsec = start_ns + nsec;

				ctx->first_period = start_tick +
					odp_timer_ns_to_tick(timer_pool,
							     test_global->period_dbl + 0.5);
				periodic_start.freq_multiplier = test_global->opt.multiplier;
				periodic_start.first_tick = 0;
				if (nsec)
					periodic_start.first_tick =
						start_tick + odp_timer_ns_to_tick(timer_pool, nsec);
				periodic_start.tmo_ev = ctx->event;
				retval = odp_timer_periodic_start(ctx->timer, &periodic_start);
			} else if (mode == MODE_CONCURRENCY) {
				ctx->nsec = start_ns + test_global->opt.period_ns;
				start_param.tick_type = ODP_TIMER_TICK_REL;
				start_param.tick = test_global->period_tick;
				start_param.tmo_ev = ctx->event;
				ctx->starts++;
				retval = odp_timer_start(ctx->timer, &start_param);
			} else {
				nsec = offset_ns + (i * period_ns) + (j * burst_gap);
				ctx->nsec = start_ns + nsec;
				start_param.tick_type = ODP_TIMER_TICK_ABS;
				start_param.tick =
					start_tick + odp_timer_ns_to_tick(timer_pool, nsec);
				start_param.tmo_ev = ctx->event;
				retval = odp_timer_start(ctx->timer, &start_param);
			}

			if (retval != ODP_TIMER_SUCCESS) {
				ODPH_ERR("Timer[%" PRIu64 "] set failed: %i\n", idx, retval);
				return -1;
			}

			idx++;
		}
	}

	printf("\nStarting timers took %" PRIu64 " nsec\n", odp_time_global_ns() - start_ns);

	return 0;
}

static int destroy_timers(test_global_t *test_global)
{
	uint64_t i, alloc_timers;
	odp_timer_t timer;
	int ret = 0;

	alloc_timers = test_global->opt.alloc_timers;

	for (i = 0; i < alloc_timers; i++) {
		timer = test_global->timer_ctx[i].timer;

		if (timer == ODP_TIMER_INVALID)
			break;

		if (odp_timer_free(timer)) {
			ODPH_ERR("Timer free failed: %" PRIu64 "\n", i);
			ret = -1;
		}
	}

	if (test_global->timer_pool != ODP_TIMER_POOL_INVALID)
		odp_timer_pool_destroy(test_global->timer_pool);

	if (test_global->timeout_pool != ODP_POOL_INVALID) {
		if (odp_pool_destroy(test_global->timeout_pool)) {
			ODPH_ERR("Pool destroy failed.\n");
			ret = -1;
		}
	}

	for (i = 0; i < (uint64_t)test_global->opt.num_queue; i++) {
		if (odp_queue_destroy(test_global->queue[i])) {
			ODPH_ERR("Queue destroy failed.\n");
			ret = -1;
		}
	}

	if (test_global->opt.groups) {
		for (i = 0; i < (uint64_t)test_global->opt.cpu_count; i++) {
			if (odp_schedule_group_destroy(test_global->group[i])) {
				ODPH_ERR("Group destroy failed.\n");
				ret = -1;
			}
		}
	}

	return ret;
}

static void print_nsec_error(const char *str, int64_t nsec, double res_ns,
			     int tid, int idx)
{
	printf("         %s: %12" PRIi64 "  /  %.3fx resolution",
	       str, nsec, (double)nsec / res_ns);
	if (tid >= 0)
		printf(", thread %d", tid);
	if (idx >= 0)
		printf(", event %d", idx);
	printf("\n");
}

static int print_stat(test_global_t *test_global)
{
	test_stat_t test_stat;
	test_stat_t *stat = &test_stat;
	uint64_t tot_timers;
	test_stat_t *s = test_global->stat;
	test_log_t *log = test_global->log;
	double res_ns = test_global->res_ns;
	uint64_t ave_after = 0;
	uint64_t ave_before = 0;
	uint64_t nsec_before_min_tid = 0;
	uint64_t nsec_before_max_tid = 0;
	uint64_t nsec_after_min_tid = 0;
	uint64_t nsec_after_max_tid = 0;

	memset(stat, 0, sizeof(*stat));
	stat->nsec_before_min = UINT64_MAX;
	stat->nsec_after_min = UINT64_MAX;

	for (int i = 1; i < test_global->opt.cpu_count + 1; i++) {
		stat->nsec_before_sum += s[i].nsec_before_sum;
		stat->nsec_after_sum += s[i].nsec_after_sum;
		stat->num_before += s[i].num_before;
		stat->num_exact += s[i].num_exact;
		stat->num_after += s[i].num_after;
		stat->num_too_near += s[i].num_too_near;

		if (s[i].nsec_before_min < stat->nsec_before_min) {
			stat->nsec_before_min = s[i].nsec_before_min;
			stat->nsec_before_min_idx = s[i].nsec_before_min_idx;
			nsec_before_min_tid = i;
		}

		if (s[i].nsec_after_min < stat->nsec_after_min) {
			stat->nsec_after_min = s[i].nsec_after_min;
			stat->nsec_after_min_idx = s[i].nsec_after_min_idx;
			nsec_after_min_tid = i;
		}

		if (s[i].nsec_before_max > stat->nsec_before_max) {
			stat->nsec_before_max = s[i].nsec_before_max;
			stat->nsec_before_max_idx = s[i].nsec_before_max_idx;
			nsec_before_max_tid = i;
		}

		if (s[i].nsec_after_max > stat->nsec_after_max) {
			stat->nsec_after_max = s[i].nsec_after_max;
			stat->nsec_after_max_idx = s[i].nsec_after_max_idx;
			nsec_after_max_tid = i;
		}
	}

	if (stat->num_after)
		ave_after = stat->nsec_after_sum / stat->num_after;
	else
		stat->nsec_after_min = 0;

	if (stat->num_before)
		ave_before = stat->nsec_before_sum / stat->num_before;
	else
		stat->nsec_before_min = 0;

	tot_timers = stat->num_before + stat->num_after + stat->num_exact;

	if (log) {
		FILE *file = test_global->file;

		fprintf(file, "   Timer  thread      tmo(ns)   diff(ns)\n");

		for (uint64_t i = 0; i < tot_timers; i++) {
			fprintf(file, "%8" PRIu64 " %7u %12" PRIu64 " %10"
				PRIi64 "\n", i, log[i].tid, log[i].tmo_ns, log[i].diff_ns);
		}

		fprintf(file, "\n");
	}

	printf("\nTest results:\n");
	printf("  num after:  %12" PRIu64 "  /  %.2f%%\n",
	       stat->num_after, 100.0 * stat->num_after / tot_timers);
	printf("  num before: %12" PRIu64 "  /  %.2f%%\n",
	       stat->num_before, 100.0 * stat->num_before / tot_timers);
	printf("  num exact:  %12" PRIu64 "  /  %.2f%%\n",
	       stat->num_exact, 100.0 * stat->num_exact / tot_timers);
	printf("  num retry:  %12" PRIu64 "  /  %.2f%%\n",
	       stat->num_too_near, 100.0 * stat->num_too_near / tot_timers);
	printf("  error after (nsec):\n");
	print_nsec_error("min", stat->nsec_after_min, res_ns, nsec_after_min_tid,
			 stat->nsec_after_min_idx);
	print_nsec_error("max", stat->nsec_after_max, res_ns, nsec_after_max_tid,
			 stat->nsec_after_max_idx);
	print_nsec_error("ave", ave_after, res_ns, -1, -1);
	printf("  error before (nsec):\n");
	print_nsec_error("min", stat->nsec_before_min, res_ns, nsec_before_min_tid,
			 stat->nsec_before_min_idx);
	print_nsec_error("max", stat->nsec_before_max, res_ns, nsec_before_max_tid,
			 stat->nsec_before_max_idx);
	print_nsec_error("ave", ave_before, res_ns, -1, -1);

	if (test_global->opt.mode == MODE_PERIODIC && !test_global->opt.offset_ns) {
		int idx = 0;
		int64_t max = 0;

		for (int i = 0; i < (int)test_global->opt.alloc_timers; i++) {
			timer_ctx_t *t = &test_global->timer_ctx[i];
			int64_t v = t->first_tmo_diff;

			if (ODPH_ABS(v) > ODPH_ABS(max)) {
				max = v;
				idx = i;
			}
		}

		printf("  first timeout difference to one period, based on %s (nsec):\n",
		       test_global->timer_ctx[idx].tmo_tick ? "timeout tick" : "time");
		print_nsec_error("max", max, res_ns, -1, -1);
	}

	int64_t max = 0;

	for (int i = 0; i < (int)test_global->opt.alloc_timers; i++) {
		timer_ctx_t *t = &test_global->timer_ctx[i];
		int64_t v = t->nsec_final;

		if (ODPH_ABS(v) > ODPH_ABS(max))
			max = v;
	}

	printf("  final timeout error (nsec):\n");
	print_nsec_error("max", max, res_ns, -1, -1);

	printf("\n");

	if (test_global->common_options.is_export) {
		if (test_common_write("num after,num before,num exact,num retry,"
				      "error after min (nsec),error after min resolution,"
				      "error after max (nsec),error after max resolution,"
				      "error after ave (nsec),error after ave resolution,"
				      "error before min (nsec),error before min resolution,"
				      "error before max (nsec),error before max resolution,"
				      "error before ave (nsec),error before ave resolution,"
				      "final timeout error max (nsec),"
				      "final timeout error max resolution\n")) {
			ODPH_ERR("Export failed\n");
			test_common_write_term();
			return -1;
		}

		if (test_common_write("%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
				      "%f,%" PRIu64 ",%f,%" PRIu64 ",%f,%" PRIu64 ",%f,%" PRIu64 ","
				      "%f,%" PRIu64 ",%f,%" PRId64 ",%f\n",
				      stat->num_after, stat->num_before,
				      stat->num_exact, stat->num_too_near,
				      stat->nsec_after_min, (double)stat->nsec_after_min / res_ns,
				      stat->nsec_after_max, (double)stat->nsec_after_max / res_ns,
				      ave_after, (double)ave_after / res_ns,
				      stat->nsec_before_min, (double)stat->nsec_before_min / res_ns,
				      stat->nsec_before_max, (double)stat->nsec_before_max / res_ns,
				      ave_before, (double)ave_before / res_ns,
				      max, (double)max / res_ns
				      )) {
			ODPH_ERR("Export failed\n");
			test_common_write_term();
			return -1;
		}

		test_common_write_term();
	}

	return 0;
}

static void cancel_periodic_timers(test_global_t *test_global)
{
	uint64_t i, alloc_timers;
	odp_timer_t timer;

	alloc_timers = test_global->opt.alloc_timers;

	for (i = 0; i < alloc_timers; i++) {
		timer = test_global->timer_ctx[i].timer;

		if (timer == ODP_TIMER_INVALID)
			break;

		if (odp_timer_periodic_cancel(timer))
			ODPH_ERR("Failed to cancel periodic timer.\n");
	}
}

static void process_event_concurrency(uint64_t events, test_global_t *test_global, timer_ctx_t *ctx,
				      uint64_t time_ns, odp_event_t ev)
{
	odp_timer_retval_t ret;
	odp_timer_start_t start_param;
	odp_timer_t tim;
	int locked = 0;
	const uint64_t period_ns = test_global->opt.period_ns;
	const uint64_t tick = test_global->period_tick;
	const int cancel_start =
		test_global->opt.cancel_start && !(events % test_global->opt.cancel_start);
	const int cancel = test_global->opt.cancel && !(events % test_global->opt.cancel);
	const int switch_timer =
		test_global->opt.switch_timer && !(events % test_global->opt.switch_timer);
	const int switch_event =
		test_global->opt.switch_event && !(events % test_global->opt.switch_event);

	if (cancel_start) {
		/*
		 * During the start-cancel-start sequence another thread could receive the event
		 * immediately after the first start() call. Use a lock to prevent the other thread
		 * from proceeding while we are still using the timer.
		 */
		locked = 1;
		odp_ticketlock_lock(&ctx->lock);
	}

	tim = ctx->timer;
	ctx->nsec = time_ns + period_ns;

	if (cancel) {
		odp_event_t event = NULL;
		/*
		 * Cancel the timer which originated this event. This should never succeed, since
		 * the timer already expired.
		 */
		ret = odp_timer_cancel(tim, &event);
		if (ret == ODP_TIMER_SUCCESS) {
			void *ev_ctx = odp_timeout_user_ptr(odp_timeout_from_event(event));

			ODPH_ERR(
				"odp_timer_cancel() succeeded: event %p ctx %p sched event %p sched ctx %p\n",
				event, ev_ctx, ev, ctx);
			goto error;
		}
	}

	if (switch_timer) {
		/*
		 * Switch timer.
		 */
		odp_timer_t timer =
			odp_timer_alloc(test_global->timer_pool,
					test_global->queue[events % test_global->opt.num_queue],
					ctx);
		if (timer == ODP_TIMER_INVALID) {
			ODPH_ERR("odp_timer_alloc() failed\n");
			goto error;
		}
		if (odp_timer_free(tim)) {
			ODPH_ERR("odp_timer_free()\n");
			goto error;
		}
		tim = timer;
		ctx->timer = tim;
	}

	if (switch_event) {
		/*
		 * Switch event.
		 */
		odp_timeout_t timeout = odp_timeout_alloc(test_global->timeout_pool);

		if (timeout == ODP_TIMEOUT_INVALID) {
			ODPH_ERR("odp_timeout_alloc() failed\n");
			goto error;
		}
		odp_event_free(ev);
		ev = odp_timeout_to_event(timeout);
	}

	start_param.tick_type = ODP_TIMER_TICK_REL;
	start_param.tmo_ev = ev;
	start_param.tick = tick;
	ctx->starts++;

	ret = odp_timer_start(tim, &start_param);
	if (ret != ODP_TIMER_SUCCESS) {
		ODPH_ERR("odp_timer_start(): %d\n", ret);
		goto error;
	}

	if (cancel_start) {
		/*
		 * Timer started, now immediately cancel and start again.
		 */
		if (odp_timer_cancel(tim, &ev) == ODP_TIMER_SUCCESS) {
			odp_timeout_t timeout = odp_timeout_alloc(test_global->timeout_pool);

			if (timeout == ODP_TIMEOUT_INVALID) {
				ODPH_ERR("odp_timeout_alloc() failed\n");
				goto error;
			}
			odp_event_free(ev);
			ev = odp_timeout_to_event(timeout);
			start_param.tmo_ev = ev;
			ret = odp_timer_start(tim, &start_param);
			if (ret != ODP_TIMER_SUCCESS) {
				ODPH_ERR("odp_timer_start(): %d\n", ret);
				goto error;
			}
		}
	}

	if (locked)
		odp_ticketlock_unlock(&ctx->lock);

	return;

error:
	if (locked)
		odp_ticketlock_unlock(&ctx->lock);

	_exit(1);
}

static int run_test(void *arg)
{
	test_global_t *test_global = (test_global_t *)arg;
	odp_event_t ev;
	odp_time_t time;
	uint64_t time_ns, diff_ns;
	odp_timeout_t tmo;
	uint64_t tmo_ns;
	timer_ctx_t *ctx;
	odp_thrmask_t mask;
	uint64_t wait = odp_schedule_wait_time(10 * ODP_TIME_MSEC_IN_NS);
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	test_log_t *log = test_global->log;
	enum mode_e mode = test_global->opt.mode;
	uint64_t tot_timers = test_global->opt.tot_timers;
	double period_dbl = test_global->period_dbl;
	odp_timer_pool_t tp = test_global->timer_pool;
	int tid = odp_thread_id();

	if (tid > test_global->opt.cpu_count) {
		ODPH_ERR("tid %d is larger than cpu_count %d.\n", tid, test_global->opt.cpu_count);
		return 0;
	}

	test_stat_t *stat = &test_global->stat[tid];

	memset(stat, 0, sizeof(*stat));
	stat->nsec_before_min = UINT64_MAX;
	stat->nsec_after_min = UINT64_MAX;

	if (test_global->opt.groups) {
		odp_thrmask_zero(&mask);
		odp_thrmask_set(&mask, tid);
		group = test_global->group[tid - 1];

		if (odp_schedule_group_join(group, &mask)) {
			ODPH_ERR("odp_schedule_group_join() failed\n");
			return 0;
		}
	}

	odp_barrier_wait(&test_global->barrier);

	while (1) {
		ev = odp_schedule(NULL, wait);
		time = odp_time_global_strict();

		if (ev == ODP_EVENT_INVALID) {
			if (mode == MODE_PERIODIC) {
				if (odp_atomic_load_u64(&test_global->last_events) >=
				    test_global->opt.alloc_timers)
					break;

			} else if (odp_atomic_load_u64(&test_global->events) >= tot_timers) {
				break;
			}

			continue;
		}

		time_ns = odp_time_to_ns(time);
		tmo = odp_timeout_from_event(ev);
		ctx = odp_timeout_user_ptr(tmo);
		tmo_ns = ctx->nsec;

		if (mode == MODE_PERIODIC) {
			if (!ctx->events && !test_global->opt.offset_ns) {
				/*
				 * If first_tick is zero, the API allows the implementation to
				 * place the timer where it can, so we have to adjust our
				 * expectation of the timeout time.
				 */

				uint64_t tmo_tick = odp_timeout_tick(tmo);

				if (tmo_tick) {
					/*
					 * Adjust by the difference between one period after start
					 * time and the timeout tick.
					 */
					ctx->tmo_tick = 1;
					ctx->first_tmo_diff =
					    (int64_t)odp_timer_tick_to_ns(tp, tmo_tick) -
					    (int64_t)odp_timer_tick_to_ns(tp, ctx->first_period);
					tmo_ns += ctx->first_tmo_diff;
				} else {
					/*
					 * Timeout tick is not provided, so the best we can do is
					 * to just take the current time as a baseline.
					 */
					ctx->first_tmo_diff = (int64_t)time_ns - (int64_t)tmo_ns;
					tmo_ns = ctx->nsec = time_ns;
				}

				ctx->nsec = tmo_ns;
			}

			/* round to closest integer number */
			tmo_ns += ctx->events * period_dbl + 0.5;
			ctx->events++;
		} else if (mode == MODE_CONCURRENCY) {
			uint64_t events = ++ctx->events;
			uint64_t starts = ctx->starts;

			if (events > starts) {
				ODPH_ERR("ctx %p timer %p time %" PRIu64 " starts %" PRIu64
					 " events %" PRIu64 "\n",
					 ctx, ctx->timer, time_ns, starts, events);
				if (test_global->opt.exit_on_error)
					_exit(1);
			}

			int64_t diff = (int64_t)time_ns - (int64_t)tmo_ns;

			if (test_global->opt.max_diff &&
			    diff > (int64_t)test_global->opt.max_diff) {
				ODPH_ERR("ctx %p timer %p time %" PRIu64 " diff %" PRIi64 "\n", ctx,
					 ctx->timer, time_ns, diff);
				if (test_global->opt.exit_on_error)
					_exit(1);
			}
		}

		uint64_t events = odp_atomic_fetch_inc_u64(&test_global->events);

		if (events >= test_global->opt.warmup_timers && events < tot_timers) {
			uint64_t i = events - test_global->opt.warmup_timers;

			ctx->nsec_final = (int64_t)time_ns - (int64_t)tmo_ns;

			if (log) {
				log[i].tmo_ns = tmo_ns;
				log[i].tid = tid;
			}

			if (time_ns > tmo_ns) {
				diff_ns = time_ns - tmo_ns;
				stat->num_after++;
				stat->nsec_after_sum += diff_ns;
				if (diff_ns < stat->nsec_after_min) {
					stat->nsec_after_min = diff_ns;
					stat->nsec_after_min_idx = i;
				}
				if (diff_ns > stat->nsec_after_max) {
					stat->nsec_after_max = diff_ns;
					stat->nsec_after_max_idx = i;
				}
				if (log)
					log[i].diff_ns = diff_ns;

			} else if (time_ns < tmo_ns) {
				diff_ns = tmo_ns - time_ns;
				stat->num_before++;
				stat->nsec_before_sum += diff_ns;
				if (diff_ns < stat->nsec_before_min) {
					stat->nsec_before_min = diff_ns;
					stat->nsec_before_min_idx = i;
				}
				if (diff_ns > stat->nsec_before_max) {
					stat->nsec_before_max = diff_ns;
					stat->nsec_before_max_idx = i;
				}
				if (log)
					log[i].diff_ns = -diff_ns;
			} else {
				stat->num_exact++;
			}
		}

		if ((mode == MODE_RESTART_ABS || mode == MODE_RESTART_REL) &&
		    events < tot_timers - 1) {
			/* Reset timer for next period */
			odp_timer_t tim;
			uint64_t nsec, tick;
			odp_timer_retval_t ret = ODP_TIMER_FAIL;
			unsigned int j;
			unsigned int retries = test_global->opt.early_retry;
			uint64_t start_ns = test_global->start_ns;
			uint64_t period_ns = test_global->opt.period_ns;
			odp_timer_start_t start_param;

			tim = ctx->timer;

			/* Depending on the option, retry when expiration
			 * time is too early */
			for (j = 0; j < retries + 1; j++) {
				if (mode == MODE_RESTART_ABS) {
					/* Absolute time */
					ctx->nsec += period_ns;
					nsec = ctx->nsec - start_ns;
					tick = test_global->start_tick +
					       odp_timer_ns_to_tick(tp, nsec);
					start_param.tick_type = ODP_TIMER_TICK_ABS;
				} else {
					/* Relative time */
					tick = test_global->period_tick;
					time = odp_time_local();
					time_ns = odp_time_to_ns(time);
					ctx->nsec = time_ns + period_ns;
					start_param.tick_type = ODP_TIMER_TICK_REL;
				}

				start_param.tmo_ev = ev;
				start_param.tick = tick;

				ret = odp_timer_start(tim, &start_param);
				if (ret == ODP_TIMER_TOO_NEAR) {
					if (events >= test_global->opt.warmup_timers)
						stat->num_too_near++;
				} else {
					break;
				}
			}

			if (ret != ODP_TIMER_SUCCESS) {
				ODPH_ERR("Timer set failed: %i. Timeout nsec "
					 "%" PRIu64 "\n",
					 ret, ctx->nsec);
				return 0;
			}
		} else if (mode == MODE_PERIODIC) {
			int ret = odp_timer_periodic_ack(ctx->timer, ev);

			if (ret < 0)
				ODPH_ERR("Failed to ack a periodic timer.\n");

			if (ret == 2)
				odp_atomic_inc_u64(&test_global->last_events);

			if (ret == 2 || ret < 0)
				odp_event_free(ev);
		} else if (mode == MODE_CONCURRENCY && events < tot_timers - 1) {
			process_event_concurrency(events, test_global, ctx, time_ns, ev);
		} else {
			odp_event_free(ev);
		}
	}

	if (test_global->opt.groups) {
		if (odp_schedule_group_leave(group, &mask))
			ODPH_ERR("odp_schedule_group_leave() failed\n");
	}

	return 0;
}

static void interval_loop_concurrency(test_global_t *test_global)
{
	uint64_t events_prev = 0;
	uint64_t events = 0;
	uint64_t start_ns = odp_time_global_strict_ns();
	uint64_t prev_ns = start_ns;

	while (events < test_global->opt.tot_timers) {
		odp_time_wait_ns(test_global->opt.interval * ODP_TIME_SEC_IN_NS);

		events = odp_atomic_load_u64(&test_global->events);

		uint64_t ns = odp_time_global_strict_ns();
		uint64_t msec = (ns - prev_ns) / ODP_TIME_MSEC_IN_NS;
		uint64_t sec_total = (ns - start_ns) / ODP_TIME_SEC_IN_NS;
		uint64_t e = events - events_prev;

		printf("sec %" PRIu64 " total events %" PRIu64 " events %" PRIu64
		       " events/s %" PRIu64 "\n", sec_total, events, e, e * 1000 / msec);
		events_prev = events;
		prev_ns = ns;
	}
}

int main(int argc, char *argv[])
{
	odp_instance_t instance;
	odp_init_t init;
	test_opt_t test_opt;
	test_global_t *test_global;
	odph_helper_options_t helper_options;
	test_common_options_t common_options;
	odp_init_t *init_ptr = NULL;
	int ret = 0;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	argc = test_common_parse_options(argc, argv);
	if (test_common_options(&common_options)) {
		ODPH_ERR("Reading test options failed\n");
		exit(EXIT_FAILURE);
	}

	if (parse_options(argc, argv, &test_opt))
		return -1;

	/* List features not to be used (may optimize performance) */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.tm       = 1;

	init.mem_model = helper_options.mem_model;

	if (test_opt.init)
		init_ptr = &init;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, init_ptr, NULL)) {
		ODPH_ERR("Global init failed.\n");
		return -1;
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		return -1;
	}

	odp_sys_info_print();

	/* Configure scheduler */
	odp_schedule_config(NULL);

	odp_shm_t shm = ODP_SHM_INVALID, shm_ctx = ODP_SHM_INVALID, shm_log = ODP_SHM_INVALID;
	uint64_t size = sizeof(test_global_t);

	shm = odp_shm_reserve("timer_accuracy", size,
			      ODP_CACHE_LINE_SIZE, ODP_SHM_SINGLE_VA);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shm alloc failed.\n");
		return -1;
	}

	test_global = odp_shm_addr(shm);
	memset(test_global, 0, size);
	memcpy(&test_global->opt, &test_opt, sizeof(test_opt_t));

	test_global->common_options = common_options;

	size = test_global->opt.alloc_timers * sizeof(timer_ctx_t);
	shm_ctx = odp_shm_reserve("timer_accuracy_ctx", size,
				  ODP_CACHE_LINE_SIZE, ODP_SHM_SINGLE_VA);

	if (shm_ctx == ODP_SHM_INVALID) {
		ODPH_ERR("Timer context alloc failed.\n");
		ret = -1;
		goto quit;
	}

	test_global->timer_ctx = odp_shm_addr(shm_ctx);
	memset(test_global->timer_ctx, 0, size);

	if (test_global->opt.output) {
		test_global->file = fopen(test_global->opt.filename, "w");
		if (test_global->file == NULL) {
			ODPH_ERR("Failed to open output file %s: %s\n", test_global->opt.filename,
				 strerror(errno));
			ret = -1;
			goto quit;
		}

		size = (test_global->opt.tot_timers - test_global->opt.warmup_timers) *
		       sizeof(test_log_t);
		shm_log = odp_shm_reserve("timer_accuracy_log", size, sizeof(test_log_t),
					  ODP_SHM_SINGLE_VA);

		if (shm_log == ODP_SHM_INVALID) {
			ODPH_ERR("Test log alloc failed.\n");
			ret = -1;
			goto quit;
		}

		test_global->log = odp_shm_addr(shm_log);
		memset(test_global->log, 0, size);
	}

	odph_thread_t thread_tbl[MAX_WORKERS];
	int num_workers;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;

	memset(thread_tbl, 0, sizeof(thread_tbl));

	num_workers = MAX_WORKERS;
	if (test_global->opt.cpu_count && test_global->opt.cpu_count < MAX_WORKERS)
		num_workers = test_global->opt.cpu_count;
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	test_global->opt.cpu_count = num_workers;
	odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	ret = create_timers(test_global);
	if (ret)
		goto quit;

	odp_barrier_init(&test_global->barrier, num_workers + 1);
	odp_atomic_init_u64(&test_global->events, 0);
	odp_atomic_init_u64(&test_global->last_events, 0);

	odph_thread_param_init(&thr_param);
	thr_param.start = run_test;
	thr_param.arg = (void *)test_global;
	thr_param.thr_type = ODP_THREAD_WORKER;

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;

	odph_thread_create(thread_tbl, &thr_common, &thr_param, num_workers);
	odp_barrier_wait(&test_global->barrier);

	ret = start_timers(test_global);
	if (ret)
		goto quit;

	if (test_global->opt.mode == MODE_PERIODIC) {
		while (odp_atomic_load_u64(&test_global->events) < test_global->opt.tot_timers)
			odp_time_wait_ns(10 * ODP_TIME_MSEC_IN_NS);

		cancel_periodic_timers(test_global);
	} else if (test_global->opt.mode == MODE_CONCURRENCY) {
		interval_loop_concurrency(test_global);
	}

	odph_thread_join(thread_tbl, num_workers);

	ret = print_stat(test_global);
	if (ret)
		goto quit;

quit:
	if (test_global->file)
		fclose(test_global->file);

	if (destroy_timers(test_global))
		ret = -1;

	if (shm_log != ODP_SHM_INVALID && odp_shm_free(shm_log))
		ret = -1;

	if (shm_ctx != ODP_SHM_INVALID && odp_shm_free(shm_ctx))
		ret = -1;

	if (odp_shm_free(shm))
		ret = -1;

	if (odp_term_local()) {
		ODPH_ERR("Term local failed.\n");
		ret = -1;
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Term global failed.\n");
		ret = -1;
	}

	return ret;
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/**
 * @example odp_timer_stress.c
 *
 * Stress test for benchmarking timer related handling performance in different scenarios.
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

#define PROG_NAME "odp_timer_stress"

#define MAX_WORKERS ((uint32_t)(ODP_THREAD_COUNT_MAX - 1))
#define MULTIPLIER 50U
#define FMT_RES "4"
#define MAX_RETRY 10U
#define WAIT_MULTIPLIER 100U

#define GIGAS 1000000000U
#define MEGAS 1000000U
#define KILOS 1000U

enum {
	SINGLE_SHOT,
	PERIODIC,
	CANCEL
};

enum {
	SHARED_TMR,
	PRIV_TMR
};

#define DEF_MODE SINGLE_SHOT
#define DEF_CLK_SRC ODP_CLOCK_DEFAULT
#define DEF_RES 1000000U
#define DEF_TIMERS 50U
#define DEF_POLICY SHARED_TMR
#define DEF_TIME 2U
#define DEF_WORKERS 1U

typedef enum {
	PRS_OK,
	PRS_NOK,
	PRS_TERM
} parse_result_t;

typedef struct {
	uint64_t num_tmo;
	uint64_t num_retry;
	uint64_t num_miss;
	uint64_t tot_tm;
	uint64_t max_mul;
} stats_t;

typedef struct prog_config_s prog_config_t;

typedef struct {
	odp_timer_t tmr;
	odp_timeout_t tmo;
	odp_bool_t is_running;
} tmr_hdls_t;

typedef struct ODP_ALIGNED_CACHE {
	stats_t stats;

	struct {
		odp_schedule_group_t grp;
		odp_queue_t q;
	} scd;

	struct {
		tmr_hdls_t *tmrs;
	} cancel;

	prog_config_t *prog_config;
	uint32_t num_boot_tmr;
} worker_config_t;

typedef struct {
	uint32_t mode;
	odp_timer_clk_src_t clk_src;
	uint64_t res_ns;
	uint32_t num_tmr;
	uint32_t policy;
	uint32_t time_sec;
	uint32_t num_workers;
} opts_t;

typedef struct prog_config_s {
	odph_thread_t thread_tbl[MAX_WORKERS];
	worker_config_t worker_config[MAX_WORKERS];
	odp_instance_t odp_instance;
	odp_cpumask_t worker_mask;
	odp_barrier_t init_barrier;
	odp_barrier_t term_barrier;
	odp_atomic_u32_t is_running;
	opts_t def_opts;
	opts_t opts;
	odp_timer_res_capability_t res_capa;
	odp_timer_periodic_capability_t per_capa;
	odp_pool_t tmo_pool;
	odp_timer_pool_t tmr_pool;
	odp_spinlock_t lock;
	odp_shm_t cancel_shm;
} prog_config_t;

static prog_config_t *prog_conf;

static void terminate(int signal ODP_UNUSED)
{
	odp_atomic_store_u32(&prog_conf->is_running, 0U);
}

static void init_config(prog_config_t *config)
{
	opts_t opts;
	odp_timer_capability_t capa;
	worker_config_t *worker;

	opts.mode = DEF_MODE;
	opts.clk_src = DEF_CLK_SRC;
	opts.res_ns = DEF_RES;
	opts.num_tmr = DEF_TIMERS;
	opts.policy = DEF_POLICY;
	opts.time_sec = DEF_TIME;
	opts.num_workers = DEF_WORKERS;

	if (odp_timer_capability(opts.clk_src, &capa) == 0) {
		if (opts.res_ns < capa.highest_res_ns)
			opts.res_ns = capa.highest_res_ns;

		if (opts.mode == SINGLE_SHOT || opts.mode == CANCEL) {
			if (capa.max_timers > 0U && opts.num_tmr > capa.max_timers)
				opts.num_tmr = capa.max_timers;
		} else if (capa.max_pools > 0U && opts.num_tmr > capa.periodic.max_timers) {
			opts.num_tmr = capa.periodic.max_timers;
		}
	}

	for (uint32_t i = 0U; i < MAX_WORKERS; ++i) {
		worker = &config->worker_config[i];
		worker->scd.grp = ODP_SCHED_GROUP_INVALID;
		worker->scd.q = ODP_QUEUE_INVALID;
	}

	config->def_opts = opts;
	config->opts = config->def_opts;
	config->tmo_pool = ODP_POOL_INVALID;
	config->tmr_pool = ODP_TIMER_POOL_INVALID;
	odp_spinlock_init(&config->lock);
	config->cancel_shm = ODP_SHM_INVALID;
}

static void print_usage(const opts_t *opts)
{
	printf("\n"
	       "Stress test for benchmarking timer related handling performance in different\n"
	       "scenarios.\n"
	       "\n"
	       "Usage: " PROG_NAME " [OPTIONS]\n");
	printf("\n"
	       "  E.g. " PROG_NAME " -m 0 -n 20\n"
	       "       " PROG_NAME " -m 2 -p 1 -t 5 -c 4\n");
	printf("\n"
	       "Optional OPTIONS:\n"
	       "\n"
	       "  -m, --mode         Timer mode. %u by default. Modes:\n"
	       "                         0: single shot\n"
	       "                         1: periodic\n"
	       "                         2: single shot with cancel\n"
	       "  -s, --clock_source Clock source. Use 'odp_timer_clk_src_t' enumeration values.\n"
	       "                     %u by default.\n"
	       "  -r, --resolution   Timer resolution in nanoseconds. %" PRIu64 " by default.\n"
	       "  -n, --num_timer    Number of timers. %u by default.\n"
	       "  -p, --policy       Timer sharing policy. %u by default. Policies:\n"
	       "                         0: Timers shared by workers\n"
	       "                         1: Private timers per worker\n"
	       "  -t, --time_sec     Time in seconds to run. 0 means infinite. %u by default.\n"
	       "  -c, --worker_count Number of workers. %u by default.\n"
	       "  -h, --help         This help.\n"
	       "\n", opts->mode, opts->clk_src, opts->res_ns, opts->num_tmr, opts->policy,
	       opts->time_sec, opts->num_workers);
}

static odp_fract_u64_t calc_req_hz(uint64_t res_ns)
{
	odp_fract_u64_t fract;
	const double hz = (double)ODP_TIME_SEC_IN_NS / (res_ns * MULTIPLIER);
	double leftover;

	fract.integer = (uint64_t)hz;
	leftover = hz - fract.integer;
	fract.numer = (uint64_t)(leftover * DEF_RES);
	fract.denom = fract.numer == 0U ? 0U : DEF_RES;

	return fract;
}

static parse_result_t check_options(prog_config_t *config)
{
	opts_t *opts = &config->opts;
	odp_timer_capability_t tmr_capa;
	int ret;
	uint32_t req_tmr, max_workers, req_shm;
	odp_fract_u64_t hz;
	double hz_d, min_hz_d, max_hz_d;
	odp_pool_capability_t pool_capa;
	odp_shm_capability_t shm_capa;
	uint64_t req_shm_sz;

	if (opts->mode != SINGLE_SHOT && opts->mode != PERIODIC && opts->mode != CANCEL) {
		ODPH_ERR("Invalid timer mode: %u\n", opts->mode);
		return PRS_NOK;
	}

	if (opts->policy != SHARED_TMR && opts->policy != PRIV_TMR) {
		ODPH_ERR("Invalid pool policy: %d\n", opts->policy);
		return PRS_NOK;
	}

	if (opts->mode == CANCEL && opts->policy != PRIV_TMR) {
		ODPH_ERR("Single shot with cancel mode supported only with worker-private "
			 "timers\n");
		return PRS_NOK;
	}

	ret = odp_timer_capability(opts->clk_src, &tmr_capa);

	if (ret < -1) {
		ODPH_ERR("Error querying timer capabilities\n");
		return PRS_NOK;
	}

	if (ret == -1) {
		ODPH_ERR("Invalid clock source: %d\n", opts->clk_src);
		return PRS_NOK;
	}

	if (!tmr_capa.queue_type_sched) {
		ODPH_ERR("Invalid queue support, scheduled completion queues not supported\n");
		return PRS_NOK;
	}

	if (opts->res_ns < tmr_capa.highest_res_ns) {
		ODPH_ERR("Invalid resolution: %" PRIu64 " ns (max: %" PRIu64 " ns)\n",
			 opts->res_ns, tmr_capa.highest_res_ns);
		return PRS_NOK;
	}

	if (opts->num_tmr == 0U) {
		ODPH_ERR("Invalid number of timers: %u\n", opts->num_tmr);
		return PRS_NOK;
	}

	max_workers = ODPH_MIN(MAX_WORKERS, (uint32_t)odp_cpumask_default_worker(NULL, 0));

	if (opts->num_workers == 0U || opts->num_workers > max_workers) {
		ODPH_ERR("Invalid worker count: %u (min: 1, max: %u)\n", opts->num_workers,
			 max_workers);
		return PRS_NOK;
	}

	(void)odp_cpumask_default_worker(&config->worker_mask, opts->num_workers);

	req_tmr = opts->num_tmr * (opts->policy == PRIV_TMR ? opts->num_workers : 1U);

	if (opts->mode == SINGLE_SHOT || opts->mode == CANCEL) {
		if (tmr_capa.max_pools == 0U) {
			ODPH_ERR("Single shot timers not supported\n");
			return PRS_NOK;
		}

		if (tmr_capa.max_timers > 0U && req_tmr > tmr_capa.max_timers) {
			ODPH_ERR("Invalid number of timers: %u (max: %u)\n", req_tmr,
				 tmr_capa.max_timers);
			return PRS_NOK;
		}

		config->res_capa.res_ns = opts->res_ns;

		if (odp_timer_res_capability(opts->clk_src, &config->res_capa) < 0) {
			ODPH_ERR("Error querying timer resolution capabilities\n");
			return PRS_NOK;
		}

		if (opts->mode == CANCEL) {
			if (odp_shm_capability(&shm_capa) < 0) {
				ODPH_ERR("Error querying SHM capabilities");
				return PRS_NOK;
			}

			/* One block for program configuration, one block divided between
			 * workers. */
			req_shm = 2U;

			if (req_shm > shm_capa.max_blocks) {
				ODPH_ERR("Invalid SHM block count support: %u (max: %u)\n",
					 req_shm, shm_capa.max_blocks);
				return PRS_NOK;
			}

			/* Dimensioned so that each structure will always start at a cache line
			 * boundary. */
			req_shm_sz = ODP_CACHE_LINE_ROUNDUP(sizeof(tmr_hdls_t)) *
				     opts->num_tmr * opts->num_workers;

			if (shm_capa.max_size != 0U && req_shm_sz > shm_capa.max_size) {
				ODPH_ERR("Invalid total SHM block size: %" PRIu64 ""
					 " (max: %" PRIu64 ")\n", req_shm_sz, shm_capa.max_size);
				return PRS_NOK;
			}
		}
	} else {
		if (tmr_capa.periodic.max_pools == 0U) {
			ODPH_ERR("Periodic timers not supported\n");
			return PRS_NOK;
		}

		if (req_tmr > tmr_capa.periodic.max_timers) {
			ODPH_ERR("Invalid number of timers: %u (max: %u)\n", req_tmr,
				 tmr_capa.periodic.max_timers);
			return PRS_NOK;
		}

		hz = calc_req_hz(opts->res_ns);
		hz_d = odp_fract_u64_to_dbl(&hz);
		min_hz_d = odp_fract_u64_to_dbl(&tmr_capa.periodic.min_base_freq_hz);
		max_hz_d = odp_fract_u64_to_dbl(&tmr_capa.periodic.max_base_freq_hz);

		if (hz_d < min_hz_d || hz_d > max_hz_d) {
			ODPH_ERR("Invalid requested resolution: %." FMT_RES "f hz "
				 "(min: %." FMT_RES "f hz, max: %." FMT_RES "f hz)\n", hz_d,
				 min_hz_d, max_hz_d);
			return PRS_NOK;
		}

		config->per_capa.base_freq_hz = hz;
		config->per_capa.max_multiplier = MULTIPLIER;
		config->per_capa.res_ns = opts->res_ns;

		if (odp_timer_periodic_capability(opts->clk_src, &config->per_capa) < 0) {
			ODPH_ERR("Error querying periodic timer capabilities\n");
			return PRS_NOK;
		}

		if (config->per_capa.max_multiplier > MULTIPLIER)
			config->per_capa.max_multiplier = MULTIPLIER;
	}

	if (odp_pool_capability(&pool_capa) < 0) {
		ODPH_ERR("Error querying pool capabilities\n");
		return PRS_NOK;
	}

	if (pool_capa.tmo.max_num > 0U && req_tmr > pool_capa.tmo.max_num) {
		ODPH_ERR("Invalid timeout event count: %u (max: %u)\n", req_tmr,
			 pool_capa.tmo.max_num);
		return PRS_NOK;
	}

	return PRS_OK;
}

static parse_result_t parse_options(int argc, char **argv, prog_config_t *config)
{
	int opt;
	opts_t *opts = &config->opts;

	static const struct option longopts[] = {
		{ "mode", required_argument, NULL, 'm' },
		{ "clock_source", required_argument, NULL, 's' },
		{ "resolution", required_argument, NULL, 'r' },
		{ "num_timer", required_argument, NULL, 'n' },
		{ "policy", required_argument, NULL, 'p' },
		{ "time_sec", required_argument, NULL, 't' },
		{ "worker_count", required_argument, NULL, 'c' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "m:s:r:n:p:t:c:h";

	init_config(config);

	while (true) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
		case 'm':
			opts->mode = atoi(optarg);
			break;
		case 's':
			opts->clk_src = atoi(optarg);
			break;
		case 'r':
			opts->res_ns = atoll(optarg);
			break;
		case 'n':
			opts->num_tmr = atoi(optarg);
			break;
		case 'p':
			opts->policy = atoi(optarg);
			break;
		case 't':
			opts->time_sec = atoi(optarg);
			break;
		case 'c':
			opts->num_workers = atoi(optarg);
			break;
		case 'h':
			print_usage(&config->def_opts);
			return PRS_TERM;
		case '?':
		default:
			print_usage(&config->def_opts);
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

static odp_timer_pool_t create_timer_pool(odp_timer_pool_param_t *param)
{
	odp_timer_pool_t pool;

	pool = odp_timer_pool_create(PROG_NAME, param);

	if (pool == ODP_TIMER_POOL_INVALID) {
		ODPH_ERR("Error creating timer pool\n");
		return ODP_TIMER_POOL_INVALID;
	}

	if (odp_timer_pool_start_multi(&pool, 1) != 1) {
		ODPH_ERR("Error starting timer pool\n");
		return ODP_TIMER_POOL_INVALID;
	}

	return pool;
}

static odp_bool_t setup_config(prog_config_t *config)
{
	opts_t *opts = &config->opts;
	odp_bool_t is_priv = opts->policy == PRIV_TMR;
	const uint32_t num_barrier = opts->num_workers + 1,
	max_tmr = opts->num_tmr * (is_priv ? opts->num_workers : 1U),
	tmr_size = ODP_CACHE_LINE_ROUNDUP(sizeof(tmr_hdls_t));
	odp_pool_param_t tmo_param;
	odp_timer_pool_param_t tmr_param;
	odp_queue_param_t q_param;
	odp_thrmask_t zero;
	void *cancel_addr = NULL;
	uint32_t num_tmr_p_w = ODPH_DIV_ROUNDUP(opts->num_tmr, opts->num_workers),
	num_tmr = opts->num_tmr;
	worker_config_t *worker;

	if (odp_schedule_config(NULL) < 0) {
		ODPH_ERR("Error initializing scheduler\n");
		return false;
	}

	odp_barrier_init(&config->init_barrier, num_barrier);
	odp_barrier_init(&config->term_barrier, num_barrier);
	odp_pool_param_init(&tmo_param);
	tmo_param.type = ODP_POOL_TIMEOUT;
	tmo_param.tmo.num = max_tmr;
	tmo_param.tmo.cache_size = 0U;
	config->tmo_pool = odp_pool_create(PROG_NAME, &tmo_param);

	if (config->tmo_pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error creating timeout pool\n");
		return false;
	}

	odp_timer_pool_param_init(&tmr_param);
	tmr_param.clk_src = opts->clk_src;
	tmr_param.res_ns = opts->res_ns;
	tmr_param.num_timers = max_tmr;

	if (opts->mode == SINGLE_SHOT || opts->mode == CANCEL) {
		tmr_param.timer_type = ODP_TIMER_TYPE_SINGLE;
		tmr_param.min_tmo = config->res_capa.min_tmo;
		tmr_param.max_tmo = config->res_capa.max_tmo;
	} else {
		tmr_param.timer_type = ODP_TIMER_TYPE_PERIODIC;
		tmr_param.periodic.base_freq_hz = config->per_capa.base_freq_hz;
		tmr_param.periodic.max_multiplier = config->per_capa.max_multiplier;
	}

	config->tmr_pool = create_timer_pool(&tmr_param);

	if (config->tmr_pool == ODP_TIMER_POOL_INVALID)
		return false;

	odp_queue_param_init(&q_param);
	q_param.type = ODP_QUEUE_TYPE_SCHED;
	q_param.sched.prio = odp_schedule_default_prio();
	odp_thrmask_zero(&zero);

	if (is_priv && opts->mode == CANCEL) {
		config->cancel_shm = odp_shm_reserve(PROG_NAME, tmr_size * max_tmr,
						     ODP_CACHE_LINE_SIZE, 0U);

		if (config->cancel_shm == ODP_SHM_INVALID) {
			ODPH_ERR("Error reserving SHM for cancel mode\n");
			return false;
		}

		cancel_addr = odp_shm_addr(config->cancel_shm);

		if (cancel_addr == NULL) {
			ODPH_ERR("Error resolving SHM address for cancel mode\n");
			return false;
		}
	}

	for (uint32_t i = 0U; i < opts->num_workers; ++i) {
		worker = &config->worker_config[i];
		worker->num_boot_tmr = num_tmr_p_w;
		num_tmr -= num_tmr_p_w;

		if (num_tmr < num_tmr_p_w)
			num_tmr_p_w = num_tmr;

		if (is_priv) {
			worker->num_boot_tmr = opts->num_tmr;

			if (opts->mode == CANCEL)
				worker->cancel.tmrs =
				  (tmr_hdls_t *)(uintptr_t)((uint8_t *)(uintptr_t)cancel_addr + i *
				  worker->num_boot_tmr * tmr_size);

			worker->scd.grp = odp_schedule_group_create(PROG_NAME, &zero);

			if (worker->scd.grp == ODP_SCHED_GROUP_INVALID) {
				ODPH_ERR("Error creating schedule group for worker %u\n", i);
				return false;
			}

			q_param.sched.group = worker->scd.grp;
		}

		worker->scd.q = odp_queue_create(PROG_NAME, &q_param);

		if (worker->scd.q == ODP_QUEUE_INVALID) {
			ODPH_ERR("Error creating completion queue for worker %u\n", i);
			return false;
		}

		worker->prog_config = config;
	}

	return true;
}

static tmr_hdls_t get_time_handles(odp_timer_pool_t tmr_pool, odp_pool_t tmo_pool, odp_queue_t q)
{
	tmr_hdls_t time;

	time.tmr = odp_timer_alloc(tmr_pool, q, NULL);

	if (time.tmr == ODP_TIMER_INVALID)
		/* We should have enough timers available, if still somehow there is a failure,
		 * abort. */
		ODPH_ABORT("Error allocating timers, aborting (tmr: %" PRIx64 ", "
			   "tmr pool: %" PRIx64 ")\n", odp_timer_to_u64(time.tmr),
			   odp_timer_pool_to_u64(tmr_pool));

	time.tmo = odp_timeout_alloc(tmo_pool);

	if (time.tmo == ODP_TIMEOUT_INVALID)
		/* We should have enough timeouts available, if still somehow there is a failure,
		 * abort. */
		ODPH_ABORT("Error allocating timeouts, aborting (tmo: %" PRIx64 ", "
			   "tmo pool: %" PRIx64 ")\n", odp_timeout_to_u64(time.tmo),
			   odp_pool_to_u64(tmo_pool));

	time.is_running = true;

	return time;
}

static inline void start_single_shot(odp_timer_pool_t tmr_pool, odp_timer_t tmr, odp_event_t tmo,
				     uint64_t res_ns, stats_t *stats)
{
	odp_timer_start_t start = { .tick_type = ODP_TIMER_TICK_REL, .tmo_ev = tmo };
	uint32_t retry = MAX_RETRY, mul = 1U;
	int ret;

	while (retry) {
		start.tick = odp_timer_ns_to_tick(tmr_pool, mul * res_ns);
		ret = odp_timer_start(tmr, &start);

		if (ret == ODP_TIMER_SUCCESS)
			break;

		--retry;

		if (retry > 0U) {
			if (ret == ODP_TIMER_BUSY) {
				/* Resources busy, don't increment multiplier, just retry. */
				++stats->num_retry;
				continue;
			}

			if (ret == ODP_TIMER_TOO_NEAR) {
				++mul;
				++stats->num_retry;
				continue;
			}
		}

		/* Arming the timer apparently not possible, abort. */
		ODPH_ABORT("Error starting timers, aborting (tmr: %" PRIx64 ", tmr pool: "
			   "%" PRIx64 ")\n", odp_timer_to_u64(tmr),
			   odp_timer_pool_to_u64(tmr_pool));
	}

	stats->max_mul = mul > stats->max_mul ? mul : stats->max_mul;
}

static void boot_single_shot(worker_config_t *worker, odp_timer_pool_t tmr_pool,
			     odp_pool_t tmo_pool, uint64_t res_ns)
{
	tmr_hdls_t time;

	for (uint32_t i = 0U; i < worker->num_boot_tmr; ++i) {
		time = get_time_handles(tmr_pool, tmo_pool, worker->scd.q);
		start_single_shot(tmr_pool, time.tmr, odp_timeout_to_event(time.tmo), res_ns,
				  &worker->stats);
	}
}

static int process_single_shot(void *args)
{
	worker_config_t *worker = args;
	odp_thrmask_t mask;
	prog_config_t *config = worker->prog_config;
	odp_timer_pool_t tmr_pool = config->tmr_pool;
	const uint64_t res_ns = prog_conf->opts.res_ns;
	odp_time_t tm;
	odp_atomic_u32_t *is_running = &config->is_running;
	odp_event_t ev;
	odp_timer_t tmr;
	stats_t *stats = &worker->stats;

	if (worker->scd.grp != ODP_SCHED_GROUP_INVALID) {
		odp_thrmask_zero(&mask);
		odp_thrmask_set(&mask, odp_thread_id());

		if (odp_schedule_group_join(worker->scd.grp, &mask) < 0)
			ODPH_ABORT("Error joining scheduler group, aborting (group: %" PRIu64 ")"
				   "\n", odp_schedule_group_to_u64(worker->scd.grp));
	}

	boot_single_shot(worker, tmr_pool, config->tmo_pool, res_ns);
	odp_barrier_wait(&config->init_barrier);
	tm = odp_time_local_strict();

	while (odp_atomic_load_u32(is_running)) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			continue;

		tmr = odp_timeout_timer(odp_timeout_from_event(ev));
		start_single_shot(tmr_pool, tmr, ev, res_ns, stats);
		++stats->num_tmo;
	}

	stats->tot_tm = odp_time_diff_ns(odp_time_local_strict(), tm);
	odp_barrier_wait(&config->term_barrier);

	while (true) {
		ev = odp_schedule(NULL, odp_schedule_wait_time(stats->max_mul * res_ns *
							       WAIT_MULTIPLIER));

		if (ev == ODP_EVENT_INVALID)
			break;

		tmr = odp_timeout_timer(odp_timeout_from_event(ev));
		odp_event_free(ev);
		(void)odp_timer_free(tmr);
	}

	return 0;
}

static void start_periodic(odp_timer_pool_t tmr_pool, odp_timer_t tmr, odp_event_t tmo,
			   uint64_t mul, stats_t *stats)
{
	const odp_timer_periodic_start_t start = { .first_tick = 0U, .freq_multiplier = mul,
						   .tmo_ev = tmo };
	uint32_t retry = MAX_RETRY;
	int ret;

	while (retry) {
		ret = odp_timer_periodic_start(tmr, &start);

		if (ret == ODP_TIMER_SUCCESS)
			break;

		--retry;

		if (retry > 0U && ret == ODP_TIMER_BUSY) {
			++stats->num_retry;
			continue;
		}

		/* Arming the timer apparently not possible, abort. */
		ODPH_ABORT("Error starting timer, aborting (tmr: %" PRIx64 ", tmr pool: "
			   "%" PRIx64 ")\n", odp_timer_to_u64(tmr),
			   odp_timer_pool_to_u64(tmr_pool));
	}
}

static void boot_periodic(worker_config_t *worker, odp_timer_pool_t tmr_pool, odp_pool_t tmo_pool,
			  uint64_t mul)
{
	tmr_hdls_t time;

	for (uint32_t i = 0U; i < worker->num_boot_tmr; ++i) {
		time = get_time_handles(tmr_pool, tmo_pool, worker->scd.q);
		start_periodic(tmr_pool, time.tmr, odp_timeout_to_event(time.tmo), mul,
			       &worker->stats);
	}
}

static int process_periodic(void *args)
{
	worker_config_t *worker = args;
	odp_thrmask_t mask;
	prog_config_t *config = worker->prog_config;
	odp_time_t tm;
	odp_atomic_u32_t *is_running = &config->is_running;
	odp_event_t ev;
	odp_timer_t tmr;
	stats_t *stats = &worker->stats;
	const uint64_t res_ns = prog_conf->opts.res_ns;
	int ret;

	if (worker->scd.grp != ODP_SCHED_GROUP_INVALID) {
		odp_thrmask_zero(&mask);
		odp_thrmask_set(&mask, odp_thread_id());

		if (odp_schedule_group_join(worker->scd.grp, &mask) < 0)
			ODPH_ABORT("Error joining scheduler group, aborting (group: %" PRIu64 ")"
				   "\n", odp_schedule_group_to_u64(worker->scd.grp));
	}

	boot_periodic(worker, config->tmr_pool, config->tmo_pool, config->per_capa.max_multiplier);
	odp_barrier_wait(&config->init_barrier);
	tm = odp_time_local_strict();

	while (odp_atomic_load_u32(is_running)) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev == ODP_EVENT_INVALID)
			continue;

		tmr = odp_timeout_timer(odp_timeout_from_event(ev));

		if (odp_unlikely(odp_timer_periodic_ack(tmr, ev) < 0))
			ODPH_ABORT("Error acking periodic timer, aborting (tmr: %" PRIx64 ")\n",
				   odp_timer_to_u64(tmr));

		++stats->num_tmo;
	}

	stats->tot_tm = odp_time_diff_ns(odp_time_local_strict(), tm);
	odp_barrier_wait(&config->term_barrier);

	while (true) {
		ev = odp_schedule(NULL, odp_schedule_wait_time(res_ns *
							       config->per_capa.max_multiplier *
							       WAIT_MULTIPLIER));

		if (ev == ODP_EVENT_INVALID)
			break;

		/* Many workers might be trying to cancel the timer, do it exclusively. */
		odp_spinlock_lock(&config->lock);
		tmr = odp_timeout_timer(odp_timeout_from_event(ev));
		ret = odp_timer_periodic_ack(tmr, ev);

		if (ret < 0)
			ODPH_ABORT("Error acking periodic timer, aborting (tmr: %" PRIx64 ")\n",
				   odp_timer_to_u64(tmr));

		if (ret == 1) {
			odp_spinlock_unlock(&config->lock);
			continue;
		}

		if (ret == 2) {
			odp_event_free(ev);
			(void)odp_timer_free(tmr);
			odp_spinlock_unlock(&config->lock);
			continue;
		}

		if (odp_timer_periodic_cancel(tmr) < 0)
			ODPH_ABORT("Error cancelling periodic timer, aborting "
				   "(tmr: %" PRIx64 ")\n", odp_timer_to_u64(tmr));

		odp_spinlock_unlock(&config->lock);
	}

	return 0;
}

static void boot_cancel(worker_config_t *worker, odp_timer_pool_t tmr_pool, odp_pool_t tmo_pool,
			uint64_t res_ns)
{
	tmr_hdls_t time;

	for (uint32_t i = 0U; i < worker->num_boot_tmr; ++i) {
		time = get_time_handles(tmr_pool, tmo_pool, worker->scd.q);
		start_single_shot(tmr_pool, time.tmr, odp_timeout_to_event(time.tmo), res_ns,
				  &worker->stats);
		worker->cancel.tmrs[i] = time;
	}
}

static int process_cancel(void *args)
{
	worker_config_t *worker = args;
	odp_thrmask_t mask;
	prog_config_t *config = worker->prog_config;
	odp_timer_pool_t tmr_pool = config->tmr_pool;
	const uint64_t res_ns = prog_conf->opts.res_ns;
	odp_time_t tm;
	odp_atomic_u32_t *is_running = &config->is_running;
	odp_event_t ev;
	stats_t *stats = &worker->stats;
	const uint32_t num_boot_tmr = worker->num_boot_tmr;
	tmr_hdls_t *time;
	int ret;
	odp_timer_t tmr;

	odp_thrmask_zero(&mask);
	odp_thrmask_set(&mask, odp_thread_id());

	if (odp_schedule_group_join(worker->scd.grp, &mask) < 0)
		ODPH_ABORT("Error joining scheduler group, aborting (group: %" PRIu64 ")\n",
			   odp_schedule_group_to_u64(worker->scd.grp));

	boot_cancel(worker, tmr_pool, config->tmo_pool, res_ns);
	odp_barrier_wait(&config->init_barrier);
	tm = odp_time_local_strict();

	while (odp_atomic_load_u32(is_running)) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (odp_unlikely(ev != ODP_EVENT_INVALID)) {
			start_single_shot(tmr_pool, odp_timeout_timer(odp_timeout_from_event(ev)),
					  ev, res_ns, stats);
			++stats->num_miss;
			continue;
		}

		for (uint32_t i = 0U; i < num_boot_tmr; ++i) {
			time = &worker->cancel.tmrs[i];
			ret = odp_timer_cancel(time->tmr, &ev);

			if (odp_unlikely(ret == ODP_TIMER_TOO_NEAR))
				continue;

			if (odp_unlikely(ret == ODP_TIMER_FAIL))
				ODPH_ABORT("Error cancelling timer, aborting (tmr: %" PRIx64 ")\n",
					   odp_timer_to_u64(time->tmr));

			time->is_running = false;
			++stats->num_tmo;
		}

		for (uint32_t i = 0U; i < num_boot_tmr; ++i) {
			time = &worker->cancel.tmrs[i];

			if (time->is_running)
				continue;

			start_single_shot(tmr_pool, time->tmr, odp_timeout_to_event(time->tmo),
					  res_ns, stats);
			time->is_running = true;
		}
	}

	stats->tot_tm = odp_time_diff_ns(odp_time_local_strict(), tm);
	odp_barrier_wait(&config->term_barrier);

	while (true) {
		ev = odp_schedule(NULL, odp_schedule_wait_time(stats->max_mul * res_ns *
							       WAIT_MULTIPLIER));

		if (ev == ODP_EVENT_INVALID)
			break;

		tmr = odp_timeout_timer(odp_timeout_from_event(ev));
		odp_event_free(ev);
		(void)odp_timer_free(tmr);
	}

	return 0;
}

static odp_bool_t setup_workers(prog_config_t *config)
{
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_params[config->opts.num_workers], *thr_param;
	worker_config_t *worker;
	const uint32_t mode = config->opts.mode;
	int (*start_fn)(void *) = mode == SINGLE_SHOT ? process_single_shot :
					mode == PERIODIC ? process_periodic : process_cancel;

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = config->odp_instance;
	thr_common.cpumask = &config->worker_mask;

	for (uint32_t i = 0; i < config->opts.num_workers; ++i) {
		thr_param = &thr_params[i];
		worker = &config->worker_config[i];
		odph_thread_param_init(thr_param);
		thr_param->start = start_fn;
		thr_param->thr_type = ODP_THREAD_WORKER;
		thr_param->arg = worker;
	}

	if ((uint32_t)odph_thread_create(config->thread_tbl, &thr_common, thr_params,
					 config->opts.num_workers) != config->opts.num_workers) {
		ODPH_ERR("Error configuring worker threads\n");
		return false;
	}

	return true;
}

static odp_bool_t setup_test(prog_config_t *config)
{
	return setup_config(config) && setup_workers(config);
}

static void run_control(prog_config_t *config)
{
	const uint32_t time_sec = config->opts.time_sec;
	odp_atomic_u32_t *is_running = &config->is_running;

	odp_barrier_wait(&config->init_barrier);

	if (time_sec > 0U) {
		sleep(time_sec);
		odp_atomic_store_u32(is_running, 0U);
	} else {
		while (odp_atomic_load_u32(is_running))
			sleep(1U);
	}

	odp_barrier_wait(&config->term_barrier);
	(void)odph_thread_join(config->thread_tbl, config->opts.num_workers);
}

static void print_humanised(uint64_t value)
{
	if (value > GIGAS)
		printf("%.2f GOPS\n", (double)value / GIGAS);
	else if (value > MEGAS)
		printf("%.2f MOPS\n", (double)value / MEGAS);
	else if (value > KILOS)
		printf("%.2f kOPS\n", (double)value / KILOS);
	else
		printf("%" PRIu64 " OPS\n", value);
}

static void print_stats(const prog_config_t *config)
{
	const stats_t *stats;
	const opts_t *opts = &config->opts;
	uint64_t tot_tmo = 0U, tot_miss = 0U, tot_retry = 0U, max_mul = 0U, rate, tot_rate = 0U;

	printf("=====================\n\n"
	       "" PROG_NAME " done\n\n"
	       "  mode:             %s\n"
	       "  clock source:     %d\n"
	       "  resolution:       %" PRIu64 " ns\n"
	       "  number of timers: %u (%s)\n\n", opts->mode == SINGLE_SHOT ? "single shot" :
							opts->mode == PERIODIC ?
							    "periodic" : "single shot with cancel",
	       opts->clk_src, opts->res_ns, opts->num_tmr,
	       opts->policy == SHARED_TMR ? "shared" : "private");

	for (uint32_t i = 0U; i < config->opts.num_workers; ++i) {
		stats = &config->worker_config[i].stats;
		tot_tmo += stats->num_tmo;
		tot_miss += stats->num_miss;
		tot_retry += stats->num_retry;
		max_mul = ODPH_MAX(max_mul, stats->max_mul);
		rate = stats->num_tmo / ((double)stats->tot_tm / ODP_TIME_SEC_IN_NS);
		tot_rate += rate;

		printf("  worker %u:\n"
		       "    %s%" PRIu64 "\n"
		       "    number of retries:  %" PRIu64 "\n", i,
		       opts->mode == SINGLE_SHOT || opts->mode == PERIODIC ?
			"number of timeouts: " : "number of cancels:  ",
		       stats->num_tmo, stats->num_retry);

		if (opts->mode == SINGLE_SHOT || opts->mode == CANCEL) {
			if (opts->mode == CANCEL)
				printf("    number of misses:   %" PRIu64 "\n", stats->num_miss);

			printf("    max start mul:      %" PRIu64 "\n", stats->max_mul);
		}

		printf("    runtime:            %" PRIu64 " ns\n"
		       "    rate:               ", stats->tot_tm);
		print_humanised(rate);
		printf("\n");
	}

	printf("  total:\n"
	       "    %s%" PRIu64 "\n", opts->mode == SINGLE_SHOT || opts->mode == PERIODIC ?
					"number of timeouts: " : "number of cancels:  ",
	       tot_tmo);

	if (opts->mode == SINGLE_SHOT || opts->mode == CANCEL) {
		if (opts->mode == CANCEL)
			printf("    number of misses:   %" PRIu64 "\n", tot_miss);

		printf("    number of retries:  %" PRIu64 "\n"
		       "    max start mul:      %" PRIu64 "\n", tot_retry, max_mul);
	}

	printf("    rate:               ");
	print_humanised(tot_rate);
	printf("\n=====================\n");
}

static void teardown(const prog_config_t *config)
{
	const opts_t *opts = &config->opts;
	const worker_config_t *worker;

	for (uint32_t i = 0U; i < opts->num_workers; ++i) {
		worker = &config->worker_config[i];

		if (worker->scd.q != ODP_QUEUE_INVALID)
			(void)odp_queue_destroy(worker->scd.q);

		if (worker->scd.grp != ODP_SCHED_GROUP_INVALID)
			(void)odp_schedule_group_destroy(worker->scd.grp);
	}

	if (config->cancel_shm != ODP_SHM_INVALID)
		(void)odp_shm_free(config->cancel_shm);

	if (config->tmr_pool != ODP_TIMER_POOL_INVALID)
		(void)odp_timer_pool_destroy(config->tmr_pool);

	if (config->tmo_pool != ODP_POOL_INVALID)
		(void)odp_pool_destroy(config->tmo_pool);
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

	if (odph_options(&odph_opts) == -1)
		ODPH_ABORT("Error while reading ODP helper options, aborting\n");

	odp_init_param_init(&init_param);
	init_param.mem_model = odph_opts.mem_model;

	if (odp_init_global(&odp_instance, &init_param, NULL))
		ODPH_ABORT("ODP global init failed, aborting\n");

	if (odp_init_local(odp_instance, ODP_THREAD_CONTROL))
		ODPH_ABORT("ODP local init failed, aborting\n");

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
	print_stats(prog_conf);

out:
	teardown(prog_conf);

	if (shm_cfg != ODP_SHM_INVALID)
		(void)odp_shm_free(shm_cfg);

	if (odp_term_local())
		ODPH_ABORT("ODP local terminate failed, aborting\n");

	if (odp_term_global(odp_instance))
		ODPH_ABORT("ODP global terminate failed, aborting\n");

	return ret;
}

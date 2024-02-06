/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

/**
 * @example odp_pool_latency.c
 *
 * Pool latency tester. Allocate from different kind of pools with a varying set of configurations
 * and record latencies.
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define PROG_NAME "odp_pool_latency"
#define DELIMITER ","
#define ALLOC '+'
#define FREE '-'
#define TOP 't'
#define BOTTOM 'b'
#define DELAY 'd'

enum {
	BUFFER = 0U,
	PACKET,
	TMO,
	VECTOR
};

enum {
	SINGLE = 0U,
	MANY
};

#define DEF_ALLOC 1U
#define DEF_FREE 1U
#define DEF_DIR TOP
#define DEF_TYPE BUFFER
#define DEF_CNT 32768U
#define DEF_SIZE 1024U
#define DEF_POLICY MANY
#define DEF_ROUNDS 100000U
#define DEF_IGNORE 0U
#define DEF_WORKERS 1U
#define DEF_UA_SIZE 0U

#define MAX_PATTERN_LEN 32U
#define MAX_WORKERS ((uint32_t)(ODP_THREAD_COUNT_MAX - 1))
#define MAX_RETRIES 10U

#define COND_MIN(a, b) ((a) > 0U ? ODPH_MIN((a), (b)) : (b))
#define UA_DATA 0xAA

ODP_STATIC_ASSERT(MAX_PATTERN_LEN < UINT8_MAX, "Too long pattern length");

typedef struct {
	uint32_t num_evs_buf;
	uint32_t num_evs_pkt;
	uint32_t num_evs_tmo;
	uint32_t num_evs_vec;
	uint32_t data_size_buf;
	uint32_t data_size_pkt;
	uint32_t data_size_vec;
	uint32_t cache_size_buf;
	uint32_t cache_size_pkt;
	uint32_t cache_size_tmo;
	uint32_t cache_size_vec;
} dynamic_defs_t;

typedef enum {
	PRS_OK,
	PRS_NOK,
	PRS_TERM
} parse_result_t;

typedef struct {
	uint64_t tot_tm;
	uint64_t alloc_tm;
	uint64_t max_alloc_tm;
	uint64_t min_alloc_tm;
	uint64_t max_alloc_rnd;
	uint64_t min_alloc_rnd;
	uint64_t alloc_cnt;
	uint64_t alloc_b_cnt;
	uint64_t uarea_tm;
	uint64_t max_uarea_tm;
	uint64_t min_uarea_tm;
	uint64_t max_uarea_rnd;
	uint64_t min_uarea_rnd;
	uint64_t free_tm;
	uint64_t max_free_tm;
	uint64_t min_free_tm;
	uint64_t max_free_rnd;
	uint64_t min_free_rnd;
	uint64_t free_b_cnt;
	uint64_t reallocs;
	uint64_t alloc_errs;
	uint64_t pattern_errs;
	uint8_t max_alloc_pt;
	uint8_t min_alloc_pt;
	uint8_t max_uarea_pt;
	uint8_t min_uarea_pt;
	uint8_t max_free_pt;
	uint8_t min_free_pt;
} stats_t;

typedef struct {
	uint32_t val;
	uint8_t op;
	uint8_t opt;
} alloc_elem_t;

typedef struct prog_config_s prog_config_t;

typedef struct ODP_ALIGNED_CACHE {
	stats_t stats;
	odp_pool_t pool;
	void *data;
	prog_config_t *prog_config;
	odp_shm_t shm;
	uint32_t data_size;
	uint32_t uarea_size;
} worker_config_t;

typedef uint32_t (*alloc_fn_t)(worker_config_t *config, void *data, uint32_t idx, uint32_t num,
			       uint64_t round, uint8_t pattern, odp_bool_t is_saved);
typedef void (*free_fn_t)(void *data, uint32_t idx, uint32_t num, stats_t *stats,
			  uint64_t round, uint8_t pattern, odp_bool_t is_saved);

typedef struct prog_config_s {
	odph_thread_t thread_tbl[MAX_WORKERS];
	worker_config_t worker_config[MAX_WORKERS];
	alloc_elem_t alloc_elems[MAX_PATTERN_LEN];
	dynamic_defs_t dyn_defs;
	odp_instance_t odp_instance;
	odp_cpumask_t worker_mask;
	odp_barrier_t init_barrier;
	odp_barrier_t term_barrier;
	alloc_fn_t alloc_fn;
	free_fn_t free_fn;
	int64_t cache_size;
	uint32_t num_data_elems;
	uint32_t seg_len;
	uint32_t handle_size;
	uint32_t num_evs;
	uint32_t data_size;
	uint32_t num_rounds;
	uint32_t num_ignore;
	uint32_t num_workers;
	uint32_t uarea_size;
	uint8_t num_elems;
	uint8_t type;
	uint8_t policy;
} prog_config_t;

static prog_config_t *prog_conf;

static void init_config(prog_config_t *config)
{
	alloc_elem_t *alloc_elem;
	odp_pool_capability_t capa;
	odp_pool_param_t param;
	worker_config_t *worker;

	memset(config, 0, sizeof(*config));
	alloc_elem = &config->alloc_elems[0];
	alloc_elem->val = DEF_ALLOC;
	alloc_elem->op = ALLOC;
	alloc_elem = &config->alloc_elems[1];
	alloc_elem->val = DEF_FREE;
	alloc_elem->op = FREE;
	alloc_elem->opt = DEF_DIR;
	config->num_elems = 2U;

	if (odp_pool_capability(&capa) == 0) {
		config->dyn_defs.num_evs_buf = COND_MIN(capa.buf.max_num, DEF_CNT);
		config->dyn_defs.num_evs_pkt = COND_MIN(capa.pkt.max_num, DEF_CNT);
		config->dyn_defs.num_evs_tmo = COND_MIN(capa.tmo.max_num, DEF_CNT);
		config->dyn_defs.num_evs_vec = COND_MIN(capa.vector.max_num, DEF_CNT);
		config->dyn_defs.data_size_buf = COND_MIN(capa.buf.max_size, DEF_SIZE);
		config->dyn_defs.data_size_pkt = COND_MIN(capa.pkt.max_len, DEF_SIZE);
		config->dyn_defs.data_size_vec = COND_MIN(capa.vector.max_size, DEF_SIZE);
		odp_pool_param_init(&param);
		config->dyn_defs.cache_size_buf = param.buf.cache_size;
		config->dyn_defs.cache_size_pkt = param.pkt.cache_size;
		config->dyn_defs.cache_size_tmo = param.tmo.cache_size;
		config->dyn_defs.cache_size_vec = param.vector.cache_size;
	}

	config->cache_size = -1;
	config->num_rounds = DEF_ROUNDS;
	config->num_ignore = DEF_IGNORE;
	config->num_workers = DEF_WORKERS;
	config->uarea_size = DEF_UA_SIZE;
	config->type = DEF_TYPE;
	config->policy = DEF_POLICY;

	for (uint32_t i = 0U; i < MAX_WORKERS; ++i) {
		worker = &config->worker_config[i];
		worker->stats.min_alloc_tm = UINT64_MAX;
		worker->stats.min_uarea_tm = UINT64_MAX;
		worker->stats.min_free_tm = UINT64_MAX;
		worker->pool = ODP_POOL_INVALID;
		worker->shm = ODP_SHM_INVALID;
	}
}

static void parse_burst_pattern(prog_config_t *config, const char *optarg)
{
	char *tmp_str = strdup(optarg), *tmp, op, opt;
	uint8_t num_elems = 0U;
	alloc_elem_t *elem;
	uint32_t val;
	int ret;

	if (tmp_str == NULL)
		return;

	tmp = strtok(tmp_str, DELIMITER);

	while (tmp && num_elems < MAX_PATTERN_LEN) {
		elem = &config->alloc_elems[num_elems];
		ret = sscanf(tmp, "%c%u%c", &op, &val, &opt);

		if (ret == 2 || ret == 3) {
			if (op == ALLOC || (op == FREE && (opt == TOP || opt == BOTTOM)) ||
			    op == DELAY) {
				if (op == FREE)
					elem->opt = opt;

				elem->val = val;
				elem->op = op;
				++num_elems;
			}
		}

		tmp = strtok(NULL, DELIMITER);
	}

	free(tmp_str);
	config->num_elems = num_elems;
}

static void print_usage(const dynamic_defs_t *dyn_defs)
{
	printf("\n"
	       "Pool latency tester. Allocate from different kind of pools with a varying set of\n"
	       "configurations and record latencies.\n"
	       "\n"
	       "Usage: " PROG_NAME " [OPTIONS]\n");
	printf("\n"
	       "  E.g. " PROG_NAME "\n"
	       "       " PROG_NAME " -b %c7" DELIMITER "%c1%c" DELIMITER "%c3" DELIMITER "%c9%c\n",
	       ALLOC, FREE, TOP, ALLOC, FREE, BOTTOM);
	printf("       " PROG_NAME " -b %c10" DELIMITER "%c1000" DELIMITER "%c10%c -t 1 -d 2048 "
	       "-p 0 -w 64\n", ALLOC, DELAY, FREE, TOP);
	printf("\n"
	       "Optional OPTIONS:\n"
	       "\n"
	       "  -b, --burst_pattern Burst pattern for allocations, frees and delays per round,\n"
	       "                      delimited by '%s', no spaces. Allocations are indicated\n"
	       "                      with a '%c' prefix, frees with a '%c' prefix. The location\n"
	       "                      of frees are indicated from the top of a previously\n"
	       "                      allocated array of events with a '%c' suffix and from the\n"
	       "                      bottom with a '%c' suffix. Delays are indicated with a\n"
	       "                      '%c' prefix, followed by a delay in nanoseconds.\n"
	       "                      Allocations and frees should be equal in the aggregate and\n"
	       "                      frees should never outnumber allocations at any instant.\n"
	       "                      '%c%u%s%c%u%c' by default. Maximum pattern length is %u.\n"
	       "  -t, --type          Pool type. %u by default.\n"
	       "                          0: buffer\n"
	       "                          1: packet\n"
	       "                          2: timeout\n"
	       "                          3: vector\n"
	       "  -e, --event_count   Number of events. Defaults:\n"
	       "                          buffer:  %u\n"
	       "                          packet:  %u\n"
	       "                          timeout: %u\n"
	       "                          vector:  %u\n"
	       "  -d, --data_size     Data size in bytes, ignored in case of timeout pools, with\n"
	       "                      vector pools, defines the vector size.\n"
	       "                      Defaults:\n"
	       "                          buffer: %u\n"
	       "                          packet: %u\n"
	       "                          vector: %u\n"
	       "  -p, --policy        Pool allocation policy. %u by default.\n"
	       "                      Policies:\n"
	       "                          0: One pool shared by workers\n"
	       "                          1: One pool per worker\n"
	       "  -r, --round_count   Number of rounds to run. %u by default.\n"
	       "  -i, --ignore_rounds Ignore an amount of initial rounds. %u by default.\n"
	       "  -c, --worker_count  Number of workers. %u by default.\n"
	       "  -C, --cache_size    Maximum cache size for pools. Defaults:\n"
	       "                          buffer:  %u\n"
	       "                          packet:  %u\n"
	       "                          timeout: %u\n"
	       "                          vector:  %u\n"
	       "  -w, --write_uarea   Write data to allocated event user areas. 0 bytes disables\n"
	       "                      user area write. %u by default.\n"
	       "  -h, --help          This help.\n"
	       "\n", DELIMITER, ALLOC, FREE, TOP, BOTTOM, DELAY, ALLOC, DEF_ALLOC, DELIMITER, FREE,
	       DEF_FREE, DEF_DIR, MAX_PATTERN_LEN, DEF_TYPE, dyn_defs->num_evs_buf,
	       dyn_defs->num_evs_pkt, dyn_defs->num_evs_tmo, dyn_defs->num_evs_vec,
	       dyn_defs->data_size_buf, dyn_defs->data_size_pkt, dyn_defs->data_size_vec,
	       DEF_POLICY, DEF_ROUNDS, DEF_IGNORE, DEF_WORKERS, dyn_defs->cache_size_buf,
	       dyn_defs->cache_size_pkt, dyn_defs->cache_size_tmo, dyn_defs->cache_size_vec,
	       DEF_UA_SIZE);
}

static parse_result_t check_options(prog_config_t *config)
{
	odp_pool_capability_t pool_capa;
	uint32_t max_workers, num_pools;
	alloc_elem_t *elem;
	int64_t num_tot = 0;
	odp_shm_capability_t shm_capa;
	uint64_t shm_size;

	if (config->type != BUFFER && config->type != PACKET && config->type != TMO &&
	    config->type != VECTOR) {
		ODPH_ERR("Invalid pool type: %u\n", config->type);
		return PRS_NOK;
	}

	if (odp_pool_capability(&pool_capa) < 0) {
		ODPH_ERR("Error querying pool capabilities\n");
		return PRS_NOK;
	}

	max_workers = ODPH_MIN(MAX_WORKERS, (uint32_t)odp_cpumask_default_worker(NULL, 0));

	if (config->num_workers == 0U || config->num_workers > max_workers) {
		ODPH_ERR("Invalid worker count: %u (min: 1, max: %u)\n", config->num_workers,
			 max_workers);
		return PRS_NOK;
	}

	(void)odp_cpumask_default_worker(&config->worker_mask, config->num_workers);
	num_pools = config->policy == SINGLE ? 1U : config->num_workers;

	if (config->type == BUFFER) {
		if (config->num_evs == 0U)
			config->num_evs = config->dyn_defs.num_evs_buf;

		if (config->data_size == 0U)
			config->data_size = config->dyn_defs.data_size_buf;

		if (config->cache_size == -1)
			config->cache_size = config->dyn_defs.cache_size_buf;

		if (config->num_evs > pool_capa.buf.max_num) {
			ODPH_ERR("Invalid event count: %u (max: %u)\n", config->num_evs,
				 pool_capa.buf.max_num);
			return PRS_NOK;
		}

		if (config->data_size > pool_capa.buf.max_size) {
			ODPH_ERR("Invalid data size: %u (max: %u)\n", config->data_size,
				 pool_capa.buf.max_size);
			return PRS_NOK;
		}

		if (config->cache_size < pool_capa.buf.min_cache_size ||
		    config->cache_size > pool_capa.buf.max_cache_size) {
			ODPH_ERR("Invalid cache size: %" PRIi64 " (min: %u, max: %u)\n",
				 config->cache_size, pool_capa.buf.min_cache_size,
				 pool_capa.buf.max_cache_size);
			return PRS_NOK;
		}

		if (num_pools > pool_capa.buf.max_pools) {
			ODPH_ERR("Invalid pool count: %u (max: %u)\n", num_pools,
				 pool_capa.buf.max_pools);
			return PRS_NOK;
		}

		config->handle_size = sizeof(odp_buffer_t);
		config->uarea_size = ODPH_MIN(config->uarea_size, pool_capa.buf.max_uarea_size);
	} else if (config->type == PACKET) {
		if (config->num_evs == 0U)
			config->num_evs = config->dyn_defs.num_evs_pkt;

		if (config->data_size == 0U)
			config->data_size = config->dyn_defs.data_size_pkt;

		if (config->cache_size == -1)
			config->cache_size = config->dyn_defs.cache_size_pkt;

		if (config->num_evs > pool_capa.pkt.max_num) {
			ODPH_ERR("Invalid event count: %u (max: %u)\n", config->num_evs,
				 pool_capa.pkt.max_num);
			return PRS_NOK;
		}

		if (config->data_size > pool_capa.pkt.max_len) {
			ODPH_ERR("Invalid data size: %u (max: %u)\n", config->data_size,
				 pool_capa.pkt.max_len);
			return PRS_NOK;
		}

		if (config->cache_size < pool_capa.pkt.min_cache_size ||
		    config->cache_size > pool_capa.pkt.max_cache_size) {
			ODPH_ERR("Invalid cache size: %" PRIi64 " (min: %u, max: %u)\n",
				 config->cache_size, pool_capa.pkt.min_cache_size,
				 pool_capa.pkt.max_cache_size);
			return PRS_NOK;
		}

		if (num_pools > pool_capa.pkt.max_pools) {
			ODPH_ERR("Invalid pool count: %u (max: %u)\n", num_pools,
				 pool_capa.pkt.max_pools);
			return PRS_NOK;
		}

		config->seg_len = pool_capa.pkt.max_seg_len > config->data_size ?
					config->data_size : pool_capa.pkt.max_seg_len;
		config->handle_size = sizeof(odp_packet_t);
		config->uarea_size = ODPH_MIN(config->uarea_size, pool_capa.pkt.max_uarea_size);
	} else if (config->type == TMO) {
		if (config->num_evs == 0U)
			config->num_evs = config->dyn_defs.num_evs_tmo;

		if (config->cache_size == -1)
			config->cache_size = config->dyn_defs.cache_size_tmo;

		if (config->num_evs > pool_capa.tmo.max_num) {
			ODPH_ERR("Invalid event count: %u (max: %u)\n", config->num_evs,
				 pool_capa.tmo.max_num);
			return PRS_NOK;
		}

		if (config->cache_size < pool_capa.tmo.min_cache_size ||
		    config->cache_size > pool_capa.tmo.max_cache_size) {
			ODPH_ERR("Invalid cache size: %" PRIi64 " (min: %u, max: %u)\n",
				 config->cache_size, pool_capa.tmo.min_cache_size,
				 pool_capa.tmo.max_cache_size);
			return PRS_NOK;
		}

		if (num_pools > pool_capa.tmo.max_pools) {
			ODPH_ERR("Invalid pool count: %u (max: %u)\n", num_pools,
				 pool_capa.tmo.max_pools);
			return PRS_NOK;
		}

		config->handle_size = sizeof(odp_timeout_t);
		config->uarea_size = ODPH_MIN(config->uarea_size, pool_capa.tmo.max_uarea_size);
	} else {
		if (config->num_evs == 0U)
			config->num_evs = config->dyn_defs.num_evs_vec;

		if (config->data_size == 0U)
			config->data_size = config->dyn_defs.data_size_vec;

		if (config->cache_size == -1)
			config->cache_size = config->dyn_defs.cache_size_vec;

		if (config->num_evs > pool_capa.vector.max_num) {
			ODPH_ERR("Invalid event count: %u (max: %u)\n", config->num_evs,
				 pool_capa.vector.max_num);
			return PRS_NOK;
		}

		if (config->data_size > pool_capa.vector.max_size) {
			ODPH_ERR("Invalid vector size: %u (max: %u)\n", config->data_size,
				 pool_capa.vector.max_size);
			return PRS_NOK;
		}

		if (config->cache_size < pool_capa.vector.min_cache_size ||
		    config->cache_size > pool_capa.vector.max_cache_size) {
			ODPH_ERR("Invalid cache size: %" PRIi64 " (min: %u, max: %u)\n",
				 config->cache_size, pool_capa.vector.min_cache_size,
				 pool_capa.vector.max_cache_size);
			return PRS_NOK;
		}

		if (num_pools > pool_capa.vector.max_pools) {
			ODPH_ERR("Invalid pool count: %u (max: %u)\n", num_pools,
				 pool_capa.vector.max_pools);
			return PRS_NOK;
		}

		config->handle_size = sizeof(odp_packet_vector_t);
		config->uarea_size = ODPH_MIN(config->uarea_size, pool_capa.vector.max_uarea_size);
	}

	if (config->num_elems == 0U) {
		ODPH_ERR("Invalid burst pattern, no elements\n");
		return PRS_NOK;
	}

	for (uint8_t i = 0U; i < config->num_elems; ++i) {
		elem = &config->alloc_elems[i];

		if (elem->op == ALLOC)
			num_tot += elem->val;
		else if (elem->op == FREE)
			num_tot -= elem->val;

		if (num_tot < 0) {
			ODPH_ERR("Invalid burst pattern, frees exceed allocations "
				 "instantaneously\n");
			return PRS_NOK;
		}

		config->num_data_elems += (elem->op == ALLOC ? elem->val : 0U);
	}

	if (num_tot != 0) {
		ODPH_ERR("Invalid burst pattern, cumulative sum not zero: %" PRId64 "\n", num_tot);
		return PRS_NOK;
	}

	if (odp_shm_capability(&shm_capa) < 0) {
		ODPH_ERR("Error querying SHM capabilities\n");
		return PRS_NOK;
	}

	if (shm_capa.max_blocks < config->num_workers + 1U) {
		ODPH_ERR("Invalid amount of SHM blocks: %u (max: %u)\n", config->num_workers + 1U,
			 shm_capa.max_blocks);
		return PRS_NOK;
	}

	shm_size = (uint64_t)config->num_data_elems * config->handle_size;

	if (shm_capa.max_size != 0U && shm_size > shm_capa.max_size) {
		ODPH_ERR("Invalid total SHM block size: %" PRIu64 " (max: %" PRIu64 ")\n",
			 shm_size, shm_capa.max_size);
		return PRS_NOK;
	}

	if (config->policy != SINGLE && config->policy != MANY) {
		ODPH_ERR("Invalid pool policy: %u\n", config->policy);
		return PRS_NOK;
	}

	if (config->num_rounds == 0U) {
		ODPH_ERR("Invalid round count: %u (min: 1)\n", config->num_rounds);
		return PRS_NOK;
	}

	if (config->num_ignore >= config->num_rounds) {
		ODPH_ERR("Invalid round ignorance count: %u (max: %u)\n", config->num_ignore,
			 config->num_rounds - 1U);
		return PRS_NOK;
	}

	return PRS_OK;
}

static parse_result_t parse_options(int argc, char **argv, prog_config_t *config)
{
	int opt, long_index;

	static const struct option longopts[] = {
		{ "burst_pattern", required_argument, NULL, 'b' },
		{ "type", required_argument, NULL, 't' },
		{ "event_count", required_argument, NULL, 'e' },
		{ "data_size", required_argument, NULL, 'd' },
		{ "policy", required_argument, NULL, 'p' },
		{ "round_count", required_argument, NULL, 'r' },
		{ "ignore_rounds", required_argument, NULL, 'i' },
		{ "worker_count", required_argument, NULL, 'c' },
		{ "cache_size", required_argument, NULL, 'C' },
		{ "write_uarea", required_argument, NULL, 'w' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "b:t:e:d:p:r:i:c:C:w:h";

	init_config(config);

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'b':
			parse_burst_pattern(config, optarg);
			break;
		case 't':
			config->type = atoi(optarg);
			break;
		case 'e':
			config->num_evs = atoi(optarg);
			break;
		case 'd':
			config->data_size = atoi(optarg);
			break;
		case 'p':
			config->policy = atoi(optarg);
			break;
		case 'r':
			config->num_rounds = atoi(optarg);
			break;
		case 'i':
			config->num_ignore = atoi(optarg);
			break;
		case 'c':
			config->num_workers = atoi(optarg);
			break;
		case 'C':
			config->cache_size = atoi(optarg);
			break;
		case 'w':
			config->uarea_size = atoi(optarg);
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

static inline void save_alloc_stats(odp_time_t t1, odp_time_t t2, uint32_t num_alloc,
				    uint64_t round, uint8_t pattern, stats_t *stats)
{
	const uint64_t tm_diff = odp_time_diff_ns(t2, t1);

	stats->alloc_tm += tm_diff;
	stats->alloc_cnt += num_alloc;
	++stats->alloc_b_cnt;

	if (tm_diff > stats->max_alloc_tm) {
		stats->max_alloc_tm = tm_diff;
		stats->max_alloc_rnd = round;
		stats->max_alloc_pt = pattern;
	}

	if (tm_diff < stats->min_alloc_tm) {
		stats->min_alloc_tm = tm_diff;
		stats->min_alloc_rnd = round;
		stats->min_alloc_pt = pattern;
	}
}

static inline void write_to_uarea(uint8_t *data, uint32_t size)
{
	memset(data, UA_DATA, size);
}

static inline void save_uarea_stats(odp_time_t t1, odp_time_t t2, uint64_t round, uint8_t pattern,
				    stats_t *stats)
{
	const uint64_t tm_diff = odp_time_diff_ns(t2, t1);

	stats->uarea_tm += tm_diff;

	if (tm_diff > stats->max_uarea_tm) {
		stats->max_uarea_tm = tm_diff;
		stats->max_uarea_rnd = round;
		stats->max_uarea_pt = pattern;
	}

	if (tm_diff < stats->min_uarea_tm) {
		stats->min_uarea_tm = tm_diff;
		stats->min_uarea_rnd = round;
		stats->min_uarea_pt = pattern;
	}
}

static inline void save_free_stats(odp_time_t t1, odp_time_t t2, uint64_t round, uint8_t pattern,
				   stats_t *stats)
{
	const uint64_t tm_diff = odp_time_diff_ns(t2, t1);

	stats->free_tm += tm_diff;
	++stats->free_b_cnt;

	if (tm_diff > stats->max_free_tm) {
		stats->max_free_tm = tm_diff;
		stats->max_free_rnd = round;
		stats->max_free_pt = pattern;
	}

	if (tm_diff < stats->min_free_tm) {
		stats->min_free_tm = tm_diff;
		stats->min_free_rnd = round;
		stats->min_free_pt = pattern;
	}

	stats->max_free_tm = ODPH_MAX(tm_diff, stats->max_free_tm);
	stats->min_free_tm = ODPH_MIN(tm_diff, stats->min_free_tm);
}

static uint32_t allocate_buffers(worker_config_t *config, void *data, uint32_t idx, uint32_t num,
				 uint64_t round, uint8_t pattern, odp_bool_t is_saved)
{
	odp_time_t t1, t2;
	odp_pool_t pool = config->pool;
	uint32_t retries = MAX_RETRIES;
	odp_buffer_t *bufs = &((odp_buffer_t *)data)[idx];
	uint32_t num_alloc, num_tot = 0U;
	int ret;
	stats_t *stats = &config->stats;

	while (retries-- > 0U && num_tot < num) {
		num_alloc = num - num_tot;
		t1 = odp_time_local_strict();
		ret = odp_buffer_alloc_multi(pool, &bufs[num_tot], num_alloc);
		t2 = odp_time_local_strict();

		if (odp_unlikely(ret < 0)) {
			++stats->alloc_errs;
			break;
		}

		if (odp_unlikely((uint32_t)ret < num_alloc))
			++stats->reallocs;

		num_tot += ret;

		if (odp_likely(is_saved))
			save_alloc_stats(t1, t2, ret, round, pattern, stats);
	}

	if (config->uarea_size > 0U) {
		t1 = odp_time_local_strict();

		for (uint32_t i = 0U; i < num_tot; ++i)
			write_to_uarea(odp_buffer_user_area(bufs[i]), config->uarea_size);

		t2 = odp_time_local_strict();

		if (odp_likely(is_saved))
			save_uarea_stats(t1, t2, round, pattern, stats);
	}

	return num_tot;
}

static void free_buffers(void *data, uint32_t idx, uint32_t num, stats_t *stats, uint64_t round,
			 uint8_t pattern, odp_bool_t is_saved)
{
	odp_time_t t1, t2;
	odp_buffer_t *bufs = &((odp_buffer_t *)data)[idx];

	t1 = odp_time_local_strict();
	odp_buffer_free_multi(bufs, num);
	t2 = odp_time_local_strict();

	if (odp_likely(is_saved))
		save_free_stats(t1, t2, round, pattern, stats);
}

static uint32_t allocate_packets(worker_config_t *config, void *data, uint32_t idx, uint32_t num,
				 uint64_t round, uint8_t pattern, odp_bool_t is_saved)
{
	odp_time_t t1, t2;
	odp_pool_t pool = config->pool;
	uint32_t retries = MAX_RETRIES, data_size = config->data_size;
	odp_packet_t *pkts = &((odp_packet_t *)data)[idx];
	uint32_t num_alloc, num_tot = 0U;
	int ret;
	stats_t *stats = &config->stats;

	while (retries-- > 0U && num_tot < num) {
		num_alloc = num - num_tot;
		t1 = odp_time_local_strict();
		ret = odp_packet_alloc_multi(pool, data_size, &pkts[num_tot], num_alloc);
		t2 = odp_time_local_strict();

		if (odp_unlikely(ret < 0)) {
			++stats->alloc_errs;
			break;
		}

		if (odp_unlikely((uint32_t)ret < num_alloc))
			++stats->reallocs;

		num_tot += ret;

		if (odp_likely(is_saved))
			save_alloc_stats(t1, t2, ret, round, pattern, stats);
	}

	if (config->uarea_size > 0U) {
		t1 = odp_time_local_strict();

		for (uint32_t i = 0U; i < num_tot; ++i)
			write_to_uarea(odp_packet_user_area(pkts[i]), config->uarea_size);

		t2 = odp_time_local_strict();

		if (odp_likely(is_saved))
			save_uarea_stats(t1, t2, round, pattern, stats);
	}

	return num_tot;
}

static void free_packets(void *data, uint32_t idx, uint32_t num, stats_t *stats, uint64_t round,
			 uint8_t pattern, odp_bool_t is_saved)
{
	odp_time_t t1, t2;
	odp_packet_t *pkts = &((odp_packet_t *)data)[idx];

	t1 = odp_time_local_strict();
	odp_packet_free_multi(pkts, num);
	t2 = odp_time_local_strict();

	if (odp_likely(is_saved))
		save_free_stats(t1, t2, round, pattern, stats);
}

static uint32_t allocate_timeouts(worker_config_t *config, void *data, uint32_t idx, uint32_t num,
				  uint64_t round, uint8_t pattern, odp_bool_t is_saved)
{
	odp_time_t t1, t2;
	odp_pool_t pool = config->pool;
	uint32_t retries = MAX_RETRIES;
	odp_timeout_t *tmos = &((odp_timeout_t *)data)[idx];
	uint32_t num_alloc, num_tot = 0U;
	int ret;
	stats_t *stats = &config->stats;

	while (retries-- > 0U && num_tot < num) {
		num_alloc = num - num_tot;
		t1 = odp_time_local_strict();
		ret = odp_timeout_alloc_multi(pool, &tmos[num_tot], num_alloc);
		t2 = odp_time_local_strict();

		if (odp_unlikely(ret < 0)) {
			++stats->alloc_errs;
			break;
		}

		if (odp_unlikely((uint32_t)ret < num_alloc))
			++stats->reallocs;

		num_tot += ret;

		if (odp_likely(is_saved))
			save_alloc_stats(t1, t2, ret, round, pattern, stats);
	}

	if (config->uarea_size > 0U) {
		t1 = odp_time_local_strict();

		for (uint32_t i = 0U; i < num_tot; ++i)
			write_to_uarea(odp_timeout_user_area(tmos[i]), config->uarea_size);

		t2 = odp_time_local_strict();

		if (odp_likely(is_saved))
			save_uarea_stats(t1, t2, round, pattern, stats);
	}

	return num_tot;
}

static void free_timeouts(void *data, uint32_t idx, uint32_t num, stats_t *stats, uint64_t round,
			  uint8_t pattern, odp_bool_t is_saved)
{
	odp_time_t t1, t2;
	odp_timeout_t *tmos = &((odp_timeout_t *)data)[idx];

	t1 = odp_time_local_strict();
	odp_timeout_free_multi(tmos, num);
	t2 = odp_time_local_strict();

	if (odp_likely(is_saved))
		save_free_stats(t1, t2, round, pattern, stats);
}

static uint32_t allocate_vectors(worker_config_t *config, void *data, uint32_t idx, uint32_t num,
				 uint64_t round, uint8_t pattern, odp_bool_t is_saved)
{
	odp_time_t t1, t2;
	odp_pool_t pool = config->pool;
	uint32_t num_tot = 0U;
	odp_packet_vector_t *vecs = &((odp_packet_vector_t *)data)[idx], vec;
	stats_t *stats = &config->stats;

	t1 = odp_time_local_strict();

	for (uint32_t i = 0U; i < num; ++i) {
		vec = odp_packet_vector_alloc(pool);

		if (odp_unlikely(vec == ODP_PACKET_VECTOR_INVALID))
			break;

		vecs[num_tot++] = vec;
	}

	t2 = odp_time_local_strict();

	if (odp_unlikely(num_tot == 0))
		++stats->alloc_errs;
	else if (odp_likely(is_saved))
		save_alloc_stats(t1, t2, num_tot, round, pattern, stats);

	if (config->uarea_size > 0U) {
		t1 = odp_time_local_strict();

		for (uint32_t i = 0U; i < num_tot; ++i)
			write_to_uarea(odp_packet_vector_user_area(vecs[i]), config->uarea_size);

		t2 = odp_time_local_strict();

		if (odp_likely(is_saved))
			save_uarea_stats(t1, t2, round, pattern, stats);
	}

	return num_tot;
}

static void free_vectors(void *data, uint32_t idx, uint32_t num, stats_t *stats, uint64_t round,
			 uint8_t pattern, odp_bool_t is_saved)
{
	odp_time_t t1, t2;
	odp_packet_vector_t *vecs = &((odp_packet_vector_t *)data)[idx];

	t1 = odp_time_local_strict();

	for (uint32_t i = 0U; i < num; ++i)
		odp_packet_vector_free(vecs[i]);

	t2 = odp_time_local_strict();

	if (odp_likely(is_saved))
		save_free_stats(t1, t2, round, pattern, stats);
}

static odp_pool_t create_pool(const char *name, const odp_pool_param_t *params, uint8_t policy)
{
	static odp_pool_t pool = ODP_POOL_INVALID;

	if (policy == SINGLE && pool != ODP_POOL_INVALID)
		return pool;

	pool = odp_pool_create(name, params);

	return pool;
}

static odp_bool_t setup_worker_config(prog_config_t *config)
{
	odp_pool_param_t param;
	odp_pool_t pool;
	worker_config_t *worker;
	odp_shm_t shm;
	void *data;

	odp_pool_param_init(&param);

	if (config->type == BUFFER) {
		param.type = ODP_POOL_BUFFER;
		param.buf.num = config->num_evs;
		param.buf.size = config->data_size;
		param.buf.uarea_size = config->uarea_size;
		param.buf.cache_size = config->cache_size;
		config->alloc_fn = allocate_buffers;
		config->free_fn = free_buffers;
	} else if (config->type == PACKET) {
		param.type = ODP_POOL_PACKET;
		param.pkt.num = config->num_evs;
		param.pkt.len = config->data_size;
		param.pkt.seg_len = config->seg_len;
		param.pkt.uarea_size = config->uarea_size;
		param.pkt.cache_size = config->cache_size;
		config->alloc_fn = allocate_packets;
		config->free_fn = free_packets;
	} else if (config->type == TMO) {
		param.type = ODP_POOL_TIMEOUT;
		param.tmo.num = config->num_evs;
		param.tmo.uarea_size = config->uarea_size;
		param.tmo.cache_size = config->cache_size;
		config->alloc_fn = allocate_timeouts;
		config->free_fn = free_timeouts;
	} else {
		param.type = ODP_POOL_VECTOR;
		param.vector.num = config->num_evs;
		param.vector.max_size = config->data_size;
		param.vector.uarea_size = config->uarea_size;
		param.vector.cache_size = config->cache_size;
		config->alloc_fn = allocate_vectors;
		config->free_fn = free_vectors;
	}

	for (uint32_t i = 0U; i < config->num_workers; ++i) {
		pool = create_pool(PROG_NAME "_pool", &param, config->policy);

		if (pool == ODP_POOL_INVALID) {
			ODPH_ERR("Error creating worker pool\n");
			return false;
		}

		shm = odp_shm_reserve(PROG_NAME "_shm",
				      config->handle_size * config->num_data_elems,
				      ODP_CACHE_LINE_SIZE, 0U);

		if (shm == ODP_SHM_INVALID) {
			ODPH_ERR("Error creating worker SHM\n");
			return false;
		}

		data = odp_shm_addr(shm);

		if (data == NULL) {
			ODPH_ERR("Error resolving worker SHM\n");
			return false;
		}

		worker = &config->worker_config[i];
		worker->pool = pool;
		worker->data = data;
		worker->prog_config = config;
		worker->shm = shm;
		worker->data_size = config->data_size;
		worker->uarea_size = config->uarea_size;
	}

	return true;
}

static int run_test(void *args)
{
	worker_config_t *config = args;
	odp_time_t t1, t2;
	uint32_t head_idx, cur_idx, num_ignore = config->prog_config->num_ignore, val, num_alloc,
	idx;
	odp_bool_t is_saved;
	const uint8_t num_elems = config->prog_config->num_elems;
	const alloc_elem_t *elems = config->prog_config->alloc_elems, *elem;
	uint8_t op;
	void *data = config->data;
	const alloc_fn_t alloc_fn = config->prog_config->alloc_fn;
	stats_t *stats = &config->stats;
	const free_fn_t free_fn = config->prog_config->free_fn;

	odp_barrier_wait(&config->prog_config->init_barrier);
	t1 = odp_time_local_strict();

	for (uint32_t i = 0U; i < config->prog_config->num_rounds; ++i) {
		head_idx = 0U;
		cur_idx = head_idx;
		is_saved = (num_ignore > 0U ? num_ignore-- : num_ignore) == 0U;

		for (uint8_t j = 0U; j < num_elems; ++j) {
			elem = &elems[j];
			val = elem->val;
			op = elem->op;

			if (op == ALLOC) {
				num_alloc = alloc_fn(config, data, cur_idx, val, i, j, is_saved);

				if (odp_unlikely(num_alloc < val))
					++stats->pattern_errs;

				cur_idx += num_alloc;
			} else if (op == FREE) {
				/* Due to potential pattern errors, there might not be expected
				 * amount of freeable events. */
				val = ODPH_MIN(val, cur_idx - head_idx);

				if (elem->opt == TOP) {
					idx = head_idx;
					head_idx += val;
				} else {
					cur_idx -= val;
					idx = cur_idx;
				}

				free_fn(data, idx, val, stats, i, j, is_saved);
			} else {
				odp_time_wait_ns(val);
			}
		}
	}

	t2 = odp_time_local_strict();
	stats->tot_tm = odp_time_diff_ns(t2, t1);
	odp_barrier_wait(&config->prog_config->term_barrier);

	return 0;
}

static odp_bool_t setup_workers(prog_config_t *config)
{
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_params[config->num_workers], *thr_param;

	odp_barrier_init(&config->init_barrier, config->num_workers + 1);
	odp_barrier_init(&config->term_barrier, config->num_workers + 1);
	odph_thread_common_param_init(&thr_common);
	thr_common.instance = config->odp_instance;
	thr_common.cpumask = &config->worker_mask;

	for (uint32_t i = 0; i < config->num_workers; ++i) {
		thr_param = &thr_params[i];
		odph_thread_param_init(thr_param);
		thr_param->start = run_test;
		thr_param->thr_type = ODP_THREAD_WORKER;
		thr_param->arg = &config->worker_config[i];
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
	return setup_worker_config(config) && setup_workers(config);
}

static void stop_test(prog_config_t *config)
{
	odp_barrier_wait(&config->term_barrier);
	(void)odph_thread_join(config->thread_tbl, config->num_workers);
}

static void print_stats(const prog_config_t *config)
{
	const alloc_elem_t *elem;
	const stats_t *stats;
	uint64_t ev_rate, ave_b_alloc_tm, b_alloc_min, b_alloc_max, ave_b_free_tm, b_free_min,
	b_free_max, ave_alloc_tm, ave_free_tm, ave_ua_b_tm, b_ua_min, b_ua_max, ave_ua_tm,
	tot_b_alloc_tm = 0U, tot_b_free_tm = 0U, tot_alloc_tm = 0U, tot_free_tm = 0U,
	tot_alloc_min = 0U, tot_alloc_max = 0U, tot_free_min = 0U, tot_free_max = 0U,
	tot_b_ua_tm = 0U, tot_ua_tm = 0U, tot_ua_min = 0U, tot_ua_max = 0U;

	printf("\n==================\n\n"
	       "Pool latency test done\n\n"
	       "    type:         %s\n"
	       "    event count:  %u\n", config->type == BUFFER ? "buffer" :
		config->type == PACKET ? "packet" : config->type == TMO ? "timeout" : "vector",
	       config->num_evs);

	if (config->type != TMO)
		printf("    %s  %u\n", config->type != VECTOR ? "data size:  " : "vector size:",
		       config->data_size);

	printf("    pool policy:  %s\n"
	       "    round count:  %u\n"
	       "    ignore count: %u\n"
	       "    cache size:   %" PRIi64 "\n"
	       "    user area:    %u (B)\n"
	       "    burst pattern:\n", config->policy == SINGLE ? "shared" : "per-worker",
	       config->num_rounds, config->num_ignore, config->cache_size, config->uarea_size);

	for (uint8_t i = 0U; i < config->num_elems; ++i) {
		elem = &config->alloc_elems[i];
		printf("        %s %u%s\n", elem->op == ALLOC ? "allocate:" :
		       elem->op == FREE && elem->opt == TOP ? "free (t):" :
			elem->op == FREE && elem->opt == BOTTOM ? "free (b):" :
				"delay:   ", elem->val, elem->op == DELAY ? " (ns)" : "");
	}

	printf("\n");

	for (uint32_t i = 0U; i < config->num_workers; ++i) {
		stats = &config->worker_config[i].stats;
		ev_rate = stats->tot_tm > 0U ?
			(double)stats->alloc_cnt / stats->tot_tm * ODP_TIME_SEC_IN_NS : 0U;
		ave_b_alloc_tm = stats->alloc_b_cnt > 0U ?
			stats->alloc_tm / stats->alloc_b_cnt : 0U;
		b_alloc_min = ave_b_alloc_tm > 0U ? stats->min_alloc_tm : 0U;
		b_alloc_max = ave_b_alloc_tm > 0U ? stats->max_alloc_tm : 0U;
		ave_b_free_tm = stats->free_b_cnt > 0U ?
			stats->free_tm / stats->free_b_cnt : 0U;
		b_free_min = ave_b_free_tm > 0U ? stats->min_free_tm : 0U;
		b_free_max = ave_b_free_tm > 0U ? stats->max_free_tm : 0U;
		ave_alloc_tm = stats->alloc_cnt > 0U ? stats->alloc_tm / stats->alloc_cnt : 0U;
		ave_free_tm = stats->alloc_cnt > 0U ? stats->free_tm / stats->alloc_cnt : 0U;

		printf("    worker %d:\n"
		       "        significant events allocated/freed: %" PRIu64 "\n"
		       "        allocation retries:                 %" PRIu64 "\n"
		       "        allocation errors:                  %" PRIu64 "\n"
		       "        pattern errors:                     %" PRIu64 "\n"
		       "        run time:                           %" PRIu64 " (ns)\n"
		       "        event rate                          %" PRIu64 " (evs/s)\n"
		       "        average latency breakdown (ns):\n"
		       "            per allocation burst: %" PRIu64 " (min: %" PRIu64 " (round: %"
		       PRIu64 ", pattern: %u), max: %" PRIu64 " (round: %" PRIu64 ", pattern: %u))"
		       "\n"
		       "            per allocation:       %" PRIu64 "\n"
		       "            per free burst:       %" PRIu64 " (min: %" PRIu64 " (round: %"
		       PRIu64 ", pattern: %u), max: %" PRIu64 " (round: %" PRIu64 ", pattern: %u))"
		       "\n"
		       "            per free:             %" PRIu64 "\n", i, stats->alloc_cnt,
		       stats->reallocs, stats->alloc_errs, stats->pattern_errs, stats->tot_tm,
		       ev_rate, ave_b_alloc_tm, b_alloc_min, stats->min_alloc_rnd,
		       stats->min_alloc_pt, b_alloc_max, stats->max_alloc_rnd, stats->max_alloc_pt,
		       ave_alloc_tm, ave_b_free_tm, b_free_min, stats->min_free_rnd,
		       stats->min_free_pt, b_free_max, stats->max_free_rnd, stats->max_free_pt,
		       ave_free_tm);
		tot_b_alloc_tm += ave_b_alloc_tm;
		tot_b_free_tm += ave_b_free_tm;
		tot_alloc_tm += ave_alloc_tm;
		tot_free_tm += ave_free_tm;
		tot_alloc_min += b_alloc_min;
		tot_alloc_max += b_alloc_max;
		tot_free_min += b_free_min;
		tot_free_max += b_free_max;

		if (config->uarea_size > 0U) {
			ave_ua_b_tm = stats->alloc_b_cnt > 0U ?
					stats->uarea_tm / stats->alloc_b_cnt : 0U;
			ave_ua_tm = stats->alloc_cnt > 0U ?
					stats->uarea_tm / stats->alloc_cnt : 0U;
			b_ua_min = ave_ua_b_tm > 0U ? stats->min_uarea_tm : 0U;
			b_ua_max = ave_ua_b_tm > 0U ? stats->max_uarea_tm : 0U;
			printf("            per ua write burst:   %" PRIu64 " (min: %" PRIu64 " ("
			       "round: %" PRIu64 ", pattern: %u), max: %" PRIu64 " (round: %"
			       PRIu64 ", pattern: %u))\n"
			       "            per ua write:         %" PRIu64 "\n", ave_ua_b_tm,
			       b_ua_min, stats->min_uarea_rnd, stats->min_uarea_pt, b_ua_max,
			       stats->max_uarea_rnd, stats->max_uarea_pt, ave_ua_tm);
			tot_b_ua_tm += ave_ua_b_tm;
			tot_ua_tm += ave_ua_tm;
			tot_ua_min += b_ua_min;
			tot_ua_max += b_ua_max;
		}

		printf("\n");
	}

	printf("    total (ns):\n"
	       "        per allocation burst: %" PRIu64 " (min: %" PRIu64 ", max: %" PRIu64 ")\n"
	       "        per allocation:       %" PRIu64 "\n"
	       "        per free burst:       %" PRIu64 " (min: %" PRIu64 ", max: %" PRIu64 ")\n"
	       "        per free:             %" PRIu64 "\n",
	       tot_b_alloc_tm / config->num_workers, tot_alloc_min / config->num_workers,
	       tot_alloc_max / config->num_workers, tot_alloc_tm / config->num_workers,
	       tot_b_free_tm / config->num_workers, tot_free_min / config->num_workers,
	       tot_free_max / config->num_workers, tot_free_tm / config->num_workers);

	if (config->uarea_size > 0U) {
		printf("        per ua write burst:   %" PRIu64 " (min: %" PRIu64 ", max: %"
		       PRIu64 ")\n"
		       "        per ua write:         %" PRIu64 "\n",
		       tot_b_ua_tm / config->num_workers, tot_ua_min / config->num_workers,
		       tot_ua_max / config->num_workers, tot_ua_tm / config->num_workers);
	}

	printf("\n==================\n");
}

static void destroy_pool(odp_pool_t pool, uint8_t policy)
{
	static odp_bool_t is_destroyed;

	if (policy == SINGLE && is_destroyed)
		return;

	(void)odp_pool_destroy(pool);
	is_destroyed = true;
}

static void teardown(const prog_config_t *config)
{
	const worker_config_t *worker;

	for (uint32_t i = 0U; i < config->num_workers; ++i) {
		worker = &config->worker_config[i];

		if (worker->pool != ODP_POOL_INVALID)
			destroy_pool(worker->pool, config->policy);

		if (worker->shm != ODP_SHM_INVALID)
			(void)odp_shm_free(worker->shm);
	}
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

	if (odp_init_global(&odp_instance, NULL, NULL)) {
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

	parse_res = parse_options(argc, argv, prog_conf);

	if (parse_res == PRS_NOK) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (parse_res == PRS_TERM) {
		ret = EXIT_SUCCESS;
		goto out;
	}

	prog_conf->odp_instance = odp_instance;

	if (!setup_test(prog_conf)) {
		ret = EXIT_FAILURE;
		goto out_test;
	}

	stop_test(prog_conf);
	print_stats(prog_conf);

out_test:
	teardown(prog_conf);

out:
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

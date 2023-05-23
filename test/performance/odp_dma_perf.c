/* Copyright (c) 2021-2023, Nokia
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define EXIT_NOT_SUP 2
#define PROG_NAME "odp_dma_perf"

enum {
	SYNC = 0U,
	ASYNC
};

enum {
	PACKET = 0U,
	MEMORY
};

enum {
	POLL = 0U,
	EVENT
};

enum {
	SINGLE = 0U,
	MANY
};

#define DEF_TRS_TYPE SYNC
#define DEF_SEG_CNT 1U
#define DEF_LEN 1024U
#define DEF_SEG_TYPE PACKET
#define DEF_MODE POLL
#define DEF_INFLIGHT 1U
#define DEF_TIME 10U
#define DEF_WORKERS 1U
#define DEF_POLICY SINGLE

#define MAX_SEGS 1024U
#define MAX_WORKERS 24

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define MAX(a, b)  (((a) < (b)) ? (b) : (a))

#define GIGAS 1000000000
#define MEGAS 1000000
#define KILOS 1000

typedef enum {
	PRS_OK,
	PRS_NOK,
	PRS_TERM,
	PRS_NOT_SUP
} parse_result_t;

typedef struct {
	uint64_t completed;
	uint64_t start_errs;
	uint64_t poll_errs;
	uint64_t scheduler_timeouts;
	uint64_t transfer_errs;
	uint64_t tot_tm;
	uint64_t trs_tm;
	uint64_t max_trs_tm;
	uint64_t min_trs_tm;
	uint64_t start_cc;
	uint64_t max_start_cc;
	uint64_t min_start_cc;
	uint64_t wait_cc;
	uint64_t max_wait_cc;
	uint64_t min_wait_cc;
	uint64_t trs_cc;
	uint64_t max_trs_cc;
	uint64_t min_trs_cc;
	uint64_t start_cnt;
	uint64_t wait_cnt;
	uint64_t trs_poll_cnt;
	uint64_t trs_cnt;
} stats_t;

typedef struct {
	odp_dma_transfer_param_t trs_param;
	odp_dma_compl_param_t compl_param;
	odp_ticketlock_t lock;
	uint64_t trs_start_tm;
	uint64_t trs_start_cc;
	uint64_t trs_poll_cnt;
	odp_bool_t is_running;
} trs_info_t;

typedef struct ODP_ALIGNED_CACHE {
	struct {
		trs_info_t infos[MAX_SEGS];
		odp_dma_seg_t src_seg[MAX_SEGS];
		odp_dma_seg_t dst_seg[MAX_SEGS];
		odp_dma_t handle;
		odp_pool_t pool;
		odp_queue_t compl_q;
		uint32_t num_in_segs;
		uint32_t num_out_segs;
		uint32_t src_seg_len;
		uint32_t dst_seg_len;
		uint32_t num_inflight;
		uint8_t trs_type;
		uint8_t compl_mode;
	} dma;

	struct {
		odp_packet_t src_pkt[MAX_SEGS];
		odp_packet_t dst_pkt[MAX_SEGS];
		odp_pool_t src_pool;
		odp_pool_t dst_pool;
		odp_shm_t src_shm;
		odp_shm_t dst_shm;
		void *src;
		void *dst;
	} seg;

	odp_schedule_group_t grp;
} sd_t;

typedef struct prog_config_s prog_config_t;

typedef struct ODP_ALIGNED_CACHE {
	stats_t stats;
	prog_config_t *prog_config;
	sd_t *sd;
} thread_config_t;

typedef struct {
	/* Configure DMA session specific resources. */
	odp_bool_t (*session_cfg_fn)(sd_t *sd);
	/* Setup transfer elements (memory/packet segments). */
	odp_bool_t (*setup_fn)(sd_t *sd);
	/* Configure DMA transfers (segment addresses etc.). */
	void (*trs_fn)(sd_t *sd);
	/* Configure transfer completion resources (transfer IDs, events etc.). */
	odp_bool_t (*compl_fn)(sd_t *sd);
	/* Initiate required initial transfers. */
	odp_bool_t (*bootstrap_fn)(sd_t *sd);
	/* Wait and handle finished transfer. */
	void (*wait_fn)(sd_t *sd, stats_t *stats);
	/* Handle all unfinished transfers after main test has been stopped. */
	void (*drain_fn)(void);
	/* Free any resources that might have been allocated during setup phase. */
	void (*free_fn)(const sd_t *sd);
} test_api_t;

typedef struct prog_config_s {
	odph_thread_t threads[MAX_WORKERS];
	thread_config_t thread_config[MAX_WORKERS];
	sd_t sds[MAX_WORKERS];
	test_api_t api;
	odp_atomic_u32_t is_running;
	odp_instance_t odp_instance;
	odp_barrier_t init_barrier;
	odp_barrier_t term_barrier;
	odp_dma_compl_mode_t compl_mode_mask;
	odp_pool_t src_pool;
	odp_pool_t dst_pool;
	uint32_t num_in_segs;
	uint32_t num_out_segs;
	uint32_t src_seg_len;
	uint32_t dst_seg_len;
	uint32_t num_inflight;
	uint32_t time_sec;
	uint32_t num_sessions;
	int num_workers;
	uint8_t trs_type;
	uint8_t seg_type;
	uint8_t compl_mode;
	uint8_t policy;
} prog_config_t;

static prog_config_t *prog_conf;

static const int mode_map[] = { ODP_DMA_COMPL_POLL, ODP_DMA_COMPL_EVENT };

static void terminate(int signal ODP_UNUSED)
{
	odp_atomic_store_u32(&prog_conf->is_running, 0U);
}

static void init_config(prog_config_t *config)
{
	sd_t *sd;
	trs_info_t *info;
	stats_t *stats;

	memset(config, 0, sizeof(*config));
	config->compl_mode_mask |= ODP_DMA_COMPL_SYNC;
	config->src_pool = ODP_POOL_INVALID;
	config->dst_pool = ODP_POOL_INVALID;
	config->num_in_segs = DEF_SEG_CNT;
	config->num_out_segs = DEF_SEG_CNT;
	config->src_seg_len = DEF_LEN;
	config->num_inflight = DEF_INFLIGHT;
	config->time_sec = DEF_TIME;
	config->num_workers = DEF_WORKERS;
	config->trs_type = DEF_TRS_TYPE;
	config->seg_type = DEF_SEG_TYPE;
	config->compl_mode = DEF_MODE;
	config->policy = DEF_POLICY;

	for (uint32_t i = 0U; i < MAX_WORKERS; ++i) {
		sd = &config->sds[i];
		stats = &config->thread_config[i].stats;
		memset(sd, 0, sizeof(*sd));

		for (uint32_t i = 0U; i < MAX_SEGS; ++i) {
			info = &sd->dma.infos[i];
			info->compl_param.transfer_id = ODP_DMA_TRANSFER_ID_INVALID;
			info->compl_param.event = ODP_EVENT_INVALID;
			info->compl_param.queue = ODP_QUEUE_INVALID;
			odp_ticketlock_init(&info->lock);
			sd->seg.src_pkt[i] = ODP_PACKET_INVALID;
			sd->seg.dst_pkt[i] = ODP_PACKET_INVALID;
		}

		sd->dma.handle = ODP_DMA_INVALID;
		sd->dma.pool = ODP_POOL_INVALID;
		sd->dma.compl_q = ODP_QUEUE_INVALID;
		sd->seg.src_shm = ODP_SHM_INVALID;
		sd->seg.dst_shm = ODP_SHM_INVALID;
		sd->grp = ODP_SCHED_GROUP_INVALID;
		stats->min_trs_tm = UINT64_MAX;
		stats->min_start_cc = UINT64_MAX;
		stats->min_wait_cc = UINT64_MAX;
		stats->min_trs_cc = UINT64_MAX;
	}
}

static void print_usage(void)
{
	printf("\n"
	       "DMA performance test. Load DMA subsystem from several workers.\n"
	       "\n"
	       "Examples:\n"
	       "    " PROG_NAME "\n"
	       "    " PROG_NAME " -s 10240\n"
	       "    " PROG_NAME " -t 0 -i 1 -o 1 -s 51200 -S 1 -f 64 -T 10\n"
	       "    " PROG_NAME " -t 1 -i 10 -o 10 -s 4096 -S 0 -m 1 -f 10 -c 4 -p 1\n"
	       "\n"
	       "Usage: " PROG_NAME " [options]\n"
	       "\n"
	       "  -t, --trs_type            Transfer type for test data. %u by default.\n"
	       "                            Types:\n"
	       "                                0: synchronous\n"
	       "                                1: asynchronous\n"
	       "  -i, --num_in_seg          Number of input segments to transfer. 0 means the\n"
	       "                            maximum count supported by the implementation. %u by\n"
	       "                            default.\n"
	       "  -o, --num_out_seg         Number of output segments to transfer to. 0 means\n"
	       "                            the maximum count supported by the implementation.\n"
	       "                            %u by default.\n"
	       "  -s, --in_seg_len	    Input segment length in bytes. 0 length means\n"
	       "                            maximum segment length supported by implementation.\n"
	       "                            The actual maximum might be limited by what type of\n"
	       "                            data is transferred (packet/memory).\n"
	       "                            %u by default.\n"
	       "  -S, --in_seg_type         Input segment data type. %u by default.\n"
	       "                            Types:\n"
	       "                                0: packet\n"
	       "                                1: memory\n"
	       "  -m, --compl_mode          Completion mode for transfers. %u by default.\n"
	       "                            Modes:\n"
	       "                                0: poll\n"
	       "                                1: event\n"
	       "  -f, --max_in_flight       Max transfers in-flight per session. 0 means the\n"
	       "                            maximum supported by tester/implementation. %u by\n"
	       "                            default.\n"
	       "  -T, --time_sec            Time in seconds to run. 0 means infinite. %u by\n"
	       "                            default.\n"
	       "  -c, --worker_count        Amount of workers. %u by default.\n"
	       "  -p, --policy              DMA session policy. %u by default.\n"
	       "                            Policies:\n"
	       "                                0: One session shared by workers\n"
	       "                                1: One session per worker\n"
	       "  -h, --help                This help.\n"
	       "\n", DEF_TRS_TYPE, DEF_SEG_CNT, DEF_SEG_CNT, DEF_LEN, DEF_SEG_TYPE, DEF_MODE,
	       DEF_INFLIGHT, DEF_TIME, DEF_WORKERS, DEF_POLICY);
}

static parse_result_t check_options(prog_config_t *config)
{
	int max_workers;
	odp_dma_capability_t dma_capa;
	uint32_t num_sessions, max_seg_len, max_trs, max_in, max_out, max_segs;
	odp_schedule_capability_t sched_capa;
	odp_pool_capability_t pool_capa;
	odp_shm_capability_t shm_capa;
	uint64_t shm_size = 0U;

	if (config->trs_type != SYNC && config->trs_type != ASYNC) {
		ODPH_ERR("Invalid transfer type: %u\n", config->trs_type);
		return PRS_NOK;
	}

	if (config->seg_type != PACKET && config->seg_type != MEMORY) {
		ODPH_ERR("Invalid segment type: %u\n", config->seg_type);
		return PRS_NOK;
	}

	max_workers = MIN(odp_thread_count_max() - 1, MAX_WORKERS);

	if (config->num_workers <= 0 || config->num_workers > max_workers) {
		ODPH_ERR("Invalid thread count: %d (min: 1, max: %d)\n", config->num_workers,
			 max_workers);
		return PRS_NOK;
	}

	if (config->policy != SINGLE && config->policy != MANY) {
		ODPH_ERR("Invalid DMA session policy: %u\n", config->policy);
		return PRS_NOK;
	}

	if (odp_dma_capability(&dma_capa) < 0) {
		ODPH_ERR("Error querying DMA capabilities\n");
		return PRS_NOK;
	}

	num_sessions = config->policy == SINGLE ? 1 : config->num_workers;

	if (num_sessions > dma_capa.max_sessions) {
		ODPH_ERR("Not enough DMA sessions supported: %u (max: %u)\n", num_sessions,
			 dma_capa.max_sessions);
		return PRS_NOT_SUP;
	}

	config->num_sessions = num_sessions;

	if (config->num_in_segs == 0U)
		config->num_in_segs = dma_capa.max_src_segs;

	if (config->num_out_segs == 0U)
		config->num_out_segs = dma_capa.max_dst_segs;

	if (config->num_in_segs > dma_capa.max_src_segs ||
	    config->num_out_segs > dma_capa.max_dst_segs ||
	    config->num_in_segs + config->num_out_segs > dma_capa.max_segs) {
		ODPH_ERR("Unsupported segment count configuration, in: %u, out: %u (max in: %u, "
			 "max out: %u, max tot: %u)\n", config->num_in_segs, config->num_out_segs,
			 dma_capa.max_src_segs, dma_capa.max_dst_segs, dma_capa.max_segs);
		return PRS_NOT_SUP;
	}

	if (config->src_seg_len == 0U)
		config->src_seg_len = dma_capa.max_seg_len;

	config->dst_seg_len = config->src_seg_len * config->num_in_segs /
			      config->num_out_segs + config->src_seg_len *
			      config->num_in_segs % config->num_out_segs;

	max_seg_len = MAX(config->src_seg_len, config->dst_seg_len);

	if (max_seg_len > dma_capa.max_seg_len) {
		ODPH_ERR("Unsupported total DMA segment length: %u (max: %u)\n", max_seg_len,
			 dma_capa.max_seg_len);
		return PRS_NOT_SUP;
	}

	if (config->trs_type == ASYNC) {
		if (config->compl_mode != POLL && config->compl_mode != EVENT) {
			ODPH_ERR("Invalid completion mode: %u\n", config->compl_mode);
			return PRS_NOK;
		}

		if (config->compl_mode == POLL && (dma_capa.compl_mode_mask & ODP_DMA_COMPL_POLL)
		    == 0U) {
			ODPH_ERR("Unsupported DMA completion mode, poll\n");
			return PRS_NOT_SUP;
		}

		if (config->compl_mode == EVENT) {
			if (config->num_sessions > dma_capa.pool.max_pools) {
				ODPH_ERR("Unsupported amount of completion pools: %u (max: %u)\n",
					 config->num_sessions, dma_capa.pool.max_pools);
				return PRS_NOT_SUP;
			}

			if ((dma_capa.compl_mode_mask & ODP_DMA_COMPL_EVENT) == 0U) {
				ODPH_ERR("Unsupported DMA completion mode, event\n");
				return PRS_NOT_SUP;
			}

			if (dma_capa.queue_type_sched == 0) {
				ODPH_ERR("Unsupported DMA queueing type, scheduled\n");
				return PRS_NOT_SUP;
			}

			if (config->num_inflight > dma_capa.pool.max_num) {
				ODPH_ERR("Unsupported amount of completion events: %u (max: %u)\n",
					 config->num_inflight, dma_capa.pool.max_num);
				return PRS_NOT_SUP;
			}

			if (odp_schedule_capability(&sched_capa) < 0) {
				ODPH_ERR("Error querying scheduler capabilities\n");
				return PRS_NOK;
			}

			if (config->num_sessions > sched_capa.max_groups - 3U) {
				ODPH_ERR("Unsupported amount of scheduler groups: %u (max: %u)\n",
					 config->num_sessions, sched_capa.max_groups - 3U);
				return PRS_NOT_SUP;
			}
		}

		config->compl_mode_mask |= mode_map[config->compl_mode];
	}

	max_trs = MIN(dma_capa.max_transfers, MAX_SEGS);

	if (config->num_inflight == 0U)
		config->num_inflight = max_trs;

	if (config->num_inflight > max_trs) {
		ODPH_ERR("Unsupported amount of in-flight DMA transfers: %u (max: %u)\n",
			 config->num_inflight, max_trs);
		return PRS_NOT_SUP;
	}

	max_in = config->num_in_segs * config->num_inflight;
	max_out = config->num_out_segs * config->num_inflight;
	max_segs = MAX(max_in, max_out);

	if (max_segs > MAX_SEGS) {
		ODPH_ERR("Unsupported input/output * inflight segment combination: %u (max: %u)\n",
			 max_segs, MAX_SEGS);
		return PRS_NOT_SUP;
	}

	if (config->seg_type == PACKET) {
		if (odp_pool_capability(&pool_capa) < 0) {
			ODPH_ERR("Error querying pool capabilities\n");
			return PRS_NOK;
		}

		if (pool_capa.pkt.max_pools < 2U) {
			ODPH_ERR("Unsupported amount of packet pools: 2 (max: %u)\n",
				 pool_capa.pkt.max_pools);
			return PRS_NOT_SUP;
		}

		if (pool_capa.pkt.max_len != 0U && max_seg_len > pool_capa.pkt.max_len) {
			ODPH_ERR("Unsupported packet size: %u (max: %u)\n", max_seg_len,
				 pool_capa.pkt.max_len);
			return PRS_NOT_SUP;
		}

		if (pool_capa.pkt.max_num != 0U &&
		    max_segs * num_sessions > pool_capa.pkt.max_num) {
			ODPH_ERR("Unsupported amount of packet pool elements: %u (max: %u)\n",
				 max_segs * num_sessions, pool_capa.pkt.max_num);
			return PRS_NOT_SUP;
		}
	} else {
		/* If SHM implementation capabilities are very puny, program will have already
		 * failed when reserving memory for global program configuration. */
		if (odp_shm_capability(&shm_capa) < 0) {
			ODPH_ERR("Error querying SHM capabilities\n");
			return PRS_NOK;
		}

		/* One block for program configuration, one for source memory and one for
		 * destination memory. */
		if (shm_capa.max_blocks < 3U) {
			ODPH_ERR("Unsupported amount of SHM blocks: 3 (max: %u)\n",
				 shm_capa.max_blocks);
			return PRS_NOT_SUP;
		}

		shm_size = (uint64_t)config->dst_seg_len * config->num_out_segs *
			   config->num_inflight;

		if (shm_capa.max_size != 0U && shm_size > shm_capa.max_size) {
			ODPH_ERR("Unsupported total SHM block size: %" PRIu64 ""
				 " (max: %" PRIu64 ")\n", shm_size, shm_capa.max_size);
			return PRS_NOT_SUP;
		}
	}

	return PRS_OK;
}

static parse_result_t parse_options(int argc, char **argv, prog_config_t *config)
{
	int opt, long_index;
	static const struct option longopts[] = {
		{ "trs_type", required_argument, NULL, 't' },
		{ "num_in_seg", required_argument, NULL, 'i' },
		{ "num_out_seg", required_argument, NULL, 'o' },
		{ "in_seg_len", required_argument, NULL, 's' },
		{ "in_seg_type", required_argument, NULL, 'S' },
		{ "compl_mode", required_argument, NULL, 'm' },
		{ "max_in_flight", required_argument, NULL, 'f'},
		{ "time_sec", required_argument, NULL, 'T' },
		{ "worker_count", required_argument, NULL, 'c' },
		{ "policy", required_argument, NULL, 'p' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	static const char *shortopts = "t:i:o:s:S:m:f:T:c:p:h";

	init_config(config);

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 't':
			config->trs_type = atoi(optarg);
			break;
		case 'i':
			config->num_in_segs = atoi(optarg);
			break;
		case 'o':
			config->num_out_segs = atoi(optarg);
			break;
		case 's':
			config->src_seg_len = atoi(optarg);
			break;
		case 'S':
			config->seg_type = atoi(optarg);
			break;
		case 'm':
			config->compl_mode = atoi(optarg);
			break;
		case 'f':
			config->num_inflight = atoi(optarg);
			break;
		case 'T':
			config->time_sec = atoi(optarg);
			break;
		case 'c':
			config->num_workers = atoi(optarg);
			break;
		case 'p':
			config->policy = atoi(optarg);
			break;
		case 'h':
			print_usage();
			return PRS_TERM;
		case '?':
		default:
			print_usage();
			return PRS_NOK;
		}
	}

	return check_options(config);
}

static parse_result_t setup_program(int argc, char **argv, prog_config_t *config)
{
	struct sigaction action = { .sa_handler = terminate };

	if (sigemptyset(&action.sa_mask) == -1 || sigaddset(&action.sa_mask, SIGINT) == -1 ||
	    sigaddset(&action.sa_mask, SIGTERM) == -1 ||
	    sigaddset(&action.sa_mask, SIGHUP) == -1 || sigaction(SIGINT, &action, NULL) == -1 ||
	    sigaction(SIGTERM, &action, NULL) == -1 || sigaction(SIGHUP, &action, NULL) == -1) {
		ODPH_ERR("Error installing signal handler\n");
		return PRS_NOK;
	}

	return parse_options(argc, argv, config);
}

static odp_pool_t get_src_packet_pool(void)
{
	odp_pool_param_t param;

	if (prog_conf->src_pool != ODP_POOL_INVALID)
		return prog_conf->src_pool;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_PACKET;
	param.pkt.num = prog_conf->num_inflight * prog_conf->num_in_segs * prog_conf->num_sessions;
	param.pkt.len = prog_conf->src_seg_len;
	param.pkt.seg_len = prog_conf->src_seg_len;
	prog_conf->src_pool = odp_pool_create(PROG_NAME "_src_pkts", &param);

	return prog_conf->src_pool;
}

static odp_pool_t get_dst_packet_pool(void)
{
	odp_pool_param_t param;

	if (prog_conf->dst_pool != ODP_POOL_INVALID)
		return prog_conf->dst_pool;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_PACKET;
	param.pkt.num = prog_conf->num_inflight * prog_conf->num_out_segs *
			prog_conf->num_sessions;
	param.pkt.len = prog_conf->dst_seg_len;
	param.pkt.seg_len = prog_conf->dst_seg_len;
	prog_conf->dst_pool = odp_pool_create(PROG_NAME "_dst_pkts", &param);

	return prog_conf->dst_pool;
}

static odp_bool_t configure_packets(sd_t *sd)
{
	sd->seg.src_pool = get_src_packet_pool();

	if (sd->seg.src_pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error creating source packet pool\n");
		return false;
	}

	sd->seg.dst_pool = get_dst_packet_pool();

	if (sd->seg.dst_pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error creating destination packet pool\n");
		return false;
	}

	return true;
}

static odp_bool_t allocate_packets(sd_t *sd)
{
	for (uint32_t i = 0U; i < sd->dma.num_inflight * sd->dma.num_in_segs; ++i) {
		sd->seg.src_pkt[i] = odp_packet_alloc(sd->seg.src_pool, sd->dma.src_seg_len);

		if (sd->seg.src_pkt[i] == ODP_PACKET_INVALID) {
			ODPH_ERR("Error allocating source segment packets\n");
			return false;
		}
	}

	for (uint32_t i = 0U; i < sd->dma.num_inflight * sd->dma.num_out_segs; ++i) {
		sd->seg.dst_pkt[i] = odp_packet_alloc(sd->seg.dst_pool, sd->dma.dst_seg_len);

		if (sd->seg.dst_pkt[i] == ODP_PACKET_INVALID) {
			ODPH_ERR("Error allocating destination segment packets\n");
			return false;
		}
	}

	return true;
}

static odp_bool_t setup_packet_segments(sd_t *sd)
{
	return configure_packets(sd) && allocate_packets(sd);
}

static void configure_packet_dma_transfer(sd_t *sd)
{
	odp_dma_seg_t *start_src_seg, *start_dst_seg, *seg;
	uint32_t k = 0U, z = 0U, len;
	odp_packet_t pkt;
	odp_dma_transfer_param_t *param;

	for (uint32_t i = 0U; i < sd->dma.num_inflight; ++i) {
		start_src_seg = &sd->dma.src_seg[k];
		start_dst_seg = &sd->dma.dst_seg[z];

		for (uint32_t j = 0U; j < sd->dma.num_in_segs; ++j, ++k) {
			pkt = sd->seg.src_pkt[k];
			seg = &start_src_seg[j];
			seg->packet = pkt;
			seg->offset = 0U;
			seg->len = sd->dma.src_seg_len;
		}

		len = sd->dma.num_in_segs * sd->dma.src_seg_len;

		for (uint32_t j = 0U; j < sd->dma.num_out_segs; ++j, ++z) {
			pkt = sd->seg.dst_pkt[z];
			seg = &start_dst_seg[j];
			seg->packet = pkt;
			seg->offset = 0U;
			seg->len = MIN(len, sd->dma.dst_seg_len);
			len -= sd->dma.dst_seg_len;
		}

		param = &sd->dma.infos[i].trs_param;
		odp_dma_transfer_param_init(param);
		param->src_format = ODP_DMA_FORMAT_PACKET;
		param->dst_format = ODP_DMA_FORMAT_PACKET;
		param->num_src = sd->dma.num_in_segs;
		param->num_dst = sd->dma.num_out_segs;
		param->src_seg = start_src_seg;
		param->dst_seg = start_dst_seg;
	}
}

static void free_packets(const sd_t *sd)
{
	for (uint32_t i = 0U; i < sd->dma.num_inflight * sd->dma.num_in_segs; ++i) {
		if (sd->seg.src_pkt[i] != ODP_PACKET_INVALID)
			odp_packet_free(sd->seg.src_pkt[i]);
	}

	for (uint32_t i = 0U; i < sd->dma.num_inflight * sd->dma.num_out_segs; ++i) {
		if (sd->seg.dst_pkt[i] != ODP_PACKET_INVALID)
			odp_packet_free(sd->seg.dst_pkt[i]);
	}
}

static odp_bool_t allocate_memory(sd_t *sd)
{
	const uint64_t num_segs = (uint64_t)sd->dma.num_in_segs * sd->dma.num_inflight;

	sd->seg.src_shm = odp_shm_reserve(PROG_NAME "_src_shm", sd->dma.src_seg_len * num_segs,
					  ODP_CACHE_LINE_SIZE, 0U);
	sd->seg.dst_shm = odp_shm_reserve(PROG_NAME "_dst_shm", sd->dma.dst_seg_len * num_segs,
					  ODP_CACHE_LINE_SIZE, 0U);

	if (sd->seg.src_shm == ODP_SHM_INVALID || sd->seg.dst_shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error allocating SHM block\n");
		return false;
	}

	sd->seg.src = odp_shm_addr(sd->seg.src_shm);
	sd->seg.dst = odp_shm_addr(sd->seg.dst_shm);

	if (sd->seg.src == NULL || sd->seg.dst == NULL) {
		ODPH_ERR("Error resolving SHM block address\n");
		return false;
	}

	return true;
}

static odp_bool_t setup_memory_segments(sd_t *sd)
{
	return allocate_memory(sd);
}

static void configure_address_dma_transfer(sd_t *sd)
{
	odp_dma_seg_t *start_src_seg, *start_dst_seg, *seg;
	uint32_t k = 0U, z = 0U, len;
	odp_dma_transfer_param_t *param;

	for (uint32_t i = 0U; i < sd->dma.num_inflight; ++i) {
		start_src_seg = &sd->dma.src_seg[k];
		start_dst_seg = &sd->dma.dst_seg[z];

		for (uint32_t j = 0U; j < sd->dma.num_in_segs; ++j, ++k) {
			seg = &start_src_seg[j];
			seg->addr = (uint8_t *)sd->seg.src + k * sd->dma.src_seg_len;
			seg->len = sd->dma.src_seg_len;
		}

		len = sd->dma.num_in_segs * sd->dma.src_seg_len;

		for (uint32_t j = 0U; j < sd->dma.num_out_segs; ++j, ++z) {
			seg = &start_dst_seg[j];
			seg->addr = (uint8_t *)sd->seg.dst + z * sd->dma.dst_seg_len;
			seg->len = MIN(len, sd->dma.dst_seg_len);
			len -= sd->dma.dst_seg_len;
		}

		param = &sd->dma.infos[i].trs_param;
		odp_dma_transfer_param_init(param);
		param->src_format = ODP_DMA_FORMAT_ADDR;
		param->dst_format = ODP_DMA_FORMAT_ADDR;
		param->num_src = sd->dma.num_in_segs;
		param->num_dst = sd->dma.num_out_segs;
		param->src_seg = start_src_seg;
		param->dst_seg = start_dst_seg;
	}
}

static void free_memory(const sd_t *sd)
{
	if (sd->seg.src_shm != ODP_SHM_INVALID)
		(void)odp_shm_free(sd->seg.src_shm);

	if (sd->seg.dst_shm != ODP_SHM_INVALID)
		(void)odp_shm_free(sd->seg.dst_shm);
}

static void run_transfer(odp_dma_t handle, trs_info_t *info, stats_t *stats)
{
	uint64_t start_tm, end_tm, start_cc, end_cc, trs_tm, trs_cc, start_cc_diff;
	odp_dma_result_t res;
	int ret;

	start_tm = odp_time_local_strict_ns();
	start_cc = odp_cpu_cycles();
	ret = odp_dma_transfer(handle, &info->trs_param, &res);
	end_cc = odp_cpu_cycles();
	end_tm = odp_time_local_strict_ns();

	if (odp_unlikely(ret <= 0)) {
		++stats->start_errs;
	} else {
		trs_tm = end_tm - start_tm;
		stats->max_trs_tm = MAX(trs_tm, stats->max_trs_tm);
		stats->min_trs_tm = MIN(trs_tm, stats->min_trs_tm);
		stats->trs_tm += trs_tm;
		trs_cc = odp_cpu_cycles_diff(end_cc, start_cc);
		stats->max_trs_cc = MAX(trs_cc, stats->max_trs_cc);
		stats->min_trs_cc = MIN(trs_cc, stats->min_trs_cc);
		stats->trs_cc += trs_cc;
		++stats->trs_cnt;
		start_cc_diff = odp_cpu_cycles_diff(end_cc, start_cc);
		stats->max_start_cc = MAX(start_cc_diff, stats->max_start_cc);
		stats->min_start_cc = MIN(start_cc_diff, stats->min_start_cc);
		stats->start_cc += start_cc_diff;
		++stats->start_cnt;

		if (odp_unlikely(!res.success))
			++stats->transfer_errs;
		else
			++stats->completed;
	}
}

static void run_transfers_mt_unsafe(sd_t *sd, stats_t *stats)
{
	const uint32_t count = sd->dma.num_inflight;
	odp_dma_t handle = sd->dma.handle;
	trs_info_t *infos = sd->dma.infos;

	for (uint32_t i = 0U; i < count; ++i)
		run_transfer(handle, &infos[i], stats);
}

static void run_transfers_mt_safe(sd_t *sd, stats_t *stats)
{
	const uint32_t count = sd->dma.num_inflight;
	odp_dma_t handle = sd->dma.handle;
	trs_info_t *infos = sd->dma.infos, *info;

	for (uint32_t i = 0U; i < count; ++i) {
		info = &infos[i];

		if (odp_ticketlock_trylock(&info->lock)) {
			run_transfer(handle, info, stats);
			odp_ticketlock_unlock(&info->lock);
		}
	}
}

static odp_bool_t configure_poll_compl(sd_t *sd)
{
	odp_dma_compl_param_t *param;

	for (uint32_t i = 0U; i < sd->dma.num_inflight; ++i) {
		param = &sd->dma.infos[i].compl_param;

		odp_dma_compl_param_init(param);
		param->compl_mode = mode_map[sd->dma.compl_mode];
		param->transfer_id = odp_dma_transfer_id_alloc(sd->dma.handle);

		if (param->transfer_id == ODP_DMA_TRANSFER_ID_INVALID) {
			ODPH_ERR("Error allocating transfer ID\n");
			return false;
		}
	}

	return true;
}

static void poll_transfer(odp_dma_t handle, trs_info_t *info, stats_t *stats)
{
	uint64_t start_cc, end_cc, trs_tm, trs_cc, wait_cc, start_tm, start_cc_diff;
	odp_dma_result_t res;
	int ret;

	if (info->is_running) {
		start_cc = odp_cpu_cycles();
		ret = odp_dma_transfer_done(handle, info->compl_param.transfer_id, &res);
		end_cc = odp_cpu_cycles();

		if (odp_unlikely(ret < 0)) {
			++stats->poll_errs;
			return;
		}

		++info->trs_poll_cnt;
		wait_cc = odp_cpu_cycles_diff(end_cc, start_cc);
		stats->max_wait_cc = MAX(wait_cc, stats->max_wait_cc);
		stats->min_wait_cc = MIN(wait_cc, stats->min_wait_cc);
		stats->wait_cc += wait_cc;
		++stats->wait_cnt;

		if (ret == 0)
			return;

		trs_tm = odp_time_global_strict_ns() - info->trs_start_tm;
		stats->max_trs_tm = MAX(trs_tm, stats->max_trs_tm);
		stats->min_trs_tm = MIN(trs_tm, stats->min_trs_tm);
		stats->trs_tm += trs_tm;
		trs_cc = odp_cpu_cycles_diff(odp_cpu_cycles(), info->trs_start_cc);
		stats->max_trs_cc = MAX(trs_cc, stats->max_trs_cc);
		stats->min_trs_cc = MIN(trs_cc, stats->min_trs_cc);
		stats->trs_cc += trs_cc;
		stats->trs_poll_cnt += info->trs_poll_cnt;
		++stats->trs_cnt;

		if (odp_unlikely(!res.success))
			++stats->transfer_errs;
		else
			++stats->completed;

		info->is_running = false;
	} else {
		start_tm = odp_time_global_strict_ns();
		start_cc = odp_cpu_cycles();
		ret = odp_dma_transfer_start(handle, &info->trs_param, &info->compl_param);
		end_cc = odp_cpu_cycles();

		if (odp_unlikely(ret <= 0)) {
			++stats->start_errs;
		} else {
			info->trs_start_tm = start_tm;
			info->trs_start_cc = start_cc;
			info->trs_poll_cnt = 0U;
			start_cc_diff = odp_cpu_cycles_diff(end_cc, start_cc);
			stats->max_start_cc = MAX(start_cc_diff, stats->max_start_cc);
			stats->min_start_cc = MIN(start_cc_diff, stats->min_start_cc);
			stats->start_cc += start_cc_diff;
			++stats->start_cnt;
			info->is_running = true;
		}
	}
}

static void poll_transfers_mt_unsafe(sd_t *sd, stats_t *stats)
{
	const uint32_t count = sd->dma.num_inflight;
	odp_dma_t handle = sd->dma.handle;
	trs_info_t *infos = sd->dma.infos;

	for (uint32_t i = 0U; i < count; ++i)
		poll_transfer(handle, &infos[i], stats);
}

static void poll_transfers_mt_safe(sd_t *sd, stats_t *stats)
{
	const uint32_t count = sd->dma.num_inflight;
	odp_dma_t handle = sd->dma.handle;
	trs_info_t *infos = sd->dma.infos, *info;

	for (uint32_t i = 0U; i < count; ++i) {
		info = &infos[i];

		if (odp_ticketlock_trylock(&info->lock)) {
			poll_transfer(handle, info, stats);
			odp_ticketlock_unlock(&info->lock);
		}
	}
}

static odp_bool_t configure_event_compl_session(sd_t *sd)
{
	odp_thrmask_t zero;
	odp_dma_pool_param_t pool_param;
	odp_queue_param_t queue_param;

	odp_thrmask_zero(&zero);
	sd->grp = odp_schedule_group_create(PROG_NAME "_scd_grp", &zero);

	if (sd->grp == ODP_SCHED_GROUP_INVALID) {
		ODPH_ERR("Error creating scheduler group for DMA session\n");
		return false;
	}

	odp_dma_pool_param_init(&pool_param);
	pool_param.num = sd->dma.num_inflight;
	sd->dma.pool = odp_dma_pool_create(PROG_NAME "_dma_evs", &pool_param);

	if (sd->dma.pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error creating DMA event completion pool\n");
		return false;
	}

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	queue_param.sched.prio = odp_schedule_default_prio();
	queue_param.sched.group = sd->grp;
	sd->dma.compl_q = odp_queue_create(PROG_NAME, &queue_param);

	if (sd->dma.compl_q == ODP_QUEUE_INVALID) {
		ODPH_ERR("Error creating DMA completion queue\n");
		return false;
	}

	return true;
}

static odp_bool_t configure_event_compl(sd_t *sd)
{
	odp_dma_compl_param_t *param;
	odp_dma_compl_t c_ev;

	for (uint32_t i = 0U; i < sd->dma.num_inflight; ++i) {
		param = &sd->dma.infos[i].compl_param;

		odp_dma_compl_param_init(param);
		param->compl_mode = mode_map[sd->dma.compl_mode];
		c_ev = odp_dma_compl_alloc(sd->dma.pool);

		if (c_ev == ODP_DMA_COMPL_INVALID) {
			ODPH_ERR("Error allocating completion event\n");
			return false;
		}

		param->event = odp_dma_compl_to_event(c_ev);
		param->queue = sd->dma.compl_q;
		param->user_ptr = &sd->dma.infos[i];
	}

	return true;
}

static odp_bool_t start_initial_transfers(sd_t *sd)
{
	uint64_t start_tm, start_cc;
	trs_info_t *info;
	int ret;

	for (uint32_t i = 0U; i < sd->dma.num_inflight; ++i) {
		info = &sd->dma.infos[i];
		start_tm = odp_time_global_strict_ns();
		start_cc = odp_cpu_cycles();
		ret = odp_dma_transfer_start(sd->dma.handle, &info->trs_param, &info->compl_param);

		if (ret <= 0) {
			ODPH_ERR("Error starting DMA transfer\n");
			return false;
		}

		info->trs_start_tm = start_tm;
		info->trs_start_cc = start_cc;
	}

	return true;
}

static void wait_compl_event(sd_t *sd, stats_t *stats)
{
	uint64_t start_cc, end_cc, wait_cc, trs_tm, trs_cc, start_tm, start_cc_diff;
	odp_event_t ev;
	odp_dma_result_t res;
	trs_info_t *info;
	int ret;

	start_cc = odp_cpu_cycles();
	ev = odp_schedule(NULL, odp_schedule_wait_time(ODP_TIME_SEC_IN_NS));
	end_cc = odp_cpu_cycles();

	if (odp_unlikely(ev == ODP_EVENT_INVALID)) {
		++stats->scheduler_timeouts;
		return;
	}

	odp_dma_compl_result(odp_dma_compl_from_event(ev), &res);
	info = res.user_ptr;
	trs_tm = odp_time_global_strict_ns() - info->trs_start_tm;
	stats->max_trs_tm = MAX(trs_tm, stats->max_trs_tm);
	stats->min_trs_tm = MIN(trs_tm, stats->min_trs_tm);
	stats->trs_tm += trs_tm;
	trs_cc = odp_cpu_cycles_diff(odp_cpu_cycles(), info->trs_start_cc);
	stats->max_trs_cc = MAX(trs_cc, stats->max_trs_cc);
	stats->min_trs_cc = MIN(trs_cc, stats->min_trs_cc);
	stats->trs_cc += trs_cc;
	++stats->trs_cnt;
	wait_cc = odp_cpu_cycles_diff(end_cc, start_cc);
	stats->max_wait_cc = MAX(wait_cc, stats->max_wait_cc);
	stats->min_wait_cc = MIN(wait_cc, stats->min_wait_cc);
	stats->wait_cc += wait_cc;
	++stats->wait_cnt;

	if (odp_unlikely(!res.success))
		++stats->transfer_errs;
	else
		++stats->completed;

	start_tm = odp_time_global_strict_ns();
	start_cc = odp_cpu_cycles();
	ret = odp_dma_transfer_start(sd->dma.handle, &info->trs_param, &info->compl_param);
	end_cc = odp_cpu_cycles();

	if (odp_unlikely(ret <= 0)) {
		++stats->start_errs;
	} else {
		info->trs_start_tm = start_tm;
		info->trs_start_cc = start_cc;
		start_cc_diff = odp_cpu_cycles_diff(end_cc, start_cc);
		stats->max_start_cc = MAX(start_cc_diff, stats->max_start_cc);
		stats->min_start_cc = MIN(start_cc_diff, stats->min_start_cc);
		stats->start_cc += start_cc_diff;
		++stats->start_cnt;
	}
}

static void drain_compl_events(void)
{
	odp_event_t ev;

	while (true) {
		ev = odp_schedule(NULL, odp_schedule_wait_time(ODP_TIME_SEC_IN_NS));

		if (ev == ODP_EVENT_INVALID)
			break;
	}
}

static void setup_api(prog_config_t *config)
{
	if (config->seg_type == PACKET) {
		config->api.setup_fn = setup_packet_segments;
		config->api.trs_fn = configure_packet_dma_transfer;
		config->api.free_fn = free_packets;
	} else {
		config->api.setup_fn = setup_memory_segments;
		config->api.trs_fn = configure_address_dma_transfer;
		config->api.free_fn = free_memory;
	}

	if (config->trs_type == SYNC) {
		config->api.compl_fn = NULL;
		config->api.wait_fn = config->num_workers == 1 || config->policy == MANY ?
					run_transfers_mt_unsafe : run_transfers_mt_safe;
		config->api.drain_fn = NULL;
	} else {
		if (config->compl_mode == POLL) {
			config->api.session_cfg_fn = NULL;
			config->api.compl_fn = configure_poll_compl;
			config->api.bootstrap_fn = NULL;
			config->api.wait_fn = config->num_workers == 1 || config->policy == MANY ?
						poll_transfers_mt_unsafe : poll_transfers_mt_safe;
			config->api.drain_fn = NULL;
		} else {
			config->api.session_cfg_fn = configure_event_compl_session;
			config->api.compl_fn = configure_event_compl;
			config->api.bootstrap_fn = start_initial_transfers;
			config->api.wait_fn = wait_compl_event;
			config->api.drain_fn = drain_compl_events;
		}
	}
}

static odp_bool_t setup_session_descriptors(prog_config_t *config)
{
	sd_t *sd;
	const odp_dma_param_t dma_params = {
		.direction = ODP_DMA_MAIN_TO_MAIN,
		.type = ODP_DMA_TYPE_COPY,
		.compl_mode_mask = config->compl_mode_mask,
		.mt_mode = config->num_workers == 1 || config->policy == MANY ?
				ODP_DMA_MT_SERIAL : ODP_DMA_MT_SAFE,
		.order = ODP_DMA_ORDER_NONE };

	for (uint32_t i = 0U; i < config->num_sessions; ++i) {
		char name[ODP_DMA_NAME_LEN];

		sd = &config->sds[i];
		sd->dma.num_in_segs = config->num_in_segs;
		sd->dma.num_out_segs = config->num_out_segs;
		sd->dma.src_seg_len = config->src_seg_len;
		sd->dma.dst_seg_len = config->dst_seg_len;
		sd->dma.num_inflight = config->num_inflight;
		sd->dma.trs_type = config->trs_type;
		sd->dma.compl_mode = config->compl_mode;
		snprintf(name, sizeof(name), PROG_NAME "_dma_%u", i);
		sd->dma.handle = odp_dma_create(name, &dma_params);

		if (sd->dma.handle == ODP_DMA_INVALID) {
			ODPH_ERR("Error creating DMA session\n");
			return false;
		}

		if (config->api.session_cfg_fn != NULL && !config->api.session_cfg_fn(sd))
			return false;
	}

	return true;
}

static odp_bool_t setup_data(prog_config_t *config)
{
	sd_t *sd;

	for (uint32_t i = 0U; i < config->num_sessions; ++i) {
		sd = &config->sds[i];

		if (!config->api.setup_fn(sd))
			return false;

		config->api.trs_fn(sd);

		if (config->api.compl_fn != NULL && !config->api.compl_fn(sd))
			return false;
	}

	return true;
}

static int transfer(void *args)
{
	thread_config_t *thr_config = args;
	prog_config_t *prog_config = thr_config->prog_config;
	sd_t *sd = thr_config->sd;
	stats_t *stats = &thr_config->stats;
	test_api_t *api = &prog_conf->api;
	odp_thrmask_t mask;
	uint64_t start_tm, end_tm;

	odp_barrier_wait(&prog_config->init_barrier);

	if (sd->grp != ODP_SCHED_GROUP_INVALID) {
		odp_thrmask_zero(&mask);
		odp_thrmask_set(&mask, odp_thread_id());

		if (odp_schedule_group_join(sd->grp, &mask) < 0) {
			ODPH_ERR("Error joining scheduler group\n");
			goto out;
		}
	}

	start_tm = odp_time_local_strict_ns();

	while (odp_atomic_load_u32(&prog_config->is_running))
		api->wait_fn(sd, stats);

	end_tm = odp_time_local_strict_ns();
	thr_config->stats.tot_tm = end_tm - start_tm;

	if (api->drain_fn != NULL)
		api->drain_fn();

out:
	odp_barrier_wait(&prog_config->term_barrier);

	return 0;
}

static odp_bool_t setup_workers(prog_config_t *config)
{
	odp_cpumask_t cpumask;
	int num_workers;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_params[config->num_workers], *thr_param;
	thread_config_t *thr_config;
	sd_t *sd;

	/* Barrier init count for control and worker. */
	odp_barrier_init(&config->init_barrier, config->num_workers + 1);
	odp_barrier_init(&config->term_barrier, config->num_workers);
	num_workers = odp_cpumask_default_worker(&cpumask, config->num_workers);
	odph_thread_common_param_init(&thr_common);
	thr_common.instance = config->odp_instance;
	thr_common.cpumask = &cpumask;

	for (int i = 0; i < config->num_workers; ++i) {
		thr_param = &thr_params[i];
		thr_config = &config->thread_config[i];
		sd = config->policy == SINGLE ? &config->sds[0U] : &config->sds[i];

		odph_thread_param_init(thr_param);
		thr_param->start = transfer;
		thr_param->thr_type = ODP_THREAD_WORKER;
		thr_config->prog_config = config;
		thr_config->sd = sd;
		thr_param->arg = thr_config;
	}

	num_workers = odph_thread_create(config->threads, &thr_common, thr_params, num_workers);

	if (num_workers != config->num_workers) {
		ODPH_ERR("Error configuring worker threads\n");
		return false;
	}

	for (uint32_t i = 0U; i < config->num_sessions; ++i) {
		if (config->api.bootstrap_fn != NULL && !config->api.bootstrap_fn(&config->sds[i]))
			return false;
	}

	odp_barrier_wait(&config->init_barrier);

	return true;
}

static odp_bool_t setup_test(prog_config_t *config)
{
	setup_api(config);

	return setup_session_descriptors(config) && setup_data(config) && setup_workers(config);
}

static void stop_test(prog_config_t *config)
{
	(void)odph_thread_join(config->threads, config->num_workers);
}

static void teardown_data(const sd_t *sd, void (*free_fn)(const sd_t *sd))
{
	const odp_dma_compl_param_t *compl_param;

	for (uint32_t i = 0U; i < MAX_SEGS; ++i) {
		compl_param = &sd->dma.infos[i].compl_param;

		if (compl_param->transfer_id != ODP_DMA_TRANSFER_ID_INVALID)
			odp_dma_transfer_id_free(sd->dma.handle, compl_param->transfer_id);

		if (compl_param->event != ODP_EVENT_INVALID)
			odp_event_free(compl_param->event);
	}

	free_fn(sd);
}

static void teardown_test(prog_config_t *config)
{
	sd_t *sd;

	for (uint32_t i = 0U; i < config->num_sessions; ++i) {
		sd = &config->sds[i];
		teardown_data(sd, config->api.free_fn);

		if (sd->dma.compl_q != ODP_QUEUE_INVALID)
			(void)odp_queue_destroy(sd->dma.compl_q);

		if (sd->dma.pool != ODP_POOL_INVALID)
			(void)odp_pool_destroy(sd->dma.pool);

		if (sd->grp != ODP_SCHED_GROUP_INVALID)
			(void)odp_schedule_group_destroy(sd->grp);

		if (sd->dma.handle != ODP_DMA_INVALID)
			(void)odp_dma_destroy(sd->dma.handle);
	}

	if (config->src_pool != ODP_POOL_INVALID)
		(void)odp_pool_destroy(config->src_pool);

	if (config->dst_pool != ODP_POOL_INVALID)
		(void)odp_pool_destroy(config->dst_pool);
}

static void print_humanised(uint64_t value, const char *type)
{
	if (value > GIGAS)
		printf("%.2f G%s\n", (double)value / GIGAS, type);
	else if (value > MEGAS)
		printf("%.2f M%s\n", (double)value / MEGAS, type);
	else if (value > KILOS)
		printf("%.2f K%s\n", (double)value / KILOS, type);
	else
		printf("%" PRIu64 " %s\n", value, type);
}

static void print_stats(const prog_config_t *config)
{
	const stats_t *stats;
	uint64_t data_cnt = config->num_in_segs * config->src_seg_len, tot_completed = 0U,
	tot_tm = 0U, tot_trs_tm = 0U, tot_trs_cc = 0U, tot_trs_cnt = 0U, tot_min_tm = UINT64_MAX,
	tot_max_tm = 0U, tot_min_cc = UINT64_MAX, tot_max_cc = 0U, avg_start_cc, avg_wait_cc,
	avg_tot_tm;

	printf("\n======================\n\n"
	       "DMA performance test done\n\n"
	       "    mode:                 %s\n"
	       "    input segment count:  %u\n"
	       "    output segment count: %u\n"
	       "    segment length:       %u\n"
	       "    segment type:         %s\n"
	       "    inflight count:       %u\n"
	       "    session policy:       %s\n\n",
	       config->trs_type == SYNC ? "synchronous" : config->compl_mode == POLL ?
			"asynchronous-poll" : "asynchronous-event", config->num_in_segs,
	       config->num_out_segs, config->src_seg_len,
	       config->seg_type == PACKET ? "packet" : "memory", config->num_inflight,
	       config->policy == SINGLE ? "shared" : "per-worker");

	for (int i = 0; i < config->num_workers; ++i) {
		stats = &config->thread_config[i].stats;
		tot_completed += stats->completed;
		tot_tm += stats->tot_tm;
		tot_trs_tm += stats->trs_tm;
		tot_trs_cc += stats->trs_cc;
		tot_trs_cnt += stats->trs_cnt;
		tot_min_tm = MIN(tot_min_tm, stats->min_trs_tm);
		tot_max_tm = MAX(tot_max_tm, stats->max_trs_tm);
		tot_min_cc = MIN(tot_min_cc, stats->min_trs_cc);
		tot_max_cc = MAX(tot_max_cc, stats->max_trs_cc);

		printf("    worker %d:\n", i);
		printf("        successful transfers: %" PRIu64 "\n"
		       "        start errors:         %" PRIu64 "\n",
		       stats->completed, stats->start_errs);

		if (config->trs_type == ASYNC) {
			if (config->compl_mode == POLL)
				printf("        poll errors:          %" PRIu64 "\n",
				       stats->poll_errs);
			else
				printf("        scheduler timeouts:   %" PRIu64 "\n",
				       stats->scheduler_timeouts);
		}

		printf("        transfer errors:      %" PRIu64 "\n"
		       "        run time:             %" PRIu64 " ns\n",
		       stats->transfer_errs, stats->tot_tm);

		if (config->policy == MANY) {
			printf("        DMA session:\n"
			       "            average time per transfer:   %" PRIu64 " "
			       "(min: %" PRIu64 ", max: %" PRIu64 ") ns\n"
			       "            average cycles per transfer: %" PRIu64 " "
			       "(min: %" PRIu64 ", max: %" PRIu64 ")\n"
			       "            ops:                         ",
			       stats->trs_cnt > 0U ? stats->trs_tm / stats->trs_cnt : 0U,
			       stats->trs_cnt > 0U ? stats->min_trs_tm : 0U,
			       stats->trs_cnt > 0U ? stats->max_trs_tm : 0U,
			       stats->trs_cnt > 0U ? stats->trs_cc / stats->trs_cnt : 0U,
			       stats->trs_cnt > 0U ? stats->min_trs_cc : 0U,
			       stats->trs_cnt > 0U ? stats->max_trs_cc : 0U);
			print_humanised(stats->completed / (stats->tot_tm / ODP_TIME_SEC_IN_NS),
					"OPS");
			printf("            speed:                       ");
			print_humanised(stats->completed * data_cnt /
					(stats->tot_tm / ODP_TIME_SEC_IN_NS), "B/s");
		}

		avg_start_cc = stats->start_cnt > 0U ? stats->start_cc / stats->start_cnt : 0U;
		printf("        average cycles breakdown:\n");

		if (config->trs_type == SYNC) {
			printf("            odp_dma_transfer(): %" PRIu64 " "
			       "(min: %" PRIu64 ", max: %" PRIu64 ")\n", avg_start_cc,
			       avg_start_cc > 0U ? stats->min_start_cc : 0U,
			       avg_start_cc > 0U ? stats->max_start_cc : 0U);
		} else {
			printf("            odp_dma_transfer_start(): %" PRIu64 " "
			       "(min: %" PRIu64 ", max: %" PRIu64 ")\n", avg_start_cc,
			       avg_start_cc > 0U ? stats->min_start_cc : 0U,
			       avg_start_cc > 0U ? stats->max_start_cc : 0U);

			avg_wait_cc = stats->wait_cnt > 0U ? stats->wait_cc / stats->wait_cnt : 0U;

			if (config->compl_mode == POLL) {
				printf("            odp_dma_transfer_done():  %" PRIu64 ""
				       " (min: %" PRIu64 ", max: %" PRIu64 ", x %" PRIu64 ""
				       " per transfer)\n", avg_wait_cc,
				       avg_wait_cc > 0U ? stats->min_wait_cc : 0U,
				       avg_wait_cc > 0U ? stats->max_wait_cc : 0U,
				       stats->trs_cnt > 0U ?
						stats->trs_poll_cnt / stats->trs_cnt : 0U);
			} else {
				printf("            odp_schedule():           %" PRIu64 " "
				       " (min: %" PRIu64 ", max: %" PRIu64 ")\n", avg_wait_cc,
				       avg_wait_cc > 0U ? stats->min_wait_cc : 0U,
				       avg_wait_cc > 0U ? stats->max_wait_cc : 0U);
			}
		}

		printf("\n");
	}

	avg_tot_tm = tot_tm / config->num_workers / ODP_TIME_SEC_IN_NS;
	printf("    total:\n"
	       "        average time per transfer:   %" PRIu64 " (min: %" PRIu64
	       ", max: %" PRIu64 ") ns\n"
	       "        average cycles per transfer: %" PRIu64 " (min: %" PRIu64
	       ", max: %" PRIu64 ")\n"
	       "        ops:                         ",
	       tot_trs_cnt > 0U ? tot_trs_tm / tot_trs_cnt : 0U,
	       tot_trs_cnt > 0U ? tot_min_tm : 0U,
	       tot_trs_cnt > 0U ? tot_max_tm : 0U,
	       tot_trs_cnt > 0U ? tot_trs_cc / tot_trs_cnt : 0U,
	       tot_trs_cnt > 0U ? tot_min_cc : 0U,
	       tot_trs_cnt > 0U ? tot_max_cc : 0U);
	print_humanised(avg_tot_tm > 0U ? tot_completed / avg_tot_tm : 0U, "OPS");
	printf("        speed:                       ");
	print_humanised(avg_tot_tm > 0U ? tot_completed * data_cnt / avg_tot_tm : 0U, "B/s");
	printf("\n");
	printf("======================\n");
}

int main(int argc, char **argv)
{
	odph_helper_options_t odph_opts;
	odp_init_t init_param;
	odp_instance_t odp_instance;
	odp_shm_t shm_cfg = ODP_SHM_INVALID;
	parse_result_t parse_res;
	int ret = EXIT_SUCCESS;

	argc = odph_parse_options(argc, argv);

	if (odph_options(&odph_opts)) {
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

	parse_res = setup_program(argc, argv, prog_conf);

	if (parse_res == PRS_NOK) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (parse_res == PRS_TERM) {
		ret = EXIT_SUCCESS;
		goto out;
	}

	if (parse_res == PRS_NOT_SUP) {
		ret = EXIT_NOT_SUP;
		goto out;
	}

	if (odp_schedule_config(NULL) < 0) {
		ODPH_ERR("Error configuring scheduler\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	prog_conf->odp_instance = odp_instance;
	odp_atomic_init_u32(&prog_conf->is_running, 1U);

	if (!setup_test(prog_conf)) {
		ret = EXIT_FAILURE;
		goto out_test;
	}

	if (prog_conf->time_sec) {
		sleep(prog_conf->time_sec);
		odp_atomic_store_u32(&prog_conf->is_running, 0U);
	}

	stop_test(prog_conf);
	print_stats(prog_conf);

out_test:
	/* Release all resources that have been allocated during 'setup_test()'. */
	teardown_test(prog_conf);

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

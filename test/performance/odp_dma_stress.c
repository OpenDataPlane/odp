/* Copyright (c) 2023, Nokia
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

#define PROG_NAME "odp_dma_stress"

enum {
	PACKET = 0U,
	MEMORY = 1U
};

enum {
	POLL = 0U,
	EVENT = 1U
};

#define INFINITY 0U

#define DEF_SIZE 4096U
#define DEF_TYPE PACKET
#define DEF_MODE POLL
#define DEF_INFLIGHT 0U
#define DEF_TIME INFINITY
#define DEF_WORKERS 1U

#define MAX_SEGS 512U
#define MAX_WORKERS 24

#define GIGAS 1000000000
#define MEGAS 1000000
#define KILOS 1000

typedef enum {
	PRS_OK,
	PRS_NOK,
	PRS_TERM
} parse_result_t;

typedef struct {
	odp_dma_transfer_param_t trs_param;
	odp_dma_compl_param_t compl_param;
	odp_ticketlock_t lock;
	odp_bool_t is_running;
} params_t;

typedef struct prog_config_s prog_config_t;

typedef struct {
	uint64_t completed;
	uint64_t start_errs;
	uint64_t poll_errs;
	uint64_t scheduler_timeouts;
	uint64_t transfer_errs;
	uint64_t time_ns;
} stats_t;

typedef struct ODP_ALIGNED_CACHE {
	prog_config_t *prog_config;
	stats_t stats;
} thread_config_t;

typedef struct prog_config_s {
	struct {
		params_t params[MAX_SEGS];
		odp_dma_seg_t src_seg[MAX_SEGS];
		odp_dma_seg_t dst_seg[MAX_SEGS];
		odp_pool_t pool;
		odp_queue_t compl_q;
		odp_dma_t handle;
		uint32_t seg_len;
		uint32_t num_inflight;
	} dma_config;

	struct {
		odp_packet_t src_pkt[MAX_SEGS];
		odp_packet_t dst_pkt[MAX_SEGS];
		odp_pool_t pool;
		odp_shm_t src_shm;
		odp_shm_t dst_shm;
		void *src;
		void *dst;
	} seg_config;

	odph_thread_t threads[MAX_WORKERS];
	thread_config_t thread_config[MAX_WORKERS];
	odp_instance_t odp_instance;
	odp_barrier_t init_barrier;
	odp_barrier_t term_barrier;
	uint32_t time_sec;
	int num_workers;
	uint8_t trs_type;
	uint8_t compl_mode;
} prog_config_t;

typedef struct {
	odp_bool_t (*setup_fn)(prog_config_t *config);
	void (*trs_fn)(prog_config_t *config);
	odp_bool_t (*compl_fn)(prog_config_t *config);
	void (*wait_fn)(prog_config_t *prog_config, thread_config_t *thr_config);
	void (*drain_fn)(void);
	void (*free_fn)(const prog_config_t *config);
} test_api_t;

static odp_atomic_u32_t is_running;
static prog_config_t *prog_global;
static const int mode_map[] = { ODP_DMA_COMPL_POLL, ODP_DMA_COMPL_EVENT };
static test_api_t test_api;

static void terminate(int signal ODP_UNUSED)
{
	odp_atomic_store_u32(&is_running, 0U);
}

static void init_config(prog_config_t *config)
{
	params_t *params;

	memset(config, 0, sizeof(*config));
	config->dma_config.pool = ODP_POOL_INVALID;
	config->dma_config.compl_q = ODP_QUEUE_INVALID;
	config->dma_config.handle = ODP_DMA_INVALID;
	config->dma_config.seg_len = DEF_SIZE;
	config->dma_config.num_inflight = DEF_INFLIGHT;
	config->seg_config.pool = ODP_POOL_INVALID;
	config->seg_config.src_shm = ODP_SHM_INVALID;
	config->seg_config.dst_shm = ODP_SHM_INVALID;
	config->time_sec = DEF_TIME;
	config->num_workers = DEF_WORKERS;
	config->trs_type = DEF_TYPE;
	config->compl_mode = DEF_MODE;

	for (uint32_t i = 0U; i < MAX_SEGS; ++i) {
		params = &config->dma_config.params[i];

		params->compl_param.transfer_id = ODP_DMA_TRANSFER_ID_INVALID;
		params->compl_param.event = ODP_EVENT_INVALID;
		params->compl_param.queue = ODP_QUEUE_INVALID;
		odp_ticketlock_init(&params->lock);
		config->seg_config.src_pkt[i] = ODP_PACKET_INVALID;
		config->seg_config.dst_pkt[i] = ODP_PACKET_INVALID;
	}
}

static void print_usage(void)
{
	printf("\n"
	       "DMA stress test. Load DMA subsystem from several workers.\n"
	       "\n"
	       "Examples:\n"
	       "    " PROG_NAME " -s 131072 -t 1 -m 0 -f 10 -T 60 -c 1\n"
	       "\n"
	       "Usage: " PROG_NAME " [options]\n"
	       "\n"
	       "  -s, --in_seg_size	    Input segment size in bytes. %u bytes by default.\n"
	       "  -t, --in_seg_type         Input segment data type. %u by default.\n"
	       "                            Types:\n"
	       "                                0: packet\n"
	       "                                1: memory\n"
	       "  -m, --compl_mode          Completion mode for transfers. %u by default.\n"
	       "                            Modes:\n"
	       "                                0: poll\n"
	       "                                1: event\n"
	       "  -f, --max_in_flight       Max transfers in-flight. 0 means the maximum\n"
	       "                            supported by tester/implementation. %u by default.\n"
	       "  -T, --time_sec            Time in seconds to run. 0 means infinite. %u by\n"
	       "                            default.\n"
	       "  -c, --worker_count        Amount of workers. %u by default.\n"
	       "  -h, --help                This help.\n"
	       "\n", DEF_SIZE, DEF_TYPE, DEF_MODE, DEF_INFLIGHT, DEF_TIME, DEF_WORKERS);
}

static parse_result_t check_options(prog_config_t *config)
{
	int max_workers;
	odp_dma_capability_t dma_capa;
	uint32_t max_trs;
	odp_pool_capability_t pool_capa;
	odp_shm_capability_t shm_capa;
	uint64_t shm_size = 0U;

	if (config->trs_type != PACKET && config->trs_type != MEMORY) {
		ODPH_ERR("Invalid transfer type: %u.\n", config->trs_type);
		return PRS_NOK;
	}

	if (config->compl_mode != POLL && config->compl_mode != EVENT) {
		ODPH_ERR("Invalid completion mode: %u.\n", config->compl_mode);
		return PRS_NOK;
	}

	max_workers = odp_thread_count_max() - 1 > MAX_WORKERS ? MAX_WORKERS :
								 odp_thread_count_max() - 1;

	if (config->num_workers <= 0 || config->num_workers > max_workers) {
		ODPH_ERR("Invalid thread count: %d (min: 1, max: %d)\n", config->num_workers,
			 max_workers);
		return PRS_NOK;
	}

	if (odp_dma_capability(&dma_capa) < 0) {
		ODPH_ERR("Error querying DMA capabilities.\n");
		return PRS_NOK;
	}

	if (dma_capa.max_sessions == 0U) {
		ODPH_ERR("DMA not supported.\n");
		return PRS_NOK;
	}

	if (config->dma_config.seg_len > dma_capa.max_seg_len) {
		ODPH_ERR("Unsupported total DMA segment size: %u (max: %u).\n",
			 config->dma_config.seg_len, dma_capa.max_seg_len);
		return PRS_NOK;
	}

	if (config->compl_mode == POLL &&
	    (dma_capa.compl_mode_mask & ODP_DMA_COMPL_POLL) == 0U) {
		ODPH_ERR("Unsupported DMA completion mode, poll.\n");
		return PRS_NOK;
	}

	if (config->compl_mode == EVENT &&
	    (dma_capa.compl_mode_mask & ODP_DMA_COMPL_EVENT) == 0U) {
		ODPH_ERR("Unsupported DMA completion mode, event.\n");
		return PRS_NOK;
	}

	if (config->compl_mode == EVENT && dma_capa.queue_type_sched == 0) {
		ODPH_ERR("Unsupported DMA queueing type, scheduled.\n");
		return PRS_NOK;
	}

	max_trs = dma_capa.max_transfers > MAX_SEGS ? MAX_SEGS : dma_capa.max_transfers;

	if (config->dma_config.num_inflight > max_trs) {
		ODPH_ERR("Unsupported amount of in-flight DMA transfers: %u (max: %u).\n",
			 config->dma_config.num_inflight, max_trs);
		return PRS_NOK;
	}

	if (config->dma_config.num_inflight == 0U)
		config->dma_config.num_inflight = dma_capa.max_transfers > MAX_SEGS ?
			MAX_SEGS : dma_capa.max_transfers;

	if (config->compl_mode == EVENT &&
	    config->dma_config.num_inflight > dma_capa.pool.max_num) {
		ODPH_ERR("Unsupported amount of completion events: %u (max: %u).\n",
			 config->dma_config.num_inflight, dma_capa.pool.max_num);
		return PRS_NOK;
	}

	if (config->trs_type == PACKET) {
		if (odp_pool_capability(&pool_capa) < 0) {
			ODPH_ERR("Error querying pool capabilities.\n");
			return PRS_NOK;
		}

		if (pool_capa.pkt.max_len != 0U &&
		    config->dma_config.seg_len > pool_capa.pkt.max_len) {
			ODPH_ERR("Unsupported packet size: %u (max: %u).\n",
				 config->dma_config.seg_len, pool_capa.pkt.max_len);
			return PRS_NOK;
		}

		if (pool_capa.pkt.max_num != 0U &&
		    config->dma_config.num_inflight * 2U > pool_capa.pkt.max_num) {
			ODPH_ERR("Unsupported amount of packet pool elements: %u (max: %u).\n",
				 config->dma_config.num_inflight * 2U, pool_capa.pkt.max_num);
			return PRS_NOK;
		}
	} else {
		/* If SHM implementation capabilities are very puny, program will have already
		 * failed when reserving memory for global program configuration. */
		if (odp_shm_capability(&shm_capa) < 0) {
			ODPH_ERR("Error querying SHM capabilities.\n");
			return PRS_NOK;
		}

		/* One block for program configuration, one for source memory and one for
		 * destination memory. */
		if (shm_capa.max_blocks < 3U) {
			ODPH_ERR("Unsupported amount of SHM blocks: 3 (max: %u).\n",
				 shm_capa.max_blocks);
			return PRS_NOK;
		}

		shm_size = config->dma_config.seg_len * config->dma_config.num_inflight;

		if (shm_capa.max_size != 0U && shm_size > shm_capa.max_size) {
			ODPH_ERR("Unsupported total SHM block size: %" PRIu64 ""
				 " (max: %" PRIu64 ").\n", shm_size, shm_capa.max_size);
			return PRS_NOK;
		}
	}

	return PRS_OK;
}

static parse_result_t parse_options(int argc, char **argv, prog_config_t *config)
{
	int opt, long_index;

	static const struct option longopts[] = {
		{ "in_seg_size", required_argument, NULL, 's' },
		{ "in_seg_type", required_argument, NULL, 't' },
		{ "compl_mode", required_argument, NULL, 'm' },
		{ "max_in_flight", required_argument, NULL, 'f'},
		{ "time_sec", required_argument, NULL, 'T' },
		{ "worker_count", required_argument, NULL, 'c' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "s:t:m:f:T:c:h";

	init_config(config);

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 's':
			config->dma_config.seg_len = atoi(optarg);
			break;
		case 't':
			config->trs_type = atoi(optarg);
			break;
		case 'm':
			config->compl_mode = atoi(optarg);
			break;
		case 'f':
			config->dma_config.num_inflight = atoi(optarg);
			break;
		case 'T':
			config->time_sec = atoi(optarg);
			break;
		case 'c':
			config->num_workers = atoi(optarg);
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

static odp_bool_t configure_packets(prog_config_t *config)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_PACKET;
	/* Source and destination packets. */
	param.pkt.num = config->dma_config.num_inflight * 2U;
	param.pkt.len = config->dma_config.seg_len;
	config->seg_config.pool = odp_pool_create(PROG_NAME "_seg_pkts", &param);

	if (config->seg_config.pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error creating packet pool.\n");
		return false;
	}

	return true;
}

static odp_bool_t allocate_packets(prog_config_t *config)
{
	for (uint32_t i = 0U; i < config->dma_config.num_inflight; ++i) {
		config->seg_config.src_pkt[i] = odp_packet_alloc(config->seg_config.pool,
								 config->dma_config.seg_len);
		config->seg_config.dst_pkt[i] = odp_packet_alloc(config->seg_config.pool,
								 config->dma_config.seg_len);
		if (config->seg_config.src_pkt[i] == ODP_PACKET_INVALID ||
		    config->seg_config.dst_pkt[i] == ODP_PACKET_INVALID) {
			ODPH_ERR("Error allocating segment packets.\n");
			return false;
		}
	}

	return true;
}

static odp_bool_t setup_packet_segments(prog_config_t *config)
{
	return configure_packets(config) && allocate_packets(config);
}

static void configure_packet_dma_transfer(prog_config_t *config)
{
	odp_packet_t src_pkt, dst_pkt;
	odp_dma_seg_t *src_seg, *dst_seg;
	odp_dma_transfer_param_t *param;

	for (uint32_t i = 0U; i < config->dma_config.num_inflight; ++i) {
		src_pkt = config->seg_config.src_pkt[i];
		dst_pkt = config->seg_config.dst_pkt[i];
		src_seg = &config->dma_config.src_seg[i];
		dst_seg = &config->dma_config.dst_seg[i];
		param = &config->dma_config.params[i].trs_param;

		src_seg->packet = src_pkt;
		src_seg->offset = 0U;
		src_seg->len = odp_packet_len(src_pkt);
		dst_seg->packet = dst_pkt;
		dst_seg->len = odp_packet_len(dst_pkt);
		odp_dma_transfer_param_init(param);
		param->src_format = ODP_DMA_FORMAT_PACKET;
		param->dst_format = ODP_DMA_FORMAT_PACKET;
		param->num_src = 1U;
		param->num_dst = 1U;
		param->src_seg = src_seg;
		param->dst_seg = dst_seg;
	}
}

static void free_packets(const prog_config_t *config)
{
	for (uint32_t i = 0U; i < config->dma_config.num_inflight; ++i) {
		if (config->seg_config.src_pkt[i] != ODP_PACKET_INVALID)
			odp_packet_free(config->seg_config.src_pkt[i]);

		if (config->seg_config.dst_pkt[i] != ODP_PACKET_INVALID)
			odp_packet_free(config->seg_config.dst_pkt[i]);
	}

	if (config->seg_config.pool != ODP_POOL_INVALID)
		(void)odp_pool_destroy(config->seg_config.pool);
}

static odp_bool_t allocate_memory(prog_config_t *config)
{
	const uint64_t shm_size = config->dma_config.seg_len * config->dma_config.num_inflight;

	config->seg_config.src_shm = odp_shm_reserve(PROG_NAME "_src_shm", shm_size,
						     ODP_CACHE_LINE_SIZE, 0);
	config->seg_config.dst_shm = odp_shm_reserve(PROG_NAME "_dst_shm", shm_size,
						     ODP_CACHE_LINE_SIZE, 0);

	if (config->seg_config.src_shm == ODP_SHM_INVALID ||
	    config->seg_config.dst_shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error allocating SHM block.\n");
		return false;
	}

	config->seg_config.src = odp_shm_addr(config->seg_config.src_shm);
	config->seg_config.dst = odp_shm_addr(config->seg_config.dst_shm);

	if (config->seg_config.src == NULL || config->seg_config.dst == NULL) {
		ODPH_ERR("Error resolving SHM block address.\n");
		return false;
	}

	return true;
}

static odp_bool_t setup_memory_segments(prog_config_t *config)
{
	return allocate_memory(config);
}

static void configure_address_dma_transfer(prog_config_t *config)
{
	odp_dma_seg_t *src_seg, *dst_seg;
	odp_dma_transfer_param_t *param;

	for (uint32_t i = 0U; i < config->dma_config.num_inflight; ++i) {
		src_seg = &config->dma_config.src_seg[i];
		dst_seg = &config->dma_config.dst_seg[i];
		param = &config->dma_config.params[i].trs_param;

		src_seg->addr = (uint8_t *)config->seg_config.src + i * config->dma_config.seg_len;
		src_seg->len = config->dma_config.seg_len;
		dst_seg->addr = (uint8_t *)config->seg_config.dst + i * config->dma_config.seg_len;
		dst_seg->len = config->dma_config.seg_len;
		odp_dma_transfer_param_init(param);
		param->src_format = ODP_DMA_FORMAT_ADDR;
		param->dst_format = ODP_DMA_FORMAT_ADDR;
		param->num_src = 1U;
		param->num_dst = 1U;
		param->src_seg = src_seg;
		param->dst_seg = dst_seg;
	}
}

static void free_memory(const prog_config_t *config)
{
	if (config->seg_config.src_shm != ODP_SHM_INVALID)
		(void)odp_shm_free(config->seg_config.src_shm);

	if (config->seg_config.dst_shm != ODP_SHM_INVALID)
		(void)odp_shm_free(config->seg_config.dst_shm);
}

static odp_bool_t configure_poll_compl(prog_config_t *config)
{
	odp_dma_compl_param_t *param;

	for (uint32_t i = 0U; i < config->dma_config.num_inflight; ++i) {
		param = &config->dma_config.params[i].compl_param;

		odp_dma_compl_param_init(param);
		param->compl_mode = mode_map[config->compl_mode];
		param->transfer_id = odp_dma_transfer_id_alloc(config->dma_config.handle);

		if (param->transfer_id == ODP_DMA_TRANSFER_ID_INVALID) {
			ODPH_ERR("Error allocating transfer ID.\n");
			return false;
		}
	}

	return true;
}

static void poll_transfer(odp_dma_t handle, params_t *params, stats_t *stats)
{
	odp_dma_result_t res;
	int done;

	if (params->is_running) {
		done = odp_dma_transfer_done(handle, params->compl_param.transfer_id, &res);

		if (done == 0)
			return;

		if (done < 0) {
			++stats->poll_errs;
			return;
		}

		if (res.success)
			++stats->completed;
		else
			++stats->transfer_errs;

		params->is_running = false;
	} else {
		if (odp_dma_transfer_start(handle, &params->trs_param, &params->compl_param) <= 0)
			++stats->start_errs;
		else
			params->is_running = true;
	}
}

static void poll_transfers_mt_safe(prog_config_t *prog_config, thread_config_t *thr_config)
{
	const uint32_t count = prog_config->dma_config.num_inflight;
	odp_dma_t handle = prog_config->dma_config.handle;
	params_t *params = prog_config->dma_config.params, *param;
	stats_t *stats = &thr_config->stats;

	for (uint32_t i = 0U; i < count; ++i) {
		param = &params[i];

		if (odp_ticketlock_trylock(&param->lock)) {
			poll_transfer(handle, param, stats);
			odp_ticketlock_unlock(&param->lock);
		}
	}
}

static void poll_transfers_mt_unsafe(prog_config_t *prog_config, thread_config_t *thr_config)
{
	const uint32_t count = prog_config->dma_config.num_inflight;
	odp_dma_t handle = prog_config->dma_config.handle;
	params_t *params = prog_config->dma_config.params;
	stats_t *stats = &thr_config->stats;

	for (uint32_t i = 0U; i < count; ++i)
		poll_transfer(handle, &params[i], stats);
}

static odp_bool_t configure_event_compl(prog_config_t *config)
{
	odp_dma_compl_param_t *param;
	odp_dma_compl_t c_ev;

	for (uint32_t i = 0U; i < config->dma_config.num_inflight; ++i) {
		param = &config->dma_config.params[i].compl_param;

		odp_dma_compl_param_init(param);
		param->compl_mode = mode_map[config->compl_mode];
		c_ev = odp_dma_compl_alloc(config->dma_config.pool);

		if (c_ev == ODP_DMA_COMPL_INVALID) {
			ODPH_ERR("Error allocating completion event.\n");
			return false;
		}

		param->event = odp_dma_compl_to_event(c_ev);
		param->queue = config->dma_config.compl_q;
		param->user_ptr = &config->dma_config.params[i];
	}

	return true;
}

static void wait_compl_events(prog_config_t *prog_config, thread_config_t *thr_config)
{
	odp_event_t ev;
	odp_dma_result_t res;
	params_t *params;

	ev = odp_schedule(NULL, odp_schedule_wait_time(ODP_TIME_SEC_IN_NS));

	if (ev == ODP_EVENT_INVALID) {
		++thr_config->stats.scheduler_timeouts;
		return;
	}

	odp_dma_compl_result(odp_dma_compl_from_event(ev), &res);

	if (res.success)
		++thr_config->stats.completed;
	else
		++thr_config->stats.transfer_errs;

	params = res.user_ptr;

	if (odp_dma_transfer_start(prog_config->dma_config.handle, &params->trs_param,
				   &params->compl_param) <= 0)
		++thr_config->stats.start_errs;
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
	if (config->trs_type == PACKET) {
		test_api.setup_fn = setup_packet_segments;
		test_api.trs_fn = configure_packet_dma_transfer;
		test_api.free_fn = free_packets;
	} else {
		test_api.setup_fn = setup_memory_segments;
		test_api.trs_fn = configure_address_dma_transfer;
		test_api.free_fn = free_memory;
	}

	if (config->compl_mode == POLL) {
		test_api.compl_fn = configure_poll_compl;
		test_api.wait_fn = config->num_workers == 1 ? poll_transfers_mt_unsafe :
							      poll_transfers_mt_safe;
		test_api.drain_fn = NULL;
	} else {
		test_api.compl_fn = configure_event_compl;
		test_api.wait_fn = wait_compl_events;
		test_api.drain_fn = drain_compl_events;
	}
}

static odp_bool_t setup_dma(prog_config_t *config)
{
	const odp_dma_param_t dma_params = {
		.direction = ODP_DMA_MAIN_TO_MAIN,
		.type = ODP_DMA_TYPE_COPY,
		.compl_mode_mask = mode_map[config->compl_mode],
		.mt_mode = ODP_DMA_MT_SAFE,
		.order = ODP_DMA_ORDER_NONE };
	odp_dma_pool_param_t pool_param;
	odp_queue_param_t queue_param;

	config->dma_config.handle = odp_dma_create(PROG_NAME "_dma", &dma_params);

	if (config->dma_config.handle == ODP_DMA_INVALID) {
		ODPH_ERR("Error creating DMA session.\n");
		return false;
	}

	odp_dma_pool_param_init(&pool_param);
	pool_param.num = config->dma_config.num_inflight;
	config->dma_config.pool = odp_dma_pool_create(PROG_NAME "_dma_evs", &pool_param);

	if (config->dma_config.pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error creating DMA event completion pool.\n");
		return false;
	}

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	queue_param.sched.prio = odp_schedule_default_prio();
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	config->dma_config.compl_q = odp_queue_create(PROG_NAME, &queue_param);

	if (config->dma_config.compl_q == ODP_QUEUE_INVALID) {
		ODPH_ERR("Error creating DMA completion queue.\n");
		return false;
	}

	return true;
}

static odp_bool_t setup_data(prog_config_t *config)
{
	if (!test_api.setup_fn(config))
		return false;

	test_api.trs_fn(config);

	if (!test_api.compl_fn(config))
		return false;

	return true;
}

static int transfer(void *args)
{
	thread_config_t *thr_config = args;
	prog_config_t *prog_config = thr_config->prog_config;
	uint64_t start = 0U, end = 0U;

	odp_barrier_wait(&prog_config->init_barrier);
	start = odp_time_local_ns();

	while (odp_atomic_load_u32(&is_running))
		test_api.wait_fn(prog_config, thr_config);

	end = odp_time_local_ns();
	thr_config->stats.time_ns = end - start;

	if (test_api.drain_fn)
		test_api.drain_fn();

	odp_barrier_wait(&prog_config->term_barrier);

	return 0;
}

static odp_bool_t start_initial(prog_config_t *config)
{
	params_t *params;

	for (uint32_t i = 0U; i < config->dma_config.num_inflight; ++i) {
		params = &config->dma_config.params[i];

		if (odp_dma_transfer_start(config->dma_config.handle, &params->trs_param,
					   &params->compl_param) <= 0) {
			ODPH_ERR("Error starting DMA transfer.\n");
			return false;
		}
	}

	return true;
}

static odp_bool_t setup_workers(prog_config_t *config)
{
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_params[config->num_workers], *thr_param;
	odp_cpumask_t cpumask;
	int num_workers;
	thread_config_t *thr_config;

	/* Barrier init count for control and worker. */
	odp_barrier_init(&config->init_barrier, config->num_workers + 1);
	odp_barrier_init(&config->term_barrier, config->num_workers + 1);
	num_workers = odp_cpumask_default_worker(&cpumask, config->num_workers);
	odph_thread_common_param_init(&thr_common);
	thr_common.instance = config->odp_instance;
	thr_common.cpumask = &cpumask;

	for (int i = 0; i < config->num_workers; ++i) {
		thr_param = &thr_params[i];
		thr_config = &config->thread_config[i];

		odph_thread_param_init(thr_param);
		thr_param->start = transfer;
		thr_param->thr_type = ODP_THREAD_WORKER;
		thr_config->prog_config = config;
		thr_param->arg = thr_config;
	}

	num_workers = odph_thread_create(config->threads, &thr_common, thr_params, num_workers);

	if (num_workers != config->num_workers) {
		ODPH_ERR("Error configuring worker threads\n");
		return false;
	}

	if (config->compl_mode == EVENT) {
		if (!start_initial(config))
			return false;
	}

	odp_barrier_wait(&config->init_barrier);

	return true;
}

static odp_bool_t setup_test(prog_config_t *config)
{
	setup_api(config);

	return setup_dma(config) && setup_data(config) && setup_workers(config);
}

static void teardown_data(const prog_config_t *config)
{
	const odp_dma_compl_param_t *compl_param;

	for (uint32_t i = 0U; i < MAX_SEGS; ++i) {
		compl_param = &config->dma_config.params[i].compl_param;

		if (compl_param->transfer_id != ODP_DMA_TRANSFER_ID_INVALID)
			odp_dma_transfer_id_free(config->dma_config.handle,
						 compl_param->transfer_id);

		if (compl_param->event != ODP_EVENT_INVALID)
			odp_event_free(compl_param->event);
	}

	test_api.free_fn(config);
}

static void stop_test(prog_config_t *config)
{
	odp_barrier_wait(&config->term_barrier);
	(void)odph_thread_join(config->threads, config->num_workers);
	teardown_data(config);

	if (config->dma_config.compl_q != ODP_QUEUE_INVALID)
		(void)odp_queue_destroy(config->dma_config.compl_q);

	if (config->dma_config.pool != ODP_POOL_INVALID)
		(void)odp_pool_destroy(config->dma_config.pool);

	if (config->dma_config.handle != ODP_DMA_INVALID)
		(void)odp_dma_destroy(config->dma_config.handle);
}

static void print_humanised_speed(uint64_t speed)
{
	if (speed > GIGAS)
		printf("%.2f GOPS\n", (double)speed / GIGAS);
	else if (speed > MEGAS)
		printf("%.2f MOPS\n", (double)speed / MEGAS);
	else if (speed > KILOS)
		printf("%.2f KOPS\n", (double)speed / KILOS);
	else
		printf("%" PRIu64 " OPS\n", speed);
}

static void print_stats(prog_config_t *config)
{
	stats_t *stats;
	uint64_t speed, tot_speed = 0U;

	printf("\n======================\n\n"
	       "DMA stress test done\n\n"
	       "    segment size:    %u\n"
	       "    segment type:    %s\n"
	       "    completion mode: %s\n"
	       "    inflight count:  %u\n\n", config->dma_config.seg_len,
	       config->trs_type == PACKET ? "packet" : "memory",
	       config->compl_mode == POLL ? "poll" : "event", config->dma_config.num_inflight);

	for (int i = 0; i < config->num_workers; ++i) {
		stats = &config->thread_config[i].stats;

		printf("    Worker %d:\n"
		       "        transfers:          %" PRIu64 "\n"
		       "        start errors:       %" PRIu64 "\n", i, stats->completed,
		       stats->start_errs);

		if (config->compl_mode == POLL)
			printf("        poll errors:        %" PRIu64 "\n", stats->poll_errs);
		else
			printf("        scheduler timeouts: %" PRIu64 "\n",
			       stats->scheduler_timeouts);

		speed = stats->completed / (stats->time_ns / ODP_TIME_SEC_IN_NS);
		tot_speed += speed;
		printf("        transfer errors:    %" PRIu64 "\n"
		       "        run time:           %" PRIu64 " ns\n"
		       "        ops/sec:            ", stats->transfer_errs, stats->time_ns);
		print_humanised_speed(speed);
		printf("\n");
	}

	printf("    total speed:     ");
	print_humanised_speed(tot_speed);
	printf("\n");
	printf("======================\n");
}

int main(int argc, char **argv)
{
	odp_instance_t odp_instance;
	odp_shm_t shm;
	parse_result_t parse_res;
	int ret = EXIT_SUCCESS;

	if (odp_init_global(&odp_instance, NULL, NULL)) {
		ODPH_ERR("ODP global init failed, exiting.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(odp_instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("ODP local init failed, exiting.\n");
		exit(EXIT_FAILURE);
	}

	shm = odp_shm_reserve(PROG_NAME "_args", sizeof(prog_config_t), ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error reserving shared memory\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	prog_global = odp_shm_addr(shm);

	if (prog_global == NULL) {
		ODPH_ERR("Error resolving shared memory address\n");
		ret = EXIT_FAILURE;
		goto out_shm;
	}

	parse_res = setup_program(argc, argv, prog_global);

	if (parse_res == PRS_NOK) {
		ret = EXIT_FAILURE;
		goto out_shm;
	}

	if (parse_res == PRS_TERM) {
		ret = EXIT_SUCCESS;
		goto out_shm;
	}

	if (odp_schedule_config(NULL) < 0) {
		ODPH_ERR("Error configuring scheduler.\n");
		ret = EXIT_FAILURE;
		goto out_shm;
	}

	prog_global->odp_instance = odp_instance;
	odp_atomic_init_u32(&is_running, 1U);

	if (!setup_test(prog_global)) {
		ret = EXIT_FAILURE;
		goto out_shm;
	}

	if (prog_global->time_sec) {
		sleep(prog_global->time_sec);
		odp_atomic_store_u32(&is_running, 0U);
	}

	stop_test(prog_global);
	print_stats(prog_global);

out_shm:
	if (odp_shm_free(shm)) {
		ODPH_ERR("Error freeing shared memory\n");
		ret = EXIT_FAILURE;
	}

out:
	if (odp_term_local()) {
		ODPH_ERR("ODP local terminate failed, exiting.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(odp_instance)) {
		ODPH_ERR("ODP global terminate failed, exiting.\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}

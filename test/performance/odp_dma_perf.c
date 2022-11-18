/* Copyright (c) 2021-2022, Nokia
 *
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#define EXIT_NOT_SUP 2

#define DEFAULT_SEG_SIZE 1024U
#define ROUNDS 1000000
#define DEFAULT_WAIT_NS ODP_TIME_SEC_IN_NS
#define COMPL_DELIMITER ","
/* For now, a static maximum amount of input segments */
#define MAX_NUM_IN_SEGS 64
#define SHM_SRC "odp_dma_perf_shm_src"
#define SHM_DST "odp_dma_perf_shm_dst"

#define TRS_TYPE_SYNC 0
#define TRS_TYPE_ASYNC 1

#define GRN_ALL 0
#define GRN_IND 1

#define TYPE_PKT 0
#define TYPE_MEM 1

#define COMPL_MODE_POLL 0
#define COMPL_MODE_EVENT 1

#define GIGAS 1000000000
#define MEGAS 1000000
#define KILOS 1000

typedef struct test_config_t {
	int trs_type;
	int trs_grn;
	int num_in_seg;
	uint32_t seg_size;
	int seg_type;
	int num_rounds;
	int dma_rounds;
	uint64_t wait_ns;

	struct {
		int num_modes;
		uint32_t compl_mask;
		int modes[MAX_NUM_IN_SEGS];
	} compl_modes;

	struct {
		odp_pool_t pool;
		odp_queue_t compl_q;
		odp_dma_t handle;
		odp_dma_seg_t dst_seg;
		odp_dma_seg_t src_seg[MAX_NUM_IN_SEGS];
	} dma_config;

	union {
		struct {
			odp_shm_t shm_src;
			odp_shm_t shm_dst;
			void *src;
			void *dst;
		};

		struct {
			odp_pool_t pool;
			odp_packet_t pkts[MAX_NUM_IN_SEGS + 1];
		};
	} seg_config;

	struct {
		int (*setup_fn)(struct test_config_t *config);
		void (*trs_base_fn)(struct test_config_t *config,
				    odp_dma_transfer_param_t *trs_params, uint32_t *trs_lengths);
		void (*trs_dyn_fn)(struct test_config_t *config, uint32_t offset, uint32_t len);
		int (*verify_fn)(const struct test_config_t *config);
		void (*free_fn)(struct test_config_t *config);
		int (*run_fn)(struct test_config_t *config);
	} test_case_api;
} test_config_t;

typedef struct compl_wait_entry_t {
	int type;
	odp_dma_transfer_id_t id;
} compl_wait_entry_t;

static const int compl_mode_map[] = { ODP_DMA_COMPL_POLL, ODP_DMA_COMPL_EVENT };

static void set_option_defaults(test_config_t *config)
{
	memset(config, 0, sizeof(*config));
	config->num_in_seg = 1;
	config->seg_size = DEFAULT_SEG_SIZE;
	config->num_rounds = ROUNDS;
	config->wait_ns = DEFAULT_WAIT_NS;
	config->compl_modes.compl_mask = ODP_DMA_COMPL_SYNC;
}

static void parse_completion_modes(test_config_t *config, const char *optarg)
{
	char *tmp_str = strdup(optarg);
	char *tmp;
	int mode;
	uint32_t i = 0U;

	config->compl_modes.num_modes = 0;

	if (tmp_str == NULL)
		return;

	tmp = strtok(tmp_str, COMPL_DELIMITER);

	while (tmp) {
		mode = atoi(tmp);
		config->compl_modes.modes[i] = mode;
		config->compl_modes.compl_mask |= compl_mode_map[mode];
		++i;
		++config->compl_modes.num_modes;
		tmp = strtok(NULL, COMPL_DELIMITER);
	}

	free(tmp_str);
}

static void print_usage(void)
{
	printf("\n"
	       "DMA performance test. Transfers a set of source segments to a single destination\n"
	       "segment.\n"
	       "\n"
	       "Examples:\n"
	       "    odp_dma_perf\n"
	       "    odp_dma_perf -t 0 -g 1 -i 2\n"
	       "    odp_dma_perf -t 1 -g 1 -i 4 -m 0,0,0,0\n"
	       "    odp_dma_perf -t 1 -g 1 -i 7 -m 0,0,0,0,0,0,1 -T 1 -r 1000 -s 2048\n"
	       "\n"
	       "Usage: odp_dma_perf [options]\n"
	       "\n"
	       "  -t, --trs_type            Transfer type for test data. Synchronous by default.\n"
	       "                            Types:\n"
	       "                                0: synchronous\n"
	       "                                1: asynchronous\n"
	       "  -g, --trs_grn             Transfer granularity for source segments. All\n"
	       "                            segments are sent in one transfer by default.\n"
	       "                            Options:\n"
	       "                                0: all segments in a single transfer\n"
	       "                                1: individual transfers for segments\n"
	       "  -i, --num_in_seg          Number of input segments to transfer. 1 by\n"
	       "                            default. Maximum supported amount is %d.\n"
	       "  -s, --in_seg_size	    Segment size for all input segments in bytes. 1024\n"
	       "                            bytes by default. Maximum allowed destination\n"
	       "                            segment size may limit this choice.\n"
	       "  -T, --in_seg_type         Input segment data type. Packet by default.\n"
	       "                            Types:\n"
	       "                                0: packet\n"
	       "                                1: memory\n"
	       "  -m, --compl_modes         Completion mode(s) for transfers delimited by a\n"
	       "                            comma. Only applicable in asynchronous mode.\n"
	       "                            Modes:\n"
	       "                                0: poll\n"
	       "                                1: event\n"
	       "  -r, --num_rounds          Number of times to run the test scenario. %d by\n"
	       "                            default.\n"
	       "  -w, --wait_nsec           Number of nanoseconds to wait for completion events.\n"
	       "                            1 second (1000000000) by default.\n"
	       "  -h, --help                This help.\n"
	       "\n",
	       MAX_NUM_IN_SEGS, ROUNDS);
}

static int check_completion_modes(test_config_t *config)
{
	if (config->trs_type == TRS_TYPE_SYNC)
		return 0;

	if (config->compl_modes.num_modes > MAX_NUM_IN_SEGS)
		return -1;

	if (config->trs_grn == GRN_IND &&
	    config->num_in_seg != config->compl_modes.num_modes)
		return -1;

	if (config->trs_grn == GRN_ALL &&
	    config->compl_modes.num_modes != 1)
		return -1;

	for (int i = 0; i < config->compl_modes.num_modes; ++i) {
		if (config->compl_modes.modes[i] != COMPL_MODE_POLL &&
		    config->compl_modes.modes[i] != COMPL_MODE_EVENT)
			return -1;

		config->compl_modes.modes[i] = compl_mode_map[config->compl_modes.modes[i]];
	}

	return 0;
}

static int check_options(test_config_t *config)
{
	if (config->trs_type != TRS_TYPE_SYNC &&
	    config->trs_type != TRS_TYPE_ASYNC) {
		ODPH_ERR("Invalid transfer type: %d.\n", config->trs_type);
		return -1;
	}

	if (config->trs_grn != GRN_ALL && config->trs_grn != GRN_IND) {
		ODPH_ERR("Invalid granularity: %d.\n", config->trs_grn);
		return -1;
	}

	config->dma_rounds = config->trs_grn == GRN_IND ? config->num_in_seg : 1;

	if (config->num_in_seg < 1 || config->num_in_seg > MAX_NUM_IN_SEGS) {
		ODPH_ERR("Invalid number of input segments: %d.\n", config->num_in_seg);
		return -1;
	}

	if (config->seg_type != TYPE_PKT && config->seg_type != TYPE_MEM) {
		ODPH_ERR("Invalid input segment type: %d.\n", config->seg_type);
		return -1;
	}

	if (check_completion_modes(config)) {
		ODPH_ERR("Invalid completion modes.\n");
		return -1;
	}

	if (config->num_rounds < 1) {
		ODPH_ERR("Invalid number of rounds: %d.\n", config->num_rounds);
		return -1;
	}

	return 0;
}

static int parse_options(int argc, char **argv, test_config_t *config)
{
	int opt, long_index;

	static const struct option longopts[] = {
		{ "trs_type", required_argument, NULL, 't' },
		{ "trs_grn", required_argument, NULL, 'g' },
		{ "num_in_seg", required_argument, NULL, 'i' },
		{ "in_seg_size", required_argument, NULL, 's' },
		{ "in_seg_type", required_argument, NULL, 'T' },
		{ "compl_modes", required_argument, NULL, 'm' },
		{ "num_rounds", required_argument, NULL, 'r' },
		{ "wait_nsec", required_argument, NULL, 'w' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	static const char *shortopts = "t:g:i:s:T:m:r:w:h";

	set_option_defaults(config);

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 't':
			config->trs_type = atoi(optarg);
			break;
		case 'g':
			config->trs_grn = atoi(optarg);
			break;
		case 'i':
			config->num_in_seg = atoi(optarg);
			break;
		case 's':
			config->seg_size = atoi(optarg);
			break;
		case 'T':
			config->seg_type = atoi(optarg);
			break;
		case 'm':
			parse_completion_modes(config, optarg);
			break;
		case 'r':
			config->num_rounds = atoi(optarg);
			break;
		case 'w':
			config->wait_ns = atoll(optarg);
			break;
		case 'h':
		default:
			print_usage();
			return -1;
		}
	}

	if (check_options(config))
		return -1;

	return 0;
}

static int check_shm_capabilities(const test_config_t *config)
{
	odp_shm_capability_t capa;

	if (odp_shm_capability(&capa)) {
		ODPH_ERR("Error querying SHM capabilities.\n");
		return -1;
	}

	if (capa.max_blocks < 2U) {
		ODPH_ERR("Unsupported amount of SHM blocks.\n");
		return -1;
	}

	if (capa.max_size != 0U && config->num_in_seg * config->seg_size > capa.max_size) {
		ODPH_ERR("Unsupported total SHM block size.\n");
		return -1;
	}

	if (capa.max_align != 0U && capa.max_align < ODP_CACHE_LINE_SIZE) {
		ODPH_ERR("Unsupported SHM block alignment size.\n");
		return -1;
	}

	return 0;
}

static int check_dma_capabilities(const test_config_t *config)
{
	odp_dma_capability_t capa;
	const int is_event = config->compl_modes.compl_mask & ODP_DMA_COMPL_EVENT;
	uint32_t event_compl_count = 0U;

	if (odp_dma_capability(&capa)) {
		ODPH_ERR("Error querying DMA capabilities.\n");
		return -1;
	}

	if (capa.max_sessions == 0U) {
		ODPH_ERR("DMA not supported.\n");
		return -1;
	}

	if (config->trs_type == TRS_TYPE_ASYNC) {
		if ((config->compl_modes.compl_mask & ODP_DMA_COMPL_POLL) &&
		    (capa.compl_mode_mask & ODP_DMA_COMPL_POLL) == 0U) {
			ODPH_ERR("Unsupported DMA completion mode, poll.\n");
			return -1;
		}

		if (is_event && (capa.compl_mode_mask & ODP_DMA_COMPL_EVENT) == 0U) {
			ODPH_ERR("Unsupported DMA completion mode, event.\n");
			return -1;
		}

		if (is_event && capa.queue_type_sched == 0) {
			ODPH_ERR("Unsupported DMA queueing type.\n");
			return -1;
		}

		if (config->trs_grn == GRN_IND) {
			if ((uint32_t)config->num_in_seg > capa.max_transfers) {
				ODPH_ERR("Unsupported amount of in-flight DMA transfers.\n");
				return -1;
			}

			for (int i = 0; i < config->compl_modes.num_modes; ++i)
				if (config->compl_modes.modes[i] == ODP_DMA_COMPL_EVENT)
					++event_compl_count;

			if (event_compl_count > capa.pool.max_num) {
				ODPH_ERR("Unsupported amount of completion events.\n");
				return -1;
			}
		}
	}

	if (config->trs_grn == GRN_ALL) {
		if ((uint32_t)config->num_in_seg > capa.max_src_segs) {
			ODPH_ERR("Unsupported amount of DMA source segments.\n");
			return -1;
		}

		if (config->num_in_seg + 1U > capa.max_segs) {
			ODPH_ERR("Unsupported total amount of DMA segments.\n");
			return -1;
		}
	}

	if (config->trs_grn == GRN_IND && capa.max_segs < 2U) {
		ODPH_ERR("Unsupported total amount of DMA segments.\n");
		return -1;
	}

	if (config->num_in_seg * config->seg_size > capa.max_seg_len) {
		ODPH_ERR("Unsupported total DMA segment size.\n");
		return -1;
	}

	return 0;
}

static int check_capabilities(const test_config_t *config)
{
	return check_shm_capabilities(config) ||
	       check_dma_capabilities(config);
}

static int configure_packets(test_config_t *config)
{
	odp_pool_param_t param;

	for (int i = 0; i < config->num_in_seg + 1; ++i)
		config->seg_config.pkts[i] = ODP_PACKET_INVALID;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_PACKET;
	/* Configured amount of input segments and one output segment */
	param.pkt.num = config->num_in_seg + 1U;
	param.pkt.len = config->num_in_seg * config->seg_size;
	config->seg_config.pool = odp_pool_create("odp_dma_perf_packets", &param);

	if (config->seg_config.pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error creating packet pool.\n");
		return -1;
	}

	return 0;
}

static int allocate_packets(test_config_t *config)
{
	for (int i = 0; i < config->num_in_seg; ++i) {
		config->seg_config.pkts[i] = odp_packet_alloc(config->seg_config.pool,
							      config->seg_size);

		if (config->seg_config.pkts[i] == ODP_PACKET_INVALID) {
			ODPH_ERR("Error allocating input test packets.\n");
			return -1;
		}
	}

	config->seg_config.pkts[config->num_in_seg] =
		odp_packet_alloc(config->seg_config.pool, config->num_in_seg * config->seg_size);

	if (config->seg_config.pkts[config->num_in_seg] == ODP_PACKET_INVALID) {
		ODPH_ERR("Error allocating output test packet.\n");
		return -1;
	}

	return 0;
}

static int populate_packets(test_config_t *config)
{
	for (int i = 0; i < config->num_in_seg; ++i) {
		uint8_t data[odp_packet_len(config->seg_config.pkts[i])];

		memset(data, i + 1, sizeof(data));

		if (odp_packet_copy_from_mem(config->seg_config.pkts[i], 0U, sizeof(data), data))
			return -1;
	}

	return 0;
}

static int setup_packet_segments(test_config_t *config)
{
	return configure_packets(config) ||
	       allocate_packets(config) ||
	       populate_packets(config);
}

static void configure_packet_dma_transfer_base(test_config_t *config,
					       odp_dma_transfer_param_t trs_params[],
					       uint32_t trs_lengths[])
{
	memset(trs_lengths, 0, sizeof(*trs_lengths) * config->dma_rounds);

	for (int i = 0; i < config->num_in_seg; ++i) {
		config->dma_config.src_seg[i].packet = config->seg_config.pkts[i];
		config->dma_config.src_seg[i].offset = 0U;
		config->dma_config.src_seg[i].len = odp_packet_len(config->seg_config.pkts[i]);
	}

	config->dma_config.dst_seg.packet = config->seg_config.pkts[config->num_in_seg];

	for (int i = 0; i < config->dma_rounds; ++i) {
		odp_dma_transfer_param_init(&trs_params[i]);
		trs_params[i].src_format = ODP_DMA_FORMAT_PACKET;
		trs_params[i].dst_format = ODP_DMA_FORMAT_PACKET;
		trs_params[i].num_src = config->trs_grn == GRN_IND ? 1 : config->num_in_seg;
		trs_params[i].num_dst = 1U;
		trs_params[i].src_seg = &config->dma_config.src_seg[i];
		trs_params[i].dst_seg = &config->dma_config.dst_seg;
		trs_lengths[i] = config->trs_grn == GRN_IND ?
						    config->dma_config.src_seg[i].len :
						    config->num_in_seg * config->seg_size;
	}
}

static inline void configure_packet_dma_transfer_dynamic(test_config_t *config, uint32_t offset,
							 uint32_t len)
{
	config->dma_config.dst_seg.offset = offset;
	config->dma_config.dst_seg.len = len;
}

static int verify_packet_transfer(const test_config_t *config)
{
	uint32_t len, offset = 0U;

	for (int i = 0; i < config->num_in_seg; ++i) {
		len = odp_packet_len(config->seg_config.pkts[i]);
		uint8_t src_data[len];
		uint8_t dst_data[len];

		if (odp_packet_copy_to_mem(config->seg_config.pkts[i], 0U, len, src_data) ||
		    odp_packet_copy_to_mem(config->seg_config.pkts[config->num_in_seg], offset,
					   len, dst_data)) {
			ODPH_ERR("Error verifying DMA transfer.\n");
			return -1;
		}

		if (memcmp(src_data, dst_data, len)) {
			ODPH_ERR("Error in DMA transfer, source and destination data do not match.\n");
			return -1;
		}

		offset += len;
	}

	return 0;
}

static void free_packets(test_config_t *config)
{
	/* Configured amount of input segments and one output segment */
	for (int i = 0; i < config->num_in_seg + 1; ++i)
		if (config->seg_config.pkts[i] != ODP_PACKET_INVALID)
			odp_packet_free(config->seg_config.pkts[i]);

	if (config->seg_config.pool != ODP_POOL_INVALID)
		(void)odp_pool_destroy(config->seg_config.pool);
}

static int allocate_memory(test_config_t *config)
{
	const uint64_t size = config->num_in_seg * (uint64_t)config->seg_size;

	config->seg_config.shm_src = ODP_SHM_INVALID;
	config->seg_config.shm_dst = ODP_SHM_INVALID;
	config->seg_config.src = NULL;
	config->seg_config.dst = NULL;

	config->seg_config.shm_src = odp_shm_reserve(SHM_SRC, size, ODP_CACHE_LINE_SIZE, 0);
	config->seg_config.shm_dst = odp_shm_reserve(SHM_DST, size, ODP_CACHE_LINE_SIZE, 0);

	if (config->seg_config.shm_src == ODP_SHM_INVALID ||
	    config->seg_config.shm_dst == ODP_SHM_INVALID) {
		ODPH_ERR("Error allocating SHM block.\n");
		return -1;
	}

	config->seg_config.src = odp_shm_addr(config->seg_config.shm_src);
	config->seg_config.dst = odp_shm_addr(config->seg_config.shm_dst);

	if (config->seg_config.src == NULL || config->seg_config.dst == NULL) {
		ODPH_ERR("Error resolving SHM block address.\n");
		return -1;
	}

	return 0;
}

static int populate_memory(test_config_t *config)
{
	uint8_t val;
	uint8_t *addr;

	for (int i = 0; i < config->num_in_seg; ++i) {
		val = 0U;
		addr = (uint8_t *)config->seg_config.src + i * config->seg_size;

		for (uint32_t i = 0U; i < config->seg_size; ++i)
			addr[i] = val++;
	}

	return 0;
}

static int setup_memory_segments(test_config_t *config)
{
	return allocate_memory(config) ||
	       populate_memory(config);
}

static void configure_address_dma_transfer_base(test_config_t *config,
						odp_dma_transfer_param_t trs_params[],
						uint32_t trs_lengths[])
{
	memset(trs_lengths, 0, sizeof(*trs_lengths) * config->dma_rounds);

	for (int i = 0; i < config->num_in_seg; ++i) {
		config->dma_config.src_seg[i].addr =
			(uint8_t *)config->seg_config.src + i * config->seg_size;
		config->dma_config.src_seg[i].len = config->seg_size;
	}

	config->dma_config.dst_seg.addr = config->seg_config.dst;

	for (int i = 0; i < config->dma_rounds; ++i) {
		odp_dma_transfer_param_init(&trs_params[i]);
		trs_params[i].src_format = ODP_DMA_FORMAT_ADDR;
		trs_params[i].dst_format = ODP_DMA_FORMAT_ADDR;
		trs_params[i].num_src = config->trs_grn == GRN_IND ? 1 : config->num_in_seg;
		trs_params[i].num_dst = 1U;
		trs_params[i].src_seg = &config->dma_config.src_seg[i];
		trs_params[i].dst_seg = &config->dma_config.dst_seg;
		trs_lengths[i] = config->trs_grn == GRN_IND ?
						    config->dma_config.src_seg[i].len :
						    config->num_in_seg * config->seg_size;
	}
}

static inline void configure_address_dma_transfer_dynamic(test_config_t *config, uint32_t offset,
							  uint32_t len)
{
	config->dma_config.dst_seg.addr = (uint8_t *)config->seg_config.dst + offset;
	config->dma_config.dst_seg.len = len;
}

static int verify_memory_transfer(const test_config_t *config)
{
	if (memcmp(config->seg_config.src, config->seg_config.dst,
		   config->num_in_seg * config->seg_size)) {
		ODPH_ERR("Error in DMA transfer, source and destination data do not match.\n");
		return -1;
	}

	return 0;
}

static void free_memory(test_config_t *config)
{
	if (config->seg_config.shm_src != ODP_SHM_INVALID)
		(void)odp_shm_free(config->seg_config.shm_src);

	if (config->seg_config.shm_dst != ODP_SHM_INVALID)
		(void)odp_shm_free(config->seg_config.shm_dst);
}

static void print_humanised_speed(uint64_t speed)
{
	if (speed > GIGAS)
		printf("%.2f GB/s\n", (double)speed / GIGAS);
	else if (speed > MEGAS)
		printf("%.2f MB/s\n", (double)speed / MEGAS);
	else if (speed > KILOS)
		printf("%.2f KB/s\n", (double)speed / KILOS);
	else
		printf("%" PRIu64 " B/s\n", speed);
}

static void print_results(const test_config_t *config, uint64_t time)
{
	const int is_sync = config->trs_type == TRS_TYPE_SYNC;
	const uint64_t avg_time = time / config->num_rounds;
	uint64_t avg_speed = 0U;

	printf("\n"
	       "=============================================\n\n"
	       "DMA transfer test done\n\n"
	       "    mode:                         %s\n"
	       "    granularity:                  %s\n"
	       "    input segment count:          %d\n"
	       "    segment size:                 %u\n"
	       "    segment type:                 %s\n",
	       is_sync ? "synchronous" : "asynchronous",
	       config->trs_grn == GRN_IND ? "individual" : "all",
	       config->num_in_seg, config->seg_size,
	       config->seg_type == TYPE_PKT ? "packet" : "memory");

	if (!is_sync) {
		printf("    completion modes in order:    ");

		for (int i = 0; i < config->compl_modes.num_modes; ++i)
			printf("%s", config->compl_modes.modes[i] == ODP_DMA_COMPL_POLL ?
								     "poll " : "event ");

		printf("\n");
	}

	if (avg_time > 0U)
		avg_speed = config->num_in_seg * config->seg_size * ODP_TIME_SEC_IN_NS / avg_time;

	printf("    rounds run:                   %d\n"
	       "    average time per transfer:    %" PRIu64 " ns\n"
	       "    average transfer speed:       ",
	       config->num_rounds, avg_time);
	print_humanised_speed(avg_speed);
	printf("\n=============================================\n");
}

static int run_dma_sync(test_config_t *config)
{
	odp_dma_transfer_param_t trs_params[config->dma_rounds];
	uint32_t trs_lengths[config->dma_rounds];
	odp_time_t start, end;
	uint32_t num_rounds = config->num_rounds, offset;

	config->test_case_api.trs_base_fn(config, trs_params, trs_lengths);
	start = odp_time_local_strict();

	while (num_rounds--) {
		offset = 0U;

		for (int i = 0; i < config->dma_rounds; ++i) {
			config->test_case_api.trs_dyn_fn(config, offset, trs_lengths[i]);

			if (odp_dma_transfer(config->dma_config.handle, &trs_params[i], NULL)
			    <= 0) {
				ODPH_ERR("Error starting a sync DMA transfer.\n");
				return -1;
			}

			offset += trs_lengths[i];
		}
	}

	end = odp_time_local_strict();
	print_results(config, odp_time_diff_ns(end, start));
	return 0;
}

static int configure_dma_event_completion(test_config_t *config)
{
	int ret;
	odp_dma_pool_param_t pool_param;
	odp_queue_param_t queue_param;

	config->dma_config.pool = ODP_POOL_INVALID;
	config->dma_config.compl_q = ODP_QUEUE_INVALID;

	ret = odp_schedule_config(NULL);

	if (ret < 0) {
		ODPH_ERR("Error configuring scheduler.\n");
		return -1;
	}

	odp_dma_pool_param_init(&pool_param);
	pool_param.num = config->num_in_seg;
	config->dma_config.pool = odp_dma_pool_create("odp_dma_perf_events", &pool_param);

	if (config->dma_config.pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error creating DMA event completion pool.\n");
		return -1;
	}

	odp_queue_param_init(&queue_param);
	queue_param.type = ODP_QUEUE_TYPE_SCHED;
	queue_param.sched.sync = ODP_SCHED_SYNC_PARALLEL;
	queue_param.sched.prio = odp_schedule_default_prio();
	queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	config->dma_config.compl_q = odp_queue_create("odp_dma_perf_queue", &queue_param);

	if (config->dma_config.compl_q == ODP_QUEUE_INVALID) {
		ODPH_ERR("Error creating DMA completion queue.\n");
		return -1;
	}

	return 0;
}

static int configure_dma_completion_params(test_config_t *config,
					   odp_dma_compl_param_t compl_params[])
{
	odp_dma_compl_t compl_ev;

	for (int i = 0; i < config->dma_rounds; ++i)
		odp_dma_compl_param_init(&compl_params[i]);

	for (int i = 0; i < config->dma_rounds; ++i) {
		if (config->compl_modes.modes[i] == ODP_DMA_COMPL_EVENT) {
			compl_params[i].compl_mode = ODP_DMA_COMPL_EVENT;
			compl_ev = odp_dma_compl_alloc(config->dma_config.pool);

			if (compl_ev == ODP_DMA_COMPL_INVALID) {
				ODPH_ERR("Error creating DMA completion event.\n");
				return -1;
			}

			compl_params[i].event = odp_dma_compl_to_event(compl_ev);
			compl_params[i].queue = config->dma_config.compl_q;
		} else if (config->compl_modes.modes[i] == ODP_DMA_COMPL_POLL) {
			compl_params[i].compl_mode = ODP_DMA_COMPL_POLL;
			compl_params[i].transfer_id =
				odp_dma_transfer_id_alloc(config->dma_config.handle);

			if (compl_params[i].transfer_id == ODP_DMA_TRANSFER_ID_INVALID) {
				ODPH_ERR("Error creating DMA transfer ID.\n");
				return -1;
			}
		}

		compl_params[i].user_ptr = NULL;
	}

	return 0;
}

static void build_wait_list(const test_config_t *config, odp_dma_compl_param_t compl_params[],
			    compl_wait_entry_t list[])
{
	int last_ev_idx, has_events = 0;

	memset(list, 0, sizeof(*list) * config->dma_rounds);

	for (int i = 0, j = 0, k = 0; i < config->dma_rounds; ++i) {
		if (config->compl_modes.modes[i] == ODP_DMA_COMPL_EVENT) {
			compl_wait_entry_t entry = { .type = ODP_DMA_COMPL_EVENT };

			list[j] = entry;
			++j;

			for (; k < i; ++k) {
				entry.type = ODP_DMA_COMPL_POLL;
				entry.id = compl_params[k].transfer_id;
				list[j++] = entry;
			}

			++k;
			last_ev_idx = i;
			has_events = 1;
		}
	}

	last_ev_idx = has_events ? last_ev_idx + 1 : 0;

	for (int i = last_ev_idx; i < config->dma_rounds; ++i) {
		compl_wait_entry_t entry = { .type = ODP_DMA_COMPL_POLL,
					     .id = compl_params[i].transfer_id };
		list[i] = entry;
	}
}

static inline int wait_dma_transfers_ready(test_config_t *config, compl_wait_entry_t list[])
{
	odp_event_t ev;
	const uint64_t wait_time = odp_schedule_wait_time(config->wait_ns);
	int done = 0;

	for (int i = 0; i < config->dma_rounds; ++i) {
		if (list[i].type == ODP_DMA_COMPL_EVENT) {
			ev = odp_schedule(NULL, wait_time);

			if (ev == ODP_EVENT_INVALID) {
				ODPH_ERR("Error waiting event completion.\n");
				return -1;
			}
		} else {
			while (1) {
				done = odp_dma_transfer_done(config->dma_config.handle, list[i].id,
							     NULL);

				if (done > 0)
					break;

				if (done == 0)
					continue;

				ODPH_ERR("Error waiting poll completion.\n");
				return -1;
			}
		}
	}

	return 0;
}

static void free_dma_completion_events(test_config_t *config, odp_dma_compl_param_t compl_params[])
{
	for (int i = 0; i < config->dma_rounds; ++i)
		if (config->compl_modes.modes[i] == ODP_DMA_COMPL_EVENT &&
		    compl_params[i].event != ODP_EVENT_INVALID)
			odp_dma_compl_free(odp_dma_compl_from_event(compl_params[i].event));
}

static void free_dma_transfer_ids(test_config_t *config, odp_dma_compl_param_t compl_params[])
{
	for (int i = 0; i < config->dma_rounds; ++i)
		if (config->compl_modes.modes[i] == ODP_DMA_COMPL_POLL &&
		    compl_params[i].transfer_id != ODP_DMA_TRANSFER_ID_INVALID)
			odp_dma_transfer_id_free(config->dma_config.handle,
						 compl_params[i].transfer_id);
}

static int run_dma_async_transfer(test_config_t *config)
{
	odp_dma_transfer_param_t trs_params[config->dma_rounds];
	uint32_t trs_lengths[config->dma_rounds];
	odp_dma_compl_param_t compl_params[config->dma_rounds];
	int ret = 0;
	compl_wait_entry_t compl_wait_list[config->dma_rounds];
	odp_time_t start, end;
	uint32_t num_rounds = config->num_rounds, offset;

	config->test_case_api.trs_base_fn(config, trs_params, trs_lengths);

	if (configure_dma_completion_params(config, compl_params)) {
		ret = -1;
		goto out_compl_evs;
	}

	build_wait_list(config, compl_params, compl_wait_list);
	start = odp_time_local_strict();

	while (num_rounds--) {
		offset = 0U;

		for (int i = 0; i < config->dma_rounds; ++i) {
			config->test_case_api.trs_dyn_fn(config, offset, trs_lengths[i]);

			if (odp_dma_transfer_start(config->dma_config.handle, &trs_params[i],
						   &compl_params[i]) <= 0) {
				ODPH_ERR("Error starting an async DMA transfer.\n");
				ret = -1;
				goto out_trs_ids;
			}

			offset += trs_lengths[i];
		}

		if (wait_dma_transfers_ready(config, compl_wait_list)) {
			ODPH_ERR("Error finishing an async DMA transfer.\n");
			ret = -1;
			goto out_trs_ids;
		}
	}

	end = odp_time_local_strict();
	print_results(config, odp_time_diff_ns(end, start));

out_compl_evs:
	free_dma_completion_events(config, compl_params);

out_trs_ids:
	free_dma_transfer_ids(config, compl_params);
	return ret;
}

static void free_dma_event_completion(test_config_t *config)
{
	if (config->dma_config.compl_q != ODP_QUEUE_INVALID)
		(void)odp_queue_destroy(config->dma_config.compl_q);

	if (config->dma_config.pool != ODP_POOL_INVALID)
		(void)odp_pool_destroy(config->dma_config.pool);
}

static int run_dma_async(test_config_t *config)
{
	const int is_event_compl = config->compl_modes.compl_mask & ODP_DMA_COMPL_EVENT;
	int ret = 0;

	if (is_event_compl)
		if (configure_dma_event_completion(config)) {
			ret = -1;
			goto out;
		}

	if (run_dma_async_transfer(config))
		ret = -1;

out:
	if (is_event_compl)
		free_dma_event_completion(config);

	return ret;
}

static void setup_test_case_api(test_config_t *config)
{
	switch (config->seg_type) {
	case TYPE_PKT:
		config->test_case_api.setup_fn = setup_packet_segments;
		config->test_case_api.trs_base_fn = configure_packet_dma_transfer_base;
		config->test_case_api.trs_dyn_fn = configure_packet_dma_transfer_dynamic;
		config->test_case_api.verify_fn = verify_packet_transfer;
		config->test_case_api.free_fn = free_packets;
		break;
	case TYPE_MEM:
		config->test_case_api.setup_fn = setup_memory_segments;
		config->test_case_api.trs_base_fn = configure_address_dma_transfer_base;
		config->test_case_api.trs_dyn_fn = configure_address_dma_transfer_dynamic;
		config->test_case_api.verify_fn = verify_memory_transfer;
		config->test_case_api.free_fn = free_memory;
		break;
	default:
		break;
	}

	config->test_case_api.run_fn = config->trs_type == TRS_TYPE_SYNC ?
							   run_dma_sync :
							   run_dma_async;
}

static int configure_dma_session(test_config_t *config)
{
	const odp_dma_param_t params = { .direction = ODP_DMA_MAIN_TO_MAIN,
					 .type = ODP_DMA_TYPE_COPY,
					 .compl_mode_mask = config->compl_modes.compl_mask,
					 .mt_mode = ODP_DMA_MT_SERIAL,
					 .order = ODP_DMA_ORDER_NONE };

	config->dma_config.handle = odp_dma_create("odp_dma_perf", &params);

	if (config->dma_config.handle == ODP_DMA_INVALID) {
		ODPH_ERR("Error creating DMA session.\n");
		return -1;
	}

	return 0;
}

static void free_dma_session(test_config_t *config)
{
	if (config->dma_config.handle != ODP_DMA_INVALID)
		(void)odp_dma_destroy(config->dma_config.handle);
}

int main(int argc, char **argv)
{
	odph_helper_options_t odph_opts;
	test_config_t test_config;
	odp_instance_t odp_instance;
	int ret = EXIT_SUCCESS;

	argc = odph_parse_options(argc, argv);

	if (odph_options(&odph_opts)) {
		ODPH_ERR("Error while reading ODP helper options, exiting.\n");
		exit(EXIT_FAILURE);
	}

	if (parse_options(argc, argv, &test_config))
		exit(EXIT_FAILURE);

	if (odp_init_global(&odp_instance, NULL, NULL)) {
		ODPH_ERR("ODP global init failed, exiting.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(odp_instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("ODP local init failed, exiting.\n");
		exit(EXIT_FAILURE);
	}

	if (check_capabilities(&test_config)) {
		ODPH_ERR("Unsupported scenario attempted, exiting.\n");
		ret = EXIT_NOT_SUP;
		goto out_odp;
	}

	setup_test_case_api(&test_config);

	if (configure_dma_session(&test_config)) {
		ret = EXIT_FAILURE;
		goto out_dma;
	}

	if (test_config.test_case_api.setup_fn(&test_config)) {
		ret = EXIT_FAILURE;
		goto out_test_case;
	}

	if (test_config.test_case_api.run_fn(&test_config) ||
	    test_config.test_case_api.verify_fn(&test_config))
		ret = EXIT_FAILURE;

out_test_case:
	test_config.test_case_api.free_fn(&test_config);

out_dma:
	free_dma_session(&test_config);

out_odp:
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

/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_bench_packet.c  Microbenchmarks for packet functions
 */

#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

/** Minimum number of packet data bytes in the first segment */
#define PKT_POOL_SEG_LEN 128

/** Packet user area size in bytes */
#define PKT_POOL_UAREA_SIZE 8

/** Minimum test packet size */
#define TEST_MIN_PKT_SIZE 64

/** Maximum test packet size */
#define TEST_MAX_PKT_SIZE 2048

/** Number of test runs per individual benchmark */
#define TEST_REPEAT_COUNT 1000

/** Number of times to run tests for each packet size */
#define TEST_SIZE_RUN_COUNT 10

/** Maximum burst size for *_multi operations */
#define TEST_MAX_BURST 64

/** Offset of the contiguous area */
#define TEST_ALIGN_OFFSET 16

/** Length of the contiguous area */
#define TEST_ALIGN_LEN 32

/** Minimum byte alignment of contiguous area */
#define TEST_ALIGN 32

/** Test packet offsets */
#define TEST_L2_OFFSET 0
#define TEST_L3_OFFSET (TEST_MIN_PKT_SIZE / 4)
#define TEST_L4_OFFSET (TEST_MIN_PKT_SIZE / 2)

/** Default burst size for *_multi operations */
#define TEST_DEF_BURST 8

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

#define BENCH_INFO(run, init, term, name) \
	{#run, run, init, term, name}

ODP_STATIC_ASSERT((TEST_ALIGN_OFFSET + TEST_ALIGN_LEN) <= TEST_MIN_PKT_SIZE,
		  "Invalid_alignment");

/** Warm up round packet size */
#define WARM_UP TEST_MIN_PKT_SIZE

/** Test packet sizes */
const uint32_t test_packet_len[] = {WARM_UP, TEST_MIN_PKT_SIZE, 128, 256, 512,
				    1024, 1518, TEST_MAX_PKT_SIZE};

/**
 * Parsed command line arguments
 */
typedef struct {
	int bench_idx;   /** Benchmark index to run indefinitely */
	int burst_size;  /** Burst size for *_multi operations */
} appl_args_t;

/**
 * Initialize benchmark resources
 */
typedef void (*bench_init_fn_t)(void);

/**
 * Run benchmark
 *
 * @retval >0 on success
 * */
typedef int (*bench_run_fn_t)(void);

/**
 * Release benchmark resources
 */
typedef void (*bench_term_fn_t)(void);

/**
 * Benchmark data
 */
typedef struct {
	const char *name;
	bench_run_fn_t run;
	bench_init_fn_t init;
	bench_term_fn_t term;
	const char *desc;
} bench_info_t;

/**
 * Grouping of all global data
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Packet pool */
	odp_pool_t pool;
	/** Benchmark functions */
	bench_info_t *bench;
	/** Number of benchmark functions */
	int num_bench;
	/** Break worker loop if set to 1 */
	int exit_thread;
	struct {
		/** Test packet length */
		uint32_t len;
		/** Minimum test packet headroom */
		uint32_t headroom;
		/** Minimum test packet tailroom */
		uint32_t tailroom;
		/** Minimum test packet segment length */
		uint32_t seg_len;
	} pkt;
	/** Array for storing test packets */
	odp_packet_t pkt_tbl[TEST_REPEAT_COUNT * TEST_MAX_BURST];
	/** Array for storing test packets */
	odp_packet_t pkt2_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test event */
	odp_event_t event_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test pointers */
	void *ptr_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test segments */
	odp_packet_seg_t seg_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test outputs */
	uint32_t output_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test pool handles */
	odp_pool_t pool_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test pktio handles */
	odp_pktio_t pktio_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test timestamps */
	odp_time_t ts_tbl[TEST_REPEAT_COUNT];
	/** Array for storing test data */
	uint8_t data_tbl[TEST_REPEAT_COUNT][TEST_MAX_PKT_SIZE];
	/** Benchmark run failed */
	uint8_t bench_failed;
} args_t;

/** Global pointer to args */
static args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	gbl_args->exit_thread = 1;
}

/**
 * Run given benchmark indefinitely
 */
static void run_indef(args_t *args, int idx)
{
	const char *desc;

	desc = args->bench[idx].desc != NULL ?
			args->bench[idx].desc : args->bench[idx].name;

	printf("Running %s() indefinitely\n", desc);

	while (!gbl_args->exit_thread) {
		int ret;

		if (args->bench[idx].init != NULL)
			args->bench[idx].init();

		ret = args->bench[idx].run();

		if (args->bench[idx].term != NULL)
			args->bench[idx].term();

		if (!ret)
			ODPH_ABORT("Benchmark %s failed\n", desc);
	}
}

/**
 * Master function for running the microbenchmarks
 */
static int run_benchmarks(void *arg)
{
	int i, j, k;
	args_t *args = arg;
	int num_sizes = sizeof(test_packet_len) / sizeof(test_packet_len[0]);
	double results[gbl_args->num_bench][num_sizes];

	memset(results, 0, sizeof(results));

	printf("\nRunning benchmarks (cycles per call)\n"
	       "------------------------------------\n");

	for (i = 0; i < num_sizes; i++) {
		uint64_t tot_cycles = 0;

		printf("\nPacket length: %6d bytes\n"
		       "---------------------------\n", test_packet_len[i]);

		gbl_args->pkt.len = test_packet_len[i];

		for (j = 0, k = 1; j < gbl_args->num_bench; k++) {
			int ret;
			uint64_t c1, c2;
			const char *desc;

			if (args->appl.bench_idx &&
			    (j + 1) != args->appl.bench_idx) {
				j++;
				continue;
			} else if (args->appl.bench_idx &&
				   (j + 1) == args->appl.bench_idx) {
				run_indef(args, j);
				return 0;
			}

			desc = args->bench[j].desc != NULL ?
					args->bench[j].desc :
					args->bench[j].name;

			if (args->bench[j].init != NULL)
				args->bench[j].init();

			c1 = odp_cpu_cycles();
			ret = args->bench[j].run();
			c2 = odp_cpu_cycles();

			if (args->bench[j].term != NULL)
				args->bench[j].term();

			if (!ret) {
				ODPH_ERR("Benchmark %s failed\n", desc);
				args->bench_failed = 1;
				return -1;
			}

			tot_cycles += odp_cpu_cycles_diff(c2, c1);

			if (k >= TEST_SIZE_RUN_COUNT) {
				double cycles;

				/** Each benchmark runs internally
				 *  TEST_REPEAT_COUNT times. */
				cycles = ((double)tot_cycles) /
					 (TEST_SIZE_RUN_COUNT *
					  TEST_REPEAT_COUNT);
				results[j][i] = cycles;

				printf("%-30s: %8.1f\n", desc, cycles);

				j++;
				k = 0;
				tot_cycles = 0;
			}
		}
	}
	printf("\n%-30s", "Benchmark / packet_size [B]");
	for (i = 0; i < num_sizes; i++) {
		if (i == 0)
			printf("      WARM UP  ");
		else
			printf("%8.1d  ", test_packet_len[i]);
	}
	printf("\n---------------------------------");
	for (i = 0; i < num_sizes; i++)
		printf("----------");

	for (i = 0; i < gbl_args->num_bench; i++) {
		printf("\n[%02d] %-30s", i + 1, args->bench[i].desc != NULL ?
		       args->bench[i].desc : args->bench[i].name);

		for (j = 0; j < num_sizes; j++)
			printf("%8.1f  ", results[i][j]);
	}
	printf("\n\n");
	return 0;
}

static void allocate_test_packets(uint32_t len, odp_packet_t pkt[], int num)
{
	int pkts = 0;

	while (pkts < num) {
		int ret;

		ret = odp_packet_alloc_multi(gbl_args->pool, len, &pkt[pkts],
					     num - pkts);
		if (ret < 0)
			ODPH_ABORT("Allocating test packets failed\n");

		pkts += ret;
	}
}

static void alloc_packets_half(void)
{
	allocate_test_packets(gbl_args->pkt.len / 2, gbl_args->pkt_tbl,
			      TEST_REPEAT_COUNT);
}

static void alloc_packets_multi(void)
{
	allocate_test_packets(gbl_args->pkt.len, gbl_args->pkt_tbl,
			      TEST_REPEAT_COUNT * gbl_args->appl.burst_size);
}

static void alloc_concat_packets(void)
{
	allocate_test_packets(gbl_args->pkt.len / 2, gbl_args->pkt_tbl,
			      TEST_REPEAT_COUNT);
	allocate_test_packets(gbl_args->pkt.len / 2, gbl_args->pkt2_tbl,
			      TEST_REPEAT_COUNT);
}

static void alloc_ref_packets(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *ref_tbl = gbl_args->pkt2_tbl;

	allocate_test_packets(gbl_args->pkt.len, pkt_tbl, TEST_REPEAT_COUNT);

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		ref_tbl[i] = odp_packet_ref(pkt_tbl[i], TEST_MIN_PKT_SIZE / 2);
		if (ref_tbl[i] == ODP_PACKET_INVALID)
			ODPH_ABORT("Allocating packet reference failed\n");
	}
}

static void alloc_packets_twice(void)
{
	allocate_test_packets(gbl_args->pkt.len, gbl_args->pkt_tbl,
			      TEST_REPEAT_COUNT);
	allocate_test_packets(gbl_args->pkt.len, gbl_args->pkt2_tbl,
			      TEST_REPEAT_COUNT);
}

static void create_packets(void)
{
	int i;
	uint32_t headroom, tailroom, seg_len;
	uint32_t min_headroom = 0;
	uint32_t min_tailroom = 0;
	uint32_t min_seg_len = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_seg_t *seg_tbl = gbl_args->seg_tbl;

	allocate_test_packets(gbl_args->pkt.len, gbl_args->pkt_tbl,
			      TEST_REPEAT_COUNT);

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		headroom = odp_packet_headroom(pkt_tbl[i]);
		tailroom = odp_packet_tailroom(pkt_tbl[i]);
		seg_len = odp_packet_seg_len(pkt_tbl[i]);

		seg_tbl[i] = odp_packet_first_seg(pkt_tbl[i]);

		if (i == 0) {
			min_headroom = headroom;
			min_tailroom = tailroom;
			min_seg_len = seg_len;
		} else {
			if (headroom < min_headroom)
				min_headroom = headroom;
			if (tailroom < min_tailroom)
				min_tailroom = tailroom;
			if (seg_len < min_seg_len)
				min_seg_len = seg_len;
		}

		if (odp_packet_l2_offset_set(pkt_tbl[i], TEST_L2_OFFSET) ||
		    odp_packet_l3_offset_set(pkt_tbl[i], TEST_L3_OFFSET) ||
		    odp_packet_l4_offset_set(pkt_tbl[i], TEST_L4_OFFSET))
			ODPH_ABORT("Setting test packet offsets failed\n");

		odp_packet_flow_hash_set(pkt_tbl[i], i);
		odp_packet_ts_set(pkt_tbl[i], odp_time_local());
	}
	gbl_args->pkt.headroom = min_headroom;
	gbl_args->pkt.tailroom = min_tailroom;
	gbl_args->pkt.seg_len = min_seg_len;
}

static void create_events(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	create_packets();

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->event_tbl[i] = odp_packet_to_event(pkt_tbl[i]);
}

static void free_packets(void)
{
	odp_packet_free_multi(gbl_args->pkt_tbl, TEST_REPEAT_COUNT);
}

static void free_packets_multi(void)
{
	odp_packet_free_multi(gbl_args->pkt_tbl,
			      TEST_REPEAT_COUNT * gbl_args->appl.burst_size);
}

static void free_packets_twice(void)
{
	odp_packet_free_multi(gbl_args->pkt_tbl, TEST_REPEAT_COUNT);
	odp_packet_free_multi(gbl_args->pkt2_tbl, TEST_REPEAT_COUNT);
}

static int bench_empty(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->output_tbl[i] = i;

	return i;
}

static int bench_packet_alloc(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		odp_packet_t pkt;

		pkt = odp_packet_alloc(gbl_args->pool, gbl_args->pkt.len);

		gbl_args->pkt_tbl[i] = pkt;
	}

	return i;
}

static int bench_packet_alloc_multi(void)
{
	int i;
	int pkts = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		pkts += odp_packet_alloc_multi(gbl_args->pool,
					       gbl_args->pkt.len,
					       &gbl_args->pkt_tbl[pkts],
					       gbl_args->appl.burst_size);
	return pkts;
}

static int bench_packet_free(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_free(gbl_args->pkt_tbl[i]);

	return i;
}

static int bench_packet_free_multi(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		int pkt_idx = i * gbl_args->appl.burst_size;

		odp_packet_free_multi(&gbl_args->pkt_tbl[pkt_idx],
				      gbl_args->appl.burst_size);
	}
	return i;
}

static int bench_packet_alloc_free(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		odp_packet_t pkt;

		pkt = odp_packet_alloc(gbl_args->pool, gbl_args->pkt.len);

		odp_packet_free(pkt);
	}
	return i;
}

static int bench_packet_alloc_free_multi(void)
{
	int i;
	int pkts;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		pkts = odp_packet_alloc_multi(gbl_args->pool, gbl_args->pkt.len,
					      gbl_args->pkt_tbl,
					      gbl_args->appl.burst_size);

		if (pkts < 0)
			ODPH_ABORT("Packet alloc failed\n");

		odp_packet_free_multi(gbl_args->pkt_tbl, pkts);
	}
	return i;
}

static int bench_packet_reset(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_reset(gbl_args->pkt_tbl[i],
					gbl_args->pkt.len);
	return !ret;
}

static int bench_packet_from_event(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		pkt_tbl[i] = odp_packet_from_event(gbl_args->event_tbl[i]);

	return i;
}

static int bench_packet_to_event(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->event_tbl[i] = odp_packet_to_event(pkt_tbl[i]);

	return i;
}

static int bench_packet_head(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_head(gbl_args->pkt_tbl[i]);

	return i;
}

static int bench_packet_buf_len(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_buf_len(gbl_args->pkt_tbl[i]);

	return ret;
}

static int bench_packet_data(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_data(gbl_args->pkt_tbl[i]);

	return i;
}

static int bench_packet_seg_len(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_seg_len(gbl_args->pkt_tbl[i]);

	return ret;
}

static int bench_packet_len(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_len(gbl_args->pkt_tbl[i]);

	return ret;
}

static int bench_packet_headroom(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_headroom(gbl_args->pkt_tbl[i]);

	return i;
}

static int bench_packet_tailroom(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_tailroom(gbl_args->pkt_tbl[i]);

	return i;
}

static int bench_packet_tail(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_tail(gbl_args->pkt_tbl[i]);

	return i;
}

static int bench_packet_offset(void)
{
	int i;
	uint32_t offset = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_offset(gbl_args->pkt_tbl[i],
							 offset, NULL, NULL);
	return i;
}

static int bench_packet_prefetch(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_prefetch(gbl_args->pkt_tbl[i], 0, gbl_args->pkt.len);

	return i;
}

static int bench_packet_push_head(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	uint32_t hroom = gbl_args->pkt.headroom;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_push_head(pkt_tbl[i], hroom);

	return i;
}

static int bench_packet_pull_head(void)
{
	int i;
	uint32_t len = gbl_args->pkt.seg_len - 1;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_pull_head(pkt_tbl[i], len);

	return i;
}

static int bench_packet_push_tail(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	uint32_t troom = gbl_args->pkt.tailroom;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_push_tail(pkt_tbl[i], troom);

	return i;
}

static int bench_packet_pull_tail(void)
{
	int i;
	uint32_t len = gbl_args->pkt.seg_len - 1;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_pull_tail(pkt_tbl[i], len);

	return i;
}

static int bench_packet_extend_head(void)
{
	int i;
	int ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	uint32_t *data_tbl = gbl_args->output_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_extend_head(&pkt_tbl[i], len, ptr_tbl[i],
					      &data_tbl[i]);
	return ret >= 0;
}

static int bench_packet_trunc_head(void)
{
	int i;
	int ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	uint32_t *data_tbl = gbl_args->output_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_trunc_head(&pkt_tbl[i], len, ptr_tbl[i],
					     &data_tbl[i]);
	return ret >= 0;
}

static int bench_packet_extend_tail(void)
{
	int i;
	int ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	uint32_t *data_tbl = gbl_args->output_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_extend_tail(&pkt_tbl[i], len, ptr_tbl[i],
					      &data_tbl[i]);
	return ret >= 0;
}

static int bench_packet_trunc_tail(void)
{
	int i;
	int ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	uint32_t *data_tbl = gbl_args->output_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_trunc_tail(&pkt_tbl[i], len, ptr_tbl[i],
					     &data_tbl[i]);
	return ret >= 0;
}

static int bench_packet_add_data(void)
{
	int i;
	int ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	uint32_t len = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_add_data(&pkt_tbl[i], 0, len);

	return ret >= 0;
}

static int bench_packet_rem_data(void)
{
	int i;
	int ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	uint32_t len = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_rem_data(&pkt_tbl[i], 0, len);

	return ret >= 0;
}

static int bench_packet_align(void)
{
	int i;
	int ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_align(&pkt_tbl[i], TEST_ALIGN_OFFSET,
					TEST_ALIGN_LEN, TEST_ALIGN);
	return ret >= 0;
}

static int bench_packet_is_segmented(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_is_segmented(gbl_args->pkt_tbl[i]);

	return (ret == 0) ? 1 : ret;
}

static int bench_packet_num_segs(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_num_segs(gbl_args->pkt_tbl[i]);

	return ret;
}

static int bench_packet_first_seg(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->seg_tbl[i] = odp_packet_first_seg(pkt_tbl[i]);

	return i;
}

static int bench_packet_last_seg(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->seg_tbl[i] = odp_packet_last_seg(pkt_tbl[i]);

	return i;
}

static int bench_packet_next_seg(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_seg_t *seg_tbl = gbl_args->seg_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->seg_tbl[i] = odp_packet_next_seg(pkt_tbl[i],
							   seg_tbl[i]);
	return i;
}

static int bench_packet_seg_data(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_seg_t *seg_tbl = gbl_args->seg_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_seg_data(pkt_tbl[i],
							   seg_tbl[i]);
	return i;
}

static int bench_packet_seg_data_len(void)
{
	int i;
	uint32_t ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_seg_t *seg_tbl = gbl_args->seg_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_seg_data_len(pkt_tbl[i], seg_tbl[i]);

	return ret;
}

static int bench_packet_concat(void)
{
	int i;
	int ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *frag_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_concat(&pkt_tbl[i], frag_tbl[i]);

	return ret >= 0;
}

static int bench_packet_split(void)
{
	int i;
	int ret = 0;
	uint32_t head_len;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *frag_tbl = gbl_args->pkt2_tbl;

	head_len = odp_packet_len(pkt_tbl[0]) / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_split(&pkt_tbl[i], head_len, &frag_tbl[i]);

	return ret >= 0;
}

static int bench_packet_copy(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *cpy_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		cpy_tbl[i] = odp_packet_copy(pkt_tbl[i], gbl_args->pool);

	return i;
}

static int bench_packet_copy_part(void)
{
	int i;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *cpy_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		cpy_tbl[i] = odp_packet_copy_part(pkt_tbl[i], 0, len,
						  gbl_args->pool);
	return i;
}

static int bench_packet_copy_to_mem(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t len = gbl_args->pkt.len;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_copy_to_mem(pkt_tbl[i], 0, len,
					      gbl_args->data_tbl[i]);
	return !ret;
}

static int bench_packet_copy_from_mem(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t len = gbl_args->pkt.len;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_copy_from_mem(pkt_tbl[i], 0, len,
						gbl_args->data_tbl[i]);
	return !ret;
}

static int bench_packet_copy_from_pkt(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t len = gbl_args->pkt.len;
	odp_packet_t *dst_tbl = gbl_args->pkt_tbl;
	odp_packet_t *src_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_copy_from_pkt(dst_tbl[i], 0, src_tbl[i], 0,
						len);
	return !ret;
}

static int bench_packet_copy_data(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_copy_data(pkt_tbl[i], 0, len, len);

	return !ret;
}

static int bench_packet_move_data(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	uint32_t offset = len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_move_data(pkt_tbl[i], offset, len, len);

	return !ret;
}

static int bench_packet_pool(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->pool_tbl[i] = odp_packet_pool(gbl_args->pkt_tbl[i]);

	return i;
}

static int bench_packet_input(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->pktio_tbl[i] = odp_packet_input(gbl_args->pkt_tbl[i]);

	return i;
}

static int bench_packet_input_index(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_input_index(gbl_args->pkt_tbl[i]);

	return (ret == 0) ? 1 : ret;
}

static int bench_packet_user_ptr(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_user_ptr(pkt_tbl[i]);

	return i;
}

static int bench_packet_user_ptr_set(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_user_ptr_set(gbl_args->pkt_tbl[i],
					gbl_args->ptr_tbl[i]);

	return i;
}

static int bench_packet_user_area(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_user_area(pkt_tbl[i]);

	return i;
}

static int bench_packet_user_area_size(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_user_area_size(gbl_args->pkt_tbl[i]);

	return ret;
}

static int bench_packet_l2_ptr(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_l2_ptr(gbl_args->pkt_tbl[i],
							 NULL);
	return i;
}

static int bench_packet_l2_offset(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l2_offset(gbl_args->pkt_tbl[i]);

	return ret >= 0;
}

static int bench_packet_l2_offset_set(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t offset = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l2_offset_set(gbl_args->pkt_tbl[i], offset);

	return !ret;
}

static int bench_packet_l3_ptr(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_l3_ptr(gbl_args->pkt_tbl[i],
							 NULL);
	return i;
}

static int bench_packet_l3_offset(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l3_offset(gbl_args->pkt_tbl[i]);

	return ret >= 0;
}

static int bench_packet_l3_offset_set(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t offset = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l3_offset_set(gbl_args->pkt_tbl[i], offset);

	return !ret;
}

static int bench_packet_l4_ptr(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_l4_ptr(gbl_args->pkt_tbl[i],
							 NULL);
	return i;
}

static int bench_packet_l4_offset(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l4_offset(gbl_args->pkt_tbl[i]);

	return ret >= 0;
}

static int bench_packet_l4_offset_set(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t offset = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l4_offset_set(gbl_args->pkt_tbl[i], offset);

	return !ret;
}

static int bench_packet_flow_hash(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_flow_hash(gbl_args->pkt_tbl[i]);

	return ret;
}

static int bench_packet_flow_hash_set(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_flow_hash_set(gbl_args->pkt_tbl[i], i);

	return i;
}

static int bench_packet_ts(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ts_tbl[i] = odp_packet_ts(gbl_args->pkt_tbl[i]);

	return i;
}

static int bench_packet_ts_set(void)
{
	int i;
	odp_time_t ts = odp_time_local();

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_ts_set(gbl_args->pkt_tbl[i], ts);

	return i;
}

static int bench_packet_ref_static(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *ref_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ref_tbl[i] = odp_packet_ref_static(pkt_tbl[i]);

	return i;
}

static int bench_packet_ref(void)
{
	int i;
	uint32_t offset = TEST_MIN_PKT_SIZE / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *ref_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ref_tbl[i] = odp_packet_ref(pkt_tbl[i], offset);

	return i;
}

static int bench_packet_ref_pkt(void)
{
	int i;
	uint32_t offset = TEST_MIN_PKT_SIZE / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *hdr_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		hdr_tbl[i] = odp_packet_ref_pkt(pkt_tbl[i], offset, hdr_tbl[i]);

	return i;
}

static int bench_packet_has_ref(void)
{
	int i;
	uint32_t ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_has_ref(pkt_tbl[i]);

	return i;
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane Packet function microbenchmark.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -b, --burst      Test packet burst size.\n"
	       "  -i, --index      Benchmark index to run indefinitely.\n"
	       "  -h, --help       Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname));
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	static const struct option longopts[] = {
		{"burst", required_argument, NULL, 'b'},
		{"help", no_argument, NULL, 'h'},
		{"index", required_argument, NULL, 'i'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "b:i:h";

	appl_args->bench_idx = 0; /* Run all benchmarks */
	appl_args->burst_size = TEST_DEF_BURST;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'b':
			appl_args->burst_size = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'i':
			appl_args->bench_idx = atoi(optarg);
			break;
		default:
			break;
		}
	}

	if (appl_args->burst_size < 1 ||
	    appl_args->burst_size > TEST_MAX_BURST) {
		printf("Invalid burst size (max %d)\n", TEST_MAX_BURST);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* Reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args ODP_UNUSED)
{
	odp_sys_info_print();

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n", progname);
	fflush(NULL);
}

/**
 * Test functions
 */
bench_info_t test_suite[] = {
		BENCH_INFO(bench_empty, NULL, NULL, NULL),
		BENCH_INFO(bench_packet_alloc, NULL, free_packets, NULL),
		BENCH_INFO(bench_packet_alloc_multi, NULL, free_packets_multi,
			   NULL),
		BENCH_INFO(bench_packet_free, create_packets, NULL, NULL),
		BENCH_INFO(bench_packet_free_multi, alloc_packets_multi, NULL,
			   NULL),
		BENCH_INFO(bench_packet_alloc_free, NULL, NULL, NULL),
		BENCH_INFO(bench_packet_alloc_free_multi, NULL, NULL, NULL),
		BENCH_INFO(bench_packet_reset, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_from_event, create_events, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_to_event, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_head, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_buf_len, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_data, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_seg_len, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_len, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_headroom, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_tailroom, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_tail, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_offset, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_prefetch, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_push_head, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_pull_head, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_push_tail, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_pull_tail, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_extend_head, alloc_packets_half,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_trunc_head, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_extend_tail, alloc_packets_half,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_trunc_tail, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_add_data, alloc_packets_half,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_rem_data, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_align, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_is_segmented, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_num_segs, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_first_seg, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_last_seg, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_next_seg, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_seg_data, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_seg_data_len, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_concat, alloc_concat_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_split, create_packets,
			   free_packets_twice, NULL),
		BENCH_INFO(bench_packet_copy, create_packets,
			   free_packets_twice, NULL),
		BENCH_INFO(bench_packet_copy_part, create_packets,
			   free_packets_twice, NULL),
		BENCH_INFO(bench_packet_copy_to_mem, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_copy_from_mem, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_copy_from_pkt, alloc_packets_twice,
			   free_packets_twice, NULL),
		BENCH_INFO(bench_packet_copy_data, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_move_data, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_pool, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_input, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_input_index, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_user_ptr, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_user_ptr_set, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_user_area, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_user_area_size, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_l2_ptr, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_l2_offset, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_l2_offset_set, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_l3_ptr, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_l3_offset, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_l3_offset_set, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_l4_ptr, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_l4_offset, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_l4_offset_set, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_flow_hash, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_flow_hash_set, create_packets,
			   free_packets, NULL),
		BENCH_INFO(bench_packet_ts, create_packets, free_packets, NULL),
		BENCH_INFO(bench_packet_ts_set, create_packets, free_packets,
			   NULL),
		BENCH_INFO(bench_packet_ref_static, create_packets,
			   free_packets_twice, NULL),
		BENCH_INFO(bench_packet_ref, create_packets,
			   free_packets_twice, NULL),
		BENCH_INFO(bench_packet_ref_pkt, alloc_packets_twice,
			   free_packets_twice, NULL),
		BENCH_INFO(bench_packet_has_ref, alloc_ref_packets,
			   free_packets_twice, NULL),
};

/**
 * ODP packet microbenchmark application
 */
int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	odph_odpthread_t worker_thread;
	int cpu;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_capability_t capa;
	odp_pool_param_t params;
	odp_instance_t instance;
	odp_init_t init_param;
	uint32_t pkt_num;
	uint8_t ret;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for args from shared mem */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Error: shared mem reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	gbl_args = odp_shm_addr(shm);

	if (gbl_args == NULL) {
		ODPH_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	memset(gbl_args, 0, sizeof(args_t));

	gbl_args->bench = test_suite;
	gbl_args->num_bench = sizeof(test_suite) / sizeof(test_suite[0]);

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &gbl_args->appl);

	/* Get default worker cpumask */
	if (odp_cpumask_default_worker(&cpumask, 1) != 1) {
		ODPH_ERR("Error: unable to allocate worker thread.\n");
		exit(EXIT_FAILURE);
	}

	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	/* Check pool capability */
	if (odp_pool_capability(&capa)) {
		ODPH_ERR("Error: unable to query pool capability.\n");
		exit(EXIT_FAILURE);
	}

	/* At least 2 x TEST_REPEAT_COUNT packets required */
	pkt_num = (gbl_args->appl.burst_size > 2) ?
			gbl_args->appl.burst_size * TEST_REPEAT_COUNT :
			2 * TEST_REPEAT_COUNT;

	if (capa.pkt.max_num && capa.pkt.max_num < pkt_num) {
		ODPH_ERR("Error: packet pool size not supported.\n");
		printf("MAX: %" PRIu32 "\n", capa.pkt.max_num);
		exit(EXIT_FAILURE);
	} else if (capa.pkt.max_len && capa.pkt.max_len < TEST_MAX_PKT_SIZE) {
		ODPH_ERR("Error: packet length not supported.\n");
		exit(EXIT_FAILURE);
	} else if (capa.pkt.max_seg_len &&
		   capa.pkt.max_seg_len < PKT_POOL_SEG_LEN) {
		ODPH_ERR("Error: segment length not supported.\n");
		exit(EXIT_FAILURE);
	} else if (capa.pkt.max_uarea_size &&
		   capa.pkt.max_uarea_size < PKT_POOL_UAREA_SIZE) {
		ODPH_ERR("Error: user area size not supported.\n");
		exit(EXIT_FAILURE);
	}

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = PKT_POOL_SEG_LEN;
	params.pkt.len     = TEST_MAX_PKT_SIZE;
	params.pkt.num     = pkt_num;
	params.pkt.uarea_size = PKT_POOL_UAREA_SIZE;
	params.type        = ODP_POOL_PACKET;

	gbl_args->pool = odp_pool_create("packet pool", &params);

	if (gbl_args->pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	printf("CPU:             %i\n", odp_cpumask_first(&cpumask));
	printf("CPU mask:        %s\n", cpumaskstr);
	printf("Burst size:      %d\n", gbl_args->appl.burst_size);
	printf("Bench repeat:    %d\n", TEST_REPEAT_COUNT);

	odp_pool_print(gbl_args->pool);

	memset(&worker_thread, 0, sizeof(odph_odpthread_t));

	signal(SIGINT, sig_handler);

	/* Create worker threads */
	cpu = odp_cpumask_first(&cpumask);

	odp_cpumask_t thd_mask;
	odph_odpthread_params_t thr_params;

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.start    = run_benchmarks;
	thr_params.arg      = gbl_args;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;

	odp_cpumask_zero(&thd_mask);
	odp_cpumask_set(&thd_mask, cpu);
	odph_odpthreads_create(&worker_thread, &thd_mask,
			       &thr_params);

	odph_odpthreads_join(&worker_thread);

	ret = gbl_args->bench_failed;

	if (odp_pool_destroy(gbl_args->pool)) {
		ODPH_ERR("Error: pool destroy\n");
		exit(EXIT_FAILURE);
	}
	gbl_args = NULL;
	odp_mb_full();

	if (odp_shm_free(shm)) {
		ODPH_ERR("Error: shm free\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Error: term local\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: term global\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}

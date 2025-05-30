/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2022-2025 Nokia
 */

/**
 * @example odp_bench_packet.c
 *
 * Microbenchmark application for packet API functions
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>

#include <test_packet_ipv4.h>
#include <test_packet_ipv6.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <bench_common.h>
#include <export_results.h>

/** Packet user area size in bytes */
#define PKT_POOL_UAREA_SIZE 8

/** Minimum test packet size */
#define TEST_MIN_PKT_SIZE 64

/** Maximum test packet size */
#define TEST_MAX_PKT_SIZE 2048

/** Number of API function calls per test case */
#define TEST_REPEAT_COUNT 1000

/** Number of rounds per test case */
#define TEST_ROUNDS 2u

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

/** Maximum number of results to be held */
#define TEST_MAX_BENCH 200

#define TEST_MAX_SIZES 7

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

#define BENCH_INFO(run_fn, init_fn, term_fn, alt_name) \
	{.name = #run_fn, .run = run_fn, .init = init_fn, .term = term_fn, .desc = alt_name}

ODP_STATIC_ASSERT((TEST_ALIGN_OFFSET + TEST_ALIGN_LEN) <= TEST_MIN_PKT_SIZE,
		  "Invalid_alignment");

/** Test packet sizes */
const uint32_t test_packet_len[] = {TEST_MIN_PKT_SIZE, 128, 256, 512,
				    1024, 1518, TEST_MAX_PKT_SIZE};

ODP_STATIC_ASSERT(ODPH_ARRAY_SIZE(test_packet_len) <= TEST_MAX_SIZES,
		  "Result array is too small to hold all the results");

/**
 * Parsed command line arguments
 */
typedef struct {
	int bench_idx;   /** Benchmark index to run indefinitely */
	int burst_size;  /** Burst size for *_multi operations */
	int cache_size;  /** Pool cache size */
	int time;        /** Measure time vs. CPU cycles */
	uint32_t rounds; /** Rounds per test case */
} appl_args_t;

/**
 * Grouping of all global data
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Common benchmark suite data */
	bench_suite_t suite;
	/** Packet pool */
	odp_pool_t pool;
	/** Buffer pool */
	odp_pool_t pool_buf;
	/** Timeout pool */
	odp_pool_t pool_tmo;
	/** Event vector pool */
	odp_pool_t pool_evv;
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
	odp_event_t event_tbl[TEST_REPEAT_COUNT * TEST_MAX_BURST];
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
	/** Options for exporting results */
	test_common_options_t common_options;
	/** Array for storing results */
	double result[TEST_MAX_SIZES][TEST_MAX_BENCH];
} args_t;

/** Global pointer to args */
static args_t *gbl_args;

static void sig_handler(int signo ODP_UNUSED)
{
	if (gbl_args == NULL)
		return;
	odp_atomic_store_u32(&gbl_args->suite.exit_worker, 1);
}

static int bench_packet_export(void *data)
{
	args_t *gbl_args = data;
	int ret = 0;

	if (test_common_write("%s", "function name,64B,128B,256B,512B,1024B,1518B,2048B\n")) {
		ret = -1;
		goto exit;
	}

	for (int i = 0; i < gbl_args->suite.num_bench; i++) {
		if (test_common_write("odp_%s,%f,%f,%f,%f,%f,%f,%f\n",
				      gbl_args->suite.bench[i].desc != NULL ?
				      gbl_args->suite.bench[i].desc : gbl_args->suite.bench[i].name,
				      gbl_args->result[0][i], gbl_args->result[1][i],
				      gbl_args->result[2][i], gbl_args->result[3][i],
				      gbl_args->result[4][i], gbl_args->result[5][i],
				      gbl_args->result[6][i])) {
			ret = -1;
			goto exit;
		}
	}

exit:
	test_common_write_term();

	return ret;
}

/**
 * Master function for running the microbenchmarks
 */
static int run_benchmarks(void *arg)
{
	int i;
	args_t *args = arg;
	bench_suite_t *suite = &args->suite;
	int num_sizes = ODPH_ARRAY_SIZE(test_packet_len);

	for (i = 0; i < num_sizes; i++) {
		printf("Packet length: %6d bytes", test_packet_len[i]);

		gbl_args->pkt.len = test_packet_len[i];

		suite->result = args->result[i];

		bench_run(suite);
	}

	printf("\n%-35s", "Benchmark / packet_size [B]");
	for (i = 0; i < num_sizes; i++)
		printf("%8.1d  ", test_packet_len[i]);

	printf("\n---------------------------------");
	for (i = 0; i < num_sizes; i++)
		printf("----------");

	for (i = 0; i < suite->num_bench; i++) {
		printf("\n[%02d] odp_%-26s", i + 1, suite->bench[i].desc != NULL ?
		       suite->bench[i].desc : suite->bench[i].name);

		for (int j = 0; j < num_sizes; j++)
			printf("%8.1f  ", args->result[j][i]);
	}
	printf("\n\n");

	if (args->common_options.is_export) {
		if (bench_packet_export(args)) {
			ODPH_ERR("Error: Export failed\n");
			return -1;
		}
	}

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

typedef struct test_packet_t {
	const uint8_t *data;
	int len;
} test_packet_t;

test_packet_t test_packets[] = {
	{test_packet_arp, sizeof(test_packet_arp)},
	{test_packet_ipv4_icmp, sizeof(test_packet_ipv4_icmp)},
	{test_packet_ipv6_icmp, sizeof(test_packet_ipv6_icmp)},
	{test_packet_ipv4_tcp, sizeof(test_packet_ipv4_tcp)},
	{test_packet_ipv6_tcp, sizeof(test_packet_ipv6_tcp)},
	{test_packet_ipv4_udp, sizeof(test_packet_ipv4_udp)},
	{test_packet_ipv6_udp, sizeof(test_packet_ipv6_udp)},
	{test_packet_ipv4_sctp, sizeof(test_packet_ipv4_sctp)},
	{test_packet_ipv6_sctp, sizeof(test_packet_ipv6_sctp)},
	{test_packet_vlan_ipv4_udp, sizeof(test_packet_vlan_ipv4_udp)},
	{test_packet_mcast_eth_ipv4_udp, sizeof(test_packet_mcast_eth_ipv4_udp)},
	{test_packet_mcast_eth_ipv6_udp, sizeof(test_packet_mcast_eth_ipv6_udp)},
	{test_packet_ipv4_udp_last_frag, sizeof(test_packet_ipv4_udp_last_frag)},
};

static uint32_t rnd(void)
{
	static uint64_t s = 1;
	uint64_t prime = 0x7fffffff;

	s = (0x12345678 * s) % prime;
	return s;
}

static void create_packets_misc(void)
{
	int num_types = ODPH_ARRAY_SIZE(test_packets);

	for (int i = 0; i < TEST_REPEAT_COUNT; i++) {
		test_packet_t *tp = &test_packets[rnd() % num_types];
		odp_packet_t *pkt = &gbl_args->pkt_tbl[i];

		*pkt = odp_packet_alloc(gbl_args->pool, tp->len);
		if (*pkt == ODP_PACKET_INVALID)
			ODPH_ABORT("Allocating test packets failed\n");
		if (odp_packet_copy_from_mem(*pkt, 0, tp->len, tp->data))
			ODPH_ABORT("Copying test packet failed\n");
	}
}

static void create_packets_misc_parsed(void)
{
	odp_packet_parse_param_t param = {
		.proto = ODP_PROTO_ETH,
		.last_layer = ODP_PROTO_LAYER_ALL,
		.chksums.all_chksum = 0
	};

	create_packets_misc();
	for (int i = 0; i < TEST_REPEAT_COUNT; i++) {
		if (odp_packet_parse(gbl_args->pkt_tbl[i], 0, &param))
			ODPH_ABORT("Packet parsing failed\n");
	}
}

static void alloc_parse_packets(const void *pkt_data, uint32_t len)
{
	int i;

	allocate_test_packets(len, gbl_args->pkt_tbl, TEST_REPEAT_COUNT);

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		if (odp_packet_copy_from_mem(gbl_args->pkt_tbl[i], 0, len,
					     pkt_data))
			ODPH_ABORT("Copying test packet failed\n");
	}
}

static void alloc_parse_packets_ipv4_tcp(void)
{
	alloc_parse_packets(test_packet_ipv4_tcp, sizeof(test_packet_ipv4_tcp));
}

static void alloc_parse_packets_ipv4_udp(void)
{
	alloc_parse_packets(test_packet_ipv4_udp, sizeof(test_packet_ipv4_udp));
}

static void alloc_parse_packets_ipv6_tcp(void)
{
	alloc_parse_packets(test_packet_ipv6_tcp, sizeof(test_packet_ipv6_tcp));
}

static void alloc_parse_packets_ipv6_udp(void)
{
	alloc_parse_packets(test_packet_ipv6_udp, sizeof(test_packet_ipv6_udp));
}

static void alloc_parse_packets_multi(const void *pkt_data, uint32_t len)
{
	int i;

	allocate_test_packets(len, gbl_args->pkt_tbl,
			      TEST_REPEAT_COUNT * gbl_args->appl.burst_size);

	for (i = 0; i < TEST_REPEAT_COUNT * gbl_args->appl.burst_size; i++) {
		if (odp_packet_copy_from_mem(gbl_args->pkt_tbl[i], 0, len,
					     pkt_data))
			ODPH_ABORT("Copying test packet failed\n");
	}
}

static void alloc_parse_packets_multi_ipv4_tcp(void)
{
	alloc_parse_packets_multi(test_packet_ipv4_tcp,
				  sizeof(test_packet_ipv4_tcp));
}

static void alloc_parse_packets_multi_ipv4_udp(void)
{
	alloc_parse_packets_multi(test_packet_ipv4_udp,
				  sizeof(test_packet_ipv4_udp));
}

static void alloc_parse_packets_multi_ipv6_tcp(void)
{
	alloc_parse_packets_multi(test_packet_ipv6_tcp,
				  sizeof(test_packet_ipv6_tcp));
}

static void alloc_parse_packets_multi_ipv6_udp(void)
{
	alloc_parse_packets_multi(test_packet_ipv6_udp,
				  sizeof(test_packet_ipv6_udp));
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

static int num_misc_event_types = 4;

static void create_events_misc(void)
{
	odp_packet_t pkt;
	odp_buffer_t buf;
	odp_timeout_t tmo;
	odp_event_vector_t evv;
	odp_event_t events[num_misc_event_types];
	int i;

	pkt = odp_packet_alloc(gbl_args->pool, gbl_args->pkt.len);
	if (pkt == ODP_PACKET_INVALID)
		ODPH_ABORT("Packet alloc failed\n");

	buf = odp_buffer_alloc(gbl_args->pool_buf);
	if (buf == ODP_BUFFER_INVALID)
		ODPH_ABORT("Buffer alloc failed\n");

	tmo = odp_timeout_alloc(gbl_args->pool_tmo);
	if (tmo == ODP_TIMEOUT_INVALID)
		ODPH_ABORT("Timeout alloc failed\n");

	events[0] = odp_packet_to_event(pkt);
	events[1] = odp_buffer_to_event(buf);
	events[2] = odp_timeout_to_event(tmo);

	if (gbl_args->pool_evv != ODP_POOL_INVALID) {
		evv = odp_event_vector_alloc(gbl_args->pool_evv);
		if (evv == ODP_EVENT_VECTOR_INVALID)
			ODPH_ABORT("Event vector alloc failed\n");
		events[3] = odp_event_vector_to_event(evv);
	} else {
		num_misc_event_types = 3;
	}

	for (i = 0; i < num_misc_event_types; i++)
		gbl_args->event_tbl[i] = events[i];
	for (; i < TEST_REPEAT_COUNT; i++)
		gbl_args->event_tbl[i] = events[rnd() % num_misc_event_types];
}

static void free_events_misc(void)
{
	for (int i = 0; i < num_misc_event_types; i++)
		odp_event_free(gbl_args->event_tbl[i]);
}

static void create_events(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	create_packets();

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->event_tbl[i] = odp_packet_to_event(pkt_tbl[i]);
}

static void create_events_multi(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	allocate_test_packets(gbl_args->pkt.len, gbl_args->pkt_tbl,
			      TEST_REPEAT_COUNT * gbl_args->appl.burst_size);

	for (i = 0; i < TEST_REPEAT_COUNT * gbl_args->appl.burst_size; i++)
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

static int packet_alloc(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		odp_packet_t pkt;

		pkt = odp_packet_alloc(gbl_args->pool, gbl_args->pkt.len);

		gbl_args->pkt_tbl[i] = pkt;
	}

	return i;
}

static int packet_alloc_multi(void)
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

static int packet_free(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_free(gbl_args->pkt_tbl[i]);

	return i;
}

static int event_free(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_free(gbl_args->event_tbl[i]);

	return i;
}

static int packet_free_multi(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		int pkt_idx = i * gbl_args->appl.burst_size;

		odp_packet_free_multi(&gbl_args->pkt_tbl[pkt_idx],
				      gbl_args->appl.burst_size);
	}
	return i;
}

static int event_free_multi(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		int pkt_idx = i * gbl_args->appl.burst_size;

		odp_event_free_multi(&gbl_args->event_tbl[pkt_idx],
				     gbl_args->appl.burst_size);
	}
	return i;
}

static int packet_free_sp(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		int pkt_idx = i * gbl_args->appl.burst_size;

		odp_packet_free_sp(&gbl_args->pkt_tbl[pkt_idx],
				   gbl_args->appl.burst_size);
	}
	return i;
}

static int event_free_sp(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		int pkt_idx = i * gbl_args->appl.burst_size;

		odp_event_free_sp(&gbl_args->event_tbl[pkt_idx],
				  gbl_args->appl.burst_size);
	}
	return i;
}

static int packet_alloc_free(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		odp_packet_t pkt;

		pkt = odp_packet_alloc(gbl_args->pool, gbl_args->pkt.len);

		odp_packet_free(pkt);
	}
	return i;
}

static int packet_alloc_free_multi(void)
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

static int packet_reset(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_reset(gbl_args->pkt_tbl[i],
					gbl_args->pkt.len);
	return !ret;
}

static int packet_reset_meta(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_reset_meta(gbl_args->pkt_tbl[i]);

	return i;
}

static int packet_reset_max_len(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_reset_max_len(gbl_args->pkt_tbl[i]);

	return ret;
}

static int packet_from_event(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		pkt_tbl[i] = odp_packet_from_event(gbl_args->event_tbl[i]);

	return i;
}

static int packet_from_event_multi(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		int idx = i * gbl_args->appl.burst_size;

		odp_packet_from_event_multi(&gbl_args->pkt_tbl[idx],
					    &gbl_args->event_tbl[idx],
					    gbl_args->appl.burst_size);
	}
	return i;
}

static int packet_to_event(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->event_tbl[i] = odp_packet_to_event(pkt_tbl[i]);

	return i;
}

static int packet_to_event_multi(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		int idx = i * gbl_args->appl.burst_size;

		odp_packet_to_event_multi(&gbl_args->pkt_tbl[idx],
					  &gbl_args->event_tbl[idx],
					  gbl_args->appl.burst_size);
	}
	return i;
}

static int packet_head(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_head(gbl_args->pkt_tbl[i]);

	return i;
}

static int packet_buf_len(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_buf_len(gbl_args->pkt_tbl[i]);

	return ret;
}

static int packet_data(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_data(gbl_args->pkt_tbl[i]);

	return i;
}

static int packet_data_seg_len(void)
{
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	uint32_t *output_tbl = gbl_args->output_tbl;
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_data_seg_len(pkt_tbl[i],
							       &output_tbl[i]);
	return i;
}

static int packet_seg_len(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_seg_len(gbl_args->pkt_tbl[i]);

	return ret;
}

static int packet_len(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_len(gbl_args->pkt_tbl[i]);

	return ret;
}

static int packet_headroom(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_headroom(gbl_args->pkt_tbl[i]);

	return i + ret;
}

static int packet_tailroom(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_tailroom(gbl_args->pkt_tbl[i]);

	return i + ret;
}

static int packet_tail(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_tail(gbl_args->pkt_tbl[i]);

	return i;
}

static int packet_offset(void)
{
	int i;
	uint32_t offset = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_offset(gbl_args->pkt_tbl[i],
							 offset, NULL, NULL);
	return i;
}

static int packet_prefetch(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_prefetch(gbl_args->pkt_tbl[i], 0, gbl_args->pkt.len);

	return i;
}

static int packet_push_head(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	uint32_t hroom = gbl_args->pkt.headroom;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_push_head(pkt_tbl[i], hroom);

	return i;
}

static int packet_pull_head(void)
{
	int i;
	uint32_t len = gbl_args->pkt.seg_len - 1;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_pull_head(pkt_tbl[i], len);

	return i;
}

static int packet_push_tail(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	uint32_t troom = gbl_args->pkt.tailroom;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_push_tail(pkt_tbl[i], troom);

	return i;
}

static int packet_pull_tail(void)
{
	int i;
	uint32_t len = gbl_args->pkt.seg_len - 1;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_pull_tail(pkt_tbl[i], len);

	return i;
}

static int packet_extend_head(void)
{
	int i;
	int ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	uint32_t *data_tbl = gbl_args->output_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_extend_head(&pkt_tbl[i], len, &ptr_tbl[i],
					      &data_tbl[i]);
	return ret >= 0;
}

static int packet_trunc_head(void)
{
	int i;
	int ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	uint32_t *data_tbl = gbl_args->output_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_trunc_head(&pkt_tbl[i], len, &ptr_tbl[i],
					     &data_tbl[i]);
	return ret >= 0;
}

static int packet_extend_tail(void)
{
	int i;
	int ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	uint32_t *data_tbl = gbl_args->output_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_extend_tail(&pkt_tbl[i], len, &ptr_tbl[i],
					      &data_tbl[i]);
	return ret >= 0;
}

static int packet_trunc_tail(void)
{
	int i;
	int ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	uint32_t *data_tbl = gbl_args->output_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_trunc_tail(&pkt_tbl[i], len, &ptr_tbl[i],
					     &data_tbl[i]);
	return ret >= 0;
}

static int packet_add_data(void)
{
	int i;
	int ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	uint32_t len = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_add_data(&pkt_tbl[i], 0, len);

	return ret >= 0;
}

static int packet_rem_data(void)
{
	int i;
	int ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	uint32_t len = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_rem_data(&pkt_tbl[i], 0, len);

	return ret >= 0;
}

static int packet_align(void)
{
	int i;
	int ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_align(&pkt_tbl[i], TEST_ALIGN_OFFSET,
					TEST_ALIGN_LEN, TEST_ALIGN);
	return ret >= 0;
}

static int packet_is_segmented(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_is_segmented(gbl_args->pkt_tbl[i]);

	return (ret == 0) ? 1 : ret;
}

static int packet_num_segs(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_num_segs(gbl_args->pkt_tbl[i]);

	return ret;
}

static int packet_first_seg(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->seg_tbl[i] = odp_packet_first_seg(pkt_tbl[i]);

	return i;
}

static int packet_last_seg(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->seg_tbl[i] = odp_packet_last_seg(pkt_tbl[i]);

	return i;
}

static int packet_next_seg(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_seg_t *seg_tbl = gbl_args->seg_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->seg_tbl[i] = odp_packet_next_seg(pkt_tbl[i],
							   seg_tbl[i]);
	return i;
}

static int packet_seg_data(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_seg_t *seg_tbl = gbl_args->seg_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_seg_data(pkt_tbl[i],
							   seg_tbl[i]);
	return i;
}

static int packet_seg_data_len(void)
{
	int i;
	uint32_t ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_seg_t *seg_tbl = gbl_args->seg_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_seg_data_len(pkt_tbl[i], seg_tbl[i]);

	return ret;
}

static int packet_concat(void)
{
	int i;
	int ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *frag_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_concat(&pkt_tbl[i], frag_tbl[i]);

	return ret >= 0;
}

static int packet_split(void)
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

static int packet_copy(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *cpy_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		cpy_tbl[i] = odp_packet_copy(pkt_tbl[i], gbl_args->pool);

	return i;
}

static int packet_copy_part(void)
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

static int packet_copy_to_mem(void)
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

static int packet_copy_from_mem(void)
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

static int packet_copy_from_pkt(void)
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

static int packet_copy_data(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t len = gbl_args->pkt.len / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_copy_data(pkt_tbl[i], 0, len, len);

	return !ret;
}

static int packet_move_data(void)
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

static int packet_pool(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->pool_tbl[i] = odp_packet_pool(gbl_args->pkt_tbl[i]);

	return i;
}

static int event_pool(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->pool_tbl[i] = odp_event_pool(gbl_args->event_tbl[i]);

	return i;
}

static int packet_input(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->pktio_tbl[i] = odp_packet_input(gbl_args->pkt_tbl[i]);

	return i;
}

static int packet_input_index(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_input_index(gbl_args->pkt_tbl[i]);

	return (ret == 0) ? 1 : ret;
}

static int packet_user_ptr(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_user_ptr(pkt_tbl[i]);

	return i;
}

static int packet_user_ptr_set(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_user_ptr_set(gbl_args->pkt_tbl[i],
					gbl_args->ptr_tbl[i]);

	return i;
}

static int packet_user_area(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_user_area(pkt_tbl[i]);

	return i;
}

static int event_user_area(void)
{
	int i;
	odp_event_t *event_tbl = gbl_args->event_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_event_user_area(event_tbl[i]);

	return i;
}

static int packet_user_area_size(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_user_area_size(gbl_args->pkt_tbl[i]);

	return ret;
}

static int packet_user_flag(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += !odp_packet_user_flag(gbl_args->pkt_tbl[i]);

	return ret;
}

static int event_user_area_and_flag(void)
{
	odp_event_t *event_tbl = gbl_args->event_tbl;
	void **ptr_tbl = gbl_args->ptr_tbl;
	int ret = 0;
	int flag;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++) {
		ptr_tbl[i] = odp_event_user_area_and_flag(event_tbl[i], &flag);
		ret += !flag;
	}

	return ret;
}

static int packet_user_flag_set(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_user_flag_set(gbl_args->pkt_tbl[i], 1);

	return i;
}

static int event_user_flag_set(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_event_user_flag_set(gbl_args->event_tbl[i], 1);

	return i;
}

#define DEF_FLAG_TEST_FUN(name, func)	                           \
static int name(void)                                              \
{                                                                  \
	uint32_t ret = 0;                                          \
								   \
	for (int i = 0; i < TEST_REPEAT_COUNT; i++)                \
		ret += func(gbl_args->pkt_tbl[i]); \
								   \
	return ret <= TEST_REPEAT_COUNT;                           \
}

DEF_FLAG_TEST_FUN(packet_has_error,     odp_packet_has_error)
DEF_FLAG_TEST_FUN(packet_has_l2_error,  odp_packet_has_l2_error)
DEF_FLAG_TEST_FUN(packet_has_l3_error,  odp_packet_has_l3_error)
DEF_FLAG_TEST_FUN(packet_has_l4_error,  odp_packet_has_l4_error)
DEF_FLAG_TEST_FUN(packet_has_l2,        odp_packet_has_l2)
DEF_FLAG_TEST_FUN(packet_has_l3,        odp_packet_has_l3)
DEF_FLAG_TEST_FUN(packet_has_l4,        odp_packet_has_l4)
DEF_FLAG_TEST_FUN(packet_has_eth,       odp_packet_has_eth)
DEF_FLAG_TEST_FUN(packet_has_eth_bcast, odp_packet_has_eth_bcast)
DEF_FLAG_TEST_FUN(packet_has_eth_mcast, odp_packet_has_eth_mcast)
DEF_FLAG_TEST_FUN(packet_has_jumbo,     odp_packet_has_jumbo)
DEF_FLAG_TEST_FUN(packet_has_vlan,      odp_packet_has_vlan)
DEF_FLAG_TEST_FUN(packet_has_vlan_qinq, odp_packet_has_vlan_qinq)
DEF_FLAG_TEST_FUN(packet_has_arp,       odp_packet_has_arp)
DEF_FLAG_TEST_FUN(packet_has_ipv4,      odp_packet_has_ipv4)
DEF_FLAG_TEST_FUN(packet_has_ipv6,      odp_packet_has_ipv6)
DEF_FLAG_TEST_FUN(packet_has_ip_bcast,  odp_packet_has_ip_bcast)
DEF_FLAG_TEST_FUN(packet_has_ip_mcast,  odp_packet_has_ip_mcast)
DEF_FLAG_TEST_FUN(packet_has_ipfrag,    odp_packet_has_ipfrag)
DEF_FLAG_TEST_FUN(packet_has_ipopt,     odp_packet_has_ipopt)
DEF_FLAG_TEST_FUN(packet_has_ipsec,     odp_packet_has_ipsec)
DEF_FLAG_TEST_FUN(packet_has_udp,       odp_packet_has_udp)
DEF_FLAG_TEST_FUN(packet_has_tcp,       odp_packet_has_tcp)
DEF_FLAG_TEST_FUN(packet_has_sctp,      odp_packet_has_sctp)
DEF_FLAG_TEST_FUN(packet_has_icmp,      odp_packet_has_icmp)
DEF_FLAG_TEST_FUN(packet_has_flow_hash, odp_packet_has_flow_hash)
DEF_FLAG_TEST_FUN(packet_has_ts,        odp_packet_has_ts)

static int packet_l2_type(void)
{
	uint32_t ret = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l2_type(gbl_args->pkt_tbl[i]);

	return ret;
}

static int packet_l2_ptr(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_l2_ptr(gbl_args->pkt_tbl[i],
							 NULL);
	return i;
}

static int packet_l2_offset(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l2_offset(gbl_args->pkt_tbl[i]);

	return ret >= 0;
}

static int packet_l2_offset_set(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t offset = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l2_offset_set(gbl_args->pkt_tbl[i], offset);

	return !ret;
}

static int packet_l3_type(void)
{
	uint32_t ret = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l3_type(gbl_args->pkt_tbl[i]);

	return ret;
}

static int packet_l3_ptr(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_l3_ptr(gbl_args->pkt_tbl[i],
							 NULL);
	return i;
}

static int packet_l3_offset(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l3_offset(gbl_args->pkt_tbl[i]);

	return ret >= 0;
}

static int packet_l3_offset_set(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t offset = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l3_offset_set(gbl_args->pkt_tbl[i], offset);

	return !ret;
}

static int packet_l4_type(void)
{
	uint32_t ret = 0;

	for (int i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l4_type(gbl_args->pkt_tbl[i]);

	return ret;
}

static int packet_l4_ptr(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ptr_tbl[i] = odp_packet_l4_ptr(gbl_args->pkt_tbl[i],
							 NULL);
	return i;
}

static int packet_l4_offset(void)
{
	int i;
	int ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l4_offset(gbl_args->pkt_tbl[i]);

	return ret >= 0;
}

static int packet_l4_offset_set(void)
{
	int i;
	uint32_t ret = 0;
	uint32_t offset = gbl_args->pkt.len / 2;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_l4_offset_set(gbl_args->pkt_tbl[i], offset);

	return !ret;
}

static int packet_flow_hash(void)
{
	int i;
	uint32_t ret = 0;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_flow_hash(gbl_args->pkt_tbl[i]);

	return ret;
}

static int packet_flow_hash_set(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_flow_hash_set(gbl_args->pkt_tbl[i], i);

	return i;
}

static int packet_ts(void)
{
	int i;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->ts_tbl[i] = odp_packet_ts(gbl_args->pkt_tbl[i]);

	return i;
}

static int packet_ts_set(void)
{
	int i;
	odp_time_t ts = odp_time_local();

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		odp_packet_ts_set(gbl_args->pkt_tbl[i], ts);

	return i;
}

static int packet_ref_static(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *ref_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ref_tbl[i] = odp_packet_ref_static(pkt_tbl[i]);

	return i;
}

static int packet_ref(void)
{
	int i;
	uint32_t offset = TEST_MIN_PKT_SIZE / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *ref_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ref_tbl[i] = odp_packet_ref(pkt_tbl[i], offset);

	return i;
}

static int packet_ref_pkt(void)
{
	int i;
	uint32_t offset = TEST_MIN_PKT_SIZE / 2;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	odp_packet_t *hdr_tbl = gbl_args->pkt2_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		hdr_tbl[i] = odp_packet_ref_pkt(pkt_tbl[i], offset, hdr_tbl[i]);

	return i;
}

static int packet_has_ref(void)
{
	int i;
	uint32_t ret = 0;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_has_ref(pkt_tbl[i]);

	return i + ret;
}

static int packet_subtype(void)
{
	int i;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->output_tbl[i] = odp_packet_subtype(pkt_tbl[i]);

	return i;
}

static int event_subtype(void)
{
	int i;
	odp_event_t *event_tbl = gbl_args->event_tbl;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		gbl_args->output_tbl[i] = odp_event_subtype(event_tbl[i]);

	return i;
}

static int do_packet_parse(int chksum)
{
	odp_packet_parse_param_t param;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	int ret = 0;
	int i;

	memset(&param, 0, sizeof(odp_packet_parse_param_t));
	param.proto = ODP_PROTO_ETH;
	param.last_layer = ODP_PROTO_LAYER_ALL;
	param.chksums.chksum.ipv4 = !!chksum;
	param.chksums.chksum.tcp = !!chksum;
	param.chksums.chksum.udp = !!chksum;

	for (i = 0; i < TEST_REPEAT_COUNT; i++)
		ret += odp_packet_parse(pkt_tbl[i], 0, &param);

	return !ret;
}

static int packet_parse(void)
{
	return do_packet_parse(1);
}

static int packet_parse_no_chksum(void)
{
	return do_packet_parse(0);
}

static int packet_parse_multi(void)
{
	int burst_size = gbl_args->appl.burst_size;
	int ret = 0;
	int i;
	odp_packet_parse_param_t param;
	odp_packet_t *pkt_tbl = gbl_args->pkt_tbl;
	uint32_t offsets[burst_size];

	memset(&offsets, 0, sizeof(offsets));

	memset(&param, 0, sizeof(odp_packet_parse_param_t));
	param.proto = ODP_PROTO_ETH;
	param.last_layer = ODP_PROTO_LAYER_ALL;
	param.chksums.chksum.ipv4 = 1;
	param.chksums.chksum.tcp = 1;
	param.chksums.chksum.udp = 1;

	for (i = 0; i < TEST_REPEAT_COUNT; i++) {
		int idx = i * burst_size;

		ret += odp_packet_parse_multi(&pkt_tbl[idx], offsets,
					      burst_size, &param);
	}
	return (ret == TEST_REPEAT_COUNT * burst_size);
}

/**
 * Print usage information
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
	       "  -b, --burst <num>       Test packet burst size.\n"
	       "  -c, --cache_size <num>  Pool cache size.\n"
	       "  -i, --index <idx>       Benchmark index to run indefinitely.\n"
	       "  -r, --rounds <num>      Run each test case 'num' times (default %u).\n"
	       "  -t, --time <opt>        Time measurement. 0: measure CPU cycles (default), 1: measure time\n"
	       "  -h, --help              Display help and exit.\n\n"
	       "\n", NO_PATH(progname), NO_PATH(progname), TEST_ROUNDS);
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
	static const struct option longopts[] = {
		{"burst", required_argument, NULL, 'b'},
		{"cache_size", required_argument, NULL, 'c'},
		{"index", required_argument, NULL, 'i'},
		{"rounds", required_argument, NULL, 'r'},
		{"time", required_argument, NULL, 't'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts =  "c:b:i:r:t:h";

	appl_args->bench_idx = 0; /* Run all benchmarks */
	appl_args->burst_size = TEST_DEF_BURST;
	appl_args->cache_size = -1;
	appl_args->rounds = TEST_ROUNDS;
	appl_args->time = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cache_size = atoi(optarg);
			break;
		case 'b':
			appl_args->burst_size = atoi(optarg);
			break;
		case 'i':
			appl_args->bench_idx = atoi(optarg);
			break;
		case 'r':
			appl_args->rounds = atoi(optarg);
			break;
		case 't':
			appl_args->time = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (appl_args->burst_size < 1 ||
	    appl_args->burst_size > TEST_MAX_BURST) {
		printf("Invalid burst size (max %d)\n", TEST_MAX_BURST);
		exit(EXIT_FAILURE);
	}

	if (appl_args->rounds < 1) {
		printf("Invalid number test rounds: %d\n", appl_args->rounds);
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
	BENCH_INFO(packet_alloc, NULL, free_packets, NULL),
	BENCH_INFO(packet_alloc_multi, NULL, free_packets_multi, NULL),
	BENCH_INFO(packet_free, create_packets, NULL, NULL),
	BENCH_INFO(event_free, create_events, NULL, NULL),
	BENCH_INFO(packet_free_multi, alloc_packets_multi, NULL, NULL),
	BENCH_INFO(event_free_multi, create_events_multi, NULL, NULL),
	BENCH_INFO(packet_free_sp, alloc_packets_multi, NULL, NULL),
	BENCH_INFO(event_free_sp, create_events_multi, NULL, NULL),
	BENCH_INFO(packet_alloc_free, NULL, NULL, NULL),
	BENCH_INFO(packet_alloc_free_multi, NULL, NULL, NULL),
	BENCH_INFO(packet_reset, create_packets, free_packets, NULL),
	BENCH_INFO(packet_reset_meta, create_packets, free_packets, NULL),
	BENCH_INFO(packet_reset_max_len, create_packets, free_packets, NULL),
	BENCH_INFO(packet_from_event, create_events, free_packets, NULL),
	BENCH_INFO(packet_from_event_multi, create_events_multi, free_packets_multi, NULL),
	BENCH_INFO(packet_to_event, create_packets, free_packets, NULL),
	BENCH_INFO(packet_to_event_multi, alloc_packets_multi, free_packets_multi, NULL),
	BENCH_INFO(packet_head, create_packets, free_packets, NULL),
	BENCH_INFO(packet_buf_len, create_packets, free_packets, NULL),
	BENCH_INFO(packet_data, create_packets, free_packets, NULL),
	BENCH_INFO(packet_data_seg_len, create_packets, free_packets, NULL),
	BENCH_INFO(packet_seg_len, create_packets, free_packets, NULL),
	BENCH_INFO(packet_len, create_packets, free_packets, NULL),
	BENCH_INFO(packet_headroom, create_packets, free_packets, NULL),
	BENCH_INFO(packet_tailroom, create_packets, free_packets, NULL),
	BENCH_INFO(packet_tail, create_packets, free_packets, NULL),
	BENCH_INFO(packet_offset, create_packets, free_packets, NULL),
	BENCH_INFO(packet_prefetch, create_packets, free_packets, NULL),
	BENCH_INFO(packet_push_head, create_packets, free_packets, NULL),
	BENCH_INFO(packet_pull_head, create_packets, free_packets, NULL),
	BENCH_INFO(packet_push_tail, create_packets, free_packets, NULL),
	BENCH_INFO(packet_pull_tail, create_packets, free_packets, NULL),
	BENCH_INFO(packet_extend_head, alloc_packets_half, free_packets, NULL),
	BENCH_INFO(packet_trunc_head, create_packets, free_packets, NULL),
	BENCH_INFO(packet_extend_tail, alloc_packets_half, free_packets, NULL),
	BENCH_INFO(packet_trunc_tail, create_packets, free_packets, NULL),
	BENCH_INFO(packet_add_data, alloc_packets_half, free_packets, NULL),
	BENCH_INFO(packet_rem_data, create_packets, free_packets, NULL),
	BENCH_INFO(packet_align, create_packets, free_packets, NULL),
	BENCH_INFO(packet_is_segmented, create_packets, free_packets, NULL),
	BENCH_INFO(packet_num_segs, create_packets, free_packets, NULL),
	BENCH_INFO(packet_first_seg, create_packets, free_packets, NULL),
	BENCH_INFO(packet_last_seg, create_packets, free_packets, NULL),
	BENCH_INFO(packet_next_seg, create_packets, free_packets, NULL),
	BENCH_INFO(packet_seg_data, create_packets, free_packets, NULL),
	BENCH_INFO(packet_seg_data_len, create_packets, free_packets, NULL),
	BENCH_INFO(packet_concat, alloc_concat_packets, free_packets, NULL),
	BENCH_INFO(packet_split, create_packets, free_packets_twice, NULL),
	BENCH_INFO(packet_copy, create_packets, free_packets_twice, NULL),
	BENCH_INFO(packet_copy_part, create_packets, free_packets_twice, NULL),
	BENCH_INFO(packet_copy_to_mem, create_packets, free_packets, NULL),
	BENCH_INFO(packet_copy_from_mem, create_packets, free_packets, NULL),
	BENCH_INFO(packet_copy_from_pkt, alloc_packets_twice, free_packets_twice, NULL),
	BENCH_INFO(packet_copy_data, create_packets, free_packets, NULL),
	BENCH_INFO(packet_move_data, create_packets, free_packets, NULL),
	BENCH_INFO(packet_pool, create_packets, free_packets, NULL),
	BENCH_INFO(event_pool, create_events, free_packets, NULL),
	BENCH_INFO(packet_input, create_packets, free_packets, NULL),
	BENCH_INFO(packet_input_index, create_packets, free_packets, NULL),
	BENCH_INFO(packet_user_ptr, create_packets, free_packets, NULL),
	BENCH_INFO(packet_user_ptr_set, create_packets, free_packets, NULL),
	BENCH_INFO(packet_user_area, create_packets, free_packets, NULL),
	BENCH_INFO(event_user_area, create_events, free_packets, NULL),
	BENCH_INFO(event_user_area, create_events_misc, free_events_misc,
		   "event_user_area misc"),
	BENCH_INFO(packet_user_area_size, create_packets, free_packets, NULL),
	BENCH_INFO(packet_user_flag, create_packets, free_packets, NULL),
	BENCH_INFO(event_user_area_and_flag, create_events, free_packets, NULL),
	BENCH_INFO(event_user_area_and_flag, create_events_misc, free_events_misc,
		   "event_user_area_and_flag misc"),
	BENCH_INFO(packet_user_flag_set, create_packets, free_packets, NULL),
	BENCH_INFO(event_user_flag_set, create_events, free_packets, NULL),
	BENCH_INFO(event_user_flag_set, create_events_misc, free_events_misc,
		   "event user_flag_set misc"),

#define BINFO(fun) BENCH_INFO(fun, create_packets_misc_parsed, free_packets, NULL)
	BINFO(packet_has_error),
	BINFO(packet_has_l2_error),
	BINFO(packet_has_l3_error),
	BINFO(packet_has_l4_error),
	BINFO(packet_has_l2),
	BINFO(packet_has_l3),
	BINFO(packet_has_l4),
	BINFO(packet_has_eth),
	BINFO(packet_has_eth_bcast),
	BINFO(packet_has_eth_mcast),
	BINFO(packet_has_jumbo),
	BINFO(packet_has_vlan),
	BINFO(packet_has_vlan_qinq),
	BINFO(packet_has_arp),
	BINFO(packet_has_ipv4),
	BINFO(packet_has_ipv6),
	BINFO(packet_has_ip_bcast),
	BINFO(packet_has_ip_mcast),
	BINFO(packet_has_ipfrag),
	BINFO(packet_has_ipopt),
	BINFO(packet_has_ipsec),
	BINFO(packet_has_udp),
	BINFO(packet_has_tcp),
	BINFO(packet_has_sctp),
	BINFO(packet_has_icmp),
	BINFO(packet_has_flow_hash),
	BINFO(packet_has_ts),

	BENCH_INFO(packet_l2_type, create_packets_misc_parsed, free_packets, NULL),
	BENCH_INFO(packet_l2_ptr, create_packets, free_packets, NULL),
	BENCH_INFO(packet_l2_offset, create_packets, free_packets, NULL),
	BENCH_INFO(packet_l2_offset_set, create_packets, free_packets, NULL),
	BENCH_INFO(packet_l3_type, create_packets_misc_parsed, free_packets, NULL),
	BENCH_INFO(packet_l3_ptr, create_packets, free_packets, NULL),
	BENCH_INFO(packet_l3_offset, create_packets, free_packets, NULL),
	BENCH_INFO(packet_l3_offset_set, create_packets, free_packets, NULL),
	BENCH_INFO(packet_l4_type, create_packets_misc_parsed, free_packets, NULL),
	BENCH_INFO(packet_l4_ptr, create_packets, free_packets, NULL),
	BENCH_INFO(packet_l4_offset, create_packets, free_packets, NULL),
	BENCH_INFO(packet_l4_offset_set, create_packets, free_packets, NULL),
	BENCH_INFO(packet_flow_hash, create_packets, free_packets, NULL),
	BENCH_INFO(packet_flow_hash_set, create_packets, free_packets, NULL),
	BENCH_INFO(packet_ts, create_packets, free_packets, NULL),
	BENCH_INFO(packet_ts_set, create_packets, free_packets, NULL),
	BENCH_INFO(packet_ref_static, create_packets, free_packets_twice, NULL),
	BENCH_INFO(packet_ref, create_packets, free_packets_twice, NULL),
	BENCH_INFO(packet_ref_pkt, alloc_packets_twice, free_packets_twice, NULL),
	BENCH_INFO(packet_has_ref, alloc_ref_packets, free_packets_twice, NULL),
	BENCH_INFO(packet_subtype, create_packets, free_packets, NULL),
	BENCH_INFO(event_subtype, create_events, free_packets, NULL),
	BENCH_INFO(packet_parse, alloc_parse_packets_ipv4_tcp, free_packets,
		   "packet_parse ipv4/tcp"),
	BENCH_INFO(packet_parse, alloc_parse_packets_ipv4_udp, free_packets,
		   "packet_parse ipv4/udp"),
	BENCH_INFO(packet_parse, alloc_parse_packets_ipv6_tcp, free_packets,
		   "packet_parse ipv6/tcp"),
	BENCH_INFO(packet_parse, alloc_parse_packets_ipv6_udp, free_packets,
		   "packet_parse ipv6/udp"),
	BENCH_INFO(packet_parse, create_packets_misc, free_packets,
		   "packet_parse misc"),
	BENCH_INFO(packet_parse_no_chksum, create_packets_misc, free_packets,
		   "packet_parse misc no csum"),
	BENCH_INFO(packet_parse_multi, alloc_parse_packets_multi_ipv4_tcp, free_packets_multi,
		   "packet_parse_multi ipv4/tcp"),
	BENCH_INFO(packet_parse_multi, alloc_parse_packets_multi_ipv4_udp, free_packets_multi,
		   "packet_parse_multi ipv4/udp"),
	BENCH_INFO(packet_parse_multi, alloc_parse_packets_multi_ipv6_tcp, free_packets_multi,
		   "packet_parse_multi ipv6/tcp"),
	BENCH_INFO(packet_parse_multi, alloc_parse_packets_multi_ipv6_udp, free_packets_multi,
		   "packet_parse_multi ipv6/udp"),
};

ODP_STATIC_ASSERT(ODPH_ARRAY_SIZE(test_suite) < TEST_MAX_BENCH,
		  "Result array is too small to hold all the results");

static odp_pool_t create_pool(const char *name, const odp_pool_param_t *param)
{
	odp_pool_t pool = odp_pool_create(name, param);

	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: %s pool creation failed.\n", name);
		exit(EXIT_FAILURE);
	}
	return pool;
}

static odp_pool_t create_buffer_pool(const odp_pool_capability_t *capa)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_BUFFER;
	param.buf.num = 1;
	param.buf.size = 1;
	param.buf.uarea_size = capa->buf.max_uarea_size > 0 ? 1 : 0;
	return create_pool("buf", &param);
}

static odp_pool_t create_timeout_pool(const odp_pool_capability_t *capa)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_TIMEOUT;
	param.tmo.num = 1;
	param.tmo.uarea_size = capa->tmo.max_uarea_size > 0 ? 1 : 0;
	return create_pool("tmo", &param);
}

static odp_pool_t create_evv_pool(const odp_pool_capability_t *capa)
{
	odp_pool_param_t param;

	if (capa->event_vector.max_pools == 0)
		return ODP_POOL_INVALID;

	odp_pool_param_init(&param);
	param.type = ODP_POOL_EVENT_VECTOR;
	param.event_vector.num = 1;
	param.event_vector.max_size = capa->event_vector.max_size;
	param.event_vector.uarea_size = capa->event_vector.max_uarea_size > 0 ? 1 : 0;
	return create_pool("evv", &param);
}

/**
 * ODP packet microbenchmark application
 */
int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	test_common_options_t common_options;
	odph_thread_t worker_thread;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;
	int cpu;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_capability_t capa;
	odp_pool_param_t params;
	odp_instance_t instance;
	odp_init_t init_param;
	uint32_t pkt_num, seg_len;
	uint8_t ret;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	argc = test_common_parse_options(argc, argv);
	if (test_common_options(&common_options)) {
		ODPH_ERR("Error: reading test options failed\n");
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

	gbl_args->common_options = common_options;

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	bench_suite_init(&gbl_args->suite);
	gbl_args->suite.bench = test_suite;
	gbl_args->suite.num_bench = ODPH_ARRAY_SIZE(test_suite);
	gbl_args->suite.indef_idx = gbl_args->appl.bench_idx;
	gbl_args->suite.rounds = gbl_args->appl.rounds;
	gbl_args->suite.repeat_count = TEST_REPEAT_COUNT;
	gbl_args->suite.measure_time = !!gbl_args->appl.time;

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

	/* At least 2 x TEST_REPEAT_COUNT packets are required for the tests and depending on the
	 * implementation extra packets may be required for packet references. */
	pkt_num = (gbl_args->appl.burst_size > 4) ?
			gbl_args->appl.burst_size * TEST_REPEAT_COUNT :
			4 * TEST_REPEAT_COUNT;

	if (capa.pkt.max_num && capa.pkt.max_num < pkt_num) {
		ODPH_ERR("Error: packet pool size not supported.\n");
		printf("MAX: %" PRIu32 "\n", capa.pkt.max_num);
		exit(EXIT_FAILURE);
	} else if (capa.pkt.max_len &&
		   capa.pkt.max_len < 2 * TEST_MAX_PKT_SIZE) {
		ODPH_ERR("Error: packet length not supported.\n");
		exit(EXIT_FAILURE);
	} else if (capa.pkt.max_uarea_size &&
		   capa.pkt.max_uarea_size < PKT_POOL_UAREA_SIZE) {
		ODPH_ERR("Error: user area size not supported.\n");
		exit(EXIT_FAILURE);
	} else if (gbl_args->appl.cache_size > (int)capa.pkt.max_cache_size) {
		ODPH_ERR("Error: cache size not supported (max %" PRIu32 ")\n",
			 capa.pkt.max_cache_size);
		exit(EXIT_FAILURE);
	}

	seg_len = TEST_MAX_PKT_SIZE;
	if (capa.pkt.max_seg_len && capa.pkt.max_seg_len < seg_len) {
		seg_len = capa.pkt.max_seg_len;
		printf("\nWarn: allocated packets may be segmented (min seg_len=%" PRIu32 ")\n\n",
		       seg_len);
	}

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = seg_len;
	/* Using packet length as twice the TEST_MAX_PKT_SIZE as some
	 * test cases (packet_ref_pkt) might allocate a bigger
	 * packet than TEST_MAX_PKT_SIZE.
	 */
	params.pkt.len     = 2 * TEST_MAX_PKT_SIZE;
	params.pkt.num     = pkt_num;
	params.pkt.uarea_size = PKT_POOL_UAREA_SIZE;
	if (gbl_args->appl.cache_size >= 0)
		params.pkt.cache_size = gbl_args->appl.cache_size;
	params.type        = ODP_POOL_PACKET;

	gbl_args->pool = odp_pool_create("packet pool", &params);
	if (gbl_args->pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	gbl_args->pool_buf = create_buffer_pool(&capa);
	gbl_args->pool_tmo = create_timeout_pool(&capa);
	gbl_args->pool_evv = create_evv_pool(&capa);

	printf("CPU:               %i\n", odp_cpumask_first(&cpumask));
	printf("CPU mask:          %s\n", cpumaskstr);
	printf("Burst size:        %d\n", gbl_args->appl.burst_size);
	printf("Bench repeat:      %d\n", TEST_REPEAT_COUNT);
	printf("Measurement unit:  %s\n", gbl_args->appl.time ? "nsec" : "CPU cycles");
	printf("Test rounds:       %u\n", gbl_args->appl.rounds);
	if (gbl_args->appl.cache_size < 0)
		printf("Pool cache size:   default\n");
	else
		printf("Pool cache size:   %d\n", gbl_args->appl.cache_size);

	odp_pool_print(gbl_args->pool);

	memset(&worker_thread, 0, sizeof(odph_thread_t));

	signal(SIGINT, sig_handler);

	/* Create worker threads */
	cpu = odp_cpumask_first(&cpumask);

	odp_cpumask_t thd_mask;

	odp_cpumask_zero(&thd_mask);
	odp_cpumask_set(&thd_mask, cpu);

	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &thd_mask;
	thr_common.share_param = 1;

	odph_thread_param_init(&thr_param);
	thr_param.start = run_benchmarks;
	thr_param.arg = gbl_args;
	thr_param.thr_type = ODP_THREAD_WORKER;

	odph_thread_create(&worker_thread, &thr_common, &thr_param, 1);

	odph_thread_join(&worker_thread, 1);

	ret = gbl_args->suite.retval;

	if (odp_pool_destroy(gbl_args->pool) ||
	    odp_pool_destroy(gbl_args->pool_buf) ||
	    odp_pool_destroy(gbl_args->pool_tmo) ||
	    (gbl_args->pool_evv != ODP_POOL_INVALID && odp_pool_destroy(gbl_args->pool_evv))) {
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

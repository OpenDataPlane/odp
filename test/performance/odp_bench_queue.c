/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/**
 * @example odp_bench_queue.c
 *
 * Microbenchmark application for queue API functions
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <bench_common.h>
#include <export_results.h>

#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#define TEST_MAX_BURST 32U
#define TEST_DEF_BURST 8U
#define TEST_REPEAT_COUNT 1000U
#define TEST_ROUNDS 100U
#define TEST_MAX_QUEUES (32U * 1024U)
#define TEST_MAX_BENCH 40U
#define TEST_MAX_DATA_ARR (TEST_MAX_BURST * TEST_REPEAT_COUNT)

#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

#define BENCH_INFO_1(run_fn, init_fn, term_fn) \
	{.name = #run_fn, .run = run_fn, .init = init_fn, .term = term_fn, .desc = NULL}

#define BENCH_INFO_2(fn_name, run_fn, init_fn, term_fn) \
	{.name = fn_name, .run = run_fn, .init = init_fn, .term = term_fn, .desc = NULL}

#define BENCH_INFO_TM_1(run_fn, init_fn, term_fn) \
	{.name = #run_fn, .run = run_fn, .init = init_fn, .term = term_fn, .cond = NULL,\
	 .max_rounds = 0}

#define BENCH_INFO_TM_2(fn_name, run_fn, init_fn, term_fn) \
	{.name = fn_name, .run = run_fn, .init = init_fn, .term = term_fn, .cond = NULL,\
	 .max_rounds = 0}

typedef enum {
	M_TPUT,
	M_LATENCY
} meas_mode_t;

typedef struct {
	uint32_t burst_size;
	uint32_t num_queues;
	uint32_t bench_idx;
	uint32_t rounds;
	meas_mode_t mode;
	odp_bool_t is_time;
} appl_args_t;

typedef struct {
	appl_args_t appl;
	char cpumask_str[ODP_CPUMASK_STR_SIZE];

	struct {
		uint32_t num_buf;
		uint32_t buf_size;
		odp_pool_t pool;
		odp_queue_t p_q;
		odp_queue_t s_q;
	} resources;

	struct {
		odp_event_t evs[TEST_MAX_DATA_ARR];
		void *ptrs[TEST_MAX_DATA_ARR];
	} data;

	struct {
		union {
			bench_suite_t b;
			bench_tm_suite_t t;
		} s;

		odp_atomic_u32_t *exit;
		int *retval;
		void *args;
		int (*suite_fn)(void *args);
		int (*export_fn)(void *data);

		union {
			double b[TEST_MAX_BENCH];
			bench_tm_result_t t[TEST_MAX_BENCH];
		} r;
	} suite;

	uint8_t context[ODP_CACHE_LINE_SIZE];
} args_t;

static args_t *gbl_args;

static void init_src_events(void)
{
	uint32_t i;
	const uint32_t num = gbl_args->resources.num_buf;
	odp_buffer_t buf;

	for (i = 0U; i < num; i++) {
		buf = odp_buffer_alloc(gbl_args->resources.pool);

		if (buf == ODP_BUFFER_INVALID)
			/* There should be enough buffers to allocate so abort in case of an
			 * error */
			ODPH_ABORT("Failed to allocate\n");

		gbl_args->data.evs[i] = odp_buffer_to_event(buf);
	}

	for (uint32_t j = i; j < ODPH_ARRAY_SIZE(gbl_args->data.evs); j++)
		gbl_args->data.evs[j] = ODP_EVENT_INVALID;
}

static void term_partial_events(uint32_t start_idx)
{
	odp_event_t ev;

	for (uint32_t i = start_idx; i < ODPH_ARRAY_SIZE(gbl_args->data.evs); i++) {
		ev = gbl_args->data.evs[i];

		if (ev != ODP_EVENT_INVALID)
			odp_event_free(ev);
	}
}

static void term_src_events(void)
{
	odp_event_t ev;
	uint32_t i = 0U;

	while (true) {
		ev = odp_queue_deq(gbl_args->resources.p_q);

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
		i++;
	}

	term_partial_events(i);
}

static void init_events(void)
{
	for (uint32_t i = 0U; i < ODPH_ARRAY_SIZE(gbl_args->data.evs); i++)
		gbl_args->data.evs[i] = ODP_EVENT_INVALID;
}

static void fill_plain_queues(void)
{
	const uint32_t num = gbl_args->resources.num_buf;
	odp_buffer_t buf;
	odp_queue_t dst = gbl_args->resources.p_q;

	for (uint32_t i = 0U; i < num; i++) {
		buf = odp_buffer_alloc(gbl_args->resources.pool);

		if (buf == ODP_BUFFER_INVALID)
			/* There should be enough buffers to allocate so abort in case of an
			 * error */
			ODPH_ABORT("Failed to allocate\n");

		if (odp_queue_enq(dst, odp_buffer_to_event(buf)) < 0)
			/* There should be enough room to enqueue test buffers to destination
			 * queues so abort in case of an error */
			ODPH_ABORT("Failed to enqueue\n");
	}

	init_events();
}

static void term_events(void)
{
	odp_event_t ev;

	for (uint32_t i = 0U; i < ODPH_ARRAY_SIZE(gbl_args->data.evs); i++) {
		ev = gbl_args->data.evs[i];

		if (ev != ODP_EVENT_INVALID)
			odp_event_free(ev);
	}
}

static void term_dst_events(void)
{
	odp_event_t ev;

	while (true) {
		ev = odp_queue_deq(gbl_args->resources.p_q);

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}

	term_events();
}

static void fill_scheduled_queues(void)
{
	const uint32_t num = gbl_args->resources.num_buf;
	odp_buffer_t buf;
	odp_queue_t dst = gbl_args->resources.s_q;

	for (uint32_t i = 0U; i < num; i++) {
		buf = odp_buffer_alloc(gbl_args->resources.pool);

		if (buf == ODP_BUFFER_INVALID)
			/* There should be enough buffers to allocate so abort in case of an
			 * error */
			ODPH_ABORT("Failed to allocate\n");

		if (odp_queue_enq(dst, odp_buffer_to_event(buf)) < 0)
			/* There should be enough room to enqueue test buffers to destination
			 * queues so abort in case of an error */
			ODPH_ABORT("Failed to enqueue\n");
	}

	init_events();
}

static void term_scheduled_src_events(void)
{
	odp_event_t ev;
	uint32_t i = 0U;

	while (true) {
		ev = odp_schedule(NULL, odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS));

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
		i++;
	}

	term_partial_events(i);
}

static void term_scheduled_dst_events(void)
{
	odp_event_t ev;

	while (true) {
		ev = odp_schedule(NULL, odp_schedule_wait_time(ODP_TIME_MSEC_IN_NS));

		if (ev == ODP_EVENT_INVALID)
			break;

		odp_event_free(ev);
	}

	term_events();
}

static int context_set_plain(void)
{
	odp_queue_t dst = gbl_args->resources.p_q;
	uint8_t *context = gbl_args->context;
	const uint32_t len = ODPH_ARRAY_SIZE(gbl_args->context);
	int ret = 0;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++)
		ret += odp_queue_context_set(dst, context, len);

	return !ret;
}

static int context_set_plain_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_queue_t dst = gbl_args->resources.p_q;
	uint8_t *context = gbl_args->context;
	const uint32_t len = ODPH_ARRAY_SIZE(gbl_args->context);
	int ret = 0;
	const uint8_t id1 = bench_tm_func_register(res, "odp_queue_context_set()");

	for (int i = 0U; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ret += odp_queue_context_set(dst, context, len);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return !ret;
}

static int context_plain(void)
{
	odp_queue_t q = gbl_args->resources.p_q;
	void **dst = gbl_args->data.ptrs;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++)
		dst[i] = odp_queue_context(q);

	return 1;
}

static int context_plain_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_queue_t q = gbl_args->resources.p_q;
	void **dst = gbl_args->data.ptrs;
	const uint8_t id1 = bench_tm_func_register(res, "odp_queue_context()");

	for (int i = 0U; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		dst[i] = odp_queue_context(q);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return 1;
}

static int context_set_scheduled(void)
{
	odp_queue_t dst = gbl_args->resources.s_q;
	uint8_t *context = gbl_args->context;
	const uint32_t len = ODPH_ARRAY_SIZE(gbl_args->context);
	int ret = 0;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++)
		ret += odp_queue_context_set(dst, context, len);

	return !ret;
}

static int context_set_scheduled_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_queue_t dst = gbl_args->resources.s_q;
	uint8_t *context = gbl_args->context;
	const uint32_t len = ODPH_ARRAY_SIZE(gbl_args->context);
	int ret = 0;
	const uint8_t id1 = bench_tm_func_register(res, "odp_queue_context_set()");

	for (int i = 0U; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ret += odp_queue_context_set(dst, context, len);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return !ret;
}

static int context_scheduled(void)
{
	odp_queue_t q = gbl_args->resources.s_q;
	void **dst = gbl_args->data.ptrs;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++)
		dst[i] = odp_queue_context(q);

	return 1;
}

static int context_scheduled_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_queue_t q = gbl_args->resources.s_q;
	void **dst = gbl_args->data.ptrs;
	const uint8_t id1 = bench_tm_func_register(res, "odp_queue_context()");

	for (int i = 0U; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		dst[i] = odp_queue_context(q);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return 1;
}

static int enqueue_plain(void)
{
	odp_queue_t dst = gbl_args->resources.p_q;
	odp_event_t *src = gbl_args->data.evs;
	int ret = 0;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++)
		ret += odp_queue_enq(dst, src[i]);

	return !ret;
}

static int enqueue_plain_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_queue_t dst = gbl_args->resources.p_q;
	odp_event_t *src = gbl_args->data.evs;
	int ret = 0;
	const uint8_t id1 = bench_tm_func_register(res, "odp_queue_enq()");

	for (int i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ret += odp_queue_enq(dst, src[i]);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return !ret;
}

static int enqueue_multi_plain(void)
{
	odp_queue_t dst = gbl_args->resources.p_q;
	odp_event_t *src = gbl_args->data.evs;
	int num_tot = 0, ret;
	const int num_burst = gbl_args->appl.burst_size;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++) {
		ret = odp_queue_enq_multi(dst, &src[num_tot], num_burst);

		ODPH_ASSERT(ret >= 0);

		num_tot += ret;
	}

	return 1;
}

static int enqueue_multi_plain_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_queue_t dst = gbl_args->resources.p_q;
	odp_event_t *src = gbl_args->data.evs;
	int num_tot = 0, ret;
	const int num_burst = gbl_args->appl.burst_size;
	const uint8_t id1 = bench_tm_func_register(res, "odp_queue_enq_multi()");

	for (int i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ret = odp_queue_enq_multi(dst, &src[num_tot], num_burst);
		bench_tm_now(res, &s2);

		ODPH_ASSERT(ret >= 0);

		bench_tm_func_record(&s2, &s1, res, id1);
		num_tot += ret;
	}

	return 1;
}

static int dequeue_plain(void)
{
	odp_queue_t src = gbl_args->resources.p_q;
	odp_event_t *dst = gbl_args->data.evs;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++)
		dst[i] = odp_queue_deq(src);

	return 1;
}

static int dequeue_plain_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_queue_t src = gbl_args->resources.p_q;
	odp_event_t *dst = gbl_args->data.evs;
	const uint8_t id1 = bench_tm_func_register(res, "odp_queue_deq()");

	for (int i = 0U; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		dst[i] = odp_queue_deq(src);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return 1;
}

static int dequeue_multi_plain(void)
{
	odp_queue_t src = gbl_args->resources.p_q;
	odp_event_t *dst = gbl_args->data.evs;
	int num_tot = 0, ret;
	const int num_burst = gbl_args->appl.burst_size;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++) {
		ret = odp_queue_deq_multi(src, &dst[num_tot], num_burst);

		ODPH_ASSERT(ret >= 0);

		num_tot += ret;
	}

	return 1;
}

static int dequeue_multi_plain_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_queue_t src = gbl_args->resources.p_q;
	odp_event_t *dst = gbl_args->data.evs;
	int num_tot = 0, ret;
	const int num_burst = gbl_args->appl.burst_size;
	const uint8_t id1 = bench_tm_func_register(res, "odp_queue_deq_multi()");

	for (int i = 0U; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ret = odp_queue_deq_multi(src, &dst[num_tot], num_burst);
		bench_tm_now(res, &s2);

		ODPH_ASSERT(ret >= 0);

		bench_tm_func_record(&s2, &s1, res, id1);
		num_tot += ret;
	}

	return 1;
}

static int enqueue_scheduled(void)
{
	odp_queue_t dst = gbl_args->resources.s_q;
	odp_event_t *src = gbl_args->data.evs;
	int ret = 0;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++)
		ret += odp_queue_enq(dst, src[i]);

	return !ret;
}

static int enqueue_scheduled_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_queue_t dst = gbl_args->resources.s_q;
	odp_event_t *src = gbl_args->data.evs;
	int ret = 0;
	const uint8_t id1 = bench_tm_func_register(res, "odp_queue_enq()");

	for (int i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ret += odp_queue_enq(dst, src[i]);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return !ret;
}

static int enqueue_multi_scheduled(void)
{
	odp_queue_t dst = gbl_args->resources.s_q;
	odp_event_t *src = gbl_args->data.evs;
	int num_tot = 0, ret;
	const int num_burst = gbl_args->appl.burst_size;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++) {
		ret = odp_queue_enq_multi(dst, &src[num_tot], num_burst);

		ODPH_ASSERT(ret >= 0);

		num_tot += ret;
	}

	return 1;
}

static int enqueue_multi_scheduled_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_queue_t dst = gbl_args->resources.s_q;
	odp_event_t *src = gbl_args->data.evs;
	int num_tot = 0, ret;
	const int num_burst = gbl_args->appl.burst_size;
	const uint8_t id1 = bench_tm_func_register(res, "odp_queue_enq_multi()");

	for (int i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		ret = odp_queue_enq_multi(dst, &src[num_tot], num_burst);
		bench_tm_now(res, &s2);

		ODPH_ASSERT(ret >= 0);

		bench_tm_func_record(&s2, &s1, res, id1);
		num_tot += ret;
	}

	return 1;
}

static int schedule(void)
{
	odp_event_t *dst = gbl_args->data.evs;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++)
		dst[i] = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

	return 1;
}

static int schedule_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_event_t *dst = gbl_args->data.evs;
	const uint8_t id1 = bench_tm_func_register(res, "odp_schedule()");

	for (int i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		dst[i] = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return 1;
}

static int schedule_multi_nw(void)
{
	odp_event_t *dst = gbl_args->data.evs;
	const int num_burst = gbl_args->appl.burst_size;
	int num_recv = 0;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++)
		num_recv += odp_schedule_multi_no_wait(NULL, &dst[num_recv], num_burst);

	return 1;
}

static int schedule_multi_nw_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_event_t *dst = gbl_args->data.evs;
	const int num_burst = gbl_args->appl.burst_size;
	int num_recv = 0;
	const uint8_t id1 = bench_tm_func_register(res, "odp_schedule_multi_no_wait()");

	for (int i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		num_recv += odp_schedule_multi_no_wait(NULL, &dst[num_recv], num_burst);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return 1;
}

static int schedule_multi(void)
{
	odp_event_t *dst = gbl_args->data.evs;
	const int num_burst = gbl_args->appl.burst_size;
	int num_recv = 0;

	for (uint32_t i = 0U; i < TEST_REPEAT_COUNT; i++)
		num_recv += odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT, &dst[num_recv], num_burst);

	return 1;
}

static int schedule_multi_tm(bench_tm_result_t *res, int repeat_count)
{
	bench_tm_stamp_t s1, s2;
	odp_event_t *dst = gbl_args->data.evs;
	const int num_burst = gbl_args->appl.burst_size;
	int num_recv = 0;
	const uint8_t id1 = bench_tm_func_register(res, "odp_schedule_multi()");

	for (int i = 0; i < repeat_count; i++) {
		bench_tm_now(res, &s1);
		num_recv += odp_schedule_multi(NULL, ODP_SCHED_NO_WAIT, &dst[num_recv], num_burst);
		bench_tm_now(res, &s2);
		bench_tm_func_record(&s2, &s1, res, id1);
	}

	return 1;
}

bench_info_t test_suite[] = {
	BENCH_INFO_1(context_set_plain, NULL, NULL),
	BENCH_INFO_1(context_plain, NULL, NULL),
	BENCH_INFO_1(context_set_scheduled, NULL, NULL),
	BENCH_INFO_1(context_scheduled, NULL, NULL),
	BENCH_INFO_1(enqueue_plain, init_src_events, term_src_events),
	BENCH_INFO_1(enqueue_multi_plain, init_src_events, term_src_events),
	BENCH_INFO_1(dequeue_plain, fill_plain_queues, term_dst_events),
	BENCH_INFO_1(dequeue_multi_plain, fill_plain_queues, term_dst_events),
	BENCH_INFO_1(enqueue_scheduled, init_src_events, term_scheduled_src_events),
	BENCH_INFO_1(enqueue_multi_scheduled, init_src_events, term_scheduled_src_events),
	BENCH_INFO_2("schedule_empty", schedule, init_events, term_events),
	BENCH_INFO_2("schedule_multi_nw_empty", schedule_multi_nw, init_events, term_events),
	BENCH_INFO_2("schedule_multi_empty", schedule_multi, init_events, term_events),
	BENCH_INFO_2("schedule_full", schedule, fill_scheduled_queues, term_scheduled_dst_events),
	BENCH_INFO_2("schedule_multi_nw_full", schedule_multi_nw, fill_scheduled_queues,
		     term_scheduled_dst_events),
	BENCH_INFO_2("schedule_multi_full", schedule_multi, fill_scheduled_queues,
		     term_scheduled_dst_events),
};

ODP_STATIC_ASSERT(ODPH_ARRAY_SIZE(test_suite) < TEST_MAX_BENCH,
		  "Result array is too small to hold all the results");

bench_tm_info_t test_suite_tm[] = {
	BENCH_INFO_TM_1(context_set_plain_tm, NULL, NULL),
	BENCH_INFO_TM_1(context_plain_tm, NULL, NULL),
	BENCH_INFO_TM_1(context_set_scheduled_tm, NULL, NULL),
	BENCH_INFO_TM_1(context_scheduled_tm, NULL, NULL),
	BENCH_INFO_TM_1(enqueue_plain_tm, init_src_events, term_src_events),
	BENCH_INFO_TM_1(enqueue_multi_plain_tm, init_src_events, term_src_events),
	BENCH_INFO_TM_1(dequeue_plain_tm, fill_plain_queues, term_dst_events),
	BENCH_INFO_TM_1(dequeue_multi_plain_tm, fill_plain_queues, term_dst_events),
	BENCH_INFO_TM_1(enqueue_scheduled_tm, init_src_events, term_scheduled_src_events),
	BENCH_INFO_TM_1(enqueue_multi_scheduled_tm, init_src_events, term_scheduled_src_events),
	BENCH_INFO_TM_2("schedule_empty_tm", schedule_tm, init_events, term_events),
	BENCH_INFO_TM_2("schedule_multi_nw_empty_tm", schedule_multi_nw_tm, init_events,
			term_events),
	BENCH_INFO_TM_2("schedule_multi_empty_tm", schedule_multi_tm, init_events, term_events),
	BENCH_INFO_TM_2("schedule_full_tm", schedule_tm, fill_scheduled_queues,
			term_scheduled_dst_events),
	BENCH_INFO_TM_2("schedule_multi_nw_full_tm", schedule_multi_nw_tm, fill_scheduled_queues,
			term_scheduled_dst_events),
	BENCH_INFO_TM_2("schedule_multi_full_tm", schedule_multi_tm, fill_scheduled_queues,
			term_scheduled_dst_events),
};

ODP_STATIC_ASSERT(ODPH_ARRAY_SIZE(test_suite_tm) < TEST_MAX_BENCH,
		  "Result array is too small to hold all the results");

static void set_defaults(void)
{
	gbl_args->appl.burst_size = TEST_DEF_BURST;
	gbl_args->appl.num_queues = 1U; /* TODO: make CLI configurable */
	gbl_args->appl.bench_idx = 0U; /* Run all benchmarks */
	gbl_args->appl.rounds = TEST_ROUNDS;
	gbl_args->appl.mode = M_TPUT;
	gbl_args->appl.is_time = false;
	gbl_args->resources.num_buf = TEST_DEF_BURST * TEST_REPEAT_COUNT;
	gbl_args->resources.buf_size = ODP_CACHE_LINE_SIZE;
	gbl_args->resources.pool = ODP_POOL_INVALID;
	gbl_args->resources.p_q = ODP_QUEUE_INVALID;
	gbl_args->resources.s_q = ODP_QUEUE_INVALID;
}

static void print_usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane queue API microbenchmarks.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s\n"
	       "\n"
	       "Optional OPTIONS:\n"
	       "  -b, --burst <num>      Test burst size for '*_multi()' functions. Maximum %u.\n"
	       "                         %u by default. Implementation capabilities may further\n"
	       "                         limit the value.\n"
	       "  -i, --index <idx>      Benchmark index to run indefinitely. Index should be\n"
	       "                         one-based. Use 0 to run all benchmarks. 0 by default.\n"
	       "                         Registered benchmarks:\n",
	       NO_PATH(progname), NO_PATH(progname), TEST_MAX_BURST, TEST_DEF_BURST);

	/* Dump the to-be-tested functions for user-friendliness */
	for (uint32_t i = 0U; i < ODPH_ARRAY_SIZE(test_suite); ++i)
		printf("                             %u: %s\n", i + 1U, test_suite[i].name);

	printf("  -r, --rounds <num>     Run each test case 'num' times. %u by default.\n"
	       "  -t, --time <opt>       Time measurement.\n"
	       "                             0: measure CPU cycles (default)\n"
	       "                             1: measure time\n"
	       "  -m, --mode <mode>      Measurement mode.\n"
	       "                             0: measure throughput, track average execution\n"
	       "                                time (default)\n"
	       "                             1: measure latency, track function minimum and\n"
	       "                                maximum in addition to average execution time.\n"
	       "  -h, --help             Display help and exit.\n\n"
	       "\n", TEST_ROUNDS);
}

static void check_args(void)
{
	odp_pool_capability_t p_capa;
	odp_queue_capability_t q_capa;
	odp_schedule_capability_t s_capa;

	gbl_args->resources.num_buf = TEST_REPEAT_COUNT * gbl_args->appl.burst_size;

	if (gbl_args->appl.mode != M_TPUT && gbl_args->appl.mode != M_LATENCY) {
		printf("Invalid measurement mode: %d\n", gbl_args->appl.mode);
		exit(EXIT_FAILURE);
	}

	if (odp_pool_capability(&p_capa) < 0) {
		ODPH_ERR("Failed to query pool capabilities\n");
		exit(EXIT_FAILURE);
	}

	if (gbl_args->resources.num_buf > p_capa.buf.max_num) {
		ODPH_ERR("Invalid amount of buffers: %u (max: %u)\n",
			 gbl_args->resources.num_buf, p_capa.buf.max_num);
		exit(EXIT_FAILURE);
	}

	if (gbl_args->resources.buf_size > p_capa.buf.max_size)
		gbl_args->resources.buf_size = p_capa.buf.max_size;

	if (odp_queue_capability(&q_capa) < 0) {
		ODPH_ERR("Failed to query queue capabilities\n");
		exit(EXIT_FAILURE);
	}

	if (gbl_args->appl.num_queues * 2U > q_capa.max_queues) {
		ODPH_ERR("Invalid number of queues: %u (max: %u, any type)\n",
			 gbl_args->appl.num_queues, q_capa.max_queues);
		exit(EXIT_FAILURE);
	}

	if (gbl_args->appl.num_queues > q_capa.plain.max_num) {
		ODPH_ERR("Invalid number of queues: %u (max: %u, plain)\n",
			 gbl_args->appl.num_queues, q_capa.max_queues);
		exit(EXIT_FAILURE);
	}

	if (gbl_args->resources.num_buf > q_capa.plain.max_size) {
		ODPH_ERR("Invalid queue size: %u (max: %u, plain)\n", gbl_args->resources.num_buf,
			 q_capa.plain.max_size);
		exit(EXIT_FAILURE);
	}

	if (odp_schedule_capability(&s_capa) < 0) {
		ODPH_ERR("Failed to query schedule capabilities\n");
		exit(EXIT_FAILURE);
	}

	if (gbl_args->appl.num_queues > s_capa.max_queues) {
		ODPH_ERR("Invalid number of queues: %u (max: %u, scheduled)\n",
			 gbl_args->appl.num_queues, s_capa.max_queues);
		exit(EXIT_FAILURE);
	}

	if (gbl_args->resources.num_buf > s_capa.max_queue_size) {
		ODPH_ERR("Invalid queue size: %u (max: %u, scheduled)\n",
			 gbl_args->resources.num_buf, s_capa.max_queue_size);
		exit(EXIT_FAILURE);
	}
}

static void parse_args(int argc, char *argv[])
{
	int opt;
	static const struct option longopts[] = {
		{"burst", required_argument, NULL, 'b'},
		{"index", required_argument, NULL, 'i'},
		{"rounds", required_argument, NULL, 'r'},
		{"time", required_argument, NULL, 't'},
		{"mode", required_argument, NULL, 'm'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
	static const char *shortopts =  "b:i:r:t:m:h";
	appl_args_t *appl_args = &gbl_args->appl;

	while (true) {
		opt = getopt_long(argc, argv, shortopts, longopts, NULL);

		if (opt == -1)
			break;

		switch (opt) {
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
			appl_args->is_time = atoi(optarg);
			break;
		case 'm':
			appl_args->mode = atoi(optarg);
			break;
		case 'h':
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	check_args();
}

static void sig_handler(int signo ODP_UNUSED)
{
	odp_atomic_store_u32(gbl_args->suite.exit, 1);
}

static int setup_sig_handler(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = sig_handler;

	/* No additional signals blocked. By default, the signal which triggered
	 * the handler is blocked. */
	if (sigemptyset(&action.sa_mask))
		return -1;

	if (sigaction(SIGINT, &action, NULL))
		return -1;

	return 0;
}

static int bench_buffer_tm_export(void *data)
{
	args_t *gbl_args = data;
	bench_tm_result_t *res;
	uint64_t num;
	int ret = 0;
	const char *unit = gbl_args->appl.is_time ? "nsec" : "cpu cycles";

	if (test_common_write("function name,min %s per function call,"
			      "average %s per function call,"
			      "max %s per function call\n", unit, unit, unit)) {
		ret = -1;
		goto exit;
	}

	for (uint32_t i = 0; i < gbl_args->suite.s.t.num_bench; i++) {
		res = &gbl_args->suite.s.t.result[i];

		for (int j = 0; j < res->num; j++) {
			num = res->func[j].num ? res->func[j].num : 1;
			if (test_common_write("%s,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
					      res->func[j].name,
					      bench_tm_to_u64(res, &res->func[j].min),
					      bench_tm_to_u64(res, &res->func[j].tot) / num,
					      bench_tm_to_u64(res, &res->func[j].max))) {
				ret = -1;
				goto exit;
			}
		}
	}

exit:
	test_common_write_term();

	return ret;
}

static int bench_buffer_export(void *data)
{
	args_t *gbl_args = data;
	int ret = 0;

	if (test_common_write("%s", gbl_args->appl.is_time ?
			      "function name,average nsec per function call\n" :
			      "function name,average cpu cycles per function call\n")) {
		ret = -1;
		goto exit;
	}

	for (int i = 0; i < gbl_args->suite.s.b.num_bench; i++) {
		if (test_common_write("odp_%s,%f\n", gbl_args->suite.s.b.bench[i].desc != NULL ?
					gbl_args->suite.s.b.bench[i].desc :
					gbl_args->suite.s.b.bench[i].name,
				      gbl_args->suite.s.b.result[i])) {
			ret = -1;
			goto exit;
		}
	}

exit:
	test_common_write_term();

	return ret;
}

static void init_suite(args_t *gbl_args)
{
	if (gbl_args->appl.mode == M_LATENCY) {
		bench_tm_suite_init(&gbl_args->suite.s.t);
		gbl_args->suite.s.t.bench = test_suite_tm;
		gbl_args->suite.s.t.num_bench = ODPH_ARRAY_SIZE(test_suite_tm);
		gbl_args->suite.s.t.rounds = TEST_REPEAT_COUNT;
		gbl_args->suite.s.t.bench_idx = gbl_args->appl.bench_idx;
		gbl_args->suite.s.t.measure_time = gbl_args->appl.is_time;
		gbl_args->suite.exit = &gbl_args->suite.s.t.exit_worker;
		gbl_args->suite.retval = &gbl_args->suite.s.t.retval;
		gbl_args->suite.args = &gbl_args->suite.s.t;
		gbl_args->suite.suite_fn = bench_tm_run;
		gbl_args->suite.export_fn = bench_buffer_tm_export;
		gbl_args->suite.s.t.result = gbl_args->suite.r.t;
	} else {
		bench_suite_init(&gbl_args->suite.s.b);
		gbl_args->suite.s.b.bench = test_suite;
		gbl_args->suite.s.b.num_bench = ODPH_ARRAY_SIZE(test_suite);
		gbl_args->suite.s.b.indef_idx = gbl_args->appl.bench_idx;
		gbl_args->suite.s.b.rounds = gbl_args->appl.rounds;
		gbl_args->suite.s.b.repeat_count = TEST_REPEAT_COUNT;
		gbl_args->suite.s.b.measure_time = gbl_args->appl.is_time;
		gbl_args->suite.exit = &gbl_args->suite.s.b.exit_worker;
		gbl_args->suite.retval = &gbl_args->suite.s.b.retval;
		gbl_args->suite.args = &gbl_args->suite.s.b;
		gbl_args->suite.suite_fn = bench_run;
		gbl_args->suite.export_fn = bench_buffer_export;
		gbl_args->suite.s.b.result = gbl_args->suite.r.b;
	}
}

static int create_resources(void)
{
	odp_pool_param_t p_param;
	odp_queue_param_t q_param;

	if (odp_schedule_config(NULL)) {
		ODPH_ERR("Failed to configure scheduler\n");
		return -1;
	}

	odp_pool_param_init(&p_param);
	p_param.type = ODP_POOL_BUFFER;
	p_param.buf.num = gbl_args->resources.num_buf;
	p_param.buf.size = gbl_args->resources.buf_size;
	gbl_args->resources.pool = odp_pool_create("bq_pool", &p_param);

	if (gbl_args->resources.pool == ODP_POOL_INVALID) {
		ODPH_ERR("Failed to create test pool\n");
		return -1;
	}

	odp_queue_param_init(&q_param);
	q_param.enq_mode = ODP_QUEUE_OP_MT_UNSAFE;
	q_param.deq_mode = ODP_QUEUE_OP_MT_UNSAFE;
	q_param.context = gbl_args->context;
	q_param.size = gbl_args->resources.num_buf;
	gbl_args->resources.p_q = odp_queue_create("bq_plain", &q_param);

	if (gbl_args->resources.p_q == ODP_QUEUE_INVALID) {
		ODPH_ERR("Failed to create plain test queue\n");
		return -1;
	}

	q_param.type = ODP_QUEUE_TYPE_SCHED;
	gbl_args->resources.s_q = odp_queue_create("bq_sched", &q_param);

	if (gbl_args->resources.s_q == ODP_QUEUE_INVALID) {
		ODPH_ERR("Failed to create scheduled test queue\n");
		return -1;
	}

	return 0;
}

static void print_info(void)
{
	odp_sys_info_print();
	printf("\n"
	       "odp_queue_buffer options\n"
	       "------------------------\n");

	printf("Burst size:       %d\n", gbl_args->appl.burst_size);
	printf("CPU mask:         %s\n", gbl_args->cpumask_str);
	printf("Measurement unit: %s\n", gbl_args->appl.is_time ? "nsec" : "CPU cycles");
	printf("Test rounds:      %u\n", gbl_args->appl.rounds);
	printf("Measurement mode: %s\n", gbl_args->appl.mode == M_TPUT ? "throughput" : "latency");
	printf("\n");
}

static void run_worker(odp_instance_t instance, odp_cpumask_t default_mask)
{
	const int cpu = odp_cpumask_first(&default_mask);
	odp_cpumask_t cpumask;
	odph_thread_t worker_thread;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param;

	memset(&worker_thread, 0, sizeof(odph_thread_t));
	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, cpu);
	odph_thread_common_param_init(&thr_common);
	thr_common.instance = instance;
	thr_common.cpumask = &cpumask;
	thr_common.share_param = 1;
	odph_thread_param_init(&thr_param);
	thr_param.start = gbl_args->suite.suite_fn;
	thr_param.arg = gbl_args->suite.args;
	thr_param.thr_type = ODP_THREAD_WORKER;

	if (odph_thread_create(&worker_thread, &thr_common, &thr_param, 1) != 1) {
		ODPH_ERR("Creating worker thread failed\n");
		exit(EXIT_FAILURE);
	}

	(void)odph_thread_join(&worker_thread, 1);
}

static void teardown_resources(void)
{
	(void)odp_queue_destroy(gbl_args->resources.s_q);
	(void)odp_queue_destroy(gbl_args->resources.p_q);
	(void)odp_pool_destroy(gbl_args->resources.pool);
}

int main(int argc, char *argv[])
{
	odph_helper_options_t helper_options;
	test_common_options_t common_options;
	odp_shm_t shm;
	odp_cpumask_t default_mask;
	odp_instance_t instance;
	odp_init_t init_param;
	uint8_t ret;

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

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (odp_init_global(&instance, &init_param, NULL)) {
		ODPH_ERR("Global init failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed\n");
		exit(EXIT_FAILURE);
	}

	shm = odp_shm_reserve("shm_args", sizeof(args_t), ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared memory reserve failed\n");
		exit(EXIT_FAILURE);
	}

	gbl_args = odp_shm_addr(shm);

	if (gbl_args == NULL) {
		ODPH_ERR("Shared memory allocation failed\n");
		exit(EXIT_FAILURE);
	}

	memset(gbl_args, 0, sizeof(args_t));
	set_defaults();
	parse_args(argc, argv);
	init_suite(gbl_args);

	if (setup_sig_handler()) {
		ODPH_ERR("Signal handler setup failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_cpumask_default_worker(&default_mask, 1) != 1) {
		ODPH_ERR("Unable to allocate worker thread\n");
		exit(EXIT_FAILURE);
	}

	(void)odp_cpumask_to_str(&default_mask, gbl_args->cpumask_str,
				 sizeof(gbl_args->cpumask_str));

	if (create_resources())
		exit(EXIT_FAILURE);

	print_info();
	run_worker(instance, default_mask);
	ret = *gbl_args->suite.retval;

	if (ret == 0 && common_options.is_export) {
		if (gbl_args->suite.export_fn(gbl_args)) {
			ODPH_ERR("Export failed\n");
			ret = -1;
		}
	}

	teardown_resources();

	if (odp_shm_free(shm)) {
		ODPH_ERR("Shared memory free failed\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Local term local\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Global term global\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}

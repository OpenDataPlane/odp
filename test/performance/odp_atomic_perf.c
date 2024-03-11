/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

/**
 * @example odp_atomic_perf.c
 *
 * Performance test application for atomic operation APIs
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

/* Default number of test rounds */
#define NUM_ROUNDS 100000u

/* Initial value for atomic variables. Supports up to 2 billion
 * rounds of 32-bit min and max tests. */
#define INIT_VAL 0x80000000

/* Max number of workers if num_cpu=0 */
#define DEFAULT_MAX_WORKERS 10

#define TEST_INFO(name, test, validate, op_type) \
	{name, test, validate, op_type}

/* Test function template */
typedef void (*test_fn_t)(void *val, void *out, uint32_t num_round);
/* Test result validation function template */
typedef int (*validate_fn_t)(void *val, void *out, uint32_t num_round,
			     uint32_t num_worker, int private);

typedef enum {
	OP_32BIT,
	OP_64BIT,
	OP_128BIT
} op_bit_t;

/* Command line options */
typedef struct test_options_t {
	uint32_t num_cpu;
	uint32_t num_round;
	int private;

} test_options_t;

/* Cache aligned atomics for private mode operation */
typedef struct ODP_ALIGNED_CACHE test_atomic_t {
	union {
		odp_atomic_u32_t u32;
		odp_atomic_u64_t u64;
		odp_atomic_u128_t u128;
	};
} test_atomic_t;

typedef struct test_global_t test_global_t;

/* Worker thread context */
typedef struct test_thread_ctx_t {
	test_global_t *global;
	test_fn_t func;
	uint64_t nsec;
	uint32_t idx;
	op_bit_t type;

} test_thread_ctx_t;

/* Global data */
struct test_global_t {
	test_options_t test_options;
	odp_barrier_t barrier;
	union {
		odp_atomic_u32_t atomic_u32;
		odp_atomic_u64_t atomic_u64;
		odp_atomic_u128_t atomic_u128;
	};
	odp_cpumask_t cpumask;
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	test_thread_ctx_t thread_ctx[ODP_THREAD_COUNT_MAX];
	test_atomic_t atomic_private[ODP_THREAD_COUNT_MAX];
	union {
		uint32_t u32;
		uint64_t u64;
		odp_u128_t u128;
	} output[ODP_THREAD_COUNT_MAX];
};

typedef struct {
	const char *name;
	test_fn_t test_fn;
	validate_fn_t validate_fn;
	op_bit_t type;
} test_case_t;

static test_global_t *test_global;

static inline void test_atomic_load_u32(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t *result = out;
	uint32_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_load_u32(atomic_val);

	*result = ret;
}

static inline void test_atomic_load_u64(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t *result = out;
	uint64_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_load_u64(atomic_val);

	*result = ret;
}

static inline void test_atomic_load_u128(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u128_t *atomic_val = val;
	odp_u128_t *result = out;
	odp_u128_t ret;

	ret.u64[0] = 0;
	ret.u64[1] = 0;

	for (uint32_t i = 0; i < num_round; i++) {
		odp_u128_t cur_val = odp_atomic_load_u128(atomic_val);

		ret.u64[0] += cur_val.u64[0];
		ret.u64[1] += cur_val.u64[1];
	}

	*result = ret;
}

static inline int validate_atomic_init_val_u32(void *val, void *out, uint32_t num_round,
					       uint32_t num_worker ODP_UNUSED,
					       int private ODP_UNUSED)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t *result = out;

	return (odp_atomic_load_u32(atomic_val) != INIT_VAL) ||
	       (*result != (uint32_t)INIT_VAL * num_round);
}

static inline int validate_atomic_init_val_u64(void *val, void *out, uint32_t num_round,
					       uint32_t worker ODP_UNUSED, int private ODP_UNUSED)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t *result = out;

	return (odp_atomic_load_u64(atomic_val) != INIT_VAL) ||
	       (*result != (uint64_t)INIT_VAL * num_round);
}

static inline int validate_atomic_init_val_u128(void *val, void *out, uint32_t num_round,
						uint32_t worker ODP_UNUSED, int private ODP_UNUSED)
{
	odp_u128_t atomic_val = odp_atomic_load_u128((odp_atomic_u128_t *)val);
	odp_u128_t *result = out;

	if (atomic_val.u64[0] != INIT_VAL || atomic_val.u64[1] != INIT_VAL)
		return -1;

	if (result->u64[0] != (uint64_t)INIT_VAL * num_round ||
	    result->u64[1] != (uint64_t)INIT_VAL * num_round)
		return -1;

	return 0;
}

static inline void test_atomic_store_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t new_val = INIT_VAL + 1;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_store_u32(atomic_val, new_val++);
}

static inline void test_atomic_store_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t new_val = INIT_VAL + 1;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_store_u64(atomic_val, new_val++);
}

static inline void test_atomic_store_u128(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u128_t *atomic_val = val;
	odp_u128_t new_val;

	new_val.u64[0] = INIT_VAL + 1;
	new_val.u64[1] = INIT_VAL + 1;

	for (uint32_t i = 0; i < num_round; i++) {
		odp_atomic_store_u128(atomic_val, new_val);
		new_val.u64[0]++;
		new_val.u64[1]++;
	}
}

static inline int validate_atomic_num_round_u32(void *val, void *out ODP_UNUSED, uint32_t num_round,
						uint32_t worker ODP_UNUSED, int private ODP_UNUSED)
{
	odp_atomic_u32_t *atomic_val = val;

	return odp_atomic_load_u32(atomic_val) != ((uint32_t)INIT_VAL + num_round);
}

static inline int validate_atomic_num_round_u64(void *val, void *out ODP_UNUSED, uint32_t num_round,
						uint32_t worker ODP_UNUSED, int private ODP_UNUSED)
{
	odp_atomic_u64_t *atomic_val = val;

	return odp_atomic_load_u64(atomic_val) != ((uint64_t)INIT_VAL + num_round);
}

static inline int validate_atomic_num_round_u128(void *val, void *out ODP_UNUSED,
						 uint32_t num_round, uint32_t worker ODP_UNUSED,
						 int private ODP_UNUSED)
{
	odp_u128_t atomic_val = odp_atomic_load_u128((odp_atomic_u128_t *)val);

	return (atomic_val.u64[0] != ((uint64_t)INIT_VAL + num_round) ||
		atomic_val.u64[1] != ((uint64_t)INIT_VAL + num_round));
}

static inline void test_atomic_fetch_add_u32(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t *result = out;
	uint32_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_fetch_add_u32(atomic_val, 1);

	*result = ret;
}

static inline void test_atomic_fetch_add_u64(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t *result = out;
	uint64_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_fetch_add_u64(atomic_val, 1);

	*result = ret;
}

static inline int validate_atomic_add_round_u32(void *val, void *out ODP_UNUSED, uint32_t num_round,
						uint32_t num_worker, int private)
{
	odp_atomic_u32_t *atomic_val = val;

	if (private)
		return odp_atomic_load_u32(atomic_val) != ((uint32_t)INIT_VAL + num_round);

	return odp_atomic_load_u32(atomic_val) != (INIT_VAL + (num_worker * num_round));
}

static inline int validate_atomic_add_round_u64(void *val, void *out ODP_UNUSED, uint32_t num_round,
						uint32_t num_worker, int private)
{
	odp_atomic_u64_t *atomic_val = val;

	if (private)
		return odp_atomic_load_u64(atomic_val) != ((uint64_t)INIT_VAL + num_round);

	return odp_atomic_load_u64(atomic_val) != (INIT_VAL + ((uint64_t)num_worker * num_round));
}

static inline void test_atomic_add_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_add_u32(atomic_val, 1);
}

static inline void test_atomic_add_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_add_u64(atomic_val, 1);
}

static inline void test_atomic_fetch_sub_u32(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t *result = out;
	uint32_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_fetch_sub_u32(atomic_val, 1);

	*result = ret;
}

static inline void test_atomic_fetch_sub_u64(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t *result = out;
	uint64_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_fetch_sub_u64(atomic_val, 1);

	*result = ret;
}

static inline int validate_atomic_sub_round_u32(void *val, void *out ODP_UNUSED, uint32_t num_round,
						uint32_t num_worker, int private)
{
	odp_atomic_u32_t *atomic_val = val;

	if (private)
		return odp_atomic_load_u32(atomic_val) != ((uint32_t)INIT_VAL - num_round);

	return odp_atomic_load_u32(atomic_val) != ((uint32_t)INIT_VAL - (num_worker * num_round));
}

static inline int validate_atomic_sub_round_u64(void *val, void *out ODP_UNUSED, uint32_t num_round,
						uint32_t num_worker, int private)
{
	odp_atomic_u64_t *atomic_val = val;

	if (private)
		return odp_atomic_load_u64(atomic_val) != ((uint64_t)INIT_VAL - num_round);

	return odp_atomic_load_u64(atomic_val) != ((uint64_t)INIT_VAL -
						   ((uint64_t)num_worker * num_round));
}

static inline void test_atomic_sub_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_sub_u32(atomic_val, 1);
}

static inline void test_atomic_sub_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_sub_u64(atomic_val, 1);
}

static inline void test_atomic_fetch_inc_u32(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t *result = out;
	uint32_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret +=  odp_atomic_fetch_inc_u32(atomic_val);

	*result = ret;
}

static inline void test_atomic_fetch_inc_u64(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t *result = out;
	uint64_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret +=  odp_atomic_fetch_inc_u64(atomic_val);

	*result = ret;
}

static inline void test_atomic_inc_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_inc_u32(atomic_val);
}

static inline void test_atomic_inc_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_inc_u64(atomic_val);
}

static inline void test_atomic_fetch_dec_u32(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t *result = out;
	uint32_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_fetch_dec_u32(atomic_val);

	*result = ret;
}

static inline void test_atomic_fetch_dec_u64(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t *result = out;
	uint64_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_fetch_dec_u64(atomic_val);

	*result = ret;
}

static inline void test_atomic_dec_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_dec_u32(atomic_val);
}

static inline void test_atomic_dec_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_dec_u64(atomic_val);
}

static inline void test_atomic_max_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t new_max = INIT_VAL + 1;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_max_u32(atomic_val, new_max++);
}

static inline void test_atomic_max_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t new_max = INIT_VAL + 1;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_max_u64(atomic_val, new_max++);
}

static inline int validate_atomic_max_u32(void *val, void *out ODP_UNUSED, uint32_t num_round,
					  uint32_t num_worker ODP_UNUSED, int private ODP_UNUSED)
{
	uint32_t result = odp_atomic_load_u32((odp_atomic_u32_t *)val);

	return (result != ((uint32_t)INIT_VAL + num_round)) && (result != UINT32_MAX);
}

static inline int validate_atomic_max_u64(void *val, void *out ODP_UNUSED, uint32_t num_round,
					  uint32_t num_worker ODP_UNUSED, int private ODP_UNUSED)
{
	uint64_t result = odp_atomic_load_u64((odp_atomic_u64_t *)val);

	return (result != ((uint64_t)INIT_VAL + num_round)) && (result != UINT64_MAX);
}

static inline void test_atomic_min_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t new_min = INIT_VAL - 1;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_min_u32(atomic_val, new_min--);
}

static inline void test_atomic_min_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t new_min = INIT_VAL - 1;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_min_u64(atomic_val, new_min--);
}

static inline int validate_atomic_min_u32(void *val, void *out ODP_UNUSED, uint32_t num_round,
					  uint32_t num_worker ODP_UNUSED, int private ODP_UNUSED)
{
	uint32_t result = odp_atomic_load_u32((odp_atomic_u32_t *)val);

	return result != ((uint32_t)INIT_VAL - num_round) && result != 0;
}

static inline int validate_atomic_min_u64(void *val, void *out ODP_UNUSED, uint32_t num_round,
					  uint32_t num_worker ODP_UNUSED, int private ODP_UNUSED)
{
	uint64_t result = odp_atomic_load_u64((odp_atomic_u64_t *)val);

	return result != ((uint64_t)INIT_VAL - num_round) && result != 0;
}

static inline void test_atomic_cas_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t new_val = INIT_VAL + 1;
	uint32_t old_val = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_u32(atomic_val, &old_val, new_val))
			old_val = new_val++;
	}
}

static inline void test_atomic_cas_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t new_val = INIT_VAL + 1;
	uint64_t old_val = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_u64(atomic_val, &old_val, new_val))
			old_val = new_val++;
	}
}

static inline void test_atomic_cas_u128(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u128_t *atomic_val = val;
	odp_u128_t new_val;
	odp_u128_t old_val;

	new_val.u64[0] = INIT_VAL + 1;
	new_val.u64[1] = INIT_VAL + 1;
	old_val.u64[0] = INIT_VAL;
	old_val.u64[1] = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_u128(atomic_val, &old_val, new_val)) {
			old_val = new_val;
			new_val.u64[0]++;
			new_val.u64[1]++;
		}
	}
}

static inline int validate_atomic_cas_u32(void *val, void *out ODP_UNUSED, uint32_t num_round,
					  uint32_t num_worker ODP_UNUSED, int private)
{
	uint32_t result = odp_atomic_load_u32((odp_atomic_u32_t *)val);

	if (private)
		return result != ((uint32_t)INIT_VAL + num_round);

	return result > ((uint32_t)INIT_VAL + num_round);
}

static inline int validate_atomic_cas_u64(void *val, void *out ODP_UNUSED, uint32_t num_round,
					  uint32_t num_worker ODP_UNUSED, int private)
{
	uint64_t result = odp_atomic_load_u64((odp_atomic_u64_t *)val);

	if (private)
		return result != ((uint64_t)INIT_VAL + num_round);

	return result > ((uint64_t)INIT_VAL + num_round);
}

static inline int validate_atomic_cas_u128(void *val, void *out ODP_UNUSED, uint32_t num_round,
					   uint32_t num_worker ODP_UNUSED, int private)
{
	odp_u128_t result = odp_atomic_load_u128((odp_atomic_u128_t *)val);

	if (private)
		return (result.u64[0] != ((uint64_t)INIT_VAL + num_round) ||
			result.u64[1] != ((uint64_t)INIT_VAL + num_round));

	return (result.u64[0] > ((uint64_t)INIT_VAL + num_round) ||
		result.u64[1] > ((uint64_t)INIT_VAL + num_round));
}

static inline void test_atomic_xchg_u32(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t new_val = INIT_VAL + 1;
	uint32_t *result = out;
	uint32_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_xchg_u32(atomic_val, new_val++);

	*result = ret;
}

static inline void test_atomic_xchg_u64(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t new_val = INIT_VAL + 1;
	uint64_t *result = out;
	uint64_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_xchg_u64(atomic_val, new_val++);

	*result = ret;
}

static inline void test_atomic_load_acq_u32(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t *result = out;
	uint32_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_load_acq_u32(atomic_val);

	*result = ret;
}

static inline void test_atomic_load_acq_u64(void *val, void *out, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t *result = out;
	uint64_t ret = 0;

	for (uint32_t i = 0; i < num_round; i++)
		ret += odp_atomic_load_acq_u64(atomic_val);

	*result = ret;
}

static inline void test_atomic_store_rel_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t new_val = INIT_VAL + 1;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_store_rel_u32(atomic_val, new_val++);
}

static inline void test_atomic_store_rel_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t new_val = INIT_VAL + 1;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_store_rel_u64(atomic_val, new_val++);
}

static inline void test_atomic_add_rel_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_add_rel_u32(atomic_val, 1);
}

static inline void test_atomic_add_rel_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_add_rel_u64(atomic_val, 1);
}

static inline void test_atomic_sub_rel_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_sub_rel_u32(atomic_val, 1);
}

static inline void test_atomic_sub_rel_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;

	for (uint32_t i = 0; i < num_round; i++)
		odp_atomic_sub_rel_u64(atomic_val, 1);
}

static inline void test_atomic_cas_acq_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t new_val = INIT_VAL + 1;
	uint32_t old_val = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_acq_u32(atomic_val, &old_val, new_val))
			old_val = new_val++;
	}
}

static inline void test_atomic_cas_acq_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t new_val = INIT_VAL + 1;
	uint64_t old_val = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_acq_u64(atomic_val, &old_val, new_val))
			old_val = new_val++;
	}
}

static inline void test_atomic_cas_acq_u128(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u128_t *atomic_val = val;
	odp_u128_t new_val;
	odp_u128_t old_val;

	new_val.u64[0] = INIT_VAL + 1;
	new_val.u64[1] = INIT_VAL + 1;
	old_val.u64[0] = INIT_VAL;
	old_val.u64[1] = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_acq_u128(atomic_val, &old_val, new_val)) {
			old_val = new_val;
			new_val.u64[0]++;
			new_val.u64[1]++;
		}
	}
}

static inline void test_atomic_cas_rel_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t new_val = INIT_VAL + 1;
	uint32_t old_val = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_rel_u32(atomic_val, &old_val, new_val))
			old_val = new_val++;
	}
}

static inline void test_atomic_cas_rel_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t new_val = INIT_VAL + 1;
	uint64_t old_val = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_rel_u64(atomic_val, &old_val, new_val))
			old_val = new_val++;
	}
}

static inline void test_atomic_cas_rel_u128(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u128_t *atomic_val = val;
	odp_u128_t new_val;
	odp_u128_t old_val;

	new_val.u64[0] = INIT_VAL + 1;
	new_val.u64[1] = INIT_VAL + 1;
	old_val.u64[0] = INIT_VAL;
	old_val.u64[1] = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_rel_u128(atomic_val, &old_val, new_val)) {
			old_val = new_val;
			new_val.u64[0]++;
			new_val.u64[1]++;
		}
	}
}

static inline void test_atomic_cas_acq_rel_u32(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u32_t *atomic_val = val;
	uint32_t new_val = INIT_VAL + 1;
	uint32_t old_val = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_acq_rel_u32(atomic_val, &old_val, new_val))
			old_val = new_val++;
	}
}

static inline void test_atomic_cas_acq_rel_u64(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u64_t *atomic_val = val;
	uint64_t new_val = INIT_VAL + 1;
	uint64_t old_val = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_acq_rel_u64(atomic_val, &old_val, new_val))
			old_val = new_val++;
	}
}

static inline void test_atomic_cas_acq_rel_u128(void *val, void *out ODP_UNUSED, uint32_t num_round)
{
	odp_atomic_u128_t *atomic_val = val;
	odp_u128_t new_val;
	odp_u128_t old_val;

	new_val.u64[0] = INIT_VAL + 1;
	new_val.u64[1] = INIT_VAL + 1;
	old_val.u64[0] = INIT_VAL;
	old_val.u64[1] = INIT_VAL;

	for (uint32_t i = 0; i < num_round; i++) {
		if (odp_atomic_cas_acq_rel_u128(atomic_val, &old_val, new_val)) {
			old_val = new_val;
			new_val.u64[0]++;
			new_val.u64[1]++;
		}
	}
}

static void print_usage(void)
{
	printf("\n"
	       "Atomic operations performance test\n"
	       "\n"
	       "Usage: odp_atomic_perf [options]\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs (or max %d) (default)\n"
	       "  -r, --num_round        Number of rounds (default %u)\n"
	       "  -p, --private          0: The same atomic variable is shared between threads (default)\n"
	       "                         1: Atomic variables are private to each thread\n"
	       "  -h, --help             This help\n"
	       "\n", DEFAULT_MAX_WORKERS, NUM_ROUNDS);
}

static void print_info(test_options_t *test_options)
{
	odp_atomic_op_t atomic_ops;

	printf("\nAtomic operations performance test configuration:\n");
	printf("  num cpu          %u\n", test_options->num_cpu);
	printf("  num rounds       %u\n", test_options->num_round);
	printf("  private          %i\n", test_options->private);
	printf("\n");

	atomic_ops.all_bits = 0;
	odp_atomic_lock_free_u64(&atomic_ops);

	printf("\nAtomic operations lock-free:\n");
	printf("  odp_atomic_load_u64:      %" PRIu32 "\n", atomic_ops.op.load);
	printf("  odp_atomic_store_u64:     %" PRIu32 "\n", atomic_ops.op.store);
	printf("  odp_atomic_fetch_add_u64: %" PRIu32 "\n", atomic_ops.op.fetch_add);
	printf("  odp_atomic_add_u64:       %" PRIu32 "\n", atomic_ops.op.add);
	printf("  odp_atomic_fetch_sub_u64: %" PRIu32 "\n", atomic_ops.op.fetch_sub);
	printf("  odp_atomic_sub_u64:       %" PRIu32 "\n", atomic_ops.op.sub);
	printf("  odp_atomic_fetch_inc_u64: %" PRIu32 "\n", atomic_ops.op.fetch_inc);
	printf("  odp_atomic_inc_u64:       %" PRIu32 "\n", atomic_ops.op.inc);
	printf("  odp_atomic_fetch_dec_u64: %" PRIu32 "\n", atomic_ops.op.fetch_dec);
	printf("  odp_atomic_dec_u64:       %" PRIu32 "\n", atomic_ops.op.dec);
	printf("  odp_atomic_min_u64:       %" PRIu32 "\n", atomic_ops.op.min);
	printf("  odp_atomic_max_u64:       %" PRIu32 "\n", atomic_ops.op.max);
	printf("  odp_atomic_cas_u64:       %" PRIu32 "\n", atomic_ops.op.cas);
	printf("  odp_atomic_xchg_u64:      %" PRIu32 "\n", atomic_ops.op.xchg);

	atomic_ops.all_bits = 0;
	odp_atomic_lock_free_u128(&atomic_ops);

	printf("  odp_atomic_load_u128:     %" PRIu32 "\n", atomic_ops.op.load);
	printf("  odp_atomic_store_u128:    %" PRIu32 "\n", atomic_ops.op.store);
	printf("  odp_atomic_cas_u128:      %" PRIu32 "\n", atomic_ops.op.cas);

	printf("\n\n");
}

static int parse_options(int argc, char *argv[], test_options_t *test_options)
{
	int opt;
	int long_index;
	int ret = 0;

	static const struct option longopts[] = {
		{"num_cpu",   required_argument, NULL, 'c'},
		{"num_round", required_argument, NULL, 'r'},
		{"private",   required_argument, NULL, 'p'},
		{"help",      no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:r:p:h";

	memset(test_options, 0, sizeof(test_options_t));
	test_options->num_cpu   = 0;
	test_options->num_round = NUM_ROUNDS;
	test_options->private   = 0;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 'r':
			test_options->num_round = atol(optarg);
			break;
		case 'p':
			test_options->private = atoi(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_options->num_round < 1) {
		ODPH_ERR("Invalid number of test rounds: %" PRIu32 "\n", test_options->num_round);
		return -1;
	}

	return ret;
}

static int set_num_cpu(test_global_t *global)
{
	int ret, max_num;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;

	/* One thread used for the main thread */
	if (num_cpu > ODP_THREAD_COUNT_MAX - 1) {
		ODPH_ERR("Too many workers. Maximum is %i.\n", ODP_THREAD_COUNT_MAX - 1);
		return -1;
	}

	max_num = num_cpu;
	if (num_cpu == 0) {
		max_num = ODP_THREAD_COUNT_MAX - 1;
		if (max_num > DEFAULT_MAX_WORKERS)
			max_num = DEFAULT_MAX_WORKERS;
	}

	ret = odp_cpumask_default_worker(&global->cpumask, max_num);

	if (num_cpu && ret != num_cpu) {
		ODPH_ERR("Too many workers. Max supported %i.\n", ret);
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		if (ret > max_num) {
			ODPH_ERR("Too many cpus from odp_cpumask_default_worker(): %i\n", ret);
			return -1;
		}

		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	odp_barrier_init(&global->barrier, num_cpu);

	return 0;
}

static int init_test(test_global_t *global, const char *name, op_bit_t type)
{
	odp_u128_t init_val;

	init_val.u64[0] = INIT_VAL;
	init_val.u64[1] = INIT_VAL;

	printf("TEST: %s\n", name);

	if (type == OP_32BIT)
		odp_atomic_init_u32(&global->atomic_u32, INIT_VAL);
	else if (type == OP_64BIT)
		odp_atomic_init_u64(&global->atomic_u64, INIT_VAL);
	else if (type == OP_128BIT)
		odp_atomic_init_u128(&global->atomic_u128, init_val);
	else
		return -1;

	for (int i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (type == OP_32BIT) {
			global->output[i].u32 = 0;
			odp_atomic_init_u32(&global->atomic_private[i].u32, INIT_VAL);
		} else if (type == OP_64BIT) {
			global->output[i].u64 = 0;
			odp_atomic_init_u64(&global->atomic_private[i].u64, INIT_VAL);
		} else {
			global->output[i].u128.u64[0] = 0;
			global->output[i].u128.u64[1] = 0;
			odp_atomic_init_u128(&global->atomic_private[i].u128, init_val);
		}
	}
	return 0;
}

static int run_test(void *arg)
{
	uint64_t nsec;
	odp_time_t t1, t2;
	test_thread_ctx_t *thread_ctx = arg;
	test_global_t *global = thread_ctx->global;
	test_options_t *test_options = &global->test_options;
	uint32_t num_round = test_options->num_round;
	uint32_t idx = thread_ctx->idx;
	test_fn_t test_func = thread_ctx->func;
	op_bit_t type = thread_ctx->type;
	void *val;
	void *out;
	uint32_t out_u32 = 0;
	uint64_t out_u64 = 0;
	odp_u128_t out_u128;

	out_u128.u64[0] = 0;
	out_u128.u64[1] = 0;

	if (type == OP_32BIT) {
		val = &global->atomic_u32;
		out = &out_u32;
	} else if (type == OP_64BIT) {
		val = &global->atomic_u64;
		out = &out_u64;
	} else {
		val = &global->atomic_u128;
		out = &out_u128;
	}

	if (global->test_options.private) {
		if (type == OP_32BIT)
			val = &global->atomic_private[idx].u32;
		else if (type == OP_64BIT)
			val = &global->atomic_private[idx].u64;
		else
			val = &global->atomic_private[idx].u128;
	}

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	t1 = odp_time_local();

	test_func(val, out, num_round);

	t2 = odp_time_local();

	nsec = odp_time_diff_ns(t2, t1);

	/* Update stats */
	thread_ctx->nsec = nsec;
	if (type == OP_32BIT)
		global->output[idx].u32 = out_u32;
	else if (type == OP_64BIT)
		global->output[idx].u64 = out_u64;
	else
		global->output[idx].u128 = out_u128;

	return 0;
}

static int start_workers(test_global_t *global, odp_instance_t instance,
			 test_fn_t func, op_bit_t type)
{
	odph_thread_common_param_t param;
	int i, ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	odph_thread_param_t thr_param[num_cpu];

	odph_thread_common_param_init(&param);
	param.instance = instance;
	param.cpumask  = &global->cpumask;

	for (i = 0; i < num_cpu; i++) {
		test_thread_ctx_t *thread_ctx = &global->thread_ctx[i];

		thread_ctx->global = global;
		thread_ctx->idx = i;
		thread_ctx->func = func;
		thread_ctx->type = type;

		odph_thread_param_init(&thr_param[i]);
		thr_param[i].thr_type = ODP_THREAD_WORKER;
		thr_param[i].start = run_test;
		thr_param[i].arg = thread_ctx;
	}

	ret = odph_thread_create(global->thread_tbl, &param, thr_param, num_cpu);
	if (ret != num_cpu) {
		ODPH_ERR("Failed to create all threads %i\n", ret);
		return -1;
	}

	return 0;
}

static int validate_results(test_global_t *global, validate_fn_t validate, op_bit_t type)
{
	int i;
	test_options_t *test_options = &global->test_options;
	uint32_t num_round = test_options->num_round;
	int num_cpu = test_options->num_cpu;
	int private = global->test_options.private;
	void *val;
	void *out;

	for (i = 0; i < num_cpu; i++) {
		if (type == OP_32BIT) {
			out = &global->output[i].u32;
			val = &global->atomic_u32;
			if (private)
				val = &global->atomic_private[i].u32;
		} else if (type == OP_64BIT) {
			out = &global->output[i].u64;
			val = &global->atomic_u64;
			if (private)
				val = &global->atomic_private[i].u64;
		} else {
			out = &global->output[i].u128;
			val = &global->atomic_u128;
			if (private)
				val = &global->atomic_private[i].u128;
		}

		if (validate(val, out, num_round, num_cpu, private))
			return -1;
	}
	return 0;
}

static void print_stat(test_global_t *global)
{
	int i, num;
	double nsec_ave;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;
	uint32_t num_round = test_options->num_round;
	uint64_t nsec_sum = 0;

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		nsec_sum += global->thread_ctx[i].nsec;

	if (nsec_sum == 0) {
		printf("No results.\n");
		return;
	}

	nsec_ave = nsec_sum / num_cpu;
	num = 0;

	printf("---------------------------------------------\n");
	printf("Per thread results (Millions of ops per sec):\n");
	printf("---------------------------------------------\n");
	printf("          1        2        3        4        5        6        7        8        9       10");

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++) {
		if (global->thread_ctx[i].nsec) {
			if ((num % 10) == 0)
				printf("\n   ");

			printf("%8.2f ", num_round / (global->thread_ctx[i].nsec / 1000.0));
			num++;
		}
	}
	printf("\n\n");

	printf("Average results over %i threads:\n", num_cpu);
	printf("---------------------------------------\n");
	printf("  duration:           %8.2f  sec\n",  nsec_ave / ODP_TIME_SEC_IN_NS);
	printf("  operations per cpu: %8.2fM ops/sec\n", num_round / (nsec_ave / 1000.0));
	printf("  total operations:   %8.2fM ops/sec\n",
	       (num_cpu * num_round) / (nsec_ave / 1000.0));
	printf("\n\n");
}

/**
 * Test functions
 */
static test_case_t test_suite[] = {
	TEST_INFO("odp_atomic_load_u32", test_atomic_load_u32,
		  validate_atomic_init_val_u32, OP_32BIT),
	TEST_INFO("odp_atomic_store_u32", test_atomic_store_u32,
		  validate_atomic_num_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_fetch_add_u32", test_atomic_fetch_add_u32,
		  validate_atomic_add_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_add_u32", test_atomic_add_u32,
		  validate_atomic_add_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_fetch_sub_u32", test_atomic_fetch_sub_u32,
		  validate_atomic_sub_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_sub_u32", test_atomic_sub_u32,
		  validate_atomic_sub_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_fetch_inc_u32", test_atomic_fetch_inc_u32,
		  validate_atomic_add_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_inc_u32", test_atomic_inc_u32,
		  validate_atomic_add_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_fetch_dec_u32", test_atomic_fetch_dec_u32,
		  validate_atomic_sub_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_dec_u32", test_atomic_dec_u32,
		  validate_atomic_sub_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_max_u32", test_atomic_max_u32,
		  validate_atomic_max_u32, OP_32BIT),
	TEST_INFO("odp_atomic_min_u32", test_atomic_min_u32,
		  validate_atomic_min_u32, OP_32BIT),
	TEST_INFO("odp_atomic_cas_u32", test_atomic_cas_u32,
		  validate_atomic_cas_u32, OP_32BIT),
	TEST_INFO("odp_atomic_xchg_u32", test_atomic_xchg_u32,
		  validate_atomic_num_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_load_acq_u32", test_atomic_load_acq_u32,
		  validate_atomic_init_val_u32, OP_32BIT),
	TEST_INFO("odp_atomic_store_rel_u32", test_atomic_store_rel_u32,
		  validate_atomic_num_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_add_rel_u32", test_atomic_add_rel_u32,
		  validate_atomic_add_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_sub_rel_u32", test_atomic_sub_rel_u32,
		  validate_atomic_sub_round_u32, OP_32BIT),
	TEST_INFO("odp_atomic_cas_acq_u32", test_atomic_cas_acq_u32,
		  validate_atomic_cas_u32, OP_32BIT),
	TEST_INFO("odp_atomic_cas_rel_u32", test_atomic_cas_rel_u32,
		  validate_atomic_cas_u32, OP_32BIT),
	TEST_INFO("odp_atomic_cas_acq_rel_u32", test_atomic_cas_acq_rel_u32,
		  validate_atomic_cas_u32, OP_32BIT),
	TEST_INFO("odp_atomic_load_u64", test_atomic_load_u64,
		  validate_atomic_init_val_u64, OP_64BIT),
	TEST_INFO("odp_atomic_store_u64", test_atomic_store_u64,
		  validate_atomic_num_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_fetch_add_u64", test_atomic_fetch_add_u64,
		  validate_atomic_add_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_add_u64", test_atomic_add_u64,
		  validate_atomic_add_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_fetch_sub_u64", test_atomic_fetch_sub_u64,
		  validate_atomic_sub_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_sub_u64", test_atomic_sub_u64,
		  validate_atomic_sub_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_fetch_inc_u64", test_atomic_fetch_inc_u64,
		  validate_atomic_add_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_inc_u64", test_atomic_inc_u64,
		  validate_atomic_add_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_fetch_dec_u64", test_atomic_fetch_dec_u64,
		  validate_atomic_sub_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_dec_u64", test_atomic_dec_u64,
		  validate_atomic_sub_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_max_u64", test_atomic_max_u64,
		  validate_atomic_max_u64, OP_64BIT),
	TEST_INFO("odp_atomic_min_u64", test_atomic_min_u64,
		  validate_atomic_min_u64, OP_64BIT),
	TEST_INFO("odp_atomic_cas_u64", test_atomic_cas_u64,
		  validate_atomic_cas_u64, OP_64BIT),
	TEST_INFO("odp_atomic_xchg_u64", test_atomic_xchg_u64,
		  validate_atomic_num_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_load_acq_u64", test_atomic_load_acq_u64,
		  validate_atomic_init_val_u64, OP_64BIT),
	TEST_INFO("odp_atomic_store_rel_u64", test_atomic_store_rel_u64,
		  validate_atomic_num_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_add_rel_u64", test_atomic_add_rel_u64,
		  validate_atomic_add_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_sub_rel_u64", test_atomic_sub_rel_u64,
		  validate_atomic_sub_round_u64, OP_64BIT),
	TEST_INFO("odp_atomic_cas_acq_u64", test_atomic_cas_acq_u64,
		  validate_atomic_cas_u64, OP_64BIT),
	TEST_INFO("odp_atomic_cas_rel_u64", test_atomic_cas_rel_u64,
		  validate_atomic_cas_u64, OP_64BIT),
	TEST_INFO("odp_atomic_cas_acq_rel_u64", test_atomic_cas_acq_rel_u64,
		  validate_atomic_cas_u64, OP_64BIT),
	TEST_INFO("odp_atomic_load_u128", test_atomic_load_u128,
		  validate_atomic_init_val_u128, OP_128BIT),
	TEST_INFO("odp_atomic_store_u128", test_atomic_store_u128,
		  validate_atomic_num_round_u128, OP_128BIT),
	TEST_INFO("odp_atomic_cas_u128", test_atomic_cas_u128,
		  validate_atomic_cas_u128, OP_128BIT),
	TEST_INFO("odp_atomic_cas_acq_u128", test_atomic_cas_acq_u128,
		  validate_atomic_cas_u128, OP_128BIT),
	TEST_INFO("odp_atomic_cas_rel_u128", test_atomic_cas_rel_u128,
		  validate_atomic_cas_u128, OP_128BIT),
	TEST_INFO("odp_atomic_cas_acq_rel_u128", test_atomic_cas_acq_rel_u128,
		  validate_atomic_cas_u128, OP_128BIT),
};

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm;
	test_options_t test_options;
	int num_tests, i;

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Error: reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	if (parse_options(argc, argv, &test_options))
		exit(EXIT_FAILURE);

	/* List features not to be used */
	odp_init_param_init(&init);
	init.not_used.feat.cls      = 1;
	init.not_used.feat.compress = 1;
	init.not_used.feat.crypto   = 1;
	init.not_used.feat.ipsec    = 1;
	init.not_used.feat.schedule = 1;
	init.not_used.feat.stash    = 1;
	init.not_used.feat.timer    = 1;
	init.not_used.feat.tm       = 1;

	init.mem_model = helper_options.mem_model;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Reserve memory for global data from shared mem */
	shm = odp_shm_reserve("test_global", sizeof(test_global_t),
			      ODP_CACHE_LINE_SIZE, 0);

	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("Shared memory reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	test_global = odp_shm_addr(shm);
	if (test_global == NULL) {
		ODPH_ERR("Shared memory alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(test_global, 0, sizeof(test_global_t));
	test_global->test_options = test_options;

	odp_sys_info_print();

	if (set_num_cpu(test_global))
		exit(EXIT_FAILURE);

	print_info(&test_global->test_options);

	/* Loop all test cases */
	num_tests = ODPH_ARRAY_SIZE(test_suite);

	for (i = 0; i < num_tests; i++) {
		/* Initialize test variables */
		if (init_test(test_global, test_suite[i].name, test_suite[i].type)) {
			ODPH_ERR("Failed to initialize atomics.\n");
			exit(EXIT_FAILURE);
		}

		/* Start workers */
		if (start_workers(test_global, instance, test_suite[i].test_fn, test_suite[i].type))
			exit(EXIT_FAILURE);

		/* Wait workers to exit */
		odph_thread_join(test_global->thread_tbl, test_global->test_options.num_cpu);

		print_stat(test_global);

		/* Validate test results */
		if (validate_results(test_global, test_suite[i].validate_fn, test_suite[i].type)) {
			ODPH_ERR("Test %s result validation failed.\n", test_suite[i].name);
			exit(EXIT_FAILURE);
		}
	}

	if (odp_shm_free(shm)) {
		ODPH_ERR("Shm free failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Local terminate failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Global terminate failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

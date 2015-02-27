/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ATOMIC_TEST_H_
#define ODP_ATOMIC_TEST_H_

#include <odp.h>
#include <odph_linux.h>

/**
 * add_sub_cnt could be any valid value
 * so to excercise explicit atomic_add/sub
 * ops. For now using 5..
 */
#define ADD_SUB_CNT	5

#define	CNT 500000
#define	U32_INIT_VAL	(1UL << 10)
#define	U64_INIT_VAL	(1ULL << 33)

typedef enum {
	TEST_MIX = 1, /* Must be first test case num */
	TEST_INC_DEC_U32,
	TEST_ADD_SUB_U32,
	TEST_INC_DEC_64,
	TEST_ADD_SUB_64,
	TEST_MAX,
} odp_test_atomic_t;


void test_atomic_inc_dec_u32(void);
void test_atomic_add_sub_u32(void);
void test_atomic_inc_dec_64(void);
void test_atomic_add_sub_64(void);
void test_atomic_inc_u32(void);
void test_atomic_dec_u32(void);
void test_atomic_add_u32(void);
void test_atomic_sub_u32(void);
void test_atomic_inc_64(void);
void test_atomic_dec_64(void);
void test_atomic_add_64(void);
void test_atomic_sub_64(void);
void test_atomic_init(void);
void test_atomic_basic(void);
void test_atomic_store(void);
int test_atomic_validate(void);

#endif /* ODP_ATOMIC_TEST_H_ */

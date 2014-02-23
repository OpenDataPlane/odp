/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ATOMIC_TEST_H_
#define ODP_ATOMIC_TEST_H_

#include <odp.h>
#include <helper/odp_linux.h>

/**
 * add_sub_cnt could be any valid value
 * so to excercise explicit atomic_add/sub
 * ops. For now using 5..
 */
#define ADD_SUB_CNT	5

#define	CNT 500000
#define	S32_INIT_VAL	(1UL << 10)
#define	U32_INIT_VAL	(1UL << 10)
#define	U64_INIT_VAL	(1ULL << 33)

#define	TEST_MIX		1 /* Must be first test case num */
#define	TEST_INC_DEC_S32	2
#define	TEST_ADD_SUB_S32	3
#define	TEST_INC_DEC_U32	4
#define	TEST_ADD_SUB_U32	5
#define	TEST_INC_DEC_64		6
#define	TEST_ADD_SUB_64		7
#define	TEST_MAX		7 /* This must match the last test case num */


void test_atomic_inc_dec_32(void);
void test_atomic_add_sub_32(void);
void test_atomic_inc_dec_u32(void);
void test_atomic_add_sub_u32(void);
void test_atomic_inc_dec_64(void);
void test_atomic_add_sub_64(void);
void test_atomic_inc_32(void);
void test_atomic_dec_32(void);
void test_atomic_add_32(void);
void test_atomic_sub_32(void);
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

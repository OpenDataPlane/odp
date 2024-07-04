/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

/**
 * @example odp_icache_perf.c
 *
 * Test application that can be used to test CPU instruction cache performance.
 *
 * @cond _ODP_HIDE_FROM_DOXYGEN_
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* Needed for sigaction */
#endif

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#ifdef __GNUC__
	#define INLINE_NEVER  __attribute__((noinline))
	#define INLINE_ALWAYS __attribute__((always_inline))
#else
	#define INLINE_NEVER
	#define INLINE_ALWAYS
#endif

/* Maximum number of data words that any work function accesses */
#define MAX_WORDS       32
#define DATA_SIZE_WORDS (4 * 1024)
#define PATTERN_RANDOM  1
#define NUM_WORK        5

typedef struct test_options_t {
	uint32_t num_cpu;
	uint32_t num_func;
	uint64_t rounds;
	int      pattern;

} test_options_t;

typedef struct test_stat_t {
	uint64_t loops;
	uint64_t tot_nsec;
	uint64_t cycles;
	uint64_t dummy_sum;

} test_stat_t;

typedef struct thread_arg_t {
	void *global;
	test_stat_t stat;

} thread_arg_t;

typedef struct test_global_t {
	test_options_t test_options;
	odp_atomic_u32_t exit_test;
	odp_barrier_t barrier;
	odp_cpumask_t cpumask;
	void *worker_mem;
	uint32_t max_func;
	odph_thread_t thread_tbl[ODP_THREAD_COUNT_MAX];
	thread_arg_t thread_arg[ODP_THREAD_COUNT_MAX];

} test_global_t;

static test_global_t *test_global;

/* Work functions. Update MAX_WORDS value to match the largest number of words accessed. */

static inline INLINE_ALWAYS uint64_t mac_28(uint64_t a, uint32_t b[], uint32_t c[])
{
	a += b[0]  * c[0];
	a += b[1]  * c[1];
	a += b[2]  * c[2];
	a += b[3]  * c[3];
	a += b[4]  * c[4];
	a += b[5]  * c[5];
	a += b[6]  * c[6];
	a += b[7]  * c[7];
	a += b[8]  * c[8];
	a += b[9]  * c[9];
	a += b[10] * c[10];
	a += b[11] * c[11];
	a += b[12] * c[12];
	a += b[13] * c[13];
	a += b[14] * c[14];
	a += b[15] * c[15];
	a += b[16] * c[16];
	a += b[17] * c[17];
	a += b[18] * c[18];
	a += b[19] * c[19];
	a += b[20] * c[20];
	a += b[21] * c[21];
	a += b[22] * c[22];
	a += b[23] * c[23];
	a += b[24] * c[24];
	a += b[25] * c[25];
	a += b[26] * c[26];
	a += b[27] * c[27];

	return a;
}

static inline INLINE_ALWAYS uint64_t mac_30(uint64_t a, uint32_t b[], uint32_t c[])
{
	a += b[0]  * c[0];
	a += b[1]  * c[1];
	a += b[2]  * c[2];
	a += b[3]  * c[3];
	a += b[4]  * c[4];
	a += b[5]  * c[5];
	a += b[6]  * c[6];
	a += b[7]  * c[7];
	a += b[8]  * c[8];
	a += b[9]  * c[9];
	a += b[10] * c[10];
	a += b[11] * c[11];
	a += b[12] * c[12];
	a += b[13] * c[13];
	a += b[14] * c[14];
	a += b[15] * c[15];
	a += b[16] * c[16];
	a += b[17] * c[17];
	a += b[18] * c[18];
	a += b[19] * c[19];
	a += b[20] * c[20];
	a += b[21] * c[21];
	a += b[22] * c[22];
	a += b[23] * c[23];
	a += b[24] * c[24];
	a += b[25] * c[25];
	a += b[26] * c[26];
	a += b[27] * c[27];
	a += b[28] * c[28];
	a += b[29] * c[29];

	return a;
}

static inline INLINE_ALWAYS uint64_t mac_32(uint64_t a, uint32_t b[], uint32_t c[])
{
	a += b[0]  * c[0];
	a += b[1]  * c[1];
	a += b[2]  * c[2];
	a += b[3]  * c[3];
	a += b[4]  * c[4];
	a += b[5]  * c[5];
	a += b[6]  * c[6];
	a += b[7]  * c[7];
	a += b[8]  * c[8];
	a += b[9]  * c[9];
	a += b[10] * c[10];
	a += b[11] * c[11];
	a += b[12] * c[12];
	a += b[13] * c[13];
	a += b[14] * c[14];
	a += b[15] * c[15];
	a += b[16] * c[16];
	a += b[17] * c[17];
	a += b[18] * c[18];
	a += b[19] * c[19];
	a += b[20] * c[20];
	a += b[21] * c[21];
	a += b[22] * c[22];
	a += b[23] * c[23];
	a += b[24] * c[24];
	a += b[25] * c[25];
	a += b[26] * c[26];
	a += b[27] * c[27];
	a += b[28] * c[28];
	a += b[29] * c[29];
	a += b[30] * c[30];
	a += b[31] * c[31];

	return a;
}

static inline INLINE_ALWAYS uint64_t mac_const_30(uint64_t a, uint32_t b[], uint32_t c)
{
	a += b[0]  * c;
	a += b[1]  * c;
	a += b[2]  * c;
	a += b[3]  * c;
	a += b[4]  * c;
	a += b[5]  * c;
	a += b[6]  * c;
	a += b[7]  * c;
	a += b[8]  * c;
	a += b[9]  * c;
	a += b[10] * c;
	a += b[11] * c;
	a += b[12] * c;
	a += b[13] * c;
	a += b[14] * c;
	a += b[15] * c;
	a += b[16] * c;
	a += b[17] * c;
	a += b[18] * c;
	a += b[19] * c;
	a += b[20] * c;
	a += b[21] * c;
	a += b[22] * c;
	a += b[23] * c;
	a += b[24] * c;
	a += b[25] * c;
	a += b[26] * c;
	a += b[27] * c;
	a += b[28] * c;
	a += b[29] * c;

	return a;
}

static inline INLINE_ALWAYS uint64_t mac_const_32(uint64_t a, uint32_t b[], uint32_t c)
{
	a += b[0]  * c;
	a += b[1]  * c;
	a += b[2]  * c;
	a += b[3]  * c;
	a += b[4]  * c;
	a += b[5]  * c;
	a += b[6]  * c;
	a += b[7]  * c;
	a += b[8]  * c;
	a += b[9]  * c;
	a += b[10] * c;
	a += b[11] * c;
	a += b[12] * c;
	a += b[13] * c;
	a += b[14] * c;
	a += b[15] * c;
	a += b[16] * c;
	a += b[17] * c;
	a += b[18] * c;
	a += b[19] * c;
	a += b[20] * c;
	a += b[21] * c;
	a += b[22] * c;
	a += b[23] * c;
	a += b[24] * c;
	a += b[25] * c;
	a += b[26] * c;
	a += b[27] * c;
	a += b[28] * c;
	a += b[29] * c;
	a += b[30] * c;
	a += b[31] * c;

	return a;
}

typedef uint64_t (*work_0_fn_t)(uint64_t a, uint32_t *b, uint32_t *c);
typedef uint64_t (*work_1_fn_t)(uint64_t a, uint32_t *b, uint32_t *c);
typedef uint64_t (*work_2_fn_t)(uint64_t a, uint32_t *b, uint32_t *c);
typedef uint64_t (*work_3_fn_t)(uint64_t a, uint32_t *b);
typedef uint64_t (*work_4_fn_t)(uint64_t a, uint32_t *b);

#define WORK_0(a, b, c, n) (mac_28((a), &(b)[(n)], &(c)[(n)]))
#define WORK_1(a, b, c, n) (mac_30((a), &(b)[(n)], &(c)[(n)]))
#define WORK_2(a, b, c, n) (mac_32((a), &(b)[(n)], &(c)[(n)]))
#define WORK_3(a, b, n)    (mac_const_30((a), &(b)[(n)], ((n) + 10)))
#define WORK_4(a, b, n)    (mac_const_32((a), &(b)[(n)], ((n) + 10)))

static uint64_t INLINE_NEVER work_0aa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 0);
}

static uint64_t INLINE_NEVER work_0ab(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 1);
}

static uint64_t INLINE_NEVER work_0ac(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 2);
}

static uint64_t INLINE_NEVER work_0ad(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 3);
}

static uint64_t INLINE_NEVER work_0ae(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 4);
}

static uint64_t INLINE_NEVER work_0af(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 5);
}

static uint64_t INLINE_NEVER work_0ag(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 6);
}

static uint64_t INLINE_NEVER work_0ah(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 7);
}

static uint64_t INLINE_NEVER work_0ai(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 8);
}

static uint64_t INLINE_NEVER work_0aj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 9);
}

static uint64_t INLINE_NEVER work_0ak(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 10);
}

static uint64_t INLINE_NEVER work_0al(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 11);
}

static uint64_t INLINE_NEVER work_0am(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 12);
}

static uint64_t INLINE_NEVER work_0an(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 13);
}

static uint64_t INLINE_NEVER work_0ao(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 14);
}

static uint64_t INLINE_NEVER work_0ap(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 15);
}

static uint64_t INLINE_NEVER work_0aq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 16);
}

static uint64_t INLINE_NEVER work_0ar(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 17);
}

static uint64_t INLINE_NEVER work_0as(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 18);
}

static uint64_t INLINE_NEVER work_0at(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 19);
}

static uint64_t INLINE_NEVER work_0au(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 20);
}

static uint64_t INLINE_NEVER work_0av(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 21);
}

static uint64_t INLINE_NEVER work_0aw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 22);
}

static uint64_t INLINE_NEVER work_0ax(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 23);
}

static uint64_t INLINE_NEVER work_0ba(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 24);
}

static uint64_t INLINE_NEVER work_0bb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 25);
}

static uint64_t INLINE_NEVER work_0bc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 26);
}

static uint64_t INLINE_NEVER work_0bd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 27);
}

static uint64_t INLINE_NEVER work_0be(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 28);
}

static uint64_t INLINE_NEVER work_0bf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 29);
}

static uint64_t INLINE_NEVER work_0bg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 30);
}

static uint64_t INLINE_NEVER work_0bh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 31);
}

static uint64_t INLINE_NEVER work_0bi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 32);
}

static uint64_t INLINE_NEVER work_0bj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 33);
}

static uint64_t INLINE_NEVER work_0bk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 34);
}

static uint64_t INLINE_NEVER work_0bl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 35);
}

static uint64_t INLINE_NEVER work_0bm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 36);
}

static uint64_t INLINE_NEVER work_0bn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 37);
}

static uint64_t INLINE_NEVER work_0bo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 38);
}

static uint64_t INLINE_NEVER work_0bp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 39);
}

static uint64_t INLINE_NEVER work_0bq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 40);
}

static uint64_t INLINE_NEVER work_0br(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 41);
}

static uint64_t INLINE_NEVER work_0bs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 42);
}

static uint64_t INLINE_NEVER work_0bt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 43);
}

static uint64_t INLINE_NEVER work_0bu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 44);
}

static uint64_t INLINE_NEVER work_0bv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 45);
}

static uint64_t INLINE_NEVER work_0bw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 46);
}

static uint64_t INLINE_NEVER work_0bx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 47);
}

static uint64_t INLINE_NEVER work_0ca(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 48);
}

static uint64_t INLINE_NEVER work_0cb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 49);
}

static uint64_t INLINE_NEVER work_0cc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 50);
}

static uint64_t INLINE_NEVER work_0cd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 51);
}

static uint64_t INLINE_NEVER work_0ce(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 52);
}

static uint64_t INLINE_NEVER work_0cf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 53);
}

static uint64_t INLINE_NEVER work_0cg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 54);
}

static uint64_t INLINE_NEVER work_0ch(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 55);
}

static uint64_t INLINE_NEVER work_0ci(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 56);
}

static uint64_t INLINE_NEVER work_0cj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 57);
}

static uint64_t INLINE_NEVER work_0ck(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 58);
}

static uint64_t INLINE_NEVER work_0cl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 59);
}

static uint64_t INLINE_NEVER work_0cm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 60);
}

static uint64_t INLINE_NEVER work_0cn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 61);
}

static uint64_t INLINE_NEVER work_0co(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 62);
}

static uint64_t INLINE_NEVER work_0cp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 63);
}

static uint64_t INLINE_NEVER work_0cq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 64);
}

static uint64_t INLINE_NEVER work_0cr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 65);
}

static uint64_t INLINE_NEVER work_0cs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 66);
}

static uint64_t INLINE_NEVER work_0ct(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 67);
}

static uint64_t INLINE_NEVER work_0cu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 68);
}

static uint64_t INLINE_NEVER work_0cv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 69);
}

static uint64_t INLINE_NEVER work_0cw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 70);
}

static uint64_t INLINE_NEVER work_0cx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 71);
}

static uint64_t INLINE_NEVER work_0da(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 72);
}

static uint64_t INLINE_NEVER work_0db(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 73);
}

static uint64_t INLINE_NEVER work_0dc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 74);
}

static uint64_t INLINE_NEVER work_0dd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 75);
}

static uint64_t INLINE_NEVER work_0de(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 76);
}

static uint64_t INLINE_NEVER work_0df(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 77);
}

static uint64_t INLINE_NEVER work_0dg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 78);
}

static uint64_t INLINE_NEVER work_0dh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 79);
}

static uint64_t INLINE_NEVER work_0di(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 80);
}

static uint64_t INLINE_NEVER work_0dj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 81);
}

static uint64_t INLINE_NEVER work_0dk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 82);
}

static uint64_t INLINE_NEVER work_0dl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 83);
}

static uint64_t INLINE_NEVER work_0dm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 84);
}

static uint64_t INLINE_NEVER work_0dn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 85);
}

static uint64_t INLINE_NEVER work_0do(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 86);
}

static uint64_t INLINE_NEVER work_0dp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 87);
}

static uint64_t INLINE_NEVER work_0dq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 88);
}

static uint64_t INLINE_NEVER work_0dr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 89);
}

static uint64_t INLINE_NEVER work_0ds(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 90);
}

static uint64_t INLINE_NEVER work_0dt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 91);
}

static uint64_t INLINE_NEVER work_0du(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 92);
}

static uint64_t INLINE_NEVER work_0dv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 93);
}

static uint64_t INLINE_NEVER work_0dw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 94);
}

static uint64_t INLINE_NEVER work_0dx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 95);
}

static uint64_t INLINE_NEVER work_0ea(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 96);
}

static uint64_t INLINE_NEVER work_0eb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 97);
}

static uint64_t INLINE_NEVER work_0ec(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 98);
}

static uint64_t INLINE_NEVER work_0ed(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 99);
}

static uint64_t INLINE_NEVER work_0ee(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 100);
}

static uint64_t INLINE_NEVER work_0ef(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 101);
}

static uint64_t INLINE_NEVER work_0eg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 102);
}

static uint64_t INLINE_NEVER work_0eh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 103);
}

static uint64_t INLINE_NEVER work_0ei(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 104);
}

static uint64_t INLINE_NEVER work_0ej(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 105);
}

static uint64_t INLINE_NEVER work_0ek(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 106);
}

static uint64_t INLINE_NEVER work_0el(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 107);
}

static uint64_t INLINE_NEVER work_0em(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 108);
}

static uint64_t INLINE_NEVER work_0en(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 109);
}

static uint64_t INLINE_NEVER work_0eo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 110);
}

static uint64_t INLINE_NEVER work_0ep(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 111);
}

static uint64_t INLINE_NEVER work_0eq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 112);
}

static uint64_t INLINE_NEVER work_0er(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 113);
}

static uint64_t INLINE_NEVER work_0es(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 114);
}

static uint64_t INLINE_NEVER work_0et(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 115);
}

static uint64_t INLINE_NEVER work_0eu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 116);
}

static uint64_t INLINE_NEVER work_0ev(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 117);
}

static uint64_t INLINE_NEVER work_0ew(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 118);
}

static uint64_t INLINE_NEVER work_0ex(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 119);
}

static uint64_t INLINE_NEVER work_0fa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 120);
}

static uint64_t INLINE_NEVER work_0fb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 121);
}

static uint64_t INLINE_NEVER work_0fc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 122);
}

static uint64_t INLINE_NEVER work_0fd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 123);
}

static uint64_t INLINE_NEVER work_0fe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 124);
}

static uint64_t INLINE_NEVER work_0ff(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 125);
}

static uint64_t INLINE_NEVER work_0fg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 126);
}

static uint64_t INLINE_NEVER work_0fh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 127);
}

static uint64_t INLINE_NEVER work_0fi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 128);
}

static uint64_t INLINE_NEVER work_0fj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 129);
}

static uint64_t INLINE_NEVER work_0fk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 130);
}

static uint64_t INLINE_NEVER work_0fl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 131);
}

static uint64_t INLINE_NEVER work_0fm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 132);
}

static uint64_t INLINE_NEVER work_0fn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 133);
}

static uint64_t INLINE_NEVER work_0fo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 134);
}

static uint64_t INLINE_NEVER work_0fp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 135);
}

static uint64_t INLINE_NEVER work_0fq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 136);
}

static uint64_t INLINE_NEVER work_0fr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 137);
}

static uint64_t INLINE_NEVER work_0fs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 138);
}

static uint64_t INLINE_NEVER work_0ft(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 139);
}

static uint64_t INLINE_NEVER work_0fu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 140);
}

static uint64_t INLINE_NEVER work_0fv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 141);
}

static uint64_t INLINE_NEVER work_0fw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 142);
}

static uint64_t INLINE_NEVER work_0fx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 143);
}

static uint64_t INLINE_NEVER work_0ga(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 144);
}

static uint64_t INLINE_NEVER work_0gb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 145);
}

static uint64_t INLINE_NEVER work_0gc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 146);
}

static uint64_t INLINE_NEVER work_0gd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 147);
}

static uint64_t INLINE_NEVER work_0ge(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 148);
}

static uint64_t INLINE_NEVER work_0gf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 149);
}

static uint64_t INLINE_NEVER work_0gg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 150);
}

static uint64_t INLINE_NEVER work_0gh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 151);
}

static uint64_t INLINE_NEVER work_0gi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 152);
}

static uint64_t INLINE_NEVER work_0gj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 153);
}

static uint64_t INLINE_NEVER work_0gk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 154);
}

static uint64_t INLINE_NEVER work_0gl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 155);
}

static uint64_t INLINE_NEVER work_0gm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 156);
}

static uint64_t INLINE_NEVER work_0gn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 157);
}

static uint64_t INLINE_NEVER work_0go(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 158);
}

static uint64_t INLINE_NEVER work_0gp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 159);
}

static uint64_t INLINE_NEVER work_0gq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 160);
}

static uint64_t INLINE_NEVER work_0gr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 161);
}

static uint64_t INLINE_NEVER work_0gs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 162);
}

static uint64_t INLINE_NEVER work_0gt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 163);
}

static uint64_t INLINE_NEVER work_0gu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 164);
}

static uint64_t INLINE_NEVER work_0gv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 165);
}

static uint64_t INLINE_NEVER work_0gw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 166);
}

static uint64_t INLINE_NEVER work_0gx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 167);
}

static uint64_t INLINE_NEVER work_0ha(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 168);
}

static uint64_t INLINE_NEVER work_0hb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 169);
}

static uint64_t INLINE_NEVER work_0hc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 170);
}

static uint64_t INLINE_NEVER work_0hd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 171);
}

static uint64_t INLINE_NEVER work_0he(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 172);
}

static uint64_t INLINE_NEVER work_0hf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 173);
}

static uint64_t INLINE_NEVER work_0hg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 174);
}

static uint64_t INLINE_NEVER work_0hh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 175);
}

static uint64_t INLINE_NEVER work_0hi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 176);
}

static uint64_t INLINE_NEVER work_0hj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 177);
}

static uint64_t INLINE_NEVER work_0hk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 178);
}

static uint64_t INLINE_NEVER work_0hl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 179);
}

static uint64_t INLINE_NEVER work_0hm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 180);
}

static uint64_t INLINE_NEVER work_0hn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 181);
}

static uint64_t INLINE_NEVER work_0ho(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 182);
}

static uint64_t INLINE_NEVER work_0hp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 183);
}

static uint64_t INLINE_NEVER work_0hq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 184);
}

static uint64_t INLINE_NEVER work_0hr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 185);
}

static uint64_t INLINE_NEVER work_0hs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 186);
}

static uint64_t INLINE_NEVER work_0ht(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 187);
}

static uint64_t INLINE_NEVER work_0hu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 188);
}

static uint64_t INLINE_NEVER work_0hv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 189);
}

static uint64_t INLINE_NEVER work_0hw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 190);
}

static uint64_t INLINE_NEVER work_0hx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 191);
}

static uint64_t INLINE_NEVER work_0ia(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 192);
}

static uint64_t INLINE_NEVER work_0ib(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 193);
}

static uint64_t INLINE_NEVER work_0ic(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 194);
}

static uint64_t INLINE_NEVER work_0id(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 195);
}

static uint64_t INLINE_NEVER work_0ie(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 196);
}

static uint64_t INLINE_NEVER work_0if(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 197);
}

static uint64_t INLINE_NEVER work_0ig(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 198);
}

static uint64_t INLINE_NEVER work_0ih(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 199);
}

static uint64_t INLINE_NEVER work_0ii(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 200);
}

static uint64_t INLINE_NEVER work_0ij(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 201);
}

static uint64_t INLINE_NEVER work_0ik(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 202);
}

static uint64_t INLINE_NEVER work_0il(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 203);
}

static uint64_t INLINE_NEVER work_0im(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 204);
}

static uint64_t INLINE_NEVER work_0in(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 205);
}

static uint64_t INLINE_NEVER work_0io(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 206);
}

static uint64_t INLINE_NEVER work_0ip(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 207);
}

static uint64_t INLINE_NEVER work_0iq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 208);
}

static uint64_t INLINE_NEVER work_0ir(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 209);
}

static uint64_t INLINE_NEVER work_0is(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 210);
}

static uint64_t INLINE_NEVER work_0it(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 211);
}

static uint64_t INLINE_NEVER work_0iu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 212);
}

static uint64_t INLINE_NEVER work_0iv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 213);
}

static uint64_t INLINE_NEVER work_0iw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 214);
}

static uint64_t INLINE_NEVER work_0ix(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 215);
}

static uint64_t INLINE_NEVER work_0ja(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 216);
}

static uint64_t INLINE_NEVER work_0jb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 217);
}

static uint64_t INLINE_NEVER work_0jc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 218);
}

static uint64_t INLINE_NEVER work_0jd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 219);
}

static uint64_t INLINE_NEVER work_0je(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 220);
}

static uint64_t INLINE_NEVER work_0jf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 221);
}

static uint64_t INLINE_NEVER work_0jg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 222);
}

static uint64_t INLINE_NEVER work_0jh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 223);
}

static uint64_t INLINE_NEVER work_0ji(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 224);
}

static uint64_t INLINE_NEVER work_0jj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 225);
}

static uint64_t INLINE_NEVER work_0jk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 226);
}

static uint64_t INLINE_NEVER work_0jl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 227);
}

static uint64_t INLINE_NEVER work_0jm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 228);
}

static uint64_t INLINE_NEVER work_0jn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 229);
}

static uint64_t INLINE_NEVER work_0jo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 230);
}

static uint64_t INLINE_NEVER work_0jp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 231);
}

static uint64_t INLINE_NEVER work_0jq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 232);
}

static uint64_t INLINE_NEVER work_0jr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 233);
}

static uint64_t INLINE_NEVER work_0js(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 234);
}

static uint64_t INLINE_NEVER work_0jt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 235);
}

static uint64_t INLINE_NEVER work_0ju(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 236);
}

static uint64_t INLINE_NEVER work_0jv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 237);
}

static uint64_t INLINE_NEVER work_0jw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 238);
}

static uint64_t INLINE_NEVER work_0jx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 239);
}

static uint64_t INLINE_NEVER work_0ka(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 240);
}

static uint64_t INLINE_NEVER work_0kb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 241);
}

static uint64_t INLINE_NEVER work_0kc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 242);
}

static uint64_t INLINE_NEVER work_0kd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 243);
}

static uint64_t INLINE_NEVER work_0ke(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 244);
}

static uint64_t INLINE_NEVER work_0kf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 245);
}

static uint64_t INLINE_NEVER work_0kg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 246);
}

static uint64_t INLINE_NEVER work_0kh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 247);
}

static uint64_t INLINE_NEVER work_0ki(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 248);
}

static uint64_t INLINE_NEVER work_0kj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 249);
}

static uint64_t INLINE_NEVER work_0kk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 250);
}

static uint64_t INLINE_NEVER work_0kl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 251);
}

static uint64_t INLINE_NEVER work_0km(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 252);
}

static uint64_t INLINE_NEVER work_0kn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 253);
}

static uint64_t INLINE_NEVER work_0ko(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 254);
}

static uint64_t INLINE_NEVER work_0kp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 255);
}

static uint64_t INLINE_NEVER work_0kq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 256);
}

static uint64_t INLINE_NEVER work_0kr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 257);
}

static uint64_t INLINE_NEVER work_0ks(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 258);
}

static uint64_t INLINE_NEVER work_0kt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 259);
}

static uint64_t INLINE_NEVER work_0ku(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 260);
}

static uint64_t INLINE_NEVER work_0kv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 261);
}

static uint64_t INLINE_NEVER work_0kw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 262);
}

static uint64_t INLINE_NEVER work_0kx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 263);
}

static uint64_t INLINE_NEVER work_0la(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 264);
}

static uint64_t INLINE_NEVER work_0lb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 265);
}

static uint64_t INLINE_NEVER work_0lc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 266);
}

static uint64_t INLINE_NEVER work_0ld(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 267);
}

static uint64_t INLINE_NEVER work_0le(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 268);
}

static uint64_t INLINE_NEVER work_0lf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 269);
}

static uint64_t INLINE_NEVER work_0lg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 270);
}

static uint64_t INLINE_NEVER work_0lh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 271);
}

static uint64_t INLINE_NEVER work_0li(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 272);
}

static uint64_t INLINE_NEVER work_0lj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 273);
}

static uint64_t INLINE_NEVER work_0lk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 274);
}

static uint64_t INLINE_NEVER work_0ll(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 275);
}

static uint64_t INLINE_NEVER work_0lm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 276);
}

static uint64_t INLINE_NEVER work_0ln(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 277);
}

static uint64_t INLINE_NEVER work_0lo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 278);
}

static uint64_t INLINE_NEVER work_0lp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 279);
}

static uint64_t INLINE_NEVER work_0lq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 280);
}

static uint64_t INLINE_NEVER work_0lr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 281);
}

static uint64_t INLINE_NEVER work_0ls(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 282);
}

static uint64_t INLINE_NEVER work_0lt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 283);
}

static uint64_t INLINE_NEVER work_0lu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 284);
}

static uint64_t INLINE_NEVER work_0lv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 285);
}

static uint64_t INLINE_NEVER work_0lw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 286);
}

static uint64_t INLINE_NEVER work_0lx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 287);
}

static uint64_t INLINE_NEVER work_0ma(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 288);
}

static uint64_t INLINE_NEVER work_0mb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 289);
}

static uint64_t INLINE_NEVER work_0mc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 290);
}

static uint64_t INLINE_NEVER work_0md(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 291);
}

static uint64_t INLINE_NEVER work_0me(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 292);
}

static uint64_t INLINE_NEVER work_0mf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 293);
}

static uint64_t INLINE_NEVER work_0mg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 294);
}

static uint64_t INLINE_NEVER work_0mh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 295);
}

static uint64_t INLINE_NEVER work_0mi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 296);
}

static uint64_t INLINE_NEVER work_0mj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 297);
}

static uint64_t INLINE_NEVER work_0mk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 298);
}

static uint64_t INLINE_NEVER work_0ml(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 299);
}

static uint64_t INLINE_NEVER work_0mm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 300);
}

static uint64_t INLINE_NEVER work_0mn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 301);
}

static uint64_t INLINE_NEVER work_0mo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 302);
}

static uint64_t INLINE_NEVER work_0mp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 303);
}

static uint64_t INLINE_NEVER work_0mq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 304);
}

static uint64_t INLINE_NEVER work_0mr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 305);
}

static uint64_t INLINE_NEVER work_0ms(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 306);
}

static uint64_t INLINE_NEVER work_0mt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 307);
}

static uint64_t INLINE_NEVER work_0mu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 308);
}

static uint64_t INLINE_NEVER work_0mv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 309);
}

static uint64_t INLINE_NEVER work_0mw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 310);
}

static uint64_t INLINE_NEVER work_0mx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 311);
}

static uint64_t INLINE_NEVER work_0na(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 312);
}

static uint64_t INLINE_NEVER work_0nb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 313);
}

static uint64_t INLINE_NEVER work_0nc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 314);
}

static uint64_t INLINE_NEVER work_0nd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 315);
}

static uint64_t INLINE_NEVER work_0ne(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 316);
}

static uint64_t INLINE_NEVER work_0nf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 317);
}

static uint64_t INLINE_NEVER work_0ng(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 318);
}

static uint64_t INLINE_NEVER work_0nh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 319);
}

static uint64_t INLINE_NEVER work_0ni(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 320);
}

static uint64_t INLINE_NEVER work_0nj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 321);
}

static uint64_t INLINE_NEVER work_0nk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 322);
}

static uint64_t INLINE_NEVER work_0nl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 323);
}

static uint64_t INLINE_NEVER work_0nm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 324);
}

static uint64_t INLINE_NEVER work_0nn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 325);
}

static uint64_t INLINE_NEVER work_0no(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 326);
}

static uint64_t INLINE_NEVER work_0np(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 327);
}

static uint64_t INLINE_NEVER work_0nq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 328);
}

static uint64_t INLINE_NEVER work_0nr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 329);
}

static uint64_t INLINE_NEVER work_0ns(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 330);
}

static uint64_t INLINE_NEVER work_0nt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 331);
}

static uint64_t INLINE_NEVER work_0nu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 332);
}

static uint64_t INLINE_NEVER work_0nv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 333);
}

static uint64_t INLINE_NEVER work_0nw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 334);
}

static uint64_t INLINE_NEVER work_0nx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 335);
}

static uint64_t INLINE_NEVER work_0oa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 336);
}

static uint64_t INLINE_NEVER work_0ob(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 337);
}

static uint64_t INLINE_NEVER work_0oc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 338);
}

static uint64_t INLINE_NEVER work_0od(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 339);
}

static uint64_t INLINE_NEVER work_0oe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 340);
}

static uint64_t INLINE_NEVER work_0of(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 341);
}

static uint64_t INLINE_NEVER work_0og(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 342);
}

static uint64_t INLINE_NEVER work_0oh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 343);
}

static uint64_t INLINE_NEVER work_0oi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 344);
}

static uint64_t INLINE_NEVER work_0oj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 345);
}

static uint64_t INLINE_NEVER work_0ok(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 346);
}

static uint64_t INLINE_NEVER work_0ol(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 347);
}

static uint64_t INLINE_NEVER work_0om(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 348);
}

static uint64_t INLINE_NEVER work_0on(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 349);
}

static uint64_t INLINE_NEVER work_0oo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 350);
}

static uint64_t INLINE_NEVER work_0op(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 351);
}

static uint64_t INLINE_NEVER work_0oq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 352);
}

static uint64_t INLINE_NEVER work_0or(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 353);
}

static uint64_t INLINE_NEVER work_0os(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 354);
}

static uint64_t INLINE_NEVER work_0ot(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 355);
}

static uint64_t INLINE_NEVER work_0ou(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 356);
}

static uint64_t INLINE_NEVER work_0ov(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 357);
}

static uint64_t INLINE_NEVER work_0ow(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 358);
}

static uint64_t INLINE_NEVER work_0ox(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 359);
}

static uint64_t INLINE_NEVER work_0pa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 360);
}

static uint64_t INLINE_NEVER work_0pb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 361);
}

static uint64_t INLINE_NEVER work_0pc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 362);
}

static uint64_t INLINE_NEVER work_0pd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 363);
}

static uint64_t INLINE_NEVER work_0pe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 364);
}

static uint64_t INLINE_NEVER work_0pf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 365);
}

static uint64_t INLINE_NEVER work_0pg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 366);
}

static uint64_t INLINE_NEVER work_0ph(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 367);
}

static uint64_t INLINE_NEVER work_0pi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 368);
}

static uint64_t INLINE_NEVER work_0pj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 369);
}

static uint64_t INLINE_NEVER work_0pk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 370);
}

static uint64_t INLINE_NEVER work_0pl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 371);
}

static uint64_t INLINE_NEVER work_0pm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 372);
}

static uint64_t INLINE_NEVER work_0pn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 373);
}

static uint64_t INLINE_NEVER work_0po(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 374);
}

static uint64_t INLINE_NEVER work_0pp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 375);
}

static uint64_t INLINE_NEVER work_0pq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 376);
}

static uint64_t INLINE_NEVER work_0pr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 377);
}

static uint64_t INLINE_NEVER work_0ps(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 378);
}

static uint64_t INLINE_NEVER work_0pt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 379);
}

static uint64_t INLINE_NEVER work_0pu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 380);
}

static uint64_t INLINE_NEVER work_0pv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 381);
}

static uint64_t INLINE_NEVER work_0pw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 382);
}

static uint64_t INLINE_NEVER work_0px(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 383);
}

static uint64_t INLINE_NEVER work_0qa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 384);
}

static uint64_t INLINE_NEVER work_0qb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 385);
}

static uint64_t INLINE_NEVER work_0qc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 386);
}

static uint64_t INLINE_NEVER work_0qd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 387);
}

static uint64_t INLINE_NEVER work_0qe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 388);
}

static uint64_t INLINE_NEVER work_0qf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 389);
}

static uint64_t INLINE_NEVER work_0qg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 390);
}

static uint64_t INLINE_NEVER work_0qh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 391);
}

static uint64_t INLINE_NEVER work_0qi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 392);
}

static uint64_t INLINE_NEVER work_0qj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 393);
}

static uint64_t INLINE_NEVER work_0qk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 394);
}

static uint64_t INLINE_NEVER work_0ql(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 395);
}

static uint64_t INLINE_NEVER work_0qm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 396);
}

static uint64_t INLINE_NEVER work_0qn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 397);
}

static uint64_t INLINE_NEVER work_0qo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 398);
}

static uint64_t INLINE_NEVER work_0qp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 399);
}

static uint64_t INLINE_NEVER work_0qq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 400);
}

static uint64_t INLINE_NEVER work_0qr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 401);
}

static uint64_t INLINE_NEVER work_0qs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 402);
}

static uint64_t INLINE_NEVER work_0qt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 403);
}

static uint64_t INLINE_NEVER work_0qu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 404);
}

static uint64_t INLINE_NEVER work_0qv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 405);
}

static uint64_t INLINE_NEVER work_0qw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 406);
}

static uint64_t INLINE_NEVER work_0qx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 407);
}

static uint64_t INLINE_NEVER work_0ra(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 408);
}

static uint64_t INLINE_NEVER work_0rb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 409);
}

static uint64_t INLINE_NEVER work_0rc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 410);
}

static uint64_t INLINE_NEVER work_0rd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 411);
}

static uint64_t INLINE_NEVER work_0re(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 412);
}

static uint64_t INLINE_NEVER work_0rf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 413);
}

static uint64_t INLINE_NEVER work_0rg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 414);
}

static uint64_t INLINE_NEVER work_0rh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 415);
}

static uint64_t INLINE_NEVER work_0ri(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 416);
}

static uint64_t INLINE_NEVER work_0rj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 417);
}

static uint64_t INLINE_NEVER work_0rk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 418);
}

static uint64_t INLINE_NEVER work_0rl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 419);
}

static uint64_t INLINE_NEVER work_0rm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 420);
}

static uint64_t INLINE_NEVER work_0rn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 421);
}

static uint64_t INLINE_NEVER work_0ro(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 422);
}

static uint64_t INLINE_NEVER work_0rp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 423);
}

static uint64_t INLINE_NEVER work_0rq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 424);
}

static uint64_t INLINE_NEVER work_0rr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 425);
}

static uint64_t INLINE_NEVER work_0rs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 426);
}

static uint64_t INLINE_NEVER work_0rt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 427);
}

static uint64_t INLINE_NEVER work_0ru(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 428);
}

static uint64_t INLINE_NEVER work_0rv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 429);
}

static uint64_t INLINE_NEVER work_0rw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 430);
}

static uint64_t INLINE_NEVER work_0rx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 431);
}

static uint64_t INLINE_NEVER work_0sa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 432);
}

static uint64_t INLINE_NEVER work_0sb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 433);
}

static uint64_t INLINE_NEVER work_0sc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 434);
}

static uint64_t INLINE_NEVER work_0sd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 435);
}

static uint64_t INLINE_NEVER work_0se(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 436);
}

static uint64_t INLINE_NEVER work_0sf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 437);
}

static uint64_t INLINE_NEVER work_0sg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 438);
}

static uint64_t INLINE_NEVER work_0sh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 439);
}

static uint64_t INLINE_NEVER work_0si(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 440);
}

static uint64_t INLINE_NEVER work_0sj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 441);
}

static uint64_t INLINE_NEVER work_0sk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 442);
}

static uint64_t INLINE_NEVER work_0sl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 443);
}

static uint64_t INLINE_NEVER work_0sm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 444);
}

static uint64_t INLINE_NEVER work_0sn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 445);
}

static uint64_t INLINE_NEVER work_0so(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 446);
}

static uint64_t INLINE_NEVER work_0sp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 447);
}

static uint64_t INLINE_NEVER work_0sq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 448);
}

static uint64_t INLINE_NEVER work_0sr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 449);
}

static uint64_t INLINE_NEVER work_0ss(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 450);
}

static uint64_t INLINE_NEVER work_0st(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 451);
}

static uint64_t INLINE_NEVER work_0su(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 452);
}

static uint64_t INLINE_NEVER work_0sv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 453);
}

static uint64_t INLINE_NEVER work_0sw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 454);
}

static uint64_t INLINE_NEVER work_0sx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 455);
}

static uint64_t INLINE_NEVER work_0ta(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 456);
}

static uint64_t INLINE_NEVER work_0tb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 457);
}

static uint64_t INLINE_NEVER work_0tc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 458);
}

static uint64_t INLINE_NEVER work_0td(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 459);
}

static uint64_t INLINE_NEVER work_0te(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 460);
}

static uint64_t INLINE_NEVER work_0tf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 461);
}

static uint64_t INLINE_NEVER work_0tg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 462);
}

static uint64_t INLINE_NEVER work_0th(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 463);
}

static uint64_t INLINE_NEVER work_0ti(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 464);
}

static uint64_t INLINE_NEVER work_0tj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 465);
}

static uint64_t INLINE_NEVER work_0tk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 466);
}

static uint64_t INLINE_NEVER work_0tl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 467);
}

static uint64_t INLINE_NEVER work_0tm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 468);
}

static uint64_t INLINE_NEVER work_0tn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 469);
}

static uint64_t INLINE_NEVER work_0to(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 470);
}

static uint64_t INLINE_NEVER work_0tp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 471);
}

static uint64_t INLINE_NEVER work_0tq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 472);
}

static uint64_t INLINE_NEVER work_0tr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 473);
}

static uint64_t INLINE_NEVER work_0ts(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 474);
}

static uint64_t INLINE_NEVER work_0tt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 475);
}

static uint64_t INLINE_NEVER work_0tu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 476);
}

static uint64_t INLINE_NEVER work_0tv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 477);
}

static uint64_t INLINE_NEVER work_0tw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 478);
}

static uint64_t INLINE_NEVER work_0tx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 479);
}

static uint64_t INLINE_NEVER work_0ua(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 480);
}

static uint64_t INLINE_NEVER work_0ub(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 481);
}

static uint64_t INLINE_NEVER work_0uc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 482);
}

static uint64_t INLINE_NEVER work_0ud(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 483);
}

static uint64_t INLINE_NEVER work_0ue(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 484);
}

static uint64_t INLINE_NEVER work_0uf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 485);
}

static uint64_t INLINE_NEVER work_0ug(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 486);
}

static uint64_t INLINE_NEVER work_0uh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 487);
}

static uint64_t INLINE_NEVER work_0ui(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 488);
}

static uint64_t INLINE_NEVER work_0uj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 489);
}

static uint64_t INLINE_NEVER work_0uk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 490);
}

static uint64_t INLINE_NEVER work_0ul(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 491);
}

static uint64_t INLINE_NEVER work_0um(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 492);
}

static uint64_t INLINE_NEVER work_0un(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 493);
}

static uint64_t INLINE_NEVER work_0uo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 494);
}

static uint64_t INLINE_NEVER work_0up(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 495);
}

static uint64_t INLINE_NEVER work_0uq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 496);
}

static uint64_t INLINE_NEVER work_0ur(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 497);
}

static uint64_t INLINE_NEVER work_0us(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 498);
}

static uint64_t INLINE_NEVER work_0ut(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 499);
}

static uint64_t INLINE_NEVER work_0uu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 500);
}

static uint64_t INLINE_NEVER work_0uv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 501);
}

static uint64_t INLINE_NEVER work_0uw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 502);
}

static uint64_t INLINE_NEVER work_0ux(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 503);
}

static uint64_t INLINE_NEVER work_0va(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 504);
}

static uint64_t INLINE_NEVER work_0vb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 505);
}

static uint64_t INLINE_NEVER work_0vc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 506);
}

static uint64_t INLINE_NEVER work_0vd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 507);
}

static uint64_t INLINE_NEVER work_0ve(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 508);
}

static uint64_t INLINE_NEVER work_0vf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 509);
}

static uint64_t INLINE_NEVER work_0vg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 510);
}

static uint64_t INLINE_NEVER work_0vh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 511);
}

static uint64_t INLINE_NEVER work_0vi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 512);
}

static uint64_t INLINE_NEVER work_0vj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 513);
}

static uint64_t INLINE_NEVER work_0vk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 514);
}

static uint64_t INLINE_NEVER work_0vl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 515);
}

static uint64_t INLINE_NEVER work_0vm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 516);
}

static uint64_t INLINE_NEVER work_0vn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 517);
}

static uint64_t INLINE_NEVER work_0vo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 518);
}

static uint64_t INLINE_NEVER work_0vp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 519);
}

static uint64_t INLINE_NEVER work_0vq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 520);
}

static uint64_t INLINE_NEVER work_0vr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 521);
}

static uint64_t INLINE_NEVER work_0vs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 522);
}

static uint64_t INLINE_NEVER work_0vt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 523);
}

static uint64_t INLINE_NEVER work_0vu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 524);
}

static uint64_t INLINE_NEVER work_0vv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 525);
}

static uint64_t INLINE_NEVER work_0vw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 526);
}

static uint64_t INLINE_NEVER work_0vx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 527);
}

static uint64_t INLINE_NEVER work_0wa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 528);
}

static uint64_t INLINE_NEVER work_0wb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 529);
}

static uint64_t INLINE_NEVER work_0wc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 530);
}

static uint64_t INLINE_NEVER work_0wd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 531);
}

static uint64_t INLINE_NEVER work_0we(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 532);
}

static uint64_t INLINE_NEVER work_0wf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 533);
}

static uint64_t INLINE_NEVER work_0wg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 534);
}

static uint64_t INLINE_NEVER work_0wh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 535);
}

static uint64_t INLINE_NEVER work_0wi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 536);
}

static uint64_t INLINE_NEVER work_0wj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 537);
}

static uint64_t INLINE_NEVER work_0wk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 538);
}

static uint64_t INLINE_NEVER work_0wl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 539);
}

static uint64_t INLINE_NEVER work_0wm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 540);
}

static uint64_t INLINE_NEVER work_0wn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 541);
}

static uint64_t INLINE_NEVER work_0wo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 542);
}

static uint64_t INLINE_NEVER work_0wp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 543);
}

static uint64_t INLINE_NEVER work_0wq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 544);
}

static uint64_t INLINE_NEVER work_0wr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 545);
}

static uint64_t INLINE_NEVER work_0ws(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 546);
}

static uint64_t INLINE_NEVER work_0wt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 547);
}

static uint64_t INLINE_NEVER work_0wu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 548);
}

static uint64_t INLINE_NEVER work_0wv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 549);
}

static uint64_t INLINE_NEVER work_0ww(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 550);
}

static uint64_t INLINE_NEVER work_0wx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 551);
}

static uint64_t INLINE_NEVER work_0xa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 552);
}

static uint64_t INLINE_NEVER work_0xb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 553);
}

static uint64_t INLINE_NEVER work_0xc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 554);
}

static uint64_t INLINE_NEVER work_0xd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 555);
}

static uint64_t INLINE_NEVER work_0xe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 556);
}

static uint64_t INLINE_NEVER work_0xf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 557);
}

static uint64_t INLINE_NEVER work_0xg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 558);
}

static uint64_t INLINE_NEVER work_0xh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 559);
}

static uint64_t INLINE_NEVER work_0xi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 560);
}

static uint64_t INLINE_NEVER work_0xj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 561);
}

static uint64_t INLINE_NEVER work_0xk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 562);
}

static uint64_t INLINE_NEVER work_0xl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 563);
}

static uint64_t INLINE_NEVER work_0xm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 564);
}

static uint64_t INLINE_NEVER work_0xn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 565);
}

static uint64_t INLINE_NEVER work_0xo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 566);
}

static uint64_t INLINE_NEVER work_0xp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 567);
}

static uint64_t INLINE_NEVER work_0xq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 568);
}

static uint64_t INLINE_NEVER work_0xr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 569);
}

static uint64_t INLINE_NEVER work_0xs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 570);
}

static uint64_t INLINE_NEVER work_0xt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 571);
}

static uint64_t INLINE_NEVER work_0xu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 572);
}

static uint64_t INLINE_NEVER work_0xv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 573);
}

static uint64_t INLINE_NEVER work_0xw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 574);
}

static uint64_t INLINE_NEVER work_0xx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_0(a, b, c, 575);
}

static work_0_fn_t work_0[] = {
	work_0aa, work_0ab, work_0ac, work_0ad, work_0ae, work_0af, work_0ag, work_0ah,
	work_0ai, work_0aj, work_0ak, work_0al, work_0am, work_0an, work_0ao, work_0ap,
	work_0aq, work_0ar, work_0as, work_0at, work_0au, work_0av, work_0aw, work_0ax,
	work_0ba, work_0bb, work_0bc, work_0bd, work_0be, work_0bf, work_0bg, work_0bh,
	work_0bi, work_0bj, work_0bk, work_0bl, work_0bm, work_0bn, work_0bo, work_0bp,
	work_0bq, work_0br, work_0bs, work_0bt, work_0bu, work_0bv, work_0bw, work_0bx,
	work_0ca, work_0cb, work_0cc, work_0cd, work_0ce, work_0cf, work_0cg, work_0ch,
	work_0ci, work_0cj, work_0ck, work_0cl, work_0cm, work_0cn, work_0co, work_0cp,
	work_0cq, work_0cr, work_0cs, work_0ct, work_0cu, work_0cv, work_0cw, work_0cx,
	work_0da, work_0db, work_0dc, work_0dd, work_0de, work_0df, work_0dg, work_0dh,
	work_0di, work_0dj, work_0dk, work_0dl, work_0dm, work_0dn, work_0do, work_0dp,
	work_0dq, work_0dr, work_0ds, work_0dt, work_0du, work_0dv, work_0dw, work_0dx,
	work_0ea, work_0eb, work_0ec, work_0ed, work_0ee, work_0ef, work_0eg, work_0eh,
	work_0ei, work_0ej, work_0ek, work_0el, work_0em, work_0en, work_0eo, work_0ep,
	work_0eq, work_0er, work_0es, work_0et, work_0eu, work_0ev, work_0ew, work_0ex,
	work_0fa, work_0fb, work_0fc, work_0fd, work_0fe, work_0ff, work_0fg, work_0fh,
	work_0fi, work_0fj, work_0fk, work_0fl, work_0fm, work_0fn, work_0fo, work_0fp,
	work_0fq, work_0fr, work_0fs, work_0ft, work_0fu, work_0fv, work_0fw, work_0fx,
	work_0ga, work_0gb, work_0gc, work_0gd, work_0ge, work_0gf, work_0gg, work_0gh,
	work_0gi, work_0gj, work_0gk, work_0gl, work_0gm, work_0gn, work_0go, work_0gp,
	work_0gq, work_0gr, work_0gs, work_0gt, work_0gu, work_0gv, work_0gw, work_0gx,
	work_0ha, work_0hb, work_0hc, work_0hd, work_0he, work_0hf, work_0hg, work_0hh,
	work_0hi, work_0hj, work_0hk, work_0hl, work_0hm, work_0hn, work_0ho, work_0hp,
	work_0hq, work_0hr, work_0hs, work_0ht, work_0hu, work_0hv, work_0hw, work_0hx,
	work_0ia, work_0ib, work_0ic, work_0id, work_0ie, work_0if, work_0ig, work_0ih,
	work_0ii, work_0ij, work_0ik, work_0il, work_0im, work_0in, work_0io, work_0ip,
	work_0iq, work_0ir, work_0is, work_0it, work_0iu, work_0iv, work_0iw, work_0ix,
	work_0ja, work_0jb, work_0jc, work_0jd, work_0je, work_0jf, work_0jg, work_0jh,
	work_0ji, work_0jj, work_0jk, work_0jl, work_0jm, work_0jn, work_0jo, work_0jp,
	work_0jq, work_0jr, work_0js, work_0jt, work_0ju, work_0jv, work_0jw, work_0jx,
	work_0ka, work_0kb, work_0kc, work_0kd, work_0ke, work_0kf, work_0kg, work_0kh,
	work_0ki, work_0kj, work_0kk, work_0kl, work_0km, work_0kn, work_0ko, work_0kp,
	work_0kq, work_0kr, work_0ks, work_0kt, work_0ku, work_0kv, work_0kw, work_0kx,
	work_0la, work_0lb, work_0lc, work_0ld, work_0le, work_0lf, work_0lg, work_0lh,
	work_0li, work_0lj, work_0lk, work_0ll, work_0lm, work_0ln, work_0lo, work_0lp,
	work_0lq, work_0lr, work_0ls, work_0lt, work_0lu, work_0lv, work_0lw, work_0lx,
	work_0ma, work_0mb, work_0mc, work_0md, work_0me, work_0mf, work_0mg, work_0mh,
	work_0mi, work_0mj, work_0mk, work_0ml, work_0mm, work_0mn, work_0mo, work_0mp,
	work_0mq, work_0mr, work_0ms, work_0mt, work_0mu, work_0mv, work_0mw, work_0mx,
	work_0na, work_0nb, work_0nc, work_0nd, work_0ne, work_0nf, work_0ng, work_0nh,
	work_0ni, work_0nj, work_0nk, work_0nl, work_0nm, work_0nn, work_0no, work_0np,
	work_0nq, work_0nr, work_0ns, work_0nt, work_0nu, work_0nv, work_0nw, work_0nx,
	work_0oa, work_0ob, work_0oc, work_0od, work_0oe, work_0of, work_0og, work_0oh,
	work_0oi, work_0oj, work_0ok, work_0ol, work_0om, work_0on, work_0oo, work_0op,
	work_0oq, work_0or, work_0os, work_0ot, work_0ou, work_0ov, work_0ow, work_0ox,
	work_0pa, work_0pb, work_0pc, work_0pd, work_0pe, work_0pf, work_0pg, work_0ph,
	work_0pi, work_0pj, work_0pk, work_0pl, work_0pm, work_0pn, work_0po, work_0pp,
	work_0pq, work_0pr, work_0ps, work_0pt, work_0pu, work_0pv, work_0pw, work_0px,
	work_0qa, work_0qb, work_0qc, work_0qd, work_0qe, work_0qf, work_0qg, work_0qh,
	work_0qi, work_0qj, work_0qk, work_0ql, work_0qm, work_0qn, work_0qo, work_0qp,
	work_0qq, work_0qr, work_0qs, work_0qt, work_0qu, work_0qv, work_0qw, work_0qx,
	work_0ra, work_0rb, work_0rc, work_0rd, work_0re, work_0rf, work_0rg, work_0rh,
	work_0ri, work_0rj, work_0rk, work_0rl, work_0rm, work_0rn, work_0ro, work_0rp,
	work_0rq, work_0rr, work_0rs, work_0rt, work_0ru, work_0rv, work_0rw, work_0rx,
	work_0sa, work_0sb, work_0sc, work_0sd, work_0se, work_0sf, work_0sg, work_0sh,
	work_0si, work_0sj, work_0sk, work_0sl, work_0sm, work_0sn, work_0so, work_0sp,
	work_0sq, work_0sr, work_0ss, work_0st, work_0su, work_0sv, work_0sw, work_0sx,
	work_0ta, work_0tb, work_0tc, work_0td, work_0te, work_0tf, work_0tg, work_0th,
	work_0ti, work_0tj, work_0tk, work_0tl, work_0tm, work_0tn, work_0to, work_0tp,
	work_0tq, work_0tr, work_0ts, work_0tt, work_0tu, work_0tv, work_0tw, work_0tx,
	work_0ua, work_0ub, work_0uc, work_0ud, work_0ue, work_0uf, work_0ug, work_0uh,
	work_0ui, work_0uj, work_0uk, work_0ul, work_0um, work_0un, work_0uo, work_0up,
	work_0uq, work_0ur, work_0us, work_0ut, work_0uu, work_0uv, work_0uw, work_0ux,
	work_0va, work_0vb, work_0vc, work_0vd, work_0ve, work_0vf, work_0vg, work_0vh,
	work_0vi, work_0vj, work_0vk, work_0vl, work_0vm, work_0vn, work_0vo, work_0vp,
	work_0vq, work_0vr, work_0vs, work_0vt, work_0vu, work_0vv, work_0vw, work_0vx,
	work_0wa, work_0wb, work_0wc, work_0wd, work_0we, work_0wf, work_0wg, work_0wh,
	work_0wi, work_0wj, work_0wk, work_0wl, work_0wm, work_0wn, work_0wo, work_0wp,
	work_0wq, work_0wr, work_0ws, work_0wt, work_0wu, work_0wv, work_0ww, work_0wx,
	work_0xa, work_0xb, work_0xc, work_0xd, work_0xe, work_0xf, work_0xg, work_0xh,
	work_0xi, work_0xj, work_0xk, work_0xl, work_0xm, work_0xn, work_0xo, work_0xp,
	work_0xq, work_0xr, work_0xs, work_0xt, work_0xu, work_0xv, work_0xw, work_0xx
};

static uint16_t work_0_rnd[] = {
	205,  15, 413, 490, 455, 102,  85, 176, 310, 393,  54, 371, 561, 540, 441, 292,
	424, 235,  24,  36, 457, 378,  97,  86, 519, 366,  91, 377, 162,  40, 394, 152,
	416, 149, 489, 343,  53, 285, 368, 159, 303, 307, 434,  28, 471, 513, 154,  17,
	197, 294, 503, 192, 346, 325, 298, 390,  83,  29, 299, 112, 342, 329, 100, 481,
	352, 195, 458, 163, 389, 553, 291, 522, 293, 446, 234, 218, 255, 569, 439, 499,
	 26, 334, 480,  45, 507, 172, 558,  79,   6, 554, 129, 103, 115, 442, 516, 411,
	478, 360, 228,  39, 500, 306, 449, 365, 147, 219, 121, 111, 465,  78, 335, 157,
	167, 491, 492, 178, 220, 508, 464, 180, 556, 132, 324, 207, 251, 354, 524, 126,
	493,  25,  93, 182, 231, 110,  80, 412, 142, 184,  57,  55, 535,  75, 266,  21,
	244, 555,  18, 336,   5, 421, 484,  69,  92,  14, 419, 400, 373, 546, 151, 382,
	128, 463, 559,  76,  49, 477, 572, 273, 548, 217, 452, 485, 246, 407, 575, 453,
	391, 253,  62, 113, 279, 429, 171, 156, 430, 134, 105,  77, 222, 185,  82, 495,
	260, 165, 257, 268, 331,   1, 229, 109, 402,  12, 386, 277,  37, 120, 544, 539,
	408, 564, 316, 227,  89,  73, 312, 461, 405, 370, 512, 379, 380, 137,  66,  30,
	 11, 232, 339, 288, 179, 330, 514, 211, 403, 467, 224, 381, 466, 502, 209, 551,
	 51,  90, 214, 196, 262, 309, 357, 341, 462, 101, 534, 305, 315, 319,  65, 107,
	150,  94, 200, 538, 193,  61, 199, 275,  81, 240, 388, 238, 174, 515, 287,  88,
	417, 116, 323,  23,  52, 143,  70, 427, 136, 560, 187, 233, 347, 337, 249, 568,
	226,  33,  19, 117, 139, 571,  50, 175,   2, 282, 280, 130, 270,  32, 444, 201,
	 59, 135, 523, 267,   8,  44, 438, 494, 333, 340, 206, 573, 436, 367,   9, 263,
	161, 545, 374, 537,  34, 383, 448, 362, 557, 164, 529, 124, 264, 459,  10, 265,
	525, 332, 170, 138, 186, 511, 223, 119, 369, 356, 304,  48,  72, 527, 542, 283,
	140, 401, 274, 425,   4, 531, 562, 566, 552, 422, 450, 123, 435, 517, 259,  56,
	190, 144, 296, 204, 322, 483, 487, 520, 518,   7, 395,  99, 225, 472, 326, 355,
	384, 440, 281, 479,  20, 208, 363, 397, 526, 122, 278,  35, 160, 532,  67, 188,
	301, 125, 387, 290, 375,  22, 565, 230, 191, 317, 521, 451, 414, 418,  68, 454,
	221,  41, 189, 153, 114, 261, 530, 358, 308, 297, 237,  71, 547, 372, 158, 198,
	327,  63, 574, 486, 242, 536, 353, 567, 361, 445, 155, 239, 276, 256,  13, 468,
	437, 470, 420, 533, 410,  46, 254, 177, 473, 133, 456, 169, 166, 498, 321, 415,
	320, 286, 258, 194,  58, 318, 447, 248, 313, 183, 300, 431, 469, 423, 528, 272,
	148, 504, 509, 563, 359, 433, 404, 243,  96, 364, 570, 426,  27, 203,   3, 311,
	131, 396, 210, 475,  43, 349, 399, 181, 118, 236, 104, 269, 145, 432, 344, 127,
	328, 398, 488, 289, 146, 348, 245, 474, 252, 351,  84, 549,  60, 212, 202, 385,
	 38, 510, 247,  64, 392, 506, 108, 482, 550,  42, 106, 215, 271,  95, 543, 295,
	173, 338, 406, 428, 284, 350, 345, 541,  87, 250, 497, 443, 496, 241, 376, 168,
	409, 505, 476,  74, 302,  47, 460, 314,   0,  98,  16,  31, 213, 216, 501, 141
};

static uint64_t INLINE_NEVER work_1aa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 0);
}

static uint64_t INLINE_NEVER work_1ab(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 1);
}

static uint64_t INLINE_NEVER work_1ac(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 2);
}

static uint64_t INLINE_NEVER work_1ad(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 3);
}

static uint64_t INLINE_NEVER work_1ae(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 4);
}

static uint64_t INLINE_NEVER work_1af(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 5);
}

static uint64_t INLINE_NEVER work_1ag(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 6);
}

static uint64_t INLINE_NEVER work_1ah(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 7);
}

static uint64_t INLINE_NEVER work_1ai(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 8);
}

static uint64_t INLINE_NEVER work_1aj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 9);
}

static uint64_t INLINE_NEVER work_1ak(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 10);
}

static uint64_t INLINE_NEVER work_1al(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 11);
}

static uint64_t INLINE_NEVER work_1am(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 12);
}

static uint64_t INLINE_NEVER work_1an(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 13);
}

static uint64_t INLINE_NEVER work_1ao(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 14);
}

static uint64_t INLINE_NEVER work_1ap(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 15);
}

static uint64_t INLINE_NEVER work_1aq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 16);
}

static uint64_t INLINE_NEVER work_1ar(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 17);
}

static uint64_t INLINE_NEVER work_1as(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 18);
}

static uint64_t INLINE_NEVER work_1at(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 19);
}

static uint64_t INLINE_NEVER work_1au(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 20);
}

static uint64_t INLINE_NEVER work_1av(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 21);
}

static uint64_t INLINE_NEVER work_1aw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 22);
}

static uint64_t INLINE_NEVER work_1ax(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 23);
}

static uint64_t INLINE_NEVER work_1ba(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 24);
}

static uint64_t INLINE_NEVER work_1bb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 25);
}

static uint64_t INLINE_NEVER work_1bc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 26);
}

static uint64_t INLINE_NEVER work_1bd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 27);
}

static uint64_t INLINE_NEVER work_1be(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 28);
}

static uint64_t INLINE_NEVER work_1bf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 29);
}

static uint64_t INLINE_NEVER work_1bg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 30);
}

static uint64_t INLINE_NEVER work_1bh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 31);
}

static uint64_t INLINE_NEVER work_1bi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 32);
}

static uint64_t INLINE_NEVER work_1bj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 33);
}

static uint64_t INLINE_NEVER work_1bk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 34);
}

static uint64_t INLINE_NEVER work_1bl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 35);
}

static uint64_t INLINE_NEVER work_1bm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 36);
}

static uint64_t INLINE_NEVER work_1bn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 37);
}

static uint64_t INLINE_NEVER work_1bo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 38);
}

static uint64_t INLINE_NEVER work_1bp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 39);
}

static uint64_t INLINE_NEVER work_1bq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 40);
}

static uint64_t INLINE_NEVER work_1br(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 41);
}

static uint64_t INLINE_NEVER work_1bs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 42);
}

static uint64_t INLINE_NEVER work_1bt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 43);
}

static uint64_t INLINE_NEVER work_1bu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 44);
}

static uint64_t INLINE_NEVER work_1bv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 45);
}

static uint64_t INLINE_NEVER work_1bw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 46);
}

static uint64_t INLINE_NEVER work_1bx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 47);
}

static uint64_t INLINE_NEVER work_1ca(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 48);
}

static uint64_t INLINE_NEVER work_1cb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 49);
}

static uint64_t INLINE_NEVER work_1cc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 50);
}

static uint64_t INLINE_NEVER work_1cd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 51);
}

static uint64_t INLINE_NEVER work_1ce(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 52);
}

static uint64_t INLINE_NEVER work_1cf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 53);
}

static uint64_t INLINE_NEVER work_1cg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 54);
}

static uint64_t INLINE_NEVER work_1ch(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 55);
}

static uint64_t INLINE_NEVER work_1ci(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 56);
}

static uint64_t INLINE_NEVER work_1cj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 57);
}

static uint64_t INLINE_NEVER work_1ck(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 58);
}

static uint64_t INLINE_NEVER work_1cl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 59);
}

static uint64_t INLINE_NEVER work_1cm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 60);
}

static uint64_t INLINE_NEVER work_1cn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 61);
}

static uint64_t INLINE_NEVER work_1co(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 62);
}

static uint64_t INLINE_NEVER work_1cp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 63);
}

static uint64_t INLINE_NEVER work_1cq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 64);
}

static uint64_t INLINE_NEVER work_1cr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 65);
}

static uint64_t INLINE_NEVER work_1cs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 66);
}

static uint64_t INLINE_NEVER work_1ct(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 67);
}

static uint64_t INLINE_NEVER work_1cu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 68);
}

static uint64_t INLINE_NEVER work_1cv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 69);
}

static uint64_t INLINE_NEVER work_1cw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 70);
}

static uint64_t INLINE_NEVER work_1cx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 71);
}

static uint64_t INLINE_NEVER work_1da(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 72);
}

static uint64_t INLINE_NEVER work_1db(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 73);
}

static uint64_t INLINE_NEVER work_1dc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 74);
}

static uint64_t INLINE_NEVER work_1dd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 75);
}

static uint64_t INLINE_NEVER work_1de(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 76);
}

static uint64_t INLINE_NEVER work_1df(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 77);
}

static uint64_t INLINE_NEVER work_1dg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 78);
}

static uint64_t INLINE_NEVER work_1dh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 79);
}

static uint64_t INLINE_NEVER work_1di(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 80);
}

static uint64_t INLINE_NEVER work_1dj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 81);
}

static uint64_t INLINE_NEVER work_1dk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 82);
}

static uint64_t INLINE_NEVER work_1dl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 83);
}

static uint64_t INLINE_NEVER work_1dm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 84);
}

static uint64_t INLINE_NEVER work_1dn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 85);
}

static uint64_t INLINE_NEVER work_1do(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 86);
}

static uint64_t INLINE_NEVER work_1dp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 87);
}

static uint64_t INLINE_NEVER work_1dq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 88);
}

static uint64_t INLINE_NEVER work_1dr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 89);
}

static uint64_t INLINE_NEVER work_1ds(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 90);
}

static uint64_t INLINE_NEVER work_1dt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 91);
}

static uint64_t INLINE_NEVER work_1du(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 92);
}

static uint64_t INLINE_NEVER work_1dv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 93);
}

static uint64_t INLINE_NEVER work_1dw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 94);
}

static uint64_t INLINE_NEVER work_1dx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 95);
}

static uint64_t INLINE_NEVER work_1ea(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 96);
}

static uint64_t INLINE_NEVER work_1eb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 97);
}

static uint64_t INLINE_NEVER work_1ec(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 98);
}

static uint64_t INLINE_NEVER work_1ed(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 99);
}

static uint64_t INLINE_NEVER work_1ee(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 100);
}

static uint64_t INLINE_NEVER work_1ef(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 101);
}

static uint64_t INLINE_NEVER work_1eg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 102);
}

static uint64_t INLINE_NEVER work_1eh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 103);
}

static uint64_t INLINE_NEVER work_1ei(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 104);
}

static uint64_t INLINE_NEVER work_1ej(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 105);
}

static uint64_t INLINE_NEVER work_1ek(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 106);
}

static uint64_t INLINE_NEVER work_1el(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 107);
}

static uint64_t INLINE_NEVER work_1em(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 108);
}

static uint64_t INLINE_NEVER work_1en(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 109);
}

static uint64_t INLINE_NEVER work_1eo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 110);
}

static uint64_t INLINE_NEVER work_1ep(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 111);
}

static uint64_t INLINE_NEVER work_1eq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 112);
}

static uint64_t INLINE_NEVER work_1er(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 113);
}

static uint64_t INLINE_NEVER work_1es(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 114);
}

static uint64_t INLINE_NEVER work_1et(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 115);
}

static uint64_t INLINE_NEVER work_1eu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 116);
}

static uint64_t INLINE_NEVER work_1ev(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 117);
}

static uint64_t INLINE_NEVER work_1ew(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 118);
}

static uint64_t INLINE_NEVER work_1ex(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 119);
}

static uint64_t INLINE_NEVER work_1fa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 120);
}

static uint64_t INLINE_NEVER work_1fb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 121);
}

static uint64_t INLINE_NEVER work_1fc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 122);
}

static uint64_t INLINE_NEVER work_1fd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 123);
}

static uint64_t INLINE_NEVER work_1fe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 124);
}

static uint64_t INLINE_NEVER work_1ff(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 125);
}

static uint64_t INLINE_NEVER work_1fg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 126);
}

static uint64_t INLINE_NEVER work_1fh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 127);
}

static uint64_t INLINE_NEVER work_1fi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 128);
}

static uint64_t INLINE_NEVER work_1fj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 129);
}

static uint64_t INLINE_NEVER work_1fk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 130);
}

static uint64_t INLINE_NEVER work_1fl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 131);
}

static uint64_t INLINE_NEVER work_1fm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 132);
}

static uint64_t INLINE_NEVER work_1fn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 133);
}

static uint64_t INLINE_NEVER work_1fo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 134);
}

static uint64_t INLINE_NEVER work_1fp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 135);
}

static uint64_t INLINE_NEVER work_1fq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 136);
}

static uint64_t INLINE_NEVER work_1fr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 137);
}

static uint64_t INLINE_NEVER work_1fs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 138);
}

static uint64_t INLINE_NEVER work_1ft(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 139);
}

static uint64_t INLINE_NEVER work_1fu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 140);
}

static uint64_t INLINE_NEVER work_1fv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 141);
}

static uint64_t INLINE_NEVER work_1fw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 142);
}

static uint64_t INLINE_NEVER work_1fx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 143);
}

static uint64_t INLINE_NEVER work_1ga(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 144);
}

static uint64_t INLINE_NEVER work_1gb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 145);
}

static uint64_t INLINE_NEVER work_1gc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 146);
}

static uint64_t INLINE_NEVER work_1gd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 147);
}

static uint64_t INLINE_NEVER work_1ge(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 148);
}

static uint64_t INLINE_NEVER work_1gf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 149);
}

static uint64_t INLINE_NEVER work_1gg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 150);
}

static uint64_t INLINE_NEVER work_1gh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 151);
}

static uint64_t INLINE_NEVER work_1gi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 152);
}

static uint64_t INLINE_NEVER work_1gj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 153);
}

static uint64_t INLINE_NEVER work_1gk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 154);
}

static uint64_t INLINE_NEVER work_1gl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 155);
}

static uint64_t INLINE_NEVER work_1gm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 156);
}

static uint64_t INLINE_NEVER work_1gn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 157);
}

static uint64_t INLINE_NEVER work_1go(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 158);
}

static uint64_t INLINE_NEVER work_1gp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 159);
}

static uint64_t INLINE_NEVER work_1gq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 160);
}

static uint64_t INLINE_NEVER work_1gr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 161);
}

static uint64_t INLINE_NEVER work_1gs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 162);
}

static uint64_t INLINE_NEVER work_1gt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 163);
}

static uint64_t INLINE_NEVER work_1gu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 164);
}

static uint64_t INLINE_NEVER work_1gv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 165);
}

static uint64_t INLINE_NEVER work_1gw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 166);
}

static uint64_t INLINE_NEVER work_1gx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 167);
}

static uint64_t INLINE_NEVER work_1ha(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 168);
}

static uint64_t INLINE_NEVER work_1hb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 169);
}

static uint64_t INLINE_NEVER work_1hc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 170);
}

static uint64_t INLINE_NEVER work_1hd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 171);
}

static uint64_t INLINE_NEVER work_1he(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 172);
}

static uint64_t INLINE_NEVER work_1hf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 173);
}

static uint64_t INLINE_NEVER work_1hg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 174);
}

static uint64_t INLINE_NEVER work_1hh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 175);
}

static uint64_t INLINE_NEVER work_1hi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 176);
}

static uint64_t INLINE_NEVER work_1hj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 177);
}

static uint64_t INLINE_NEVER work_1hk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 178);
}

static uint64_t INLINE_NEVER work_1hl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 179);
}

static uint64_t INLINE_NEVER work_1hm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 180);
}

static uint64_t INLINE_NEVER work_1hn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 181);
}

static uint64_t INLINE_NEVER work_1ho(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 182);
}

static uint64_t INLINE_NEVER work_1hp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 183);
}

static uint64_t INLINE_NEVER work_1hq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 184);
}

static uint64_t INLINE_NEVER work_1hr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 185);
}

static uint64_t INLINE_NEVER work_1hs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 186);
}

static uint64_t INLINE_NEVER work_1ht(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 187);
}

static uint64_t INLINE_NEVER work_1hu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 188);
}

static uint64_t INLINE_NEVER work_1hv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 189);
}

static uint64_t INLINE_NEVER work_1hw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 190);
}

static uint64_t INLINE_NEVER work_1hx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 191);
}

static uint64_t INLINE_NEVER work_1ia(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 192);
}

static uint64_t INLINE_NEVER work_1ib(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 193);
}

static uint64_t INLINE_NEVER work_1ic(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 194);
}

static uint64_t INLINE_NEVER work_1id(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 195);
}

static uint64_t INLINE_NEVER work_1ie(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 196);
}

static uint64_t INLINE_NEVER work_1if(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 197);
}

static uint64_t INLINE_NEVER work_1ig(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 198);
}

static uint64_t INLINE_NEVER work_1ih(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 199);
}

static uint64_t INLINE_NEVER work_1ii(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 200);
}

static uint64_t INLINE_NEVER work_1ij(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 201);
}

static uint64_t INLINE_NEVER work_1ik(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 202);
}

static uint64_t INLINE_NEVER work_1il(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 203);
}

static uint64_t INLINE_NEVER work_1im(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 204);
}

static uint64_t INLINE_NEVER work_1in(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 205);
}

static uint64_t INLINE_NEVER work_1io(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 206);
}

static uint64_t INLINE_NEVER work_1ip(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 207);
}

static uint64_t INLINE_NEVER work_1iq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 208);
}

static uint64_t INLINE_NEVER work_1ir(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 209);
}

static uint64_t INLINE_NEVER work_1is(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 210);
}

static uint64_t INLINE_NEVER work_1it(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 211);
}

static uint64_t INLINE_NEVER work_1iu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 212);
}

static uint64_t INLINE_NEVER work_1iv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 213);
}

static uint64_t INLINE_NEVER work_1iw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 214);
}

static uint64_t INLINE_NEVER work_1ix(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 215);
}

static uint64_t INLINE_NEVER work_1ja(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 216);
}

static uint64_t INLINE_NEVER work_1jb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 217);
}

static uint64_t INLINE_NEVER work_1jc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 218);
}

static uint64_t INLINE_NEVER work_1jd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 219);
}

static uint64_t INLINE_NEVER work_1je(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 220);
}

static uint64_t INLINE_NEVER work_1jf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 221);
}

static uint64_t INLINE_NEVER work_1jg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 222);
}

static uint64_t INLINE_NEVER work_1jh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 223);
}

static uint64_t INLINE_NEVER work_1ji(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 224);
}

static uint64_t INLINE_NEVER work_1jj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 225);
}

static uint64_t INLINE_NEVER work_1jk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 226);
}

static uint64_t INLINE_NEVER work_1jl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 227);
}

static uint64_t INLINE_NEVER work_1jm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 228);
}

static uint64_t INLINE_NEVER work_1jn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 229);
}

static uint64_t INLINE_NEVER work_1jo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 230);
}

static uint64_t INLINE_NEVER work_1jp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 231);
}

static uint64_t INLINE_NEVER work_1jq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 232);
}

static uint64_t INLINE_NEVER work_1jr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 233);
}

static uint64_t INLINE_NEVER work_1js(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 234);
}

static uint64_t INLINE_NEVER work_1jt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 235);
}

static uint64_t INLINE_NEVER work_1ju(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 236);
}

static uint64_t INLINE_NEVER work_1jv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 237);
}

static uint64_t INLINE_NEVER work_1jw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 238);
}

static uint64_t INLINE_NEVER work_1jx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 239);
}

static uint64_t INLINE_NEVER work_1ka(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 240);
}

static uint64_t INLINE_NEVER work_1kb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 241);
}

static uint64_t INLINE_NEVER work_1kc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 242);
}

static uint64_t INLINE_NEVER work_1kd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 243);
}

static uint64_t INLINE_NEVER work_1ke(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 244);
}

static uint64_t INLINE_NEVER work_1kf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 245);
}

static uint64_t INLINE_NEVER work_1kg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 246);
}

static uint64_t INLINE_NEVER work_1kh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 247);
}

static uint64_t INLINE_NEVER work_1ki(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 248);
}

static uint64_t INLINE_NEVER work_1kj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 249);
}

static uint64_t INLINE_NEVER work_1kk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 250);
}

static uint64_t INLINE_NEVER work_1kl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 251);
}

static uint64_t INLINE_NEVER work_1km(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 252);
}

static uint64_t INLINE_NEVER work_1kn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 253);
}

static uint64_t INLINE_NEVER work_1ko(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 254);
}

static uint64_t INLINE_NEVER work_1kp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 255);
}

static uint64_t INLINE_NEVER work_1kq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 256);
}

static uint64_t INLINE_NEVER work_1kr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 257);
}

static uint64_t INLINE_NEVER work_1ks(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 258);
}

static uint64_t INLINE_NEVER work_1kt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 259);
}

static uint64_t INLINE_NEVER work_1ku(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 260);
}

static uint64_t INLINE_NEVER work_1kv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 261);
}

static uint64_t INLINE_NEVER work_1kw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 262);
}

static uint64_t INLINE_NEVER work_1kx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 263);
}

static uint64_t INLINE_NEVER work_1la(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 264);
}

static uint64_t INLINE_NEVER work_1lb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 265);
}

static uint64_t INLINE_NEVER work_1lc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 266);
}

static uint64_t INLINE_NEVER work_1ld(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 267);
}

static uint64_t INLINE_NEVER work_1le(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 268);
}

static uint64_t INLINE_NEVER work_1lf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 269);
}

static uint64_t INLINE_NEVER work_1lg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 270);
}

static uint64_t INLINE_NEVER work_1lh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 271);
}

static uint64_t INLINE_NEVER work_1li(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 272);
}

static uint64_t INLINE_NEVER work_1lj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 273);
}

static uint64_t INLINE_NEVER work_1lk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 274);
}

static uint64_t INLINE_NEVER work_1ll(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 275);
}

static uint64_t INLINE_NEVER work_1lm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 276);
}

static uint64_t INLINE_NEVER work_1ln(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 277);
}

static uint64_t INLINE_NEVER work_1lo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 278);
}

static uint64_t INLINE_NEVER work_1lp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 279);
}

static uint64_t INLINE_NEVER work_1lq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 280);
}

static uint64_t INLINE_NEVER work_1lr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 281);
}

static uint64_t INLINE_NEVER work_1ls(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 282);
}

static uint64_t INLINE_NEVER work_1lt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 283);
}

static uint64_t INLINE_NEVER work_1lu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 284);
}

static uint64_t INLINE_NEVER work_1lv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 285);
}

static uint64_t INLINE_NEVER work_1lw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 286);
}

static uint64_t INLINE_NEVER work_1lx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 287);
}

static uint64_t INLINE_NEVER work_1ma(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 288);
}

static uint64_t INLINE_NEVER work_1mb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 289);
}

static uint64_t INLINE_NEVER work_1mc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 290);
}

static uint64_t INLINE_NEVER work_1md(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 291);
}

static uint64_t INLINE_NEVER work_1me(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 292);
}

static uint64_t INLINE_NEVER work_1mf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 293);
}

static uint64_t INLINE_NEVER work_1mg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 294);
}

static uint64_t INLINE_NEVER work_1mh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 295);
}

static uint64_t INLINE_NEVER work_1mi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 296);
}

static uint64_t INLINE_NEVER work_1mj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 297);
}

static uint64_t INLINE_NEVER work_1mk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 298);
}

static uint64_t INLINE_NEVER work_1ml(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 299);
}

static uint64_t INLINE_NEVER work_1mm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 300);
}

static uint64_t INLINE_NEVER work_1mn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 301);
}

static uint64_t INLINE_NEVER work_1mo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 302);
}

static uint64_t INLINE_NEVER work_1mp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 303);
}

static uint64_t INLINE_NEVER work_1mq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 304);
}

static uint64_t INLINE_NEVER work_1mr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 305);
}

static uint64_t INLINE_NEVER work_1ms(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 306);
}

static uint64_t INLINE_NEVER work_1mt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 307);
}

static uint64_t INLINE_NEVER work_1mu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 308);
}

static uint64_t INLINE_NEVER work_1mv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 309);
}

static uint64_t INLINE_NEVER work_1mw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 310);
}

static uint64_t INLINE_NEVER work_1mx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 311);
}

static uint64_t INLINE_NEVER work_1na(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 312);
}

static uint64_t INLINE_NEVER work_1nb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 313);
}

static uint64_t INLINE_NEVER work_1nc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 314);
}

static uint64_t INLINE_NEVER work_1nd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 315);
}

static uint64_t INLINE_NEVER work_1ne(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 316);
}

static uint64_t INLINE_NEVER work_1nf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 317);
}

static uint64_t INLINE_NEVER work_1ng(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 318);
}

static uint64_t INLINE_NEVER work_1nh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 319);
}

static uint64_t INLINE_NEVER work_1ni(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 320);
}

static uint64_t INLINE_NEVER work_1nj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 321);
}

static uint64_t INLINE_NEVER work_1nk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 322);
}

static uint64_t INLINE_NEVER work_1nl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 323);
}

static uint64_t INLINE_NEVER work_1nm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 324);
}

static uint64_t INLINE_NEVER work_1nn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 325);
}

static uint64_t INLINE_NEVER work_1no(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 326);
}

static uint64_t INLINE_NEVER work_1np(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 327);
}

static uint64_t INLINE_NEVER work_1nq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 328);
}

static uint64_t INLINE_NEVER work_1nr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 329);
}

static uint64_t INLINE_NEVER work_1ns(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 330);
}

static uint64_t INLINE_NEVER work_1nt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 331);
}

static uint64_t INLINE_NEVER work_1nu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 332);
}

static uint64_t INLINE_NEVER work_1nv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 333);
}

static uint64_t INLINE_NEVER work_1nw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 334);
}

static uint64_t INLINE_NEVER work_1nx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 335);
}

static uint64_t INLINE_NEVER work_1oa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 336);
}

static uint64_t INLINE_NEVER work_1ob(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 337);
}

static uint64_t INLINE_NEVER work_1oc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 338);
}

static uint64_t INLINE_NEVER work_1od(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 339);
}

static uint64_t INLINE_NEVER work_1oe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 340);
}

static uint64_t INLINE_NEVER work_1of(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 341);
}

static uint64_t INLINE_NEVER work_1og(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 342);
}

static uint64_t INLINE_NEVER work_1oh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 343);
}

static uint64_t INLINE_NEVER work_1oi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 344);
}

static uint64_t INLINE_NEVER work_1oj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 345);
}

static uint64_t INLINE_NEVER work_1ok(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 346);
}

static uint64_t INLINE_NEVER work_1ol(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 347);
}

static uint64_t INLINE_NEVER work_1om(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 348);
}

static uint64_t INLINE_NEVER work_1on(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 349);
}

static uint64_t INLINE_NEVER work_1oo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 350);
}

static uint64_t INLINE_NEVER work_1op(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 351);
}

static uint64_t INLINE_NEVER work_1oq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 352);
}

static uint64_t INLINE_NEVER work_1or(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 353);
}

static uint64_t INLINE_NEVER work_1os(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 354);
}

static uint64_t INLINE_NEVER work_1ot(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 355);
}

static uint64_t INLINE_NEVER work_1ou(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 356);
}

static uint64_t INLINE_NEVER work_1ov(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 357);
}

static uint64_t INLINE_NEVER work_1ow(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 358);
}

static uint64_t INLINE_NEVER work_1ox(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 359);
}

static uint64_t INLINE_NEVER work_1pa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 360);
}

static uint64_t INLINE_NEVER work_1pb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 361);
}

static uint64_t INLINE_NEVER work_1pc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 362);
}

static uint64_t INLINE_NEVER work_1pd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 363);
}

static uint64_t INLINE_NEVER work_1pe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 364);
}

static uint64_t INLINE_NEVER work_1pf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 365);
}

static uint64_t INLINE_NEVER work_1pg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 366);
}

static uint64_t INLINE_NEVER work_1ph(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 367);
}

static uint64_t INLINE_NEVER work_1pi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 368);
}

static uint64_t INLINE_NEVER work_1pj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 369);
}

static uint64_t INLINE_NEVER work_1pk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 370);
}

static uint64_t INLINE_NEVER work_1pl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 371);
}

static uint64_t INLINE_NEVER work_1pm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 372);
}

static uint64_t INLINE_NEVER work_1pn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 373);
}

static uint64_t INLINE_NEVER work_1po(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 374);
}

static uint64_t INLINE_NEVER work_1pp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 375);
}

static uint64_t INLINE_NEVER work_1pq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 376);
}

static uint64_t INLINE_NEVER work_1pr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 377);
}

static uint64_t INLINE_NEVER work_1ps(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 378);
}

static uint64_t INLINE_NEVER work_1pt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 379);
}

static uint64_t INLINE_NEVER work_1pu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 380);
}

static uint64_t INLINE_NEVER work_1pv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 381);
}

static uint64_t INLINE_NEVER work_1pw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 382);
}

static uint64_t INLINE_NEVER work_1px(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 383);
}

static uint64_t INLINE_NEVER work_1qa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 384);
}

static uint64_t INLINE_NEVER work_1qb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 385);
}

static uint64_t INLINE_NEVER work_1qc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 386);
}

static uint64_t INLINE_NEVER work_1qd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 387);
}

static uint64_t INLINE_NEVER work_1qe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 388);
}

static uint64_t INLINE_NEVER work_1qf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 389);
}

static uint64_t INLINE_NEVER work_1qg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 390);
}

static uint64_t INLINE_NEVER work_1qh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 391);
}

static uint64_t INLINE_NEVER work_1qi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 392);
}

static uint64_t INLINE_NEVER work_1qj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 393);
}

static uint64_t INLINE_NEVER work_1qk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 394);
}

static uint64_t INLINE_NEVER work_1ql(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 395);
}

static uint64_t INLINE_NEVER work_1qm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 396);
}

static uint64_t INLINE_NEVER work_1qn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 397);
}

static uint64_t INLINE_NEVER work_1qo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 398);
}

static uint64_t INLINE_NEVER work_1qp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 399);
}

static uint64_t INLINE_NEVER work_1qq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 400);
}

static uint64_t INLINE_NEVER work_1qr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 401);
}

static uint64_t INLINE_NEVER work_1qs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 402);
}

static uint64_t INLINE_NEVER work_1qt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 403);
}

static uint64_t INLINE_NEVER work_1qu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 404);
}

static uint64_t INLINE_NEVER work_1qv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 405);
}

static uint64_t INLINE_NEVER work_1qw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 406);
}

static uint64_t INLINE_NEVER work_1qx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 407);
}

static uint64_t INLINE_NEVER work_1ra(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 408);
}

static uint64_t INLINE_NEVER work_1rb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 409);
}

static uint64_t INLINE_NEVER work_1rc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 410);
}

static uint64_t INLINE_NEVER work_1rd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 411);
}

static uint64_t INLINE_NEVER work_1re(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 412);
}

static uint64_t INLINE_NEVER work_1rf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 413);
}

static uint64_t INLINE_NEVER work_1rg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 414);
}

static uint64_t INLINE_NEVER work_1rh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 415);
}

static uint64_t INLINE_NEVER work_1ri(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 416);
}

static uint64_t INLINE_NEVER work_1rj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 417);
}

static uint64_t INLINE_NEVER work_1rk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 418);
}

static uint64_t INLINE_NEVER work_1rl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 419);
}

static uint64_t INLINE_NEVER work_1rm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 420);
}

static uint64_t INLINE_NEVER work_1rn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 421);
}

static uint64_t INLINE_NEVER work_1ro(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 422);
}

static uint64_t INLINE_NEVER work_1rp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 423);
}

static uint64_t INLINE_NEVER work_1rq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 424);
}

static uint64_t INLINE_NEVER work_1rr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 425);
}

static uint64_t INLINE_NEVER work_1rs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 426);
}

static uint64_t INLINE_NEVER work_1rt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 427);
}

static uint64_t INLINE_NEVER work_1ru(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 428);
}

static uint64_t INLINE_NEVER work_1rv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 429);
}

static uint64_t INLINE_NEVER work_1rw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 430);
}

static uint64_t INLINE_NEVER work_1rx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 431);
}

static uint64_t INLINE_NEVER work_1sa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 432);
}

static uint64_t INLINE_NEVER work_1sb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 433);
}

static uint64_t INLINE_NEVER work_1sc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 434);
}

static uint64_t INLINE_NEVER work_1sd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 435);
}

static uint64_t INLINE_NEVER work_1se(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 436);
}

static uint64_t INLINE_NEVER work_1sf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 437);
}

static uint64_t INLINE_NEVER work_1sg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 438);
}

static uint64_t INLINE_NEVER work_1sh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 439);
}

static uint64_t INLINE_NEVER work_1si(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 440);
}

static uint64_t INLINE_NEVER work_1sj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 441);
}

static uint64_t INLINE_NEVER work_1sk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 442);
}

static uint64_t INLINE_NEVER work_1sl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 443);
}

static uint64_t INLINE_NEVER work_1sm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 444);
}

static uint64_t INLINE_NEVER work_1sn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 445);
}

static uint64_t INLINE_NEVER work_1so(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 446);
}

static uint64_t INLINE_NEVER work_1sp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 447);
}

static uint64_t INLINE_NEVER work_1sq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 448);
}

static uint64_t INLINE_NEVER work_1sr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 449);
}

static uint64_t INLINE_NEVER work_1ss(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 450);
}

static uint64_t INLINE_NEVER work_1st(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 451);
}

static uint64_t INLINE_NEVER work_1su(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 452);
}

static uint64_t INLINE_NEVER work_1sv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 453);
}

static uint64_t INLINE_NEVER work_1sw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 454);
}

static uint64_t INLINE_NEVER work_1sx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 455);
}

static uint64_t INLINE_NEVER work_1ta(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 456);
}

static uint64_t INLINE_NEVER work_1tb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 457);
}

static uint64_t INLINE_NEVER work_1tc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 458);
}

static uint64_t INLINE_NEVER work_1td(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 459);
}

static uint64_t INLINE_NEVER work_1te(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 460);
}

static uint64_t INLINE_NEVER work_1tf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 461);
}

static uint64_t INLINE_NEVER work_1tg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 462);
}

static uint64_t INLINE_NEVER work_1th(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 463);
}

static uint64_t INLINE_NEVER work_1ti(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 464);
}

static uint64_t INLINE_NEVER work_1tj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 465);
}

static uint64_t INLINE_NEVER work_1tk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 466);
}

static uint64_t INLINE_NEVER work_1tl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 467);
}

static uint64_t INLINE_NEVER work_1tm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 468);
}

static uint64_t INLINE_NEVER work_1tn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 469);
}

static uint64_t INLINE_NEVER work_1to(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 470);
}

static uint64_t INLINE_NEVER work_1tp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 471);
}

static uint64_t INLINE_NEVER work_1tq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 472);
}

static uint64_t INLINE_NEVER work_1tr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 473);
}

static uint64_t INLINE_NEVER work_1ts(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 474);
}

static uint64_t INLINE_NEVER work_1tt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 475);
}

static uint64_t INLINE_NEVER work_1tu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 476);
}

static uint64_t INLINE_NEVER work_1tv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 477);
}

static uint64_t INLINE_NEVER work_1tw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 478);
}

static uint64_t INLINE_NEVER work_1tx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 479);
}

static uint64_t INLINE_NEVER work_1ua(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 480);
}

static uint64_t INLINE_NEVER work_1ub(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 481);
}

static uint64_t INLINE_NEVER work_1uc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 482);
}

static uint64_t INLINE_NEVER work_1ud(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 483);
}

static uint64_t INLINE_NEVER work_1ue(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 484);
}

static uint64_t INLINE_NEVER work_1uf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 485);
}

static uint64_t INLINE_NEVER work_1ug(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 486);
}

static uint64_t INLINE_NEVER work_1uh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 487);
}

static uint64_t INLINE_NEVER work_1ui(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 488);
}

static uint64_t INLINE_NEVER work_1uj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 489);
}

static uint64_t INLINE_NEVER work_1uk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 490);
}

static uint64_t INLINE_NEVER work_1ul(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 491);
}

static uint64_t INLINE_NEVER work_1um(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 492);
}

static uint64_t INLINE_NEVER work_1un(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 493);
}

static uint64_t INLINE_NEVER work_1uo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 494);
}

static uint64_t INLINE_NEVER work_1up(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 495);
}

static uint64_t INLINE_NEVER work_1uq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 496);
}

static uint64_t INLINE_NEVER work_1ur(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 497);
}

static uint64_t INLINE_NEVER work_1us(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 498);
}

static uint64_t INLINE_NEVER work_1ut(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 499);
}

static uint64_t INLINE_NEVER work_1uu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 500);
}

static uint64_t INLINE_NEVER work_1uv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 501);
}

static uint64_t INLINE_NEVER work_1uw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 502);
}

static uint64_t INLINE_NEVER work_1ux(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 503);
}

static uint64_t INLINE_NEVER work_1va(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 504);
}

static uint64_t INLINE_NEVER work_1vb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 505);
}

static uint64_t INLINE_NEVER work_1vc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 506);
}

static uint64_t INLINE_NEVER work_1vd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 507);
}

static uint64_t INLINE_NEVER work_1ve(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 508);
}

static uint64_t INLINE_NEVER work_1vf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 509);
}

static uint64_t INLINE_NEVER work_1vg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 510);
}

static uint64_t INLINE_NEVER work_1vh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 511);
}

static uint64_t INLINE_NEVER work_1vi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 512);
}

static uint64_t INLINE_NEVER work_1vj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 513);
}

static uint64_t INLINE_NEVER work_1vk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 514);
}

static uint64_t INLINE_NEVER work_1vl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 515);
}

static uint64_t INLINE_NEVER work_1vm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 516);
}

static uint64_t INLINE_NEVER work_1vn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 517);
}

static uint64_t INLINE_NEVER work_1vo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 518);
}

static uint64_t INLINE_NEVER work_1vp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 519);
}

static uint64_t INLINE_NEVER work_1vq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 520);
}

static uint64_t INLINE_NEVER work_1vr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 521);
}

static uint64_t INLINE_NEVER work_1vs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 522);
}

static uint64_t INLINE_NEVER work_1vt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 523);
}

static uint64_t INLINE_NEVER work_1vu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 524);
}

static uint64_t INLINE_NEVER work_1vv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 525);
}

static uint64_t INLINE_NEVER work_1vw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 526);
}

static uint64_t INLINE_NEVER work_1vx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 527);
}

static uint64_t INLINE_NEVER work_1wa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 528);
}

static uint64_t INLINE_NEVER work_1wb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 529);
}

static uint64_t INLINE_NEVER work_1wc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 530);
}

static uint64_t INLINE_NEVER work_1wd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 531);
}

static uint64_t INLINE_NEVER work_1we(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 532);
}

static uint64_t INLINE_NEVER work_1wf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 533);
}

static uint64_t INLINE_NEVER work_1wg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 534);
}

static uint64_t INLINE_NEVER work_1wh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 535);
}

static uint64_t INLINE_NEVER work_1wi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 536);
}

static uint64_t INLINE_NEVER work_1wj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 537);
}

static uint64_t INLINE_NEVER work_1wk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 538);
}

static uint64_t INLINE_NEVER work_1wl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 539);
}

static uint64_t INLINE_NEVER work_1wm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 540);
}

static uint64_t INLINE_NEVER work_1wn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 541);
}

static uint64_t INLINE_NEVER work_1wo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 542);
}

static uint64_t INLINE_NEVER work_1wp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 543);
}

static uint64_t INLINE_NEVER work_1wq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 544);
}

static uint64_t INLINE_NEVER work_1wr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 545);
}

static uint64_t INLINE_NEVER work_1ws(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 546);
}

static uint64_t INLINE_NEVER work_1wt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 547);
}

static uint64_t INLINE_NEVER work_1wu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 548);
}

static uint64_t INLINE_NEVER work_1wv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 549);
}

static uint64_t INLINE_NEVER work_1ww(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 550);
}

static uint64_t INLINE_NEVER work_1wx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 551);
}

static uint64_t INLINE_NEVER work_1xa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 552);
}

static uint64_t INLINE_NEVER work_1xb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 553);
}

static uint64_t INLINE_NEVER work_1xc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 554);
}

static uint64_t INLINE_NEVER work_1xd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 555);
}

static uint64_t INLINE_NEVER work_1xe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 556);
}

static uint64_t INLINE_NEVER work_1xf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 557);
}

static uint64_t INLINE_NEVER work_1xg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 558);
}

static uint64_t INLINE_NEVER work_1xh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 559);
}

static uint64_t INLINE_NEVER work_1xi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 560);
}

static uint64_t INLINE_NEVER work_1xj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 561);
}

static uint64_t INLINE_NEVER work_1xk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 562);
}

static uint64_t INLINE_NEVER work_1xl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 563);
}

static uint64_t INLINE_NEVER work_1xm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 564);
}

static uint64_t INLINE_NEVER work_1xn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 565);
}

static uint64_t INLINE_NEVER work_1xo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 566);
}

static uint64_t INLINE_NEVER work_1xp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 567);
}

static uint64_t INLINE_NEVER work_1xq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 568);
}

static uint64_t INLINE_NEVER work_1xr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 569);
}

static uint64_t INLINE_NEVER work_1xs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 570);
}

static uint64_t INLINE_NEVER work_1xt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 571);
}

static uint64_t INLINE_NEVER work_1xu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 572);
}

static uint64_t INLINE_NEVER work_1xv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 573);
}

static uint64_t INLINE_NEVER work_1xw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 574);
}

static uint64_t INLINE_NEVER work_1xx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_1(a, b, c, 575);
}

static work_1_fn_t work_1[] = {
	work_1aa, work_1ab, work_1ac, work_1ad, work_1ae, work_1af, work_1ag, work_1ah,
	work_1ai, work_1aj, work_1ak, work_1al, work_1am, work_1an, work_1ao, work_1ap,
	work_1aq, work_1ar, work_1as, work_1at, work_1au, work_1av, work_1aw, work_1ax,
	work_1ba, work_1bb, work_1bc, work_1bd, work_1be, work_1bf, work_1bg, work_1bh,
	work_1bi, work_1bj, work_1bk, work_1bl, work_1bm, work_1bn, work_1bo, work_1bp,
	work_1bq, work_1br, work_1bs, work_1bt, work_1bu, work_1bv, work_1bw, work_1bx,
	work_1ca, work_1cb, work_1cc, work_1cd, work_1ce, work_1cf, work_1cg, work_1ch,
	work_1ci, work_1cj, work_1ck, work_1cl, work_1cm, work_1cn, work_1co, work_1cp,
	work_1cq, work_1cr, work_1cs, work_1ct, work_1cu, work_1cv, work_1cw, work_1cx,
	work_1da, work_1db, work_1dc, work_1dd, work_1de, work_1df, work_1dg, work_1dh,
	work_1di, work_1dj, work_1dk, work_1dl, work_1dm, work_1dn, work_1do, work_1dp,
	work_1dq, work_1dr, work_1ds, work_1dt, work_1du, work_1dv, work_1dw, work_1dx,
	work_1ea, work_1eb, work_1ec, work_1ed, work_1ee, work_1ef, work_1eg, work_1eh,
	work_1ei, work_1ej, work_1ek, work_1el, work_1em, work_1en, work_1eo, work_1ep,
	work_1eq, work_1er, work_1es, work_1et, work_1eu, work_1ev, work_1ew, work_1ex,
	work_1fa, work_1fb, work_1fc, work_1fd, work_1fe, work_1ff, work_1fg, work_1fh,
	work_1fi, work_1fj, work_1fk, work_1fl, work_1fm, work_1fn, work_1fo, work_1fp,
	work_1fq, work_1fr, work_1fs, work_1ft, work_1fu, work_1fv, work_1fw, work_1fx,
	work_1ga, work_1gb, work_1gc, work_1gd, work_1ge, work_1gf, work_1gg, work_1gh,
	work_1gi, work_1gj, work_1gk, work_1gl, work_1gm, work_1gn, work_1go, work_1gp,
	work_1gq, work_1gr, work_1gs, work_1gt, work_1gu, work_1gv, work_1gw, work_1gx,
	work_1ha, work_1hb, work_1hc, work_1hd, work_1he, work_1hf, work_1hg, work_1hh,
	work_1hi, work_1hj, work_1hk, work_1hl, work_1hm, work_1hn, work_1ho, work_1hp,
	work_1hq, work_1hr, work_1hs, work_1ht, work_1hu, work_1hv, work_1hw, work_1hx,
	work_1ia, work_1ib, work_1ic, work_1id, work_1ie, work_1if, work_1ig, work_1ih,
	work_1ii, work_1ij, work_1ik, work_1il, work_1im, work_1in, work_1io, work_1ip,
	work_1iq, work_1ir, work_1is, work_1it, work_1iu, work_1iv, work_1iw, work_1ix,
	work_1ja, work_1jb, work_1jc, work_1jd, work_1je, work_1jf, work_1jg, work_1jh,
	work_1ji, work_1jj, work_1jk, work_1jl, work_1jm, work_1jn, work_1jo, work_1jp,
	work_1jq, work_1jr, work_1js, work_1jt, work_1ju, work_1jv, work_1jw, work_1jx,
	work_1ka, work_1kb, work_1kc, work_1kd, work_1ke, work_1kf, work_1kg, work_1kh,
	work_1ki, work_1kj, work_1kk, work_1kl, work_1km, work_1kn, work_1ko, work_1kp,
	work_1kq, work_1kr, work_1ks, work_1kt, work_1ku, work_1kv, work_1kw, work_1kx,
	work_1la, work_1lb, work_1lc, work_1ld, work_1le, work_1lf, work_1lg, work_1lh,
	work_1li, work_1lj, work_1lk, work_1ll, work_1lm, work_1ln, work_1lo, work_1lp,
	work_1lq, work_1lr, work_1ls, work_1lt, work_1lu, work_1lv, work_1lw, work_1lx,
	work_1ma, work_1mb, work_1mc, work_1md, work_1me, work_1mf, work_1mg, work_1mh,
	work_1mi, work_1mj, work_1mk, work_1ml, work_1mm, work_1mn, work_1mo, work_1mp,
	work_1mq, work_1mr, work_1ms, work_1mt, work_1mu, work_1mv, work_1mw, work_1mx,
	work_1na, work_1nb, work_1nc, work_1nd, work_1ne, work_1nf, work_1ng, work_1nh,
	work_1ni, work_1nj, work_1nk, work_1nl, work_1nm, work_1nn, work_1no, work_1np,
	work_1nq, work_1nr, work_1ns, work_1nt, work_1nu, work_1nv, work_1nw, work_1nx,
	work_1oa, work_1ob, work_1oc, work_1od, work_1oe, work_1of, work_1og, work_1oh,
	work_1oi, work_1oj, work_1ok, work_1ol, work_1om, work_1on, work_1oo, work_1op,
	work_1oq, work_1or, work_1os, work_1ot, work_1ou, work_1ov, work_1ow, work_1ox,
	work_1pa, work_1pb, work_1pc, work_1pd, work_1pe, work_1pf, work_1pg, work_1ph,
	work_1pi, work_1pj, work_1pk, work_1pl, work_1pm, work_1pn, work_1po, work_1pp,
	work_1pq, work_1pr, work_1ps, work_1pt, work_1pu, work_1pv, work_1pw, work_1px,
	work_1qa, work_1qb, work_1qc, work_1qd, work_1qe, work_1qf, work_1qg, work_1qh,
	work_1qi, work_1qj, work_1qk, work_1ql, work_1qm, work_1qn, work_1qo, work_1qp,
	work_1qq, work_1qr, work_1qs, work_1qt, work_1qu, work_1qv, work_1qw, work_1qx,
	work_1ra, work_1rb, work_1rc, work_1rd, work_1re, work_1rf, work_1rg, work_1rh,
	work_1ri, work_1rj, work_1rk, work_1rl, work_1rm, work_1rn, work_1ro, work_1rp,
	work_1rq, work_1rr, work_1rs, work_1rt, work_1ru, work_1rv, work_1rw, work_1rx,
	work_1sa, work_1sb, work_1sc, work_1sd, work_1se, work_1sf, work_1sg, work_1sh,
	work_1si, work_1sj, work_1sk, work_1sl, work_1sm, work_1sn, work_1so, work_1sp,
	work_1sq, work_1sr, work_1ss, work_1st, work_1su, work_1sv, work_1sw, work_1sx,
	work_1ta, work_1tb, work_1tc, work_1td, work_1te, work_1tf, work_1tg, work_1th,
	work_1ti, work_1tj, work_1tk, work_1tl, work_1tm, work_1tn, work_1to, work_1tp,
	work_1tq, work_1tr, work_1ts, work_1tt, work_1tu, work_1tv, work_1tw, work_1tx,
	work_1ua, work_1ub, work_1uc, work_1ud, work_1ue, work_1uf, work_1ug, work_1uh,
	work_1ui, work_1uj, work_1uk, work_1ul, work_1um, work_1un, work_1uo, work_1up,
	work_1uq, work_1ur, work_1us, work_1ut, work_1uu, work_1uv, work_1uw, work_1ux,
	work_1va, work_1vb, work_1vc, work_1vd, work_1ve, work_1vf, work_1vg, work_1vh,
	work_1vi, work_1vj, work_1vk, work_1vl, work_1vm, work_1vn, work_1vo, work_1vp,
	work_1vq, work_1vr, work_1vs, work_1vt, work_1vu, work_1vv, work_1vw, work_1vx,
	work_1wa, work_1wb, work_1wc, work_1wd, work_1we, work_1wf, work_1wg, work_1wh,
	work_1wi, work_1wj, work_1wk, work_1wl, work_1wm, work_1wn, work_1wo, work_1wp,
	work_1wq, work_1wr, work_1ws, work_1wt, work_1wu, work_1wv, work_1ww, work_1wx,
	work_1xa, work_1xb, work_1xc, work_1xd, work_1xe, work_1xf, work_1xg, work_1xh,
	work_1xi, work_1xj, work_1xk, work_1xl, work_1xm, work_1xn, work_1xo, work_1xp,
	work_1xq, work_1xr, work_1xs, work_1xt, work_1xu, work_1xv, work_1xw, work_1xx
};

static uint16_t work_1_rnd[] = {
	150, 424,  26, 457,  74, 294, 218, 487, 348, 358, 540, 465, 305, 499, 103, 535,
	162,  92, 388, 269,  78, 245,  96, 546, 146, 346, 513, 116, 306, 383, 264,  85,
	 75,  98, 437, 200, 362, 283, 147, 270,  51, 541, 272, 575, 239, 404, 498, 212,
	168, 290,  31, 396, 384, 310, 551, 179, 139, 204, 292,  61, 154, 266,  66, 108,
	 44, 196, 400, 460, 410,  55, 491, 459,  80, 188, 128, 333, 489, 538, 447, 389,
	181, 378, 105,  62, 468, 417, 189, 194, 376, 562, 131, 518, 409,  87, 195,  57,
	422, 151, 470, 415, 215,   7,  15, 354, 542, 211, 241, 107, 243, 528, 274, 366,
	197, 566, 463, 331, 454, 152, 324, 412, 236, 364, 484, 279, 481,   4, 497, 569,
	  6, 548,   0, 372, 115, 157, 217, 406, 338, 494, 325, 109, 552, 202, 505, 208,
	510, 397, 526,  52, 301, 382, 190, 148, 327, 565, 130, 431, 219, 263,  25,  84,
	347, 374, 238, 278,  20, 221,  71,  56, 433, 450, 339,  35, 509, 368, 401, 300,
	167,  46, 353,  93,  54, 136, 230, 251, 101, 125, 341, 365, 411, 330, 391, 201,
	233, 213,   9,  18, 440, 567, 156, 507, 486, 224,  58, 448, 120,  41, 385, 298,
	284, 395, 550, 340, 124, 531, 571, 434, 471, 488,  81, 235,  27, 512, 432, 248,
	423, 318,   8, 216, 508, 549, 249, 291,  95, 271, 351, 267, 308, 532, 467, 186,
	244,  60, 572, 184, 399, 317, 545,  12, 134, 461, 171,  43, 472, 118, 350, 172,
	183,   1, 259, 570, 380, 361,  73, 446, 534,  24, 555, 142, 402, 158, 319,  36,
	240, 203, 164, 419,  14,  64, 359, 451,  50, 449, 321, 455, 198, 287, 316, 307,
	363, 464,   5, 173, 511, 187, 191, 138, 163,  37, 490,  69,  67, 547, 479, 106,
	355, 352, 524, 297, 166,  59, 182, 276,  48, 312, 149, 556, 110, 515, 257, 314,
	517, 143, 265, 476, 277,   3, 332, 232, 323,  45, 554, 268, 226, 141,  28, 335,
	206,  72, 533, 482, 492, 220, 439, 159, 393, 398, 414,  39, 530,  77,  29, 483,
	246, 407, 329, 413, 429, 360, 229, 502, 322, 403, 462,  42, 453, 520, 558,  34,
	304,  99,  88,   2, 114, 477,  97, 223, 227, 328, 295, 210, 311, 336, 231, 132,
	495, 425, 371, 394, 129, 474, 309, 426, 344, 285, 296, 503, 258, 560, 155, 370,
	 21, 386, 228, 161, 379, 506, 539, 521, 145, 475, 537, 289, 237, 111, 369, 456,
	373, 568, 536, 473, 334, 445, 299, 303,  70, 209, 222,  23, 177, 170,  40, 207,
	 76, 100, 478, 286, 293, 438, 392, 252, 574, 485, 553, 255, 104, 559, 253, 119,
	140, 242, 469, 176, 544,  19, 126, 441, 390, 377, 153, 543,  16, 180, 275,  82,
	 79, 525, 427, 527, 367, 169, 428, 302,  13, 420, 466, 496, 133, 357, 342, 416,
	 22, 519, 122,  49, 113, 123, 418, 349, 178, 529, 165, 199,  89, 280, 356, 256,
	247, 127, 135, 430, 193, 444,  86,  30, 313, 261,  68, 381, 442, 121,  17, 501,
	343, 436, 281, 405, 500, 250, 421, 435, 192, 345, 563, 262, 320,  91, 387,  33,
	 32, 516, 557, 160, 443, 260, 458, 175,  53,  83, 375, 174, 288,  65, 522,  10,
	480, 315,  90, 561,  11, 254, 234, 214,  38, 273, 523,  47, 337, 102, 326, 452,
	205, 573, 112, 185, 144, 408,  63, 225, 493, 282, 504, 514, 564, 117,  94, 137
};

static uint64_t INLINE_NEVER work_2aa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 0);
}

static uint64_t INLINE_NEVER work_2ab(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 1);
}

static uint64_t INLINE_NEVER work_2ac(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 2);
}

static uint64_t INLINE_NEVER work_2ad(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 3);
}

static uint64_t INLINE_NEVER work_2ae(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 4);
}

static uint64_t INLINE_NEVER work_2af(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 5);
}

static uint64_t INLINE_NEVER work_2ag(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 6);
}

static uint64_t INLINE_NEVER work_2ah(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 7);
}

static uint64_t INLINE_NEVER work_2ai(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 8);
}

static uint64_t INLINE_NEVER work_2aj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 9);
}

static uint64_t INLINE_NEVER work_2ak(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 10);
}

static uint64_t INLINE_NEVER work_2al(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 11);
}

static uint64_t INLINE_NEVER work_2am(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 12);
}

static uint64_t INLINE_NEVER work_2an(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 13);
}

static uint64_t INLINE_NEVER work_2ao(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 14);
}

static uint64_t INLINE_NEVER work_2ap(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 15);
}

static uint64_t INLINE_NEVER work_2aq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 16);
}

static uint64_t INLINE_NEVER work_2ar(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 17);
}

static uint64_t INLINE_NEVER work_2as(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 18);
}

static uint64_t INLINE_NEVER work_2at(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 19);
}

static uint64_t INLINE_NEVER work_2au(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 20);
}

static uint64_t INLINE_NEVER work_2av(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 21);
}

static uint64_t INLINE_NEVER work_2aw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 22);
}

static uint64_t INLINE_NEVER work_2ax(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 23);
}

static uint64_t INLINE_NEVER work_2ba(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 24);
}

static uint64_t INLINE_NEVER work_2bb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 25);
}

static uint64_t INLINE_NEVER work_2bc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 26);
}

static uint64_t INLINE_NEVER work_2bd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 27);
}

static uint64_t INLINE_NEVER work_2be(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 28);
}

static uint64_t INLINE_NEVER work_2bf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 29);
}

static uint64_t INLINE_NEVER work_2bg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 30);
}

static uint64_t INLINE_NEVER work_2bh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 31);
}

static uint64_t INLINE_NEVER work_2bi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 32);
}

static uint64_t INLINE_NEVER work_2bj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 33);
}

static uint64_t INLINE_NEVER work_2bk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 34);
}

static uint64_t INLINE_NEVER work_2bl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 35);
}

static uint64_t INLINE_NEVER work_2bm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 36);
}

static uint64_t INLINE_NEVER work_2bn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 37);
}

static uint64_t INLINE_NEVER work_2bo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 38);
}

static uint64_t INLINE_NEVER work_2bp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 39);
}

static uint64_t INLINE_NEVER work_2bq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 40);
}

static uint64_t INLINE_NEVER work_2br(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 41);
}

static uint64_t INLINE_NEVER work_2bs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 42);
}

static uint64_t INLINE_NEVER work_2bt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 43);
}

static uint64_t INLINE_NEVER work_2bu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 44);
}

static uint64_t INLINE_NEVER work_2bv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 45);
}

static uint64_t INLINE_NEVER work_2bw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 46);
}

static uint64_t INLINE_NEVER work_2bx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 47);
}

static uint64_t INLINE_NEVER work_2ca(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 48);
}

static uint64_t INLINE_NEVER work_2cb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 49);
}

static uint64_t INLINE_NEVER work_2cc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 50);
}

static uint64_t INLINE_NEVER work_2cd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 51);
}

static uint64_t INLINE_NEVER work_2ce(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 52);
}

static uint64_t INLINE_NEVER work_2cf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 53);
}

static uint64_t INLINE_NEVER work_2cg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 54);
}

static uint64_t INLINE_NEVER work_2ch(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 55);
}

static uint64_t INLINE_NEVER work_2ci(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 56);
}

static uint64_t INLINE_NEVER work_2cj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 57);
}

static uint64_t INLINE_NEVER work_2ck(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 58);
}

static uint64_t INLINE_NEVER work_2cl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 59);
}

static uint64_t INLINE_NEVER work_2cm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 60);
}

static uint64_t INLINE_NEVER work_2cn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 61);
}

static uint64_t INLINE_NEVER work_2co(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 62);
}

static uint64_t INLINE_NEVER work_2cp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 63);
}

static uint64_t INLINE_NEVER work_2cq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 64);
}

static uint64_t INLINE_NEVER work_2cr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 65);
}

static uint64_t INLINE_NEVER work_2cs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 66);
}

static uint64_t INLINE_NEVER work_2ct(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 67);
}

static uint64_t INLINE_NEVER work_2cu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 68);
}

static uint64_t INLINE_NEVER work_2cv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 69);
}

static uint64_t INLINE_NEVER work_2cw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 70);
}

static uint64_t INLINE_NEVER work_2cx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 71);
}

static uint64_t INLINE_NEVER work_2da(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 72);
}

static uint64_t INLINE_NEVER work_2db(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 73);
}

static uint64_t INLINE_NEVER work_2dc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 74);
}

static uint64_t INLINE_NEVER work_2dd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 75);
}

static uint64_t INLINE_NEVER work_2de(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 76);
}

static uint64_t INLINE_NEVER work_2df(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 77);
}

static uint64_t INLINE_NEVER work_2dg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 78);
}

static uint64_t INLINE_NEVER work_2dh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 79);
}

static uint64_t INLINE_NEVER work_2di(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 80);
}

static uint64_t INLINE_NEVER work_2dj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 81);
}

static uint64_t INLINE_NEVER work_2dk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 82);
}

static uint64_t INLINE_NEVER work_2dl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 83);
}

static uint64_t INLINE_NEVER work_2dm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 84);
}

static uint64_t INLINE_NEVER work_2dn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 85);
}

static uint64_t INLINE_NEVER work_2do(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 86);
}

static uint64_t INLINE_NEVER work_2dp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 87);
}

static uint64_t INLINE_NEVER work_2dq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 88);
}

static uint64_t INLINE_NEVER work_2dr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 89);
}

static uint64_t INLINE_NEVER work_2ds(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 90);
}

static uint64_t INLINE_NEVER work_2dt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 91);
}

static uint64_t INLINE_NEVER work_2du(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 92);
}

static uint64_t INLINE_NEVER work_2dv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 93);
}

static uint64_t INLINE_NEVER work_2dw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 94);
}

static uint64_t INLINE_NEVER work_2dx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 95);
}

static uint64_t INLINE_NEVER work_2ea(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 96);
}

static uint64_t INLINE_NEVER work_2eb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 97);
}

static uint64_t INLINE_NEVER work_2ec(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 98);
}

static uint64_t INLINE_NEVER work_2ed(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 99);
}

static uint64_t INLINE_NEVER work_2ee(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 100);
}

static uint64_t INLINE_NEVER work_2ef(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 101);
}

static uint64_t INLINE_NEVER work_2eg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 102);
}

static uint64_t INLINE_NEVER work_2eh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 103);
}

static uint64_t INLINE_NEVER work_2ei(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 104);
}

static uint64_t INLINE_NEVER work_2ej(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 105);
}

static uint64_t INLINE_NEVER work_2ek(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 106);
}

static uint64_t INLINE_NEVER work_2el(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 107);
}

static uint64_t INLINE_NEVER work_2em(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 108);
}

static uint64_t INLINE_NEVER work_2en(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 109);
}

static uint64_t INLINE_NEVER work_2eo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 110);
}

static uint64_t INLINE_NEVER work_2ep(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 111);
}

static uint64_t INLINE_NEVER work_2eq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 112);
}

static uint64_t INLINE_NEVER work_2er(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 113);
}

static uint64_t INLINE_NEVER work_2es(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 114);
}

static uint64_t INLINE_NEVER work_2et(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 115);
}

static uint64_t INLINE_NEVER work_2eu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 116);
}

static uint64_t INLINE_NEVER work_2ev(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 117);
}

static uint64_t INLINE_NEVER work_2ew(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 118);
}

static uint64_t INLINE_NEVER work_2ex(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 119);
}

static uint64_t INLINE_NEVER work_2fa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 120);
}

static uint64_t INLINE_NEVER work_2fb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 121);
}

static uint64_t INLINE_NEVER work_2fc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 122);
}

static uint64_t INLINE_NEVER work_2fd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 123);
}

static uint64_t INLINE_NEVER work_2fe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 124);
}

static uint64_t INLINE_NEVER work_2ff(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 125);
}

static uint64_t INLINE_NEVER work_2fg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 126);
}

static uint64_t INLINE_NEVER work_2fh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 127);
}

static uint64_t INLINE_NEVER work_2fi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 128);
}

static uint64_t INLINE_NEVER work_2fj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 129);
}

static uint64_t INLINE_NEVER work_2fk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 130);
}

static uint64_t INLINE_NEVER work_2fl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 131);
}

static uint64_t INLINE_NEVER work_2fm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 132);
}

static uint64_t INLINE_NEVER work_2fn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 133);
}

static uint64_t INLINE_NEVER work_2fo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 134);
}

static uint64_t INLINE_NEVER work_2fp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 135);
}

static uint64_t INLINE_NEVER work_2fq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 136);
}

static uint64_t INLINE_NEVER work_2fr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 137);
}

static uint64_t INLINE_NEVER work_2fs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 138);
}

static uint64_t INLINE_NEVER work_2ft(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 139);
}

static uint64_t INLINE_NEVER work_2fu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 140);
}

static uint64_t INLINE_NEVER work_2fv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 141);
}

static uint64_t INLINE_NEVER work_2fw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 142);
}

static uint64_t INLINE_NEVER work_2fx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 143);
}

static uint64_t INLINE_NEVER work_2ga(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 144);
}

static uint64_t INLINE_NEVER work_2gb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 145);
}

static uint64_t INLINE_NEVER work_2gc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 146);
}

static uint64_t INLINE_NEVER work_2gd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 147);
}

static uint64_t INLINE_NEVER work_2ge(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 148);
}

static uint64_t INLINE_NEVER work_2gf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 149);
}

static uint64_t INLINE_NEVER work_2gg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 150);
}

static uint64_t INLINE_NEVER work_2gh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 151);
}

static uint64_t INLINE_NEVER work_2gi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 152);
}

static uint64_t INLINE_NEVER work_2gj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 153);
}

static uint64_t INLINE_NEVER work_2gk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 154);
}

static uint64_t INLINE_NEVER work_2gl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 155);
}

static uint64_t INLINE_NEVER work_2gm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 156);
}

static uint64_t INLINE_NEVER work_2gn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 157);
}

static uint64_t INLINE_NEVER work_2go(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 158);
}

static uint64_t INLINE_NEVER work_2gp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 159);
}

static uint64_t INLINE_NEVER work_2gq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 160);
}

static uint64_t INLINE_NEVER work_2gr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 161);
}

static uint64_t INLINE_NEVER work_2gs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 162);
}

static uint64_t INLINE_NEVER work_2gt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 163);
}

static uint64_t INLINE_NEVER work_2gu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 164);
}

static uint64_t INLINE_NEVER work_2gv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 165);
}

static uint64_t INLINE_NEVER work_2gw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 166);
}

static uint64_t INLINE_NEVER work_2gx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 167);
}

static uint64_t INLINE_NEVER work_2ha(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 168);
}

static uint64_t INLINE_NEVER work_2hb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 169);
}

static uint64_t INLINE_NEVER work_2hc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 170);
}

static uint64_t INLINE_NEVER work_2hd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 171);
}

static uint64_t INLINE_NEVER work_2he(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 172);
}

static uint64_t INLINE_NEVER work_2hf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 173);
}

static uint64_t INLINE_NEVER work_2hg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 174);
}

static uint64_t INLINE_NEVER work_2hh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 175);
}

static uint64_t INLINE_NEVER work_2hi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 176);
}

static uint64_t INLINE_NEVER work_2hj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 177);
}

static uint64_t INLINE_NEVER work_2hk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 178);
}

static uint64_t INLINE_NEVER work_2hl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 179);
}

static uint64_t INLINE_NEVER work_2hm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 180);
}

static uint64_t INLINE_NEVER work_2hn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 181);
}

static uint64_t INLINE_NEVER work_2ho(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 182);
}

static uint64_t INLINE_NEVER work_2hp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 183);
}

static uint64_t INLINE_NEVER work_2hq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 184);
}

static uint64_t INLINE_NEVER work_2hr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 185);
}

static uint64_t INLINE_NEVER work_2hs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 186);
}

static uint64_t INLINE_NEVER work_2ht(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 187);
}

static uint64_t INLINE_NEVER work_2hu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 188);
}

static uint64_t INLINE_NEVER work_2hv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 189);
}

static uint64_t INLINE_NEVER work_2hw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 190);
}

static uint64_t INLINE_NEVER work_2hx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 191);
}

static uint64_t INLINE_NEVER work_2ia(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 192);
}

static uint64_t INLINE_NEVER work_2ib(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 193);
}

static uint64_t INLINE_NEVER work_2ic(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 194);
}

static uint64_t INLINE_NEVER work_2id(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 195);
}

static uint64_t INLINE_NEVER work_2ie(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 196);
}

static uint64_t INLINE_NEVER work_2if(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 197);
}

static uint64_t INLINE_NEVER work_2ig(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 198);
}

static uint64_t INLINE_NEVER work_2ih(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 199);
}

static uint64_t INLINE_NEVER work_2ii(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 200);
}

static uint64_t INLINE_NEVER work_2ij(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 201);
}

static uint64_t INLINE_NEVER work_2ik(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 202);
}

static uint64_t INLINE_NEVER work_2il(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 203);
}

static uint64_t INLINE_NEVER work_2im(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 204);
}

static uint64_t INLINE_NEVER work_2in(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 205);
}

static uint64_t INLINE_NEVER work_2io(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 206);
}

static uint64_t INLINE_NEVER work_2ip(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 207);
}

static uint64_t INLINE_NEVER work_2iq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 208);
}

static uint64_t INLINE_NEVER work_2ir(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 209);
}

static uint64_t INLINE_NEVER work_2is(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 210);
}

static uint64_t INLINE_NEVER work_2it(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 211);
}

static uint64_t INLINE_NEVER work_2iu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 212);
}

static uint64_t INLINE_NEVER work_2iv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 213);
}

static uint64_t INLINE_NEVER work_2iw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 214);
}

static uint64_t INLINE_NEVER work_2ix(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 215);
}

static uint64_t INLINE_NEVER work_2ja(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 216);
}

static uint64_t INLINE_NEVER work_2jb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 217);
}

static uint64_t INLINE_NEVER work_2jc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 218);
}

static uint64_t INLINE_NEVER work_2jd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 219);
}

static uint64_t INLINE_NEVER work_2je(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 220);
}

static uint64_t INLINE_NEVER work_2jf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 221);
}

static uint64_t INLINE_NEVER work_2jg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 222);
}

static uint64_t INLINE_NEVER work_2jh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 223);
}

static uint64_t INLINE_NEVER work_2ji(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 224);
}

static uint64_t INLINE_NEVER work_2jj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 225);
}

static uint64_t INLINE_NEVER work_2jk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 226);
}

static uint64_t INLINE_NEVER work_2jl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 227);
}

static uint64_t INLINE_NEVER work_2jm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 228);
}

static uint64_t INLINE_NEVER work_2jn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 229);
}

static uint64_t INLINE_NEVER work_2jo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 230);
}

static uint64_t INLINE_NEVER work_2jp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 231);
}

static uint64_t INLINE_NEVER work_2jq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 232);
}

static uint64_t INLINE_NEVER work_2jr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 233);
}

static uint64_t INLINE_NEVER work_2js(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 234);
}

static uint64_t INLINE_NEVER work_2jt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 235);
}

static uint64_t INLINE_NEVER work_2ju(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 236);
}

static uint64_t INLINE_NEVER work_2jv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 237);
}

static uint64_t INLINE_NEVER work_2jw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 238);
}

static uint64_t INLINE_NEVER work_2jx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 239);
}

static uint64_t INLINE_NEVER work_2ka(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 240);
}

static uint64_t INLINE_NEVER work_2kb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 241);
}

static uint64_t INLINE_NEVER work_2kc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 242);
}

static uint64_t INLINE_NEVER work_2kd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 243);
}

static uint64_t INLINE_NEVER work_2ke(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 244);
}

static uint64_t INLINE_NEVER work_2kf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 245);
}

static uint64_t INLINE_NEVER work_2kg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 246);
}

static uint64_t INLINE_NEVER work_2kh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 247);
}

static uint64_t INLINE_NEVER work_2ki(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 248);
}

static uint64_t INLINE_NEVER work_2kj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 249);
}

static uint64_t INLINE_NEVER work_2kk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 250);
}

static uint64_t INLINE_NEVER work_2kl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 251);
}

static uint64_t INLINE_NEVER work_2km(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 252);
}

static uint64_t INLINE_NEVER work_2kn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 253);
}

static uint64_t INLINE_NEVER work_2ko(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 254);
}

static uint64_t INLINE_NEVER work_2kp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 255);
}

static uint64_t INLINE_NEVER work_2kq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 256);
}

static uint64_t INLINE_NEVER work_2kr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 257);
}

static uint64_t INLINE_NEVER work_2ks(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 258);
}

static uint64_t INLINE_NEVER work_2kt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 259);
}

static uint64_t INLINE_NEVER work_2ku(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 260);
}

static uint64_t INLINE_NEVER work_2kv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 261);
}

static uint64_t INLINE_NEVER work_2kw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 262);
}

static uint64_t INLINE_NEVER work_2kx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 263);
}

static uint64_t INLINE_NEVER work_2la(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 264);
}

static uint64_t INLINE_NEVER work_2lb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 265);
}

static uint64_t INLINE_NEVER work_2lc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 266);
}

static uint64_t INLINE_NEVER work_2ld(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 267);
}

static uint64_t INLINE_NEVER work_2le(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 268);
}

static uint64_t INLINE_NEVER work_2lf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 269);
}

static uint64_t INLINE_NEVER work_2lg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 270);
}

static uint64_t INLINE_NEVER work_2lh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 271);
}

static uint64_t INLINE_NEVER work_2li(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 272);
}

static uint64_t INLINE_NEVER work_2lj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 273);
}

static uint64_t INLINE_NEVER work_2lk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 274);
}

static uint64_t INLINE_NEVER work_2ll(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 275);
}

static uint64_t INLINE_NEVER work_2lm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 276);
}

static uint64_t INLINE_NEVER work_2ln(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 277);
}

static uint64_t INLINE_NEVER work_2lo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 278);
}

static uint64_t INLINE_NEVER work_2lp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 279);
}

static uint64_t INLINE_NEVER work_2lq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 280);
}

static uint64_t INLINE_NEVER work_2lr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 281);
}

static uint64_t INLINE_NEVER work_2ls(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 282);
}

static uint64_t INLINE_NEVER work_2lt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 283);
}

static uint64_t INLINE_NEVER work_2lu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 284);
}

static uint64_t INLINE_NEVER work_2lv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 285);
}

static uint64_t INLINE_NEVER work_2lw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 286);
}

static uint64_t INLINE_NEVER work_2lx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 287);
}

static uint64_t INLINE_NEVER work_2ma(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 288);
}

static uint64_t INLINE_NEVER work_2mb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 289);
}

static uint64_t INLINE_NEVER work_2mc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 290);
}

static uint64_t INLINE_NEVER work_2md(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 291);
}

static uint64_t INLINE_NEVER work_2me(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 292);
}

static uint64_t INLINE_NEVER work_2mf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 293);
}

static uint64_t INLINE_NEVER work_2mg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 294);
}

static uint64_t INLINE_NEVER work_2mh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 295);
}

static uint64_t INLINE_NEVER work_2mi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 296);
}

static uint64_t INLINE_NEVER work_2mj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 297);
}

static uint64_t INLINE_NEVER work_2mk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 298);
}

static uint64_t INLINE_NEVER work_2ml(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 299);
}

static uint64_t INLINE_NEVER work_2mm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 300);
}

static uint64_t INLINE_NEVER work_2mn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 301);
}

static uint64_t INLINE_NEVER work_2mo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 302);
}

static uint64_t INLINE_NEVER work_2mp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 303);
}

static uint64_t INLINE_NEVER work_2mq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 304);
}

static uint64_t INLINE_NEVER work_2mr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 305);
}

static uint64_t INLINE_NEVER work_2ms(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 306);
}

static uint64_t INLINE_NEVER work_2mt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 307);
}

static uint64_t INLINE_NEVER work_2mu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 308);
}

static uint64_t INLINE_NEVER work_2mv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 309);
}

static uint64_t INLINE_NEVER work_2mw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 310);
}

static uint64_t INLINE_NEVER work_2mx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 311);
}

static uint64_t INLINE_NEVER work_2na(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 312);
}

static uint64_t INLINE_NEVER work_2nb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 313);
}

static uint64_t INLINE_NEVER work_2nc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 314);
}

static uint64_t INLINE_NEVER work_2nd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 315);
}

static uint64_t INLINE_NEVER work_2ne(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 316);
}

static uint64_t INLINE_NEVER work_2nf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 317);
}

static uint64_t INLINE_NEVER work_2ng(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 318);
}

static uint64_t INLINE_NEVER work_2nh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 319);
}

static uint64_t INLINE_NEVER work_2ni(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 320);
}

static uint64_t INLINE_NEVER work_2nj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 321);
}

static uint64_t INLINE_NEVER work_2nk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 322);
}

static uint64_t INLINE_NEVER work_2nl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 323);
}

static uint64_t INLINE_NEVER work_2nm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 324);
}

static uint64_t INLINE_NEVER work_2nn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 325);
}

static uint64_t INLINE_NEVER work_2no(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 326);
}

static uint64_t INLINE_NEVER work_2np(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 327);
}

static uint64_t INLINE_NEVER work_2nq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 328);
}

static uint64_t INLINE_NEVER work_2nr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 329);
}

static uint64_t INLINE_NEVER work_2ns(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 330);
}

static uint64_t INLINE_NEVER work_2nt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 331);
}

static uint64_t INLINE_NEVER work_2nu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 332);
}

static uint64_t INLINE_NEVER work_2nv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 333);
}

static uint64_t INLINE_NEVER work_2nw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 334);
}

static uint64_t INLINE_NEVER work_2nx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 335);
}

static uint64_t INLINE_NEVER work_2oa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 336);
}

static uint64_t INLINE_NEVER work_2ob(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 337);
}

static uint64_t INLINE_NEVER work_2oc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 338);
}

static uint64_t INLINE_NEVER work_2od(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 339);
}

static uint64_t INLINE_NEVER work_2oe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 340);
}

static uint64_t INLINE_NEVER work_2of(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 341);
}

static uint64_t INLINE_NEVER work_2og(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 342);
}

static uint64_t INLINE_NEVER work_2oh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 343);
}

static uint64_t INLINE_NEVER work_2oi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 344);
}

static uint64_t INLINE_NEVER work_2oj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 345);
}

static uint64_t INLINE_NEVER work_2ok(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 346);
}

static uint64_t INLINE_NEVER work_2ol(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 347);
}

static uint64_t INLINE_NEVER work_2om(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 348);
}

static uint64_t INLINE_NEVER work_2on(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 349);
}

static uint64_t INLINE_NEVER work_2oo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 350);
}

static uint64_t INLINE_NEVER work_2op(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 351);
}

static uint64_t INLINE_NEVER work_2oq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 352);
}

static uint64_t INLINE_NEVER work_2or(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 353);
}

static uint64_t INLINE_NEVER work_2os(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 354);
}

static uint64_t INLINE_NEVER work_2ot(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 355);
}

static uint64_t INLINE_NEVER work_2ou(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 356);
}

static uint64_t INLINE_NEVER work_2ov(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 357);
}

static uint64_t INLINE_NEVER work_2ow(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 358);
}

static uint64_t INLINE_NEVER work_2ox(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 359);
}

static uint64_t INLINE_NEVER work_2pa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 360);
}

static uint64_t INLINE_NEVER work_2pb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 361);
}

static uint64_t INLINE_NEVER work_2pc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 362);
}

static uint64_t INLINE_NEVER work_2pd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 363);
}

static uint64_t INLINE_NEVER work_2pe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 364);
}

static uint64_t INLINE_NEVER work_2pf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 365);
}

static uint64_t INLINE_NEVER work_2pg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 366);
}

static uint64_t INLINE_NEVER work_2ph(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 367);
}

static uint64_t INLINE_NEVER work_2pi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 368);
}

static uint64_t INLINE_NEVER work_2pj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 369);
}

static uint64_t INLINE_NEVER work_2pk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 370);
}

static uint64_t INLINE_NEVER work_2pl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 371);
}

static uint64_t INLINE_NEVER work_2pm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 372);
}

static uint64_t INLINE_NEVER work_2pn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 373);
}

static uint64_t INLINE_NEVER work_2po(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 374);
}

static uint64_t INLINE_NEVER work_2pp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 375);
}

static uint64_t INLINE_NEVER work_2pq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 376);
}

static uint64_t INLINE_NEVER work_2pr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 377);
}

static uint64_t INLINE_NEVER work_2ps(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 378);
}

static uint64_t INLINE_NEVER work_2pt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 379);
}

static uint64_t INLINE_NEVER work_2pu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 380);
}

static uint64_t INLINE_NEVER work_2pv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 381);
}

static uint64_t INLINE_NEVER work_2pw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 382);
}

static uint64_t INLINE_NEVER work_2px(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 383);
}

static uint64_t INLINE_NEVER work_2qa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 384);
}

static uint64_t INLINE_NEVER work_2qb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 385);
}

static uint64_t INLINE_NEVER work_2qc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 386);
}

static uint64_t INLINE_NEVER work_2qd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 387);
}

static uint64_t INLINE_NEVER work_2qe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 388);
}

static uint64_t INLINE_NEVER work_2qf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 389);
}

static uint64_t INLINE_NEVER work_2qg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 390);
}

static uint64_t INLINE_NEVER work_2qh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 391);
}

static uint64_t INLINE_NEVER work_2qi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 392);
}

static uint64_t INLINE_NEVER work_2qj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 393);
}

static uint64_t INLINE_NEVER work_2qk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 394);
}

static uint64_t INLINE_NEVER work_2ql(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 395);
}

static uint64_t INLINE_NEVER work_2qm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 396);
}

static uint64_t INLINE_NEVER work_2qn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 397);
}

static uint64_t INLINE_NEVER work_2qo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 398);
}

static uint64_t INLINE_NEVER work_2qp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 399);
}

static uint64_t INLINE_NEVER work_2qq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 400);
}

static uint64_t INLINE_NEVER work_2qr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 401);
}

static uint64_t INLINE_NEVER work_2qs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 402);
}

static uint64_t INLINE_NEVER work_2qt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 403);
}

static uint64_t INLINE_NEVER work_2qu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 404);
}

static uint64_t INLINE_NEVER work_2qv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 405);
}

static uint64_t INLINE_NEVER work_2qw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 406);
}

static uint64_t INLINE_NEVER work_2qx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 407);
}

static uint64_t INLINE_NEVER work_2ra(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 408);
}

static uint64_t INLINE_NEVER work_2rb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 409);
}

static uint64_t INLINE_NEVER work_2rc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 410);
}

static uint64_t INLINE_NEVER work_2rd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 411);
}

static uint64_t INLINE_NEVER work_2re(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 412);
}

static uint64_t INLINE_NEVER work_2rf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 413);
}

static uint64_t INLINE_NEVER work_2rg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 414);
}

static uint64_t INLINE_NEVER work_2rh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 415);
}

static uint64_t INLINE_NEVER work_2ri(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 416);
}

static uint64_t INLINE_NEVER work_2rj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 417);
}

static uint64_t INLINE_NEVER work_2rk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 418);
}

static uint64_t INLINE_NEVER work_2rl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 419);
}

static uint64_t INLINE_NEVER work_2rm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 420);
}

static uint64_t INLINE_NEVER work_2rn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 421);
}

static uint64_t INLINE_NEVER work_2ro(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 422);
}

static uint64_t INLINE_NEVER work_2rp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 423);
}

static uint64_t INLINE_NEVER work_2rq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 424);
}

static uint64_t INLINE_NEVER work_2rr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 425);
}

static uint64_t INLINE_NEVER work_2rs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 426);
}

static uint64_t INLINE_NEVER work_2rt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 427);
}

static uint64_t INLINE_NEVER work_2ru(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 428);
}

static uint64_t INLINE_NEVER work_2rv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 429);
}

static uint64_t INLINE_NEVER work_2rw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 430);
}

static uint64_t INLINE_NEVER work_2rx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 431);
}

static uint64_t INLINE_NEVER work_2sa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 432);
}

static uint64_t INLINE_NEVER work_2sb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 433);
}

static uint64_t INLINE_NEVER work_2sc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 434);
}

static uint64_t INLINE_NEVER work_2sd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 435);
}

static uint64_t INLINE_NEVER work_2se(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 436);
}

static uint64_t INLINE_NEVER work_2sf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 437);
}

static uint64_t INLINE_NEVER work_2sg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 438);
}

static uint64_t INLINE_NEVER work_2sh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 439);
}

static uint64_t INLINE_NEVER work_2si(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 440);
}

static uint64_t INLINE_NEVER work_2sj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 441);
}

static uint64_t INLINE_NEVER work_2sk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 442);
}

static uint64_t INLINE_NEVER work_2sl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 443);
}

static uint64_t INLINE_NEVER work_2sm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 444);
}

static uint64_t INLINE_NEVER work_2sn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 445);
}

static uint64_t INLINE_NEVER work_2so(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 446);
}

static uint64_t INLINE_NEVER work_2sp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 447);
}

static uint64_t INLINE_NEVER work_2sq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 448);
}

static uint64_t INLINE_NEVER work_2sr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 449);
}

static uint64_t INLINE_NEVER work_2ss(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 450);
}

static uint64_t INLINE_NEVER work_2st(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 451);
}

static uint64_t INLINE_NEVER work_2su(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 452);
}

static uint64_t INLINE_NEVER work_2sv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 453);
}

static uint64_t INLINE_NEVER work_2sw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 454);
}

static uint64_t INLINE_NEVER work_2sx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 455);
}

static uint64_t INLINE_NEVER work_2ta(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 456);
}

static uint64_t INLINE_NEVER work_2tb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 457);
}

static uint64_t INLINE_NEVER work_2tc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 458);
}

static uint64_t INLINE_NEVER work_2td(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 459);
}

static uint64_t INLINE_NEVER work_2te(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 460);
}

static uint64_t INLINE_NEVER work_2tf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 461);
}

static uint64_t INLINE_NEVER work_2tg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 462);
}

static uint64_t INLINE_NEVER work_2th(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 463);
}

static uint64_t INLINE_NEVER work_2ti(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 464);
}

static uint64_t INLINE_NEVER work_2tj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 465);
}

static uint64_t INLINE_NEVER work_2tk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 466);
}

static uint64_t INLINE_NEVER work_2tl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 467);
}

static uint64_t INLINE_NEVER work_2tm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 468);
}

static uint64_t INLINE_NEVER work_2tn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 469);
}

static uint64_t INLINE_NEVER work_2to(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 470);
}

static uint64_t INLINE_NEVER work_2tp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 471);
}

static uint64_t INLINE_NEVER work_2tq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 472);
}

static uint64_t INLINE_NEVER work_2tr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 473);
}

static uint64_t INLINE_NEVER work_2ts(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 474);
}

static uint64_t INLINE_NEVER work_2tt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 475);
}

static uint64_t INLINE_NEVER work_2tu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 476);
}

static uint64_t INLINE_NEVER work_2tv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 477);
}

static uint64_t INLINE_NEVER work_2tw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 478);
}

static uint64_t INLINE_NEVER work_2tx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 479);
}

static uint64_t INLINE_NEVER work_2ua(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 480);
}

static uint64_t INLINE_NEVER work_2ub(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 481);
}

static uint64_t INLINE_NEVER work_2uc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 482);
}

static uint64_t INLINE_NEVER work_2ud(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 483);
}

static uint64_t INLINE_NEVER work_2ue(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 484);
}

static uint64_t INLINE_NEVER work_2uf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 485);
}

static uint64_t INLINE_NEVER work_2ug(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 486);
}

static uint64_t INLINE_NEVER work_2uh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 487);
}

static uint64_t INLINE_NEVER work_2ui(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 488);
}

static uint64_t INLINE_NEVER work_2uj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 489);
}

static uint64_t INLINE_NEVER work_2uk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 490);
}

static uint64_t INLINE_NEVER work_2ul(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 491);
}

static uint64_t INLINE_NEVER work_2um(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 492);
}

static uint64_t INLINE_NEVER work_2un(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 493);
}

static uint64_t INLINE_NEVER work_2uo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 494);
}

static uint64_t INLINE_NEVER work_2up(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 495);
}

static uint64_t INLINE_NEVER work_2uq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 496);
}

static uint64_t INLINE_NEVER work_2ur(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 497);
}

static uint64_t INLINE_NEVER work_2us(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 498);
}

static uint64_t INLINE_NEVER work_2ut(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 499);
}

static uint64_t INLINE_NEVER work_2uu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 500);
}

static uint64_t INLINE_NEVER work_2uv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 501);
}

static uint64_t INLINE_NEVER work_2uw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 502);
}

static uint64_t INLINE_NEVER work_2ux(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 503);
}

static uint64_t INLINE_NEVER work_2va(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 504);
}

static uint64_t INLINE_NEVER work_2vb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 505);
}

static uint64_t INLINE_NEVER work_2vc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 506);
}

static uint64_t INLINE_NEVER work_2vd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 507);
}

static uint64_t INLINE_NEVER work_2ve(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 508);
}

static uint64_t INLINE_NEVER work_2vf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 509);
}

static uint64_t INLINE_NEVER work_2vg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 510);
}

static uint64_t INLINE_NEVER work_2vh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 511);
}

static uint64_t INLINE_NEVER work_2vi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 512);
}

static uint64_t INLINE_NEVER work_2vj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 513);
}

static uint64_t INLINE_NEVER work_2vk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 514);
}

static uint64_t INLINE_NEVER work_2vl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 515);
}

static uint64_t INLINE_NEVER work_2vm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 516);
}

static uint64_t INLINE_NEVER work_2vn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 517);
}

static uint64_t INLINE_NEVER work_2vo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 518);
}

static uint64_t INLINE_NEVER work_2vp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 519);
}

static uint64_t INLINE_NEVER work_2vq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 520);
}

static uint64_t INLINE_NEVER work_2vr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 521);
}

static uint64_t INLINE_NEVER work_2vs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 522);
}

static uint64_t INLINE_NEVER work_2vt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 523);
}

static uint64_t INLINE_NEVER work_2vu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 524);
}

static uint64_t INLINE_NEVER work_2vv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 525);
}

static uint64_t INLINE_NEVER work_2vw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 526);
}

static uint64_t INLINE_NEVER work_2vx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 527);
}

static uint64_t INLINE_NEVER work_2wa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 528);
}

static uint64_t INLINE_NEVER work_2wb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 529);
}

static uint64_t INLINE_NEVER work_2wc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 530);
}

static uint64_t INLINE_NEVER work_2wd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 531);
}

static uint64_t INLINE_NEVER work_2we(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 532);
}

static uint64_t INLINE_NEVER work_2wf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 533);
}

static uint64_t INLINE_NEVER work_2wg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 534);
}

static uint64_t INLINE_NEVER work_2wh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 535);
}

static uint64_t INLINE_NEVER work_2wi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 536);
}

static uint64_t INLINE_NEVER work_2wj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 537);
}

static uint64_t INLINE_NEVER work_2wk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 538);
}

static uint64_t INLINE_NEVER work_2wl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 539);
}

static uint64_t INLINE_NEVER work_2wm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 540);
}

static uint64_t INLINE_NEVER work_2wn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 541);
}

static uint64_t INLINE_NEVER work_2wo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 542);
}

static uint64_t INLINE_NEVER work_2wp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 543);
}

static uint64_t INLINE_NEVER work_2wq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 544);
}

static uint64_t INLINE_NEVER work_2wr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 545);
}

static uint64_t INLINE_NEVER work_2ws(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 546);
}

static uint64_t INLINE_NEVER work_2wt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 547);
}

static uint64_t INLINE_NEVER work_2wu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 548);
}

static uint64_t INLINE_NEVER work_2wv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 549);
}

static uint64_t INLINE_NEVER work_2ww(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 550);
}

static uint64_t INLINE_NEVER work_2wx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 551);
}

static uint64_t INLINE_NEVER work_2xa(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 552);
}

static uint64_t INLINE_NEVER work_2xb(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 553);
}

static uint64_t INLINE_NEVER work_2xc(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 554);
}

static uint64_t INLINE_NEVER work_2xd(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 555);
}

static uint64_t INLINE_NEVER work_2xe(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 556);
}

static uint64_t INLINE_NEVER work_2xf(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 557);
}

static uint64_t INLINE_NEVER work_2xg(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 558);
}

static uint64_t INLINE_NEVER work_2xh(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 559);
}

static uint64_t INLINE_NEVER work_2xi(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 560);
}

static uint64_t INLINE_NEVER work_2xj(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 561);
}

static uint64_t INLINE_NEVER work_2xk(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 562);
}

static uint64_t INLINE_NEVER work_2xl(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 563);
}

static uint64_t INLINE_NEVER work_2xm(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 564);
}

static uint64_t INLINE_NEVER work_2xn(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 565);
}

static uint64_t INLINE_NEVER work_2xo(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 566);
}

static uint64_t INLINE_NEVER work_2xp(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 567);
}

static uint64_t INLINE_NEVER work_2xq(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 568);
}

static uint64_t INLINE_NEVER work_2xr(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 569);
}

static uint64_t INLINE_NEVER work_2xs(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 570);
}

static uint64_t INLINE_NEVER work_2xt(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 571);
}

static uint64_t INLINE_NEVER work_2xu(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 572);
}

static uint64_t INLINE_NEVER work_2xv(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 573);
}

static uint64_t INLINE_NEVER work_2xw(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 574);
}

static uint64_t INLINE_NEVER work_2xx(uint64_t a, uint32_t *b, uint32_t *c)
{
	return WORK_2(a, b, c, 575);
}

static work_2_fn_t work_2[] = {
	work_2aa, work_2ab, work_2ac, work_2ad, work_2ae, work_2af, work_2ag, work_2ah,
	work_2ai, work_2aj, work_2ak, work_2al, work_2am, work_2an, work_2ao, work_2ap,
	work_2aq, work_2ar, work_2as, work_2at, work_2au, work_2av, work_2aw, work_2ax,
	work_2ba, work_2bb, work_2bc, work_2bd, work_2be, work_2bf, work_2bg, work_2bh,
	work_2bi, work_2bj, work_2bk, work_2bl, work_2bm, work_2bn, work_2bo, work_2bp,
	work_2bq, work_2br, work_2bs, work_2bt, work_2bu, work_2bv, work_2bw, work_2bx,
	work_2ca, work_2cb, work_2cc, work_2cd, work_2ce, work_2cf, work_2cg, work_2ch,
	work_2ci, work_2cj, work_2ck, work_2cl, work_2cm, work_2cn, work_2co, work_2cp,
	work_2cq, work_2cr, work_2cs, work_2ct, work_2cu, work_2cv, work_2cw, work_2cx,
	work_2da, work_2db, work_2dc, work_2dd, work_2de, work_2df, work_2dg, work_2dh,
	work_2di, work_2dj, work_2dk, work_2dl, work_2dm, work_2dn, work_2do, work_2dp,
	work_2dq, work_2dr, work_2ds, work_2dt, work_2du, work_2dv, work_2dw, work_2dx,
	work_2ea, work_2eb, work_2ec, work_2ed, work_2ee, work_2ef, work_2eg, work_2eh,
	work_2ei, work_2ej, work_2ek, work_2el, work_2em, work_2en, work_2eo, work_2ep,
	work_2eq, work_2er, work_2es, work_2et, work_2eu, work_2ev, work_2ew, work_2ex,
	work_2fa, work_2fb, work_2fc, work_2fd, work_2fe, work_2ff, work_2fg, work_2fh,
	work_2fi, work_2fj, work_2fk, work_2fl, work_2fm, work_2fn, work_2fo, work_2fp,
	work_2fq, work_2fr, work_2fs, work_2ft, work_2fu, work_2fv, work_2fw, work_2fx,
	work_2ga, work_2gb, work_2gc, work_2gd, work_2ge, work_2gf, work_2gg, work_2gh,
	work_2gi, work_2gj, work_2gk, work_2gl, work_2gm, work_2gn, work_2go, work_2gp,
	work_2gq, work_2gr, work_2gs, work_2gt, work_2gu, work_2gv, work_2gw, work_2gx,
	work_2ha, work_2hb, work_2hc, work_2hd, work_2he, work_2hf, work_2hg, work_2hh,
	work_2hi, work_2hj, work_2hk, work_2hl, work_2hm, work_2hn, work_2ho, work_2hp,
	work_2hq, work_2hr, work_2hs, work_2ht, work_2hu, work_2hv, work_2hw, work_2hx,
	work_2ia, work_2ib, work_2ic, work_2id, work_2ie, work_2if, work_2ig, work_2ih,
	work_2ii, work_2ij, work_2ik, work_2il, work_2im, work_2in, work_2io, work_2ip,
	work_2iq, work_2ir, work_2is, work_2it, work_2iu, work_2iv, work_2iw, work_2ix,
	work_2ja, work_2jb, work_2jc, work_2jd, work_2je, work_2jf, work_2jg, work_2jh,
	work_2ji, work_2jj, work_2jk, work_2jl, work_2jm, work_2jn, work_2jo, work_2jp,
	work_2jq, work_2jr, work_2js, work_2jt, work_2ju, work_2jv, work_2jw, work_2jx,
	work_2ka, work_2kb, work_2kc, work_2kd, work_2ke, work_2kf, work_2kg, work_2kh,
	work_2ki, work_2kj, work_2kk, work_2kl, work_2km, work_2kn, work_2ko, work_2kp,
	work_2kq, work_2kr, work_2ks, work_2kt, work_2ku, work_2kv, work_2kw, work_2kx,
	work_2la, work_2lb, work_2lc, work_2ld, work_2le, work_2lf, work_2lg, work_2lh,
	work_2li, work_2lj, work_2lk, work_2ll, work_2lm, work_2ln, work_2lo, work_2lp,
	work_2lq, work_2lr, work_2ls, work_2lt, work_2lu, work_2lv, work_2lw, work_2lx,
	work_2ma, work_2mb, work_2mc, work_2md, work_2me, work_2mf, work_2mg, work_2mh,
	work_2mi, work_2mj, work_2mk, work_2ml, work_2mm, work_2mn, work_2mo, work_2mp,
	work_2mq, work_2mr, work_2ms, work_2mt, work_2mu, work_2mv, work_2mw, work_2mx,
	work_2na, work_2nb, work_2nc, work_2nd, work_2ne, work_2nf, work_2ng, work_2nh,
	work_2ni, work_2nj, work_2nk, work_2nl, work_2nm, work_2nn, work_2no, work_2np,
	work_2nq, work_2nr, work_2ns, work_2nt, work_2nu, work_2nv, work_2nw, work_2nx,
	work_2oa, work_2ob, work_2oc, work_2od, work_2oe, work_2of, work_2og, work_2oh,
	work_2oi, work_2oj, work_2ok, work_2ol, work_2om, work_2on, work_2oo, work_2op,
	work_2oq, work_2or, work_2os, work_2ot, work_2ou, work_2ov, work_2ow, work_2ox,
	work_2pa, work_2pb, work_2pc, work_2pd, work_2pe, work_2pf, work_2pg, work_2ph,
	work_2pi, work_2pj, work_2pk, work_2pl, work_2pm, work_2pn, work_2po, work_2pp,
	work_2pq, work_2pr, work_2ps, work_2pt, work_2pu, work_2pv, work_2pw, work_2px,
	work_2qa, work_2qb, work_2qc, work_2qd, work_2qe, work_2qf, work_2qg, work_2qh,
	work_2qi, work_2qj, work_2qk, work_2ql, work_2qm, work_2qn, work_2qo, work_2qp,
	work_2qq, work_2qr, work_2qs, work_2qt, work_2qu, work_2qv, work_2qw, work_2qx,
	work_2ra, work_2rb, work_2rc, work_2rd, work_2re, work_2rf, work_2rg, work_2rh,
	work_2ri, work_2rj, work_2rk, work_2rl, work_2rm, work_2rn, work_2ro, work_2rp,
	work_2rq, work_2rr, work_2rs, work_2rt, work_2ru, work_2rv, work_2rw, work_2rx,
	work_2sa, work_2sb, work_2sc, work_2sd, work_2se, work_2sf, work_2sg, work_2sh,
	work_2si, work_2sj, work_2sk, work_2sl, work_2sm, work_2sn, work_2so, work_2sp,
	work_2sq, work_2sr, work_2ss, work_2st, work_2su, work_2sv, work_2sw, work_2sx,
	work_2ta, work_2tb, work_2tc, work_2td, work_2te, work_2tf, work_2tg, work_2th,
	work_2ti, work_2tj, work_2tk, work_2tl, work_2tm, work_2tn, work_2to, work_2tp,
	work_2tq, work_2tr, work_2ts, work_2tt, work_2tu, work_2tv, work_2tw, work_2tx,
	work_2ua, work_2ub, work_2uc, work_2ud, work_2ue, work_2uf, work_2ug, work_2uh,
	work_2ui, work_2uj, work_2uk, work_2ul, work_2um, work_2un, work_2uo, work_2up,
	work_2uq, work_2ur, work_2us, work_2ut, work_2uu, work_2uv, work_2uw, work_2ux,
	work_2va, work_2vb, work_2vc, work_2vd, work_2ve, work_2vf, work_2vg, work_2vh,
	work_2vi, work_2vj, work_2vk, work_2vl, work_2vm, work_2vn, work_2vo, work_2vp,
	work_2vq, work_2vr, work_2vs, work_2vt, work_2vu, work_2vv, work_2vw, work_2vx,
	work_2wa, work_2wb, work_2wc, work_2wd, work_2we, work_2wf, work_2wg, work_2wh,
	work_2wi, work_2wj, work_2wk, work_2wl, work_2wm, work_2wn, work_2wo, work_2wp,
	work_2wq, work_2wr, work_2ws, work_2wt, work_2wu, work_2wv, work_2ww, work_2wx,
	work_2xa, work_2xb, work_2xc, work_2xd, work_2xe, work_2xf, work_2xg, work_2xh,
	work_2xi, work_2xj, work_2xk, work_2xl, work_2xm, work_2xn, work_2xo, work_2xp,
	work_2xq, work_2xr, work_2xs, work_2xt, work_2xu, work_2xv, work_2xw, work_2xx
};

static uint16_t work_2_rnd[] = {
	 11, 493, 534,  99, 120, 162, 507, 221, 423, 356, 188, 174, 167, 106, 280,  73,
	322, 535, 146, 559, 157, 263,  83,  22, 436,  95, 117, 554, 563, 426, 369, 485,
	182, 353, 254, 545,   8,  63, 470, 569, 226, 239, 192, 557, 435,  82, 500, 471,
	211, 458,  97, 294,  20, 347,  26, 240, 300, 454, 561, 564, 126, 136, 148,  30,
	 24,  39, 512, 309,   0, 116, 222, 159, 376, 465, 198, 141, 403, 537,  58,  35,
	 69, 538, 552, 544, 187, 291,  91, 482, 299,   6, 197, 451,  31, 519, 287, 326,
	229, 393, 275, 185,  43, 360, 147, 112, 379,  65,  57, 358, 290, 355, 138, 527,
	104, 464, 442, 179, 468, 206, 548, 427, 319, 107, 219, 491, 304, 279, 459, 530,
	218, 521,  15, 387, 115, 556,  49, 496, 340, 380, 446, 422, 501, 528, 139,   4,
	418, 242, 195, 566, 302, 483, 342,  64,   9,  13, 508, 440, 511, 420, 344, 513,
	571,  10, 489, 151, 332, 394,  76, 476, 498, 134, 170,  37, 180, 443,   3,  18,
	520, 278, 518, 499, 346, 205,  41, 270, 215, 510,  50, 129, 378,  67, 409, 408,
	312, 480,  44, 541, 495, 109, 424, 301, 124, 214, 305,  38,  19, 490, 486, 232,
	248, 526, 310, 234, 574, 542, 529, 318,  16, 246, 425, 213, 391, 143, 406,  89,
	256, 233, 306, 227, 208, 119,  80, 502, 103, 373, 271, 276, 131, 377,  51, 101,
	317, 522, 516, 497, 311, 430, 374, 477, 295, 257,  71,  34, 132, 531, 368,  25,
	547, 396,  96, 441,  45, 111, 449, 252,  60, 517,  87, 334, 388, 191, 550, 463,
	 72, 438, 385,  54,  42, 536,  29, 202, 203, 404, 484, 236, 183, 150, 412, 474,
	161, 515, 193, 244,  74, 308, 572, 133, 163, 573, 558, 549, 467, 225, 283, 481,
	265, 434, 281, 145, 509, 144, 456, 479, 450, 241, 212,  53, 343, 190,  12,   5,
	259,  40, 324, 247,  93, 363, 348, 354,  47, 384, 386, 100, 327, 568, 472, 175,
	303, 160,  21, 267, 296, 260, 335, 445, 492, 466, 371, 165,  79, 457, 565, 382,
	217, 361, 122, 399,  55, 339, 523, 178,  70, 274, 411, 102, 114, 243, 453, 525,
	539,  98, 207, 210, 341, 359, 228, 292, 273, 488, 351, 415,  81, 365, 416, 282,
	444, 285, 469, 108, 402, 186, 349,   1, 437, 337, 224, 220, 357, 543, 184, 478,
	505,   2,  78, 506, 125, 532, 250, 475, 249, 168, 421, 323, 460,  68, 439,  86,
	330, 173, 397, 105, 432, 524,  61, 128, 375, 216, 389, 142, 268,  84, 199,  14,
	514, 235, 284, 328, 414, 164, 238,  52, 130, 127, 269, 123, 390, 333, 194, 494,
	237, 372, 315, 433, 110, 209, 156, 383,  75,  62, 392, 137, 152, 155, 419,  48,
	 88, 118, 171, 177,  33, 135, 336, 462, 277, 567, 398,  94, 204, 298,  85, 429,
	321, 540, 487, 201,  23, 158, 230, 258, 401, 262, 455, 251,  27, 407, 473, 289,
	166, 314, 381, 176, 417,  92, 266, 121, 196,  66, 575,  36,  56, 316, 153, 320,
	546, 364, 367, 452, 413, 503, 350, 245, 362, 313, 264,  59, 272, 286, 370,   7,
	181, 331, 113, 395, 223, 570, 338, 447, 366, 562, 325, 405, 400,  17, 288, 461,
	307, 200,  32, 154, 345, 428, 189, 293, 533, 172,  46,  77, 410, 431,  28, 555,
	149, 297, 352, 448, 504,  90, 261, 253, 140, 169, 231, 560, 553, 329, 551, 255
};

static uint64_t INLINE_NEVER work_3aa(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 0);
}

static uint64_t INLINE_NEVER work_3ab(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 1);
}

static uint64_t INLINE_NEVER work_3ac(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 2);
}

static uint64_t INLINE_NEVER work_3ad(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 3);
}

static uint64_t INLINE_NEVER work_3ae(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 4);
}

static uint64_t INLINE_NEVER work_3af(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 5);
}

static uint64_t INLINE_NEVER work_3ag(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 6);
}

static uint64_t INLINE_NEVER work_3ah(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 7);
}

static uint64_t INLINE_NEVER work_3ai(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 8);
}

static uint64_t INLINE_NEVER work_3aj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 9);
}

static uint64_t INLINE_NEVER work_3ak(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 10);
}

static uint64_t INLINE_NEVER work_3al(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 11);
}

static uint64_t INLINE_NEVER work_3am(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 12);
}

static uint64_t INLINE_NEVER work_3an(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 13);
}

static uint64_t INLINE_NEVER work_3ao(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 14);
}

static uint64_t INLINE_NEVER work_3ap(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 15);
}

static uint64_t INLINE_NEVER work_3aq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 16);
}

static uint64_t INLINE_NEVER work_3ar(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 17);
}

static uint64_t INLINE_NEVER work_3as(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 18);
}

static uint64_t INLINE_NEVER work_3at(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 19);
}

static uint64_t INLINE_NEVER work_3au(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 20);
}

static uint64_t INLINE_NEVER work_3av(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 21);
}

static uint64_t INLINE_NEVER work_3aw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 22);
}

static uint64_t INLINE_NEVER work_3ax(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 23);
}

static uint64_t INLINE_NEVER work_3ba(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 24);
}

static uint64_t INLINE_NEVER work_3bb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 25);
}

static uint64_t INLINE_NEVER work_3bc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 26);
}

static uint64_t INLINE_NEVER work_3bd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 27);
}

static uint64_t INLINE_NEVER work_3be(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 28);
}

static uint64_t INLINE_NEVER work_3bf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 29);
}

static uint64_t INLINE_NEVER work_3bg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 30);
}

static uint64_t INLINE_NEVER work_3bh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 31);
}

static uint64_t INLINE_NEVER work_3bi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 32);
}

static uint64_t INLINE_NEVER work_3bj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 33);
}

static uint64_t INLINE_NEVER work_3bk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 34);
}

static uint64_t INLINE_NEVER work_3bl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 35);
}

static uint64_t INLINE_NEVER work_3bm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 36);
}

static uint64_t INLINE_NEVER work_3bn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 37);
}

static uint64_t INLINE_NEVER work_3bo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 38);
}

static uint64_t INLINE_NEVER work_3bp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 39);
}

static uint64_t INLINE_NEVER work_3bq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 40);
}

static uint64_t INLINE_NEVER work_3br(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 41);
}

static uint64_t INLINE_NEVER work_3bs(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 42);
}

static uint64_t INLINE_NEVER work_3bt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 43);
}

static uint64_t INLINE_NEVER work_3bu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 44);
}

static uint64_t INLINE_NEVER work_3bv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 45);
}

static uint64_t INLINE_NEVER work_3bw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 46);
}

static uint64_t INLINE_NEVER work_3bx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 47);
}

static uint64_t INLINE_NEVER work_3ca(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 48);
}

static uint64_t INLINE_NEVER work_3cb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 49);
}

static uint64_t INLINE_NEVER work_3cc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 50);
}

static uint64_t INLINE_NEVER work_3cd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 51);
}

static uint64_t INLINE_NEVER work_3ce(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 52);
}

static uint64_t INLINE_NEVER work_3cf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 53);
}

static uint64_t INLINE_NEVER work_3cg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 54);
}

static uint64_t INLINE_NEVER work_3ch(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 55);
}

static uint64_t INLINE_NEVER work_3ci(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 56);
}

static uint64_t INLINE_NEVER work_3cj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 57);
}

static uint64_t INLINE_NEVER work_3ck(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 58);
}

static uint64_t INLINE_NEVER work_3cl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 59);
}

static uint64_t INLINE_NEVER work_3cm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 60);
}

static uint64_t INLINE_NEVER work_3cn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 61);
}

static uint64_t INLINE_NEVER work_3co(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 62);
}

static uint64_t INLINE_NEVER work_3cp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 63);
}

static uint64_t INLINE_NEVER work_3cq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 64);
}

static uint64_t INLINE_NEVER work_3cr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 65);
}

static uint64_t INLINE_NEVER work_3cs(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 66);
}

static uint64_t INLINE_NEVER work_3ct(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 67);
}

static uint64_t INLINE_NEVER work_3cu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 68);
}

static uint64_t INLINE_NEVER work_3cv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 69);
}

static uint64_t INLINE_NEVER work_3cw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 70);
}

static uint64_t INLINE_NEVER work_3cx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 71);
}

static uint64_t INLINE_NEVER work_3da(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 72);
}

static uint64_t INLINE_NEVER work_3db(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 73);
}

static uint64_t INLINE_NEVER work_3dc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 74);
}

static uint64_t INLINE_NEVER work_3dd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 75);
}

static uint64_t INLINE_NEVER work_3de(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 76);
}

static uint64_t INLINE_NEVER work_3df(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 77);
}

static uint64_t INLINE_NEVER work_3dg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 78);
}

static uint64_t INLINE_NEVER work_3dh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 79);
}

static uint64_t INLINE_NEVER work_3di(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 80);
}

static uint64_t INLINE_NEVER work_3dj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 81);
}

static uint64_t INLINE_NEVER work_3dk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 82);
}

static uint64_t INLINE_NEVER work_3dl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 83);
}

static uint64_t INLINE_NEVER work_3dm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 84);
}

static uint64_t INLINE_NEVER work_3dn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 85);
}

static uint64_t INLINE_NEVER work_3do(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 86);
}

static uint64_t INLINE_NEVER work_3dp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 87);
}

static uint64_t INLINE_NEVER work_3dq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 88);
}

static uint64_t INLINE_NEVER work_3dr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 89);
}

static uint64_t INLINE_NEVER work_3ds(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 90);
}

static uint64_t INLINE_NEVER work_3dt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 91);
}

static uint64_t INLINE_NEVER work_3du(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 92);
}

static uint64_t INLINE_NEVER work_3dv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 93);
}

static uint64_t INLINE_NEVER work_3dw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 94);
}

static uint64_t INLINE_NEVER work_3dx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 95);
}

static uint64_t INLINE_NEVER work_3ea(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 96);
}

static uint64_t INLINE_NEVER work_3eb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 97);
}

static uint64_t INLINE_NEVER work_3ec(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 98);
}

static uint64_t INLINE_NEVER work_3ed(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 99);
}

static uint64_t INLINE_NEVER work_3ee(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 100);
}

static uint64_t INLINE_NEVER work_3ef(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 101);
}

static uint64_t INLINE_NEVER work_3eg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 102);
}

static uint64_t INLINE_NEVER work_3eh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 103);
}

static uint64_t INLINE_NEVER work_3ei(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 104);
}

static uint64_t INLINE_NEVER work_3ej(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 105);
}

static uint64_t INLINE_NEVER work_3ek(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 106);
}

static uint64_t INLINE_NEVER work_3el(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 107);
}

static uint64_t INLINE_NEVER work_3em(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 108);
}

static uint64_t INLINE_NEVER work_3en(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 109);
}

static uint64_t INLINE_NEVER work_3eo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 110);
}

static uint64_t INLINE_NEVER work_3ep(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 111);
}

static uint64_t INLINE_NEVER work_3eq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 112);
}

static uint64_t INLINE_NEVER work_3er(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 113);
}

static uint64_t INLINE_NEVER work_3es(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 114);
}

static uint64_t INLINE_NEVER work_3et(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 115);
}

static uint64_t INLINE_NEVER work_3eu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 116);
}

static uint64_t INLINE_NEVER work_3ev(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 117);
}

static uint64_t INLINE_NEVER work_3ew(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 118);
}

static uint64_t INLINE_NEVER work_3ex(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 119);
}

static uint64_t INLINE_NEVER work_3fa(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 120);
}

static uint64_t INLINE_NEVER work_3fb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 121);
}

static uint64_t INLINE_NEVER work_3fc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 122);
}

static uint64_t INLINE_NEVER work_3fd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 123);
}

static uint64_t INLINE_NEVER work_3fe(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 124);
}

static uint64_t INLINE_NEVER work_3ff(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 125);
}

static uint64_t INLINE_NEVER work_3fg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 126);
}

static uint64_t INLINE_NEVER work_3fh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 127);
}

static uint64_t INLINE_NEVER work_3fi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 128);
}

static uint64_t INLINE_NEVER work_3fj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 129);
}

static uint64_t INLINE_NEVER work_3fk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 130);
}

static uint64_t INLINE_NEVER work_3fl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 131);
}

static uint64_t INLINE_NEVER work_3fm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 132);
}

static uint64_t INLINE_NEVER work_3fn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 133);
}

static uint64_t INLINE_NEVER work_3fo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 134);
}

static uint64_t INLINE_NEVER work_3fp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 135);
}

static uint64_t INLINE_NEVER work_3fq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 136);
}

static uint64_t INLINE_NEVER work_3fr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 137);
}

static uint64_t INLINE_NEVER work_3fs(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 138);
}

static uint64_t INLINE_NEVER work_3ft(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 139);
}

static uint64_t INLINE_NEVER work_3fu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 140);
}

static uint64_t INLINE_NEVER work_3fv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 141);
}

static uint64_t INLINE_NEVER work_3fw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 142);
}

static uint64_t INLINE_NEVER work_3fx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 143);
}

static uint64_t INLINE_NEVER work_3ga(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 144);
}

static uint64_t INLINE_NEVER work_3gb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 145);
}

static uint64_t INLINE_NEVER work_3gc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 146);
}

static uint64_t INLINE_NEVER work_3gd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 147);
}

static uint64_t INLINE_NEVER work_3ge(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 148);
}

static uint64_t INLINE_NEVER work_3gf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 149);
}

static uint64_t INLINE_NEVER work_3gg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 150);
}

static uint64_t INLINE_NEVER work_3gh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 151);
}

static uint64_t INLINE_NEVER work_3gi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 152);
}

static uint64_t INLINE_NEVER work_3gj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 153);
}

static uint64_t INLINE_NEVER work_3gk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 154);
}

static uint64_t INLINE_NEVER work_3gl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 155);
}

static uint64_t INLINE_NEVER work_3gm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 156);
}

static uint64_t INLINE_NEVER work_3gn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 157);
}

static uint64_t INLINE_NEVER work_3go(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 158);
}

static uint64_t INLINE_NEVER work_3gp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 159);
}

static uint64_t INLINE_NEVER work_3gq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 160);
}

static uint64_t INLINE_NEVER work_3gr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 161);
}

static uint64_t INLINE_NEVER work_3gs(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 162);
}

static uint64_t INLINE_NEVER work_3gt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 163);
}

static uint64_t INLINE_NEVER work_3gu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 164);
}

static uint64_t INLINE_NEVER work_3gv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 165);
}

static uint64_t INLINE_NEVER work_3gw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 166);
}

static uint64_t INLINE_NEVER work_3gx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 167);
}

static uint64_t INLINE_NEVER work_3ha(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 168);
}

static uint64_t INLINE_NEVER work_3hb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 169);
}

static uint64_t INLINE_NEVER work_3hc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 170);
}

static uint64_t INLINE_NEVER work_3hd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 171);
}

static uint64_t INLINE_NEVER work_3he(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 172);
}

static uint64_t INLINE_NEVER work_3hf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 173);
}

static uint64_t INLINE_NEVER work_3hg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 174);
}

static uint64_t INLINE_NEVER work_3hh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 175);
}

static uint64_t INLINE_NEVER work_3hi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 176);
}

static uint64_t INLINE_NEVER work_3hj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 177);
}

static uint64_t INLINE_NEVER work_3hk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 178);
}

static uint64_t INLINE_NEVER work_3hl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 179);
}

static uint64_t INLINE_NEVER work_3hm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 180);
}

static uint64_t INLINE_NEVER work_3hn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 181);
}

static uint64_t INLINE_NEVER work_3ho(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 182);
}

static uint64_t INLINE_NEVER work_3hp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 183);
}

static uint64_t INLINE_NEVER work_3hq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 184);
}

static uint64_t INLINE_NEVER work_3hr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 185);
}

static uint64_t INLINE_NEVER work_3hs(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 186);
}

static uint64_t INLINE_NEVER work_3ht(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 187);
}

static uint64_t INLINE_NEVER work_3hu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 188);
}

static uint64_t INLINE_NEVER work_3hv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 189);
}

static uint64_t INLINE_NEVER work_3hw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 190);
}

static uint64_t INLINE_NEVER work_3hx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 191);
}

static uint64_t INLINE_NEVER work_3ia(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 192);
}

static uint64_t INLINE_NEVER work_3ib(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 193);
}

static uint64_t INLINE_NEVER work_3ic(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 194);
}

static uint64_t INLINE_NEVER work_3id(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 195);
}

static uint64_t INLINE_NEVER work_3ie(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 196);
}

static uint64_t INLINE_NEVER work_3if(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 197);
}

static uint64_t INLINE_NEVER work_3ig(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 198);
}

static uint64_t INLINE_NEVER work_3ih(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 199);
}

static uint64_t INLINE_NEVER work_3ii(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 200);
}

static uint64_t INLINE_NEVER work_3ij(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 201);
}

static uint64_t INLINE_NEVER work_3ik(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 202);
}

static uint64_t INLINE_NEVER work_3il(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 203);
}

static uint64_t INLINE_NEVER work_3im(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 204);
}

static uint64_t INLINE_NEVER work_3in(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 205);
}

static uint64_t INLINE_NEVER work_3io(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 206);
}

static uint64_t INLINE_NEVER work_3ip(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 207);
}

static uint64_t INLINE_NEVER work_3iq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 208);
}

static uint64_t INLINE_NEVER work_3ir(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 209);
}

static uint64_t INLINE_NEVER work_3is(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 210);
}

static uint64_t INLINE_NEVER work_3it(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 211);
}

static uint64_t INLINE_NEVER work_3iu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 212);
}

static uint64_t INLINE_NEVER work_3iv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 213);
}

static uint64_t INLINE_NEVER work_3iw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 214);
}

static uint64_t INLINE_NEVER work_3ix(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 215);
}

static uint64_t INLINE_NEVER work_3ja(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 216);
}

static uint64_t INLINE_NEVER work_3jb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 217);
}

static uint64_t INLINE_NEVER work_3jc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 218);
}

static uint64_t INLINE_NEVER work_3jd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 219);
}

static uint64_t INLINE_NEVER work_3je(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 220);
}

static uint64_t INLINE_NEVER work_3jf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 221);
}

static uint64_t INLINE_NEVER work_3jg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 222);
}

static uint64_t INLINE_NEVER work_3jh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 223);
}

static uint64_t INLINE_NEVER work_3ji(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 224);
}

static uint64_t INLINE_NEVER work_3jj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 225);
}

static uint64_t INLINE_NEVER work_3jk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 226);
}

static uint64_t INLINE_NEVER work_3jl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 227);
}

static uint64_t INLINE_NEVER work_3jm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 228);
}

static uint64_t INLINE_NEVER work_3jn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 229);
}

static uint64_t INLINE_NEVER work_3jo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 230);
}

static uint64_t INLINE_NEVER work_3jp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 231);
}

static uint64_t INLINE_NEVER work_3jq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 232);
}

static uint64_t INLINE_NEVER work_3jr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 233);
}

static uint64_t INLINE_NEVER work_3js(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 234);
}

static uint64_t INLINE_NEVER work_3jt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 235);
}

static uint64_t INLINE_NEVER work_3ju(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 236);
}

static uint64_t INLINE_NEVER work_3jv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 237);
}

static uint64_t INLINE_NEVER work_3jw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 238);
}

static uint64_t INLINE_NEVER work_3jx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 239);
}

static uint64_t INLINE_NEVER work_3ka(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 240);
}

static uint64_t INLINE_NEVER work_3kb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 241);
}

static uint64_t INLINE_NEVER work_3kc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 242);
}

static uint64_t INLINE_NEVER work_3kd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 243);
}

static uint64_t INLINE_NEVER work_3ke(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 244);
}

static uint64_t INLINE_NEVER work_3kf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 245);
}

static uint64_t INLINE_NEVER work_3kg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 246);
}

static uint64_t INLINE_NEVER work_3kh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 247);
}

static uint64_t INLINE_NEVER work_3ki(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 248);
}

static uint64_t INLINE_NEVER work_3kj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 249);
}

static uint64_t INLINE_NEVER work_3kk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 250);
}

static uint64_t INLINE_NEVER work_3kl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 251);
}

static uint64_t INLINE_NEVER work_3km(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 252);
}

static uint64_t INLINE_NEVER work_3kn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 253);
}

static uint64_t INLINE_NEVER work_3ko(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 254);
}

static uint64_t INLINE_NEVER work_3kp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 255);
}

static uint64_t INLINE_NEVER work_3kq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 256);
}

static uint64_t INLINE_NEVER work_3kr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 257);
}

static uint64_t INLINE_NEVER work_3ks(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 258);
}

static uint64_t INLINE_NEVER work_3kt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 259);
}

static uint64_t INLINE_NEVER work_3ku(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 260);
}

static uint64_t INLINE_NEVER work_3kv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 261);
}

static uint64_t INLINE_NEVER work_3kw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 262);
}

static uint64_t INLINE_NEVER work_3kx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 263);
}

static uint64_t INLINE_NEVER work_3la(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 264);
}

static uint64_t INLINE_NEVER work_3lb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 265);
}

static uint64_t INLINE_NEVER work_3lc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 266);
}

static uint64_t INLINE_NEVER work_3ld(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 267);
}

static uint64_t INLINE_NEVER work_3le(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 268);
}

static uint64_t INLINE_NEVER work_3lf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 269);
}

static uint64_t INLINE_NEVER work_3lg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 270);
}

static uint64_t INLINE_NEVER work_3lh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 271);
}

static uint64_t INLINE_NEVER work_3li(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 272);
}

static uint64_t INLINE_NEVER work_3lj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 273);
}

static uint64_t INLINE_NEVER work_3lk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 274);
}

static uint64_t INLINE_NEVER work_3ll(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 275);
}

static uint64_t INLINE_NEVER work_3lm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 276);
}

static uint64_t INLINE_NEVER work_3ln(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 277);
}

static uint64_t INLINE_NEVER work_3lo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 278);
}

static uint64_t INLINE_NEVER work_3lp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 279);
}

static uint64_t INLINE_NEVER work_3lq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 280);
}

static uint64_t INLINE_NEVER work_3lr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 281);
}

static uint64_t INLINE_NEVER work_3ls(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 282);
}

static uint64_t INLINE_NEVER work_3lt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 283);
}

static uint64_t INLINE_NEVER work_3lu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 284);
}

static uint64_t INLINE_NEVER work_3lv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 285);
}

static uint64_t INLINE_NEVER work_3lw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 286);
}

static uint64_t INLINE_NEVER work_3lx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 287);
}

static uint64_t INLINE_NEVER work_3ma(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 288);
}

static uint64_t INLINE_NEVER work_3mb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 289);
}

static uint64_t INLINE_NEVER work_3mc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 290);
}

static uint64_t INLINE_NEVER work_3md(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 291);
}

static uint64_t INLINE_NEVER work_3me(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 292);
}

static uint64_t INLINE_NEVER work_3mf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 293);
}

static uint64_t INLINE_NEVER work_3mg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 294);
}

static uint64_t INLINE_NEVER work_3mh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 295);
}

static uint64_t INLINE_NEVER work_3mi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 296);
}

static uint64_t INLINE_NEVER work_3mj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 297);
}

static uint64_t INLINE_NEVER work_3mk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 298);
}

static uint64_t INLINE_NEVER work_3ml(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 299);
}

static uint64_t INLINE_NEVER work_3mm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 300);
}

static uint64_t INLINE_NEVER work_3mn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 301);
}

static uint64_t INLINE_NEVER work_3mo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 302);
}

static uint64_t INLINE_NEVER work_3mp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 303);
}

static uint64_t INLINE_NEVER work_3mq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 304);
}

static uint64_t INLINE_NEVER work_3mr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 305);
}

static uint64_t INLINE_NEVER work_3ms(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 306);
}

static uint64_t INLINE_NEVER work_3mt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 307);
}

static uint64_t INLINE_NEVER work_3mu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 308);
}

static uint64_t INLINE_NEVER work_3mv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 309);
}

static uint64_t INLINE_NEVER work_3mw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 310);
}

static uint64_t INLINE_NEVER work_3mx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 311);
}

static uint64_t INLINE_NEVER work_3na(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 312);
}

static uint64_t INLINE_NEVER work_3nb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 313);
}

static uint64_t INLINE_NEVER work_3nc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 314);
}

static uint64_t INLINE_NEVER work_3nd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 315);
}

static uint64_t INLINE_NEVER work_3ne(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 316);
}

static uint64_t INLINE_NEVER work_3nf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 317);
}

static uint64_t INLINE_NEVER work_3ng(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 318);
}

static uint64_t INLINE_NEVER work_3nh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 319);
}

static uint64_t INLINE_NEVER work_3ni(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 320);
}

static uint64_t INLINE_NEVER work_3nj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 321);
}

static uint64_t INLINE_NEVER work_3nk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 322);
}

static uint64_t INLINE_NEVER work_3nl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 323);
}

static uint64_t INLINE_NEVER work_3nm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 324);
}

static uint64_t INLINE_NEVER work_3nn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 325);
}

static uint64_t INLINE_NEVER work_3no(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 326);
}

static uint64_t INLINE_NEVER work_3np(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 327);
}

static uint64_t INLINE_NEVER work_3nq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 328);
}

static uint64_t INLINE_NEVER work_3nr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 329);
}

static uint64_t INLINE_NEVER work_3ns(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 330);
}

static uint64_t INLINE_NEVER work_3nt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 331);
}

static uint64_t INLINE_NEVER work_3nu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 332);
}

static uint64_t INLINE_NEVER work_3nv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 333);
}

static uint64_t INLINE_NEVER work_3nw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 334);
}

static uint64_t INLINE_NEVER work_3nx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 335);
}

static uint64_t INLINE_NEVER work_3oa(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 336);
}

static uint64_t INLINE_NEVER work_3ob(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 337);
}

static uint64_t INLINE_NEVER work_3oc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 338);
}

static uint64_t INLINE_NEVER work_3od(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 339);
}

static uint64_t INLINE_NEVER work_3oe(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 340);
}

static uint64_t INLINE_NEVER work_3of(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 341);
}

static uint64_t INLINE_NEVER work_3og(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 342);
}

static uint64_t INLINE_NEVER work_3oh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 343);
}

static uint64_t INLINE_NEVER work_3oi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 344);
}

static uint64_t INLINE_NEVER work_3oj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 345);
}

static uint64_t INLINE_NEVER work_3ok(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 346);
}

static uint64_t INLINE_NEVER work_3ol(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 347);
}

static uint64_t INLINE_NEVER work_3om(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 348);
}

static uint64_t INLINE_NEVER work_3on(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 349);
}

static uint64_t INLINE_NEVER work_3oo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 350);
}

static uint64_t INLINE_NEVER work_3op(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 351);
}

static uint64_t INLINE_NEVER work_3oq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 352);
}

static uint64_t INLINE_NEVER work_3or(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 353);
}

static uint64_t INLINE_NEVER work_3os(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 354);
}

static uint64_t INLINE_NEVER work_3ot(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 355);
}

static uint64_t INLINE_NEVER work_3ou(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 356);
}

static uint64_t INLINE_NEVER work_3ov(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 357);
}

static uint64_t INLINE_NEVER work_3ow(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 358);
}

static uint64_t INLINE_NEVER work_3ox(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 359);
}

static uint64_t INLINE_NEVER work_3pa(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 360);
}

static uint64_t INLINE_NEVER work_3pb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 361);
}

static uint64_t INLINE_NEVER work_3pc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 362);
}

static uint64_t INLINE_NEVER work_3pd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 363);
}

static uint64_t INLINE_NEVER work_3pe(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 364);
}

static uint64_t INLINE_NEVER work_3pf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 365);
}

static uint64_t INLINE_NEVER work_3pg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 366);
}

static uint64_t INLINE_NEVER work_3ph(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 367);
}

static uint64_t INLINE_NEVER work_3pi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 368);
}

static uint64_t INLINE_NEVER work_3pj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 369);
}

static uint64_t INLINE_NEVER work_3pk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 370);
}

static uint64_t INLINE_NEVER work_3pl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 371);
}

static uint64_t INLINE_NEVER work_3pm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 372);
}

static uint64_t INLINE_NEVER work_3pn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 373);
}

static uint64_t INLINE_NEVER work_3po(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 374);
}

static uint64_t INLINE_NEVER work_3pp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 375);
}

static uint64_t INLINE_NEVER work_3pq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 376);
}

static uint64_t INLINE_NEVER work_3pr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 377);
}

static uint64_t INLINE_NEVER work_3ps(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 378);
}

static uint64_t INLINE_NEVER work_3pt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 379);
}

static uint64_t INLINE_NEVER work_3pu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 380);
}

static uint64_t INLINE_NEVER work_3pv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 381);
}

static uint64_t INLINE_NEVER work_3pw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 382);
}

static uint64_t INLINE_NEVER work_3px(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 383);
}

static uint64_t INLINE_NEVER work_3qa(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 384);
}

static uint64_t INLINE_NEVER work_3qb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 385);
}

static uint64_t INLINE_NEVER work_3qc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 386);
}

static uint64_t INLINE_NEVER work_3qd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 387);
}

static uint64_t INLINE_NEVER work_3qe(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 388);
}

static uint64_t INLINE_NEVER work_3qf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 389);
}

static uint64_t INLINE_NEVER work_3qg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 390);
}

static uint64_t INLINE_NEVER work_3qh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 391);
}

static uint64_t INLINE_NEVER work_3qi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 392);
}

static uint64_t INLINE_NEVER work_3qj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 393);
}

static uint64_t INLINE_NEVER work_3qk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 394);
}

static uint64_t INLINE_NEVER work_3ql(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 395);
}

static uint64_t INLINE_NEVER work_3qm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 396);
}

static uint64_t INLINE_NEVER work_3qn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 397);
}

static uint64_t INLINE_NEVER work_3qo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 398);
}

static uint64_t INLINE_NEVER work_3qp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 399);
}

static uint64_t INLINE_NEVER work_3qq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 400);
}

static uint64_t INLINE_NEVER work_3qr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 401);
}

static uint64_t INLINE_NEVER work_3qs(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 402);
}

static uint64_t INLINE_NEVER work_3qt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 403);
}

static uint64_t INLINE_NEVER work_3qu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 404);
}

static uint64_t INLINE_NEVER work_3qv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 405);
}

static uint64_t INLINE_NEVER work_3qw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 406);
}

static uint64_t INLINE_NEVER work_3qx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 407);
}

static uint64_t INLINE_NEVER work_3ra(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 408);
}

static uint64_t INLINE_NEVER work_3rb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 409);
}

static uint64_t INLINE_NEVER work_3rc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 410);
}

static uint64_t INLINE_NEVER work_3rd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 411);
}

static uint64_t INLINE_NEVER work_3re(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 412);
}

static uint64_t INLINE_NEVER work_3rf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 413);
}

static uint64_t INLINE_NEVER work_3rg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 414);
}

static uint64_t INLINE_NEVER work_3rh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 415);
}

static uint64_t INLINE_NEVER work_3ri(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 416);
}

static uint64_t INLINE_NEVER work_3rj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 417);
}

static uint64_t INLINE_NEVER work_3rk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 418);
}

static uint64_t INLINE_NEVER work_3rl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 419);
}

static uint64_t INLINE_NEVER work_3rm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 420);
}

static uint64_t INLINE_NEVER work_3rn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 421);
}

static uint64_t INLINE_NEVER work_3ro(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 422);
}

static uint64_t INLINE_NEVER work_3rp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 423);
}

static uint64_t INLINE_NEVER work_3rq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 424);
}

static uint64_t INLINE_NEVER work_3rr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 425);
}

static uint64_t INLINE_NEVER work_3rs(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 426);
}

static uint64_t INLINE_NEVER work_3rt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 427);
}

static uint64_t INLINE_NEVER work_3ru(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 428);
}

static uint64_t INLINE_NEVER work_3rv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 429);
}

static uint64_t INLINE_NEVER work_3rw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 430);
}

static uint64_t INLINE_NEVER work_3rx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 431);
}

static uint64_t INLINE_NEVER work_3sa(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 432);
}

static uint64_t INLINE_NEVER work_3sb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 433);
}

static uint64_t INLINE_NEVER work_3sc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 434);
}

static uint64_t INLINE_NEVER work_3sd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 435);
}

static uint64_t INLINE_NEVER work_3se(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 436);
}

static uint64_t INLINE_NEVER work_3sf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 437);
}

static uint64_t INLINE_NEVER work_3sg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 438);
}

static uint64_t INLINE_NEVER work_3sh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 439);
}

static uint64_t INLINE_NEVER work_3si(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 440);
}

static uint64_t INLINE_NEVER work_3sj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 441);
}

static uint64_t INLINE_NEVER work_3sk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 442);
}

static uint64_t INLINE_NEVER work_3sl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 443);
}

static uint64_t INLINE_NEVER work_3sm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 444);
}

static uint64_t INLINE_NEVER work_3sn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 445);
}

static uint64_t INLINE_NEVER work_3so(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 446);
}

static uint64_t INLINE_NEVER work_3sp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 447);
}

static uint64_t INLINE_NEVER work_3sq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 448);
}

static uint64_t INLINE_NEVER work_3sr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 449);
}

static uint64_t INLINE_NEVER work_3ss(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 450);
}

static uint64_t INLINE_NEVER work_3st(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 451);
}

static uint64_t INLINE_NEVER work_3su(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 452);
}

static uint64_t INLINE_NEVER work_3sv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 453);
}

static uint64_t INLINE_NEVER work_3sw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 454);
}

static uint64_t INLINE_NEVER work_3sx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 455);
}

static uint64_t INLINE_NEVER work_3ta(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 456);
}

static uint64_t INLINE_NEVER work_3tb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 457);
}

static uint64_t INLINE_NEVER work_3tc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 458);
}

static uint64_t INLINE_NEVER work_3td(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 459);
}

static uint64_t INLINE_NEVER work_3te(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 460);
}

static uint64_t INLINE_NEVER work_3tf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 461);
}

static uint64_t INLINE_NEVER work_3tg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 462);
}

static uint64_t INLINE_NEVER work_3th(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 463);
}

static uint64_t INLINE_NEVER work_3ti(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 464);
}

static uint64_t INLINE_NEVER work_3tj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 465);
}

static uint64_t INLINE_NEVER work_3tk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 466);
}

static uint64_t INLINE_NEVER work_3tl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 467);
}

static uint64_t INLINE_NEVER work_3tm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 468);
}

static uint64_t INLINE_NEVER work_3tn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 469);
}

static uint64_t INLINE_NEVER work_3to(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 470);
}

static uint64_t INLINE_NEVER work_3tp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 471);
}

static uint64_t INLINE_NEVER work_3tq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 472);
}

static uint64_t INLINE_NEVER work_3tr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 473);
}

static uint64_t INLINE_NEVER work_3ts(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 474);
}

static uint64_t INLINE_NEVER work_3tt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 475);
}

static uint64_t INLINE_NEVER work_3tu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 476);
}

static uint64_t INLINE_NEVER work_3tv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 477);
}

static uint64_t INLINE_NEVER work_3tw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 478);
}

static uint64_t INLINE_NEVER work_3tx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 479);
}

static uint64_t INLINE_NEVER work_3ua(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 480);
}

static uint64_t INLINE_NEVER work_3ub(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 481);
}

static uint64_t INLINE_NEVER work_3uc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 482);
}

static uint64_t INLINE_NEVER work_3ud(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 483);
}

static uint64_t INLINE_NEVER work_3ue(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 484);
}

static uint64_t INLINE_NEVER work_3uf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 485);
}

static uint64_t INLINE_NEVER work_3ug(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 486);
}

static uint64_t INLINE_NEVER work_3uh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 487);
}

static uint64_t INLINE_NEVER work_3ui(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 488);
}

static uint64_t INLINE_NEVER work_3uj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 489);
}

static uint64_t INLINE_NEVER work_3uk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 490);
}

static uint64_t INLINE_NEVER work_3ul(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 491);
}

static uint64_t INLINE_NEVER work_3um(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 492);
}

static uint64_t INLINE_NEVER work_3un(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 493);
}

static uint64_t INLINE_NEVER work_3uo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 494);
}

static uint64_t INLINE_NEVER work_3up(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 495);
}

static uint64_t INLINE_NEVER work_3uq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 496);
}

static uint64_t INLINE_NEVER work_3ur(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 497);
}

static uint64_t INLINE_NEVER work_3us(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 498);
}

static uint64_t INLINE_NEVER work_3ut(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 499);
}

static uint64_t INLINE_NEVER work_3uu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 500);
}

static uint64_t INLINE_NEVER work_3uv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 501);
}

static uint64_t INLINE_NEVER work_3uw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 502);
}

static uint64_t INLINE_NEVER work_3ux(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 503);
}

static uint64_t INLINE_NEVER work_3va(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 504);
}

static uint64_t INLINE_NEVER work_3vb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 505);
}

static uint64_t INLINE_NEVER work_3vc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 506);
}

static uint64_t INLINE_NEVER work_3vd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 507);
}

static uint64_t INLINE_NEVER work_3ve(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 508);
}

static uint64_t INLINE_NEVER work_3vf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 509);
}

static uint64_t INLINE_NEVER work_3vg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 510);
}

static uint64_t INLINE_NEVER work_3vh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 511);
}

static uint64_t INLINE_NEVER work_3vi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 512);
}

static uint64_t INLINE_NEVER work_3vj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 513);
}

static uint64_t INLINE_NEVER work_3vk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 514);
}

static uint64_t INLINE_NEVER work_3vl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 515);
}

static uint64_t INLINE_NEVER work_3vm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 516);
}

static uint64_t INLINE_NEVER work_3vn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 517);
}

static uint64_t INLINE_NEVER work_3vo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 518);
}

static uint64_t INLINE_NEVER work_3vp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 519);
}

static uint64_t INLINE_NEVER work_3vq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 520);
}

static uint64_t INLINE_NEVER work_3vr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 521);
}

static uint64_t INLINE_NEVER work_3vs(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 522);
}

static uint64_t INLINE_NEVER work_3vt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 523);
}

static uint64_t INLINE_NEVER work_3vu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 524);
}

static uint64_t INLINE_NEVER work_3vv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 525);
}

static uint64_t INLINE_NEVER work_3vw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 526);
}

static uint64_t INLINE_NEVER work_3vx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 527);
}

static uint64_t INLINE_NEVER work_3wa(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 528);
}

static uint64_t INLINE_NEVER work_3wb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 529);
}

static uint64_t INLINE_NEVER work_3wc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 530);
}

static uint64_t INLINE_NEVER work_3wd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 531);
}

static uint64_t INLINE_NEVER work_3we(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 532);
}

static uint64_t INLINE_NEVER work_3wf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 533);
}

static uint64_t INLINE_NEVER work_3wg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 534);
}

static uint64_t INLINE_NEVER work_3wh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 535);
}

static uint64_t INLINE_NEVER work_3wi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 536);
}

static uint64_t INLINE_NEVER work_3wj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 537);
}

static uint64_t INLINE_NEVER work_3wk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 538);
}

static uint64_t INLINE_NEVER work_3wl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 539);
}

static uint64_t INLINE_NEVER work_3wm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 540);
}

static uint64_t INLINE_NEVER work_3wn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 541);
}

static uint64_t INLINE_NEVER work_3wo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 542);
}

static uint64_t INLINE_NEVER work_3wp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 543);
}

static uint64_t INLINE_NEVER work_3wq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 544);
}

static uint64_t INLINE_NEVER work_3wr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 545);
}

static uint64_t INLINE_NEVER work_3ws(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 546);
}

static uint64_t INLINE_NEVER work_3wt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 547);
}

static uint64_t INLINE_NEVER work_3wu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 548);
}

static uint64_t INLINE_NEVER work_3wv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 549);
}

static uint64_t INLINE_NEVER work_3ww(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 550);
}

static uint64_t INLINE_NEVER work_3wx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 551);
}

static uint64_t INLINE_NEVER work_3xa(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 552);
}

static uint64_t INLINE_NEVER work_3xb(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 553);
}

static uint64_t INLINE_NEVER work_3xc(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 554);
}

static uint64_t INLINE_NEVER work_3xd(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 555);
}

static uint64_t INLINE_NEVER work_3xe(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 556);
}

static uint64_t INLINE_NEVER work_3xf(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 557);
}

static uint64_t INLINE_NEVER work_3xg(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 558);
}

static uint64_t INLINE_NEVER work_3xh(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 559);
}

static uint64_t INLINE_NEVER work_3xi(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 560);
}

static uint64_t INLINE_NEVER work_3xj(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 561);
}

static uint64_t INLINE_NEVER work_3xk(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 562);
}

static uint64_t INLINE_NEVER work_3xl(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 563);
}

static uint64_t INLINE_NEVER work_3xm(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 564);
}

static uint64_t INLINE_NEVER work_3xn(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 565);
}

static uint64_t INLINE_NEVER work_3xo(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 566);
}

static uint64_t INLINE_NEVER work_3xp(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 567);
}

static uint64_t INLINE_NEVER work_3xq(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 568);
}

static uint64_t INLINE_NEVER work_3xr(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 569);
}

static uint64_t INLINE_NEVER work_3xs(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 570);
}

static uint64_t INLINE_NEVER work_3xt(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 571);
}

static uint64_t INLINE_NEVER work_3xu(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 572);
}

static uint64_t INLINE_NEVER work_3xv(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 573);
}

static uint64_t INLINE_NEVER work_3xw(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 574);
}

static uint64_t INLINE_NEVER work_3xx(uint64_t a, uint32_t *b)
{
	return WORK_3(a, b, 575);
}

static work_3_fn_t work_3[] = {
	work_3aa, work_3ab, work_3ac, work_3ad, work_3ae, work_3af, work_3ag, work_3ah,
	work_3ai, work_3aj, work_3ak, work_3al, work_3am, work_3an, work_3ao, work_3ap,
	work_3aq, work_3ar, work_3as, work_3at, work_3au, work_3av, work_3aw, work_3ax,
	work_3ba, work_3bb, work_3bc, work_3bd, work_3be, work_3bf, work_3bg, work_3bh,
	work_3bi, work_3bj, work_3bk, work_3bl, work_3bm, work_3bn, work_3bo, work_3bp,
	work_3bq, work_3br, work_3bs, work_3bt, work_3bu, work_3bv, work_3bw, work_3bx,
	work_3ca, work_3cb, work_3cc, work_3cd, work_3ce, work_3cf, work_3cg, work_3ch,
	work_3ci, work_3cj, work_3ck, work_3cl, work_3cm, work_3cn, work_3co, work_3cp,
	work_3cq, work_3cr, work_3cs, work_3ct, work_3cu, work_3cv, work_3cw, work_3cx,
	work_3da, work_3db, work_3dc, work_3dd, work_3de, work_3df, work_3dg, work_3dh,
	work_3di, work_3dj, work_3dk, work_3dl, work_3dm, work_3dn, work_3do, work_3dp,
	work_3dq, work_3dr, work_3ds, work_3dt, work_3du, work_3dv, work_3dw, work_3dx,
	work_3ea, work_3eb, work_3ec, work_3ed, work_3ee, work_3ef, work_3eg, work_3eh,
	work_3ei, work_3ej, work_3ek, work_3el, work_3em, work_3en, work_3eo, work_3ep,
	work_3eq, work_3er, work_3es, work_3et, work_3eu, work_3ev, work_3ew, work_3ex,
	work_3fa, work_3fb, work_3fc, work_3fd, work_3fe, work_3ff, work_3fg, work_3fh,
	work_3fi, work_3fj, work_3fk, work_3fl, work_3fm, work_3fn, work_3fo, work_3fp,
	work_3fq, work_3fr, work_3fs, work_3ft, work_3fu, work_3fv, work_3fw, work_3fx,
	work_3ga, work_3gb, work_3gc, work_3gd, work_3ge, work_3gf, work_3gg, work_3gh,
	work_3gi, work_3gj, work_3gk, work_3gl, work_3gm, work_3gn, work_3go, work_3gp,
	work_3gq, work_3gr, work_3gs, work_3gt, work_3gu, work_3gv, work_3gw, work_3gx,
	work_3ha, work_3hb, work_3hc, work_3hd, work_3he, work_3hf, work_3hg, work_3hh,
	work_3hi, work_3hj, work_3hk, work_3hl, work_3hm, work_3hn, work_3ho, work_3hp,
	work_3hq, work_3hr, work_3hs, work_3ht, work_3hu, work_3hv, work_3hw, work_3hx,
	work_3ia, work_3ib, work_3ic, work_3id, work_3ie, work_3if, work_3ig, work_3ih,
	work_3ii, work_3ij, work_3ik, work_3il, work_3im, work_3in, work_3io, work_3ip,
	work_3iq, work_3ir, work_3is, work_3it, work_3iu, work_3iv, work_3iw, work_3ix,
	work_3ja, work_3jb, work_3jc, work_3jd, work_3je, work_3jf, work_3jg, work_3jh,
	work_3ji, work_3jj, work_3jk, work_3jl, work_3jm, work_3jn, work_3jo, work_3jp,
	work_3jq, work_3jr, work_3js, work_3jt, work_3ju, work_3jv, work_3jw, work_3jx,
	work_3ka, work_3kb, work_3kc, work_3kd, work_3ke, work_3kf, work_3kg, work_3kh,
	work_3ki, work_3kj, work_3kk, work_3kl, work_3km, work_3kn, work_3ko, work_3kp,
	work_3kq, work_3kr, work_3ks, work_3kt, work_3ku, work_3kv, work_3kw, work_3kx,
	work_3la, work_3lb, work_3lc, work_3ld, work_3le, work_3lf, work_3lg, work_3lh,
	work_3li, work_3lj, work_3lk, work_3ll, work_3lm, work_3ln, work_3lo, work_3lp,
	work_3lq, work_3lr, work_3ls, work_3lt, work_3lu, work_3lv, work_3lw, work_3lx,
	work_3ma, work_3mb, work_3mc, work_3md, work_3me, work_3mf, work_3mg, work_3mh,
	work_3mi, work_3mj, work_3mk, work_3ml, work_3mm, work_3mn, work_3mo, work_3mp,
	work_3mq, work_3mr, work_3ms, work_3mt, work_3mu, work_3mv, work_3mw, work_3mx,
	work_3na, work_3nb, work_3nc, work_3nd, work_3ne, work_3nf, work_3ng, work_3nh,
	work_3ni, work_3nj, work_3nk, work_3nl, work_3nm, work_3nn, work_3no, work_3np,
	work_3nq, work_3nr, work_3ns, work_3nt, work_3nu, work_3nv, work_3nw, work_3nx,
	work_3oa, work_3ob, work_3oc, work_3od, work_3oe, work_3of, work_3og, work_3oh,
	work_3oi, work_3oj, work_3ok, work_3ol, work_3om, work_3on, work_3oo, work_3op,
	work_3oq, work_3or, work_3os, work_3ot, work_3ou, work_3ov, work_3ow, work_3ox,
	work_3pa, work_3pb, work_3pc, work_3pd, work_3pe, work_3pf, work_3pg, work_3ph,
	work_3pi, work_3pj, work_3pk, work_3pl, work_3pm, work_3pn, work_3po, work_3pp,
	work_3pq, work_3pr, work_3ps, work_3pt, work_3pu, work_3pv, work_3pw, work_3px,
	work_3qa, work_3qb, work_3qc, work_3qd, work_3qe, work_3qf, work_3qg, work_3qh,
	work_3qi, work_3qj, work_3qk, work_3ql, work_3qm, work_3qn, work_3qo, work_3qp,
	work_3qq, work_3qr, work_3qs, work_3qt, work_3qu, work_3qv, work_3qw, work_3qx,
	work_3ra, work_3rb, work_3rc, work_3rd, work_3re, work_3rf, work_3rg, work_3rh,
	work_3ri, work_3rj, work_3rk, work_3rl, work_3rm, work_3rn, work_3ro, work_3rp,
	work_3rq, work_3rr, work_3rs, work_3rt, work_3ru, work_3rv, work_3rw, work_3rx,
	work_3sa, work_3sb, work_3sc, work_3sd, work_3se, work_3sf, work_3sg, work_3sh,
	work_3si, work_3sj, work_3sk, work_3sl, work_3sm, work_3sn, work_3so, work_3sp,
	work_3sq, work_3sr, work_3ss, work_3st, work_3su, work_3sv, work_3sw, work_3sx,
	work_3ta, work_3tb, work_3tc, work_3td, work_3te, work_3tf, work_3tg, work_3th,
	work_3ti, work_3tj, work_3tk, work_3tl, work_3tm, work_3tn, work_3to, work_3tp,
	work_3tq, work_3tr, work_3ts, work_3tt, work_3tu, work_3tv, work_3tw, work_3tx,
	work_3ua, work_3ub, work_3uc, work_3ud, work_3ue, work_3uf, work_3ug, work_3uh,
	work_3ui, work_3uj, work_3uk, work_3ul, work_3um, work_3un, work_3uo, work_3up,
	work_3uq, work_3ur, work_3us, work_3ut, work_3uu, work_3uv, work_3uw, work_3ux,
	work_3va, work_3vb, work_3vc, work_3vd, work_3ve, work_3vf, work_3vg, work_3vh,
	work_3vi, work_3vj, work_3vk, work_3vl, work_3vm, work_3vn, work_3vo, work_3vp,
	work_3vq, work_3vr, work_3vs, work_3vt, work_3vu, work_3vv, work_3vw, work_3vx,
	work_3wa, work_3wb, work_3wc, work_3wd, work_3we, work_3wf, work_3wg, work_3wh,
	work_3wi, work_3wj, work_3wk, work_3wl, work_3wm, work_3wn, work_3wo, work_3wp,
	work_3wq, work_3wr, work_3ws, work_3wt, work_3wu, work_3wv, work_3ww, work_3wx,
	work_3xa, work_3xb, work_3xc, work_3xd, work_3xe, work_3xf, work_3xg, work_3xh,
	work_3xi, work_3xj, work_3xk, work_3xl, work_3xm, work_3xn, work_3xo, work_3xp,
	work_3xq, work_3xr, work_3xs, work_3xt, work_3xu, work_3xv, work_3xw, work_3xx
};

static uint16_t work_3_rnd[] = {
	318,  11, 340, 402,  10, 249, 395, 575, 486, 258, 130, 334, 482, 350, 422, 265,
	185,  41, 523,  13, 427,  45, 519,  24, 552, 151, 432, 442, 298, 498,  56,  21,
	279,  75, 489, 284, 317, 114, 510, 135, 560, 212,  14, 132,  53, 501, 490, 125,
	 49, 573, 163, 529, 170,  33,  36, 389, 463, 492, 475, 413,  26, 364, 319, 345,
	 17, 426, 451, 439, 116,  79, 148,  60, 539,  25, 506, 208, 246, 551, 177, 159,
	  5, 408, 555,  71, 206,  57, 549, 348, 144,  22, 278, 115, 124, 119, 518,  77,
	294, 189, 447, 406, 219,  97,  30, 256, 459,  90, 346, 360, 515, 367, 405, 215,
	270,  44, 240, 272,  28,  15, 366, 107, 101, 160, 171, 253, 443,   8, 198, 204,
	241, 247, 105, 398, 295, 220, 126,  92, 351,   3, 561, 454, 468,  35, 282, 437,
	 29, 507, 548, 103,  70, 108, 327, 478, 104, 485, 274, 352, 158, 202,  86, 532,
	269, 428, 311, 404, 465, 176, 474, 239, 225, 385, 146, 455, 403,  66, 456, 273,
	 18, 415, 464, 354, 473, 233, 384, 120, 209, 452, 187, 251,  87, 227, 516, 128,
	152, 571, 337, 290, 430, 191, 237, 538, 313, 343, 288, 527, 336, 143, 509, 543,
	136,  73,  78,  47, 342, 309, 556, 357, 161, 513, 168, 328,  94, 525, 545, 293,
	563, 118, 540, 502, 257, 221, 301, 431, 479, 462,   1,  91,  39, 325, 310, 299,
	 93, 469, 445, 569, 362, 172, 526,  52, 205, 193, 400, 201, 565, 218, 228, 371,
	312, 378,  54, 111, 186, 372, 508,  72, 332,  89, 493, 252,  61, 418, 533, 520,
	238, 203,  95, 304, 230, 323, 223, 133, 211, 392, 243, 190,   6, 425, 121, 182,
	210,   2, 149, 517, 333, 235, 194, 291,  68, 397, 487, 453, 436, 380, 341, 192,
	558,  16, 250, 100,  55, 531, 457, 314,  37,  84,  64, 536, 255, 412,  20, 401,
	356, 420,  59, 521, 199, 147, 375, 476, 387,   9, 370, 416,  50,  74, 417, 174,
	156, 154, 184,  42, 229, 562, 300, 505, 500, 537, 117, 567, 564, 214, 286,  12,
	260,  96, 495, 181, 275,  76,  62, 470, 329,  98,  99, 374,  85, 137, 433, 440,
	153, 321, 263, 216, 570,  23, 434, 110, 195,  63, 484, 381,  65, 326, 461, 175,
	382, 361, 296, 438,  40, 407, 129, 267, 305, 232, 363, 483, 236, 369,  31, 448,
	503,  88, 113, 245, 231, 123, 162,  43, 414, 566, 421, 277, 349, 261, 307, 164,
	423, 494, 283, 179, 377, 353, 138, 546, 358, 183, 167, 391, 373, 394, 472, 109,
	339, 359, 496, 429, 320, 150, 330, 242, 410,  34, 458, 383, 169, 280, 544, 140,
	568, 224, 547, 173, 297, 166, 450, 514, 308,  81, 477, 368, 200, 222, 196, 541,
	213, 534, 386, 248, 524, 157, 504, 441, 254, 480, 411,   0, 550, 522, 419, 106,
	289,  83,  67, 134, 142, 554, 266, 262, 435,  27,   4, 271, 112, 141, 244, 499,
	 51, 306, 127,  69, 467, 335, 315, 424, 180, 466, 178, 393, 281,   7,  48, 399,
	446, 388, 355, 188, 264, 145, 344,  19, 122, 491,  32,  46, 302, 376, 471, 460,
	226, 217, 331, 139, 322, 574, 276, 338, 553, 197,  82, 303,  38, 542, 292, 530,
	155, 287,  80, 511, 316, 324, 207, 379, 481, 234, 444, 259, 488, 390, 396, 165,
	347, 365, 268, 449, 512, 557, 535, 572, 131, 285, 497,  58, 102, 409, 559, 528
};

static uint64_t INLINE_NEVER work_4aa(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 0);
}

static uint64_t INLINE_NEVER work_4ab(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 1);
}

static uint64_t INLINE_NEVER work_4ac(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 2);
}

static uint64_t INLINE_NEVER work_4ad(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 3);
}

static uint64_t INLINE_NEVER work_4ae(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 4);
}

static uint64_t INLINE_NEVER work_4af(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 5);
}

static uint64_t INLINE_NEVER work_4ag(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 6);
}

static uint64_t INLINE_NEVER work_4ah(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 7);
}

static uint64_t INLINE_NEVER work_4ai(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 8);
}

static uint64_t INLINE_NEVER work_4aj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 9);
}

static uint64_t INLINE_NEVER work_4ak(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 10);
}

static uint64_t INLINE_NEVER work_4al(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 11);
}

static uint64_t INLINE_NEVER work_4am(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 12);
}

static uint64_t INLINE_NEVER work_4an(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 13);
}

static uint64_t INLINE_NEVER work_4ao(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 14);
}

static uint64_t INLINE_NEVER work_4ap(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 15);
}

static uint64_t INLINE_NEVER work_4aq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 16);
}

static uint64_t INLINE_NEVER work_4ar(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 17);
}

static uint64_t INLINE_NEVER work_4as(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 18);
}

static uint64_t INLINE_NEVER work_4at(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 19);
}

static uint64_t INLINE_NEVER work_4au(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 20);
}

static uint64_t INLINE_NEVER work_4av(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 21);
}

static uint64_t INLINE_NEVER work_4aw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 22);
}

static uint64_t INLINE_NEVER work_4ax(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 23);
}

static uint64_t INLINE_NEVER work_4ba(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 24);
}

static uint64_t INLINE_NEVER work_4bb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 25);
}

static uint64_t INLINE_NEVER work_4bc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 26);
}

static uint64_t INLINE_NEVER work_4bd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 27);
}

static uint64_t INLINE_NEVER work_4be(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 28);
}

static uint64_t INLINE_NEVER work_4bf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 29);
}

static uint64_t INLINE_NEVER work_4bg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 30);
}

static uint64_t INLINE_NEVER work_4bh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 31);
}

static uint64_t INLINE_NEVER work_4bi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 32);
}

static uint64_t INLINE_NEVER work_4bj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 33);
}

static uint64_t INLINE_NEVER work_4bk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 34);
}

static uint64_t INLINE_NEVER work_4bl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 35);
}

static uint64_t INLINE_NEVER work_4bm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 36);
}

static uint64_t INLINE_NEVER work_4bn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 37);
}

static uint64_t INLINE_NEVER work_4bo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 38);
}

static uint64_t INLINE_NEVER work_4bp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 39);
}

static uint64_t INLINE_NEVER work_4bq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 40);
}

static uint64_t INLINE_NEVER work_4br(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 41);
}

static uint64_t INLINE_NEVER work_4bs(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 42);
}

static uint64_t INLINE_NEVER work_4bt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 43);
}

static uint64_t INLINE_NEVER work_4bu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 44);
}

static uint64_t INLINE_NEVER work_4bv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 45);
}

static uint64_t INLINE_NEVER work_4bw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 46);
}

static uint64_t INLINE_NEVER work_4bx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 47);
}

static uint64_t INLINE_NEVER work_4ca(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 48);
}

static uint64_t INLINE_NEVER work_4cb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 49);
}

static uint64_t INLINE_NEVER work_4cc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 50);
}

static uint64_t INLINE_NEVER work_4cd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 51);
}

static uint64_t INLINE_NEVER work_4ce(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 52);
}

static uint64_t INLINE_NEVER work_4cf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 53);
}

static uint64_t INLINE_NEVER work_4cg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 54);
}

static uint64_t INLINE_NEVER work_4ch(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 55);
}

static uint64_t INLINE_NEVER work_4ci(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 56);
}

static uint64_t INLINE_NEVER work_4cj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 57);
}

static uint64_t INLINE_NEVER work_4ck(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 58);
}

static uint64_t INLINE_NEVER work_4cl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 59);
}

static uint64_t INLINE_NEVER work_4cm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 60);
}

static uint64_t INLINE_NEVER work_4cn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 61);
}

static uint64_t INLINE_NEVER work_4co(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 62);
}

static uint64_t INLINE_NEVER work_4cp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 63);
}

static uint64_t INLINE_NEVER work_4cq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 64);
}

static uint64_t INLINE_NEVER work_4cr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 65);
}

static uint64_t INLINE_NEVER work_4cs(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 66);
}

static uint64_t INLINE_NEVER work_4ct(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 67);
}

static uint64_t INLINE_NEVER work_4cu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 68);
}

static uint64_t INLINE_NEVER work_4cv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 69);
}

static uint64_t INLINE_NEVER work_4cw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 70);
}

static uint64_t INLINE_NEVER work_4cx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 71);
}

static uint64_t INLINE_NEVER work_4da(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 72);
}

static uint64_t INLINE_NEVER work_4db(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 73);
}

static uint64_t INLINE_NEVER work_4dc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 74);
}

static uint64_t INLINE_NEVER work_4dd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 75);
}

static uint64_t INLINE_NEVER work_4de(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 76);
}

static uint64_t INLINE_NEVER work_4df(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 77);
}

static uint64_t INLINE_NEVER work_4dg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 78);
}

static uint64_t INLINE_NEVER work_4dh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 79);
}

static uint64_t INLINE_NEVER work_4di(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 80);
}

static uint64_t INLINE_NEVER work_4dj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 81);
}

static uint64_t INLINE_NEVER work_4dk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 82);
}

static uint64_t INLINE_NEVER work_4dl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 83);
}

static uint64_t INLINE_NEVER work_4dm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 84);
}

static uint64_t INLINE_NEVER work_4dn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 85);
}

static uint64_t INLINE_NEVER work_4do(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 86);
}

static uint64_t INLINE_NEVER work_4dp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 87);
}

static uint64_t INLINE_NEVER work_4dq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 88);
}

static uint64_t INLINE_NEVER work_4dr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 89);
}

static uint64_t INLINE_NEVER work_4ds(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 90);
}

static uint64_t INLINE_NEVER work_4dt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 91);
}

static uint64_t INLINE_NEVER work_4du(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 92);
}

static uint64_t INLINE_NEVER work_4dv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 93);
}

static uint64_t INLINE_NEVER work_4dw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 94);
}

static uint64_t INLINE_NEVER work_4dx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 95);
}

static uint64_t INLINE_NEVER work_4ea(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 96);
}

static uint64_t INLINE_NEVER work_4eb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 97);
}

static uint64_t INLINE_NEVER work_4ec(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 98);
}

static uint64_t INLINE_NEVER work_4ed(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 99);
}

static uint64_t INLINE_NEVER work_4ee(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 100);
}

static uint64_t INLINE_NEVER work_4ef(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 101);
}

static uint64_t INLINE_NEVER work_4eg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 102);
}

static uint64_t INLINE_NEVER work_4eh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 103);
}

static uint64_t INLINE_NEVER work_4ei(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 104);
}

static uint64_t INLINE_NEVER work_4ej(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 105);
}

static uint64_t INLINE_NEVER work_4ek(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 106);
}

static uint64_t INLINE_NEVER work_4el(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 107);
}

static uint64_t INLINE_NEVER work_4em(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 108);
}

static uint64_t INLINE_NEVER work_4en(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 109);
}

static uint64_t INLINE_NEVER work_4eo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 110);
}

static uint64_t INLINE_NEVER work_4ep(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 111);
}

static uint64_t INLINE_NEVER work_4eq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 112);
}

static uint64_t INLINE_NEVER work_4er(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 113);
}

static uint64_t INLINE_NEVER work_4es(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 114);
}

static uint64_t INLINE_NEVER work_4et(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 115);
}

static uint64_t INLINE_NEVER work_4eu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 116);
}

static uint64_t INLINE_NEVER work_4ev(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 117);
}

static uint64_t INLINE_NEVER work_4ew(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 118);
}

static uint64_t INLINE_NEVER work_4ex(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 119);
}

static uint64_t INLINE_NEVER work_4fa(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 120);
}

static uint64_t INLINE_NEVER work_4fb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 121);
}

static uint64_t INLINE_NEVER work_4fc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 122);
}

static uint64_t INLINE_NEVER work_4fd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 123);
}

static uint64_t INLINE_NEVER work_4fe(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 124);
}

static uint64_t INLINE_NEVER work_4ff(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 125);
}

static uint64_t INLINE_NEVER work_4fg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 126);
}

static uint64_t INLINE_NEVER work_4fh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 127);
}

static uint64_t INLINE_NEVER work_4fi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 128);
}

static uint64_t INLINE_NEVER work_4fj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 129);
}

static uint64_t INLINE_NEVER work_4fk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 130);
}

static uint64_t INLINE_NEVER work_4fl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 131);
}

static uint64_t INLINE_NEVER work_4fm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 132);
}

static uint64_t INLINE_NEVER work_4fn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 133);
}

static uint64_t INLINE_NEVER work_4fo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 134);
}

static uint64_t INLINE_NEVER work_4fp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 135);
}

static uint64_t INLINE_NEVER work_4fq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 136);
}

static uint64_t INLINE_NEVER work_4fr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 137);
}

static uint64_t INLINE_NEVER work_4fs(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 138);
}

static uint64_t INLINE_NEVER work_4ft(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 139);
}

static uint64_t INLINE_NEVER work_4fu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 140);
}

static uint64_t INLINE_NEVER work_4fv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 141);
}

static uint64_t INLINE_NEVER work_4fw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 142);
}

static uint64_t INLINE_NEVER work_4fx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 143);
}

static uint64_t INLINE_NEVER work_4ga(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 144);
}

static uint64_t INLINE_NEVER work_4gb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 145);
}

static uint64_t INLINE_NEVER work_4gc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 146);
}

static uint64_t INLINE_NEVER work_4gd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 147);
}

static uint64_t INLINE_NEVER work_4ge(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 148);
}

static uint64_t INLINE_NEVER work_4gf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 149);
}

static uint64_t INLINE_NEVER work_4gg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 150);
}

static uint64_t INLINE_NEVER work_4gh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 151);
}

static uint64_t INLINE_NEVER work_4gi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 152);
}

static uint64_t INLINE_NEVER work_4gj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 153);
}

static uint64_t INLINE_NEVER work_4gk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 154);
}

static uint64_t INLINE_NEVER work_4gl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 155);
}

static uint64_t INLINE_NEVER work_4gm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 156);
}

static uint64_t INLINE_NEVER work_4gn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 157);
}

static uint64_t INLINE_NEVER work_4go(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 158);
}

static uint64_t INLINE_NEVER work_4gp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 159);
}

static uint64_t INLINE_NEVER work_4gq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 160);
}

static uint64_t INLINE_NEVER work_4gr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 161);
}

static uint64_t INLINE_NEVER work_4gs(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 162);
}

static uint64_t INLINE_NEVER work_4gt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 163);
}

static uint64_t INLINE_NEVER work_4gu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 164);
}

static uint64_t INLINE_NEVER work_4gv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 165);
}

static uint64_t INLINE_NEVER work_4gw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 166);
}

static uint64_t INLINE_NEVER work_4gx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 167);
}

static uint64_t INLINE_NEVER work_4ha(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 168);
}

static uint64_t INLINE_NEVER work_4hb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 169);
}

static uint64_t INLINE_NEVER work_4hc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 170);
}

static uint64_t INLINE_NEVER work_4hd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 171);
}

static uint64_t INLINE_NEVER work_4he(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 172);
}

static uint64_t INLINE_NEVER work_4hf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 173);
}

static uint64_t INLINE_NEVER work_4hg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 174);
}

static uint64_t INLINE_NEVER work_4hh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 175);
}

static uint64_t INLINE_NEVER work_4hi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 176);
}

static uint64_t INLINE_NEVER work_4hj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 177);
}

static uint64_t INLINE_NEVER work_4hk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 178);
}

static uint64_t INLINE_NEVER work_4hl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 179);
}

static uint64_t INLINE_NEVER work_4hm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 180);
}

static uint64_t INLINE_NEVER work_4hn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 181);
}

static uint64_t INLINE_NEVER work_4ho(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 182);
}

static uint64_t INLINE_NEVER work_4hp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 183);
}

static uint64_t INLINE_NEVER work_4hq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 184);
}

static uint64_t INLINE_NEVER work_4hr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 185);
}

static uint64_t INLINE_NEVER work_4hs(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 186);
}

static uint64_t INLINE_NEVER work_4ht(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 187);
}

static uint64_t INLINE_NEVER work_4hu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 188);
}

static uint64_t INLINE_NEVER work_4hv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 189);
}

static uint64_t INLINE_NEVER work_4hw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 190);
}

static uint64_t INLINE_NEVER work_4hx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 191);
}

static uint64_t INLINE_NEVER work_4ia(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 192);
}

static uint64_t INLINE_NEVER work_4ib(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 193);
}

static uint64_t INLINE_NEVER work_4ic(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 194);
}

static uint64_t INLINE_NEVER work_4id(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 195);
}

static uint64_t INLINE_NEVER work_4ie(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 196);
}

static uint64_t INLINE_NEVER work_4if(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 197);
}

static uint64_t INLINE_NEVER work_4ig(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 198);
}

static uint64_t INLINE_NEVER work_4ih(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 199);
}

static uint64_t INLINE_NEVER work_4ii(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 200);
}

static uint64_t INLINE_NEVER work_4ij(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 201);
}

static uint64_t INLINE_NEVER work_4ik(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 202);
}

static uint64_t INLINE_NEVER work_4il(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 203);
}

static uint64_t INLINE_NEVER work_4im(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 204);
}

static uint64_t INLINE_NEVER work_4in(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 205);
}

static uint64_t INLINE_NEVER work_4io(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 206);
}

static uint64_t INLINE_NEVER work_4ip(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 207);
}

static uint64_t INLINE_NEVER work_4iq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 208);
}

static uint64_t INLINE_NEVER work_4ir(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 209);
}

static uint64_t INLINE_NEVER work_4is(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 210);
}

static uint64_t INLINE_NEVER work_4it(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 211);
}

static uint64_t INLINE_NEVER work_4iu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 212);
}

static uint64_t INLINE_NEVER work_4iv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 213);
}

static uint64_t INLINE_NEVER work_4iw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 214);
}

static uint64_t INLINE_NEVER work_4ix(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 215);
}

static uint64_t INLINE_NEVER work_4ja(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 216);
}

static uint64_t INLINE_NEVER work_4jb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 217);
}

static uint64_t INLINE_NEVER work_4jc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 218);
}

static uint64_t INLINE_NEVER work_4jd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 219);
}

static uint64_t INLINE_NEVER work_4je(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 220);
}

static uint64_t INLINE_NEVER work_4jf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 221);
}

static uint64_t INLINE_NEVER work_4jg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 222);
}

static uint64_t INLINE_NEVER work_4jh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 223);
}

static uint64_t INLINE_NEVER work_4ji(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 224);
}

static uint64_t INLINE_NEVER work_4jj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 225);
}

static uint64_t INLINE_NEVER work_4jk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 225);
}

static uint64_t INLINE_NEVER work_4jl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 226);
}

static uint64_t INLINE_NEVER work_4jm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 228);
}

static uint64_t INLINE_NEVER work_4jn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 229);
}

static uint64_t INLINE_NEVER work_4jo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 230);
}

static uint64_t INLINE_NEVER work_4jp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 231);
}

static uint64_t INLINE_NEVER work_4jq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 232);
}

static uint64_t INLINE_NEVER work_4jr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 233);
}

static uint64_t INLINE_NEVER work_4js(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 234);
}

static uint64_t INLINE_NEVER work_4jt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 235);
}

static uint64_t INLINE_NEVER work_4ju(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 236);
}

static uint64_t INLINE_NEVER work_4jv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 237);
}

static uint64_t INLINE_NEVER work_4jw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 238);
}

static uint64_t INLINE_NEVER work_4jx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 239);
}

static uint64_t INLINE_NEVER work_4ka(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 240);
}

static uint64_t INLINE_NEVER work_4kb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 241);
}

static uint64_t INLINE_NEVER work_4kc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 242);
}

static uint64_t INLINE_NEVER work_4kd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 243);
}

static uint64_t INLINE_NEVER work_4ke(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 244);
}

static uint64_t INLINE_NEVER work_4kf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 245);
}

static uint64_t INLINE_NEVER work_4kg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 246);
}

static uint64_t INLINE_NEVER work_4kh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 247);
}

static uint64_t INLINE_NEVER work_4ki(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 248);
}

static uint64_t INLINE_NEVER work_4kj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 249);
}

static uint64_t INLINE_NEVER work_4kk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 250);
}

static uint64_t INLINE_NEVER work_4kl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 251);
}

static uint64_t INLINE_NEVER work_4km(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 252);
}

static uint64_t INLINE_NEVER work_4kn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 253);
}

static uint64_t INLINE_NEVER work_4ko(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 254);
}

static uint64_t INLINE_NEVER work_4kp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 255);
}

static uint64_t INLINE_NEVER work_4kq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 256);
}

static uint64_t INLINE_NEVER work_4kr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 257);
}

static uint64_t INLINE_NEVER work_4ks(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 258);
}

static uint64_t INLINE_NEVER work_4kt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 259);
}

static uint64_t INLINE_NEVER work_4ku(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 260);
}

static uint64_t INLINE_NEVER work_4kv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 261);
}

static uint64_t INLINE_NEVER work_4kw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 262);
}

static uint64_t INLINE_NEVER work_4kx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 263);
}

static uint64_t INLINE_NEVER work_4la(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 264);
}

static uint64_t INLINE_NEVER work_4lb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 265);
}

static uint64_t INLINE_NEVER work_4lc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 266);
}

static uint64_t INLINE_NEVER work_4ld(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 267);
}

static uint64_t INLINE_NEVER work_4le(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 268);
}

static uint64_t INLINE_NEVER work_4lf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 269);
}

static uint64_t INLINE_NEVER work_4lg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 270);
}

static uint64_t INLINE_NEVER work_4lh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 271);
}

static uint64_t INLINE_NEVER work_4li(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 272);
}

static uint64_t INLINE_NEVER work_4lj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 273);
}

static uint64_t INLINE_NEVER work_4lk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 274);
}

static uint64_t INLINE_NEVER work_4ll(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 275);
}

static uint64_t INLINE_NEVER work_4lm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 276);
}

static uint64_t INLINE_NEVER work_4ln(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 277);
}

static uint64_t INLINE_NEVER work_4lo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 278);
}

static uint64_t INLINE_NEVER work_4lp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 279);
}

static uint64_t INLINE_NEVER work_4lq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 280);
}

static uint64_t INLINE_NEVER work_4lr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 281);
}

static uint64_t INLINE_NEVER work_4ls(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 282);
}

static uint64_t INLINE_NEVER work_4lt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 283);
}

static uint64_t INLINE_NEVER work_4lu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 284);
}

static uint64_t INLINE_NEVER work_4lv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 285);
}

static uint64_t INLINE_NEVER work_4lw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 286);
}

static uint64_t INLINE_NEVER work_4lx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 287);
}

static uint64_t INLINE_NEVER work_4ma(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 288);
}

static uint64_t INLINE_NEVER work_4mb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 289);
}

static uint64_t INLINE_NEVER work_4mc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 290);
}

static uint64_t INLINE_NEVER work_4md(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 291);
}

static uint64_t INLINE_NEVER work_4me(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 292);
}

static uint64_t INLINE_NEVER work_4mf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 293);
}

static uint64_t INLINE_NEVER work_4mg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 294);
}

static uint64_t INLINE_NEVER work_4mh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 295);
}

static uint64_t INLINE_NEVER work_4mi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 296);
}

static uint64_t INLINE_NEVER work_4mj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 297);
}

static uint64_t INLINE_NEVER work_4mk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 298);
}

static uint64_t INLINE_NEVER work_4ml(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 299);
}

static uint64_t INLINE_NEVER work_4mm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 300);
}

static uint64_t INLINE_NEVER work_4mn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 301);
}

static uint64_t INLINE_NEVER work_4mo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 302);
}

static uint64_t INLINE_NEVER work_4mp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 303);
}

static uint64_t INLINE_NEVER work_4mq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 304);
}

static uint64_t INLINE_NEVER work_4mr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 305);
}

static uint64_t INLINE_NEVER work_4ms(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 306);
}

static uint64_t INLINE_NEVER work_4mt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 307);
}

static uint64_t INLINE_NEVER work_4mu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 308);
}

static uint64_t INLINE_NEVER work_4mv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 309);
}

static uint64_t INLINE_NEVER work_4mw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 310);
}

static uint64_t INLINE_NEVER work_4mx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 311);
}

static uint64_t INLINE_NEVER work_4na(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 312);
}

static uint64_t INLINE_NEVER work_4nb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 313);
}

static uint64_t INLINE_NEVER work_4nc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 314);
}

static uint64_t INLINE_NEVER work_4nd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 315);
}

static uint64_t INLINE_NEVER work_4ne(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 316);
}

static uint64_t INLINE_NEVER work_4nf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 317);
}

static uint64_t INLINE_NEVER work_4ng(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 318);
}

static uint64_t INLINE_NEVER work_4nh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 319);
}

static uint64_t INLINE_NEVER work_4ni(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 320);
}

static uint64_t INLINE_NEVER work_4nj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 321);
}

static uint64_t INLINE_NEVER work_4nk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 322);
}

static uint64_t INLINE_NEVER work_4nl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 323);
}

static uint64_t INLINE_NEVER work_4nm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 324);
}

static uint64_t INLINE_NEVER work_4nn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 325);
}

static uint64_t INLINE_NEVER work_4no(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 326);
}

static uint64_t INLINE_NEVER work_4np(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 327);
}

static uint64_t INLINE_NEVER work_4nq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 328);
}

static uint64_t INLINE_NEVER work_4nr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 329);
}

static uint64_t INLINE_NEVER work_4ns(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 330);
}

static uint64_t INLINE_NEVER work_4nt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 331);
}

static uint64_t INLINE_NEVER work_4nu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 332);
}

static uint64_t INLINE_NEVER work_4nv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 333);
}

static uint64_t INLINE_NEVER work_4nw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 334);
}

static uint64_t INLINE_NEVER work_4nx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 335);
}

static uint64_t INLINE_NEVER work_4oa(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 336);
}

static uint64_t INLINE_NEVER work_4ob(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 337);
}

static uint64_t INLINE_NEVER work_4oc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 338);
}

static uint64_t INLINE_NEVER work_4od(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 339);
}

static uint64_t INLINE_NEVER work_4oe(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 340);
}

static uint64_t INLINE_NEVER work_4of(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 341);
}

static uint64_t INLINE_NEVER work_4og(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 342);
}

static uint64_t INLINE_NEVER work_4oh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 343);
}

static uint64_t INLINE_NEVER work_4oi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 344);
}

static uint64_t INLINE_NEVER work_4oj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 345);
}

static uint64_t INLINE_NEVER work_4ok(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 346);
}

static uint64_t INLINE_NEVER work_4ol(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 347);
}

static uint64_t INLINE_NEVER work_4om(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 348);
}

static uint64_t INLINE_NEVER work_4on(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 349);
}

static uint64_t INLINE_NEVER work_4oo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 350);
}

static uint64_t INLINE_NEVER work_4op(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 351);
}

static uint64_t INLINE_NEVER work_4oq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 352);
}

static uint64_t INLINE_NEVER work_4or(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 353);
}

static uint64_t INLINE_NEVER work_4os(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 354);
}

static uint64_t INLINE_NEVER work_4ot(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 355);
}

static uint64_t INLINE_NEVER work_4ou(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 356);
}

static uint64_t INLINE_NEVER work_4ov(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 357);
}

static uint64_t INLINE_NEVER work_4ow(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 358);
}

static uint64_t INLINE_NEVER work_4ox(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 359);
}

static uint64_t INLINE_NEVER work_4pa(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 360);
}

static uint64_t INLINE_NEVER work_4pb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 361);
}

static uint64_t INLINE_NEVER work_4pc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 362);
}

static uint64_t INLINE_NEVER work_4pd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 363);
}

static uint64_t INLINE_NEVER work_4pe(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 364);
}

static uint64_t INLINE_NEVER work_4pf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 365);
}

static uint64_t INLINE_NEVER work_4pg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 366);
}

static uint64_t INLINE_NEVER work_4ph(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 367);
}

static uint64_t INLINE_NEVER work_4pi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 368);
}

static uint64_t INLINE_NEVER work_4pj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 369);
}

static uint64_t INLINE_NEVER work_4pk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 370);
}

static uint64_t INLINE_NEVER work_4pl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 371);
}

static uint64_t INLINE_NEVER work_4pm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 372);
}

static uint64_t INLINE_NEVER work_4pn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 373);
}

static uint64_t INLINE_NEVER work_4po(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 374);
}

static uint64_t INLINE_NEVER work_4pp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 375);
}

static uint64_t INLINE_NEVER work_4pq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 376);
}

static uint64_t INLINE_NEVER work_4pr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 377);
}

static uint64_t INLINE_NEVER work_4ps(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 378);
}

static uint64_t INLINE_NEVER work_4pt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 379);
}

static uint64_t INLINE_NEVER work_4pu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 380);
}

static uint64_t INLINE_NEVER work_4pv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 381);
}

static uint64_t INLINE_NEVER work_4pw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 382);
}

static uint64_t INLINE_NEVER work_4px(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 383);
}

static uint64_t INLINE_NEVER work_4qa(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 384);
}

static uint64_t INLINE_NEVER work_4qb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 385);
}

static uint64_t INLINE_NEVER work_4qc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 386);
}

static uint64_t INLINE_NEVER work_4qd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 387);
}

static uint64_t INLINE_NEVER work_4qe(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 388);
}

static uint64_t INLINE_NEVER work_4qf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 389);
}

static uint64_t INLINE_NEVER work_4qg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 390);
}

static uint64_t INLINE_NEVER work_4qh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 391);
}

static uint64_t INLINE_NEVER work_4qi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 392);
}

static uint64_t INLINE_NEVER work_4qj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 393);
}

static uint64_t INLINE_NEVER work_4qk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 394);
}

static uint64_t INLINE_NEVER work_4ql(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 395);
}

static uint64_t INLINE_NEVER work_4qm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 396);
}

static uint64_t INLINE_NEVER work_4qn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 397);
}

static uint64_t INLINE_NEVER work_4qo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 398);
}

static uint64_t INLINE_NEVER work_4qp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 399);
}

static uint64_t INLINE_NEVER work_4qq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 400);
}

static uint64_t INLINE_NEVER work_4qr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 401);
}

static uint64_t INLINE_NEVER work_4qs(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 402);
}

static uint64_t INLINE_NEVER work_4qt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 403);
}

static uint64_t INLINE_NEVER work_4qu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 404);
}

static uint64_t INLINE_NEVER work_4qv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 405);
}

static uint64_t INLINE_NEVER work_4qw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 406);
}

static uint64_t INLINE_NEVER work_4qx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 407);
}

static uint64_t INLINE_NEVER work_4ra(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 408);
}

static uint64_t INLINE_NEVER work_4rb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 409);
}

static uint64_t INLINE_NEVER work_4rc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 410);
}

static uint64_t INLINE_NEVER work_4rd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 411);
}

static uint64_t INLINE_NEVER work_4re(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 412);
}

static uint64_t INLINE_NEVER work_4rf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 413);
}

static uint64_t INLINE_NEVER work_4rg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 414);
}

static uint64_t INLINE_NEVER work_4rh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 415);
}

static uint64_t INLINE_NEVER work_4ri(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 416);
}

static uint64_t INLINE_NEVER work_4rj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 417);
}

static uint64_t INLINE_NEVER work_4rk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 418);
}

static uint64_t INLINE_NEVER work_4rl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 419);
}

static uint64_t INLINE_NEVER work_4rm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 420);
}

static uint64_t INLINE_NEVER work_4rn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 421);
}

static uint64_t INLINE_NEVER work_4ro(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 422);
}

static uint64_t INLINE_NEVER work_4rp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 423);
}

static uint64_t INLINE_NEVER work_4rq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 424);
}

static uint64_t INLINE_NEVER work_4rr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 425);
}

static uint64_t INLINE_NEVER work_4rs(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 426);
}

static uint64_t INLINE_NEVER work_4rt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 427);
}

static uint64_t INLINE_NEVER work_4ru(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 428);
}

static uint64_t INLINE_NEVER work_4rv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 429);
}

static uint64_t INLINE_NEVER work_4rw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 430);
}

static uint64_t INLINE_NEVER work_4rx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 431);
}

static uint64_t INLINE_NEVER work_4sa(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 432);
}

static uint64_t INLINE_NEVER work_4sb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 433);
}

static uint64_t INLINE_NEVER work_4sc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 434);
}

static uint64_t INLINE_NEVER work_4sd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 435);
}

static uint64_t INLINE_NEVER work_4se(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 436);
}

static uint64_t INLINE_NEVER work_4sf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 437);
}

static uint64_t INLINE_NEVER work_4sg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 438);
}

static uint64_t INLINE_NEVER work_4sh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 439);
}

static uint64_t INLINE_NEVER work_4si(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 440);
}

static uint64_t INLINE_NEVER work_4sj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 441);
}

static uint64_t INLINE_NEVER work_4sk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 442);
}

static uint64_t INLINE_NEVER work_4sl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 443);
}

static uint64_t INLINE_NEVER work_4sm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 444);
}

static uint64_t INLINE_NEVER work_4sn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 445);
}

static uint64_t INLINE_NEVER work_4so(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 446);
}

static uint64_t INLINE_NEVER work_4sp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 447);
}

static uint64_t INLINE_NEVER work_4sq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 448);
}

static uint64_t INLINE_NEVER work_4sr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 449);
}

static uint64_t INLINE_NEVER work_4ss(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 450);
}

static uint64_t INLINE_NEVER work_4st(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 451);
}

static uint64_t INLINE_NEVER work_4su(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 452);
}

static uint64_t INLINE_NEVER work_4sv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 453);
}

static uint64_t INLINE_NEVER work_4sw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 454);
}

static uint64_t INLINE_NEVER work_4sx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 455);
}

static uint64_t INLINE_NEVER work_4ta(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 456);
}

static uint64_t INLINE_NEVER work_4tb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 457);
}

static uint64_t INLINE_NEVER work_4tc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 458);
}

static uint64_t INLINE_NEVER work_4td(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 459);
}

static uint64_t INLINE_NEVER work_4te(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 460);
}

static uint64_t INLINE_NEVER work_4tf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 461);
}

static uint64_t INLINE_NEVER work_4tg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 462);
}

static uint64_t INLINE_NEVER work_4th(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 463);
}

static uint64_t INLINE_NEVER work_4ti(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 464);
}

static uint64_t INLINE_NEVER work_4tj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 465);
}

static uint64_t INLINE_NEVER work_4tk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 466);
}

static uint64_t INLINE_NEVER work_4tl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 467);
}

static uint64_t INLINE_NEVER work_4tm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 468);
}

static uint64_t INLINE_NEVER work_4tn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 469);
}

static uint64_t INLINE_NEVER work_4to(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 470);
}

static uint64_t INLINE_NEVER work_4tp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 471);
}

static uint64_t INLINE_NEVER work_4tq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 472);
}

static uint64_t INLINE_NEVER work_4tr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 473);
}

static uint64_t INLINE_NEVER work_4ts(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 474);
}

static uint64_t INLINE_NEVER work_4tt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 475);
}

static uint64_t INLINE_NEVER work_4tu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 476);
}

static uint64_t INLINE_NEVER work_4tv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 477);
}

static uint64_t INLINE_NEVER work_4tw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 478);
}

static uint64_t INLINE_NEVER work_4tx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 479);
}

static uint64_t INLINE_NEVER work_4ua(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 480);
}

static uint64_t INLINE_NEVER work_4ub(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 481);
}

static uint64_t INLINE_NEVER work_4uc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 482);
}

static uint64_t INLINE_NEVER work_4ud(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 483);
}

static uint64_t INLINE_NEVER work_4ue(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 484);
}

static uint64_t INLINE_NEVER work_4uf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 485);
}

static uint64_t INLINE_NEVER work_4ug(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 486);
}

static uint64_t INLINE_NEVER work_4uh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 487);
}

static uint64_t INLINE_NEVER work_4ui(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 488);
}

static uint64_t INLINE_NEVER work_4uj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 489);
}

static uint64_t INLINE_NEVER work_4uk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 490);
}

static uint64_t INLINE_NEVER work_4ul(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 491);
}

static uint64_t INLINE_NEVER work_4um(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 492);
}

static uint64_t INLINE_NEVER work_4un(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 493);
}

static uint64_t INLINE_NEVER work_4uo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 494);
}

static uint64_t INLINE_NEVER work_4up(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 495);
}

static uint64_t INLINE_NEVER work_4uq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 496);
}

static uint64_t INLINE_NEVER work_4ur(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 497);
}

static uint64_t INLINE_NEVER work_4us(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 498);
}

static uint64_t INLINE_NEVER work_4ut(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 499);
}

static uint64_t INLINE_NEVER work_4uu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 500);
}

static uint64_t INLINE_NEVER work_4uv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 501);
}

static uint64_t INLINE_NEVER work_4uw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 502);
}

static uint64_t INLINE_NEVER work_4ux(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 503);
}

static uint64_t INLINE_NEVER work_4va(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 504);
}

static uint64_t INLINE_NEVER work_4vb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 505);
}

static uint64_t INLINE_NEVER work_4vc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 506);
}

static uint64_t INLINE_NEVER work_4vd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 507);
}

static uint64_t INLINE_NEVER work_4ve(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 508);
}

static uint64_t INLINE_NEVER work_4vf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 509);
}

static uint64_t INLINE_NEVER work_4vg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 510);
}

static uint64_t INLINE_NEVER work_4vh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 511);
}

static uint64_t INLINE_NEVER work_4vi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 512);
}

static uint64_t INLINE_NEVER work_4vj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 513);
}

static uint64_t INLINE_NEVER work_4vk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 514);
}

static uint64_t INLINE_NEVER work_4vl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 515);
}

static uint64_t INLINE_NEVER work_4vm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 516);
}

static uint64_t INLINE_NEVER work_4vn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 517);
}

static uint64_t INLINE_NEVER work_4vo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 518);
}

static uint64_t INLINE_NEVER work_4vp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 519);
}

static uint64_t INLINE_NEVER work_4vq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 520);
}

static uint64_t INLINE_NEVER work_4vr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 521);
}

static uint64_t INLINE_NEVER work_4vs(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 522);
}

static uint64_t INLINE_NEVER work_4vt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 523);
}

static uint64_t INLINE_NEVER work_4vu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 524);
}

static uint64_t INLINE_NEVER work_4vv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 525);
}

static uint64_t INLINE_NEVER work_4vw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 526);
}

static uint64_t INLINE_NEVER work_4vx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 527);
}

static uint64_t INLINE_NEVER work_4wa(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 528);
}

static uint64_t INLINE_NEVER work_4wb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 529);
}

static uint64_t INLINE_NEVER work_4wc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 530);
}

static uint64_t INLINE_NEVER work_4wd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 531);
}

static uint64_t INLINE_NEVER work_4we(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 532);
}

static uint64_t INLINE_NEVER work_4wf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 533);
}

static uint64_t INLINE_NEVER work_4wg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 534);
}

static uint64_t INLINE_NEVER work_4wh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 535);
}

static uint64_t INLINE_NEVER work_4wi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 536);
}

static uint64_t INLINE_NEVER work_4wj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 537);
}

static uint64_t INLINE_NEVER work_4wk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 538);
}

static uint64_t INLINE_NEVER work_4wl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 539);
}

static uint64_t INLINE_NEVER work_4wm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 540);
}

static uint64_t INLINE_NEVER work_4wn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 541);
}

static uint64_t INLINE_NEVER work_4wo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 542);
}

static uint64_t INLINE_NEVER work_4wp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 543);
}

static uint64_t INLINE_NEVER work_4wq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 544);
}

static uint64_t INLINE_NEVER work_4wr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 545);
}

static uint64_t INLINE_NEVER work_4ws(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 546);
}

static uint64_t INLINE_NEVER work_4wt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 547);
}

static uint64_t INLINE_NEVER work_4wu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 548);
}

static uint64_t INLINE_NEVER work_4wv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 549);
}

static uint64_t INLINE_NEVER work_4ww(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 550);
}

static uint64_t INLINE_NEVER work_4wx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 551);
}

static uint64_t INLINE_NEVER work_4xa(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 552);
}

static uint64_t INLINE_NEVER work_4xb(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 553);
}

static uint64_t INLINE_NEVER work_4xc(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 554);
}

static uint64_t INLINE_NEVER work_4xd(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 555);
}

static uint64_t INLINE_NEVER work_4xe(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 556);
}

static uint64_t INLINE_NEVER work_4xf(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 557);
}

static uint64_t INLINE_NEVER work_4xg(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 558);
}

static uint64_t INLINE_NEVER work_4xh(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 559);
}

static uint64_t INLINE_NEVER work_4xi(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 560);
}

static uint64_t INLINE_NEVER work_4xj(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 561);
}

static uint64_t INLINE_NEVER work_4xk(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 562);
}

static uint64_t INLINE_NEVER work_4xl(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 563);
}

static uint64_t INLINE_NEVER work_4xm(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 564);
}

static uint64_t INLINE_NEVER work_4xn(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 565);
}

static uint64_t INLINE_NEVER work_4xo(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 566);
}

static uint64_t INLINE_NEVER work_4xp(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 567);
}

static uint64_t INLINE_NEVER work_4xq(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 568);
}

static uint64_t INLINE_NEVER work_4xr(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 569);
}

static uint64_t INLINE_NEVER work_4xs(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 570);
}

static uint64_t INLINE_NEVER work_4xt(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 571);
}

static uint64_t INLINE_NEVER work_4xu(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 572);
}

static uint64_t INLINE_NEVER work_4xv(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 573);
}

static uint64_t INLINE_NEVER work_4xw(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 574);
}

static uint64_t INLINE_NEVER work_4xx(uint64_t a, uint32_t *b)
{
	return WORK_4(a, b, 575);
}

static work_4_fn_t work_4[] = {
	work_4aa, work_4ab, work_4ac, work_4ad, work_4ae, work_4af, work_4ag, work_4ah,
	work_4ai, work_4aj, work_4ak, work_4al, work_4am, work_4an, work_4ao, work_4ap,
	work_4aq, work_4ar, work_4as, work_4at, work_4au, work_4av, work_4aw, work_4ax,
	work_4ba, work_4bb, work_4bc, work_4bd, work_4be, work_4bf, work_4bg, work_4bh,
	work_4bi, work_4bj, work_4bk, work_4bl, work_4bm, work_4bn, work_4bo, work_4bp,
	work_4bq, work_4br, work_4bs, work_4bt, work_4bu, work_4bv, work_4bw, work_4bx,
	work_4ca, work_4cb, work_4cc, work_4cd, work_4ce, work_4cf, work_4cg, work_4ch,
	work_4ci, work_4cj, work_4ck, work_4cl, work_4cm, work_4cn, work_4co, work_4cp,
	work_4cq, work_4cr, work_4cs, work_4ct, work_4cu, work_4cv, work_4cw, work_4cx,
	work_4da, work_4db, work_4dc, work_4dd, work_4de, work_4df, work_4dg, work_4dh,
	work_4di, work_4dj, work_4dk, work_4dl, work_4dm, work_4dn, work_4do, work_4dp,
	work_4dq, work_4dr, work_4ds, work_4dt, work_4du, work_4dv, work_4dw, work_4dx,
	work_4ea, work_4eb, work_4ec, work_4ed, work_4ee, work_4ef, work_4eg, work_4eh,
	work_4ei, work_4ej, work_4ek, work_4el, work_4em, work_4en, work_4eo, work_4ep,
	work_4eq, work_4er, work_4es, work_4et, work_4eu, work_4ev, work_4ew, work_4ex,
	work_4fa, work_4fb, work_4fc, work_4fd, work_4fe, work_4ff, work_4fg, work_4fh,
	work_4fi, work_4fj, work_4fk, work_4fl, work_4fm, work_4fn, work_4fo, work_4fp,
	work_4fq, work_4fr, work_4fs, work_4ft, work_4fu, work_4fv, work_4fw, work_4fx,
	work_4ga, work_4gb, work_4gc, work_4gd, work_4ge, work_4gf, work_4gg, work_4gh,
	work_4gi, work_4gj, work_4gk, work_4gl, work_4gm, work_4gn, work_4go, work_4gp,
	work_4gq, work_4gr, work_4gs, work_4gt, work_4gu, work_4gv, work_4gw, work_4gx,
	work_4ha, work_4hb, work_4hc, work_4hd, work_4he, work_4hf, work_4hg, work_4hh,
	work_4hi, work_4hj, work_4hk, work_4hl, work_4hm, work_4hn, work_4ho, work_4hp,
	work_4hq, work_4hr, work_4hs, work_4ht, work_4hu, work_4hv, work_4hw, work_4hx,
	work_4ia, work_4ib, work_4ic, work_4id, work_4ie, work_4if, work_4ig, work_4ih,
	work_4ii, work_4ij, work_4ik, work_4il, work_4im, work_4in, work_4io, work_4ip,
	work_4iq, work_4ir, work_4is, work_4it, work_4iu, work_4iv, work_4iw, work_4ix,
	work_4ja, work_4jb, work_4jc, work_4jd, work_4je, work_4jf, work_4jg, work_4jh,
	work_4ji, work_4jj, work_4jk, work_4jl, work_4jm, work_4jn, work_4jo, work_4jp,
	work_4jq, work_4jr, work_4js, work_4jt, work_4ju, work_4jv, work_4jw, work_4jx,
	work_4ka, work_4kb, work_4kc, work_4kd, work_4ke, work_4kf, work_4kg, work_4kh,
	work_4ki, work_4kj, work_4kk, work_4kl, work_4km, work_4kn, work_4ko, work_4kp,
	work_4kq, work_4kr, work_4ks, work_4kt, work_4ku, work_4kv, work_4kw, work_4kx,
	work_4la, work_4lb, work_4lc, work_4ld, work_4le, work_4lf, work_4lg, work_4lh,
	work_4li, work_4lj, work_4lk, work_4ll, work_4lm, work_4ln, work_4lo, work_4lp,
	work_4lq, work_4lr, work_4ls, work_4lt, work_4lu, work_4lv, work_4lw, work_4lx,
	work_4ma, work_4mb, work_4mc, work_4md, work_4me, work_4mf, work_4mg, work_4mh,
	work_4mi, work_4mj, work_4mk, work_4ml, work_4mm, work_4mn, work_4mo, work_4mp,
	work_4mq, work_4mr, work_4ms, work_4mt, work_4mu, work_4mv, work_4mw, work_4mx,
	work_4na, work_4nb, work_4nc, work_4nd, work_4ne, work_4nf, work_4ng, work_4nh,
	work_4ni, work_4nj, work_4nk, work_4nl, work_4nm, work_4nn, work_4no, work_4np,
	work_4nq, work_4nr, work_4ns, work_4nt, work_4nu, work_4nv, work_4nw, work_4nx,
	work_4oa, work_4ob, work_4oc, work_4od, work_4oe, work_4of, work_4og, work_4oh,
	work_4oi, work_4oj, work_4ok, work_4ol, work_4om, work_4on, work_4oo, work_4op,
	work_4oq, work_4or, work_4os, work_4ot, work_4ou, work_4ov, work_4ow, work_4ox,
	work_4pa, work_4pb, work_4pc, work_4pd, work_4pe, work_4pf, work_4pg, work_4ph,
	work_4pi, work_4pj, work_4pk, work_4pl, work_4pm, work_4pn, work_4po, work_4pp,
	work_4pq, work_4pr, work_4ps, work_4pt, work_4pu, work_4pv, work_4pw, work_4px,
	work_4qa, work_4qb, work_4qc, work_4qd, work_4qe, work_4qf, work_4qg, work_4qh,
	work_4qi, work_4qj, work_4qk, work_4ql, work_4qm, work_4qn, work_4qo, work_4qp,
	work_4qq, work_4qr, work_4qs, work_4qt, work_4qu, work_4qv, work_4qw, work_4qx,
	work_4ra, work_4rb, work_4rc, work_4rd, work_4re, work_4rf, work_4rg, work_4rh,
	work_4ri, work_4rj, work_4rk, work_4rl, work_4rm, work_4rn, work_4ro, work_4rp,
	work_4rq, work_4rr, work_4rs, work_4rt, work_4ru, work_4rv, work_4rw, work_4rx,
	work_4sa, work_4sb, work_4sc, work_4sd, work_4se, work_4sf, work_4sg, work_4sh,
	work_4si, work_4sj, work_4sk, work_4sl, work_4sm, work_4sn, work_4so, work_4sp,
	work_4sq, work_4sr, work_4ss, work_4st, work_4su, work_4sv, work_4sw, work_4sx,
	work_4ta, work_4tb, work_4tc, work_4td, work_4te, work_4tf, work_4tg, work_4th,
	work_4ti, work_4tj, work_4tk, work_4tl, work_4tm, work_4tn, work_4to, work_4tp,
	work_4tq, work_4tr, work_4ts, work_4tt, work_4tu, work_4tv, work_4tw, work_4tx,
	work_4ua, work_4ub, work_4uc, work_4ud, work_4ue, work_4uf, work_4ug, work_4uh,
	work_4ui, work_4uj, work_4uk, work_4ul, work_4um, work_4un, work_4uo, work_4up,
	work_4uq, work_4ur, work_4us, work_4ut, work_4uu, work_4uv, work_4uw, work_4ux,
	work_4va, work_4vb, work_4vc, work_4vd, work_4ve, work_4vf, work_4vg, work_4vh,
	work_4vi, work_4vj, work_4vk, work_4vl, work_4vm, work_4vn, work_4vo, work_4vp,
	work_4vq, work_4vr, work_4vs, work_4vt, work_4vu, work_4vv, work_4vw, work_4vx,
	work_4wa, work_4wb, work_4wc, work_4wd, work_4we, work_4wf, work_4wg, work_4wh,
	work_4wi, work_4wj, work_4wk, work_4wl, work_4wm, work_4wn, work_4wo, work_4wp,
	work_4wq, work_4wr, work_4ws, work_4wt, work_4wu, work_4wv, work_4ww, work_4wx,
	work_4xa, work_4xb, work_4xc, work_4xd, work_4xe, work_4xf, work_4xg, work_4xh,
	work_4xi, work_4xj, work_4xk, work_4xl, work_4xm, work_4xn, work_4xo, work_4xp,
	work_4xq, work_4xr, work_4xs, work_4xt, work_4xu, work_4xv, work_4xw, work_4xx
};

static uint16_t work_4_rnd[] = {
	179, 285, 182, 547, 171, 346, 155, 505, 402,  81, 472, 409, 234,  79, 477, 341,
	151, 215, 318,   0, 408, 461,  57, 314, 438, 165, 486,  61, 205, 310,  16, 245,
	453, 572, 493, 533,  10, 296,  32, 437,  92, 507,  12, 238, 336, 444, 223, 419,
	 30, 449,  52, 366,  88, 567, 333,  77,  84, 345, 130,  75, 443, 227, 349, 384,
	 15, 184, 220, 556, 133, 361,  23, 511, 209, 322, 403,  59, 376, 213, 263, 162,
	252, 259, 125, 168, 332, 177, 200, 246, 370, 526, 123, 175, 255, 365,  85, 464,
	520, 463, 235, 191, 316, 452, 350, 465, 427, 410, 275, 126, 265, 565, 289, 154,
	569, 448, 374, 483, 192, 436, 319, 105, 383, 144,  27, 250,  39, 313, 379, 257,
	120, 535, 382, 121, 490, 460, 397, 531,  65, 399, 232, 390, 529, 367, 185, 508,
	237,  26, 396, 308, 391,  60, 389, 145, 170, 117, 439, 301, 189, 315, 320,  36,
	 42,  43,  94, 552, 112, 456, 124, 169, 115,   6,  20, 442, 525, 551, 298, 150,
	570, 173, 378, 221, 513, 538, 424, 138,  91, 360, 434, 167, 199, 204,  70, 479,
	 44, 156, 433, 114, 174, 423,  82, 242, 368, 446,   8,   5, 545, 194, 190, 323,
	417, 139, 455, 217, 226, 447, 377, 451, 405,  69, 253, 539,  80, 288, 160, 295,
	 11, 198, 387, 268, 503,  51, 413, 214, 412, 329, 415, 317, 364, 468, 216, 236,
	 22, 163, 148, 481, 532, 562,  86,  89,  98, 264, 300, 414, 563, 311, 542,  63,
	282,  56, 159,  33, 136, 111, 568, 528,   1, 110, 230, 518, 394, 516, 260, 432,
	454,  35, 571, 458, 355, 243,  37, 206, 351, 489,  76, 475, 312, 328, 347, 211,
	375, 359, 101, 109, 353, 292, 183, 240,  96, 386, 339, 335, 143, 212, 515, 119,
	305, 342,  62, 269, 557, 548, 248, 496,  50, 421,  99,  48, 202,   2, 521, 330,
	283, 512, 457, 307, 474, 372, 135, 471,  25,  90, 277, 392,  41, 546, 131,  38,
	304,  55, 172, 440, 207, 271, 258, 380, 530, 431,  17, 430, 100,  47, 180, 262,
	543, 534,  74, 152, 356, 574, 233, 325, 181, 494, 222,  72, 266, 106, 134, 358,
	426, 467, 502,  67,  83, 128, 147, 416, 418, 371, 157, 491, 231, 422, 321, 149,
	281,  24, 195, 536,  95, 411, 498, 166, 122, 395,  21, 537, 401, 303, 108, 186,
	  7, 306, 188, 550, 385, 104, 178, 500, 514, 210,  46, 196, 309, 478, 247, 485,
	251, 129, 575, 469, 193, 564, 197, 103, 102, 337, 388, 294,  66,   4, 343, 425,
	 73, 558, 400, 116, 239, 524, 519, 504, 153, 429, 549, 302, 450, 290, 357, 267,
	228, 229, 127, 509, 404,  93, 352, 393, 299, 241, 373, 435, 187, 559, 484, 555,
	362,  29, 573,  54, 176, 506,  49, 218, 291, 113, 517, 273,   3,  58, 324, 287,
	381, 219, 522, 225, 499, 297,  28, 286, 338, 270, 208,  87, 142, 406, 560, 327,
	407, 466, 274, 334, 527, 488,   9, 118, 272, 140, 476, 445,  71, 523,  19, 279,
	 14, 132, 161,  31, 164, 470, 276, 224, 278,  64, 541, 487,  68, 348, 201, 344,
	482,  45,  34, 107, 561, 428, 354, 420, 495, 363,  40, 340, 280, 441,  53, 473,
	 13, 497, 501, 331, 244, 462, 459, 254, 492, 137, 141, 293, 203, 566,  78,  18,
	284, 398, 510, 554, 540, 261, 249, 544, 256, 326,  97, 480, 146, 369, 553, 158
};

static int worker_thread(void *arg)
{
	int thr;
	uint32_t i, exit_test;
	uint64_t c1, c2;
	odp_time_t t1, t2;
	thread_arg_t *thread_arg = arg;
	test_global_t *global = thread_arg->global;
	test_stat_t *stat = &thread_arg->stat;
	test_options_t *test_options = &global->test_options;
	const uint32_t num_func = test_options->num_func;
	const int pattern = test_options->pattern;
	uint64_t rounds = test_options->rounds;
	uint64_t dummy_sum = 0;
	uint32_t *b = global->worker_mem;
	uint32_t *c = b;

	thr = odp_thread_id();
	printf("Thread %i starting on CPU %i\n", thr, odp_cpu_id());

	/* Start all workers at the same time */
	odp_barrier_wait(&global->barrier);

	c1 = odp_cpu_cycles();
	t1 = odp_time_local_strict();

	while (1) {
		exit_test = odp_atomic_load_u32(&global->exit_test);
		if (rounds == 0)
			exit_test += 1;

		if (exit_test)
			break;

		for (i = 0; i < num_func; i++) {
			uint32_t i0 = i;
			uint32_t i1 = i;
			uint32_t i2 = i;
			uint32_t i3 = i;
			uint32_t i4 = i;

			if (pattern == PATTERN_RANDOM) {
				i0 = work_0_rnd[i];
				i1 = work_1_rnd[i];
				i2 = work_2_rnd[i];
				i3 = work_3_rnd[i];
				i4 = work_4_rnd[i];
			}

			dummy_sum += work_0[i0](dummy_sum, b, c);

			dummy_sum += work_1[i1](dummy_sum, b, c);

			dummy_sum += work_2[i2](dummy_sum, b, c);

			dummy_sum += work_3[i3](dummy_sum, b);

			dummy_sum += work_4[i4](dummy_sum, b);
		}

		rounds--;
	}

	t2 = odp_time_local_strict();
	c2 = odp_cpu_cycles();

	/* Update stats*/
	rounds = test_options->rounds - rounds;
	stat->loops     = rounds * num_func;
	stat->tot_nsec  = odp_time_diff_ns(t2, t1);
	stat->cycles    = odp_cpu_cycles_diff(c2, c1);
	stat->dummy_sum = dummy_sum;

	return 0;
}

static int start_workers(test_global_t *global, odp_instance_t instance)
{
	odph_thread_common_param_t thr_common;
	int i, ret;
	test_options_t *test_options = &global->test_options;
	const int num_cpu = test_options->num_cpu;
	odph_thread_param_t thr_param[num_cpu];

	memset(global->thread_tbl, 0, sizeof(global->thread_tbl));
	odph_thread_common_param_init(&thr_common);

	thr_common.instance = instance;
	thr_common.cpumask  = &global->cpumask;

	for (i = 0; i < num_cpu; i++) {
		odph_thread_param_init(&thr_param[i]);
		thr_param[i].start    = worker_thread;
		thr_param[i].arg      = &global->thread_arg[i];
		thr_param[i].thr_type = ODP_THREAD_WORKER;
	}

	ret = odph_thread_create(global->thread_tbl, &thr_common, thr_param, num_cpu);

	if (ret != num_cpu) {
		ODPH_ERR("Thread create failed %i\n", ret);
		return -1;
	}

	return 0;
}

static void print_stat(test_global_t *global)
{
	uint32_t i;
	uint64_t nsec, loops;
	uint64_t sum_cycles = 0;
	uint64_t sum_nsec = 0;
	uint64_t sum_loops = 0;
	test_options_t *test_options = &global->test_options;
	const uint32_t num_cpu = test_options->num_cpu;
	double rate, sum_sec, ave_loops;
	const double giga = 1000000000.0;
	const double kilo = 1000.0;

	if (num_cpu == 0)
		return;

	printf("\n");
	printf("Loops per sec per thread (k / sec):\n");
	printf("-----------------------------------------------\n");
	printf("          1        2        3        4        5        6        7        8        9       10");

	for (i = 0; i < num_cpu; i++) {
		test_stat_t *stat = &global->thread_arg[i].stat;

		nsec   = stat->tot_nsec;
		loops  = stat->loops;

		if ((i % 10) == 0)
			printf("\n   ");

		if (nsec == 0) {
			printf("       0 ");
			continue;
		}

		rate = loops / (nsec / giga);
		printf("%8.1f ", rate / kilo);

		sum_nsec += nsec;
		sum_loops += loops;
		sum_cycles += stat->cycles;
	}

	sum_sec = sum_nsec / giga;
	ave_loops = sum_loops / sum_sec;

	printf("\n\n");
	printf("TOTAL (%i workers)\n", num_cpu);
	printf("  ave loops per sec:       %.1f k/sec\n", ave_loops / kilo);
	printf("  ave test run time:       %.3f msec\n", 1000 * (sum_sec / num_cpu));
	printf("  ave CPU cycles per loop: %.1f\n",
	       sum_loops > 0 ? sum_cycles / (double)sum_loops : 0);
	printf("\n");
}

static void print_usage(void)
{
	printf("\n"
	       "Instruction cache performance test options:\n"
	       "\n"
	       "  -c, --num_cpu          Number of CPUs (worker threads). 0: all available CPUs. Default: 1\n"
	       "  -r, --rounds           Number of rounds. Default: 10000\n"
	       "  -p, --pattern          Function call pattern:\n"
	       "                           0: Linear\n"
	       "                           1: Random (default)\n"
	       "  -n, --num_func         Number of functions to call per function type.\n"
	       "                           0: all functions (default)\n"
	       "  -h, --help             This help\n"
	       "\n");
}

static int parse_options(int argc, char *argv[], test_global_t *global)
{
	int opt;
	int long_index;
	test_options_t *test_options = &global->test_options;
	int ret = 0;
	uint32_t max_func = ODPH_ARRAY_SIZE(work_0);

	static const struct option longopts[] = {
		{"num_cpu",      required_argument, NULL, 'c'},
		{"rounds",       required_argument, NULL, 'r'},
		{"pattern",      required_argument, NULL, 'p'},
		{"num_func",     required_argument, NULL, 'n'},
		{"help",         no_argument,       NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:r:p:n:h";

	global->max_func = max_func;

	test_options->num_cpu     = 1;
	test_options->rounds      = 10000;
	test_options->pattern     = PATTERN_RANDOM;
	test_options->num_func    = max_func;

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'c':
			test_options->num_cpu = atoi(optarg);
			break;
		case 'r':
			test_options->rounds = atoll(optarg);
			break;
		case 'p':
			test_options->pattern = atoi(optarg);
			break;
		case 'n':
			test_options->num_func = atoi(optarg);
			break;
		case 'h':
			/* fall through */
		default:
			print_usage();
			ret = -1;
			break;
		}
	}

	if (test_options->num_func == 0)
		test_options->num_func = max_func;

	if (test_options->num_func > max_func) {
		ODPH_ERR("Bad number of functions: %u (max: %u)\n", test_options->num_func,
			 max_func);
		return -1;
	}

	/* Check that there is large enough data buffer */
	if (test_options->num_func + MAX_WORDS > DATA_SIZE_WORDS) {
		ODPH_ERR("Not enough data, %u words needed\n", test_options->num_func + MAX_WORDS);
		return -1;
	}

	return ret;
}

static int set_num_cpu(test_global_t *global)
{
	int ret;
	test_options_t *test_options = &global->test_options;
	int num_cpu = test_options->num_cpu;

	/* One thread used for the main thread */
	if (num_cpu < 0 || num_cpu > ODP_THREAD_COUNT_MAX - 1) {
		ODPH_ERR("Bad number of workers. Maximum is %i.\n", ODP_THREAD_COUNT_MAX - 1);
		return -1;
	}

	ret = odp_cpumask_default_worker(&global->cpumask, num_cpu);

	if (num_cpu && ret != num_cpu) {
		ODPH_ERR("Too many workers. Max supported %i\n.", ret);
		return -1;
	}

	/* Zero: all available workers */
	if (num_cpu == 0) {
		num_cpu = ret;
		test_options->num_cpu = num_cpu;
	}

	odp_barrier_init(&global->barrier, num_cpu + 1);

	return 0;
}

static void sig_handler(int signo)
{
	(void)signo;

	if (test_global == NULL)
		return;

	odp_atomic_add_u32(&test_global->exit_test, 1);
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

int main(int argc, char **argv)
{
	odph_helper_options_t helper_options;
	odp_instance_t instance;
	odp_init_t init;
	odp_shm_t shm, shm_global;
	test_global_t *global;
	test_options_t *test_options;
	uint64_t data_size, table_size, max_table_size;
	uint32_t i, num_cpu;
	uint32_t *data;
	odp_shm_t shm_work = ODP_SHM_INVALID;

	if (setup_sig_handler()) {
		ODPH_ERR("Signal handler setup failed\n");
		exit(EXIT_FAILURE);
	}

	/* Let helper collect its own arguments (e.g. --odph_proc) */
	argc = odph_parse_options(argc, argv);
	if (odph_options(&helper_options)) {
		ODPH_ERR("Reading ODP helper options failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_init_param_init(&init);
	init.mem_model = helper_options.mem_model;

	if (odp_init_global(&instance, &init, NULL)) {
		ODPH_ERR("Global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODPH_ERR("Local init failed.\n");
		exit(EXIT_FAILURE);
	}

	shm = odp_shm_reserve("icache perf global", sizeof(test_global_t), ODP_CACHE_LINE_SIZE, 0);
	shm_global = shm;
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("SHM reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	global = odp_shm_addr(shm);
	if (global == NULL) {
		ODPH_ERR("SHM addr failed\n");
		exit(EXIT_FAILURE);
	}
	test_global = global;

	memset(global, 0, sizeof(test_global_t));
	odp_atomic_init_u32(&global->exit_test, 0);

	for (i = 0; i < ODP_THREAD_COUNT_MAX; i++)
		global->thread_arg[i].global = global;

	if (parse_options(argc, argv, global))
		exit(EXIT_FAILURE);

	test_options = &global->test_options;

	odp_sys_info_print();

	if (set_num_cpu(global))
		exit(EXIT_FAILURE);

	num_cpu = test_options->num_cpu;

	/* Memory for workers */
	shm = odp_shm_reserve("Test memory", DATA_SIZE_WORDS * sizeof(uint32_t),
			      ODP_CACHE_LINE_SIZE, 0);
	shm_work = shm;
	if (shm == ODP_SHM_INVALID) {
		ODPH_ERR("SHM reserve failed.\n");
		exit(EXIT_FAILURE);
	}

	global->worker_mem = odp_shm_addr(shm);
	if (global->worker_mem == NULL) {
		ODPH_ERR("SHM addr failed\n");
		exit(EXIT_FAILURE);
	}

	data = (uint32_t *)global->worker_mem;
	for (i = 0; i < DATA_SIZE_WORDS; i++)
		data[i] = i;

	/* Test data usage */
	data_size = (MAX_WORDS + test_options->num_func) * sizeof(uint32_t);

	/* Function pointer and random number tables */
	table_size = NUM_WORK * test_options->num_func * (sizeof(uint16_t) + sizeof(void *));

	/* In the worst case, every table entry on separate cache line */
	max_table_size = table_size;
	if (test_options->pattern) {
		uint64_t max = NUM_WORK * global->max_func * (sizeof(uint16_t) + sizeof(void *));

		max_table_size = NUM_WORK * test_options->num_func * 2 * ODP_CACHE_LINE_SIZE;
		if (max_table_size > max)
			max_table_size = max;
	}

	printf("\n");
	printf("Test parameters\n");
	printf("  num workers         %u\n", num_cpu);
	printf("  rounds              %" PRIu64 "\n", test_options->rounds);
	printf("  call pattern        %s\n", test_options->pattern == 0 ? "linear" : "random");
	printf("  func calls          %u\n", test_options->num_func);
	printf("  min data size       %.1f kB\n", (data_size + table_size) / 1024.0);
	printf("  max data size       %.1f kB\n\n", (data_size + max_table_size) / 1024.0);

	/* Start worker threads */
	start_workers(global, instance);

	/* Wait until all workers are ready */
	odp_barrier_wait(&global->barrier);

	/* Wait workers to exit */
	odph_thread_join(global->thread_tbl, num_cpu);

	print_stat(global);

	if (odp_shm_free(shm_work)) {
		ODPH_ERR("SHM free failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_shm_free(shm_global)) {
		ODPH_ERR("SHM free failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Term local failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Term global failed.\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}

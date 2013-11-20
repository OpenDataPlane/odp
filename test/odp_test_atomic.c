/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Linaro Limited nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIALDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include "odp_test_atomic.h"

/**
 * add_sub_cnt could be any valid value
 * so to excercise explicit atomic_add/sub
 * ops. For now using 5..
 */
#define ADD_SUB_CNT	5

/**
 * Test basic atomic operation like
 * add/sub/increment/dcrement operation.
 */
void test_atomic_basic(void)
{
	unsigned int i;

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_int(&a16);
	for (i = 0; i < CNT; i++)
		odp_atomic_dec_int(&a16);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_add_int(&a16, ADD_SUB_CNT);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_sub_int(&a16, ADD_SUB_CNT);

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_u32(&a32);
	for (i = 0; i < CNT; i++)
		odp_atomic_dec_u32(&a32);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_add_u32(&a32, ADD_SUB_CNT);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_sub_u32(&a32, ADD_SUB_CNT);

	for (i = 0; i < CNT; i++)
		odp_atomic_inc_u64(&a64);
	for (i = 0; i < CNT; i++)
		odp_atomic_dec_u64(&a64);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_add_u64(&a64, ADD_SUB_CNT);
	for (i = 0; i < (CNT / ADD_SUB_CNT); i++)
		odp_atomic_fetch_sub_u64(&a64, ADD_SUB_CNT);
}


void test_atomic_init(void)
{
	odp_atomic_init_int(&a16);
	odp_atomic_init_u32(&a32);
	odp_atomic_init_u64(&a64);
}

void test_atomic_store(void)
{
	odp_atomic_store_int(&a16, 1UL << 10);
	odp_atomic_store_u32(&a32, 1UL << 10);
	odp_atomic_store_u64(&a64, 1UL << 33);
}

int test_atomic_validate(void)
{
	if (odp_atomic_load_int(&a16) != 1UL << 10) {
		printf("Atomic int usual functions failed\n");
		return -1;
	}

	if (odp_atomic_load_u32(&a32) != 1UL << 10) {
		printf("Atomic u32 usual functions failed\n");
		return -1;
	}

	if (odp_atomic_load_u64(&a64) != 1UL << 33) {
		printf("Atomic u64 usual functions failed\n");
		return -1;
	}

	printf("test OK\n");

	return 0;
}

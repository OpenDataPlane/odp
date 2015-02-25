/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <odp.h>
#include <CUnit/Basic.h>
#include <CUnit/TestDB.h>
#include "test_vectors_len.h"

/*
 * This test verifies that HW random number generator is able
 * to produce an IV for TDES_CBC cipher algorithm.
 * */
#define RNG_GET_SIZE	"RNG_GET_SIZE"
static void rng_get_size(void)
{
	int32_t ret;
	uint8_t buf[TDES_CBC_IV_LEN];

	ret = odp_random_data(buf, sizeof(buf), false);
	CU_ASSERT(ret == TDES_CBC_IV_LEN);
}

CU_TestInfo test_rng[] = {
	{ RNG_GET_SIZE, rng_get_size },
	CU_TEST_INFO_NULL,
};

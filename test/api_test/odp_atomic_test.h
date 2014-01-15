/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ATOMIC_TEST_H_
#define ODP_ATOMIC_TEST_H_

#include <odp.h>
#include <helper/odp_linux.h>

#define CNT 10000
odp_atomic_int_t a16;
odp_atomic_u32_t a32;
odp_atomic_u64_t a64;

void test_atomic_init(void);
void test_atomic_basic(void);
void test_atomic_store(void);
int test_atomic_validate(void);

#endif /* ODP_ATOMIC_TEST_H_ */

/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#ifndef ODP_CRYPTO_TEST_ASYNC_INP_
#define ODP_CRYPTO_TEST_ASYNC_INP_

#include "CUnit/TestDB.h"

/* Suite names */
#define ODP_CRYPTO_ASYNC_INP	"odp_crypto_async_inp"
#define ODP_CRYPTO_SYNC_INP    "odp_crypto_sync_inp"

/* Suite test array */
extern CU_TestInfo test_array_inp[];

int suite_sync_inp_init(void);
int suite_async_inp_init(void);

#endif

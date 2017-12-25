/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_CRYPTO_H_
#define _ODP_TEST_CRYPTO_H_

#include "odp_cunit_common.h"

/* test arrays: */
extern odp_testinfo_t crypto_suite[];

/* test array init/term functions: */
int crypto_suite_sync_init(void);
int crypto_suite_async_init(void);

/* test registry: */
extern odp_suiteinfo_t crypto_suites[];

/* executable init/term functions: */
int crypto_init(odp_instance_t *inst);
int crypto_term(odp_instance_t inst);

/* main test program: */
int crypto_main(int argc, char *argv[]);

#endif

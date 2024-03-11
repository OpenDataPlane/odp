/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 */

#ifndef _ODP_TEST_PARSER_H_
#define _ODP_TEST_PARSER_H_

#include <odp_cunit_common.h>

/* test array init/term functions: */
int parser_suite_term(void);
int parser_suite_init(void);

/* test arrays: */
extern odp_testinfo_t parser_suite[];

#endif

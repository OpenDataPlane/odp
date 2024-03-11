/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Nokia
 */

#ifndef _ODP_TEST_PKTIO_LSO_H_
#define _ODP_TEST_PKTIO_LSO_H_

#include <odp_cunit_common.h>

/* test array init/term functions: */
int lso_suite_term(void);
int lso_suite_init(void);

/* test arrays: */
extern odp_testinfo_t lso_suite[];

#endif

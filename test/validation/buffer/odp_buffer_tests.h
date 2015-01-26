/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef ODP_BUFFER_TESTS_H_
#define ODP_BUFFER_TESTS_H_

#include <odp.h>
#include "odp_cunit_common.h"

/* Helper macro for CU_TestInfo initialization */
#define _CU_TEST_INFO(test_func) {#test_func, test_func}

extern CU_TestInfo buffer_pool_tests[];
extern CU_TestInfo buffer_tests[];
extern CU_TestInfo packet_tests[];

extern int buffer_testsuite_init(void);
extern int buffer_testsuite_finalize(void);

extern int packet_testsuite_init(void);
extern int packet_testsuite_finalize(void);

odp_pool_t pool_create(int buf_num, int buf_size, int buf_type);

#endif /* ODP_BUFFER_TESTS_H_ */

/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_TEST_COMP_H_
#define _ODP_TEST_COMP_H_

#include "odp_cunit_common.h"

/* test functions: */
void comp_test_compress_alg_def(void);
void comp_test_compress_alg_zlib(void);
void comp_test_decompress_alg_def(void);
void comp_test_decompress_alg_zlib(void);
void comp_test_comp_decomp_alg_def(void);
void comp_test_comp_decomp_alg_zlib(void);
void comp_test_ofs_compress_deflate(void);
void comp_test_ofs_compress_zlib(void);
void comp_test_ofs_decompress_deflate(void);
void comp_test_ofs_decompress_zlib(void);
void comp_test_ofs_segment_deflate(void);
void comp_test_ofs_segment_zlib(void);

/* test arrays: */
extern odp_testinfo_t comp_suite[];

/* test array init/term functions: */
int comp_suite_sync_init(void);
int comp_suite_async_init(void);
int comp_suite_term(void);

/* test registry: */
extern odp_suiteinfo_t comp_suites[];

/* executable init/term functions: */
int comp_init(odp_instance_t *inst);
int comp_term(odp_instance_t inst);

/* main test program: */
int comp_main(int argc, char *argv[]);

void test_outof_space_error(odp_comp_alg_t comp_alg,
			    odp_comp_hash_alg_t hash_alg,
			    odp_bool_t compress,
			    odp_comp_op_mode_t mode);
#endif

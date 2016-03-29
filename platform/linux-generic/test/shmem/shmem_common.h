/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _COMMON_TEST_SHMEM_H_
#define _COMMON_TEST_SHMEM_H_

#define ODP_SHM_NAME "odp_linux_shared_mem"
#define FIFO_NAME_FMT "/tmp/shmem_test_fifo-%d"
#define ALIGN_SIZE  (128)
#define TEST_SHARE_FOO (0xf0f0f0f0)
#define TEST_SHARE_BAR (0xf0f0f0f)
#define TEST_FAILURE 'F'
#define TEST_SUCCESS 'S'

typedef struct {
	uint32_t foo;
	uint32_t bar;
} test_shared_linux_data_t;

#endif

/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP api test shared memory header
 */

#ifndef ODP_SHM_TEST_H
#define ODP_SHM_TEST_H

typedef struct {
	int foo;
	int bar;
} test_shared_data_t;

extern __thread test_shared_data_t *test_shared_data;
extern int test_shm(void);

#endif /* ODP_SHM_TEST_H */

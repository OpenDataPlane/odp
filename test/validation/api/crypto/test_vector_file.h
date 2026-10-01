/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#ifndef TEST_VECTOR_FILE_H_
#define TEST_VECTOR_FILE_H_

#include "test_vectors.h"

/* A named set of test vectors */
typedef struct test_vector_set_t {
	/* Source location and set name */
	char *location;
	crypto_test_reference_t *refs;
	int num_refs;
} test_vector_set_t;

/*
 * Load test vectors from a libconfig file. The test vector sets of the file are
 * added after the sets of any previously loaded files.
 */
int test_vector_file_load(const char *filename);

/* Free the loaded test vectors */
void test_vector_file_free(void);

/* Number of loaded test vector sets. Zero when no file has been loaded. */
int test_vector_file_num_sets(void);

const test_vector_set_t *test_vector_file_set(int index);

#endif

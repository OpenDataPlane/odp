/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#include <stddef.h>

#include <odp/helper/odph_api.h>

#include "test_vector_file.h"

int test_vector_file_load(const char *filename)
{
	ODPH_ERR("Cannot load %s: built without libconfig\n", filename);
	return -1;
}

void test_vector_file_free(void)
{
}

int test_vector_file_num_sets(void)
{
	return 0;
}

const test_vector_set_t *test_vector_file_set(int index ODP_UNUSED)
{
	return NULL;
}

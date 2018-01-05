/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

static __attribute__((constructor)) void setup_wrappers(void)
{
	printf("Setup Wrappers\n");
}

static __attribute__((destructor)) void teardown_wrappers(void)
{
	printf("Teardown Wrappers\n");
}

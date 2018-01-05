/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <store.h>
#include <init.h>
#include <drv.h>
#include <sched.h>

static __attribute__((constructor)) void setup_wrappers(void)
{
	printf("Setup Wrappers\n");

	if (instr_store_init())
		return;

	if (instr_odpinit_init())
		return;

	if (instr_odpdrv_init())
		return;

	if (instr_odpsched_init())
		return;
}

static __attribute__((destructor)) void teardown_wrappers(void)
{
	printf("Teardown Wrappers\n");
	instr_store_term();
}

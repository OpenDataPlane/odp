/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <odp_drv.h>
#include <instrum_common.h>
#include <drv.h>
#include <store.h>

static int (*instr_odpdrv_print_all)(void);

int instr_odpdrv_init(void)
{
	INSTR_FUNCTION(odpdrv_print_all);

	if (!instr_odpdrv_print_all) {
		printf("odpdrv_print_all: Not Found\n");
		return -1;
	}

	return 0;
}

int odpdrv_print_all(void)
{
	int ret;

	STORE_SAMPLE_INIT;

	STORE_SAMPLE_START;
	ret = (*instr_odpdrv_print_all)();
	STORE_SAMPLE_END;

	return ret;
}

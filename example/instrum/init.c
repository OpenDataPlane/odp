/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <odp_api.h>
#include <instrum_common.h>
#include <init.h>
#include <store.h>

static int (*instr_odp_init_local)(odp_instance_t instance,
				   odp_thread_type_t thr_type);

static int (*instr_odp_term_local)(void);

int instr_odpinit_init(void)
{
	INSTR_FUNCTION(odp_init_local);

	if (!instr_odp_init_local) {
		printf("odp_init_local: Not Found\n");
		return -1;
	}

	INSTR_FUNCTION(odp_term_local);

	if (!instr_odp_term_local) {
		printf("odp_term_local: Not Found\n");
		return -1;
	}

	return 0;
}

int odp_init_local(odp_instance_t instance, odp_thread_type_t thr_type)
{
	int ret;

	ret = (*instr_odp_init_local)(instance, thr_type);

	instr_store_init_local();

	return ret;
}

int odp_term_local(void)
{
	instr_store_term_local();

	return (*instr_odp_term_local)();
}

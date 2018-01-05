/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <odp_api.h>
#include <instrum_common.h>
#include <sched.h>
#include <store.h>

static int (*instr_odp_schedule_multi)(odp_queue_t *from,
				       uint64_t wait,
				       odp_event_t events[],
				       int num);

int instr_odpsched_init(void)
{
	INSTR_FUNCTION(odp_schedule_multi);

	if (!instr_odp_schedule_multi) {
		fprintf(stderr, "odp_schedule_multi: Not Found\n");
		return -1;
	}

	return 0;
}

int odp_schedule_multi(odp_queue_t *from, uint64_t wait, odp_event_t events[],
		       int num)
{
	int ret;

	STORE_SAMPLE_INIT;

	STORE_SAMPLE_START;
	ret = (*instr_odp_schedule_multi)(from, wait, events, num);
	STORE_SAMPLE_END;

	return ret;
}

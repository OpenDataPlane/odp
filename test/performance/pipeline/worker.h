/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef WORKER_H_
#define WORKER_H_

#include <stdint.h>

typedef enum {
	WT_PLAIN,
	WT_SCHED
} worker_type_t;

typedef struct {
	char *name;
	char **inputs;
	char **outputs;
	int64_t wait_ns;
	uint32_t num_in;
	uint32_t num_out;
	uint32_t burst_size;
	worker_type_t type;
} worker_t;

#endif

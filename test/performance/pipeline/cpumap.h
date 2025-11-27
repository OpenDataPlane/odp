/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef CPUMAP_H_
#define CPUMAP_H_

#include <stdint.h>

#include <odp_api.h>

typedef struct {
	char **workers;
	uint32_t num;
	odp_cpumask_t cpumask;
} cpumap_t;

#endif

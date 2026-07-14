/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef ODP_PIPELINE_WORK_H_
#define ODP_PIPELINE_WORK_H_

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include <libconfig.h>
#include <odp_api.h>

#define ODP_PL_WORK_CONCAT_HELPER(a, b) a##b
#define ODP_PL_WORK_CONCAT(a, b) ODP_PL_WORK_CONCAT_HELPER(a, b)

typedef struct {
	char *queue;
	char *type;
	config_setting_t *param;
} odp_pl_work_param_t;

typedef struct {
	uint64_t data1;
	uint64_t data2;
	uint64_t data3;
	uint64_t data4;
} odp_pl_work_stats_t;

typedef int (*odp_pl_work_fn_t)(uintptr_t data, odp_event_t ev[], int num,
				odp_pl_work_stats_t *stats);

typedef struct {
	odp_pl_work_fn_t fn;
	uintptr_t data;
} odp_pl_work_init_t;

typedef void (*odp_pl_work_init_fn_t)(const odp_pl_work_param_t *param, odp_pl_work_init_t *init);
typedef void (*odp_pl_work_print_fn_t)(const char *queue, const odp_pl_work_stats_t *stats);
typedef void (*odp_pl_work_destroy_fn_t)(uintptr_t data);

void odp_pl_work_register_work(const char *name, odp_pl_work_init_fn_t init_fn,
			       odp_pl_work_print_fn_t print_fn,
			       odp_pl_work_destroy_fn_t destroy_fn);

#define ODP_PL_WORK_AUTOREGISTER(name, init, print, destroy)		\
	__attribute__((constructor))					\
	static void ODP_PL_WORK_CONCAT(autoregister, __LINE__)(void) {	\
		odp_pl_work_register_work(name, init, print, destroy);	\
	}

#endif

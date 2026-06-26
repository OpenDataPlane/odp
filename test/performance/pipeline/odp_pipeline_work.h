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

#define WORK_CONCAT_HELPER(a, b) a##b
#define WORK_CONCAT(a, b) WORK_CONCAT_HELPER(a, b)

typedef struct {
	char *queue;
	char *type;
	config_setting_t *param;
} work_param_t;

typedef struct {
	uint64_t data1;
	uint64_t data2;
	uint64_t data3;
	uint64_t data4;
} work_stats_t;

typedef int (*work_fn_t)(uintptr_t data, odp_event_t ev[], int num, work_stats_t *stats);

typedef struct {
	work_fn_t fn;
	uintptr_t data;
} work_init_t;

typedef void (*work_init_fn_t)(const work_param_t *param, work_init_t *init);
typedef void (*work_print_fn_t)(const char *queue, const work_stats_t *stats);
typedef void (*work_destroy_fn_t)(uintptr_t data);

void work_register_work(const char *name, work_init_fn_t init_fn, work_print_fn_t print_fn,
			work_destroy_fn_t destroy_fn);

#define WORK_AUTOREGISTER(name, init, print, destroy)			\
	__attribute__((constructor))					\
	static void WORK_CONCAT(autoregister, __LINE__)(void) {		\
		work_register_work(name, init, print, destroy);		\
	}

#endif

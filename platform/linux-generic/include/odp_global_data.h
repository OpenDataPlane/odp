/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_GLOBAL_DATA_H_
#define ODP_GLOBAL_DATA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/init.h>
#include <odp/api/cpumask.h>
#include <odp/api/random.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdint.h>
#include <libconfig.h>
#include <odp_config_internal.h>

#define MODEL_STR_SIZE 128
#define UID_MAXLEN 30

typedef struct {
	uint64_t cpu_hz_max[CONFIG_NUM_CPU];
	uint64_t page_size;
	int      cache_line_size;
	int      cpu_count;
	char     cpu_arch_str[128];
	char     model_str[CONFIG_NUM_CPU][MODEL_STR_SIZE];
} system_info_t;

typedef struct {
	uint64_t default_huge_page_size;
	char     *default_huge_page_dir;
} hugepage_info_t;

/* Read-only global data. Members should not be modified after global init
 * to enable process more support. */
struct odp_global_data_ro_t {
	odp_init_t init_param;
	/* directory for odp mmaped files */
	char *shm_dir;
	/* overload default with env */
	int   shm_dir_from_env;
	uint64_t shm_max_memory;
	uint64_t shm_max_size;
	int shm_single_va;
	pid_t main_pid;
	char uid[UID_MAXLEN];
	odp_log_func_t log_fn;
	odp_abort_func_t abort_fn;
	system_info_t system_info;
	hugepage_info_t hugepage_info;
	odp_cpumask_t control_cpus;
	odp_cpumask_t worker_cpus;
	int num_cpus_installed;
	config_t libconfig_default;
	config_t libconfig_runtime;
	odp_random_kind_t ipsec_rand_kind;
};

/* Modifiable global data. Memory region is shared and synchronized amongst all
 * worker processes. */
struct odp_global_data_rw_t {
	odp_bool_t dpdk_initialized;
	odp_bool_t inline_timers;
};

extern struct odp_global_data_ro_t odp_global_ro;
extern struct odp_global_data_rw_t *odp_global_rw;

#ifdef __cplusplus
}
#endif

#endif

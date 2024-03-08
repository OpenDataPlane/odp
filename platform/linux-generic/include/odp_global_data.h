/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2023 Nokia
 */

#ifndef ODP_GLOBAL_DATA_H_
#define ODP_GLOBAL_DATA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/cpumask.h>
#include <odp/api/init.h>
#include <odp/api/random.h>
#include <odp/api/system_info.h>
#include <odp/api/std_types.h>

#include <odp_config_internal.h>

#include <libconfig.h>
#include <stdint.h>
#include <sys/types.h>

#define MODEL_STR_SIZE 128
#define UID_MAXLEN 30

typedef struct {
	uint64_t cpu_hz_max[CONFIG_NUM_CPU_IDS];
	uint64_t cpu_hz[CONFIG_NUM_CPU_IDS];
	uint64_t default_cpu_hz_max;
	uint64_t default_cpu_hz;
	uint64_t page_size;
	int      cache_line_size;
	uint8_t cpu_hz_static;
	uint8_t cpu_constant_tsc;
	odp_cpu_arch_t cpu_arch;
	odp_cpu_arch_isa_t cpu_isa_sw;
	odp_cpu_arch_isa_t cpu_isa_hw;
	char     cpu_arch_str[128];
	char     model_str[CONFIG_NUM_CPU_IDS][MODEL_STR_SIZE];
} system_info_t;

typedef struct {
	uint64_t default_huge_page_size;
	char     *default_huge_page_dir;
} hugepage_info_t;

/* Read-only global data. Members should not be modified after global init
 * to enable process more support. */
typedef struct odp_global_data_ro_t {
	odp_init_t init_param;
	/* directory for odp mapped files */
	char *shm_dir;
	/* overload default with env */
	int   shm_dir_from_env;
	uint64_t shm_max_memory;
	uint64_t shm_max_size;
	int shm_single_va;
	pid_t main_pid;
	pid_t fdserver_pid;
	char uid[UID_MAXLEN];
	system_info_t system_info;
	hugepage_info_t hugepage_info;
	odp_cpumask_t all_cpus;
	odp_cpumask_t control_cpus;
	odp_cpumask_t worker_cpus;
	int num_cpus_installed;
	uint8_t has_config_rt;
	config_t libconfig_default;
	config_t libconfig_runtime;

	/* Disabled features during global init */
	struct {
		uint8_t compress;
		uint8_t crypto;
		uint8_t dma;
		uint8_t ipsec;
		uint8_t stash;
		uint8_t traffic_mngr;
		uint8_t ml;

	} disable;

} odp_global_data_ro_t;

/* Modifiable global data. Memory region is shared and synchronized amongst all
 * worker processes. */
typedef struct odp_global_data_rw_t {
	odp_bool_t dpdk_initialized;
	odp_bool_t inline_timers;
	odp_bool_t schedule_configured;

} odp_global_data_rw_t;

extern odp_global_data_ro_t odp_global_ro;
extern odp_global_data_rw_t *odp_global_rw;

#ifdef __cplusplus
}
#endif

#endif

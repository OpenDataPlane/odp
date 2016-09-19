/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP HW system information
 */

#ifndef ODP_INTERNAL_H_
#define ODP_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/init.h>
#include <odp/api/cpumask.h>
#include <odp/api/thread.h>
#include <stdio.h>
#include <sys/types.h>

extern __thread int __odp_errno;

#define MAX_CPU_NUMBER 128

typedef struct {
	uint64_t cpu_hz_max[MAX_CPU_NUMBER];
	uint64_t default_huge_page_size;
	uint64_t page_size;
	int      cache_line_size;
	int      cpu_count;
	char     cpu_arch_str[128];
	char     model_str[MAX_CPU_NUMBER][128];
} system_info_t;

struct odp_global_data_s {
	pid_t main_pid;
	odp_log_func_t log_fn;
	odp_abort_func_t abort_fn;
	system_info_t system_info;
	odp_cpumask_t control_cpus;
	odp_cpumask_t worker_cpus;
	int num_cpus_installed;
	int ipc_ns;
};

enum init_stage {
	NO_INIT = 0,    /* No init stages completed */
	CPUMASK_INIT,
	TIME_INIT,
	SYSINFO_INIT,
	SHM_INIT,
	THREAD_INIT,
	POOL_INIT,
	QUEUE_INIT,
	SCHED_INIT,
	PKTIO_INIT,
	TIMER_INIT,
	CRYPTO_INIT,
	CLASSIFICATION_INIT,
	TRAFFIC_MNGR_INIT,
	NAME_TABLE_INIT,
	ALL_INIT      /* All init stages completed */
};

extern struct odp_global_data_s odp_global_data;

int _odp_term_global(enum init_stage stage);
int _odp_term_local(enum init_stage stage);

int odp_cpumask_init_global(const odp_init_t *params);
int odp_cpumask_term_global(void);

int odp_system_info_init(void);
int odp_system_info_term(void);

int odp_thread_init_global(void);
int odp_thread_init_local(odp_thread_type_t type);
int odp_thread_term_local(void);
int odp_thread_term_global(void);

int odp_shm_init_global(void);
int odp_shm_term_global(void);
int odp_shm_init_local(void);

int odp_pool_init_global(void);
int odp_pool_init_local(void);
int odp_pool_term_global(void);
int odp_pool_term_local(void);

int odp_pktio_init_global(void);
int odp_pktio_term_global(void);
int odp_pktio_init_local(void);

int odp_classification_init_global(void);
int odp_classification_term_global(void);

int odp_queue_init_global(void);
int odp_queue_term_global(void);

int odp_crypto_init_global(void);
int odp_crypto_term_global(void);

int odp_timer_init_global(void);
int odp_timer_term_global(void);
int odp_timer_disarm_all(void);

int odp_time_init_global(void);
int odp_time_term_global(void);

int odp_tm_init_global(void);
int odp_tm_term_global(void);

int _odp_int_name_tbl_init_global(void);
int _odp_int_name_tbl_term_global(void);

int cpuinfo_parser(FILE *file, system_info_t *sysinfo);
uint64_t odp_cpu_hz_current(int id);

#ifdef __cplusplus
}
#endif

#endif

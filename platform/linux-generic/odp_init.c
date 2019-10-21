/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>

#include <odp/api/init.h>
#include <odp/api/shared_memory.h>
#include <odp_debug_internal.h>
#include <odp_init_internal.h>
#include <odp_schedule_if.h>
#include <odp_libconfig_internal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

enum init_stage {
	NO_INIT = 0,    /* No init stages completed */
	LIBCONFIG_INIT,
	CPUMASK_INIT,
	CPU_CYCLES_INIT,
	TIME_INIT,
	SYSINFO_INIT,
	ISHM_INIT,
	FDSERVER_INIT,
	GLOBAL_RW_DATA_INIT,
	HASH_INIT,
	THREAD_INIT,
	POOL_INIT,
	QUEUE_INIT,
	SCHED_INIT,
	PKTIO_INIT,
	TIMER_INIT,
	RANDOM_INIT,
	CRYPTO_INIT,
	COMP_INIT,
	CLASSIFICATION_INIT,
	TRAFFIC_MNGR_INIT,
	NAME_TABLE_INIT,
	IPSEC_EVENTS_INIT,
	IPSEC_SAD_INIT,
	IPSEC_INIT,
	ALL_INIT      /* All init stages completed */
};

struct odp_global_data_ro_t odp_global_ro;
struct odp_global_data_rw_t *odp_global_rw;

void odp_init_param_init(odp_init_t *param)
{
	memset(param, 0, sizeof(odp_init_t));
}

static int global_rw_data_init(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("_odp_global_rw_data",
			      sizeof(struct odp_global_data_rw_t),
			      ODP_CACHE_LINE_SIZE, 0);

	odp_global_rw = odp_shm_addr(shm);
	if (odp_global_rw == NULL) {
		ODP_ERR("Global RW data shm reserve failed.\n");
		return -1;
	}

	memset(odp_global_rw, 0, sizeof(struct odp_global_data_rw_t));

	return 0;
}

static int global_rw_data_term(void)
{
	odp_shm_t shm;

	shm = odp_shm_lookup("_odp_global_rw_data");
	if (shm == ODP_SHM_INVALID) {
		ODP_ERR("Unable to find global RW data shm.\n");
		return -1;
	}

	if (odp_shm_free(shm)) {
		ODP_ERR("Global RW data shm free failed.\n");
		return -1;
	}

	return 0;
}

static int term_global(enum init_stage stage)
{
	int rc = 0;

	switch (stage) {
	case ALL_INIT:
	case IPSEC_INIT:
		if (_odp_ipsec_term_global()) {
			ODP_ERR("ODP IPsec term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case IPSEC_SAD_INIT:
		if (_odp_ipsec_sad_term_global()) {
			ODP_ERR("ODP IPsec SAD term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case IPSEC_EVENTS_INIT:
		if (_odp_ipsec_events_term_global()) {
			ODP_ERR("ODP IPsec events term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case NAME_TABLE_INIT:
		if (_odp_int_name_tbl_term_global()) {
			ODP_ERR("Name table term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TRAFFIC_MNGR_INIT:
		if (_odp_tm_term_global()) {
			ODP_ERR("TM term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CLASSIFICATION_INIT:
		if (_odp_classification_term_global()) {
			ODP_ERR("ODP classification term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case COMP_INIT:
		if (_odp_comp_term_global()) {
			ODP_ERR("ODP comp term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CRYPTO_INIT:
		if (_odp_crypto_term_global()) {
			ODP_ERR("ODP crypto term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case RANDOM_INIT:
		/* Fall through */

	case TIMER_INIT:
		if (_odp_timer_term_global()) {
			ODP_ERR("ODP timer term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case PKTIO_INIT:
		if (_odp_pktio_term_global()) {
			ODP_ERR("ODP pktio term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case SCHED_INIT:
		if (_odp_schedule_term_global()) {
			ODP_ERR("ODP schedule term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case QUEUE_INIT:
		if (_odp_queue_term_global()) {
			ODP_ERR("ODP queue term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case POOL_INIT:
		if (_odp_pool_term_global()) {
			ODP_ERR("ODP buffer pool term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case THREAD_INIT:
		if (_odp_thread_term_global()) {
			ODP_ERR("ODP thread term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case HASH_INIT:
		if (_odp_hash_term_global()) {
			ODP_ERR("ODP hash term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case GLOBAL_RW_DATA_INIT:
		if (global_rw_data_term()) {
			ODP_ERR("ODP global RW data term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case FDSERVER_INIT:
		if (_odp_fdserver_term_global()) {
			ODP_ERR("ODP fdserver term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case ISHM_INIT:
		if (_odp_ishm_term_global()) {
			ODP_ERR("ODP ishm term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case SYSINFO_INIT:
		if (_odp_system_info_term()) {
			ODP_ERR("ODP system info term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TIME_INIT:
		if (_odp_time_term_global()) {
			ODP_ERR("ODP time term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CPU_CYCLES_INIT:
		/* Fall through */
	case CPUMASK_INIT:
		if (_odp_cpumask_term_global()) {
			ODP_ERR("ODP cpumask term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case LIBCONFIG_INIT:
		if (_odp_libconfig_term_global()) {
			ODP_ERR("ODP runtime config term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case NO_INIT:
		;
	}

	return rc;
}

int odp_init_global(odp_instance_t *instance,
		    const odp_init_t *params,
		    const odp_platform_init_t *platform_params ODP_UNUSED)
{
	memset(&odp_global_ro, 0, sizeof(struct odp_global_data_ro_t));
	odp_global_ro.main_pid = getpid();

	enum init_stage stage = NO_INIT;
	odp_global_ro.log_fn = odp_override_log;
	odp_global_ro.abort_fn = odp_override_abort;

	odp_init_param_init(&odp_global_ro.init_param);
	if (params != NULL) {
		odp_global_ro.init_param  = *params;

		if (params->log_fn != NULL)
			odp_global_ro.log_fn = params->log_fn;
		if (params->abort_fn != NULL)
			odp_global_ro.abort_fn = params->abort_fn;
		if (params->mem_model == ODP_MEM_MODEL_PROCESS)
			odp_global_ro.shm_single_va = 1;
	}

	if (_odp_libconfig_init_global()) {
		ODP_ERR("ODP runtime config init failed.\n");
		goto init_failed;
	}
	stage = LIBCONFIG_INIT;

	if (_odp_cpumask_init_global(params)) {
		ODP_ERR("ODP cpumask init failed.\n");
		goto init_failed;
	}
	stage = CPUMASK_INIT;

	if (_odp_cpu_cycles_init_global()) {
		ODP_ERR("ODP cpu cycle init failed.\n");
		goto init_failed;
	}
	stage = CPU_CYCLES_INIT;

	if (_odp_time_init_global()) {
		ODP_ERR("ODP time init failed.\n");
		goto init_failed;
	}
	stage = TIME_INIT;

	if (_odp_system_info_init()) {
		ODP_ERR("ODP system_info init failed.\n");
		goto init_failed;
	}
	stage = SYSINFO_INIT;

	if (_odp_ishm_init_global(params)) {
		ODP_ERR("ODP ishm init failed.\n");
		goto init_failed;
	}
	stage = ISHM_INIT;

	if (_odp_fdserver_init_global()) {
		ODP_ERR("ODP fdserver init failed.\n");
		goto init_failed;
	}
	stage = FDSERVER_INIT;

	if (global_rw_data_init()) {
		ODP_ERR("ODP global RW data init failed.\n");
		goto init_failed;
	}
	stage = GLOBAL_RW_DATA_INIT;

	if (_odp_hash_init_global()) {
		ODP_ERR("ODP hash init failed.\n");
		goto init_failed;
	}
	stage = HASH_INIT;

	if (_odp_thread_init_global()) {
		ODP_ERR("ODP thread init failed.\n");
		goto init_failed;
	}
	stage = THREAD_INIT;

	if (_odp_pool_init_global()) {
		ODP_ERR("ODP pool init failed.\n");
		goto init_failed;
	}
	stage = POOL_INIT;

	if (_odp_queue_init_global()) {
		ODP_ERR("ODP queue init failed.\n");
		goto init_failed;
	}
	stage = QUEUE_INIT;

	if (_odp_schedule_init_global()) {
		ODP_ERR("ODP schedule init failed.\n");
		goto init_failed;
	}
	stage = SCHED_INIT;

	if (_odp_pktio_init_global()) {
		ODP_ERR("ODP packet io init failed.\n");
		goto init_failed;
	}
	stage = PKTIO_INIT;

	if (_odp_timer_init_global(params)) {
		ODP_ERR("ODP timer init failed.\n");
		goto init_failed;
	}
	stage = TIMER_INIT;

	/* No init neeeded */
	stage = RANDOM_INIT;

	if (_odp_crypto_init_global()) {
		ODP_ERR("ODP crypto init failed.\n");
		goto init_failed;
	}
	stage = CRYPTO_INIT;

	if (_odp_comp_init_global()) {
		ODP_ERR("ODP comp init failed.\n");
		goto init_failed;
	}
	stage = COMP_INIT;

	if (_odp_classification_init_global()) {
		ODP_ERR("ODP classification init failed.\n");
		goto init_failed;
	}
	stage = CLASSIFICATION_INIT;

	if (_odp_tm_init_global()) {
		ODP_ERR("ODP traffic manager init failed\n");
		goto init_failed;
	}
	stage = TRAFFIC_MNGR_INIT;

	if (_odp_int_name_tbl_init_global()) {
		ODP_ERR("ODP name table init failed\n");
		goto init_failed;
	}
	stage = NAME_TABLE_INIT;

	if (_odp_ipsec_events_init_global()) {
		ODP_ERR("ODP IPsec events init failed.\n");
		goto init_failed;
	}
	stage = IPSEC_EVENTS_INIT;

	if (_odp_ipsec_sad_init_global()) {
		ODP_ERR("ODP IPsec SAD init failed.\n");
		goto init_failed;
	}
	stage = IPSEC_SAD_INIT;

	if (_odp_ipsec_init_global()) {
		ODP_ERR("ODP IPsec init failed.\n");
		goto init_failed;
	}
	stage = IPSEC_INIT;

	*instance = (odp_instance_t)odp_global_ro.main_pid;

	return 0;

init_failed:
	term_global(stage);
	return -1;
}

int odp_term_global(odp_instance_t instance)
{
	if (instance != (odp_instance_t)odp_global_ro.main_pid) {
		ODP_ERR("Bad instance.\n");
		return -1;
	}
	return term_global(ALL_INIT);
}

static int term_local(enum init_stage stage)
{
	int rc = 0;
	int rc_thd = 0;

	switch (stage) {
	case ALL_INIT:

	case SCHED_INIT:
		if (sched_fn->term_local()) {
			ODP_ERR("ODP schedule local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case QUEUE_INIT:
		if (queue_fn->term_local()) {
			ODP_ERR("ODP queue local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case POOL_INIT:
		if (_odp_pool_term_local()) {
			ODP_ERR("ODP buffer pool local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CRYPTO_INIT:
		if (_odp_crypto_term_local()) {
			ODP_ERR("ODP crypto local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case RANDOM_INIT:
		if (_odp_random_term_local()) {
			ODP_ERR("ODP random local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TIMER_INIT:
		if (_odp_timer_term_local()) {
			ODP_ERR("ODP timer local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case THREAD_INIT:
		rc_thd = _odp_thread_term_local();
		if (rc_thd < 0) {
			ODP_ERR("ODP thread local term failed.\n");
			rc = -1;
		} else {
			if (!rc)
				rc = rc_thd;
		}
		/* Fall through */

	case ISHM_INIT:
		if (_odp_ishm_term_local()) {
			ODP_ERR("ODP ishm local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	default:
		break;
	}

	return rc;
}

int odp_init_local(odp_instance_t instance, odp_thread_type_t thr_type)
{
	enum init_stage stage = NO_INIT;

	if (instance != (odp_instance_t)odp_global_ro.main_pid) {
		ODP_ERR("Bad instance.\n");
		goto init_fail;
	}

	if (_odp_ishm_init_local()) {
		ODP_ERR("ODP ishm local init failed.\n");
		goto init_fail;
	}
	stage = ISHM_INIT;

	if (_odp_thread_init_local(thr_type)) {
		ODP_ERR("ODP thread local init failed.\n");
		goto init_fail;
	}
	stage = THREAD_INIT;

	if (_odp_pktio_init_local()) {
		ODP_ERR("ODP packet io local init failed.\n");
		goto init_fail;
	}
	stage = PKTIO_INIT;

	if (_odp_timer_init_local()) {
		ODP_ERR("ODP timer local init failed.\n");
		goto init_fail;
	}
	stage = TIMER_INIT;

	if (_odp_random_init_local()) {
		ODP_ERR("ODP random local init failed.\n");
		goto init_fail;
	}
	stage = RANDOM_INIT;

	if (_odp_crypto_init_local()) {
		ODP_ERR("ODP crypto local init failed.\n");
		goto init_fail;
	}
	stage = CRYPTO_INIT;

	if (_odp_pool_init_local()) {
		ODP_ERR("ODP pool local init failed.\n");
		goto init_fail;
	}
	stage = POOL_INIT;

	if (queue_fn->init_local()) {
		ODP_ERR("ODP queue local init failed.\n");
		goto init_fail;
	}
	stage = QUEUE_INIT;

	if (sched_fn->init_local()) {
		ODP_ERR("ODP schedule local init failed.\n");
		goto init_fail;
	}
	/* stage = SCHED_INIT; */

	return 0;

init_fail:
	term_local(stage);
	return -1;
}

int odp_term_local(void)
{
	return term_local(ALL_INIT);
}

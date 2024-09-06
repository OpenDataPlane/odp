/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2021-2024 Nokia
 */

#include <odp_posix_extensions.h>

#include <odp/api/init.h>
#include <odp/api/shared_memory.h>

#include <odp/api/plat/strong_types.h>
#include <odp/api/plat/thread_inlines.h>

#include <odp_debug_internal.h>
#include <odp_global_data.h>
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
	SYSINFO_INIT,
	CPU_CYCLES_INIT,
	TIME_INIT,
	ISHM_INIT,
	FDSERVER_INIT,
	GLOBAL_RW_DATA_INIT,
	HASH_INIT,
	THREAD_INIT,
	POOL_INIT,
	EVENT_VALIDATION_INIT,
	STASH_INIT,
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
	DMA_INIT,
	ML_INIT,
	ALL_INIT      /* All init stages completed */
};

odp_global_data_ro_t odp_global_ro;
odp_global_data_rw_t *odp_global_rw;

/* Global function pointers for inline header usage.  The values are written
 * during odp_init_global() (enables process mode support). */
#include <odp/visibility_begin.h>

odp_log_func_t _odp_log_fn;
odp_abort_func_t _odp_abort_fn;

#include <odp/visibility_end.h>

/* odp_init_local() call status */
static __thread uint8_t init_local_called;

static void disable_features(odp_global_data_ro_t *global_ro,
			     const odp_init_t *init_param)
{
	int disable_ipsec, disable_crypto;
	int disable_dma;

	if (init_param == NULL)
		return;

	disable_ipsec = init_param->not_used.feat.ipsec;
	global_ro->disable.ipsec = disable_ipsec;

	disable_crypto = init_param->not_used.feat.crypto;
	/* Crypto can be disabled only if IPSec is disabled */
	if (disable_ipsec && disable_crypto)
		global_ro->disable.crypto = 1;

	disable_dma = init_param->not_used.feat.dma;
	global_ro->disable.dma = disable_dma;

	/* DMA uses stash. Disable stash only when both are disabled. */
	if (disable_dma && init_param->not_used.feat.stash)
		global_ro->disable.stash = 1;

	global_ro->disable.traffic_mngr = init_param->not_used.feat.tm;
	global_ro->disable.compress = init_param->not_used.feat.compress;
	global_ro->disable.ml = init_param->not_used.feat.ml;
}

void odp_init_param_init(odp_init_t *param)
{
	memset(param, 0, sizeof(odp_init_t));
}

static int global_rw_data_init(void)
{
	odp_shm_t shm;

	shm = odp_shm_reserve("_odp_global_rw_data",
			      sizeof(odp_global_data_rw_t),
			      ODP_CACHE_LINE_SIZE, 0);

	odp_global_rw = odp_shm_addr(shm);
	if (odp_global_rw == NULL) {
		_ODP_ERR("Global RW data shm reserve failed.\n");
		return -1;
	}

	memset(odp_global_rw, 0, sizeof(odp_global_data_rw_t));

	return 0;
}

static int global_rw_data_term(void)
{
	odp_shm_t shm;

	shm = odp_shm_lookup("_odp_global_rw_data");
	if (shm == ODP_SHM_INVALID) {
		_ODP_ERR("Unable to find global RW data shm.\n");
		return -1;
	}

	if (odp_shm_free(shm)) {
		_ODP_ERR("Global RW data shm free failed.\n");
		return -1;
	}

	return 0;
}

static int term_global(enum init_stage stage)
{
	int rc = 0;

	switch (stage) {
	case ALL_INIT:
	case ML_INIT:
		if (_odp_ml_term_global()) {
			_ODP_ERR("ODP ML term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case DMA_INIT:
		if (_odp_dma_term_global()) {
			_ODP_ERR("ODP DMA term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case IPSEC_INIT:
		if (_odp_ipsec_term_global()) {
			_ODP_ERR("ODP IPsec term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case IPSEC_SAD_INIT:
		if (_odp_ipsec_sad_term_global()) {
			_ODP_ERR("ODP IPsec SAD term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case IPSEC_EVENTS_INIT:
		if (_odp_ipsec_events_term_global()) {
			_ODP_ERR("ODP IPsec events term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case NAME_TABLE_INIT:
		if (_odp_int_name_tbl_term_global()) {
			_ODP_ERR("Name table term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TRAFFIC_MNGR_INIT:
		if (_odp_tm_term_global()) {
			_ODP_ERR("TM term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CLASSIFICATION_INIT:
		if (_odp_classification_term_global()) {
			_ODP_ERR("ODP classification term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case COMP_INIT:
		if (_odp_comp_term_global()) {
			_ODP_ERR("ODP comp term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CRYPTO_INIT:
		if (_odp_crypto_term_global()) {
			_ODP_ERR("ODP crypto term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TIMER_INIT:
		if (_odp_timer_term_global()) {
			_ODP_ERR("ODP timer term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case PKTIO_INIT:
		if (_odp_pktio_term_global()) {
			_ODP_ERR("ODP pktio term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case SCHED_INIT:
		if (_odp_schedule_term_global()) {
			_ODP_ERR("ODP schedule term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case QUEUE_INIT:
		if (_odp_queue_term_global()) {
			_ODP_ERR("ODP queue term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case STASH_INIT:
		if (_odp_stash_term_global()) {
			_ODP_ERR("ODP stash term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case EVENT_VALIDATION_INIT:
		if (_odp_event_validation_term_global()) {
			_ODP_ERR("ODP event validation term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case POOL_INIT:
		if (_odp_pool_term_global()) {
			_ODP_ERR("ODP buffer pool term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case THREAD_INIT:
		if (_odp_thread_term_global()) {
			_ODP_ERR("ODP thread term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case HASH_INIT:
		if (_odp_hash_term_global()) {
			_ODP_ERR("ODP hash term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case GLOBAL_RW_DATA_INIT:
		if (global_rw_data_term()) {
			_ODP_ERR("ODP global RW data term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case FDSERVER_INIT:
		if (_odp_fdserver_term_global()) {
			_ODP_ERR("ODP fdserver term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case ISHM_INIT:
		if (_odp_ishm_term_global()) {
			_ODP_ERR("ODP ishm term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TIME_INIT:
		if (_odp_time_term_global()) {
			_ODP_ERR("ODP time term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CPU_CYCLES_INIT:
	case SYSINFO_INIT:
		if (_odp_system_info_term()) {
			_ODP_ERR("ODP system info term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CPUMASK_INIT:
		if (_odp_cpumask_term_global()) {
			_ODP_ERR("ODP cpumask term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case LIBCONFIG_INIT:
		if (_odp_libconfig_term_global()) {
			_ODP_ERR("ODP runtime config term failed.\n");
			rc = -1;
		}
		/* Fall through */

	default:
		break;
	}

	return rc;
}

int odp_init_global(odp_instance_t *instance,
		    const odp_init_t *params,
		    const odp_platform_init_t *platform_params ODP_UNUSED)
{
	enum init_stage stage = NO_INIT;

	memset(&odp_global_ro, 0, sizeof(odp_global_data_ro_t));
	odp_global_ro.main_pid = getpid();
	_odp_log_fn = odp_override_log;
	_odp_abort_fn = odp_override_abort;

	odp_init_param_init(&odp_global_ro.init_param);
	if (params != NULL) {
		odp_global_ro.init_param  = *params;

		if (params->log_fn != NULL)
			_odp_log_fn = params->log_fn;
		if (params->abort_fn != NULL)
			_odp_abort_fn = params->abort_fn;
		if (params->mem_model == ODP_MEM_MODEL_PROCESS)
			odp_global_ro.shm_single_va = 1;
	}

	if (_odp_libconfig_init_global()) {
		_ODP_ERR("ODP runtime config init failed.\n");
		goto init_failed;
	}
	stage = LIBCONFIG_INIT;

	disable_features(&odp_global_ro, params);

	if (_odp_cpumask_init_global(params)) {
		_ODP_ERR("ODP cpumask init failed.\n");
		goto init_failed;
	}
	stage = CPUMASK_INIT;

	if (_odp_system_info_init()) {
		_ODP_ERR("ODP system_info init failed.\n");
		goto init_failed;
	}
	stage = SYSINFO_INIT;

	if (_odp_cpu_cycles_init_global()) {
		_ODP_ERR("ODP cpu cycle init failed.\n");
		goto init_failed;
	}
	stage = CPU_CYCLES_INIT;

	if (_odp_time_init_global()) {
		_ODP_ERR("ODP time init failed.\n");
		goto init_failed;
	}
	stage = TIME_INIT;

	if (_odp_ishm_init_global(params)) {
		_ODP_ERR("ODP ishm init failed.\n");
		goto init_failed;
	}
	stage = ISHM_INIT;

	if (_odp_fdserver_init_global()) {
		_ODP_ERR("ODP fdserver init failed.\n");
		goto init_failed;
	}
	stage = FDSERVER_INIT;

	if (global_rw_data_init()) {
		_ODP_ERR("ODP global RW data init failed.\n");
		goto init_failed;
	}
	stage = GLOBAL_RW_DATA_INIT;

	if (_odp_hash_init_global()) {
		_ODP_ERR("ODP hash init failed.\n");
		goto init_failed;
	}
	stage = HASH_INIT;

	if (_odp_thread_init_global()) {
		_ODP_ERR("ODP thread init failed.\n");
		goto init_failed;
	}
	stage = THREAD_INIT;

	if (_odp_pool_init_global()) {
		_ODP_ERR("ODP pool init failed.\n");
		goto init_failed;
	}
	stage = POOL_INIT;

	if (_odp_event_validation_init_global()) {
		_ODP_ERR("ODP event validation init failed.\n");
		goto init_failed;
	}
	stage = EVENT_VALIDATION_INIT;

	if (_odp_stash_init_global()) {
		_ODP_ERR("ODP stash init failed.\n");
		goto init_failed;
	}
	stage = STASH_INIT;

	if (_odp_queue_init_global()) {
		_ODP_ERR("ODP queue init failed.\n");
		goto init_failed;
	}
	stage = QUEUE_INIT;

	if (_odp_schedule_init_global()) {
		_ODP_ERR("ODP schedule init failed.\n");
		goto init_failed;
	}
	stage = SCHED_INIT;

	if (_odp_pktio_init_global()) {
		_ODP_ERR("ODP packet io init failed.\n");
		goto init_failed;
	}
	stage = PKTIO_INIT;

	if (_odp_timer_init_global(params)) {
		_ODP_ERR("ODP timer init failed.\n");
		goto init_failed;
	}
	stage = TIMER_INIT;

	if (_odp_crypto_init_global()) {
		_ODP_ERR("ODP crypto init failed.\n");
		goto init_failed;
	}
	stage = CRYPTO_INIT;

	if (_odp_comp_init_global()) {
		_ODP_ERR("ODP comp init failed.\n");
		goto init_failed;
	}
	stage = COMP_INIT;

	if (_odp_classification_init_global()) {
		_ODP_ERR("ODP classification init failed.\n");
		goto init_failed;
	}
	stage = CLASSIFICATION_INIT;

	if (_odp_tm_init_global()) {
		_ODP_ERR("ODP traffic manager init failed\n");
		goto init_failed;
	}
	stage = TRAFFIC_MNGR_INIT;

	if (_odp_int_name_tbl_init_global()) {
		_ODP_ERR("ODP name table init failed\n");
		goto init_failed;
	}
	stage = NAME_TABLE_INIT;

	if (_odp_ipsec_events_init_global()) {
		_ODP_ERR("ODP IPsec events init failed.\n");
		goto init_failed;
	}
	stage = IPSEC_EVENTS_INIT;

	if (_odp_ipsec_sad_init_global()) {
		_ODP_ERR("ODP IPsec SAD init failed.\n");
		goto init_failed;
	}
	stage = IPSEC_SAD_INIT;

	if (_odp_ipsec_init_global()) {
		_ODP_ERR("ODP IPsec init failed.\n");
		goto init_failed;
	}
	stage = IPSEC_INIT;

	if (_odp_dma_init_global()) {
		_ODP_ERR("ODP DMA init failed.\n");
		goto init_failed;
	}
	stage = DMA_INIT;

	if (_odp_ml_init_global()) {
		_ODP_ERR("ODP ML init failed.\n");
		goto init_failed;
	}
	stage = ML_INIT;

	*instance = (odp_instance_t)odp_global_ro.main_pid;

	return 0;

init_failed:
	term_global(stage);
	return -1;
}

int odp_term_global(odp_instance_t instance)
{
	if (instance != (odp_instance_t)odp_global_ro.main_pid) {
		_ODP_ERR("Bad instance.\n");
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
		if (_odp_sched_fn->term_local()) {
			_ODP_ERR("ODP schedule local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case QUEUE_INIT:
		if (_odp_queue_fn->term_local()) {
			_ODP_ERR("ODP queue local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case POOL_INIT:
		if (_odp_pool_term_local()) {
			_ODP_ERR("ODP buffer pool local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case CRYPTO_INIT:
		if (_odp_crypto_term_local()) {
			_ODP_ERR("ODP crypto local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case RANDOM_INIT:
		if (_odp_random_term_local()) {
			_ODP_ERR("ODP random local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case TIMER_INIT:
		if (_odp_timer_term_local()) {
			_ODP_ERR("ODP timer local term failed.\n");
			rc = -1;
		}
		/* Fall through */

	case THREAD_INIT:
		rc_thd = _odp_thread_term_local();
		if (rc_thd < 0) {
			_ODP_ERR("ODP thread local term failed.\n");
			rc = -1;
		} else {
			if (!rc)
				rc = (rc_thd == 0) ? 0 : 1;
		}
		/* Fall through */

	case ISHM_INIT:
		if (_odp_ishm_term_local()) {
			_ODP_ERR("ODP ishm local term failed.\n");
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
		_ODP_ERR("Bad instance.\n");
		goto init_fail;
	}

	/* Detect if odp_init_local() has been already called from this thread */
	if (getpid() == odp_global_ro.main_pid && init_local_called) {
		_ODP_ERR("%s() called multiple times by the same thread\n", __func__);
		goto init_fail;
	}
	init_local_called = 1;

	if (_odp_ishm_init_local()) {
		_ODP_ERR("ODP ishm local init failed.\n");
		goto init_fail;
	}
	stage = ISHM_INIT;

	if (_odp_thread_init_local(thr_type)) {
		_ODP_ERR("ODP thread local init failed.\n");
		goto init_fail;
	}
	stage = THREAD_INIT;

	if (_odp_pktio_init_local()) {
		_ODP_ERR("ODP packet io local init failed.\n");
		goto init_fail;
	}
	stage = PKTIO_INIT;

	if (_odp_timer_init_local()) {
		_ODP_ERR("ODP timer local init failed.\n");
		goto init_fail;
	}
	stage = TIMER_INIT;

	if (_odp_random_init_local()) {
		_ODP_ERR("ODP random local init failed.\n");
		goto init_fail;
	}
	stage = RANDOM_INIT;

	if (_odp_crypto_init_local()) {
		_ODP_ERR("ODP crypto local init failed.\n");
		goto init_fail;
	}
	stage = CRYPTO_INIT;

	if (_odp_pool_init_local()) {
		_ODP_ERR("ODP pool local init failed.\n");
		goto init_fail;
	}
	stage = POOL_INIT;

	if (_odp_queue_fn->init_local()) {
		_ODP_ERR("ODP queue local init failed.\n");
		goto init_fail;
	}
	stage = QUEUE_INIT;

	if (_odp_sched_fn->init_local()) {
		_ODP_ERR("ODP schedule local init failed.\n");
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
	/* Check that odp_init_local() has been called by this thread */
	if (!init_local_called) {
		_ODP_ERR("%s() called by a non-initialized thread\n", __func__);
		return -1;
	}
	init_local_called = 0;

	return term_local(ALL_INIT);
}

int odp_term_abnormal(odp_instance_t instance, uint64_t flags, void *data ODP_UNUSED)
{
	if (flags & ODP_TERM_FROM_SIGH)
		/* Called from signal handler, not safe to terminate with local/global,
		 * return with failure as not able to perform all actions */
		return -1;

	if (odp_term_local() < 0) {
		_ODP_ERR("ODP local terminate failed.\n");
		return -2;
	}

	if (odp_term_global(instance) < 0) {
		_ODP_ERR("ODP global terminate failed.\n");
		return -3;
	}

	return 0;
}

void odp_log_thread_fn_set(odp_log_func_t func)
{
	_odp_this_thread->log_fn = func;
}

odp_log_func_t odp_log_fn_get(void)
{
	return _odp_log_fn_get();
}

int odp_instance(odp_instance_t *instance)
{
	*instance = (odp_instance_t)odp_global_ro.main_pid;

	return 0;
}

uint64_t odp_instance_to_u64(odp_instance_t instance)
{
	return _odp_pri(instance);
}

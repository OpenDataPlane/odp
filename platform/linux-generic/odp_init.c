/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/init.h>
#include <odp_internal.h>
#include <odp/debug.h>
#include <odp_debug_internal.h>

struct odp_global_data_s odp_global_data;

int odp_init_global(odp_init_t *params,
			odp_platform_init_t *platform_params ODP_UNUSED)
{
	odp_global_data.log_fn = odp_override_log;
	odp_global_data.abort_fn = odp_override_abort;

	if (params != NULL) {
		if (params->log_fn != NULL)
			odp_global_data.log_fn = params->log_fn;
		if (params->abort_fn != NULL)
			odp_global_data.abort_fn = params->abort_fn;
	}


	odp_system_info_init();

	if (odp_shm_init_global()) {
		ODP_ERR("ODP shm init failed.\n");
		return -1;
	}

	if (odp_thread_init_global()) {
		ODP_ERR("ODP thread init failed.\n");
		return -1;
	}

	if (odp_pool_init_global()) {
		ODP_ERR("ODP pool init failed.\n");
		return -1;
	}

	if (odp_queue_init_global()) {
		ODP_ERR("ODP queue init failed.\n");
		return -1;
	}

	if (odp_schedule_init_global()) {
		ODP_ERR("ODP schedule init failed.\n");
		return -1;
	}

	if (odp_pktio_init_global()) {
		ODP_ERR("ODP packet io init failed.\n");
		return -1;
	}

	if (odp_timer_init_global()) {
		ODP_ERR("ODP timer init failed.\n");
		return -1;
	}

	if (odp_crypto_init_global()) {
		ODP_ERR("ODP crypto init failed.\n");
		return -1;
	}
	if (odp_classification_init_global()) {
		ODP_ERR("ODP classification init failed.\n");
		return -1;
	}

	return 0;
}

int odp_term_global(void)
{
	int rc = 0;

	if (odp_classification_term_global()) {
		ODP_ERR("ODP classificatio term failed.\n");
		rc = -1;
	}

	if (odp_crypto_term_global()) {
		ODP_ERR("ODP crypto term failed.\n");
		rc = -1;
	}

	if (odp_pktio_term_global()) {
		ODP_ERR("ODP pktio term failed.\n");
		rc = -1;
	}

	if (odp_schedule_term_global()) {
		ODP_ERR("ODP schedule term failed.\n");
		rc = -1;
	}

	if (odp_queue_term_global()) {
		ODP_ERR("ODP queue term failed.\n");
		rc = -1;
	}

	return rc;
}

int odp_init_local(void)
{
	if (odp_shm_init_local()) {
		ODP_ERR("ODP shm local init failed.\n");
		return -1;
	}

	if (odp_thread_init_local()) {
		ODP_ERR("ODP thread local init failed.\n");
		return -1;
	}

	if (odp_pktio_init_local()) {
		ODP_ERR("ODP packet io local init failed.\n");
		return -1;
	}

	if (odp_schedule_init_local()) {
		ODP_ERR("ODP schedule local init failed.\n");
		return -1;
	}

	return 0;
}

int odp_term_local(void)
{
	return (odp_thread_term_local() > 0) ? 1 : 0;
}

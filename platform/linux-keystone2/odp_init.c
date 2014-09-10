/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_init.h>
#include <odp_internal.h>
#include <odp_debug.h>
#include <odp_config.h>
#include <odp_packet_internal.h>

struct odp_global_s *odp_global;
struct odp_proc_s odp_proc;
__thread struct odp_local_s odp_local;

int odp_init_global(void)
{
	odp_thread_init_global();

	odp_system_info_init();

	if (mcsdk_global_init()) {
		odp_pr_err("ODP McSDK init failed.\n");
		return -1;
	}

	if (odp_shm_init_global()) {
		odp_pr_err("ODP shm init failed.\n");
		return -1;
	}

	if (odp_buffer_pool_init_global()) {
		odp_pr_err("ODP buffer pool init failed.\n");
		return -1;
	}

	if (odp_queue_init_global()) {
		odp_pr_err("ODP queue init failed.\n");
		return -1;
	}

	if (odp_schedule_init_global()) {
		odp_pr_err("ODP schedule init failed.\n");
		return -1;
	}

	if (odp_pktio_init_global()) {
		odp_pr_err("ODP packet io init failed.\n");
		return -1;
	}

	if (odp_crypto_init_global()) {
		odp_pr_err("ODP crypto init failed.\n");
		return -1;
	}

	if (odp_timer_init_global()) {
		odp_pr_err("ODP timer init failed.\n");
		return -1;
	}

	return 0;
}


int odp_init_local(int thr_id)
{
	int ret = 0;
	odp_thread_init_local(thr_id);

	ret = mcsdk_local_init(thr_id);
	if (ret < 0) {
		odp_pr_err("Failed to local init McSDK\n");
		return -1;
	} else if (ret > 0) {
		odp_pr_dbg("Skipping local init McSDK\n");
		return 0;
	}

	if (odp_schedule_init_local()) {
		odp_pr_err("ODP schedule local init failed.\n");
		return -1;
	}
	return 0;
}

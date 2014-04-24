/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_init.h>
#include <odp_internal.h>
#include <odp_debug.h>
#include <configs/odp_config_platform.h>
#include <ti_em_osal_core.h>
#include <ti_em_osal_queue.h>
#include <ti_em_rh.h>
#include <odp_config.h>
#include <odp_packet_internal.h>

/*
 * Make region_configs[] global, because hw_config is saved in
 * ti_em_rh_init_global() and it references region_configs[].
 */
static ti_em_osal_hw_region_config_t region_configs[TI_ODP_REGION_NUM];

static int ti_init_hw_config(void)
{
	ti_em_rh_hw_config_t           hw_config;
	ti_em_osal_hw_region_config_t *reg_config;
	memset(&hw_config, 0, sizeof(ti_em_rh_hw_config_t));

	/* Set ODP initialization parameters */
	hw_config.private_free_queue_idx = MY_EM_PRIVATE_FREE_QUEUE_IDX;
	hw_config.hw_queue_base_idx      = MY_EM_SCHED_QUEUE_IDX;
	hw_config.dma_idx                = -1; /* not used */
	hw_config.dma_queue_base_idx     = 0; /* not used */
	hw_config.device_id              = MY_EM_DEVICE_ID;
	hw_config.process_id             = MY_EM_PROCESS_ID;
	hw_config.chain_config_ptr       = NULL;
	hw_config.dispatch_mode          = MY_EM_DISPATCH_MODE;

	/* The location of the PDSP communication memory (physical address) */
	hw_config.pdsp_comm_mem_config.paddr  = MY_EM_PDSP_COMM_MEM_BASE;
	hw_config.pdsp_comm_mem_config.vaddr  = MY_EM_PDSP_COMM_MEM_VBASE;
	hw_config.pdsp_comm_mem_config.size   = MY_EM_PDSP_COMM_MEM_SIZE;
	hw_config.pdsp_comm_mem_config.offset = MY_EM_PDSP_COMM_MEM_OFFSET;

	TI_EM_OSAL_TRACE(2, "physical address of the PDSP communication memory is 0x%x\n",
			 hw_config.pdsp_comm_mem_config.paddr);

	/* Define descriptor regions */
	reg_config = &region_configs[TI_EM_RH_PUBLIC];
	reg_config->region_idx   = TI_ODP_PUBLIC_REGION_IDX;
	reg_config->desc_size    =
		ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_packet_hdr_t));
	reg_config->desc_num     = TI_ODP_PUBLIC_DESC_NUM;
	reg_config->desc_base    = TI_ODP_PUBLIC_DESC_BASE;
	reg_config->desc_vbase   = TI_ODP_PUBLIC_DESC_VBASE;
	reg_config->desc_offset  = TI_ODP_PUBLIC_DESC_OFFSET;
	reg_config->desc_flag    = TI_EM_RH_UNMANAGED_DESCRIPTOR;
	reg_config->start_idx    = TI_ODP_PUBLIC_START_DESC_IDX;

	reg_config = &region_configs[TI_EM_RH_PRIVATE];
	reg_config->region_idx  = TI_ODP_PRIVATE_REGION_IDX;
	reg_config->desc_size   = TI_EM_PRIVATE_EVENT_DSC_SIZE;
	reg_config->desc_num    = TI_EM_RH_PRIVATE_EVENT_NUM;
	reg_config->desc_base   = TI_ODP_PRIVATE_DESC_BASE;
	reg_config->desc_vbase  = TI_ODP_PRIVATE_DESC_VBASE;
	reg_config->desc_offset = TI_ODP_PRIVATE_DESC_OFFSET;
	reg_config->desc_flag   = TI_EM_RH_UNMANAGED_DESCRIPTOR;
	reg_config->start_idx   = TI_ODP_PRIVATE_START_DESC_IDX;

	hw_config.region_num     = TI_ODP_REGION_NUM;
	hw_config.region_configs = &region_configs[0];

	/* Define PDSP configuration */
	hw_config.pdsp_num = 0;
	/* do not use router (no chaining) */
	hw_config.pdsp_router.pdsp_id = -1;

	TI_EM_OSAL_TRACE(1, "calling EM global initialization\n");

	/* call OpenEM global initialization */
	if (ti_em_rh_init_global(0,
				 NULL,
				 MY_EM_CORE_NUM,
				 &hw_config) != EM_OK) {
		TI_EM_OSAL_ERROR("EM global initialization failed!\n");
		return -1;
	}

	return 0;
}


int odp_init_global(void)
{
	odp_thread_init_global();

	odp_system_info_init();

	ti_em_osal_core_init_global();
	ti_init_hw_config();

	if (odp_shm_init_global()) {
		ODP_ERR("ODP shm init failed.\n");
		return -1;
	}

	if (odp_buffer_pool_init_global()) {
		ODP_ERR("ODP buffer pool init failed.\n");
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

	return 0;
}


int odp_init_local(int thr_id)
{
	odp_thread_init_local(thr_id);

	ti_em_rh_init_local();

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

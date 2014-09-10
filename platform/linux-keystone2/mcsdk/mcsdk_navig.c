/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <odp_state.h>

#include <odp_ti_mcsdk.h>
#include <odp_debug_internal.h>

extern Qmss_GlobalConfigParams qmssGblCfgParams;
extern Cppi_GlobalConfigParams cppiGblCfgParams;

/**
 * Internal NETAPI macro to convert to IP Register Virtual Address
 * from a mapped base Virtual Address.
 *
 * @param virt_base_addr Virtual base address mapped using mmap for IP
 * @param phys_base_addr Physical base address for the IP
 * @param phys_reg_addr  Physical register address
 *
 * @return virtual address
 */
static inline void *reg_phys2virt(void *virt_base_addr,
				  uint32_t phys_base_addr,
				  uint32_t phys_reg_addr)
{
	return (void *)((uint8_t *)virt_base_addr +
			(phys_reg_addr - phys_base_addr));
}

/*****************************************************************************
 * FUNCTION PURPOSE: Global Initialization of CPPI. Once Per System
 *****************************************************************************
 * DESCRIPTION: The function will initialize the CPPI
 *****************************************************************************/
int mcsdk_cppi_init(void)
{
	int32_t result;
	Cppi_GlobalConfigParams config_params;
	Cppi_GlobalCPDMAConfigParams *dma_cfgs;

	config_params = cppiGblCfgParams;
	/* Convert Physical address to Virtual address for LLD access */
	/* PASS CPDMA regs */
	dma_cfgs = &config_params.cpDmaCfgs[Cppi_CpDma_PASS_CPDMA];
	dma_cfgs->gblCfgRegs = reg_phys2virt(odp_vm_info.passCfgVaddr,
			CSL_NETCP_CFG_REGS, (uint32_t)dma_cfgs->gblCfgRegs);

	dma_cfgs->txChRegs = reg_phys2virt(odp_vm_info.passCfgVaddr,
			CSL_NETCP_CFG_REGS, (uint32_t)dma_cfgs->txChRegs);

	dma_cfgs->rxChRegs = reg_phys2virt(odp_vm_info.passCfgVaddr,
			CSL_NETCP_CFG_REGS, (uint32_t)dma_cfgs->rxChRegs);

	dma_cfgs->txSchedRegs = reg_phys2virt(odp_vm_info.passCfgVaddr,
			CSL_NETCP_CFG_REGS, (uint32_t)dma_cfgs->txSchedRegs);

	dma_cfgs->rxFlowRegs = reg_phys2virt(odp_vm_info.passCfgVaddr,
			CSL_NETCP_CFG_REGS, (uint32_t)dma_cfgs->rxFlowRegs);

	/* QMSS CPDMA regs */
	dma_cfgs = &config_params.cpDmaCfgs[Cppi_CpDma_QMSS_CPDMA];
	dma_cfgs->gblCfgRegs = reg_phys2virt(odp_vm_info.qmssCfgVaddr,
			CSL_QMSS_CFG_BASE, (uint32_t)dma_cfgs->gblCfgRegs);

	dma_cfgs->txChRegs = reg_phys2virt(odp_vm_info.qmssCfgVaddr,
			CSL_QMSS_CFG_BASE, (uint32_t)dma_cfgs->txChRegs);

	dma_cfgs->rxChRegs = reg_phys2virt(odp_vm_info.qmssCfgVaddr,
			CSL_QMSS_CFG_BASE, (uint32_t)dma_cfgs->rxChRegs);

	dma_cfgs->txSchedRegs = reg_phys2virt(odp_vm_info.qmssCfgVaddr,
			CSL_QMSS_CFG_BASE, (uint32_t)dma_cfgs->txSchedRegs);

	dma_cfgs->rxFlowRegs = reg_phys2virt(odp_vm_info.qmssCfgVaddr,
			CSL_QMSS_CFG_BASE, (uint32_t)dma_cfgs->rxFlowRegs);

	result = Cppi_init(&config_params);
	if (result != CPPI_SOK) {
		odp_pr_err("Cppi_init failed with error code %d\n", result);
		return -1;
	}
	return 1;
}

/*****************************************************************************
 * FUNCTION PURPOSE: Global Initialization of Queue Manager. Once Per System
 *****************************************************************************
 * DESCRIPTION: The function will initialize the Queue Manager
 *****************************************************************************/
int mcsdk_qmss_init(int max_descriptors)
{
	Qmss_InitCfg init_config;
	int32_t result;
	Qmss_GlobalConfigParams config_params;
	Qmss_GlobalConfigRegs *regs;
	uint32_t count;

	memset(&init_config, 0, sizeof(Qmss_InitCfg));

	/* Use Internal Linking RAM for optimal performance */
	init_config.linkingRAM0Base = 0;
	init_config.linkingRAM0Size = 0;
	init_config.linkingRAM1Base = 0;
	init_config.maxDescNum = max_descriptors;
	init_config.qmssHwStatus = QMSS_HW_INIT_COMPLETE;

	config_params = qmssGblCfgParams;
	config_params.qmRmServiceHandle = odp_proc.rm_service;
	regs = &config_params.regs;

	/* Convert address to Virtual address */
	for (count = 0; count < config_params.maxQueMgrGroups; count++) {
		Qmss_GlobalConfigGroupRegs *group_regs;
		group_regs = &config_params.groupRegs[count];
		group_regs->qmConfigReg = reg_phys2virt(
				odp_vm_info.qmssCfgVaddr,
				CSL_QMSS_CFG_BASE,
				(uint32_t)group_regs->qmConfigReg);

		group_regs->qmDescReg = reg_phys2virt(
				odp_vm_info.qmssCfgVaddr,
				CSL_QMSS_CFG_BASE,
				(uint32_t)group_regs->qmDescReg);

		group_regs->qmQueMgmtReg = reg_phys2virt(
				odp_vm_info.qmssCfgVaddr,
				CSL_QMSS_CFG_BASE,
				(uint32_t)group_regs->qmQueMgmtReg);

		group_regs->qmQueMgmtProxyReg = reg_phys2virt(
				odp_vm_info.qmssCfgVaddr,
				CSL_QMSS_CFG_BASE,
				(uint32_t)group_regs->qmQueMgmtProxyReg);

		group_regs->qmQueStatReg = reg_phys2virt(
				odp_vm_info.qmssCfgVaddr,
				CSL_QMSS_CFG_BASE,
				(uint32_t)group_regs->qmQueStatReg);

		group_regs->qmStatusRAM = reg_phys2virt(
				odp_vm_info.qmssCfgVaddr,
				CSL_QMSS_CFG_BASE,
				(uint32_t)group_regs->qmStatusRAM);

		group_regs->qmQueMgmtDataReg = reg_phys2virt(
				odp_vm_info.qmssDataVaddr,
				CSL_QMSS_DATA_BASE,
				(uint32_t)group_regs->qmQueMgmtDataReg);

		group_regs->qmQueMgmtProxyDataReg =
				NULL;
	}

	for (count = 0; count < QMSS_MAX_INTD; count++) {
		regs->qmQueIntdReg[count] = reg_phys2virt(
				odp_vm_info.qmssCfgVaddr,
				CSL_QMSS_CFG_BASE,
				(uint32_t)regs->qmQueIntdReg[count]);
	}

	for (count = 0; count < QMSS_MAX_PDSP; count++) {
		regs->qmPdspCmdReg[count] = reg_phys2virt(
				odp_vm_info.qmssCfgVaddr,
				CSL_QMSS_CFG_BASE,
				(uint32_t)regs->qmPdspCmdReg[count]);

		regs->qmPdspCtrlReg[count] = reg_phys2virt(
				odp_vm_info.qmssCfgVaddr,
				CSL_QMSS_CFG_BASE,
				(uint32_t)regs->qmPdspCtrlReg[count]);

		regs->qmPdspIRamReg[count] = reg_phys2virt(
				odp_vm_info.qmssCfgVaddr,
				CSL_QMSS_CFG_BASE,
				(uint32_t)regs->qmPdspIRamReg[count]);
	}

	regs->qmLinkingRAMReg = reg_phys2virt(odp_vm_info.qmssCfgVaddr,
			CSL_QMSS_CFG_BASE, (uint32_t)regs->qmLinkingRAMReg);

	regs->qmBaseAddr = reg_phys2virt(odp_vm_info.qmssCfgVaddr,
			CSL_QMSS_CFG_BASE, (uint32_t)regs->qmBaseAddr);

	result = Qmss_init(&init_config, &config_params);
	if (result != QMSS_SOK) {
		odp_pr_err("%s: qmss_Init failed with error code %d\n",
			   __func__, result);
		return nwal_FALSE;
	}
	return 1;
}

/********************************************************************
 * FUNCTION PURPOSE:  Internal NETAPI function to start QM
 ********************************************************************
 * DESCRIPTION:  Internal NETAPI function to start QM
 *               once per thread/core
 ********************************************************************/
int mcsdk_qmss_start(void)
{
	int32_t result;
	Qmss_StartCfg start_cfg;

	start_cfg.rmServiceHandle = odp_proc.rm_service;

	result = Qmss_startCfg(&start_cfg);
	if (result != QMSS_SOK) {
		odp_pr_err("Qmss_start failed with error code %d\n", result);
		return -1;
	}
	return 1;
}

int mcsdk_cppi_start(void)
{
	Cppi_StartCfg start_cfg;

	start_cfg.rmServiceHandle = odp_proc.rm_service;

	Cppi_startCfg(&start_cfg);

	return 1;
}

/********************************************************************
 * FUNCTION PURPOSE:  Internal NETAPI function to setup the QM memory region
 ********************************************************************
 * DESCRIPTION:  Internal NETAPI function to setup the QM memory region,
 *               once per SOC
 ********************************************************************/
int mcsdk_qmss_setup_memregion(uint32_t desc_num, uint32_t desc_size,
		uint32_t *desc_mem_base, Qmss_MemRegion mem_region)
{
	Qmss_MemRegInfo mem_info;
	Int32 result;

	memset(&mem_info, 0, sizeof(Qmss_MemRegInfo));
	mem_info.descBase = desc_mem_base;
	mem_info.descSize = desc_size;
	mem_info.descNum = desc_num;
	mem_info.manageDescFlag = Qmss_ManageDesc_MANAGE_DESCRIPTOR;
	mem_info.memRegion = mem_region;
	mem_info.startIndex = TUNE_NETAPI_QM_START_INDEX;

	memset(desc_mem_base, 0, (desc_size * desc_num));

	result = Qmss_insertMemoryRegion(&mem_info);
	if (result < QMSS_SOK) {
		odp_pr_err("Qmss_insertMemoryRegion returned error code %d\n",
			   result);
		return -1;
	}

	return 1;
}

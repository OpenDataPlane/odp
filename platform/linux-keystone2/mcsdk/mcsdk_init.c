/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <odp_align.h>
#include <odp_thread.h>
#include <odp_internal.h>
#include <odp_ti_mcsdk.h>
#include <odp_debug_internal.h>

/* Global variables to hold virtual address of various subsystems */
hplib_virtualAddrInfo_T odp_vm_info;

/*
 * Global variables which needs to be populated with memory pool attributes
 * which is passed to HPLIB for memory pool initialization
 */
void *global_descriptor_mem_base;
void *sa_context_mem_base;

static uint8_t *cma_mem_alloc(uint32_t size);
static void cma_mem_free(uint8_t *ptr, uint32_t size);

Pktlib_HeapIfTable  pktlib_if_table = {
	.data_malloc = cma_mem_alloc,
	.data_free =   cma_mem_free,
};

struct mcsdk_cfg_s default_mcsdk_cfg = {
	.def_mem_size = TUNE_NETAPI_PERM_MEM_SZ,
	.def_max_descriptors = TUNE_NETAPI_QM_CONFIG_MAX_DESC_NUM,
	.def_tot_descriptors_for_us = TUNE_NETAPI_NUM_GLOBAL_DESC,
	.def_heap_n_descriptors = TUNE_NETAPI_DEFAULT_NUM_BUFFERS,
	.def_heap_n_zdescriptors = 0,
	.def_heap_buf_size = TUNE_NETAPI_DEFAULT_BUFFER_SIZE,
	.def_heap_tailroom_size = 0,
	.def_heap_extra_size = 0,
	.min_buf_headroom_size = ODP_CACHE_LINE_SIZE,
};

/**
 * NWAL Memory Buffer Configuration
 * @todo: Buffers for NWAL can be allocated dynamically
 */
#define NWAL_CONFIG_SEC_CONTEXT_SZ			384

#define NWAL_CONFIG_BUFSIZE_NWAL_HANDLE			3400

#define NWAL_CONFIG_BUFSIZE_NWAL_PER_MAC		256
#define NWAL_CONFIG_BUFSIZE_NWAL_IPSEC_HANDLE_PER_CHAN	256
#define NWAL_CONFIG_BUFSIZE_NWAL_PER_IP			128
#define NWAL_CONFIG_BUFSIZE_NWAL_PER_PORT		128
#define NWAL_CONFIG_BUFSIZE_NWAL_PER_L2L3_HDR		128
#define NWAL_CONFIG_BUFSIZE_NWAL_PER_LOC_CONTEXT	384
#define NWAL_CHAN_HANDLE_SIZE  \
	((NWAL_CONFIG_BUFSIZE_NWAL_PER_MAC * TUNE_NETAPI_MAX_NUM_MAC) + \
	 (NWAL_CONFIG_BUFSIZE_NWAL_IPSEC_HANDLE_PER_CHAN * \
				TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS*2) + \
	 (NWAL_CONFIG_BUFSIZE_NWAL_PER_IP * TUNE_NETAPI_MAX_NUM_IP) + \
	 (NWAL_CONFIG_BUFSIZE_NWAL_PER_PORT * TUNE_NETAPI_MAX_NUM_PORTS) + \
	 (NWAL_CONFIG_BUFSIZE_NWAL_PER_LOC_CONTEXT * TUNE_NETAPI_NUM_CORES) + \
	 (NWAL_CONFIG_BUFSIZE_NWAL_PER_L2L3_HDR * \
				TUNE_NETAPI_MAX_NUM_L2_L3_HDRS))

uint8_t nwal_inst_mem[NWAL_CONFIG_BUFSIZE_NWAL_HANDLE] ODP_ALIGNED_CACHE;
uint8_t nwal_handle_mem[NWAL_CHAN_HANDLE_SIZE]         ODP_ALIGNED_CACHE;

/**
 * @todo: Check if below size information can be made available
 * from PA interface file
 */
#define NWAL_CONFIG_BUFSIZE_PA_BUF0   256
#define NWAL_CONFIG_BUFSIZE_PA_BUF1   (128 * TUNE_NETAPI_MAX_NUM_MAC)
#define NWAL_CONFIG_BUFSIZE_PA_BUF2   13824

struct pa_global {
	/* Memory used for the PA Instance.*/
	uint8_t pa_buf0[NWAL_CONFIG_BUFSIZE_PA_BUF0] ODP_ALIGNED_CACHE;
	/* Memory used for PA handles */
	uint8_t pa_buf1[NWAL_CONFIG_BUFSIZE_PA_BUF1] ODP_ALIGNED_CACHE;
	uint8_t pa_buf2[NWAL_CONFIG_BUFSIZE_PA_BUF2] ODP_ALIGNED_CACHE;
};


#define NWAL_CONFIG_BUFSIZE_SA_HANDLE           512
#define NWAL_CONFIG_BUFSIZE_SA_HANDLE_PER_CHAN  512

struct sa_global {
	/* Memory used for SA LLD global Handle */
	uint8_t salld_handle[NWAL_CONFIG_BUFSIZE_SA_HANDLE] ODP_ALIGNED_CACHE;
	/* Memory used by SA LLD per Channel */
	uint8_t salld_chan_handle[NWAL_CONFIG_BUFSIZE_SA_HANDLE_PER_CHAN *
				TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS*2]
				ODP_ALIGNED_CACHE;
};

static uint8_t *cma_mem_alloc(uint32_t size)
{
	return (uint8_t *)hplib_vmMemAlloc(
			size + odp_global->cfg.def_heap_extra_size, 128, 0);
}

static void cma_mem_free(uint8_t *ptr ODP_UNUSED, uint32_t size ODP_UNUSED)
{
	/* Do Nothing. */
	odp_pr_err("need to provide a free () for some reason!!\n");
	return;
}

/********************************************************************
 * FUNCTION PURPOSE:  Internal NETAPI function to initialize NWAL subsystem
 ********************************************************************
 * DESCRIPTION:  Internal NETAPI function to initialize NWAL subsytem
 ********************************************************************/
int mcsdk_nwal_init(int region2use, Pktlib_HeapIfTable *p_table)
{
	nwalSizeInfo_t nwal_size_info;
	nwal_RetValue nwal_ret;
	nwalGlobCfg_t nwal_global_cfg;
	uint8_t count;
	int sizes[nwal_N_BUFS];
	int aligns[nwal_N_BUFS];
	void *bases[nwal_N_BUFS];
	Pktlib_HeapCfg heap_cfg;
	int32_t pktlib_err;
	void *base = NULL;
	struct pa_global *pa_entry = NULL;
	struct sa_global *sa_entry = NULL;

	memset(&odp_global->nwal, 0, sizeof(odp_global->nwal));
	memset(&nwal_global_cfg, 0, sizeof(nwal_global_cfg));

	nwal_global_cfg.rmHandle = odp_proc.rm_service;

	base = hplib_shmOpen();
	if (base) {
		if (hplib_shmAddEntry(base, sizeof(struct pa_global), PA_ENTRY)
				== hplib_OK) {
			pa_entry = (struct pa_global *)hplib_shmGetEntry(
					base, PA_ENTRY);
			nwal_global_cfg.instPoolBaseAddr = (void *)pa_entry;
		} else {
			odp_pr_err("Unable to Add shared memory segment for PASS\n");
			return -1;
		}
		if (hplib_shmAddEntry(base, sizeof(struct sa_global), SA_ENTRY)
				== hplib_OK) {
			sa_entry = (struct sa_global *)hplib_shmGetEntry(
					base, SA_ENTRY);
			nwal_global_cfg.instPoolSaBaseAddr = (void *)sa_entry;
		} else {
			odp_pr_err("Unable to Add shared memory segment for SASS\n");
			return -1;
		}
	}
	/* Initialize Buffer Pool for NetCP PA to SA packets */
	nwal_global_cfg.pa2SaBufPool.numBufPools = 1;
	nwal_global_cfg.pa2SaBufPool.bufPool[0].descSize =
			TUNE_NETAPI_DESC_SIZE;
	nwal_global_cfg.pa2SaBufPool.bufPool[0].bufSize =
			odp_global->cfg.def_heap_buf_size;

	/* Initialize the heap configuration. */
	memset((void *)&heap_cfg, 0, sizeof(Pktlib_HeapCfg));
	/* Populate the heap configuration */
	heap_cfg.name = "nwal PA2SA";
	heap_cfg.memRegion = region2use;
	heap_cfg.sharedHeap = 0;
	heap_cfg.useStarvationQueue = 0;
	heap_cfg.dataBufferSize = odp_global->cfg.def_heap_buf_size;
	heap_cfg.numPkts = TUNE_NETAPI_CONFIG_MAX_PA_TO_SA_DESC;
	heap_cfg.numZeroBufferPackets = 0;
	heap_cfg.heapInterfaceTable.data_malloc = p_table->data_malloc;
	heap_cfg.heapInterfaceTable.data_free = p_table->data_free;
	heap_cfg.dataBufferPktThreshold = 0;
	heap_cfg.zeroBufferPktThreshold = 0;

	nwal_global_cfg.pa2SaBufPool.bufPool[0].heapHandle =
			Pktlib_createHeap(&heap_cfg, &pktlib_err);
	if (nwal_global_cfg.pa2SaBufPool.bufPool[0].heapHandle == NULL) {
		odp_pr_err("Heap Creation Failed for PA to SA Buffer Pool, Error Code: %d\n",
			   pktlib_err);
		return -1;
	}
	odp_global->nwal.pa2sa_heap =
			nwal_global_cfg.pa2SaBufPool.bufPool[0].heapHandle;
	/* Initialize Buffer Pool for NetCP SA to PA packets */
	nwal_global_cfg.sa2PaBufPool.numBufPools = 1;
	nwal_global_cfg.sa2PaBufPool.bufPool[0].descSize =
			TUNE_NETAPI_DESC_SIZE;
	nwal_global_cfg.sa2PaBufPool.bufPool[0].bufSize =
			odp_global->cfg.def_heap_buf_size;

	/* Populate the heap configuration */
	heap_cfg.name = "nwal SA2PA";
	heap_cfg.numPkts = TUNE_NETAPI_CONFIG_MAX_SA_TO_PA_DESC;

	nwal_global_cfg.sa2PaBufPool.bufPool[0].heapHandle =
			Pktlib_createHeap(&heap_cfg, &pktlib_err);
	if (nwal_global_cfg.sa2PaBufPool.bufPool[0].heapHandle == NULL) {
		odp_pr_err("Heap Creation Failed for SA to PA Buffer Pool, Error Code: %d\n",
			   pktlib_err);
		return -1;
	}
	odp_global->nwal.sa2pa_heap =
			nwal_global_cfg.sa2PaBufPool.bufPool[0].heapHandle;
	nwal_global_cfg.hopLimit = 5;/* Default TTL / Hop Limit */
	nwal_global_cfg.paPowerOn = nwal_TRUE;
	nwal_global_cfg.saPowerOn = nwal_TRUE;
	nwal_global_cfg.paFwActive = nwal_TRUE;
	nwal_global_cfg.saFwActive = nwal_FALSE;

	/* Pick Default Physical Address */
	nwal_global_cfg.paVirtBaseAddr = (uint32_t)odp_vm_info.passCfgVaddr;
	nwal_global_cfg.saVirtBaseAddr = (uint32_t)odp_vm_info.passCfgVaddr +
					 CSL_NETCP_CFG_SA_CFG_REGS -
					 CSL_NETCP_CFG_REGS;

	nwal_global_cfg.rxDefPktQ = QMSS_PARAM_NOT_SPECIFIED;

	/* Get the Buffer Requirement from NWAL */
	memset(&nwal_size_info, 0, sizeof(nwal_size_info));
	nwal_size_info.nMaxMacAddress = TUNE_NETAPI_MAX_NUM_MAC;
	nwal_size_info.nMaxIpAddress = TUNE_NETAPI_MAX_NUM_IP;
	nwal_size_info.nMaxL4Ports = TUNE_NETAPI_MAX_NUM_PORTS;
	nwal_size_info.nMaxIpSecChannels = TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS;
	nwal_size_info.nMaxDmSecChannels = TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS;
	nwal_size_info.nMaxL2L3Hdr = TUNE_NETAPI_MAX_NUM_L2_L3_HDRS;
	/**
	 * @todo: nProc increased by 1, because nwal_getLocContext()
	 * checks for >=. Better to fix nwal_getLocContext()
	 */
	nwal_size_info.nProc = TUNE_NETAPI_NUM_CORES + 1;
	nwal_ret = nwal_getBufferReq(&nwal_size_info, sizes, aligns);
	if (nwal_ret != nwal_OK) {
		odp_pr_err("nwal_getBufferReq Failed %d\n",
			   nwal_ret);
		return nwal_FALSE;
	}

	/* Check for memory size requirement and update the base */
	count = 0;
	bases[nwal_BUF_INDEX_INST] = (uint32_t *)Osal_nwalLocToGlobAddr(
			(uint32_t)nwal_inst_mem);
	if (NWAL_CONFIG_BUFSIZE_NWAL_HANDLE < sizes[nwal_BUF_INDEX_INST]) {
		/* Resize Memory */
		while (1)
			;
	}
	count++;

	bases[nwal_BUF_INDEX_INT_HANDLES] = (uint32_t *)Osal_nwalLocToGlobAddr(
			(uint32_t)nwal_handle_mem);
	if (NWAL_CHAN_HANDLE_SIZE < sizes[nwal_BUF_INDEX_INT_HANDLES]) {
		/* Resize Memory */
		while (1)
			;
	}
	count++;
	bases[nwal_BUF_INDEX_PA_LLD_BUF0] = (uint32_t *)Osal_nwalLocToGlobAddr(
			(uint32_t)pa_entry->pa_buf0);
	if ((NWAL_CONFIG_BUFSIZE_PA_BUF0) < sizes[nwal_BUF_INDEX_PA_LLD_BUF0]) {
		/* Resize Memory */
		while (1)
			;
	}
	count++;

	bases[nwal_BUF_INDEX_PA_LLD_BUF1] = (uint32_t *)Osal_nwalLocToGlobAddr(
			(uint32_t)pa_entry->pa_buf1);
	if ((NWAL_CONFIG_BUFSIZE_PA_BUF1) < sizes[nwal_BUF_INDEX_PA_LLD_BUF1]) {
		/* Resize Memory */
		while (1)
			;
	}
	count++;

	bases[nwal_BUF_INDEX_PA_LLD_BUF2] = (uint32_t *)Osal_nwalLocToGlobAddr(
			(uint32_t)pa_entry->pa_buf2);
	if ((NWAL_CONFIG_BUFSIZE_PA_BUF2) < sizes[nwal_BUF_INDEX_PA_LLD_BUF2]) {
		/* Resize Memory */
		while (1)
			;
	}
	count++;
#ifdef NETAPI_ENABLE_SECURITY
	bases[nwal_BUF_INDEX_SA_LLD_HANDLE] =
			(uint32_t *)Osal_nwalLocToGlobAddr(
					(uint32_t)sa_entry->salld_handle);
	if ((NWAL_CONFIG_BUFSIZE_SA_HANDLE)
			< sizes[nwal_BUF_INDEX_SA_LLD_HANDLE]) {
		/* Resize Memory */
		while (1)
			;
	}
	count++;

	bases[nwal_BUF_INDEX_SA_CONTEXT] = (uint32_t *)Osal_nwalLocToGlobAddr(
			(uint32_t)sa_context_mem_base);
	/* also save this here for easy access to sa_start */
	nwal_global_cfg.scPoolBaseAddr = bases[nwal_BUF_INDEX_SA_CONTEXT];
	count++;

	bases[nwal_BUF_INDEX_SA_LLD_CHAN_HANDLE] =
			(uint32_t *)Osal_nwalLocToGlobAddr(
					(uint32_t)sa_entry->salld_chan_handle);
	if ((NWAL_CONFIG_BUFSIZE_SA_HANDLE_PER_CHAN
			* TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS * 2)
			< sizes[nwal_BUF_INDEX_SA_LLD_CHAN_HANDLE]) {
		/* Resize Memory */
		while (1)
			;
	}
	count++;
#else
	bases[nwal_BUF_INDEX_SA_LLD_HANDLE] = 0;
	bases[nwal_BUF_INDEX_SA_CONTEXT] = 0;
	bases[nwal_BUF_INDEX_SA_LLD_CHAN_HANDLE] = 0;
	count = count+3;
#endif
	if (count != nwal_N_BUFS) {
		while (1)
			;
	}

	/* Initialize NWAL module */
	nwal_ret = nwal_create(&nwal_global_cfg, &nwal_size_info, sizes, bases,
					&odp_global->nwal.handle);
	if (nwal_ret != nwal_OK) {
		odp_pr_err("nwal_create Failed %d\n",
			   nwal_ret);
		return -1;
	}

	odp_pr_dbg("Global and Local Network initialization Successful\n");
	return 1;
}

/********************************************************************
 * FUNCTION PURPOSE:  Internal NETAPI function to start  NWAL
 ********************************************************************
 * DESCRIPTION:  Internal NETAPI function to start NWAL, per thread/core
 ********************************************************************/
int mcsdk_nwal_start(Pktlib_HeapHandle pkt_heap, Pktlib_HeapHandle cmd_rx_heap,
			Pktlib_HeapHandle cmd_tx_heap)
{
	nwalLocCfg_t nwal_local_cfg;
	nwal_RetValue nwal_ret;

	memset(&nwal_local_cfg, 0, sizeof(nwal_local_cfg));

	/*
	 * Update the Start of Packet Offset for the default flows created
	 * by NWAL
	 */
	nwal_local_cfg.rxSopPktOffset = odp_global->cfg.min_buf_headroom_size;
	nwal_local_cfg.rxPktTailRoomSz = odp_global->cfg.def_heap_tailroom_size;

	/* Call back registration for the core */
	nwal_local_cfg.pRxPktCallBack = NULL;
	nwal_local_cfg.pCmdCallBack = NULL;
	nwal_local_cfg.pPaStatsCallBack = NULL;
	nwal_local_cfg.pRxDmCallBack = NULL;

	/* Initialize Buffer Pool for Control packets from NetCP to Host */
	nwal_local_cfg.rxCtlPool.numBufPools = 1;
	nwal_local_cfg.rxCtlPool.bufPool[0].descSize = TUNE_NETAPI_DESC_SIZE;
	nwal_local_cfg.rxCtlPool.bufPool[0].bufSize =
	TUNE_NETAPI_CONFIG_MAX_CTL_RXTX_BUF_SIZE;
	nwal_local_cfg.rxCtlPool.bufPool[0].heapHandle = cmd_rx_heap;

	/* Initialize Buffer Pool for Control packets from Host to NetCP */
	nwal_local_cfg.txCtlPool.numBufPools = 1;
	nwal_local_cfg.txCtlPool.bufPool[0].descSize = TUNE_NETAPI_DESC_SIZE;
	nwal_local_cfg.txCtlPool.bufPool[0].bufSize =
	TUNE_NETAPI_CONFIG_MAX_CTL_RXTX_BUF_SIZE;
	nwal_local_cfg.txCtlPool.bufPool[0].heapHandle = cmd_tx_heap;

	/* Initialize Buffer Pool for Packets from NetCP to Host */
	nwal_local_cfg.rxPktPool.numBufPools = 1;
	nwal_local_cfg.rxPktPool.bufPool[0].descSize = TUNE_NETAPI_DESC_SIZE;
	nwal_local_cfg.rxPktPool.bufPool[0].bufSize =
			odp_global->cfg.def_heap_buf_size;
	nwal_local_cfg.rxPktPool.bufPool[0].heapHandle = pkt_heap;

	/* Initialize Buffer Pool for Packets from Host to NetCP */
	nwal_local_cfg.txPktPool.numBufPools = 1;
	nwal_local_cfg.txPktPool.bufPool[0].descSize = TUNE_NETAPI_DESC_SIZE;
	nwal_local_cfg.txPktPool.bufPool[0].bufSize =
			odp_global->cfg.def_heap_buf_size;
	nwal_local_cfg.txPktPool.bufPool[0].heapHandle = pkt_heap;

	memcpy(&odp_local.nwal.cfg, &nwal_local_cfg, sizeof(nwalLocCfg_t));
	while (1) {
		nwal_ret = nwal_start(odp_global->nwal.handle, &nwal_local_cfg);
		if (nwal_ret == nwal_ERR_INVALID_STATE)
			continue;
		break;
	}

	if (nwal_ret != nwal_OK) {
		odp_pr_err(">nwal_start:Failed ->err %d !!!\n", nwal_ret);
		return -1;
	}
	return 1;
}

int mcsdk_global_init(void)
{
	int32_t result;
	Pktlib_HeapHandle shared_heap;
	Pktlib_HeapHandle control_rx_heap, control_tx_heap;
	Pktlib_HeapCfg heap_cfg;
	int32_t pktlib_err;
	void *base;
	hplib_memPoolAttr_T mem_pool_attr[HPLIB_MAX_MEM_POOLS];
	int thread_id;

	thread_id = odp_thread_create(0);
	odp_thread_init_local(thread_id);
	hplib_utilSetupThread(thread_id, NULL, hplib_spinLock_Type_LOL);

	odp_local.is_main_thread = 1; /*Prevent local_init on this thread */

	base = hplib_shmCreate(HPLIB_SHM_SIZE);
	if (base == NULL) {
		odp_pr_err("hplib_shmCreate failure\n");
		return -1;
	} else {
		odp_pr_dbg("hplib_shmCreate success\n");
	}

	if (hplib_shmAddEntry(base, sizeof(struct odp_global_s), NETAPI_ENTRY)
			!= hplib_OK) {
		odp_pr_err("hplib_shmAddEntry failed for NETAPI_ENTRY\n");
		return -1;
	} else {
		odp_pr_dbg("hplib_shmAddEntry success for NETAPI_ENTRY\n");
		odp_global = hplib_shmGetEntry(base, NETAPI_ENTRY);
		odp_global->cfg = default_mcsdk_cfg;
	}

	hplib_utilModOpen();
	hplib_utilOsalCreate();

	odp_proc.rm_service = rm_client_init();

#ifdef NETAPI_USE_DDR
	/* Init attributes for DDR */
	mem_pool_attr[0].attr = HPLIB_ATTR_KM_CACHED0;
	mem_pool_attr[0].phys_addr = 0;
	mem_pool_attr[0].size = 0;

	/* Init attributes for un-cached MSMC */
	mem_pool_attr[1].attr = HPLIB_ATTR_UN_CACHED;
	mem_pool_attr[1].phys_addr = CSL_MSMC_SRAM_REGS;
	mem_pool_attr[1].size = TUNE_NETAPI_PERM_MEM_SZ;
#else
	mem_pool_attr[1].attr = HPLIB_ATTR_KM_CACHED0;
	mem_pool_attr[1].phys_addr = 0;
	mem_pool_attr[1].size = 0;

	/* Init attributes for un-cached MSMC */
	mem_pool_attr[0].attr = HPLIB_ATTR_UN_CACHED;
	mem_pool_attr[0].phys_addr = CSL_MSMC_SRAM_REGS;
	mem_pool_attr[0].size = TUNE_NETAPI_PERM_MEM_SZ;
#endif
	/* initialize all the memory we are going to use
	 - chunk for buffers, descriptors
	 - memory mapped peripherals we use, such as QMSS, PA, etc */
	result = hplib_vmInit(&odp_vm_info, 2, &mem_pool_attr[0]);

	hplib_initMallocArea(0);
	hplib_initMallocArea(1);

#ifdef NETAPI_ENABLE_SECURITY
	/*
	 * allocate 2x number of tunnels since we need one for inflow and
	 * one for data mode
	 */
	sa_context_mem_base = hplib_vmMemAlloc(
			(TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS * 2 *
			NWAL_CONFIG_SEC_CONTEXT_SZ),
			128, 0);
	if (!sa_context_mem_base) {
		odp_pr_err("Failed to map SA context memory region\n");
		return -1;
	}
	odp_pr_dbg("SA Memory mapped/allocated at address %p.\n",
		   sa_context_mem_base);

#else
	sa_context_mem_base = NULL;
#endif

	/* Allocate QM region from contiguous chunk above */
	global_descriptor_mem_base = hplib_vmMemAlloc(
			(odp_global->cfg.def_tot_descriptors_for_us
					* TUNE_NETAPI_DESC_SIZE),
			128, 0);

	odp_pr_dbg("global desc region=%p\n", global_descriptor_mem_base);

	/* Initialize Queue Manager Sub System */
	result = mcsdk_qmss_init(odp_global->cfg.def_max_descriptors);

	if (result != 1) {
		odp_pr_err("returned from netapip_initQm with failure\n");
		return -1;
	}

	/* Start the QMSS. */
	if (mcsdk_qmss_start() != 1) {
		odp_pr_err("returned from netapip_startQm with failure\n");
		return -1;
	}

	/* Initialize the global descriptor memory region. */
	result = mcsdk_qmss_setup_memregion(
			odp_global->cfg.def_tot_descriptors_for_us,
			TUNE_NETAPI_DESC_SIZE,
			global_descriptor_mem_base,
			TUNE_NETAPI_QM_GLOBAL_REGION);

	if (result < 0) {
		odp_pr_err("can't setup QM shared region\n");
		return -1;
	}

	odp_pr_dbg("returned from netapip_qmSetupMemRegion\n");
	/* Initialize CPPI CPDMA */

	result = mcsdk_cppi_init();
	odp_pr_dbg("returned from netapip_initCppi\n");
	if (result != 1) {
		odp_pr_err("Error initializing CPPI SubSystem error code : %d\n",
			   result);
		return -1;
	}
	mcsdk_cppi_start();

	/* CPPI and Queue Manager are initialized. */
	odp_pr_dbg("Queue Manager and CPPI are initialized.\n");

	/* create main pkt heap */
	/* Initialize the Shared Heaps. */
	Pktlib_sharedHeapInit();
	odp_pr_dbg("returned from Pktlib_sharedHeapInit\n");

	/* Initialize the heap configuration. */
	memset((void *)&heap_cfg, 0, sizeof(Pktlib_HeapCfg));
	/* Populate the heap configuration */
	heap_cfg.name = "nwal_packet";
	heap_cfg.memRegion = TUNE_NETAPI_QM_GLOBAL_REGION;
	heap_cfg.sharedHeap = 1;
	heap_cfg.useStarvationQueue = 0;
	heap_cfg.dataBufferSize = odp_global->cfg.def_heap_buf_size;
	heap_cfg.numPkts = odp_global->cfg.def_heap_n_descriptors;
	heap_cfg.numZeroBufferPackets = odp_global->cfg.def_heap_n_zdescriptors;
	heap_cfg.heapInterfaceTable.data_malloc =
			pktlib_if_table.data_malloc;
	heap_cfg.heapInterfaceTable.data_free = pktlib_if_table.data_free;
	heap_cfg.dataBufferPktThreshold = 0;
	heap_cfg.zeroBufferPktThreshold = 0;

	/* Create Shared Heap with specified configuration. */
	shared_heap = Pktlib_createHeap(&heap_cfg, &pktlib_err);
	odp_pr_dbg("returned from Pktlib_createHeap1\n");
	if (!shared_heap) {
		/** @todo: cleanup on failure */
		odp_pr_err("heap create failed, Error Code: %d\n",
			   pktlib_err);
		return -1;
	}
	odp_proc.nwal.netcp_heap = shared_heap;

	/* Update for Control */
	heap_cfg.name = "nwal_control_rx";
	heap_cfg.sharedHeap = 1;
	heap_cfg.dataBufferSize = TUNE_NETAPI_CONFIG_MAX_CTL_RXTX_BUF_SIZE;
	heap_cfg.numPkts = TUNE_NETAPI_CONFIG_NUM_CTL_RX_BUF;
	heap_cfg.numZeroBufferPackets = 0;

	control_rx_heap = Pktlib_createHeap(&heap_cfg, &pktlib_err);
	odp_pr_dbg("returned from Pktlib_createHeap2\n");
	if (!control_rx_heap) {
		/** @todo: cleanup on failure */
		odp_pr_err("control rx heap create failed, Error Code: %d\n",
			   pktlib_err);
		return -1;
	}
	odp_proc.nwal.netcp_control_rx_heap = control_rx_heap;

	heap_cfg.name = "nwal_control_tx";
	heap_cfg.numPkts = TUNE_NETAPI_CONFIG_NUM_CTL_TX_BUF;

	control_tx_heap = Pktlib_createHeap(&heap_cfg, &pktlib_err);
	odp_pr_dbg("returned from Pktlib_createHeap3\n");
	if (!control_tx_heap) {
		/** @todo: cleanup on failure */
		odp_pr_err("control tx heap create failed, Error Code: %d\n",
			   pktlib_err);
		return -1;
	}
	odp_proc.nwal.netcp_control_tx_heap = control_tx_heap;

	/* Init NWAL */
	result = mcsdk_nwal_init(TUNE_NETAPI_QM_GLOBAL_REGION,
					&pktlib_if_table);
	if (result < 0) {
		odp_pr_err("netapi  init_nwal() failed\n");
		return -1;
	}
	odp_pr_dbg("returned from netapip_initNwal\n");

	/* start NWAL */
	result = mcsdk_nwal_start(shared_heap, control_rx_heap,
					control_tx_heap);
	if (result < 0) {
		odp_pr_err("netapi start_nwal() failed\n");
		return -1;
	}
	odp_pr_dbg("returned from netapip_startNwal\n");
	return 0;
}

int mcsdk_local_init(int thread_id)
{
	int ret;
	/* Main thread already finished initialization */
	if (odp_local.is_main_thread) {
		odp_pr_dbg("Skip odp_local_init() for the main thread\n");
		return 1;
	}
	odp_pr_dbg("thread_id: %d\n", thread_id);

	hplib_utilSetupThread(thread_id, NULL, hplib_spinLock_Type_LOL);
	/* Start the QMSS. */
	if (mcsdk_qmss_start() != 1)
		return -1;

	mcsdk_cppi_start();

	ret = mcsdk_nwal_start(odp_proc.nwal.netcp_heap,
				odp_proc.nwal.netcp_control_rx_heap,
				odp_proc.nwal.netcp_control_tx_heap);

	if (ret < 0) {
		odp_pr_err("mcsdk_nwal_start() failed\n");
		return -1;
	}
	odp_pr_dbg("thread_id: %d\n", thread_id);
	return 0;
}

void odp_print_mem(void *addr, size_t size, const char *desc)
{
	uint8_t *start_ptr, *end_ptr, *ptr;
	int i;

	if (!size)
		return;

	if (desc)
		printf("\n%s (%u bytes)\n", desc, size);
	else
		printf("Dumping %u bytes at address 0x%08x\n",
		       size, (unsigned int)addr);

	start_ptr = addr;
	end_ptr = start_ptr + size;
	ptr = (typeof(ptr))(((uintptr_t)start_ptr) & ~0xF);

	while (ptr < end_ptr) {
		printf("0x%08x: ", (unsigned int)ptr);
		for (i = 0; i < 16; i++) {
			if (start_ptr <= ptr && ptr < end_ptr)
				printf("%02x ", *ptr);
			else
				printf("__ ");
			ptr++;
		}
		printf("\n");
	}
}

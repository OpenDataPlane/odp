/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_TI_MCSDK_H_
#define ODP_TI_MCSDK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <ti/csl/cslr_device.h>
#include <ti/runtime/hplib/hplib.h>
#include <ti/runtime/pktlib/pktlib.h>
#include <ti/drv/nwal/nwal.h>
#include <ti/drv/nwal/nwal_osal.h>
#include <mcsdk_tune.h>

/** @internal McSDK initialization configuration */
struct mcsdk_cfg_s {
	int def_mem_size;            /**<  Bytes of CMA memory we have allocated */
	int min_buf_headroom_size;   /**<  Minimal amount of headroom in a buffer */
	int def_max_descriptors;     /**<  Number of descriptors in system  (must be power of 2), 2^14 max */
	int def_tot_descriptors_for_us; /**<  Number of descriptors to create in our region (must be power of 2)*/
	int def_heap_n_descriptors;  /**<  Number of descriptor plus buffers in default heap*/
	int def_heap_n_zdescriptors; /**<  Number of zero len descriptors in defaut heap*/
	int def_heap_buf_size;       /**<  Size of buffers in default heap, max amount of area for packet data */
	int def_heap_tailroom_size;  /**<  Size of tailroom in reserve */
	int def_heap_extra_size;     /**<  Size of extra space at end of buffer */
	int def_multi_process;       /**<  Flag to indicate if NETAPI init is for multi-process environment */
};

Rm_ServiceHandle *rm_client_init(void);
int mcsdk_global_init(void);
int mcsdk_local_init(int thread_id);
int mcsdk_cppi_init(void);
int mcsdk_qmss_init(int max_descriptors);
int mcsdk_qmss_start(void);
int mcsdk_cppi_start(void);
int mcsdk_qmss_setup_memregion(uint32_t desc_num, uint32_t desc_size,
		uint32_t *desc_mem_base, Qmss_MemRegion mem_region);
int mcsdk_nwal_init(int region2use, Pktlib_HeapIfTable *p_table);
int mcsdk_nwal_start(Pktlib_HeapHandle pkt_heap,
		     Pktlib_HeapHandle cmd_rx_heap,
		     Pktlib_HeapHandle cmd_tx_heap);

extern Pktlib_HeapIfTable  pktlib_if_table;
extern hplib_virtualAddrInfo_T odp_vm_info;

#ifdef __cplusplus
}
#endif

#endif /* ODP_TI_MCSDK_H_ */

/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_STATE_H_
#define ODP_STATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_ti_mcsdk.h>

/**
 * @internal Global ODP state
 */
struct odp_global_s {
	struct mcsdk_cfg_s cfg; /**< McSDK configuration */
	struct {
		nwal_Inst         handle;     /**< NWAL handle */
		Pktlib_HeapHandle sa2pa_heap; /**< Internal SA->PA heap */
		Pktlib_HeapHandle pa2sa_heap; /**< Internal PA->SA head */
	} nwal;                 /**< Global NWAL state */
};

/** @internal Per process ODP state */
struct odp_proc_s {
	struct {
		Pktlib_HeapHandle netcp_heap;            /**< internal default heap */
		Pktlib_HeapHandle netcp_control_rx_heap; /**< rx control messages */
		Pktlib_HeapHandle netcp_control_tx_heap; /**< tx control messages */
	} nwal;                         /**< Per process NWAL state */
	Rm_ServiceHandle *rm_service;   /**< Resource Manager service handle */
};

/** @internal Per thread ODP state */
struct odp_local_s {
	struct {
		nwalLocCfg_t cfg;  /**< Local NWAL configuration */
	} nwal;              /**< thread NWAL state */
	int is_main_thread;  /**< Marks a main thread which run global init */
};

extern struct odp_global_s *odp_global;
extern struct odp_proc_s odp_proc;
extern __thread struct odp_local_s odp_local;

#ifdef __cplusplus
}
#endif

#endif /* ODP_STATE_H_ */

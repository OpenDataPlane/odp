/*
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, Texas Instruments Incorporated
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef MCSDK_TUNE_H_
#define MCSDK_TUNE_H_


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup tune_parameters
 * @def NETAPI_ENABLE_SECURITY
 *      Define this to enable securtiy.
 * @note Libraries using netapi need to be built with SA enabled
*/
#ifdef NWAL_ENABLE_SA
#define NETAPI_ENABLE_SECURITY
#endif

/**
 * @ingroup tune_parameters
 * @def NETAPI_USE_DDR
 *      Define this to enable use of cached DDR for buffers and descriptors.
 * @note Do not define if USE_MSMC defined below
*/
#define NETAPI_USE_DDR

/**
 * @ingroup tune_parameters
 * @def NETAPI_USE_MSMC
 *      Define this to enable use of un-cached MSMC for buffers and descriptors
 * @note Do not define if USE_DDR defined above
*/

#if defined(NETAPI_USE_MSMC) && defined(NETAPI_USE_DDR)
#error "only define NETAPI_USE_MSMC or NETAPI_USE_DDR"
#endif

/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_NUM_CORES
 *      This defines the number of cores (theads)
 */
#define TUNE_NETAPI_NUM_CORES 5

/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_PERM_MEM_SZ
 *      This defines how much contiguous memory to grab. This is used for
 *      descriptors and buffers in the case of uncached configuration only.
 *      descriptors and buffers.  Can't be bigger than  msmc if
 *      MSMC memory is being using uncached.
 */
#define TUNE_NETAPI_PERM_MEM_SZ   (2*1024*1024)

/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_DEFAULT_BUFFER_SIZE
 *      This defines the size of the netapi default pktlib heap buffers This
 *      can be set at @ref netapi_init
 */
#define TUNE_NETAPI_DEFAULT_BUFFER_SIZE 1600


/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_DEFAULT_NUM_BUFFERS
 *      This defines the number of netapi default pktlib heap buffers
 *      (and assoc descriptors) this can be set at @ref netapi_init
 */
#define TUNE_NETAPI_DEFAULT_NUM_BUFFERS  200

/**
 * @ingroup tune_parameters
 * @def  TUNE_NETAPI_QM_CONFIG_MAX_DESC_NUM
 *       Defines the number of of QM descriptors (total).
 * @note Must be a power or 2. 16384 is abs max.
 */
#define TUNE_NETAPI_QM_CONFIG_MAX_DESC_NUM  0x4000

/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_NUM_GLOBAL_DESC
 *      This defines the number of global descriptors.
 * @note Must be a power or 2
*/
#define TUNE_NETAPI_NUM_GLOBAL_DESC         TUNE_NETAPI_QM_CONFIG_MAX_DESC_NUM

/**
 * @ingroup tune_parameters
 * @def  TUNE_NETAPI_DESC_SIZE
 *      This defines the descriptor size
 * @note This define should NOT be changes
 */
#define TUNE_NETAPI_DESC_SIZE  128

#ifdef NETAPI_USE_DDR
/**
 * @ingroup tune_parameters
 * @def  TUNE_NETAPI_QM_START_INDEX
 *      This defines the queue manager start index
 * @note This must reflect what the kernel is uding for their region,
 *       see device tree blob for details.
 */
#define TUNE_NETAPI_QM_START_INDEX  0

/**
 * @ingroup tune_parameters
 * @def  TUNE_NETAPI_QM_GLOBAL_REGION
 *       This defines the queue manager global region
 * @note This must reflect what the kernel is using for their region,
 *       see device tree blob for details.
 */
#define TUNE_NETAPI_QM_GLOBAL_REGION 18

#else /* use msmc */
#define TUNE_NETAPI_QM_START_INDEX  0
#define  TUNE_NETAPI_QM_GLOBAL_REGION 0
#endif


/* NWAL internal config. Should not have to change */
#define TUNE_NETAPI_CONFIG_MAX_PA_TO_SA_DESC       32
#define TUNE_NETAPI_CONFIG_MAX_SA_TO_PA_DESC       200

/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_MAX_NUM_MAC
 *      This defines the number of logical mac addresses
 */
#define TUNE_NETAPI_MAX_NUM_MAC                64

/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_MAX_NUM_IP
 *      This defines the number of ip addresses
 */
#define TUNE_NETAPI_MAX_NUM_IP                 64

/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_MAX_NUM_PORTS_PER_CORE
 *      This defines the number of ports per core
 */
#define TUNE_NETAPI_MAX_NUM_PORTS_PER_CORE     4

/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_MAX_NUM_PORTS
 *      This defines the number maximum number of ports
 */
#define TUNE_NETAPI_MAX_NUM_PORTS	(TUNE_NETAPI_MAX_NUM_PORTS_PER_CORE * \
					 TUNE_NETAPI_NUM_CORES)

#ifdef NETAPI_ENABLE_SECURITY
/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS
 *      This defines the number maximum number of ipsec channels
 */
#define TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS     128
#else
/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS
 *      This defines the number maximum number of ipsec channels
 */
#define TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS     0
#endif

/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_MAX_NUM_L2_L3_HDRS
 *      This defines the number maximum number of L2_L3 headers to reserve
 *      in the nwal layer. This should be kept small as transport lib does not
 *      expose this nwal feature by default
 */
#define TUNE_NETAPI_MAX_NUM_L2_L3_HDRS         3

/**
 * @ingroup tune_parameters
 * @def TUNE_NETAPI_MAX_NUM_TRANS
 *      This defines the number maximum number of transactions with NETCP that
 *      can be outstanding at any one time
 */
#define TUNE_NETAPI_MAX_NUM_TRANS (TUNE_NETAPI_MAX_NUM_MAC + \
				   TUNE_NETAPI_MAX_NUM_IP + \
				   TUNE_NETAPI_MAX_NUM_PORTS + \
				   TUNE_NETAPI_MAX_NUM_IPSEC_CHANNELS)

/* PA control buffer pool (internal) */
#define TUNE_NETAPI_CONFIG_MAX_CTL_RXTX_BUF_SIZE 520
#define TUNE_NETAPI_CONFIG_NUM_CTL_RX_BUF  16
#define TUNE_NETAPI_CONFIG_NUM_CTL_TX_BUF  16


#ifdef __cplusplus
}
#endif

#endif /* MCSDK_TUNE_H_ */

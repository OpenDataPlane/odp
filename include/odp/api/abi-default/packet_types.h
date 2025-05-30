/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_ABI_PACKET_TYPES_H_
#define ODP_ABI_PACKET_TYPES_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_packet_t;

/** @internal Dummy  type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_packet_seg_t;

/** @internal Dummy  type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_packet_buf_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_packet_vector_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_packet_tx_compl_t;

/** @addtogroup odp_packet
 *  @{
 */

typedef _odp_abi_packet_t *odp_packet_t;
typedef _odp_abi_packet_seg_t *odp_packet_seg_t;
typedef _odp_abi_packet_buf_t *odp_packet_buf_t;
typedef _odp_abi_packet_vector_t *odp_packet_vector_t;
typedef _odp_abi_packet_tx_compl_t *odp_packet_tx_compl_t;

#define ODP_PACKET_INVALID        ((odp_packet_t)0)
#define ODP_PACKET_SEG_INVALID    ((odp_packet_seg_t)0)
#define ODP_PACKET_BUF_INVALID    ((odp_packet_buf_t)0)
#define ODP_PACKET_OFFSET_INVALID 0xffff
#define ODP_PACKET_VECTOR_INVALID   ((odp_packet_vector_t)0)
#define ODP_PACKET_TX_COMPL_INVALID ((odp_packet_tx_compl_t)0)

typedef enum {
	ODP_PACKET_GREEN = 0,
	ODP_PACKET_YELLOW = 1,
	ODP_PACKET_RED = 2,
	ODP_PACKET_ALL_COLORS = 3,
} odp_packet_color_t;

typedef enum {
	ODP_PACKET_CHKSUM_UNKNOWN = 0,
	ODP_PACKET_CHKSUM_BAD,
	ODP_PACKET_CHKSUM_OK
} odp_packet_chksum_status_t;


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

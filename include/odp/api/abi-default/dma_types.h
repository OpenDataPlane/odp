/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_ABI_DMA_TYPES_H_
#define ODP_ABI_DMA_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_dma_t;

/** @internal Dummy type for strong typing */
typedef struct { char dummy; /**< @internal Dummy */ } _odp_abi_dma_compl_t;

/** @addtogroup odp_dma
 *  @{
 */

typedef _odp_abi_dma_t *odp_dma_t;

#define ODP_DMA_INVALID  ((odp_dma_t)0)

typedef _odp_abi_dma_t *odp_dma_compl_t;

#define ODP_DMA_COMPL_INVALID  ((odp_dma_compl_t)0)

typedef uint64_t odp_dma_transfer_id_t;

#define ODP_DMA_TRANSFER_ID_INVALID ((odp_dma_transfer_id_t)0)

#define ODP_DMA_NAME_LEN  32

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

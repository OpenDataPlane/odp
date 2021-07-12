/* Copyright (c) 2021, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_API_ABI_DMA_H_
#define ODP_API_ABI_DMA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>

/** @ingroup odp_dma
 *  @{
 */

typedef ODP_HANDLE_T(odp_dma_t);

#define ODP_DMA_INVALID _odp_cast_scalar(odp_dma_t, 0)

typedef ODP_HANDLE_T(odp_dma_transfer_id_t);

#define ODP_DMA_TRANSFER_ID_INVALID _odp_cast_scalar(odp_dma_transfer_id_t, 0)

#define ODP_DMA_NAME_LEN 32

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

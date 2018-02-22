/* Copyright (c) 2018-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 */

#ifndef ODP_PLAT_PKTIO_INLINES_API_H_
#define ODP_PLAT_PKTIO_INLINES_API_H_

#ifdef __cplusplus
extern "C" {
#endif

_ODP_INLINE int odp_pktio_index(odp_pktio_t pktio)
{
	return _odp_pktio_index(pktio);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

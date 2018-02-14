/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PLAT_PKTIO_INLINES_H_
#define ODP_PLAT_PKTIO_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

static inline int _odp_pktio_index(odp_pktio_t pktio)
{
	return (int)(uintptr_t)pktio - 1;
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif

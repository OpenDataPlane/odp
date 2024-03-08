/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2022 Nokia
 */

/**
 * @file
 *
 * ODP IPsec platform specific types
 */

#ifndef ODP_API_ABI_IPSEC_TYPES_H_
#define ODP_API_ABI_IPSEC_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

#include <odp/api/plat/strong_types.h>

/** @addtogroup odp_ipsec
 *  @{
 */

typedef ODP_HANDLE_T(odp_ipsec_sa_t);

#define ODP_IPSEC_SA_INVALID _odp_cast_scalar(odp_ipsec_sa_t, 0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

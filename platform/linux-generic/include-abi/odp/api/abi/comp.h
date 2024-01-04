/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_ABI_COMP_H_
#define ODP_ABI_COMP_H_

#include <odp/api/plat/strong_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/** @addtogroup odp_compression
 *  @{
 */

typedef ODP_HANDLE_T(odp_comp_session_t);

#define ODP_COMP_SESSION_INVALID _odp_cast_scalar(odp_comp_session_t, 0)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

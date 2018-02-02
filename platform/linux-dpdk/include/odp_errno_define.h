/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP error number define
 */

#ifndef ODP_ERRNO_DEFINE_H_
#define ODP_ERRNO_DEFINE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_errno.h>

#define __odp_errno (rte_errno)

#ifdef __cplusplus
}
#endif

#endif

/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ODP_DEFAULT_CPU_H_
#define ODP_DEFAULT_CPU_H_

/******************************************************************************
 * Atomics
 *****************************************************************************/

#define atomic_store_release(loc, val, ro) \
	__atomic_store_n(loc, val, __ATOMIC_RELEASE)

#include "odp_cpu_idling.h"

#endif

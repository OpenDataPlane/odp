/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <odp_module.h>

#define SUBSYSTEM_VERSION 0x00010000UL
ODP_SUBSYSTEM_DEFINE(pool, "memory pool public APIs", SUBSYSTEM_VERSION);

ODP_SUBSYSTEM_CONSTRUCTOR(pool)
{
	odp_subsystem_constructor(pool);
}


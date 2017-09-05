/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#include <odp_module.h>
#include <odp_queue_subsystem.h>

ODP_SUBSYSTEM_DEFINE(queue, "queue public APIs", QUEUE_SUBSYSTEM_VERSION);

ODP_SUBSYSTEM_CONSTRUCTOR(queue)
{
	odp_subsystem_constructor(queue);
}

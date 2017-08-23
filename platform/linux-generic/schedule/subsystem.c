/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Internal header files */
#include <odp_module.h>
#include <odp_schedule_subsystem.h>

ODP_SUBSYSTEM_DEFINE(schedule, "schedule public APIs",
		     SCHEDULE_SUBSYSTEM_VERSION);

ODP_SUBSYSTEM_CONSTRUCTOR(schedule)
{
	odp_subsystem_constructor(schedule);
}

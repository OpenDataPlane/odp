/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <subsystem/spec/packet_subsystem.h>
#include <odp_module.h>

ODP_SUBSYSTEM_DEFINE(packet, "packet public APIs",
		     PACKET_SUBSYSTEM_VERSION);

ODP_SUBSYSTEM_CONSTRUCTOR(packet)
{
	odp_subsystem_constructor(packet);
}


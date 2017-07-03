/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <odp_packet_io_internal.h>

#define SUBSYSTEM_VERSION 0x00010000UL
SUBSYSTEM(pktio_ops, "packet IO operations", SUBSYSTEM_VERSION);

SUBSYSTEM_CONSTRUCTOR(pktio_ops)
{
        subsystem_constructor(pktio_ops);

        /* Further initialization per subsystem */
}

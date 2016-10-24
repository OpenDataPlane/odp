/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PLAT_PACKET_FLAGS_H_
#define ODP_PLAT_PACKET_FLAGS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/event_types.h>
#include <odp/api/plat/packet_io_types.h>
#include <odp/api/plat/packet_types.h>
#include <odp/api/plat/buffer_types.h>
#include <odp/api/plat/pool_types.h>

/** @ingroup odp_packet
 *  @{
 */

#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 0
#include <odp/api/plat/packet_flags_inlines.h>
#endif

/**
 * @}
 */

#include <odp/api/spec/packet_flags.h>

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_PACKET_FLAGS_H_ */

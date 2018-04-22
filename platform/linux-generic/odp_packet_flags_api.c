/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp/api/plat/packet_flag_inlines.h>
#include <odp/api/packet_flags.h>
#include <odp_packet_internal.h>

/* Include non-inlined versions of API functions */
#undef _ODP_INLINE
#define _ODP_INLINE
#include <odp/api/plat/packet_flag_inlines_api.h>

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 */

#include <odp/api/packet.h>

/* Prevent this header from being included again later */
#include <odp/api/plat/packet_io_inlines.h>

/* Include non-inlined versions of API functions */
#define _ODP_NO_INLINE
#include <odp/api/plat/packet_inlines.h>
#include <odp/api/plat/packet_vector_inlines.h>

/* Copyright (c) 2013-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp/api/ticketlock.h>

#include <odp/api/plat/ticketlock_inlines.h>

/* Include non-inlined versions of API functions */
#undef _ODP_INLINE
#define _ODP_INLINE
#include <odp/api/plat/ticketlock_inlines_api.h>

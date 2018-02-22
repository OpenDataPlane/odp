/* Copyright (c) 2018-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp/api/thread.h>
#include <odp/api/cpu.h>
#include <odp/api/plat/thread_inlines.h>

/* Include non-inlined versions of API functions */
#define _ODP_INLINE
#include <odp/api/plat/thread_inlines_api.h>

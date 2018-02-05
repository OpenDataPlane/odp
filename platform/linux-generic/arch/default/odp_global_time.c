/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_posix_extensions.h>

#include <stdlib.h>
#include <time.h>

#include <odp/api/cpu.h>
#include <odp/api/hints.h>
#include <odp/api/system_info.h>
#include <odp_debug_internal.h>
#include <odp_time_internal.h>

int cpu_has_global_time(void)
{
	return 0;
}

uint64_t cpu_global_time(void)
{
	return 0;
}

uint64_t cpu_global_time_freq(void)
{
	return 0;
}

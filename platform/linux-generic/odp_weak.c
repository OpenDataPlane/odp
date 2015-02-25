/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_internal.h>
#include <odp/debug.h>
#include <odp_debug_internal.h>
#include <odp/hints.h>

#include <stdarg.h>

ODP_WEAK_SYMBOL ODP_PRINTF_FORMAT(2, 3)
int odp_override_log(odp_log_level_e level ODP_UNUSED, const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vfprintf(stderr, fmt, args);
	va_end(args);

	return r;
}

ODP_WEAK_SYMBOL void odp_override_abort(void)
{
	abort();
}

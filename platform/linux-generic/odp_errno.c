/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp/api/errno.h>
#include <string.h>
#include <stdio.h>
#include <odp_debug_internal.h>

__thread int _odp_errno;

int odp_errno(void)
{
	return _odp_errno;
}

void odp_errno_zero(void)
{
	_odp_errno = 0;
}

void odp_errno_print(const char *str)
{
	if (str != NULL)
		_ODP_PRINT("%s %s\n", str, strerror(_odp_errno));
	else
		_ODP_PRINT("%s\n", strerror(_odp_errno));
}

const char *odp_errno_str(int errnum)
{
	return strerror(errnum);
}

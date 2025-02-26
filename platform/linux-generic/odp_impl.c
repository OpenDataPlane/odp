/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 */

#include <odp/autoheader_internal.h>
#include <odp/api/version.h>

const char *odp_version_impl_str(void)
{
	return _ODP_IMPLEMENTATION_NAME "-"
		ODP_VERSION_TO_STR(ODP_VERSION_BUILD)
		_ODP_GIT_REVISION;
}

const char *odp_version_impl_name(void)
{
	return _ODP_IMPLEMENTATION_NAME;
}

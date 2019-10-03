/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/autoheader_internal.h>
#include <odp/api/version.h>

#define ODP_VERSION_IMPL 0
#define ODP_VERSION_IMPL_STR \
	_ODP_IMPLEMENTATION_NAME " " \
	ODP_VERSION_TO_STR(ODP_VERSION_API_GENERATION) "." \
	ODP_VERSION_TO_STR(ODP_VERSION_API_MAJOR) "." \
	ODP_VERSION_TO_STR(ODP_VERSION_API_MINOR) "-" \
	ODP_VERSION_TO_STR(ODP_VERSION_IMPL) " (v" \
	ODP_VERSION_TO_STR(ODP_VERSION_API_GENERATION) "." \
	ODP_VERSION_TO_STR(ODP_VERSION_API_MAJOR) "." \
	ODP_VERSION_TO_STR(ODP_VERSION_API_MINOR) ") " \
	ODP_VERSION_TO_STR(ODP_VERSION_BUILD)

const char *odp_version_impl_str(void)
{
	return ODP_VERSION_IMPL_STR;
}

const char *odp_version_impl_name(void)
{
	return _ODP_IMPLEMENTATION_NAME;
}

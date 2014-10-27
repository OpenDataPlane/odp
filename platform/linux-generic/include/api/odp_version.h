/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP version
 */

#ifndef ODP_VERSION_H_
#define ODP_VERSION_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_ver_abt_log_dbg ODP LOGGING / ABORT / VERSION / DEBUG
 *  @{
 */

/**
 * ODP API generation version
 *
 * Introduction of major new features or changes that make
 * very significant changes to the API. APIs with different
 * versions are likely not backward compatible.
 */
#define ODP_VERSION_API_GENERATION 0

/**
 * ODP API major version
 *
 * Introduction of major new features or changes. APIs with different major
 * versions are likely not backward compatible.
 */
#define ODP_VERSION_API_MAJOR 3

/**
 * ODP API minor version
 * Minor version is incremented when introducing backward compatible changes
 * to the API.
 * For an API with common generation and major version, but with different
 * minor numbers the two versions are backward compatible.
 * Changes to the test suite will increment this digit.
 * Changes to linux-generic will not increment this digit.
 */
#define ODP_VERSION_API_MINOR 0

/** @internal Version string expand */
#define ODP_VERSION_STR_EXPAND(x)  #x

/** @internal Version to string */
#define ODP_VERSION_TO_STR(x)      ODP_VERSION_STR_EXPAND(x)

/** @internal API version string */
#define ODP_VERSION_API_STR \
ODP_VERSION_TO_STR(ODP_VERSION_API_GENERATION) "."\
ODP_VERSION_TO_STR(ODP_VERSION_API_MAJOR) "."\
ODP_VERSION_TO_STR(ODP_VERSION_API_MINOR)

/**
 * Returns ODP API version string
 */
static inline const char *odp_version_api_str(void)
{
	return ODP_VERSION_API_STR;
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

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
 * ODP API main version
 *
 * Introduction of major new features or changes. APIs with different major
 * versions are likely not backward compatible.
 */
#define ODP_VERSION_API_MAIN  0

/**
 * ODP API sub version
 *
 * Introduction of additional features or minor changes. APIs with common
 * major version and different sub versions may be backward compatible (if only
 * additions).
 */
#define ODP_VERSION_API_SUB   0

/**
 * ODP API bug correction version
 *
 * Bug corrections to the API files. APIs with the same major and sub
 * versions, but different bug correction versions are backward compatible.
 */
#define ODP_VERSION_API_BUG   1


/** @internal Version string expand */
#define ODP_VERSION_STR_EXPAND(x)  #x

/** @internal Version to string */
#define ODP_VERSION_TO_STR(x)      ODP_VERSION_STR_EXPAND(x)

/** @internal API version string */
#define ODP_VERSION_API_STR \
ODP_VERSION_TO_STR(ODP_VERSION_API_MAIN) "."\
ODP_VERSION_TO_STR(ODP_VERSION_API_SUB) "."\
ODP_VERSION_TO_STR(ODP_VERSION_API_BUG)


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

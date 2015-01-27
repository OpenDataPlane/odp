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
#define ODP_VERSION_API_MAJOR 9

/**
 * ODP API minor version
 *
 * Minor version is incremented when introducing backward compatible changes
 * to the API. For an API with common generation and major version, but with
 * different minor numbers the two versions are backward compatible.
 */
#define ODP_VERSION_API_MINOR 0

/**
 * Returns ODP API version string
 */
const char *odp_version_api_str(void);


/**
 * Returns ODP implementation version string
 *
 * Every implementation of ODP may receive bug fixes independent of the version
 * of the API changing, this function returns that indication string.
 * @note This string is implementation specific.
 * @sa odp_version_api_str()
 *
 * @return null terminated implementation specific version identifier string
  */
const char *odp_version_impl_str(void);
/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

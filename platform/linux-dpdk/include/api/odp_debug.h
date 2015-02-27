/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
/**
 * @file
 *
 * ODP debug
 */

#ifndef ODP_DEBUG_H_
#define ODP_DEBUG_H_


#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_ver_abt_log_dbg
 *  Macros that allows different messages.
 *  @{
 */

#ifdef __GNUC__


#if __GNUC__ < 4 || (__GNUC__ == 4 && (__GNUC_MINOR__ < 6))

/**
 * _Static_assert was only added in GCC 4.6. Provide a weak replacement
 * for previous versions.
 */
#define _Static_assert(e, s) extern int (*static_assert_checker (void)) \
	[sizeof (struct { unsigned int error_if_negative: (e) ? 1 : -1; })]

#endif



#endif


/**
 * Compile time assertion-macro - fail compilation if cond is false.
 * @note This macro has zero runtime overhead
 */
#define _ODP_STATIC_ASSERT(cond, msg)  _Static_assert(1, msg)

/**
 * ODP log level.
 */
typedef enum odp_log_level {
	ODP_LOG_DBG,
	ODP_LOG_ERR,
	ODP_LOG_UNIMPLEMENTED,
	ODP_LOG_ABORT,
	ODP_LOG_PRINT
} odp_log_level_e;

/**
 * ODP log function
 *
 * Instead of direct prints to stdout/stderr all logging in ODP implementation
 * should be done via this function or its wrappers.
 * ODP platform MUST provide a default *weak* implementation of this function.
 * Application MAY override the function if needed by providing a strong
 * function.
 *
 * @param[in] level   Log level
 * @param[in] fmt     printf-style message format
 *
 * @return The number of characters logged if succeeded. Otherwise returns
 *         a negative number.
 */
extern int odp_override_log(odp_log_level_e level, const char *fmt, ...);



/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

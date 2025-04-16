/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2020-2023 Nokia
 */

/**
 * @file
 *
 * ODP Debug inlines
 *
 * @warning These definitions are not part of ODP API, they are for
 * implementation internal use only.
 */

#ifndef ODP_DEBUG_INLINES_H_
#define ODP_DEBUG_INLINES_H_

#include <odp/autoheader_external.h>

#include <odp/api/hints.h>
#include <odp/api/init.h>

#include <odp/api/plat/thread_inline_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#pragma GCC diagnostic push

#ifdef __clang__
#pragma GCC diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

extern odp_log_func_t _odp_log_fn;
extern odp_abort_func_t _odp_abort_fn;

static inline odp_log_func_t _odp_log_fn_get(void)
{
	if (_odp_this_thread && _odp_this_thread->log_fn)
		return _odp_this_thread->log_fn;

	return _odp_log_fn;
}

#define _ODP_LOG_FN(level, ...) \
	do { \
		_odp_log_fn_get()(level, ##__VA_ARGS__); \
	} while (0)

/**
 * ODP LOG macro.
 */
#define _ODP_LOG(level, prefix, fmt, ...) \
		 _ODP_LOG_FN(level, "%s: %s:%d:%s(): " fmt, prefix, \
			     __FILE__, __LINE__, __func__, ##__VA_ARGS__)

/**
 * Runtime assertion-macro - aborts if 'cond' is false.
 */
#define _ODP_ASSERT(cond) \
	do { if ((ODP_DEBUG == 1) && (!(cond))) { \
		_ODP_ERR("%s\n", #cond); \
		_odp_abort_fn(); } \
	} while (0)

/*
 * Print debug message to log, if ODP_DEBUG_PRINT flag is set (ignores CONFIG_DEBUG_LEVEL).
 */
#define _ODP_DBG(...) \
	do { \
		if (ODP_DEBUG_PRINT == 1) \
			__extension__ ({ \
				_ODP_LOG(ODP_LOG_DBG, "DBG", ##__VA_ARGS__); \
			}); \
	} while (0)

/**
 * Log warning message.
 */
#define _ODP_WARN(...) \
	do { \
		__extension__ ({ \
			_ODP_LOG(ODP_LOG_WARN, "WARN", ##__VA_ARGS__); \
		}); \
	} while (0)

/**
 * Log error message.
 */
#define _ODP_ERR(...) \
	do { \
		__extension__ ({ \
			_ODP_LOG(ODP_LOG_ERR, "ERR", ##__VA_ARGS__); \
		}); \
	} while (0)

/**
 * Log abort message and then stop execution (by default call abort()).
 * This function should not return.
 */
#define _ODP_ABORT(...) \
	do { \
		__extension__ ({ \
			_ODP_LOG(ODP_LOG_ABORT, "ABORT", ##__VA_ARGS__); \
		}); \
		_odp_abort_fn(); \
	} while (0)

/**
 * Log print message when the application calls one of the ODP APIs
 * specifically for dumping internal data.
 */
#define _ODP_PRINT(...) \
	_ODP_LOG_FN(ODP_LOG_PRINT, ##__VA_ARGS__)

#pragma GCC diagnostic pop

#ifdef __cplusplus
}
#endif

/** @endcond */

#endif

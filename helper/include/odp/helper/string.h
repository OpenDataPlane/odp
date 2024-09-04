/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Nokia
 */

/**
 * @file
 *
 * ODP string helper
 */

#ifndef ODPH_STRING_H_
#define ODPH_STRING_H_

#include <odp/api/hints.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odph_string ODPH STRING
 * String helper
 *
 * @{
 */

/**
 * Copy a string
 *
 * Like strncpy(), but additionally ensures that the destination string is null
 * terminated, unless sz is zero in which case returns dst without doing
 * anything else.
 *
 * @param[out] dst Pointer to destination string.
 * @param src Pointer to source string.
 * @param sz Destination size.
 * @return Pointer to destination string.
 */
#ifdef __cplusplus
ODP_UNUSED static char *odph_strcpy(char *dst, const char *src, size_t sz)
#else
ODP_UNUSED static char *odph_strcpy(char *restrict dst, const char *restrict src, size_t sz)
#endif
{
	if (!sz)
		return dst;

#pragma GCC diagnostic push
#if __GNUC__ >= 8
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
	strncpy(dst, src, sz - 1);
#pragma GCC diagnostic pop
	dst[sz - 1] = 0;
	return dst;
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

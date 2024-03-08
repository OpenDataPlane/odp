/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Nokia
 */

#ifndef ODP_STRING_INTERNAL_H_
#define ODP_STRING_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/* Helps with snprintf() return value checking
 *
 * Otherwise like snprintf(), but returns always the number of characters
 * printed (without the end mark) or zero on error. Terminates the string
 * always with the end mark. */
int _odp_snprint(char *str, size_t size, const char *format, ...);

/*
 * Copy a string
 *
 * Like strncpy(), but additionally ensures that the destination string is null
 * terminated, unless sz is zero in which case returns dst without doing
 * anything else.
 */
char *_odp_strcpy(char *restrict dst, const char *restrict src, size_t sz);

#ifdef __cplusplus
}
#endif

#endif

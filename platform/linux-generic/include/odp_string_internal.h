/* Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
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

#ifdef __cplusplus
}
#endif

#endif

/* Copyright (c) 2022, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PRINT_INTERNAL_H_
#define ODP_PRINT_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

int _odp_snprint(char *str, size_t size, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif

/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _STR_FUNCTIONS_INTERNAL_H
#define _STR_FUNCTIONS_INTERNAL_H

#include <string.h>
#include <odp_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t _odp_str_to_size(const char *str);
int _odp_strsplit(char *string, int stringlen,
		  char **tokens, int maxtokens, char delim);

#ifdef __cplusplus
}
#endif

#endif

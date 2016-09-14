/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 */

#include <odp_posix_extensions.h>

#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <_str_functions_internal.h>
#include <odp/api/align.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <ctype.h>

/*
 * split string into tokens. largely "inspired" by dpdk:
 * lib/librte_eal/common/eal_common_string_fns.c: rte_strsplit
 */
int _odp_strsplit(char *string, int stringlen,
		  char **tokens, int maxtokens, char delim)
{
	int i, tok = 0;
	int tokstart = 1; /* first token is right at start of string */

	if (string == NULL || tokens == NULL)
		return -1;

	for (i = 0; i < stringlen; i++) {
		if (string[i] == '\0' || tok >= maxtokens)
			break;
		if (tokstart) {
			tokstart = 0;
			tokens[tok++] = &string[i];
		}
		if (string[i] == delim) {
			string[i] = '\0';
			tokstart = 1;
		}
	}
	return tok;
}

/*
 * Converts a numeric string to the equivalent uint64_t value.
 * As well as straight number conversion, also recognises the suffixes
 * k, m and g for kilobytes, megabytes and gigabytes respectively.
 *
 * If a negative number is passed in  i.e. a string with the first non-black
 * character being "-", zero is returned. Zero is also returned in the case of
 * an error with the strtoull call in the function.
 * largely "inspired" by dpdk:
 * lib/librte_eal/common/include/rte_common.h: rte_str_to_size
 *
 * param str
 *     String containing number to convert.
 * return
 *     Number.
 */
uint64_t _odp_str_to_size(const char *str)
{
	char *endptr;
	unsigned long long size;

	while (isspace((int)*str))
		str++;
	if (*str == '-')
		return 0;

	errno = 0;
	size = strtoull(str, &endptr, 0);
	if (errno)
		return 0;

	if (*endptr == ' ')
		endptr++; /* allow 1 space gap */

	switch (*endptr) {
	case 'G':
	case 'g':
		size *= 1024; /* fall-through */
	case 'M':
	case 'm':
		size *= 1024; /* fall-through */
	case 'K':
	case 'k':
		size *= 1024; /* fall-through */
	default:
		break;
	}
	return size;
}

/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>
#include <stdint.h>
#include <stdlib.h>
#include <odp/api/random.h>
#include <odp/api/cpu.h>
#include <odp_init_internal.h>

#include <time.h>

odp_random_kind_t odp_random_max_kind(void)
{
	return ODP_RANDOM_BASIC;
}

static int32_t _random_data(uint8_t *buf, uint32_t len, uint32_t *seed)
{
	union {
		uint32_t rand_word;
		uint8_t rand_byte[4];
	} u;
	uint32_t i = 0, j;

	while (i < len) {
		u.rand_word = rand_r(seed);

		for (j = 0; j < 4 && i < len; j++, i++)
			*buf++ = u.rand_byte[j];
	}

	return len;
}

int32_t odp_random_test_data(uint8_t *buf, uint32_t len, uint64_t *seed)
{
	uint32_t seed32 = (*seed) & 0xffffffff;

	_random_data(buf, len, &seed32);

	*seed = seed32;
	return len;
}

static __thread uint32_t this_seed;

int32_t odp_random_data(uint8_t *buf, uint32_t len, odp_random_kind_t kind)
{
	if (kind != ODP_RANDOM_BASIC)
		return -1;

	return _random_data(buf, len, &this_seed);
}

int _odp_random_init_local(void)
{
	this_seed = time(NULL);
	this_seed ^= odp_cpu_id() << 16;

	return 0;
}

int _odp_random_term_local(void)
{
	return 0;
}

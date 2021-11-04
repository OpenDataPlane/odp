/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>
#include <stdint.h>
#include <stdlib.h>
#include <odp/api/byteorder.h>
#include <odp/api/cpu.h>
#include <odp/api/debug.h>
#include <odp_init_internal.h>
#include <odp_random_std_internal.h>

#include <time.h>

/* Assume at least two rand bytes are available and RAND_MAX is power of two - 1 */
ODP_STATIC_ASSERT(RAND_MAX >= UINT16_MAX, "RAND_MAX too small");
ODP_STATIC_ASSERT((RAND_MAX & (RAND_MAX + 1ULL))  ==  0, "RAND_MAX not power of two - 1");

static int32_t _random_data(uint8_t *buf, uint32_t len, uint32_t *seed)
{
	union {
		uint32_t rand_word;
		uint8_t rand_byte[4];
	} u;
	uint32_t i = 0, j, k;

	while (i < len) {
		u.rand_word = rand_r(seed);

		/* Use two least significant bytes */
		j = ODP_LITTLE_ENDIAN ? 0 : 2;
		for (k = 0; k < 2 && i < len; i++, j++, k++)
			*buf++ = u.rand_byte[j];
	}

	return len;
}

int32_t _odp_random_std_test_data(uint8_t *buf, uint32_t len, uint64_t *seed)
{
	uint32_t seed32 = (*seed) & 0xffffffff;

	_random_data(buf, len, &seed32);

	*seed = seed32;
	return len;
}

static __thread uint32_t this_seed;

int32_t _odp_random_std_data(uint8_t *buf, uint32_t len)
{
	return _random_data(buf, len, &this_seed);
}

int _odp_random_std_init_local(void)
{
	this_seed = time(NULL);
	this_seed ^= odp_cpu_id() << 16;

	return 0;
}

int _odp_random_std_term_local(void)
{
	return 0;
}

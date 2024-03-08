/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

/*
 * These functions implement ODP_RANDOM_CRYPTO random data using rdrand [1],
 * and ODP_RANDOM_TRUE random data using rdseed [1], via compiler builtin
 * functions.
 *
 * Note that there may be issues with the quality or security of rdrand and
 * rdseed. [2]
 *
 * [1] Intel Digital Random Number Generator (DRNG) Software Implementation
 *     Guide. John P Mechalas, 17 October 2018.
 *     https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html
 *
 * [2] RDRAND. Wikipedia, 29 September 2021.
 *     https://en.wikipedia.org/wiki/RDRAND#Reception
 */

#ifndef ODP_X86_RANDOM_H_
#define ODP_X86_RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/spec/random.h>

#include <stdint.h>

odp_random_kind_t _odp_random_max_kind_generic(void);
int32_t _odp_random_true_data_generic(uint8_t *buf, uint32_t len);
int32_t _odp_random_crypto_data_generic(uint8_t *buf, uint32_t len);

#ifdef __RDRND__

static inline int _odp_random_max_kind(void)
{
#ifdef __RDSEED__
	return ODP_RANDOM_TRUE;
#else
	return ODP_RANDOM_CRYPTO;
#endif
}

#else

static inline int _odp_random_max_kind(void)
{
	return _odp_random_max_kind_generic();
}

#endif

#ifdef __RDSEED__

static inline int32_t _odp_random_true_data(uint8_t *buf, uint32_t len)
{
#ifdef __x86_64__
	for (uint32_t i = 0; i < len / 8; i++) {
		while (!__builtin_ia32_rdseed_di_step((unsigned long long *)buf))
			;
		buf += 8;
	}

	if (len & 4) {
		while (!__builtin_ia32_rdseed_si_step((unsigned int *)buf))
			;
		buf += 4;
	}
#else
	for (uint32_t i = 0; i < len / 4; i++) {
		while (!__builtin_ia32_rdseed_si_step((unsigned int *)buf))
			;
		buf += 4;
	}
#endif
	if (len & 2) {
		while (!__builtin_ia32_rdseed_hi_step((unsigned short int *)buf))
			;
		buf += 2;
	}

	if (len & 1) {
		uint16_t w;

		while (!__builtin_ia32_rdseed_hi_step(&w))
			;
		*((uint8_t *)buf) = w & 0xff;
	}

	return len;
}

#else

static inline int32_t _odp_random_true_data(uint8_t *buf, uint32_t len)
{
	return _odp_random_true_data_generic(buf, len);
}

#endif

#ifdef __RDRND__

static inline int32_t _odp_random_crypto_data(uint8_t *buf, uint32_t len)
{
#ifdef __x86_64__
	for (uint32_t i = 0; i < len / 8; i++) {
		while (!__builtin_ia32_rdrand64_step((unsigned long long *)buf))
			;
		buf += 8;
	}

	if (len & 4) {
		while (!__builtin_ia32_rdrand32_step((unsigned int *)buf))
			;
		buf += 4;
	}
#else
	for (uint32_t i = 0; i < len / 4; i++) {
		while (!__builtin_ia32_rdrand32_step((unsigned int *)buf))
			;
		buf += 4;
	}
#endif
	if (len & 2) {
		while (!__builtin_ia32_rdrand16_step((unsigned short int *)buf))
			;
		buf += 2;
	}

	if (len & 1) {
		uint16_t w;

		while (!__builtin_ia32_rdrand16_step(&w))
			;
		*((uint8_t *)buf) = w & 0xff;
	}

	return len;
}

#else

static inline int32_t _odp_random_crypto_data(uint8_t *buf, uint32_t len)
{
	return _odp_random_crypto_data_generic(buf, len);
}

#endif

#ifdef __cplusplus
}
#endif

#endif

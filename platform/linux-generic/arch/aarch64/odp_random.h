/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ARM Limited
 */

#ifndef ODP_AARCH64_RANDOM_H_
#define ODP_AARCH64_RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/spec/random.h>
#include <odp/autoheader_internal.h>

#include <stdint.h>

odp_random_kind_t _odp_random_max_kind_generic(void);
int32_t _odp_random_true_data_generic(uint8_t *buf, uint32_t len);
int32_t _odp_random_crypto_data_generic(uint8_t *buf, uint32_t len);

#ifdef __ARM_FEATURE_RNG

#if __ARM_FEATURE_UNALIGNED != 1
#error This implementation requires unaligned access
#endif

static inline int _odp_random_max_kind(void)
{
	return ODP_RANDOM_TRUE;
}

static inline int _odp_rndr(uint64_t *v)
{
	int pass;

	/* Return a 64-bit random number which is reseeded from the True Random
	 * Number source. If the hardware returns a genuine random number,
	 * PSTATE.NZCV is set to 0b0000. The NZCV condition flag is checked via
	 * the CSET instruction. If the hardware cannot return a genuine random
	 * number in a reasonable period of time, PSTATE.NZCV is set to 0b0100
	 * and the data value returned is 0. */
	__asm__ volatile("mrs   %0, s3_3_c2_c4_0\n\t"
			 "cset  %w[pass], ne"
			 : "=r" (*v), [pass] "=r" (pass)
			 :
			 : "cc");

	return pass;
}

static inline int _odp_rndrrs(uint64_t *v)
{
	int pass;

	/* Return a 64-bit random number which is reseeded from the True Random
	 * Number source immediately before the read of the random number.
	 * If the hardware returns a genuine random number, PSTATE.NZCV is
	 * set to 0b0000. The NZCV condition flag is checked via the CSET
	 * instruction. If the hardware cannot return a genuine random number
	 * in a reasonable period of time, PSTATE.NZCV is set to 0b0100 and the
	 * data value returned is 0. */
	__asm__ volatile("mrs   %0, s3_3_c2_c4_1\n\t"
			 "cset  %w[pass], ne"
			 : "=r" (*v), [pass] "=r" (pass)
			 :
			 : "cc");

	return pass;
}

static inline int32_t _odp_random_crypto_data(uint8_t *buf, uint32_t len)
{
	uint64_t temp;

	for (uint32_t i = 0; i < len / 8; i++) {
		while (!_odp_rndr(&temp))
			;

		*(uint64_t *)(uintptr_t)buf = temp;
		buf += 8;
	}

	if (len & 7) {
		while (!_odp_rndr(&temp))
			;

		if (len & 4) {
			*(uint32_t *)(uintptr_t)buf = temp & 0xffffffff;
			temp >>= 32;
			buf += 4;
		}

		if (len & 2) {
			*(uint16_t *)(uintptr_t)buf = temp & 0xffff;
			temp >>= 16;
			buf += 2;
		}

		if (len & 1)
			*buf = temp & 0xff;
	}

	return len;
}

static inline int32_t _odp_random_true_data(uint8_t *buf, uint32_t len)
{
	uint64_t temp;

	for (uint32_t i = 0; i < len / 8; i++) {
		while (!_odp_rndrrs(&temp))
			;

		*(uint64_t *)(uintptr_t)buf = temp;
		buf += 8;
	}

	if (len & 7) {
		while (!_odp_rndrrs(&temp))
			;

		if (len & 4) {
			*(uint32_t *)(uintptr_t)buf = temp & 0xffffffff;
			temp >>= 32;
			buf += 4;
		}

		if (len & 2) {
			*(uint16_t *)(uintptr_t)buf = temp & 0xffff;
			temp >>= 16;
			buf += 2;
		}

		if (len & 1)
			*buf = temp & 0xff;
	}

	return len;
}

#else

static inline int _odp_random_max_kind(void)
{
	return _odp_random_max_kind_generic();
}

static inline int32_t _odp_random_crypto_data(uint8_t *buf, uint32_t len)
{
	return _odp_random_crypto_data_generic(buf, len);
}

static inline int32_t _odp_random_true_data(uint8_t *buf, uint32_t len)
{
	return _odp_random_true_data_generic(buf, len);
}

#endif

#ifdef __cplusplus
}
#endif

#endif

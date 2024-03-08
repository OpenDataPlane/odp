/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Nokia
 */

#include <stdint.h>

#include <odp/api/random.h>

#include <odp/autoheader_internal.h>
#include <odp_init_internal.h>
#include <odp_random_std_internal.h>
#include <odp_random_openssl_internal.h>
#include <odp_random.h>

odp_random_kind_t odp_random_max_kind(void)
{
	odp_random_kind_t kind, max_kind = ODP_RANDOM_BASIC;

	if (_ODP_OPENSSL_RAND)
		max_kind = ODP_RANDOM_CRYPTO;

	kind = _odp_random_max_kind();
	if (kind > max_kind)
		max_kind = kind;

	return max_kind;
}

int32_t odp_random_data(uint8_t *buf, uint32_t len, odp_random_kind_t kind)
{
	switch (kind) {
	case ODP_RANDOM_BASIC:
		if (_ODP_OPENSSL_RAND)
			return _odp_random_openssl_data(buf, len);
		return _odp_random_std_data(buf, len);
	case ODP_RANDOM_CRYPTO:
		if (_ODP_OPENSSL_RAND)
			return _odp_random_openssl_data(buf, len);
		return _odp_random_crypto_data(buf, len);
	case ODP_RANDOM_TRUE:
		return _odp_random_true_data(buf, len);
	}

	return -1;
}

int32_t odp_random_test_data(uint8_t *buf, uint32_t len, uint64_t *seed)
{
	return _odp_random_std_test_data(buf, len, seed);
}

int _odp_random_init_local(void)
{
	if (_ODP_OPENSSL_RAND)
		return _odp_random_openssl_init_local();
	return _odp_random_std_init_local();
}

int _odp_random_term_local(void)
{
	if (_ODP_OPENSSL_RAND)
		return _odp_random_openssl_term_local();
	return _odp_random_std_term_local();
}

/* Copyright (c) 2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdint.h>

#include <odp/api/random.h>

#include <odp/autoheader_internal.h>
#include <odp_init_internal.h>
#include <odp_random_std_internal.h>
#include <odp_random_openssl_internal.h>

odp_random_kind_t odp_random_max_kind(void)
{
	if (_ODP_OPENSSL)
		return _odp_random_openssl_max_kind();
	return _odp_random_std_max_kind();
}

int32_t odp_random_data(uint8_t *buf, uint32_t len, odp_random_kind_t kind)
{
	if (_ODP_OPENSSL)
		return _odp_random_openssl_data(buf, len, kind);
	return _odp_random_std_data(buf, len, kind);
}

int32_t odp_random_test_data(uint8_t *buf, uint32_t len, uint64_t *seed)
{
	if (_ODP_OPENSSL)
		return _odp_random_openssl_test_data(buf, len, seed);
	return _odp_random_std_test_data(buf, len, seed);
}

int _odp_random_init_local(void)
{
	if (_ODP_OPENSSL)
		return _odp_random_openssl_init_local();
	return _odp_random_std_init_local();
}

int _odp_random_term_local(void)
{
	if (_ODP_OPENSSL)
		return _odp_random_openssl_term_local();
	return _odp_random_std_term_local();
}

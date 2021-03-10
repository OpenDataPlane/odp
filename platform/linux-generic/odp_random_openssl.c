/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_posix_extensions.h>
#include <stdint.h>
#include <odp/api/random.h>
#include <odp/autoheader_internal.h>
#include <odp_init_internal.h>
#include <odp_random_openssl_internal.h>

#if _ODP_OPENSSL
#include <openssl/rand.h>

odp_random_kind_t _odp_random_openssl_max_kind(void)
{
	return ODP_RANDOM_CRYPTO;
}

int32_t _odp_random_openssl_data(uint8_t *buf, uint32_t len,
				 odp_random_kind_t kind)
{
	int rc;

	switch (kind) {
	case ODP_RANDOM_BASIC:
	case ODP_RANDOM_CRYPTO:
		rc = RAND_bytes(buf, len);
		return (1 == rc) ? (int)len /*success*/: -1 /*failure*/;

	case ODP_RANDOM_TRUE:
	default:
		return -1;
	}
}
#else
/* Dummy functions for building without OpenSSL support */
odp_random_kind_t _odp_random_openssl_max_kind(void)
{
	return ODP_RANDOM_BASIC;
}

int32_t _odp_random_openssl_data(uint8_t *buf ODP_UNUSED,
				 uint32_t len ODP_UNUSED,
				 odp_random_kind_t kind ODP_UNUSED)
{
	return -1;
}
#endif /* _ODP_OPENSSL */

int _odp_random_openssl_init_local(void)
{
	return 0;
}

int _odp_random_openssl_term_local(void)
{
	return 0;
}

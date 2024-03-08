/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2020 Nokia
 */

#include <odp_posix_extensions.h>
#include <stdint.h>
#include <odp/autoheader_internal.h>
#include <odp_init_internal.h>
#include <odp_random_openssl_internal.h>

#if _ODP_OPENSSL_RAND
#include <openssl/rand.h>

int32_t _odp_random_openssl_data(uint8_t *buf, uint32_t len)
{
	int rc;

	rc = RAND_bytes(buf, len);
	return (1 == rc) ? (int)len /*success*/: -1 /*failure*/;
}
#else
/* Dummy functions for building without OpenSSL support */
int32_t _odp_random_openssl_data(uint8_t *buf ODP_UNUSED,
				 uint32_t len ODP_UNUSED)
{
	return -1;
}
#endif /* _ODP_OPENSSL_RAND */

int _odp_random_openssl_init_local(void)
{
	return 0;
}

int _odp_random_openssl_term_local(void)
{
	return 0;
}

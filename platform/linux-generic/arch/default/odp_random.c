/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

#include <odp_random.h>
#include <odp/api/spec/random.h>

#include <odp/visibility_begin.h>

odp_random_kind_t _odp_random_max_kind_generic(void)
{
	return ODP_RANDOM_BASIC;
}

int32_t _odp_random_true_data_generic(uint8_t *buf, uint32_t len)
{
	(void)buf;
	(void)len;

	return -1;
}

int32_t _odp_random_crypto_data_generic(uint8_t *buf, uint32_t len)
{
	(void)buf;
	(void)len;

	return -1;
}

#include <odp/visibility_end.h>

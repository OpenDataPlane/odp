/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_DEFAULT_RANDOM_H_
#define ODP_DEFAULT_RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/spec/random.h>

#include <stdint.h>

odp_random_kind_t _odp_random_max_kind_generic(void);
int32_t _odp_random_true_data_generic(uint8_t *buf, uint32_t len);
int32_t _odp_random_crypto_data_generic(uint8_t *buf, uint32_t len);

static inline odp_random_kind_t _odp_random_max_kind(void)
{
	return _odp_random_max_kind_generic();
}

static inline int32_t _odp_random_true_data(uint8_t *buf, uint32_t len)
{
	return _odp_random_true_data_generic(buf, len);
}

static inline int32_t _odp_random_crypto_data(uint8_t *buf, uint32_t len)
{
	return _odp_random_crypto_data_generic(buf, len);
}

#ifdef __cplusplus
}
#endif

#endif

/* Copyright (c) 2020, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_RANDOM_OPENSSL_INTERNAL_H_
#define ODP_RANDOM_OPENSSL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <odp/api/random.h>

odp_random_kind_t _odp_random_openssl_max_kind(void);
int32_t _odp_random_openssl_test_data(uint8_t *buf, uint32_t len, uint64_t *seed);
int32_t _odp_random_openssl_data(uint8_t *buf, uint32_t len, odp_random_kind_t kind);
int _odp_random_openssl_init_local(void);
int _odp_random_openssl_term_local(void);

#ifdef __cplusplus
}
#endif
#endif /* ODP_RANDOM_OPENSSL_INTERNAL_H_ */

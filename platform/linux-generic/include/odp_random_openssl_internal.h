/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Nokia
 */

#ifndef ODP_RANDOM_OPENSSL_INTERNAL_H_
#define ODP_RANDOM_OPENSSL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int32_t _odp_random_openssl_data(uint8_t *buf, uint32_t len);
int _odp_random_openssl_init_local(void);
int _odp_random_openssl_term_local(void);

#ifdef __cplusplus
}
#endif
#endif /* ODP_RANDOM_OPENSSL_INTERNAL_H_ */

/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP random number API
 */

#ifndef ODP_RANDOM_H_
#define ODP_RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_random ODP RANDOM
 *  @{
 */


/**
 * Generate random byte string
 *
 * @param buf          Pointer to store result
 * @param len          Pointer to input length value as well as return value
 * @param use_entropy  Use entropy
 *
 * @todo Define the implication of the use_entropy parameter
 *
 * @return 0 if succesful
 */
int odp_random_data(uint8_t *buf, size_t *len, odp_bool_t use_entropy);


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

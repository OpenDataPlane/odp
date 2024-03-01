/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#ifndef ODP_ML_FP16_H_
#define ODP_ML_FP16_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

uint16_t _odp_float32_to_float16(float x);
float _odp_float16_to_float32(uint16_t f16);
uint16_t _odp_float32_to_bfloat16(float x);
float _odp_bfloat16_to_float32(uint16_t f16);

#ifdef __cplusplus
}
#endif

#endif /* ODP_ML_FP16_H_ */

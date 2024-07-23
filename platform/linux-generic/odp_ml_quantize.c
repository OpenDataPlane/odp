/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 */

#include <odp/api/ml_quantize.h>

#include <odp_debug_internal.h>
#include <odp_macros_internal.h>
#include <odp_ml_fp16.h>

#include <math.h>
#include <stdint.h>

void odp_ml_fp32_to_uint8(uint8_t *u8, const float *fp32, uint32_t num, float scale,
			  uint8_t zerop)
{
	float fval;

	_ODP_ASSERT(scale < 0.0 || scale > 0.0);

	for (uint32_t i = 0; i < num; i++) {
		/* Range mapping: map real values to signed integer */
		fval = nearbyintf(fp32[i] / scale) + (float)zerop;

		/* clip */
		fval = _ODP_MAX(fval, 0.f);
		fval = _ODP_MIN(fval, 255.f);
		u8[i] = (uint8_t)(int32_t)fval;
	}
}

void odp_ml_fp32_from_uint8(float *fp32, const uint8_t *u8, uint32_t num, float scale,
			    uint8_t zerop)
{
	for (uint32_t i = 0; i < num; i++)
		fp32[i] = (float)(u8[i] - zerop) * scale;
}

void odp_ml_fp32_to_int8(int8_t *i8, const float *fp32, uint32_t num, float scale, int8_t zerop)
{
	float fval;

	_ODP_ASSERT(scale < 0.0 || scale > 0.0);

	for (uint32_t i = 0; i < num; i++) {
		/* Range mapping: map real values to signed integer */
		fval = nearbyintf(fp32[i] / scale) + (float)zerop;

		/* NOTE: Clamps signed quantization values to [-127,127] instead of [-128,127].
		 * This is to ensure that symmetric quantization results in a zero
		 * point of exactly 0 for signed 8 bit ints.
		 */
		fval = _ODP_MAX(fval, -127.f);
		fval = _ODP_MIN(fval, 127.f);
		i8[i] = (int8_t)(int32_t)fval;
	}
}

void odp_ml_fp32_from_int8(float *fp32, const int8_t *i8, uint32_t num, float scale, int8_t zerop)
{
	for (uint32_t i = 0; i < num; i++)
		fp32[i] = (float)(i8[i] - zerop) * scale;
}

void odp_ml_fp32_to_fp16(uint16_t *fp16, const float *fp32, uint32_t num)
{
	uint32_t i;

	for (i = 0; i < num; i++)
		fp16[i] = _odp_float32_to_float16(fp32[i]);
}

void odp_ml_fp32_from_fp16(float *fp32, const uint16_t *fp16, uint32_t num)
{
	uint32_t i;

	for (i = 0; i < num; i++)
		fp32[i] = _odp_float16_to_float32(fp16[i]);
}

/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Nokia
 * Copyright (c) 2024 Marvell
 */

/**
 * @file
 *
 * ODP Machine Learning (ML) quantization functions
 */

#ifndef ODP_API_SPEC_ML_QUANTIZE_H_
#define ODP_API_SPEC_ML_QUANTIZE_H_
#include <odp/visibility_begin.h>

#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_ml
 *  @{
 */

/**
 * Quantize 32-bit float to uint8_t
 *
 * Quantizes 'num' 32-bit floating point values to uint8_t values using the provided scale and
 * zero point.
 *
 *   dst_u8 = (src_fp32 / scale) + zerop
 *
 * @param[out] dst_u8    Destination address for quantized values
 * @param src_fp32       Source address of values to be quantized
 * @param num            Number of values
 * @param scale          Scale for quantization
 * @param zerop          Zero point for quantization
 */
void odp_ml_fp32_to_uint8(uint8_t *dst_u8, const float *src_fp32, uint32_t num,
			  float scale, uint8_t zerop);

/**
 * De-quantize 32-bit float from uint8_t
 *
 * De-quantizes 'num' 32-bit floating point values from uint8_t values using the provided scale and
 * zero point.
 *
 *   dst_fp32 = (src_u8 - zerop) * scale
 *
 * @param[out] dst_fp32  Destination address for de-quantized values
 * @param src_u8         Source address of values to be de-quantized
 * @param num            Number of values
 * @param scale          Scale for de-quantization
 * @param zerop          Zero point for de-quantization
 */
void odp_ml_fp32_from_uint8(float *dst_fp32, const uint8_t *src_u8, uint32_t num,
			    float scale, uint8_t zerop);

/**
 * Quantize 32-bit float to int8_t
 *
 * Quantizes 'num' 32-bit floating point values to int8_t values using the provided scale and
 * zero point.
 *
 *   dst_i8 = (src_fp32 / scale) + zerop
 *
 * @param[out] dst_i8    Destination address for quantized values
 * @param src_fp32       Source address of values to be quantized
 * @param num            Number of values
 * @param scale          Scale for quantization
 * @param zerop          Zero point for quantization
 */
void odp_ml_fp32_to_int8(int8_t *dst_i8, const float *src_fp32, uint32_t num, float scale,
			 int8_t zerop);

/**
 * De-quantize 32-bit float from int8_t
 *
 * De-quantizes 'num' 32-bit floating point values from int8_t values using the provided scale and
 * zero point.
 *
 *   dst_fp32 = (src_i8 - zerop) * scale
 *
 * @param[out] dst_fp32  Destination address for de-quantized values
 * @param src_i8         Source address of values to be de-quantized
 * @param num            Number of values
 * @param scale          Scale for de-quantization
 * @param zerop          Zero point for de-quantization
 */
void odp_ml_fp32_from_int8(float *dst_fp32, const int8_t *src_i8, uint32_t num, float scale,
			   int8_t zerop);

/**
 * Quantize 32-bit float to uint16_t
 *
 * Quantizes 'num' 32-bit floating point values to uint16_t values using the provided scale and
 * zero point.
 *
 *   dst_u16 = (src_fp32 / scale) + zerop
 *
 * @param[out] dst_u16   Destination address for quantized values
 * @param src_fp32       Source address of values to be quantized
 * @param num            Number of values
 * @param scale          Scale for quantization
 * @param zerop          Zero point for quantization
 */
void odp_ml_fp32_to_uint16(uint16_t *dst_u16, const float *src_fp32, uint32_t num, float scale,
			   uint16_t zerop);

/**
 * De-quantize 32-bit float from uint16_t
 *
 * De-quantizes 'num' 32-bit floating point values from uint16_t values using the provided scale and
 * zero point.
 *
 *   dst_fp32 = (src_u16 - zerop) * scale
 *
 * @param[out] dst_fp32  Destination address for de-quantized values
 * @param src_u16        Source address of values to be de-quantized
 * @param num            Number of values
 * @param scale          Scale for de-quantization
 * @param zerop          Zero point for de-quantization
 */
void odp_ml_fp32_from_uint16(float *dst_fp32, const uint16_t *src_u16, uint32_t num, float scale,
			     uint16_t zerop);

/**
 * Quantize 32-bit float to int16_t
 *
 * Quantizes 'num' 32-bit floating point values to int16_t values using the provided scale and
 * zero point.
 *
 *   dst_i16 = (src_fp32 / scale) + zerop
 *
 * @param[out] dst_i16   Destination address for quantized values
 * @param src_fp32       Source address of values to be quantized
 * @param num            Number of values
 * @param scale          Scale for quantization
 * @param zerop          Zero point for quantization
 */
void odp_ml_fp32_to_int16(int16_t *dst_i16, const float *src_fp32, uint32_t num, float scale,
			  int16_t zerop);

/**
 * De-quantize 32-bit float from int16_t
 *
 * De-quantizes 'num' 32-bit floating point values from int16_t values using the provided scale and
 * zero point.
 *
 *   dst_fp32 = (src_i16 - zerop) * scale
 *
 * @param[out] dst_fp32  Destination address for de-quantized values
 * @param src_i16        Source address of values to be de-quantized
 * @param num            Number of values
 * @param scale          Scale for de-quantization
 * @param zerop          Zero point for de-quantization
 */
void odp_ml_fp32_from_int16(float *dst_fp32, const int16_t *src_i16, uint32_t num, float scale,
			    int16_t zerop);

/**
 * Quantize 32-bit float to 16-bit float
 *
 * Quantizes 'num' 32-bit floating point values to 16-bit floating point values.
 *
 * @param[out] dst_fp16  Destination address for quantized values
 * @param src_fp32       Source address of values to be quantized
 * @param num            Number of values
 */
void odp_ml_fp32_to_fp16(uint16_t *dst_fp16, const float *src_fp32, uint32_t num);

/**
 * De-quantize 32-bit float from 16-bit float
 *
 * De-quantizes 'num' 32-bit floating point values from 16-bit floating point values.
 *
 * @param[out] dst_fp32  Destination address for de-quantized values
 * @param src_fp16       Source address of values to be de-quantized
 * @param num            Number of values
 */
void odp_ml_fp32_from_fp16(float *dst_fp32, const uint16_t *src_fp16, uint32_t num);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

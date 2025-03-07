/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP checksum functions.
 */

#ifndef ODP_API_SPEC_CHKSUM_H_
#define ODP_API_SPEC_CHKSUM_H_
#include <odp/visibility_begin.h>

#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_chksum ODP CHECKSUM
 *  Checksum functions.
 *  @{
 */

/**
 * Ones' complement sum of 16-bit words
 *
 * Calculates 16-bit ones' complement sum over the data. In case of odd number
 * of bytes, calculation uses a zero byte as padding at the end. This algorithm
 * may be used as part of e.g. IPv4/UDP/TCP checksum generation and checking.
 *
 * @param data       Pointer to data. Data address must be 16-bit aligned
 *                   in minimum.
 * @param data_len   Data length in bytes. In case of an odd number, calculation
 *                   includes one byte of padding.
 *
 * @return Ones' complement sum
 */
uint16_t odp_chksum_ones_comp16(const void *data, uint32_t data_len);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

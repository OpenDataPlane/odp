/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP byteorder
 */

#ifndef ODP_BYTEORDER_H_
#define ODP_BYTEORDER_H_

#ifdef __cplusplus
extern "C" {
#endif

uint16_t odp_be_to_cpu_16(uint16_t be16);
uint32_t odp_be_to_cpu_32(uint16_t be32);
uint64_t odp_be_to_cpu_64(uint16_t be64);

uint16_t odp_cpu_to_be_16(uint16_t cpu16);
uint32_t odp_cpu_to_be_32(uint32_t cpu32);
uint64_t odp_cpu_to_be_64(uint64_t cpu64);

uint16_t odp_le_to_cpu_16(uint16_t le16);
uint32_t odp_le_to_cpu_32(uint16_t le32);
uint64_t odp_le_to_cpu_64(uint16_t le64);

uint16_t odp_cpu_to_le_16(uint16_t cpu16);
uint32_t odp_cpu_to_le_32(uint32_t cpu32);
uint64_t odp_cpu_to_le_64(uint64_t cpu64);

#ifdef __cplusplus
}
#endif

#endif

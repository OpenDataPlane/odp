/* Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP byteorder
 */

#ifndef ODP_PLAT_BYTEORDER_INLINES_API_H_
#define ODP_PLAT_BYTEORDER_INLINES_API_H_

#ifdef __cplusplus
extern "C" {
#endif

_ODP_INLINE uint16_t odp_be_to_cpu_16(odp_u16be_t be16)
{
	return _odp_be_to_cpu_16(be16);
}

_ODP_INLINE uint32_t odp_be_to_cpu_32(odp_u32be_t be32)
{
	return _odp_be_to_cpu_32(be32);
}

_ODP_INLINE uint64_t odp_be_to_cpu_64(odp_u64be_t be64)
{
	return _odp_be_to_cpu_64(be64);
}

_ODP_INLINE odp_u16be_t odp_cpu_to_be_16(uint16_t cpu16)
{
	return _odp_cpu_to_be_16(cpu16);
}

_ODP_INLINE odp_u32be_t odp_cpu_to_be_32(uint32_t cpu32)
{
	return _odp_cpu_to_be_32(cpu32);
}

_ODP_INLINE odp_u64be_t odp_cpu_to_be_64(uint64_t cpu64)
{
	return _odp_cpu_to_be_64(cpu64);
}

_ODP_INLINE uint16_t odp_le_to_cpu_16(odp_u16le_t le16)
{
	return _odp_le_to_cpu_16(le16);
}

_ODP_INLINE uint32_t odp_le_to_cpu_32(odp_u32le_t le32)
{
	return _odp_le_to_cpu_32(le32);
}

_ODP_INLINE uint64_t odp_le_to_cpu_64(odp_u64le_t le64)
{
	return _odp_le_to_cpu_64(le64);
}

_ODP_INLINE odp_u16le_t odp_cpu_to_le_16(uint16_t cpu16)
{
	return _odp_cpu_to_le_16(cpu16);
}

_ODP_INLINE odp_u32le_t odp_cpu_to_le_32(uint32_t cpu32)
{
	return _odp_cpu_to_le_32(cpu32);
}

_ODP_INLINE odp_u64le_t odp_cpu_to_le_64(uint64_t cpu64)
{
	return _odp_cpu_to_le_64(cpu64);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

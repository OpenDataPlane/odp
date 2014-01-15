/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


#include <endian.h>
#include <odp_std_types.h>
#include <odp_byteorder.h>

#ifndef BYTE_ORDER
#error BYTE_ORDER not defined!
#endif

#define ODP_BIG_ENDIAN    BIG_ENDIAN
#define ODP_LITTLE_ENDIAN LITTLE_ENDIAN

#if BYTE_ORDER == LITTLE_ENDIAN
#define ODP_BYTE_ORDER ODP_LITTLE_ENDIAN
#elif BYTE_ORDER == BIG_ENDIAN
#define ODP_BYTE_ORDER ODP_BIG_ENDIAN
#endif


static inline uint16_t swap_16(uint16_t u16)
{
	/* __builtin_bswap16() is not available on all platforms */
	uint16_t swap16 = ((u16 & 0x00ff) << 8) | ((u16 & 0xff00) >> 8);

	return swap16;
}

static inline uint32_t swap_32(uint32_t u32)
{
	return __builtin_bswap32(u32);
}

static inline uint64_t swap_64(uint64_t u64)
{
	return __builtin_bswap64(u64);
}

/*
 * Big Endian -> CPU byte order:
 */

uint16_t odp_be_to_cpu_16(uint16_t be16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return swap_16(be16);
#else
	return be16;
#endif
}

uint32_t odp_be_to_cpu_32(uint16_t be32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return swap_32(be32);
#else
	return be32;
#endif
}

uint64_t odp_be_to_cpu_64(uint16_t be64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return swap_64(be64);
#else
	return be64;
#endif
}

/*
 * CPU byte order -> Big Endian:
 */

uint16_t odp_cpu_to_be_16(uint16_t cpu16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return swap_16(cpu16);
#else
	return cpu16;
#endif
}

uint32_t odp_cpu_to_be_32(uint32_t cpu32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return swap_32(cpu32);
#else
	return cpu32;
#endif
}


uint64_t odp_cpu_to_be_64(uint64_t cpu64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return swap_64(cpu64);
#else
	return cpu64;
#endif
}

/*
 * Little Endian -> CPU byte order:
 */

uint16_t odp_le_to_cpu_16(uint16_t le16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return le16;
#else
	return swap_16(le16);
#endif
}


uint32_t odp_le_to_cpu_32(uint16_t le32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return le32;
#else
	return swap_32(le32);
#endif
}

uint64_t odp_le_to_cpu_64(uint16_t le64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return le64;
#else
	return swap_64(le64);
#endif
}

/*
 * CPU byte order -> Little Endian:
 */

uint16_t odp_cpu_to_le_16(uint16_t cpu16)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return cpu16;
#else
	return swap_16(cpu16);
#endif
}

uint32_t odp_cpu_to_le_32(uint32_t cpu32)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return cpu32;
#else
	return swap_32(cpu32);
#endif
}

uint64_t odp_cpu_to_le_64(uint64_t cpu64)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	return cpu64;
#else
	return swap_64(cpu64);
#endif
}


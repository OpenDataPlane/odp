/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 Nokia
 */

#ifndef ODP_PLAT_HASH_INLINES_H_
#define ODP_PLAT_HASH_INLINES_H_

#include <odp/api/abi/hash_crc32.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_hash_crc32      __odp_hash_crc32
	#define odp_hash_crc32c     __odp_hash_crc32c
#else
	#define _ODP_INLINE
#endif

_ODP_INLINE uint32_t odp_hash_crc32(const void *data, uint32_t data_len,
				    uint32_t init_val)
{
	return _odp_hash_crc32(data, data_len, init_val);
}

_ODP_INLINE uint32_t odp_hash_crc32c(const void *data, uint32_t data_len,
				     uint32_t init_val)
{
	return _odp_hash_crc32c(data, data_len, init_val);
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif

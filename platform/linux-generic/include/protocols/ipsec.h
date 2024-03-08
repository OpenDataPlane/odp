/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */


/**
 * @file
 *
 * ODP IPSec headers
 */

#ifndef ODP_IPSEC_H_
#define ODP_IPSEC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/byteorder.h>
#include <odp/api/debug.h>

#include <stdint.h>

/** @addtogroup odp_header ODP HEADER
 *  @{
 */

#define _ODP_ESPHDR_LEN      8    /**< IPSec ESP header length */
#define _ODP_ESPTRL_LEN      2    /**< IPSec ESP trailer length */
#define _ODP_AHHDR_LEN      12    /**< IPSec AH header length */

/**
 * IPSec ESP header
 */
typedef struct ODP_PACKED {
	odp_u32be_t spi;     /**< Security Parameter Index */
	odp_u32be_t seq_no;  /**< Sequence Number */
	uint8_t     iv[];    /**< Initialization vector */
} _odp_esphdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_esphdr_t) == _ODP_ESPHDR_LEN,
		  "_ODP_ESPHDR_T__SIZE_ERROR");

/**
 * IPSec ESP trailer
 */
typedef struct ODP_PACKED {
	uint8_t pad_len;      /**< Padding length (0-255) */
	uint8_t next_header;  /**< Next header protocol */
	uint8_t icv[];        /**< Integrity Check Value (optional) */
} _odp_esptrl_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_esptrl_t) == _ODP_ESPTRL_LEN,
		  "_ODP_ESPTRL_T__SIZE_ERROR");

/**
 * IPSec AH header
 */
typedef struct ODP_PACKED {
	uint8_t     next_header; /**< Next header protocol */
	uint8_t     ah_len;      /**< AH header length */
	odp_u16be_t pad;         /**< Padding (must be 0) */
	odp_u32be_t spi;         /**< Security Parameter Index */
	odp_u32be_t seq_no;      /**< Sequence Number */
	uint8_t     icv[];       /**< Integrity Check Value */
} _odp_ahhdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_ahhdr_t) == _ODP_AHHDR_LEN,
		  "_ODP_AHHDR_T__SIZE_ERROR");

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

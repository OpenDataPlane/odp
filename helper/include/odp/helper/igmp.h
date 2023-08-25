/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Marvell
 */

/**
 * @file
 *
 * ODP IGMP header
 */
#ifndef _ODPH_IGMP_H_
#define _ODPH_IGMP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

/**
 * @addtogroup odph_protocols
 * @{
 */

/**
 * Simplified IGMP protocol header.
 * Contains 8-bit type, 8-bit code,
 * 16-bit csum, 32-bit group.
 * No optional fields and next extension header.
 */
typedef struct ODP_PACKED {
	uint8_t type;      /**< Message Type */
	uint8_t code;      /**< Max response code */
	odp_u16be_t csum;  /**< Checksum */
	odp_u32be_t group; /**< Group address */
} odph_igmphdr_t;

/** IGMP header length */
#define ODPH_IGMP_HLEN sizeof(odph_igmphdr_t)

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ODP_IGMP_H_ */

/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODPH VxLAN header
 */

#ifndef ODPH_VXLAN_H_
#define ODPH_VXLAN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

/** @addtogroup odp_header ODP HEADER
 *  @{
 */

/** VXLAN header length */
#define ODPH_VXLANHDR_LEN 8

/** VNI from VXLAN header format */
#define ODPH_VXLAN_VNI(vxlan_vni) ((vxlan_vni & 0xffffff00) >> 8)

/** UDP VXLAN destination port */
#define ODPH_UDP_VXLAN_PORT 4789

/** VNI to VXLAN header format */
#define ODPH_VNI_VXLAN(vxlan_vni) (vxlan_vni << 8)

/** VXLAN header */
typedef struct ODP_PACKED {
	uint8_t flags; /**< VXLAN flags */
	uint8_t reserved1; /**< reserved bits */
	uint16_t reserved2; /**< reserved bits */
	odp_u32be_t vni; /**< VNI Identifier */
} odph_vxlanhdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(odph_vxlanhdr_t) == ODPH_VXLANHDR_LEN,
		  "ODPH_VXLANHDR_T__SIZE_ERROR");

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

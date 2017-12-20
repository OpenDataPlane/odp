/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP VxLAN header
 */

#ifndef ODP_VXLAN_H_
#define ODP_VXLAN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

/** @addtogroup odp_header ODP HEADER
 *  @{
 */

/** VXLAN header length */
#define _ODP_VXLANHDR_LEN 8

/** VXLAN UDP destination port */
#define _ODP_UDP_VXLAN_PORT 4789

#define ODPH_VXLAN_VNI(vxlan_vni) ((vxlan_vni & 0xffffff00) >> 8)

#define ODPH_VXLAN_BIT(vxlan_flag) (vxlan_flag & 0x08)

/** UDP header */
typedef struct ODP_PACKED {
	uint8_t flags; /**< VXLAN flags */
	uint8_t reserved1; /**< reserved bits */
	uint16_t reserved2; /**< reserved bits */
	odp_u32be_t vni; /**< VNI Identifier */
} _odp_vxlanhdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_vxlanhdr_t) == _ODP_VXLANHDR_LEN,
		  "_ODP_VXLANHDR_T__SIZE_ERROR");

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

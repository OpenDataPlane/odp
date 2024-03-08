/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP ethernet header
 */

#ifndef ODP_ETH_H_
#define ODP_ETH_H_

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

#define _ODP_ETHADDR_LEN     6    /**< Ethernet address length */
#define _ODP_ETHHDR_LEN      14   /**< Ethernet header length */
#define _ODP_VLANHDR_LEN     4    /**< VLAN header length */
#define _ODP_ETH_LEN_MIN     60   /**< Min frame length (excl CRC 4 bytes) */
#define _ODP_ETH_LEN_MIN_CRC 64   /**< Min frame length (incl CRC 4 bytes) */
#define _ODP_ETH_LEN_MAX     1514 /**< Max frame length (excl CRC 4 bytes) */
#define _ODP_ETH_LEN_MAX_CRC 1518 /**< Max frame length (incl CRC 4 bytes) */

/* The two byte _odp_vlanhdr_t tci field is composed of the following three
 * subfields - a three bit Priority Code Point (PCP), a one bit Drop
 * Eligibility Indicator (DEI) and a twelve bit VLAN Identifier (VID).  The
 * following constants can be used to extract or modify these subfields, once
 * the tci field has been read in and converted to host byte order.  Note
 * that the DEI subfield used to be the CFI bit.
 */
#define _ODP_VLANHDR_MAX_PRIO   7      /**< Max value of the 3 bit priority */
#define _ODP_VLANHDR_PCP_MASK   0xE000 /**< PCP field bit mask */
#define _ODP_VLANHDR_PCP_SHIFT  13     /**< PCP field shift */
#define _ODP_VLANHDR_DEI_MASK   0x1000 /**< DEI field bit mask */
#define _ODP_VLANHDR_DEI_SHIFT  12     /**< DEI field shift */
#define _ODP_VLANHDR_MAX_VID    0x0FFF /**< Max value of the 12 bit VID field */
#define _ODP_VLANHDR_VID_MASK   0x0FFF /**< VID field bit mask */
#define _ODP_VLANHDR_VID_SHIFT  0      /**< VID field shift */

/**
 * Ethernet MAC address
 */
typedef struct ODP_PACKED {
	uint8_t addr[_ODP_ETHADDR_LEN]; /**< @private Address */
} _odp_ethaddr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_ethaddr_t) == _ODP_ETHADDR_LEN,
		  "_ODP_ETHADDR_T__SIZE_ERROR");

/**
 * Ethernet header
 */
typedef struct ODP_PACKED {
	_odp_ethaddr_t dst; /**< Destination address */
	_odp_ethaddr_t src; /**< Source address */
	odp_u16be_t type;   /**< EtherType */
} _odp_ethhdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_ethhdr_t) == _ODP_ETHHDR_LEN,
		  "_ODP_ETHHDR_T__SIZE_ERROR");

/**
 * IEEE 802.1Q VLAN header
 *
 * This field is present when the EtherType (the _odp_ethhdr_t type field) of
 * the preceding ethernet header is _ODP_ETHTYPE_VLAN.  The inner EtherType
 * (the _odp_vlanhdr_t type field) then indicates what comes next.  Note that
 * the so called TPID field isn't here because it overlaps with the
 * _odp_ethhdr_t type field.
 */
typedef struct ODP_PACKED {
	odp_u16be_t tci;   /**< Priority / CFI / VLAN ID */
	odp_u16be_t type;  /**< Inner EtherType */
} _odp_vlanhdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(_odp_vlanhdr_t) == _ODP_VLANHDR_LEN,
		  "_ODP_VLANHDR_T__SIZE_ERROR");

/* Ethernet header Ether Type ('type') values, a selected few */
#define _ODP_ETHTYPE_IPV4       0x0800 /**< Internet Protocol version 4 */
#define _ODP_ETHTYPE_ARP        0x0806 /**< Address Resolution Protocol */
#define _ODP_ETHTYPE_RARP       0x8035 /**< Reverse Address Resolution Protocol*/
#define _ODP_ETHTYPE_VLAN       0x8100 /**< VLAN-tagged frame IEEE 802.1Q */
#define _ODP_ETHTYPE_VLAN_OUTER 0x88A8 /**< Stacked VLANs/QinQ, outer-tag/S-TAG*/
#define _ODP_ETHTYPE_IPV6       0x86dd /**< Internet Protocol version 6 */
#define _ODP_ETHTYPE_FLOW_CTRL  0x8808 /**< Ethernet flow control */
#define _ODP_ETHTYPE_MPLS       0x8847 /**< MPLS unicast */
#define _ODP_ETHTYPE_MPLS_MCAST 0x8848 /**< MPLS multicast */
#define _ODP_ETHTYPE_MACSEC     0x88E5 /**< MAC security IEEE 802.1AE */
#define _ODP_ETHTYPE_1588       0x88F7 /**< Precision Time Protocol IEEE 1588 */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

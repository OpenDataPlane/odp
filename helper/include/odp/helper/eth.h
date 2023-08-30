/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP ethernet header
 */

#ifndef ODPH_ETH_H_
#define ODPH_ETH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

/**
 * @defgroup odph_protocols ODPH PROTOCOLS
 * Network protocols
 *
 * @{
 */

#define ODPH_ETHADDR_LEN     6    /**< Ethernet address length */
#define ODPH_ETHHDR_LEN      14   /**< Ethernet header length */
#define ODPH_VLANHDR_LEN     4    /**< VLAN header length */
#define ODPH_ETH_LEN_MIN     60   /**< Min frame length (excl CRC 4 bytes) */
#define ODPH_ETH_LEN_MIN_CRC 64   /**< Min frame length (incl CRC 4 bytes) */
#define ODPH_ETH_LEN_MAX     1514 /**< Max frame length (excl CRC 4 bytes) */
#define ODPH_ETH_LEN_MAX_CRC 1518 /**< Max frame length (incl CRC 4 bytes) */

/* The two byte odph_vlanhdr_t tci field is composed of the following three
 * subfields - a three bit Priority Code Point (PCP), a one bit Drop
 * Eligibility Indicator (DEI) and a twelve bit VLAN Identifier (VID).  The
 * following constants can be used to extract or modify these subfields, once
 * the tci field has been read in and converted to host byte order.  Note
 * that the DEI subfield used to be the CFI bit.
 */
#define ODPH_VLANHDR_MAX_PRIO   7      /**< Max value of the 3 bit priority */
#define ODPH_VLANHDR_PCP_MASK   0xE000 /**< PCP field bit mask */
#define ODPH_VLANHDR_PCP_SHIFT  13     /**< PCP field shift */
#define ODPH_VLANHDR_DEI_MASK   0x1000 /**< DEI field bit mask */
#define ODPH_VLANHDR_DEI_SHIFT  12     /**< DEI field shift */
#define ODPH_VLANHDR_MAX_VID    0x0FFF /**< Max value of the 12 bit VID field */
#define ODPH_VLANHDR_VID_MASK   0x0FFF /**< VID field bit mask */
#define ODPH_VLANHDR_VID_SHIFT  0      /**< VID field shift */

/**
 * Ethernet MAC address
 */
typedef struct ODP_PACKED {
	uint8_t addr[ODPH_ETHADDR_LEN]; /**< Address */
} odph_ethaddr_t;

/**
 * Ethernet header
 */
typedef struct ODP_PACKED {
	odph_ethaddr_t dst; /**< Destination address */
	odph_ethaddr_t src; /**< Source address */
	odp_u16be_t type;   /**< EtherType */
} odph_ethhdr_t;

/**
 * IEEE 802.1Q VLAN header
 *
 * This field is present when the EtherType (the odph_ethhdr_t type field) of
 * the preceding ethernet header is ODPH_ETHTYPE_VLAN.  The inner EtherType
 * (the odph_vlanhdr_t type field) then indicates what comes next.  Note that
 * the so called TPID field isn't here because it overlaps with the
 * odph_ethhdr_t type field.
 */
typedef struct ODP_PACKED {
	odp_u16be_t tci;   /**< Priority / CFI / VLAN ID */
	odp_u16be_t type;  /**< Inner EtherType */
} odph_vlanhdr_t;

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */
ODP_STATIC_ASSERT(sizeof(odph_ethaddr_t) == ODPH_ETHADDR_LEN,
		  "ODPH_ETHADDR_T__SIZE_ERROR");

ODP_STATIC_ASSERT(sizeof(odph_ethhdr_t) == ODPH_ETHHDR_LEN,
		  "ODPH_ETHHDR_T__SIZE_ERROR");

ODP_STATIC_ASSERT(sizeof(odph_vlanhdr_t) == ODPH_VLANHDR_LEN,
		  "ODPH_VLANHDR_T__SIZE_ERROR");
/** @endcond */

/* Ethernet header Ether Type ('type') values, a selected few */
#define ODPH_ETHTYPE_IPV4       0x0800 /**< Internet Protocol version 4 */
#define ODPH_ETHTYPE_ARP        0x0806 /**< Address Resolution Protocol */
#define ODPH_ETHTYPE_RARP       0x8035 /**< Reverse Address Resolution Protocol*/
#define ODPH_ETHTYPE_VLAN       0x8100 /**< VLAN-tagged frame IEEE 802.1Q */
#define ODPH_ETHTYPE_VLAN_OUTER 0x88A8 /**< Stacked VLANs/QinQ, outer-tag/S-TAG*/
#define ODPH_ETHTYPE_IPV6       0x86dd /**< Internet Protocol version 6 */
#define ODPH_ETHTYPE_FLOW_CTRL  0x8808 /**< Ethernet flow control */
#define ODPH_ETHTYPE_MPLS       0x8847 /**< MPLS unicast */
#define ODPH_ETHTYPE_MPLS_MCAST 0x8848 /**< MPLS multicast */
#define ODPH_ETHTYPE_MACSEC     0x88E5 /**< MAC security IEEE 802.1AE */
#define ODPH_ETHTYPE_1588       0x88F7 /**< Precision Time Protocol IEEE 1588 */

/**
 * Parse Ethernet from a string
 *
 * Parses Ethernet MAC address from the string which must be passed in format of
 * six hexadecimal digits delimited by colons (xx:xx:xx:xx:xx:xx). Both upper
 * and lower case characters are supported. All six digits have to be present
 * and may have leading zeros. String does not have to be NULL terminated.
 * The address is written only when successful.
 *
 * @param[out] mac   Pointer to Ethernet address for output
 * @param      str   MAC address string to be parsed
 *
 * @retval 0  on success
 * @retval <0 on failure
 */
int odph_eth_addr_parse(odph_ethaddr_t *mac, const char *str);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

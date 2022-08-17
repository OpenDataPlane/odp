/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP IP header
 */

#ifndef ODPH_IP_H_
#define ODPH_IP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>
#include <odp/helper/chksum.h>

#include <string.h>

/** @addtogroup odph_header ODPH HEADER
 *  @{
 */

#define ODPH_IPV4             4  /**< IP version 4 */
#define ODPH_IPV4HDR_LEN     20  /**< Min length of IP header (no options) */
#define ODPH_IPV4HDR_IHL_MIN  5  /**< Minimum IHL value*/
#define ODPH_IPV4ADDR_LEN     4  /**< IPv4 address length in bytes */

/** The one byte IPv4 tos or IPv6 tc field is composed of the following two
 * subfields - a six bit Differentiated Service Code Point (DSCP) and a two
 * bit Explicit Congestion Notification (ECN) subfield.  The following
 * constants can be used to extract or modify these fields.  Despite the
 * name prefix being ODPH_IP_TOS_* these constants apply equally well for
 * the IPv6 Traffic Class (tc) field.
 */
#define ODPH_IP_TOS_MAX_DSCP   63    /**< 6-bit DSCP field has max value 63  */
#define ODPH_IP_TOS_DSCP_MASK  0xFC  /**< DSCP field is in bits <7:2>  */
#define ODPH_IP_TOS_DSCP_SHIFT 2     /**< DSCP field is shifted letf by 2  */
#define ODPH_IP_TOS_MAX_ECN    3     /**< 2-bit ECN field has max value 3  */
#define ODPH_IP_TOS_ECN_MASK   0x03  /**< ECN field is in bits <1:0>  */
#define ODPH_IP_TOS_ECN_SHIFT  0     /**< ECN field is not shifted.  */

/** The following constants give names to the four possible ECN values,
 * as described in RFC 3168.
 */
#define ODPH_IP_ECN_NOT_ECT  0  /**< 0 indicates not participating in ECN */
#define ODPH_IP_ECN_ECT1     1  /**< Indicates no congestion seen yet */
#define ODPH_IP_ECN_ECT0     2  /**< Indicates no congestion seen yet */
#define ODPH_IP_ECN_CE       3  /**< Used to signal Congestion Experienced */

/** @internal Returns IPv4 version */
#define ODPH_IPV4HDR_VER(ver_ihl) (((ver_ihl) & 0xf0) >> 4)

/** @internal Returns IPv4 header length */
#define ODPH_IPV4HDR_IHL(ver_ihl) ((ver_ihl) & 0x0f)

/** @internal Returns IPv4 DSCP */
#define ODPH_IPV4HDR_DSCP(tos) (((tos) & 0xfc) >> 2)

/** @internal Returns IPv4 Don't fragment */
#define ODPH_IPV4HDR_FLAGS_DONT_FRAG(frag_offset)  ((frag_offset) & 0x4000)

/** @internal Returns IPv4 more fragments */
#define ODPH_IPV4HDR_FLAGS_MORE_FRAGS(frag_offset)  ((frag_offset) & 0x2000)

/** @internal Returns IPv4 fragment offset */
#define ODPH_IPV4HDR_FRAG_OFFSET(frag_offset) ((frag_offset) & 0x1fff)

/** @internal Returns true if IPv4 packet is a fragment */
#define ODPH_IPV4HDR_IS_FRAGMENT(frag_offset) ((frag_offset) & 0x3fff)

/** @internal Checksum offset in IPv4 header */
#define ODPH_IPV4HDR_CSUM_OFFSET	10

/** IPv4 header */
typedef struct ODP_PACKED {
	uint8_t    ver_ihl;     /**< Version / Header length */
	uint8_t    tos;         /**< Type of service */
	odp_u16be_t tot_len;    /**< Total length */
	odp_u16be_t id;         /**< ID */
	odp_u16be_t frag_offset;/**< Fragmentation offset */
	uint8_t    ttl;         /**< Time to live */
	uint8_t    proto;       /**< Protocol */
	odp_u16sum_t chksum;    /**< Checksum */
	odp_u32be_t src_addr;   /**< Source address */
	odp_u32be_t dst_addr;   /**< Destination address */
} odph_ipv4hdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(odph_ipv4hdr_t) == ODPH_IPV4HDR_LEN,
		  "ODPH_IPV4HDR_T__SIZE_ERROR");

/**
 * Calculate IPv4 header checksum
 *
 * @param pkt         The packet to be checksummed
 * @param offset      Offset into pkt of start of IP header
 * @param ip          Pointer to IPv4 header to be checksummed
 * @param[out] chksum Field to receive checksum results
 *
 * @retval 0  On success
 * @retval <0 On failure
 */
static inline int odph_ipv4_csum(odp_packet_t pkt,
				 uint32_t offset,
				 odph_ipv4hdr_t *ip,
				 odp_u16sum_t *chksum)
{
	unsigned nleft = ODPH_IPV4HDR_IHL(ip->ver_ihl) * 4;
	uint16_t buf[nleft / 2];
	int res;

	if (odp_unlikely(nleft < sizeof(*ip)))
		return -1;
	ip->chksum = 0;
	memcpy(buf, ip, sizeof(*ip));
	res = odp_packet_copy_to_mem(pkt, offset + sizeof(*ip),
				     nleft - (uint32_t)sizeof(*ip),
				     buf + sizeof(*ip) / 2);
	if (odp_unlikely(res < 0))
		return res;

	*chksum = ~odp_chksum_ones_comp16(buf, nleft);

	return 0;
}

/**
 * Check if IPv4 checksum is valid
 *
 * @param pkt  ODP packet
 *
 * @return 1 if checksum is valid, otherwise 0
 */
static inline int odph_ipv4_csum_valid(odp_packet_t pkt)
{
	uint32_t offset;
	int res;
	odph_ipv4hdr_t ip;
	odp_u16sum_t chksum, cur_chksum;

	offset = odp_packet_l3_offset(pkt);
	if (offset == ODP_PACKET_OFFSET_INVALID)
		return 0;

	res = odp_packet_copy_to_mem(pkt, offset, sizeof(odph_ipv4hdr_t), &ip);
	if (odp_unlikely(res < 0))
		return 0;

	chksum = ip.chksum;

	res = odph_ipv4_csum(pkt, offset, &ip, &cur_chksum);
	if (odp_unlikely(res < 0))
		return 0;

	return (cur_chksum == chksum) ? 1 : 0;
}

/**
 * Calculate and fill in IPv4 checksum
 *
 * @param pkt  ODP packet
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
static inline int odph_ipv4_csum_update(odp_packet_t pkt)
{
	uint32_t offset;
	odph_ipv4hdr_t ip;
	odp_u16sum_t chksum;
	int res;

	offset = odp_packet_l3_offset(pkt);
	if (offset == ODP_PACKET_OFFSET_INVALID)
		return -1;

	res = odp_packet_copy_to_mem(pkt, offset, sizeof(ip), &ip);
	if (odp_unlikely(res < 0))
		return res;

	res = odph_ipv4_csum(pkt, offset, &ip, &chksum);
	if (odp_unlikely(res < 0))
		return res;

	return odp_packet_copy_from_mem(pkt,
					offset + ODPH_IPV4HDR_CSUM_OFFSET,
					2, &chksum);
}

/** IPv6 version */
#define ODPH_IPV6 6

/** IPv6 header length */
#define ODPH_IPV6HDR_LEN 40

/** IPv6 address length in bytes */
#define ODPH_IPV6ADDR_LEN 16

/** The following constants can be used to access the three subfields
 * of the 4 byte ver_tc_flow field - namely the four bit Version subfield,
 * the eight bit Traffic Class subfield (TC) and the twenty bit Flow Label
 * subfield.  Note that the IPv6 TC field is analogous to the IPv4 TOS
 * field and is composed of the DSCP and ECN subfields.  Use the ODPH_IP_TOS_*
 * constants above to access these subfields.
 */
#define ODPH_IPV6HDR_VERSION_MASK     0xF0000000 /**< Version field bit mask */
#define ODPH_IPV6HDR_VERSION_SHIFT    28         /**< Version field shift */
#define ODPH_IPV6HDR_TC_MASK          0x0FF00000 /**< TC field bit mask */
#define ODPH_IPV6HDR_TC_SHIFT         20         /**< TC field shift */
#define ODPH_IPV6HDR_FLOW_LABEL_MASK  0x000FFFFF /**< Flow Label bit mask */
#define ODPH_IPV6HDR_FLOW_LABEL_SHIFT 0          /**< Flow Label shift */

/** @internal Returns IPv6 DSCP */
#define ODPH_IPV6HDR_DSCP(ver_tc_flow) \
	(uint8_t)((((ver_tc_flow) & 0x0fc00000) >> 22) & 0xff)

/**
 * IPv6 header
 */
typedef struct ODP_PACKED {
	odp_u32be_t ver_tc_flow; /**< Version / Traffic class / Flow label */
	odp_u16be_t payload_len; /**< Payload length */
	uint8_t    next_hdr;     /**< Next header */
	uint8_t    hop_limit;    /**< Hop limit */
	uint8_t    src_addr[16]; /**< Source address */
	uint8_t    dst_addr[16]; /**< Destination address */
} odph_ipv6hdr_t;

/** @internal Compile time assert */
ODP_STATIC_ASSERT(sizeof(odph_ipv6hdr_t) == ODPH_IPV6HDR_LEN,
		  "ODPH_IPV6HDR_T__SIZE_ERROR");

/**
 * IPv6 Header extensions
 */
typedef struct ODP_PACKED {
	uint8_t    next_hdr;     /**< Protocol of next header */
	uint8_t    ext_len;      /**< Length of this extension in 8 byte units,
				    not counting first 8 bytes, so 0 = 8 bytes
				    1 = 16 bytes, etc. */
	uint8_t    filler[6];    /**< Fill out first 8 byte segment */
} odph_ipv6hdr_ext_t;

/** @name
 * IP protocol values (IPv4:'proto' or IPv6:'next_hdr')
 * @{*/
#define ODPH_IPPROTO_HOPOPTS 0x00 /**< IPv6 hop-by-hop options */
#define ODPH_IPPROTO_ICMPV4  0x01 /**< Internet Control Message Protocol (1) */
#define ODPH_IPPROTO_IGMP    0x02 /**< Internet Group Message Protocol (1) */
#define ODPH_IPPROTO_TCP     0x06 /**< Transmission Control Protocol (6) */
#define ODPH_IPPROTO_UDP     0x11 /**< User Datagram Protocol (17) */
#define ODPH_IPPROTO_ROUTE   0x2B /**< IPv6 Routing header (43) */
#define ODPH_IPPROTO_FRAG    0x2C /**< IPv6 Fragment (44) */
#define ODPH_IPPROTO_AH      0x33 /**< Authentication Header (51) */
#define ODPH_IPPROTO_ESP     0x32 /**< Encapsulating Security Payload (50) */
#define ODPH_IPPROTO_ICMPV6  0x3A /**< Internet Control Message Protocol (58) */
#define ODPH_IPPROTO_SCTP    0x84 /**< Stream Control Transmission protocol
				       (132) */
#define ODPH_IPPROTO_INVALID 0xFF /**< Reserved invalid by IANA */

/**@}*/

/**
 * Parse IPv4 address from a string
 *
 * Parses IPv4 address from the string which must be passed in the format of
 * four decimal digits delimited by dots (xxx.xxx.xxx.xxx). All four digits
 * have to be present and may have leading zeros. String does not have to be
 * NULL terminated. The address is written only when successful. The address
 * byte order is CPU native.
 *
 * @param[out] ip_addr    Pointer to IPv4 address for output (in native endian)
 * @param      str        IPv4 address string to be parsed
 *
 * @retval 0  on success
 * @retval <0 on failure
 */
int odph_ipv4_addr_parse(uint32_t *ip_addr, const char *str);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif

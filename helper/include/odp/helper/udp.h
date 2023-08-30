/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP UDP header
 */

#ifndef ODPH_UDP_H_
#define ODPH_UDP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>
#include <odp/helper/chksum.h>

/**
 * @addtogroup odph_protocols
 * @{
 */

/** UDP header length */
#define ODPH_UDPHDR_LEN 8

/** UDP header */
typedef struct ODP_PACKED {
	odp_u16be_t src_port; /**< Source port */
	odp_u16be_t dst_port; /**< Destination port */
	odp_u16be_t length;   /**< UDP datagram length in bytes (header+data) */
	odp_u16be_t chksum;   /**< UDP header and data checksum (0 if not used)*/
} odph_udphdr_t;

/**
 * UDP checksum
 *
 * This function calculates the UDP checksum given an odp packet.
 *
 * @param pkt  calculate chksum for pkt
 * @return  checksum value in BE endianness
 */
static inline uint16_t odph_ipv4_udp_chksum(odp_packet_t pkt)
{
	uint16_t chksum;
	int      rc;

	rc = odph_udp_tcp_chksum(pkt, ODPH_CHKSUM_RETURN, &chksum);
	return (rc == 0) ? chksum : 0;
}

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */
ODP_STATIC_ASSERT(sizeof(odph_udphdr_t) == ODPH_UDPHDR_LEN,
		  "ODPH_UDPHDR_T__SIZE_ERROR");
/** @endcond */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

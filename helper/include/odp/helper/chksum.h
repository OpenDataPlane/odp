/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP checksum helper
 */
#ifndef ODPH_CHKSUM_H_
#define ODPH_CHKSUM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_api.h>

/** @defgroup odph_chksum ODPH CHECKSUM
 * TCP/UDP/SCTP checksum
 *
 * @{
 */

/**
 * Chksum Operation Code
 *
 * This enumeration type is used to tell odph_udp_tcp_chksum what to do once
 * it has calculated the TCP/UDP check sum.
 */
typedef enum {
	ODPH_CHKSUM_GENERATE, /**< Set TCP/UDP header chksum field */
	ODPH_CHKSUM_VERIFY,   /**< See if TCP/UDP header chksum is correct */
	ODPH_CHKSUM_RETURN    /**< Don't generate or verify chksum */
} odph_chksum_op_t;

/**
 * General Purpose TCP/UDP checksum function
 *
 * This function handles all the different checksum operations like
 * ODPH_CHKSUM_GENERATE, ODPH_CHKSUM_VERIFY and ODPH_CHKSUM_RETURN for both
 * TCP and UDP pkts over either IPv4 or IPv6.
 * Note that the packet will be modified only if op==ODPH_CHKSUM_GENERATE.
 * In the case of ODPH_CHKSUM_RETURN, the checksum will be calculated, but
 * will neither be written or compared, but just returned via the chksum_ptr
 * parameter (assuming that chksum_ptr is non NULL).  Because the code doesn't
 * know whether a GENERATE or VERIFY is occurring, when using
 * ODPH_CHKSUM_RETURN it is important that the chksum field be well defined
 * (either the value as received or set to 0
 * when created).  Note that for ODPH_CHKSUM_GENERATE, the existing chksum
 * field is ignored (i.e. the code will zero it out before computing the
 * chksum).  See also comments in the convenience functions below.
 *
 * @param  odp_pkt     Calculate the chksum for this pkt and based on the op
 *                     parameter either replace the existing chksum field,
 *                     or verify that it is correct or just return it.
 * @param  op          What is to be done with the calculated chksum.
 *                     doesn't handle tunnels of multiple IPv4/IPv6 headers.
 * @param  chksum_ptr  Pointer to a 16 bit field where the checksum will be
 *                     written.  Note that if this pointer is non NULL, the
 *                     calculated checksum will always be returned regardless
 *                     of op.  Note that the calculated chksum always includes
 *                     the chksum in the TCP or UDP header.
 * @return             Returns < 0 upon an error which prevents the checksum
 *                     calculation. Returns 0 when there is no error AND the
 *                     op is either ODPH_CHKSUM_GENERATE or ODPH_CHKSUM_RETURN.
 *                     If there is no error and the op is ODPH_CHKSUM_VERIFY
 *                     then (a) 1 is returned if this is a UDP pkt whose
 *                     incoming checksum value was 0 (indicating a disabled
 *                     UDP chksum), else (b) 0 is returned if the incoming
 *                     chksum is "correct" (i.e. calculated value is 0),
 *                     else (c) 2 is returned if the incoming chksum is
 *                     incorrect (including the case of an incoming TCP chksum
 *                     of 0).
 */
int odph_udp_tcp_chksum(odp_packet_t     odp_pkt,
			odph_chksum_op_t op,
			uint16_t        *chksum_ptr);

/**
 * Generate TCP checksum
 *
 * This function supports TCP over either IPv4 or IPV6 - including handling
 * any IPv4 header options and any IPv6 extension headers.  However it
 * does not handle tunneled pkts (i.e. any case where there is more than
 * one IPv4/IPv6 header).
 * This function also handles non-contiguous pkts.  In particular it can
 * handle arbitrary packet segmentation, including cases where the segments
 * are not 2 byte aligned, nor have a length that is a multiple of 2.  This
 * function also can handle jumbo frames (at least up to 10K).
 *
 * This function will insert the calculated IP checksum into the proper
 * location in the TCP header.
 *
 * @param  odp_pkt     Calculate and insert chksum for this TCP pkt, which can
 *                     be over IPv4 or IPv6.
 * @return             0 upon success and < 0 upon failure.
 */
static inline int odph_tcp_chksum_set(odp_packet_t odp_pkt)
{
	if (!odp_packet_has_tcp(odp_pkt))
		return -1;

	return odph_udp_tcp_chksum(odp_pkt, ODPH_CHKSUM_GENERATE, NULL);
}

/**
 * Generate UDP checksum
 *
 * This function supports UDP over either IPv4 or IPV6 - including handling
 * any IPv4 header options and any IPv6 extension headers.  However it
 * does not handle tunneled pkts (i.e. any case where there is more than
 * one IPv4/IPv6 header).
 * This function also handles non-contiguous pkts.  In particular it can
 * handle arbitrary packet segmentation, including cases where the segments
 * are not 2 byte aligned, nor have a length that is a multiple of 2.  This
 * function also can handle jumbo frames (at least up to 10K).
 *
 * This function will insert the calculated IP checksum into the proper
 * location in the UDP header.
 *
 * @param  odp_pkt     Calculate and insert chksum for this UDP pkt, which can
 *                     be over IPv4 or IPv6.
 * @return             0 upon success and < 0 upon failure.
 */
static inline int odph_udp_chksum_set(odp_packet_t odp_pkt)
{
	if (!odp_packet_has_udp(odp_pkt))
		return -1;

	return odph_udp_tcp_chksum(odp_pkt, ODPH_CHKSUM_GENERATE, NULL);
}

/**
 * Verify TCP checksum
 *
 * This function supports TCP over either IPv4 or IPV6 - including handling
 * any IPv4 header options and any IPv6 extension headers.  However it
 * does not handle tunneled pkts (i.e. any case where there is more than
 * one IPv4/IPv6 header).
 * This function also handles non-contiguous pkts.  In particular it can
 * handle arbitrary packet segmentation, including cases where the segments
 * are not 2 byte aligned, nor have a length that is a multiple of 2.  This
 * function also can handle jumbo frames (at least up to 10K).
 * Note that since TCP checksums cannot be turned off, an incoming TCP
 * checksum of 0 will return an "incorrect" indication (the value 2).
 *
 * @param  odp_pkt     Calculate and compare the chksum for this TCP pkt,
 *                     which can be over IPv4 or IPv6.
 * @return             Returns < 0 upon an error. Returns 0 upon no error and
 *                     the incoming chksum field is correct, else returns 2
 *                     when the chksum field is incorrect or 0.
 */
static inline int odph_tcp_chksum_verify(odp_packet_t odp_pkt)
{
	if (!odp_packet_has_tcp(odp_pkt))
		return -1;

	return odph_udp_tcp_chksum(odp_pkt, ODPH_CHKSUM_VERIFY, NULL);
}

/**
 * Verify UDP checksum
 *
 * This function supports UDP over either IPv4 or IPV6 - including handling
 * any IPv4 header options and any IPv6 extension headers.  However it
 * does not handle tunneled pkts (i.e. any case where there is more than
 * one IPv4/IPv6 header).
 * This function also handles non-contiguous pkts.  In particular it can
 * handle arbitrary packet segmentation, including cases where the segments
 * are not 2 byte aligned, nor have a length that is a multiple of 2.  This
 * function also can handle jumbo frames (at least up to 10K).
 * Note that UDP checksums can be disabled by setting the incoming UDP
 * chksum field to 0.  In this case this function will return the value 1 -
 * indicating neither a correct or incorrect chksum.
 *
 * @param  odp_pkt     Calculate and compare the chksum for this UDP pkt,
 *                     which can be over IPv4 or IPv6.
 * @return             Returns < 0 upon an error.  Returns 1 upon no error and
 *                     the incoming chksum field is 0 (disabled), else returns 0
 *                     if the incoming chksum field is correct, else returns 2
 *                     when the chksum field is incorrect.
 */
static inline int odph_udp_chksum_verify(odp_packet_t odp_pkt)
{
	if (!odp_packet_has_udp(odp_pkt))
		return -1;

	return odph_udp_tcp_chksum(odp_pkt, ODPH_CHKSUM_VERIFY, NULL);
}

/**
 * Generate SCTP checksum
 *
 * This function supports SCTP over either IPv4 or IPV6 - including handling
 * any IPv4 header options and any IPv6 extension headers.  However it
 * does not handle tunneled pkts (i.e. any case where there is more than
 * one IPv4/IPv6 header).
 * This function also handles non-contiguous pkts.  In particular it can
 * handle arbitrary packet segmentation, including cases where the segments
 * are not 2 byte aligned, nor have a length that is a multiple of 2.  This
 * function also can handle jumbo frames (at least up to 10K).
 *
 * This function will insert the calculated CRC32-c checksum into the proper
 * location in the SCTP header.
 *
 * @param  odp_pkt     Calculate and insert chksum for this SCTP pkt, which can
 *                     be over IPv4 or IPv6.
 * @retval 0 on success
 * @retval <0 on failure
 */
int odph_sctp_chksum_set(odp_packet_t odp_pkt);

/**
 * Verify SCTP checksum
 *
 * This function supports SCTP over either IPv4 or IPV6 - including handling
 * any IPv4 header options and any IPv6 extension headers.  However it
 * does not handle tunneled pkts (i.e. any case where there is more than
 * one IPv4/IPv6 header).
 * This function also handles non-contiguous pkts.  In particular it can
 * handle arbitrary packet segmentation, including cases where the segments
 * are not 2 byte aligned, nor have a length that is a multiple of 2.  This
 * function also can handle jumbo frames (at least up to 10K).
 *
 * @param  odp_pkt     Calculate and compare the chksum for this SCTP pkt,
 *                     which can be over IPv4 or IPv6.
 * @retval <0 on failure
 * @retval 0 if the incoming chksum field is correct
 * @retval 2 when the chksum field is incorrect
 */
int odph_sctp_chksum_verify(odp_packet_t odp_pkt);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

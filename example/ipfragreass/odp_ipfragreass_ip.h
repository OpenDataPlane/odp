/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef ODP_FRAGREASS_PP_IP_H_
#define ODP_FRAGREASS_PP_IP_H_

#include <odp/helper/ip.h>

#define IP_HDR_LEN_MIN	ODPH_IPV4HDR_LEN
#define IP_HDR_LEN_MAX	60
#define IP_IHL_MIN	ODPH_IPV4HDR_IHL_MIN
#define IP_IHL_MAX	15
#define IP_OCTET_MAX	((1U << 14U) - 1U) /* 65535 bytes, 8192 octs, 14 bits */
#define IP_FRAGOFF_MAX	8192 /* 13 bits */

#define IP_FRAG_RESV 0x8000 /**< "Reserved" fragment flag (must be zero) */
#define IP_FRAG_DONT 0x4000 /**< "Don't Fragment" (DF) fragment flag */
#define IP_FRAG_MORE 0x2000 /**< "More Fragments" (MF) fragment flag */
#define IP_FRAG_MASK 0x1fff /**< "Fragment Offset" mask */

#define BYTES_TO_OCTS(bytes)	(((bytes) + 7U) / 8U)
#define OCTS_TO_BYTES(bytes)	((bytes) * 8)
#define WORDS_TO_BYTES(words)	((words) * 4)

/**
 * Initialise an IPv4 header structure
 *
 * @param h A pointer to the header structure to initialise
 */
static inline void ipv4hdr_init(odph_ipv4hdr_t *h)
{
	h->ver_ihl     = 0x45; /* IHL of 5, Version of 4 [0x45 = 0100 0101] */
	h->tos         = 0;
	h->tot_len     = odp_cpu_to_be_16(IP_HDR_LEN_MIN);
	h->frag_offset = 0;
	h->ttl         = UINT8_MAX;
	h->chksum      = 0;
}

/**
 * Get the Internet Header Length (IHL) of an IPv4 header in words
 *
 * @param h The header to get the IHL of
 *
 * @return The IHL of "h" in words
 */
static inline uint8_t ipv4hdr_ihl_words(odph_ipv4hdr_t h)
{
	return ODPH_IPV4HDR_IHL(h.ver_ihl);
}

/**
 * Get the Internet Header Length (IHL) of an IPv4 header in bytes
 *
 * @param h The header to get the IHL of
 *
 * @return The IHL of "h" in bytes
 */
static inline uint8_t ipv4hdr_ihl(odph_ipv4hdr_t h)
{
	return WORDS_TO_BYTES(ipv4hdr_ihl_words(h));
}

/**
 * Set the Internet Header Length (IHL) of an IPv4 header in words
 *
 * @param h   A pointer to the header to set the IHL of
 * @param ihl The new IHL in words
 */
static inline void ipv4hdr_set_ihl_words(odph_ipv4hdr_t *h, uint8_t ihl)
{
	h->ver_ihl = (ODPH_IPV4HDR_VER(h->ver_ihl) << 4)
		     | ODPH_IPV4HDR_IHL(ihl);
}

/**
 * Check whether the "Don't Fragment" (DF) flag is set in an IPv4 header
 *
 * @param h The header to check the DF flag of
 *
 * @return Whether the DF flag is set
 */
static inline bool ipv4hdr_dont_fragment(odph_ipv4hdr_t h)
{
	return (h.frag_offset & odp_cpu_to_be_16(IP_FRAG_DONT));
}

/**
 * Set the "Don't Fragment" (DF) flag of an IPv4 header
 *
 * @param h  A pointer to the header to set the DF of
 * @param df Whether the DF flag should be set or unset
 */
static inline void ipv4hdr_set_dont_fragment(odph_ipv4hdr_t *h, bool df)
{
	if (df)
		h->frag_offset |=  odp_cpu_to_be_16(IP_FRAG_DONT);
	else
		h->frag_offset &= ~odp_cpu_to_be_16(IP_FRAG_DONT);
}

/**
 * Check whether the "More Fragments" (MF) flag is set in an IPv4 header
 *
 * @param h The header to check the MF flag of
 *
 * @return Whether the MF flag is set
 */
static inline bool ipv4hdr_more_fragments(odph_ipv4hdr_t h)
{
	return (h.frag_offset & odp_cpu_to_be_16(IP_FRAG_MORE));
}

/**
 * Set the "More Fragments" (MF) flag of an IPv4 header
 *
 * @param h  A pointer to the header to set the MF of
 * @param mf Whether the MF flag should be set or unset
 */
static inline void ipv4hdr_set_more_fragments(odph_ipv4hdr_t *h, bool mf)
{
	if (mf)
		h->frag_offset |=  odp_cpu_to_be_16(IP_FRAG_MORE);
	else
		h->frag_offset &= ~odp_cpu_to_be_16(IP_FRAG_MORE);
}

/**
 * Check whether an IPv4 header represents an IPv4 fragment or not
 *
 * @param h The header to check
 *
 * @return Whether "h" is the header of an IPv4 fragment or not
 */
static inline bool ipv4hdr_is_fragment(odph_ipv4hdr_t h)
{
	return (h.frag_offset & odp_cpu_to_be_16(IP_FRAG_MORE | IP_FRAG_MASK));
}

/**
 * Get the fragment offset of an IPv4 header in octets
 *
 * @param h The header to get the fragment offset of
 *
 * @return The fragment offset of "h" in octets
 */
static inline uint16_t ipv4hdr_fragment_offset_oct(odph_ipv4hdr_t h)
{
	return (odp_be_to_cpu_16(h.frag_offset) & IP_FRAG_MASK);
}

/**
 * Set the fragment offset of an IPv4 header in octets
 *
 * @param h	 A pointer to the header to set the fragment offset of
 * @param offset The new fragment offset in octets
 */
static inline void ipv4hdr_set_fragment_offset_oct(odph_ipv4hdr_t *h,
						   uint16_t offset)
{
	h->frag_offset = odp_cpu_to_be_16((odp_be_to_cpu_16(h->frag_offset)
					   & ~IP_FRAG_MASK) | offset);
}

/**
 * Get the payload length of an IPv4 header in bytes
 *
 * @param h The header to get the payload length of
 *
 * @return The payload length of "h" in bytes
 */
static inline uint16_t ipv4hdr_payload_len(odph_ipv4hdr_t h)
{
	uint32_t packet_len  = odp_be_to_cpu_16(h.tot_len);
	uint32_t header_size = ipv4hdr_ihl(h);

	return (uint16_t)(packet_len >= header_size ? (packet_len - header_size)
						    : 0);
}

/**
 * Get the payload length of an IPv4 header in octets
 *
 * @param h The header to get the payload length of
 *
 * @return The payload length of "h" in octets
 */
static inline uint16_t ipv4hdr_payload_len_oct(odph_ipv4hdr_t h)
{
	return BYTES_TO_OCTS(ipv4hdr_payload_len(h));
}

/**
 * Set the payload length of an IPv4 header in bytes
 *
 * @param h   A pointer to the header to set the payload length of
 * @param len The new payload length in bytes
 */
static inline void ipv4hdr_set_payload_len(odph_ipv4hdr_t *h, uint16_t len)
{
	h->tot_len = odp_cpu_to_be_16(len + ipv4hdr_ihl(*h));
}

/**
 * Get the upper bound length in bytes of the reassembled payload that this
 * fragment contributes to from an IPv4 header
 *
 * If this is called with the final fragment in a series, the exact length of
 * the reassembled payload is computed. Otherwise, UINT16_MAX is returned.
 *
 * @param h The header to get the reassembled payload length from
 *
 * @return The upper bound for the reassembled payload length of "h" in bytes
 */
static inline uint16_t ipv4hdr_reass_payload_len(odph_ipv4hdr_t h)
{
	uint16_t fragment_offset_oct;

	if (ipv4hdr_more_fragments(h))
		return UINT16_MAX;

	fragment_offset_oct = ipv4hdr_fragment_offset_oct(h);
	return OCTS_TO_BYTES(fragment_offset_oct) + ipv4hdr_payload_len(h);
}

/**
 * Get the upper bound length in octets of the reassembled payload that this
 * fragment contributes to from an IPv4 header
 *
 * If this is called with the final fragment in a series, the exact length of
 * the reassembled payload is computed. Otherwise, IP_OCTET_MAX is returned.
 *
 * @param h The header to estimate the reassembled payload length from
 *
 * @return The estimate for the reassembled payload length of "h" in octets
 */
static inline uint16_t ipv4hdr_reass_payload_len_oct(odph_ipv4hdr_t h)
{
	uint16_t fragment_offset_oct;

	if (ipv4hdr_more_fragments(h))
		return IP_OCTET_MAX;

	fragment_offset_oct = ipv4hdr_fragment_offset_oct(h);
	return fragment_offset_oct + ipv4hdr_payload_len_oct(h);
}

#endif

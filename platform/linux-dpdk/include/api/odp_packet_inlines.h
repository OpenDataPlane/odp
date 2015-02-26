/*
 * odp_packet_inlines.h
 *
 *  Created on: 2 Feb 2015
 *      Author: kz
 */

#ifndef ODP_PACKET_INLINES_H_
#define ODP_PACKET_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

/* This is the offset for packet length inside odp_packet_t. It is defined in
 * odp_packet.c
 */
extern const unsigned int pkt_len_offset;

/**
 * Packet data length
 *
 * Returns sum of data lengths over all packet segments.
 *
 * @param pkt  Packet handle
 *
 * @return Packet data length
 */
static inline uint32_t odp_packet_len(odp_packet_t pkt)
{
	uint32_t accessor = (uint32_t)(((char *)pkt)[pkt_len_offset]);
	return accessor;
}

#ifdef __cplusplus
}
#endif

#endif /* ODP_PACKET_INLINES_H_ */

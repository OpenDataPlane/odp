/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet inline functions
 */

#ifndef ODP_PLAT_PACKET_INLINES_H_
#define ODP_PLAT_PACKET_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#if ODP_ABI_COMPAT == 0

extern const unsigned int buf_addr_offset;
extern const unsigned int data_off_offset;
extern const unsigned int pkt_len_offset;
extern const unsigned int seg_len_offset;
extern const unsigned int udata_len_offset;
extern const unsigned int udata_offset;
extern const unsigned int rss_offset;
extern const unsigned int ol_flags_offset;
extern const uint64_t rss_flag;

#endif /* ODP_ABI_COMPAT */
/*
 * NOTE: These functions are inlined because they are on a performance hot path.
 * As we can't force the application to directly include DPDK headers we have to
 * export these fields through constants calculated compile time in
 * odp_packet.c, where we can see the DPDK definitions.
 *
 */
_STATIC uint32_t odp_packet_len(odp_packet_t pkt)
{
	return *(uint32_t *)(void *)((char *)pkt + pkt_len_offset);
}

_STATIC uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	return *(uint16_t *)(void *)((char *)pkt + seg_len_offset);
}

_STATIC void *odp_packet_user_area(odp_packet_t pkt)
{
	return (void *)((char *)pkt + udata_offset);
}

_STATIC uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	return *(uint32_t *)(void *)((char *)pkt + udata_len_offset);
}

_STATIC void *odp_packet_data(odp_packet_t pkt)
{
	char **buf_addr = (char **)(void *)((char *)pkt + buf_addr_offset);
	uint16_t data_off =
		*(uint16_t *)(void *)((char *)pkt + data_off_offset);

	return (void *)(*buf_addr + data_off);
}

_STATIC uint32_t odp_packet_flow_hash(odp_packet_t pkt)
{
	return *(uint32_t *)(void *)((char *)pkt + rss_offset);
}

_STATIC void odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	*(uint32_t *)(void *)((char *)pkt + rss_offset) = flow_hash;
	*(uint64_t *)(void *)((char *)pkt + ol_flags_offset) |= rss_flag;
}

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_PACKET_INLINES_H_ */

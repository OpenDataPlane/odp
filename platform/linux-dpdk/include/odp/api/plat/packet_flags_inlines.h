/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet flags inline functions
 */

#ifndef ODP_PLAT_PACKET_FLAGS_INLINES_H_
#define ODP_PLAT_PACKET_FLAGS_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const unsigned int ol_flags_offset;
extern const uint64_t rss_flag;

/*
 * NOTE: These functions are inlined because they are on a performance hot path.
 * As we can't force the application to directly include DPDK headers we have to
 * export these fields through constants calculated compile time in
 * odp_packet.c, where we can see the DPDK definitions.
 *
 */
_STATIC int odp_packet_has_flow_hash(odp_packet_t pkt)
{
	return *(uint64_t *)((char *)pkt + ol_flags_offset) & rss_flag;
}

_STATIC void odp_packet_has_flow_hash_clr(odp_packet_t pkt)
{
	*(uint64_t *)((char *)pkt + ol_flags_offset) &= ~rss_flag;
}

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_PACKET_FLAGS_INLINES_H_ */

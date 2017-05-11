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

/** @internal Inline function offsets */
extern const _odp_packet_inline_offset_t _odp_packet_inline;

/*
 * NOTE: These functions are inlined because they are on a performance hot path.
 * As we can't force the application to directly include DPDK headers we have to
 * export these fields through constants calculated compile time in
 * odp_packet.c, where we can see the DPDK definitions.
 *
 */
_ODP_INLINE int odp_packet_has_flow_hash(odp_packet_t pkt)
{
	return *(uint64_t *)((char *)pkt + _odp_packet_inline.ol_flags) &
					   _odp_packet_inline.rss_flag;
}

_ODP_INLINE void odp_packet_has_flow_hash_clr(odp_packet_t pkt)
{
	*(uint64_t *)((char *)pkt + _odp_packet_inline.ol_flags) &=
				    ~_odp_packet_inline.rss_flag;
}

#ifdef __cplusplus
}
#endif

#endif /* ODP_PLAT_PACKET_FLAGS_INLINES_H_ */

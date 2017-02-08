/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * Packet inline functions
 */

#ifndef _ODP_PLAT_PACKET_FLAG_INLINES_API_H_
#define _ODP_PLAT_PACKET_FLAG_INLINES_API_H_

_ODP_INLINE int odp_packet_has_l2(odp_packet_t pkt)
{
	return _odp_packet_has_l2(pkt);
}

_ODP_INLINE int odp_packet_has_eth(odp_packet_t pkt)
{
	return _odp_packet_has_eth(pkt);
}

_ODP_INLINE int odp_packet_has_jumbo(odp_packet_t pkt)
{
	return _odp_packet_has_jumbo(pkt);
}

_ODP_INLINE int odp_packet_has_flow_hash(odp_packet_t pkt)
{
	return _odp_packet_has_flow_hash(pkt);
}

_ODP_INLINE int odp_packet_has_ts(odp_packet_t pkt)
{
	return _odp_packet_has_ts(pkt);
}

#endif

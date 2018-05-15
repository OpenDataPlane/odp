/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * Packet inline functions
 */

#ifndef _ODP_PLAT_PACKET_FLAG_INLINES_H_
#define _ODP_PLAT_PACKET_FLAG_INLINES_H_

#include <odp/api/abi/packet.h>
#include <odp/api/plat/packet_inline_types.h>
#include <odp/api/hints.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

extern const _odp_packet_inline_offset_t _odp_packet_inline;

static inline uint64_t _odp_packet_input_flags(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint64_t, input_flags);
}

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_packet_has_l2 __odp_packet_has_l2
	#define odp_packet_has_eth __odp_packet_has_eth
	#define odp_packet_has_jumbo __odp_packet_has_jumbo
	#define odp_packet_has_flow_hash __odp_packet_has_flow_hash
	#define odp_packet_has_ts __odp_packet_has_ts
	#define odp_packet_has_ipsec __odp_packet_has_ipsec
#else
	#undef _ODP_INLINE
	#define _ODP_INLINE
#endif

_ODP_INLINE int odp_packet_has_l2(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.l2;
}

_ODP_INLINE int odp_packet_has_eth(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.eth;
}

_ODP_INLINE int odp_packet_has_jumbo(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.jumbo;
}

_ODP_INLINE int odp_packet_has_flow_hash(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.flow_hash;
}

_ODP_INLINE int odp_packet_has_ts(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.timestamp;
}

_ODP_INLINE int odp_packet_has_ipsec(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.ipsec;
}

/** @endcond */

#endif

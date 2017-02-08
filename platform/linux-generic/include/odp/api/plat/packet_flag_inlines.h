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

#ifndef _ODP_PLAT_PACKET_FLAG_INLINES_H_
#define _ODP_PLAT_PACKET_FLAG_INLINES_H_

#include <odp/api/plat/packet_types.h>
#include <odp/api/hints.h>

/** @internal Inline function offsets */
extern const _odp_packet_inline_offset_t _odp_packet_inline;

/** @internal Inline function @param pkt @return */
static inline uint64_t _odp_packet_input_flags(odp_packet_t pkt)
{
	return *(uint64_t *)(uintptr_t)((uint8_t *)pkt +
	       _odp_packet_inline.input_flags);
}

/** @internal Inline function @param pkt @return */
static inline int _odp_packet_has_l2(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.l2;
}

/** @internal Inline function @param pkt @return */
static inline int _odp_packet_has_eth(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.eth;
}

/** @internal Inline function @param pkt @return */
static inline int _odp_packet_has_jumbo(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.jumbo;
}

/** @internal Inline function @param pkt @return */
static inline int _odp_packet_has_flow_hash(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.flow_hash;
}

/** @internal Inline function @param pkt @return */
static inline int _odp_packet_has_ts(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.timestamp;
}

/* Include inlined versions of API functions */
#include <odp/api/plat/static_inline.h>
#if ODP_ABI_COMPAT == 0

/** @ingroup odp_packet
 *  @{
 */

#include <odp/api/plat/packet_flag_inlines_api.h>

/**
 * @}
 */

#endif

#endif

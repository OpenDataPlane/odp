/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Nokia
 */

/**
 * @file
 *
 * Packet vector inline functions
 */

#ifndef _ODP_PLAT_PACKET_VECTOR_INLINES_H_
#define _ODP_PLAT_PACKET_VECTOR_INLINES_H_

#include <odp/api/deprecated.h>
#include <odp/api/event.h>
#include <odp/api/packet_types.h>
#include <odp/api/pool_types.h>

#include <odp/api/plat/debug_inlines.h>
#include <odp/api/plat/event_vector_inline_types.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

/*
 * Deprecating inline functions needs special handling. The inline definitions
 * below use the public function name wrapped in ODP_DEPRECATE(), which renames
 * it to a hidden symbol when deprecated APIs are disabled. In ABI compat builds
 * the implementation .c files include this header only after the matching
 * non-inline prototype (of the exact same, possibly renamed, name) is already
 * visible, so emitting the definitions there would clash with that prototype.
 *
 * The definitions are therefore emitted only where they are actually used and
 * cannot clash:
 *   - _ODP_NO_INLINE builds emit the non-inline ABI symbols.
 *   - Inline builds pull this header in early (before the prototypes) via
 *     <odp/api/abi/packet.h>, which sets _ODP_PACKET_VECTOR_ABI_INLINE to
 *     request the static inline definitions.
 * In ABI compat builds neither is set, so no definitions are emitted here and
 * the implementation .c files link against the non-inline ABI symbols instead.
 *
 * This keeps the deprecated-name knowledge entirely inside ODP_DEPRECATE() and
 * avoids spelling out the hidden-symbol prefix anywhere.
 */
#if defined(_ODP_NO_INLINE)
	#define _ODP_INLINE
	#define _ODP_PACKET_VECTOR_DEFINE 1
#elif defined(_ODP_PACKET_VECTOR_ABI_INLINE)
	#define _ODP_INLINE static inline
	#define _ODP_PACKET_VECTOR_DEFINE 1
#else
	#define _ODP_PACKET_VECTOR_DEFINE 0
#endif

#if _ODP_PACKET_VECTOR_DEFINE

_ODP_INLINE odp_packet_vector_t ODP_DEPRECATE(odp_packet_vector_from_event)(odp_event_t ev)
{
	_ODP_ASSERT(odp_event_type(ev) == ODP_DEPRECATE(ODP_EVENT_PACKET_VECTOR));

	return (odp_packet_vector_t)ev;
}

_ODP_INLINE odp_event_t ODP_DEPRECATE(odp_packet_vector_to_event)(odp_packet_vector_t pktv)
{
	return (odp_event_t)pktv;
}

_ODP_INLINE uint32_t ODP_DEPRECATE(odp_packet_vector_tbl)(odp_packet_vector_t pktv,
							  odp_packet_t **pkt_tbl)
{
	*pkt_tbl = _odp_event_vect_get_ptr(pktv, odp_packet_t, event);

	return _odp_event_vect_get(pktv, uint32_t, size);
}

_ODP_INLINE odp_pool_t ODP_DEPRECATE(odp_packet_vector_pool)(odp_packet_vector_t pktv)
{
	return _odp_event_vect_get(pktv, odp_pool_t, pool);
}

_ODP_INLINE uint32_t ODP_DEPRECATE(odp_packet_vector_size)(odp_packet_vector_t pktv)
{
	return _odp_event_vect_get(pktv, uint32_t, size);
}

_ODP_INLINE void ODP_DEPRECATE(odp_packet_vector_size_set)(odp_packet_vector_t pktv, uint32_t size)
{
	uint32_t *vector_size = _odp_event_vect_get_ptr(pktv, uint32_t, size);

	*vector_size = size;
}

_ODP_INLINE void *ODP_DEPRECATE(odp_packet_vector_user_area)(odp_packet_vector_t pktv)
{
	return _odp_event_vect_get(pktv, void *, uarea_addr);
}

_ODP_INLINE int ODP_DEPRECATE(odp_packet_vector_user_flag)(odp_packet_vector_t pktv)
{
	_odp_event_vector_flags_t flags;

	flags.all_flags = _odp_event_vect_get(pktv, uint32_t, flags);

	return flags.user_flag;
}

_ODP_INLINE void ODP_DEPRECATE(odp_packet_vector_user_flag_set)(odp_packet_vector_t pktv, int val)
{
	_odp_event_vector_flags_t *flags = _odp_event_vect_get_ptr(pktv, _odp_event_vector_flags_t,
								   flags);

	flags->user_flag = !!val;
}

#endif /* _ODP_PACKET_VECTOR_DEFINE */

#undef _ODP_PACKET_VECTOR_DEFINE

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif

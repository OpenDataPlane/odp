/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2022-2024 Nokia
 */

/**
 * @file
 *
 * Packet inline functions
 */

#ifndef _ODP_PLAT_PACKET_FLAG_INLINES_H_
#define _ODP_PLAT_PACKET_FLAG_INLINES_H_

#include <odp/api/abi/packet_types.h>
#include <odp/api/plat/packet_inline_types.h>
#include <odp/api/hints.h>

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

static inline uint64_t _odp_packet_input_flags(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint64_t, input_flags);
}

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_packet_has_l2 __odp_packet_has_l2
	#define odp_packet_has_l3 __odp_packet_has_l3
	#define odp_packet_has_l4 __odp_packet_has_l4
	#define odp_packet_has_eth __odp_packet_has_eth
	#define odp_packet_has_jumbo __odp_packet_has_jumbo
	#define odp_packet_has_flow_hash __odp_packet_has_flow_hash
	#define odp_packet_has_flow_hash_clr __odp_packet_has_flow_hash_clr
	#define odp_packet_has_ts __odp_packet_has_ts
	#define odp_packet_has_ipsec __odp_packet_has_ipsec
	#define odp_packet_has_eth_bcast __odp_packet_has_eth_bcast
	#define odp_packet_has_eth_mcast __odp_packet_has_eth_mcast
	#define odp_packet_has_vlan __odp_packet_has_vlan
	#define odp_packet_has_vlan_qinq __odp_packet_has_vlan_qinq
	#define odp_packet_has_arp __odp_packet_has_arp
	#define odp_packet_has_ipv4 __odp_packet_has_ipv4
	#define odp_packet_has_ipv6 __odp_packet_has_ipv6
	#define odp_packet_has_ip_bcast __odp_packet_has_ip_bcast
	#define odp_packet_has_ip_mcast __odp_packet_has_ip_mcast
	#define odp_packet_has_ipfrag __odp_packet_has_ipfrag
	#define odp_packet_has_ipopt __odp_packet_has_ipopt
	#define odp_packet_has_udp __odp_packet_has_udp
	#define odp_packet_has_tcp __odp_packet_has_tcp
	#define odp_packet_has_sctp __odp_packet_has_sctp
	#define odp_packet_has_icmp __odp_packet_has_icmp
	#define odp_packet_has_error __odp_packet_has_error
	#define odp_packet_has_l2_error __odp_packet_has_l2_error
	#define odp_packet_has_l3_error __odp_packet_has_l3_error
	#define odp_packet_has_l4_error __odp_packet_has_l4_error
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

_ODP_INLINE int odp_packet_has_l3(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.l3;
}

_ODP_INLINE int odp_packet_has_l4(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.l4;
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

_ODP_INLINE void odp_packet_has_flow_hash_clr(odp_packet_t pkt)
{
	_odp_packet_input_flags_t *flags = _odp_pkt_get_ptr(pkt, _odp_packet_input_flags_t,
							    input_flags);

	flags->flow_hash = 0;
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

_ODP_INLINE int odp_packet_has_eth_bcast(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.eth_bcast;
}

_ODP_INLINE int odp_packet_has_eth_mcast(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.eth_mcast;
}

_ODP_INLINE int odp_packet_has_vlan(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.vlan;
}

_ODP_INLINE int odp_packet_has_vlan_qinq(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.vlan_qinq;
}

_ODP_INLINE int odp_packet_has_arp(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.arp;
}

_ODP_INLINE int odp_packet_has_ipv4(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.ipv4;
}

_ODP_INLINE int odp_packet_has_ipv6(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.ipv6;
}

_ODP_INLINE int odp_packet_has_ip_bcast(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.ip_bcast;
}

_ODP_INLINE int odp_packet_has_ip_mcast(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.ip_mcast;
}

_ODP_INLINE int odp_packet_has_ipfrag(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.ipfrag;
}

_ODP_INLINE int odp_packet_has_ipopt(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.ipopt;
}

_ODP_INLINE int odp_packet_has_udp(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.udp;
}

_ODP_INLINE int odp_packet_has_tcp(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.tcp;
}

_ODP_INLINE int odp_packet_has_sctp(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.sctp;
}

_ODP_INLINE int odp_packet_has_icmp(odp_packet_t pkt)
{
	_odp_packet_input_flags_t flags;

	flags.all = _odp_packet_input_flags(pkt);
	return flags.icmp;
}

_ODP_INLINE int odp_packet_has_error(odp_packet_t pkt)
{
	_odp_packet_flags_t flags;

	flags.all_flags = _odp_pkt_get(pkt, uint32_t, flags);
	return flags.all.error != 0;
}

_ODP_INLINE int odp_packet_has_l2_error(odp_packet_t pkt)
{
	_odp_packet_flags_t flags;

	flags.all_flags = _odp_pkt_get(pkt, uint32_t, flags);

	/* L2 parsing is always done by default and hence
	no additional check is required. */
	return flags.snap_len_err;
}

_ODP_INLINE int odp_packet_has_l3_error(odp_packet_t pkt)
{
	_odp_packet_flags_t flags;

	flags.all_flags = _odp_pkt_get(pkt, uint32_t, flags);

	return flags.ip_err;
}

_ODP_INLINE int odp_packet_has_l4_error(odp_packet_t pkt)
{
	_odp_packet_flags_t flags;

	flags.all_flags = _odp_pkt_get(pkt, uint32_t, flags);

	return flags.tcp_err | flags.udp_err;
}

/** @endcond */

#endif

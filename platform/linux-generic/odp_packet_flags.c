/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2025 Nokia
 */

#include <odp/api/plat/packet_flag_inlines.h>
#include <odp/api/packet_flags.h>
#include <odp_packet_internal.h>

#define setflag(pkt, x, v) do {                          \
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt); \
	pkt_hdr->p.x = (v) & 1;				 \
	} while (0)

void odp_packet_color_set(odp_packet_t pkt, odp_packet_color_t color)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.input_flags.color = color;
}

void odp_packet_drop_eligible_set(odp_packet_t pkt, odp_bool_t drop)
{
	setflag(pkt, input_flags.nodrop, !drop);
}

void odp_packet_shaper_len_adjust_set(odp_packet_t pkt, int8_t adj)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.flags.shaper_len_adj = adj;
}

/* Set Input Flags */

void odp_packet_has_l2_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.l2, val);
}

void odp_packet_has_l3_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.l3, val);
}

void odp_packet_has_l4_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.l4, val);
}

void odp_packet_has_eth_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.eth, val);
}

void odp_packet_has_eth_bcast_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.eth_bcast, val);
}

void odp_packet_has_eth_mcast_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.eth_mcast, val);
}

void odp_packet_has_jumbo_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.jumbo, val);
}

void odp_packet_has_vlan_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.vlan, val);
	setflag(pkt, input_flags.vlan_qinq, 0);
}

void odp_packet_has_vlan_qinq_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.vlan, val);
	setflag(pkt, input_flags.vlan_qinq, val);
}

void odp_packet_has_arp_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.arp, val);
}

void odp_packet_has_ipv4_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.ipv4, val);
}

void odp_packet_has_ipv6_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.ipv6, val);
}

void odp_packet_has_ip_bcast_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.ip_bcast, val);
}

void odp_packet_has_ip_mcast_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.ip_mcast, val);
}

void odp_packet_has_ipfrag_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.ipfrag, val);
}

void odp_packet_has_ipopt_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.ipopt, val);
}

void odp_packet_has_ipsec_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.ipsec, val);
}

static inline void set_type(odp_packet_t pkt, odp_proto_l4_type_t type, int val)
{
	packet_hdr(pkt)->p.l4_type = val ? type : ODP_PROTO_L4_TYPE_NONE;
}

void odp_packet_has_udp_set(odp_packet_t pkt, int val)
{
	set_type(pkt, ODP_PROTO_L4_TYPE_UDP, val);
}

void odp_packet_has_tcp_set(odp_packet_t pkt, int val)
{
	set_type(pkt, ODP_PROTO_L4_TYPE_TCP, val);
}

void odp_packet_has_sctp_set(odp_packet_t pkt, int val)
{
	set_type(pkt, ODP_PROTO_L4_TYPE_SCTP, val);
}

void odp_packet_has_icmp_set(odp_packet_t pkt, int val)
{
	odp_proto_l4_type_t type = ODP_PROTO_L4_TYPE_NONE;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	if (val) {
		if (pkt_hdr->p.input_flags.ipv6)
			type = ODP_PROTO_L4_TYPE_ICMPV6;
		else
			type = ODP_PROTO_L4_TYPE_ICMPV4;
	}
	pkt_hdr->p.l4_type = type;
}

void odp_packet_has_ts_clr(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	pkt_hdr->p.input_flags.timestamp = 0;
}

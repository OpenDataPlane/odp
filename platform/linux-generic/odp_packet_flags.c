/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp/api/plat/packet_flag_inlines.h>
#include <odp/api/packet_flags.h>
#include <odp_packet_internal.h>

#define retflag(pkt, x) do {                             \
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt); \
	return pkt_hdr->p.x;                             \
	} while (0)

#define setflag(pkt, x, v) do {                          \
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt); \
	pkt_hdr->p.x = (v) & 1;				 \
	} while (0)

int odp_packet_has_error(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.flags.all.error != 0;
}

/* Get Input Flags */

int odp_packet_has_l2_error(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	/* L2 parsing is always done by default and hence
	no additional check is required */
	return pkt_hdr->p.flags.snap_len_err;
}

int odp_packet_has_l3(odp_packet_t pkt)
{
	retflag(pkt, input_flags.l3);
}

int odp_packet_has_l3_error(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.flags.ip_err;
}

int odp_packet_has_l4(odp_packet_t pkt)
{
	retflag(pkt, input_flags.l4);
}

int odp_packet_has_l4_error(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.flags.tcp_err | pkt_hdr->p.flags.udp_err;
}

int odp_packet_has_eth_bcast(odp_packet_t pkt)
{
	retflag(pkt, input_flags.eth_bcast);
}

int odp_packet_has_eth_mcast(odp_packet_t pkt)
{
	retflag(pkt, input_flags.eth_mcast);
}

int odp_packet_has_vlan(odp_packet_t pkt)
{
	retflag(pkt, input_flags.vlan);
}

int odp_packet_has_vlan_qinq(odp_packet_t pkt)
{
	retflag(pkt, input_flags.vlan_qinq);
}

int odp_packet_has_arp(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L3_TYPE_ARP;
}

int odp_packet_has_ipv4(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L3_TYPE_IPV4;
}

int odp_packet_has_ipv6(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L3_TYPE_IPV6;
}

int odp_packet_has_ip_bcast(odp_packet_t pkt)
{
	retflag(pkt, input_flags.ip_bcast);
}

int odp_packet_has_ip_mcast(odp_packet_t pkt)
{
	retflag(pkt, input_flags.ip_mcast);
}

int odp_packet_has_ipfrag(odp_packet_t pkt)
{
	retflag(pkt, input_flags.ipfrag);
}

int odp_packet_has_ipopt(odp_packet_t pkt)
{
	retflag(pkt, input_flags.ipopt);
}

int odp_packet_has_ipsec(odp_packet_t pkt)
{
	retflag(pkt, input_flags.ipsec);
}

int odp_packet_has_udp(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.input_flags.l4_type == ODP_PROTO_L4_TYPE_UDP;
}

int odp_packet_has_tcp(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.input_flags.l4_type == ODP_PROTO_L4_TYPE_TCP;
}

int odp_packet_has_sctp(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.input_flags.l4_type == ODP_PROTO_L4_TYPE_SCTP;
}

int odp_packet_has_icmp(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return pkt_hdr->p.input_flags.l4_type == ODP_PROTO_L4_TYPE_ICMPV4 ||
	       pkt_hdr->p.input_flags.l4_type == ODP_PROTO_L4_TYPE_ICMPV6;
}

odp_packet_color_t odp_packet_color(odp_packet_t pkt)
{
	retflag(pkt, input_flags.color);
}

void odp_packet_color_set(odp_packet_t pkt, odp_packet_color_t color)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	pkt_hdr->p.input_flags.color = color;
}

odp_bool_t odp_packet_drop_eligible(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return !pkt_hdr->p.input_flags.nodrop;
}

void odp_packet_drop_eligible_set(odp_packet_t pkt, odp_bool_t drop)
{
	setflag(pkt, input_flags.nodrop, !drop);
}

int8_t odp_packet_shaper_len_adjust(odp_packet_t pkt)
{
	retflag(pkt, flags.shaper_len_adj);
}

void odp_packet_shaper_len_adjust_set(odp_packet_t pkt, int8_t adj)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

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
}

void odp_packet_has_vlan_qinq_set(odp_packet_t pkt, int val)
{
	setflag(pkt, input_flags.vlan_qinq, val);
}

void odp_packet_has_arp_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (val)
		odp_packet_l3_type_set(pkt, ODP_PROTO_L3_TYPE_ARP);
	else if (pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L3_TYPE_ARP)
		odp_packet_l3_type_set(pkt, ODP_PROTO_L3_TYPE_NONE);
}

void odp_packet_has_ipv4_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (val)
		odp_packet_l3_type_set(pkt, ODP_PROTO_L3_TYPE_IPV4);
	else if (pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L3_TYPE_IPV4)
		odp_packet_l3_type_set(pkt, ODP_PROTO_L3_TYPE_NONE);
}

void odp_packet_has_ipv6_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (val)
		odp_packet_l3_type_set(pkt, ODP_PROTO_L3_TYPE_IPV6);
	else if (pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L3_TYPE_IPV6)
		odp_packet_l3_type_set(pkt, ODP_PROTO_L3_TYPE_NONE);
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

void odp_packet_has_udp_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (val)
		odp_packet_l4_type_set(pkt, ODP_PROTO_L4_TYPE_UDP);
	else if (pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L4_TYPE_UDP)
		odp_packet_l4_type_set(pkt, ODP_PROTO_L4_TYPE_NONE);
}

void odp_packet_has_tcp_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (val)
		odp_packet_l4_type_set(pkt, ODP_PROTO_L4_TYPE_TCP);
	else if (pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L4_TYPE_TCP)
		odp_packet_l4_type_set(pkt, ODP_PROTO_L4_TYPE_NONE);
}

void odp_packet_has_sctp_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (val)
		odp_packet_l4_type_set(pkt, ODP_PROTO_L4_TYPE_SCTP);
	else if (pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L4_TYPE_SCTP)
		odp_packet_l4_type_set(pkt, ODP_PROTO_L4_TYPE_NONE);
}

void odp_packet_has_icmp_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (val && odp_packet_has_ipv6(pkt))
		odp_packet_l4_type_set(pkt, ODP_PROTO_L4_TYPE_ICMPV6);
	else if (val)
		odp_packet_l4_type_set(pkt, ODP_PROTO_L4_TYPE_ICMPV4);
	else if (pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L4_TYPE_ICMPV4)
		odp_packet_l4_type_set(pkt, ODP_PROTO_L4_TYPE_NONE);
	else if (pkt_hdr->p.input_flags.l3_type == ODP_PROTO_L4_TYPE_ICMPV6)
		odp_packet_l4_type_set(pkt, ODP_PROTO_L4_TYPE_NONE);
}

void odp_packet_has_flow_hash_clr(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	pkt_hdr->p.input_flags.flow_hash = 0;
}

void odp_packet_has_ts_clr(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	pkt_hdr->p.input_flags.timestamp = 0;
}

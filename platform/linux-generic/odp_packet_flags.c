/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_packet_flags.h>
#include <odp_packet_internal.h>


int odp_packet_error(odp_packet_t pkt)
{
	return (odp_packet_hdr(pkt)->error_flags.all != 0);
}

/* Get Error Flags */

int odp_packet_errflag_frame_len(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->error_flags.frame_len;
}

/* Get Input Flags */

int odp_packet_has_l2(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.l2;
}

int odp_packet_has_l3(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.l3;
}

int odp_packet_has_l4(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.l4;
}

int odp_packet_has_eth(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.eth;
}

int odp_packet_has_jumbo(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.jumbo;
}

int odp_packet_has_vlan(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.vlan;
}

int odp_packet_has_vlan_qinq(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.vlan_qinq;
}

int odp_packet_has_arp(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.arp;
}

int odp_packet_has_ipv4(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.ipv4;
}

int odp_packet_has_ipv6(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.ipv6;
}

int odp_packet_has_ipfrag(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.ipfrag;
}

int odp_packet_has_ipopt(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.ipopt;
}

int odp_packet_has_ipsec(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.ipsec;
}

int odp_packet_has_udp(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.udp;
}

int odp_packet_has_tcp(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.tcp;
}

int odp_packet_has_sctp(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.sctp;
}

int odp_packet_has_icmp(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.icmp;
}

/* Set Output Flags */

void odp_packet_override_l4_chksum(odp_packet_t pkt)
{
	odp_packet_hdr(pkt)->output_flags.l4_chksum = 1;
}

/* Set Input Flags */

void odp_packet_has_l2_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.l2 = val;
}

void odp_packet_has_l3_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.l3 = val;
}

void odp_packet_has_l4_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.l4 = val;
}

void odp_packet_has_eth_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.eth = val;
}

void odp_packet_has_jumbo_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.jumbo = val;
}

void odp_packet_has_vlan_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.vlan = val;
}

void odp_packet_has_vlan_qinq_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.vlan_qinq = val;
}

void odp_packet_has_arp_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.arp = val;
}

void odp_packet_has_ipv4_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.ipv4 = val;
}

void odp_packet_has_ipv6_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.ipv6 = val;
}

void odp_packet_has_ipfrag_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.ipfrag = val;
}

void odp_packet_has_ipopt_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.ipopt = val;
}

void odp_packet_has_ipsec_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.ipsec = val;
}

void odp_packet_has_udp_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.udp = val;
}

void odp_packet_has_tcp_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.tcp = val;
}

void odp_packet_has_sctp_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.sctp = val;
}

void odp_packet_has_icmp_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->input_flags.icmp = val;
}

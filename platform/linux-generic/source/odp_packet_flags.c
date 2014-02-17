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

int odp_packet_inflag_l2(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.l2;
}

int odp_packet_inflag_l3(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.l3;
}

int odp_packet_inflag_l4(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.l4;
}

int odp_packet_inflag_eth(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.eth;
}

int odp_packet_inflag_jumbo(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.jumbo;
}

int odp_packet_inflag_vlan(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.vlan;
}

int odp_packet_inflag_vlan_qinq(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.vlan_qinq;
}

int odp_packet_inflag_arp(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.arp;
}

int odp_packet_inflag_ipv4(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.ipv4;
}

int odp_packet_inflag_ipv6(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.ipv6;
}

int odp_packet_inflag_ipfrag(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.ipfrag;
}

int odp_packet_inflag_ipopt(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.ipopt;
}

int odp_packet_inflag_ipsec(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.ipsec;
}

int odp_packet_inflag_udp(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.udp;
}

int odp_packet_inflag_tcp(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.tcp;
}

int odp_packet_inflag_sctp(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.sctp;
}

int odp_packet_inflag_icmp(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input_flags.icmp;
}

/* Set Output Flags */

void odp_packet_outflag_l4_chksum(odp_packet_t pkt)
{
	odp_packet_hdr(pkt)->output_flags.l4_chksum = 1;
}


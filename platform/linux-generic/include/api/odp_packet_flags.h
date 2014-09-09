/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet flags
 */

#ifndef ODP_PACKET_FLAGS_H_
#define ODP_PACKET_FLAGS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_packet.h>

/**
 * Check for packet errors
 *
 * Checks all error flags at once.
 *
 * @param pkt Packet handle
 * @return 1 if packet has errors, 0 otherwise
 */
int odp_packet_error(odp_packet_t pkt);

/**
 * Check if error was 'frame length' error
 *
 * @param pkt Packet handle
 * @return 1 if frame length error detected, 0 otherwise
 */
int odp_packet_errflag_frame_len(odp_packet_t pkt);

/**
 * Check for L2 header, e.g. ethernet
 *
 * @param pkt Packet handle
 * @return 1 if packet contains a valid & known L2 header, 0 otherwise
 */
int odp_packet_inflag_l2(odp_packet_t pkt);

/**
 * Check for L3 header, e.g. IPv4, IPv6
 *
 * @param pkt Packet handle
 * @return 1 if packet contains a valid & known L3 header, 0 otherwise
 */
int odp_packet_inflag_l3(odp_packet_t pkt);

/**
 * Check for L4 header, e.g. UDP, TCP, SCTP (also ICMP)
 *
 * @param pkt Packet handle
 * @return 1 if packet contains a valid & known L4 header, 0 otherwise
 */
int odp_packet_inflag_l4(odp_packet_t pkt);

/**
 * Check for Ethernet header
 *
 * @param pkt Packet handle
 * @return 1 if packet contains a valid eth header, 0 otherwise
 */
int odp_packet_inflag_eth(odp_packet_t pkt);

/**
 * Check for jumbo frame
 *
 * @param pkt Packet handle
 * @return 1 if packet contains jumbo frame, 0 otherwise
 */
int odp_packet_inflag_jumbo(odp_packet_t pkt);

/**
 * Check for VLAN
 *
 * @param pkt Packet handle
 * @return 1 if packet contains a VLAN header, 0 otherwise
 */
int odp_packet_inflag_vlan(odp_packet_t pkt);

/**
 * Check for VLAN QinQ (stacked VLAN)
 *
 * @param pkt Packet handle
 * @return 1 if packet contains a VLAN QinQ header, 0 otherwise
 */
int odp_packet_inflag_vlan_qinq(odp_packet_t pkt);

/**
 * Check for ARP
 *
 * @param pkt Packet handle
 * @return 1 if packet contains an ARP header, 0 otherwise
 */
int odp_packet_inflag_arp(odp_packet_t pkt);

/**
 * Check for IPv4
 *
 * @param pkt Packet handle
 * @return 1 if packet contains an IPv4 header, 0 otherwise
 */
int odp_packet_inflag_ipv4(odp_packet_t pkt);

/**
 * Check for IPv6
 *
 * @param pkt Packet handle
 * @return 1 if packet contains an IPv6 header, 0 otherwise
 */
int odp_packet_inflag_ipv6(odp_packet_t pkt);

/**
 * Check for IP fragment
 *
 * @param pkt Packet handle
 * @return 1 if packet is an IP fragment, 0 otherwise
 */
int odp_packet_inflag_ipfrag(odp_packet_t pkt);

/**
 * Check for IP options
 *
 * @param pkt Packet handle
 * @return 1 if packet contains IP options, 0 otherwise
 */
int odp_packet_inflag_ipopt(odp_packet_t pkt);

/**
 * Check for IPSec
 *
 * @param pkt Packet handle
 * @return 1 if packet requires IPSec processing, 0 otherwise
 */
int odp_packet_inflag_ipsec(odp_packet_t pkt);

/**
 * Check for UDP
 *
 * @param pkt Packet handle
 * @return 1 if packet contains a UDP header, 0 otherwise
 */
int odp_packet_inflag_udp(odp_packet_t pkt);

/**
 * Check for TCP
 *
 * @param pkt Packet handle
 * @return 1 if packet contains a TCP header, 0 otherwise
 */
int odp_packet_inflag_tcp(odp_packet_t pkt);

/**
 * Check for SCTP
 *
 * @param pkt Packet handle
 * @return 1 if packet contains an SCTP header, 0 otherwise
 */
int odp_packet_inflag_sctp(odp_packet_t pkt);

/**
 * Check for ICMP
 *
 * @param pkt Packet handle
 * @return 1 if packet contains an ICMP header, 0 otherwise
 */
int odp_packet_inflag_icmp(odp_packet_t pkt);

/**
 * Request L4 checksum calculation
 *
 * @param pkt Packet handle
 */
void odp_packet_outflag_l4_chksum(odp_packet_t pkt);

/**
 * Set flag for L2 header, e.g. ethernet
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_l2(odp_packet_t pkt, int val);

/**
 * Set flag for L3 header, e.g. IPv4, IPv6
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_l3(odp_packet_t pkt, int val);

/**
 * Set flag for L4 header, e.g. UDP, TCP, SCTP (also ICMP)
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_l4(odp_packet_t pkt, int val);

/**
 * Set flag for Ethernet header
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_eth(odp_packet_t pkt, int val);

/**
 * Set flag for jumbo frame
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_jumbo(odp_packet_t pkt, int val);

/**
 * Set flag for VLAN
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_vlan(odp_packet_t pkt, int val);

/**
 * Set flag for VLAN QinQ (stacked VLAN)
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_vlan_qinq(odp_packet_t pkt, int val);

/**
 * Set flag for ARP
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_arp(odp_packet_t pkt, int val);

/**
 * Set flag for IPv4
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_ipv4(odp_packet_t pkt, int val);

/**
 * Set flag for IPv6
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_ipv6(odp_packet_t pkt, int val);

/**
 * Set flag for IP fragment
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_ipfrag(odp_packet_t pkt, int val);

/**
 * Set flag for IP options
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_ipopt(odp_packet_t pkt, int val);

/**
 * Set flag for IPSec
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_ipsec(odp_packet_t pkt, int val);

/**
 * Set flag for UDP
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_udp(odp_packet_t pkt, int val);

/**
 * Set flag for TCP
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_tcp(odp_packet_t pkt, int val);

/**
 * Set flag for SCTP
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_sctp(odp_packet_t pkt, int val);

/**
 * Set flag for ICMP
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_set_inflag_icmp(odp_packet_t pkt, int val);

#ifdef __cplusplus
}
#endif

#endif

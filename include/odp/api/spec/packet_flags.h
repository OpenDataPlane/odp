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

#ifndef ODP_API_PACKET_FLAGS_H_
#define ODP_API_PACKET_FLAGS_H_
#include <odp/api/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/packet.h>

/** @addtogroup odp_packet
 *  Boolean operations on a packet.
 *  @{
 */

/**
 * Check for packet errors
 *
 * Checks all error flags at once.
 *
 * @param pkt Packet handle
 * @retval non-zero packet has errors
 * @retval 0 packet has no errors
 */
int odp_packet_has_error(odp_packet_t pkt);

/**
 * Check for packet L2 errors
 *
 * check for all L2 errors
 *
 * @param pkt Packet handle
 * @retval non-zero packet has L2 errors
 * @retval 0 packet has no L2 error
 */
int odp_packet_has_l2_error(odp_packet_t pkt);

/**
 * Check for L2 header, e.g. ethernet
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a valid & known L2 header
 * @retval 0 if packet does not contain a valid & known L2 header
 */
int odp_packet_has_l2(odp_packet_t pkt);

/**
 * Check for packet L3 errors
 *
 * check for all L3 errors
 *
 * @param pkt Packet handle
 * @retval non-zero packet has L3 errors
 * @retval 0 packet has no L3 error
 */
int odp_packet_has_l3_error(odp_packet_t pkt);

/**
 * Check for L3 header, e.g. IPv4, IPv6
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a valid & known L3 header
 * @retval 0 if packet does not contain a valid & known L3 header
 */
int odp_packet_has_l3(odp_packet_t pkt);

/**
 * Check for packet L4 errors
 *
 * check for all L4 errors
 *
 * @param pkt Packet handle
 * @retval non-zero packet has L4 errors
 * @retval 0 packet has no L4 error
 */
int odp_packet_has_l4_error(odp_packet_t pkt);

/**
 * Check for L4 header, e.g. UDP, TCP, SCTP (also ICMP)
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a valid & known L4 header
 * @retval 0 if packet does not contain a valid & known L4 header
 */
int odp_packet_has_l4(odp_packet_t pkt);

/**
 * Check for Ethernet header
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a valid eth header
 * @retval 0 if packet does not contain a valid eth header
 */
int odp_packet_has_eth(odp_packet_t pkt);

/**
 * Check for Ethernet broadcast address
 *
 * ODP recognizes the destination MAC address FF:FF:FF:FF:FF:FF as
 * a broadcast address. All others are considered non-broadcast.
 *
 * @param pkt Packet handle
 * @retval non-zero if Ethernet destination address is the broadcast address
 * @retval 0 if Ethernet destination address is not the broadcast address
 */
int odp_packet_has_eth_bcast(odp_packet_t pkt);

/**
 * Check for Ethernet multicast address
 *
 * ODP recognizes the destination MAC address as multicast if bit 7 is 1.
 *
 * @param pkt Packet handle
 * @retval non-zero if Ethernet destination address is a multicast address
 * @retval 0 if Ethernet destination address is not a multicast address
 */
int odp_packet_has_eth_mcast(odp_packet_t pkt);

/**
 * Check for jumbo frame
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a jumbo frame
 * @retval 0 if packet does not contain a jumbo frame
 */
int odp_packet_has_jumbo(odp_packet_t pkt);

/**
 * Check for VLAN
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a VLAN header
 * @retval 0 if packet does not contain a VLAN header
 */
int odp_packet_has_vlan(odp_packet_t pkt);

/**
 * Check for VLAN QinQ (stacked VLAN)
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a VLAN QinQ header
 * @retval 0 if packet does not contain a VLAN QinQ header
 */
int odp_packet_has_vlan_qinq(odp_packet_t pkt);

/**
 * Check for ARP
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains an ARP message
 * @retval 0 if packet does not contain an ARP message
 */
int odp_packet_has_arp(odp_packet_t pkt);

/**
 * Check for IPv4
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains an IPv4 header
 * @retval 0 if packet does not contain an IPv4 header
 */
int odp_packet_has_ipv4(odp_packet_t pkt);

/**
 * Check for IPv6
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains an IPv6 header
 * @retval 0 if packet does not contain an IPv6 header
 */
int odp_packet_has_ipv6(odp_packet_t pkt);

/**
 * Check for IP broadcast address
 *
 * For IPv4, ODP recognizes the destination IP address 255.255.255.255 as
 * a broadcast address. All other addresses are considered non-broadcast.
 *
 * For IPv6, no destination addresses are recognized as broadcast addresses.
 *
 * @param pkt Packet handle
 * @retval non-zero if IP destination address is a broadcast address
 * @retval 0 if IP destination address is not a broadcast address
 */
int odp_packet_has_ip_bcast(odp_packet_t pkt);

/**
 * Check for IP multicast address
 *
 * For IPv4 ODP recognizes destination IP addresses in the range 224.0.0.0
 * through 239.255.255.255 as multicast addresses.
 *
 * For IPv6 ODP recognizes destination IP addresses with prefixes FF00::
 * through FFFF:: as multicast addresses.
 *
 * @param pkt Packet handle
 * @retval non-zero if IP destination address is a multicast address
 * @retval 0 if IP destination address is not a multicast address
 */
int odp_packet_has_ip_mcast(odp_packet_t pkt);

/**
 * Check for IP fragment
 *
 * @param pkt Packet handle
 * @retval non-zero if packet is an IP fragment
 * @retval 0 if packet is not an IP fragment
 */
int odp_packet_has_ipfrag(odp_packet_t pkt);

/**
 * Check for IP options
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains IP options
 * @retval 0 if packet does not contain IP options
 */
int odp_packet_has_ipopt(odp_packet_t pkt);

/**
 * Check for IPSec
 *
 * @param pkt Packet handle
 * @retval non-zero if packet requires IPSec processing
 * @retval 0 if packet does not require IPSec processing
 */
int odp_packet_has_ipsec(odp_packet_t pkt);

/**
 * Check for UDP
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a UDP header
 * @retval 0 if packet does not contain a UDP header
 */
int odp_packet_has_udp(odp_packet_t pkt);

/**
 * Check for TCP
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a TCP header
 * @retval 0 if packet does not contain a TCP header
 */
int odp_packet_has_tcp(odp_packet_t pkt);

/**
 * Check for SCTP
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a SCTP header
 * @retval 0 if packet does not contain a SCTP header
 */
int odp_packet_has_sctp(odp_packet_t pkt);

/**
 * Check for ICMP
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains an ICMP header
 * @retval 0 if packet does not contain an ICMP header
 */
int odp_packet_has_icmp(odp_packet_t pkt);

/**
 * Check for packet flow hash
 *
 * @param pkt Packet handle
 * @retval non-zero if packet contains a hash value
 * @retval 0 if packet does not contain a hash value
 */
int odp_packet_has_flow_hash(odp_packet_t pkt);

/**
 * Check for packet timestamp
 *
 * @param pkt Packet handle
 *
 * @retval non-zero if packet contains a timestamp value
 * @retval 0 if packet does not contain a timestamp value
 *
 * @see odp_packet_has_ts_clr()
 */
int odp_packet_has_ts(odp_packet_t pkt);

/**
 * Set flag for L2 header, e.g. ethernet
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_l2_set(odp_packet_t pkt, int val);

/**
 * Set flag for L3 header, e.g. IPv4, IPv6
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_l3_set(odp_packet_t pkt, int val);

/**
 * Set flag for L4 header, e.g. UDP, TCP, SCTP (also ICMP)
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_l4_set(odp_packet_t pkt, int val);

/**
 * Set flag for Ethernet header
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_eth_set(odp_packet_t pkt, int val);

/**
 * Set flag for Ethernet broadcast address
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_eth_bcast_set(odp_packet_t pkt, int val);

/**
 * Set flag for Ethernet multicast address
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_eth_mcast_set(odp_packet_t pkt, int val);

/**
 * Set flag for jumbo frame
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_jumbo_set(odp_packet_t pkt, int val);

/**
 * Set flag for VLAN
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_vlan_set(odp_packet_t pkt, int val);

/**
 * Set flag for VLAN QinQ (stacked VLAN)
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_vlan_qinq_set(odp_packet_t pkt, int val);

/**
 * Set flag for ARP
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_arp_set(odp_packet_t pkt, int val);

/**
 * Set flag for IPv4
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_ipv4_set(odp_packet_t pkt, int val);

/**
 * Set flag for IPv6
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_ipv6_set(odp_packet_t pkt, int val);

/**
 * Set flag for IP broadcast address
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_ip_bcast_set(odp_packet_t pkt, int val);

/**
 * Set flag for IP multicast address
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_ip_mcast_set(odp_packet_t pkt, int val);

/**
 * Set flag for IP fragment
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_ipfrag_set(odp_packet_t pkt, int val);

/**
 * Set flag for IP options
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_ipopt_set(odp_packet_t pkt, int val);

/**
 * Set flag for IPSec
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_ipsec_set(odp_packet_t pkt, int val);

/**
 * Set flag for UDP
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_udp_set(odp_packet_t pkt, int val);

/**
 * Set flag for TCP
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_tcp_set(odp_packet_t pkt, int val);

/**
 * Set flag for SCTP
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_sctp_set(odp_packet_t pkt, int val);

/**
 * Set flag for ICMP
 *
 * @param pkt Packet handle
 * @param val Value
 */
void odp_packet_has_icmp_set(odp_packet_t pkt, int val);

/**
 * Clear flag for packet flow hash
 *
 * @param pkt Packet handle
 *
 * @note Set this flag is only possible through odp_packet_flow_hash_set()
 */
void odp_packet_has_flow_hash_clr(odp_packet_t pkt);

/**
 * Clear flag for packet timestamp
 *
 * This call clears the timestamp flag. A odp_packet_ts_set() call sets
 * the flag in addition to the timestamp value.
 *
 * @param pkt Packet handle
 *
 * @see odp_packet_has_ts(), odp_packet_ts_set()
 */
void odp_packet_has_ts_clr(odp_packet_t pkt);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/api/visibility_end.h>
#endif

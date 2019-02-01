/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet flags
 */

#ifndef ODP_API_SPEC_PACKET_FLAGS_H_
#define ODP_API_SPEC_PACKET_FLAGS_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/packet.h>

/** @addtogroup odp_packet
 *  Operations on packet metadata flags.
 *  @{
 */

/**
 * Check for all errors in packet
 *
 * Check if packet parsing has found any errors in the packet. The level of
 * error checking depends on the parse configuration (e.g. included layers and
 * checksums). Protocol layer functions (e.g. odp_packet_has_l3()) indicate
 * which layers have been checked, and layer error functions
 * (e.g. odp_packet_has_l3_error()) which layers have errors.
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet has errors
 * @retval 0           No errors were found
 */
int odp_packet_has_error(odp_packet_t pkt);

/**
 * Check for errors in layer 2
 *
 * When layer 2 is included in the parse configuration, check if any errors were
 * found in layer 2 of the packet.
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet has errors in layer 2
 * @retval 0           No errors were found in layer 2
 */
int odp_packet_has_l2_error(odp_packet_t pkt);

/**
 * Check for errors in layer 3
 *
 * When layer 3 is included in the parse configuration, check if any errors were
 * found in layer 3 of the packet.
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet has errors in layer 3
 * @retval 0           No errors found in layer 3
 */
int odp_packet_has_l3_error(odp_packet_t pkt);

/**
 * Check for errors in layer 4
 *
 * When layer 4 is included in the parse configuration, check if any errors were
 * found in layer 4 of the packet.
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet has errors in layer 4
 * @retval 0           No errors were found in layer 4
 */
int odp_packet_has_l4_error(odp_packet_t pkt);

/**
 * Check for layer 2 protocols
 *
 * When layer 2 is included in the parse configuration, check if packet parsing
 * has found and checked a layer 2 protocol (e.g. Ethernet) in the packet.
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    A layer 2 protocol header was found and checked
 * @retval 0           No layer 2 protocol was found
 */
int odp_packet_has_l2(odp_packet_t pkt);

/**
 * Check for layer 3 protocols
 *
 * When layer 3 is included in the parse configuration, check if packet parsing
 * has found and checked a layer 3 protocol (e.g. IPv4, IPv6) in the packet.
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    A layer 3 protocol header was found and checked
 * @retval 0           No layer 3 protocol was found
 */
int odp_packet_has_l3(odp_packet_t pkt);

/**
 * Check for layer 4 protocols
 *
 * When layer 4 is included in the parse configuration, check if packet parsing
 * has found and checked a layer 4 protocol (e.g. UDP, TCP, SCTP) in the packet.
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    A layer 4 protocol header was found and checked
 * @retval 0           No layer 4 protocol was found
 */
int odp_packet_has_l4(odp_packet_t pkt);

/**
 * Check for Ethernet header
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains an Ethernet header
 * @retval 0           Packet does not contain an Ethernet header
 */
int odp_packet_has_eth(odp_packet_t pkt);

/**
 * Check for Ethernet broadcast address
 *
 * ODP recognizes the destination MAC address FF:FF:FF:FF:FF:FF as
 * a broadcast address. All others are considered non-broadcast.
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Ethernet destination address is the broadcast address
 * @retval 0           Ethernet destination address is not the broadcast address
 */
int odp_packet_has_eth_bcast(odp_packet_t pkt);

/**
 * Check for Ethernet multicast address
 *
 * ODP recognizes the destination MAC address as multicast if bit 7 is 1.
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Ethernet destination address is a multicast address
 * @retval 0           Ethernet destination address is not a multicast address
 */
int odp_packet_has_eth_mcast(odp_packet_t pkt);

/**
 * Check for jumbo frame
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet is a jumbo frame
 * @retval 0           Packet is not a jumbo frame
 */
int odp_packet_has_jumbo(odp_packet_t pkt);

/**
 * Check for VLAN
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains a VLAN header
 * @retval 0           Packet does not contain a VLAN header
 */
int odp_packet_has_vlan(odp_packet_t pkt);

/**
 * Check for VLAN QinQ (stacked VLAN)
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains a VLAN QinQ header
 * @retval 0           Packet does not contain a VLAN QinQ header
 */
int odp_packet_has_vlan_qinq(odp_packet_t pkt);

/**
 * Check for ARP
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains an ARP message
 * @retval 0           Packet does not contain an ARP message
 */
int odp_packet_has_arp(odp_packet_t pkt);

/**
 * Check for IPv4
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains an IPv4 header
 * @retval 0           Packet does not contain an IPv4 header
 */
int odp_packet_has_ipv4(odp_packet_t pkt);

/**
 * Check for IPv6
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains an IPv6 header
 * @retval 0           Packet does not contain an IPv6 header
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
 * @param pkt          Packet handle
 *
 * @retval non-zero    IP destination address is a broadcast address
 * @retval 0           IP destination address is not a broadcast address
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
 * @param pkt          Packet handle
 *
 * @retval non-zero    IP destination address is a multicast address
 * @retval 0           IP destination address is not a multicast address
 */
int odp_packet_has_ip_mcast(odp_packet_t pkt);

/**
 * Check for IP fragment
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet is an IP fragment
 * @retval 0           Packet is not an IP fragment
 */
int odp_packet_has_ipfrag(odp_packet_t pkt);

/**
 * Check for IP options
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains IP options
 * @retval 0           Packet does not contain IP options
 */
int odp_packet_has_ipopt(odp_packet_t pkt);

/**
 * Check for IPSec
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet requires IPSec processing
 * @retval 0           Packet does not require IPSec processing
 */
int odp_packet_has_ipsec(odp_packet_t pkt);

/**
 * Check for UDP
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains a UDP header
 * @retval 0           Packet does not contain a UDP header
 */
int odp_packet_has_udp(odp_packet_t pkt);

/**
 * Check for TCP
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains a TCP header
 * @retval 0           Packet does not contain a TCP header
 */
int odp_packet_has_tcp(odp_packet_t pkt);

/**
 * Check for SCTP
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains a SCTP header
 * @retval 0           Packet does not contain a SCTP header
 */
int odp_packet_has_sctp(odp_packet_t pkt);

/**
 * Check for ICMP
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains an ICMP header
 * @retval 0           Packet does not contain an ICMP header
 */
int odp_packet_has_icmp(odp_packet_t pkt);

/**
 * Check for packet flow hash
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains a hash value
 * @retval 0           Packet does not contain a hash value
 */
int odp_packet_has_flow_hash(odp_packet_t pkt);

/**
 * Check for packet timestamp
 *
 * @param pkt          Packet handle
 *
 * @retval non-zero    Packet contains a timestamp value
 * @retval 0           Packet does not contain a timestamp value
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

#include <odp/visibility_end.h>
#endif

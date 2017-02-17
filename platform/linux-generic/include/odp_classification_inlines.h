/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Classification Inlines
 * Classification Inlines Functions
 */
#ifndef __ODP_CLASSIFICATION_INLINES_H_
#define __ODP_CLASSIFICATION_INLINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/debug.h>
#include <protocols/eth.h>
#include <protocols/ip.h>
#include <protocols/ipsec.h>
#include <protocols/udp.h>
#include <protocols/tcp.h>
#include <odp_packet_internal.h>
#include <stdio.h>
#include <inttypes.h>

/* PMR term value verification function
These functions verify the given PMR term value with the value in the packet
These following functions return 1 on success and 0 on failure
*/

static inline int verify_pmr_packet_len(odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	if (term_value->match.value == (packet_len(pkt_hdr) &
				     term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ip_proto(const uint8_t *pkt_addr,
				      odp_packet_hdr_t *pkt_hdr,
				      pmr_term_value_t *term_value)
{
	const _odp_ipv4hdr_t *ip;
	uint8_t proto;
	if (!pkt_hdr->p.input_flags.ipv4)
		return 0;
	ip = (const _odp_ipv4hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);
	proto = ip->proto;
	if (term_value->match.value == (proto & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipv4_saddr(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ipv4hdr_t *ip;
	uint32_t ipaddr;
	if (!pkt_hdr->p.input_flags.ipv4)
		return 0;
	ip = (const _odp_ipv4hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);
	ipaddr = odp_be_to_cpu_32(ip->src_addr);
	if (term_value->match.value == (ipaddr & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipv4_daddr(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ipv4hdr_t *ip;
	uint32_t ipaddr;
	if (!pkt_hdr->p.input_flags.ipv4)
		return 0;
	ip = (const _odp_ipv4hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);
	ipaddr = odp_be_to_cpu_32(ip->dst_addr);
	if (term_value->match.value == (ipaddr & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_tcp_sport(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint16_t sport;
	const _odp_tcphdr_t *tcp;
	if (!pkt_hdr->p.input_flags.tcp)
		return 0;
	tcp = (const _odp_tcphdr_t *)(pkt_addr + pkt_hdr->p.l4_offset);
	sport = odp_be_to_cpu_16(tcp->src_port);
	if (term_value->match.value == (sport & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_tcp_dport(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint16_t dport;
	const _odp_tcphdr_t *tcp;
	if (!pkt_hdr->p.input_flags.tcp)
		return 0;
	tcp = (const _odp_tcphdr_t *)(pkt_addr + pkt_hdr->p.l4_offset);
	dport = odp_be_to_cpu_16(tcp->dst_port);
	if (term_value->match.value == (dport & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_udp_dport(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint16_t dport;
	const _odp_udphdr_t *udp;
	if (!pkt_hdr->p.input_flags.udp)
		return 0;
	udp = (const _odp_udphdr_t *)(pkt_addr + pkt_hdr->p.l4_offset);
	dport = odp_be_to_cpu_16(udp->dst_port);
	if (term_value->match.value == (dport & term_value->match.mask))
			return 1;

	return 0;
}

static inline int verify_pmr_udp_sport(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint16_t sport;
	const _odp_udphdr_t *udp;

	if (!pkt_hdr->p.input_flags.udp)
		return 0;
	udp = (const _odp_udphdr_t *)(pkt_addr + pkt_hdr->p.l4_offset);
	sport = odp_be_to_cpu_16(udp->src_port);
	if (term_value->match.value == (sport & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_dmac(const uint8_t *pkt_addr,
				  odp_packet_hdr_t *pkt_hdr,
				  pmr_term_value_t *term_value)
{
	uint64_t dmac = 0;
	uint64_t dmac_be = 0;
	const _odp_ethhdr_t *eth;

	if (!packet_hdr_has_eth(pkt_hdr))
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	memcpy(&dmac_be, eth->dst.addr, _ODP_ETHADDR_LEN);
	dmac = odp_be_to_cpu_64(dmac_be);
	/* since we are converting a 48 bit ethernet address from BE to cpu
	format using odp_be_to_cpu_64() the last 16 bits needs to be right
	shifted */
	if (dmac_be != dmac)
		dmac = dmac >> (64 - (_ODP_ETHADDR_LEN * 8));

	if (term_value->match.value == (dmac & term_value->match.mask))
		return 1;
	return 0;
}

static inline int verify_pmr_ipv6_saddr(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ipv6hdr_t *ipv6;
	uint64_t addr[2];

	if (!packet_hdr_has_ipv6(pkt_hdr))
		return 0;

	ipv6 = (const _odp_ipv6hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);

	addr[0] = ipv6->src_addr.u64[0];
	addr[1] = ipv6->src_addr.u64[1];

	/* 128 bit address is processed as two 64 bit value
	* for bitwise AND operation */
	addr[0] = addr[0] & term_value->match_ipv6.mask.u64[0];
	addr[1] = addr[1] & term_value->match_ipv6.mask.u64[1];

	if (!memcmp(addr, term_value->match_ipv6.addr.u8, _ODP_IPV6ADDR_LEN))
		return 1;

	return 0;
}

static inline int verify_pmr_ipv6_daddr(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ipv6hdr_t *ipv6;
	uint64_t addr[2];

	if (!packet_hdr_has_ipv6(pkt_hdr))
		return 0;
	ipv6 = (const _odp_ipv6hdr_t *)(pkt_addr + pkt_hdr->p.l3_offset);
	addr[0] = ipv6->dst_addr.u64[0];
	addr[1] = ipv6->dst_addr.u64[1];

	/* 128 bit address is processed as two 64 bit value
	* for bitwise AND operation */
	addr[0] = addr[0] & term_value->match_ipv6.mask.u64[0];
	addr[1] = addr[1] & term_value->match_ipv6.mask.u64[1];

	if (!memcmp(addr, term_value->match_ipv6.addr.u8, _ODP_IPV6ADDR_LEN))
		return 1;

	return 0;
}

static inline int verify_pmr_vlan_id_0(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	const _odp_ethhdr_t *eth;
	const _odp_vlanhdr_t *vlan;
	uint16_t tci;
	uint16_t vlan_id;

	if (!pkt_hdr->p.input_flags.vlan_qinq)
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	vlan = (const _odp_vlanhdr_t *)(eth + 1);
	tci = odp_be_to_cpu_16(vlan->tci);
	vlan_id = tci & 0x0fff;

	if (term_value->match.value == (vlan_id & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_vlan_id_x(const uint8_t *pkt_addr ODP_UNUSED,
				       odp_packet_hdr_t *pkt_hdr ODP_UNUSED,
				       pmr_term_value_t *term_value ODP_UNUSED)
{
	const _odp_ethhdr_t *eth;
	const _odp_vlanhdr_t *vlan;
	uint16_t tci;
	uint16_t vlan_id;

	if (!pkt_hdr->p.input_flags.vlan_qinq)
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	vlan = (const _odp_vlanhdr_t *)(eth + 1);
	vlan++;
	tci = odp_be_to_cpu_16(vlan->tci);
	vlan_id = tci & 0x0fff;

	if (term_value->match.value == (vlan_id & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ipsec_spi(const uint8_t *pkt_addr,
				       odp_packet_hdr_t *pkt_hdr,
				       pmr_term_value_t *term_value)
{
	uint32_t spi;

	pkt_addr += pkt_hdr->p.l4_offset;

	if (pkt_hdr->p.input_flags.ipsec_ah) {
		const _odp_ahhdr_t *ahhdr = (const _odp_ahhdr_t *)pkt_addr;

		spi = odp_be_to_cpu_32(ahhdr->spi);
	} else if (pkt_hdr->p.input_flags.ipsec_esp) {
		const _odp_esphdr_t *esphdr = (const _odp_esphdr_t *)pkt_addr;

		spi = odp_be_to_cpu_32(esphdr->spi);
	} else {
		return 0;
	}

	if (term_value->match.value == (spi & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_ld_vni(const uint8_t *pkt_addr ODP_UNUSED,
				    odp_packet_hdr_t *pkt_hdr ODP_UNUSED,
				    pmr_term_value_t *term_value ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static inline int verify_pmr_custom_frame(const uint8_t *pkt_addr,
					  odp_packet_hdr_t *pkt_hdr,
					  pmr_term_value_t *term_value)
{
	uint64_t val = 0;
	uint32_t offset = term_value->offset;
	uint32_t val_sz = term_value->val_sz;

	ODP_ASSERT(val_sz <= ODP_PMR_TERM_BYTES_MAX);

	if (packet_len(pkt_hdr) <= offset + val_sz)
		return 0;

	memcpy(&val, pkt_addr + offset, val_sz);
	if (term_value->match.value == (val & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_eth_type_0(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ethhdr_t *eth;
	uint16_t ethtype;

	if (!pkt_hdr->p.input_flags.vlan_qinq)
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	ethtype = odp_be_to_cpu_16(eth->type);

	if (term_value->match.value == (ethtype & term_value->match.mask))
		return 1;

	return 0;
}

static inline int verify_pmr_eth_type_x(const uint8_t *pkt_addr,
					odp_packet_hdr_t *pkt_hdr,
					pmr_term_value_t *term_value)
{
	const _odp_ethhdr_t *eth;
	uint16_t ethtype;
	const _odp_vlanhdr_t *vlan;

	if (!pkt_hdr->p.input_flags.vlan_qinq)
		return 0;

	eth = (const _odp_ethhdr_t *)(pkt_addr + pkt_hdr->p.l2_offset);
	vlan = (const _odp_vlanhdr_t *)(eth + 1);
	ethtype = odp_be_to_cpu_16(vlan->type);

	if (term_value->match.value == (ethtype & term_value->match.mask))
		return 1;

	return 0;
}
#ifdef __cplusplus
}
#endif
#endif

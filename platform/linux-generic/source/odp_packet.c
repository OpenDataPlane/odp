/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_packet.h>
#include <odp_packet_internal.h>
#include <odp_hints.h>
#include <odp_byteorder.h>

#include <helper/odp_eth.h>
#include <helper/odp_ip.h>

#include <string.h>
#include <stdio.h>

void odp_packet_init(odp_packet_t pkt)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	const size_t start_offset = ODP_FIELD_SIZEOF(odp_packet_hdr_t, buf_hdr);
	uint8_t *start;
	size_t len;

	start = (uint8_t *)pkt_hdr + start_offset;
	len = ODP_OFFSETOF(odp_packet_hdr_t, payload) - start_offset;
	memset(start, 0, len);
}

odp_packet_t odp_packet_from_buffer(odp_buffer_t buf)
{
	return (odp_packet_t)buf;
}

odp_buffer_t odp_buffer_from_packet(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}

void odp_packet_set_len(odp_packet_t pkt, size_t len)
{
	odp_packet_hdr(pkt)->frame_len = len;
}

size_t odp_packet_get_len(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->frame_len;
}

uint8_t *odp_packet_buf_addr(odp_packet_t pkt)
{
	return odp_buffer_addr(odp_buffer_from_packet(pkt));
}


uint8_t *odp_packet_l2(odp_packet_t pkt)
{
	return odp_packet_buf_addr(pkt) + odp_packet_l2_offset(pkt);
}

size_t odp_packet_l2_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l2_offset;
}

void odp_packet_set_l2_offset(odp_packet_t pkt, size_t offset)
{
	odp_packet_hdr(pkt)->l2_offset = offset;
}


uint8_t *odp_packet_l3(odp_packet_t pkt)
{
	return odp_packet_buf_addr(pkt) + odp_packet_l3_offset(pkt);
}

size_t odp_packet_l3_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l3_offset;
}

void odp_packet_set_l3_offset(odp_packet_t pkt, size_t offset)
{
	odp_packet_hdr(pkt)->l3_offset = offset;
}


uint8_t *odp_packet_l4(odp_packet_t pkt)
{
	return odp_packet_buf_addr(pkt) + odp_packet_l4_offset(pkt);
}

size_t odp_packet_l4_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l4_offset;
}

void odp_packet_set_l4_offset(odp_packet_t pkt, size_t offset)
{
	odp_packet_hdr(pkt)->l4_offset = offset;
}

/**
 * Simple packet parser: eth, VLAN, IP, TCP/UDP/ICMP
 *
 * Internal function: caller is resposible for passing only valid packet handles
 * , lengths and offsets (usually done&called in packet input).
 *
 * @param pkt        Packet handle
 * @param len        Packet length in bytes
 * @param l2_offset  Byte offset to L2 header
 */
void odp_packet_parse(odp_packet_t pkt, size_t len, size_t l2_offset)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	odp_ethhdr_t *eth;
	odp_vlanhdr_t *vlan;
	odp_ipv4hdr_t *ip;
	uint16_t ethtype;
	size_t offset = 0;


	pkt_hdr->frame_len = len;
	if (odp_unlikely(len < ODP_ETH_LEN_MIN))
		pkt_hdr->error_flags.frame_len = 1;

	pkt_hdr->input_flags.l2 = 1;
	pkt_hdr->l2_offset = l2_offset;
	eth = (odp_ethhdr_t *)odp_packet_l2(pkt);

	ethtype = odp_be_to_cpu_16(eth->type);
	vlan = (odp_vlanhdr_t *)&eth->type;

	if (ethtype == ODP_ETHTYPE_VLAN_OUTER) {
		pkt_hdr->input_flags.vlan_qinq = 1;
		ethtype = odp_be_to_cpu_16(vlan->tpid);
		offset += sizeof(odp_vlanhdr_t);
		vlan = &vlan[1];
	}

	if (ethtype == ODP_ETHTYPE_VLAN) {
		pkt_hdr->input_flags.vlan = 1;
		ethtype = odp_be_to_cpu_16(vlan->tpid);
		offset += sizeof(odp_vlanhdr_t);
	}

	pkt_hdr->input_flags.l3 = 1;
	pkt_hdr->l3_offset = l2_offset + ODP_ETHHDR_LEN + offset;

	if (ethtype == ODP_ETHTYPE_IPV4) {
		uint8_t ihl;

		pkt_hdr->input_flags.ipv4 = 1;
		ip = (odp_ipv4hdr_t *)odp_packet_l3(pkt);

		ihl = ODP_IPV4HDR_IHL(ip->ver_ihl);
		if (odp_unlikely(ihl < ODP_IPV4HDR_IHL_MIN)) {
			pkt_hdr->error_flags.ip_err = 1;
			return;
		}

		pkt_hdr->input_flags.l4 = 1;
		pkt_hdr->l4_offset = pkt_hdr->l3_offset +
				     sizeof(uint32_t) * ihl;

		switch (ip->proto) {
		case ODP_IPPROTO_UDP:
			pkt_hdr->input_flags.udp = 1;
			break;
		case ODP_IPPROTO_TCP:
			pkt_hdr->input_flags.tcp = 1;
			break;
		case ODP_IPPROTO_ICMP:
			pkt_hdr->input_flags.icmp = 1;
			break;
		}
	}
}

void odp_packet_print(odp_packet_t pkt)
{
	int max_len = 512;
	char str[max_len];
	int len = 0;
	int n = max_len-1;
	odp_packet_hdr_t *hdr = odp_packet_hdr(pkt);

	len += snprintf(&str[len], n-len, "Packet ");
	len += odp_buffer_snprint(&str[len], n-len, (odp_buffer_t) pkt);
	len += snprintf(&str[len], n-len,
			"  l2_offset    %u\n", hdr->l2_offset);
	len += snprintf(&str[len], n-len,
			"  l3_offset    %u\n", hdr->l3_offset);
	len += snprintf(&str[len], n-len,
			"  l4_offset    %u\n", hdr->l4_offset);
	str[len] = '\0';

	printf("\n%s\n", str);
}


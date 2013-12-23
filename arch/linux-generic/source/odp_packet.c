/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_packet.h>
#include <odp_packet_internal.h>

#include <string.h>
#include <stdio.h>

void odp_packet_init(odp_packet_t pkt)
{
	(void)pkt;
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

uint8_t *odp_packet_payload(odp_packet_t pkt)
{
	return odp_buffer_addr(odp_buffer_from_packet(pkt));
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
			"  l2_offset    %zu\n", hdr->l2_offset);
	len += snprintf(&str[len], n-len,
			"  l3_offset    %zu\n", hdr->l3_offset);
	len += snprintf(&str[len], n-len,
			"  l4_offset    %zu\n", hdr->l4_offset);
	str[len] = 0;

	printf("\n%s\n", str);
}


/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	 BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>

#include <assert.h>
#include <arpa/inet.h>

#include "odp_ipfragreass_helpers.h"
#include "odp_ipfragreass_ip.h"

#define IP_SRC_ADDR 0xC0A80001 /* 192.168.0.1 */
#define IP_DST_ADDR 0xC0A80002 /* 192.168.0.2 */

static void set_random_payload(odp_packet_t packet, uint32_t payload_offset,
			       uint32_t size)
{
	uint32_t i, j;
	unsigned char *buffer;
	unsigned char seed = rand() % (UINT8_MAX + 1);
	uint32_t bytes_remaining = 0;

	/*
	 * Set the payload to a run of consecutive numbers from a random seed.
	 * Not completely random as some structure is good for debugging.
	 */
	for (i = 0; i < size; ++i) {
		buffer = odp_packet_offset(packet, payload_offset + i,
					   &bytes_remaining, NULL);
		for (j = 0; i < size && j < bytes_remaining; ++j, ++i)
			buffer[j] = (unsigned char)(seed + i);
	}
}

odp_packet_t pack_udp_ipv4_packet(odp_pool_t pool, odp_u16be_t ip_id,
				  uint32_t max_size, uint32_t min_size)
{
	odp_packet_t result;
	unsigned char *buffer;
	odph_ipv4hdr_t *header;
	uint32_t size;
	uint32_t header_len;
	uint32_t header_len_words;

	size = (rand() % (max_size - min_size)) + min_size;
	result = odp_packet_alloc(pool, size);
	if (result == ODP_PACKET_INVALID)
		return ODP_PACKET_INVALID;
	odp_packet_ts_set(result, odp_time_global());

	/* Set the IPv4 header */
	header_len_words = (rand() % (IP_IHL_MAX - IP_IHL_MIN + 1));
	header_len_words += IP_IHL_MIN;
	header_len = WORDS_TO_BYTES(header_len_words);
	assert(header_len >= IP_HDR_LEN_MIN && header_len <= IP_HDR_LEN_MAX);
	odp_packet_l3_offset_set(result, 0);
	odp_packet_has_ipv4_set(result, 1);
	buffer = odp_packet_data(result);
	header = (odph_ipv4hdr_t *)buffer;
	ipv4hdr_init(header);
	header->id = odp_cpu_to_be_16(ip_id);
	header->proto = ODPH_IPPROTO_UDP;
	header->src_addr = odp_cpu_to_be_32(IP_SRC_ADDR);
	header->dst_addr = odp_cpu_to_be_32(IP_DST_ADDR);
	ipv4hdr_set_ihl_words(header, header_len_words);
	ipv4hdr_set_payload_len(header, size - header_len);
	header->chksum = 0;
	odph_ipv4_csum_update(result);

	/* Set the payload */
	size -= header_len;
	set_random_payload(result, header_len, size);

	return result;
}

void shuffle(odp_packet_t *packets, int num_packets)
{
	int i;

	if (num_packets <= 1)
		return;

	for (i = 0; i < num_packets; ++i) {
		odp_packet_t tmp = packets[i];
		int j = rand() % num_packets;

		packets[i] = packets[j];
		packets[j] = tmp;
	}
}

int packet_memcmp(odp_packet_t a, odp_packet_t b, uint32_t offset_a,
		  uint32_t offset_b, uint32_t length)
{
	uint32_t i = 0;
	void *data_a, *data_b;
	uint32_t bytes_remaining_a = 0;
	uint32_t bytes_remaining_b = 0;

	while (i < length) {
		int status;
		uint32_t bytes_remaining;

		data_a = odp_packet_offset(a, offset_a + i, &bytes_remaining_a,
					   NULL);
		data_b = odp_packet_offset(b, offset_b + i, &bytes_remaining_b,
					   NULL);
		bytes_remaining = min(bytes_remaining_a, bytes_remaining_b);
		bytes_remaining = min(bytes_remaining, length - i);
		assert(bytes_remaining != 0 && data_a && data_b);

		status = memcmp(data_a, data_b, bytes_remaining);
		if (status != 0)
			return status;
		i += bytes_remaining;
	}

	return 0;
}

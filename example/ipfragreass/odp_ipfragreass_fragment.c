/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <stdio.h>
#include <assert.h>

#include "odp_ipfragreass_ip.h"
#include "odp_ipfragreass_fragment.h"

int fragment_ipv4_packet(odp_packet_t orig_packet, odp_packet_t *out,
			 int *out_len)
{
	int fragments = 0;
	odp_bool_t first_fragment = 1;
	odph_ipv4hdr_t *orig_header = odp_packet_data(orig_packet);
	uint32_t header_len = ipv4hdr_ihl(*orig_header);
	uint32_t orig_len = odp_packet_len(orig_packet);
	uint32_t bytes_remaining = orig_len - header_len;
	uint32_t frag_offset = 0;
	odp_packet_t frag = orig_packet;
	odp_packet_t rest = ODP_PACKET_INVALID;

	if (bytes_remaining <= MTU)
		return -1;

	/*
	 * The main fragmentation loop (continue until all bytes from the
	 * original payload have been assigned to a fragment)
	 */
	while (bytes_remaining) {
		odph_ipv4hdr_t *header;
		uint32_t frag_len;

		frag_len = (bytes_remaining > MTU ? (MTU + header_len)
						  : (bytes_remaining
						     + header_len));
		bytes_remaining -= (frag_len - header_len);
		if (bytes_remaining) {
			uint32_t split_point;
			int split_success;

			split_point = first_fragment ? (frag_len)
						     : (frag_len - header_len);
			split_success = odp_packet_split(&frag, split_point,
							 &rest);
			if (split_success < 0) {
				fprintf(stderr,
					"ERROR: odp_packet_split\n");
				return -1;
			} else if (first_fragment && split_success > 0) {
				orig_header = odp_packet_data(frag);
			}
		}

		/* Add a header to the packet if necessary */
		if (first_fragment) {
			first_fragment = 0;
		} else {
			if (odp_packet_extend_head(&frag, header_len, NULL,
						   NULL) < 0) {
				fprintf(stderr,
					"ERROR: odp_packet_extend_head\n");
				return -1;
			}
			if (odp_packet_copy_from_mem(frag, 0, header_len,
						     orig_header)) {
				fprintf(stderr,
					"ERROR: odp_packet_copy_from_mem\n");
				return -1;
			}
		}

		/* Update the header */
		header = odp_packet_data(frag);
		ipv4hdr_set_more_fragments(header, bytes_remaining != 0);
		header->tot_len = odp_cpu_to_be_16(frag_len);
		ipv4hdr_set_fragment_offset_oct(header, (frag_offset / 8));
		assert((bytes_remaining == 0) ||
		       (odp_packet_len(frag) == (MTU + header_len)));
		assert((bytes_remaining != 0) ||
		       (ipv4hdr_reass_payload_len(*header) + header_len
			== orig_len));
		odp_packet_l3_offset_set(frag, 0);
		header->chksum = 0;
		odph_ipv4_csum_update(frag);

		out[fragments++] = frag;
		frag = rest;
		frag_offset += (frag_len - header_len);
	}

	if (out_len)
		*out_len = fragments;

	return 0;
}

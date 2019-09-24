/* Copyright (c) 2016-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <odp/helper/sctp.h>
#include <odp/helper/tcp.h>
#include <odp/helper/chksum.h>
#include <stddef.h>
#include <stdbool.h>

/* The following union type is used to "view" an ordered set of bytes (either
 * 2 or 4) as 1 or 2 16-bit quantities - using host endian order. */
typedef union {
	uint16_t words16[2];
	uint8_t  bytes[4];
} swap_buf_t;

typedef union {
	odph_udphdr_t udp_hdr;
	odph_tcphdr_t tcp_hdr;
} odph_l4_hdr_t;

static uint8_t ZEROS[2] = { 0, 0 };

/* Note that for data_seg_sum byte_len MUST be >= 1.  This function Returns the
 * sum of the data (as described by data8_ptr and data_len) as 16-bit
 * integers. */

static uint32_t data_seg_sum(uint8_t   *data8_ptr,
			     uint32_t   data_len,   /* length in bytes */
			     odp_bool_t is_last,
			     odp_bool_t has_odd_byte_in,
			     uint8_t   *odd_byte_in_out)
{
	swap_buf_t swap_buf;
	uint32_t   sum, len_in_16_byte_chunks, idx, data0, data1, data2, data3;
	uint32_t   data4, data5, data6, data7;
	uint16_t  *data16_ptr;

	sum = 0;
	if (has_odd_byte_in) {
		swap_buf.bytes[0] = *odd_byte_in_out;
		swap_buf.bytes[1] = *data8_ptr++;
		sum              += (uint32_t)swap_buf.words16[0];
		data_len--;
	}

	data16_ptr = (uint16_t *)(void *)data8_ptr;

	/* The following code tries to gain a modest performance enhancement by
	 * unrolling the normal 16 bits at a time loop eight times.  Even
	 * better would be to add some data prefetching instructions here. */
	len_in_16_byte_chunks = data_len / 16;
	for (idx = 0; idx < len_in_16_byte_chunks; idx++) {
		data0 = (uint32_t)*data16_ptr++;
		data1 = (uint32_t)*data16_ptr++;
		data2 = (uint32_t)*data16_ptr++;
		data3 = (uint32_t)*data16_ptr++;
		data4 = (uint32_t)*data16_ptr++;
		data5 = (uint32_t)*data16_ptr++;
		data6 = (uint32_t)*data16_ptr++;
		data7 = (uint32_t)*data16_ptr++;

		data_len -= 16;
		sum      += data0 + data1;
		sum      += data2 + data3;
		sum      += data4 + data5;
		sum      += data6 + data7;
	}

	for (idx = 0; idx < data_len / 2; idx++)
		sum += (uint32_t)*data16_ptr++;

	if ((data_len & 1) == 0)
		return sum;

	/* Now handle the case of a single odd byte. */
	if (is_last) {
		swap_buf.bytes[0] = *(uint8_t *)data16_ptr;
		swap_buf.bytes[1] = 0;
		sum              += (uint32_t)swap_buf.words16[0];
	} else {
		*odd_byte_in_out = *(uint8_t *)data16_ptr;
	}

	return sum;
}

static inline int odph_process_l4_hdr(odp_packet_t      odp_pkt,
				      odph_chksum_op_t  op,
				      odph_l4_hdr_t    *udp_tcp_hdr,
				      uint16_t         *chksum_ptr,
				      uint32_t         *l4_len_ptr,
				      odp_bool_t       *split_l4_hdr_ptr,
				      odp_bool_t       *is_tcp_ptr,
				      uint32_t         *pkt_chksum_offset_ptr,
				      uint16_t        **pkt_chksum_ptr_ptr)
{
	odph_udphdr_t  *udp_hdr_ptr;
	odph_tcphdr_t  *tcp_hdr_ptr;
	odp_bool_t      split_l4_hdr, is_tcp;
	uint32_t        l4_offset, l4_len, pkt_chksum_offset;
	uint16_t       *pkt_chksum_ptr;
	uint8_t        *l4_ptr;
	uint32_t hdr_len = 0;

	/* Parse the TCP/UDP header. */
	l4_offset         = odp_packet_l4_offset(odp_pkt);
	l4_ptr            = odp_packet_l4_ptr(odp_pkt, &hdr_len);
	pkt_chksum_offset = l4_offset;
	l4_len            = 0;
	split_l4_hdr      = false;
	is_tcp            = false;

	if (odp_packet_has_udp(odp_pkt)) {
		udp_hdr_ptr  = (odph_udphdr_t *)l4_ptr;
		split_l4_hdr = hdr_len < ODPH_UDPHDR_LEN;
		if (split_l4_hdr) {
			udp_hdr_ptr = &udp_tcp_hdr->udp_hdr;
			odp_packet_copy_to_mem(odp_pkt, l4_offset,
					       ODPH_UDPHDR_LEN, udp_hdr_ptr);
		}

		/* According to the spec's the l4_len to be used for UDP pkts
		 * should come from the udp header, unlike for TCP where is
		 * derived. */
		l4_len            = odp_be_to_cpu_16(udp_hdr_ptr->length);
		pkt_chksum_ptr    = (uint16_t *)(void *)&udp_hdr_ptr->chksum;
		pkt_chksum_offset = l4_offset + offsetof(odph_udphdr_t, chksum);
	} else if (odp_packet_has_tcp(odp_pkt)) {
		tcp_hdr_ptr  = (odph_tcphdr_t *)l4_ptr;
		split_l4_hdr = hdr_len < ODPH_TCPHDR_LEN;
		if (split_l4_hdr) {
			tcp_hdr_ptr = &udp_tcp_hdr->tcp_hdr;
			odp_packet_copy_to_mem(odp_pkt, l4_offset,
					       ODPH_TCPHDR_LEN, tcp_hdr_ptr);
		}

		pkt_chksum_ptr    = (uint16_t *)(void *)&tcp_hdr_ptr->cksm;
		pkt_chksum_offset = l4_offset + offsetof(odph_tcphdr_t, cksm);
		is_tcp            = true;
	} else {
		return -1;
	}

	/* Note that if the op is ODPH_CHKSUM_VERIFY and the existing
	 * chksum field is 0 and this is a UDP pkt and the chksum_ptr is NULL
	 * then skip the rest of the chksum calculation, returning 1 instead. */
	if ((op == ODPH_CHKSUM_VERIFY) && (*pkt_chksum_ptr == 0) &&
	    (!is_tcp) && (chksum_ptr == NULL))
		return 1;

	/* If we are doing a ODPH_CHKSUM_GENERATE op, then make sure that the
	 * existing chksum field has been set to zeros. */
	if ((op == ODPH_CHKSUM_GENERATE) && (*pkt_chksum_ptr != 0)) {
		if (split_l4_hdr)
			odp_packet_copy_from_mem(odp_pkt, pkt_chksum_offset,
						 2, ZEROS);
		else
			*pkt_chksum_ptr = 0;
	}

	*l4_len_ptr            = l4_len;
	*split_l4_hdr_ptr      = split_l4_hdr;
	*is_tcp_ptr            = is_tcp;
	*pkt_chksum_offset_ptr = pkt_chksum_offset;
	*pkt_chksum_ptr_ptr    = pkt_chksum_ptr;
	return 0;
}

/* odph_process_l3_hdr includes the 16-bit sum of the pseudo header. */

static inline int odph_process_l3_hdr(odp_packet_t odp_pkt,
				      odp_bool_t   is_tcp,
				      uint32_t    *l4_len_ptr,
				      uint32_t    *sum_ptr)
{
	odph_ipv4hdr_t *ipv4_hdr_ptr, ipv4_hdr;
	odph_ipv6hdr_t *ipv6_hdr_ptr, ipv6_hdr;
	odp_bool_t      split_l3_hdr;
	swap_buf_t      swap_buf;
	uint32_t        l3_offset, l4_offset, l3_hdrs_len, addrs_len;
	uint32_t        protocol, l3_len, l4_len, idx, ipv6_payload_len, sum;
	uint16_t       *addrs_ptr;
	uint32_t hdr_len = 0;

	/* The following computation using the l3 and l4 offsets handles both
	 * the case of IPv4 options and IPv6 extension headers uniformly. */
	l3_offset   = odp_packet_l3_offset(odp_pkt);
	l4_offset   = odp_packet_l4_offset(odp_pkt);
	l3_hdrs_len = l4_offset - l3_offset;

	/* Parse the IPv4/IPv6 header. */
	split_l3_hdr = false;
	if (odp_packet_has_ipv4(odp_pkt)) {
		ipv4_hdr_ptr = odp_packet_l3_ptr(odp_pkt, &hdr_len);
		split_l3_hdr = hdr_len < ODPH_IPV4HDR_LEN;
		if (split_l3_hdr) {
			odp_packet_copy_to_mem(odp_pkt, l3_offset,
					       ODPH_IPV4HDR_LEN, &ipv4_hdr);
			ipv4_hdr_ptr = &ipv4_hdr;
		}

		addrs_ptr = (uint16_t *)(void *)&ipv4_hdr_ptr->src_addr;
		addrs_len = 2 * ODPH_IPV4ADDR_LEN;
		protocol  = ipv4_hdr_ptr->proto;
		l3_len    = odp_be_to_cpu_16(ipv4_hdr_ptr->tot_len);
	} else if (odp_packet_has_ipv6(odp_pkt)) {
		ipv6_hdr_ptr = odp_packet_l3_ptr(odp_pkt, &hdr_len);
		split_l3_hdr = hdr_len < ODPH_IPV6HDR_LEN;
		if (split_l3_hdr) {
			odp_packet_copy_to_mem(odp_pkt, l3_offset,
					       ODPH_IPV6HDR_LEN, &ipv6_hdr);
			ipv6_hdr_ptr = &ipv6_hdr;
		}

		addrs_ptr        = (uint16_t *)(void *)&ipv6_hdr_ptr->src_addr;
		addrs_len        = 2 * ODPH_IPV6ADDR_LEN;
		protocol         = ipv6_hdr_ptr->next_hdr;
		ipv6_payload_len = odp_be_to_cpu_16(ipv6_hdr_ptr->payload_len);
		l3_len           = ipv6_payload_len + ODPH_IPV6HDR_LEN;
	} else {
		return -1;
	}

	/* For UDP pkts, must use the incoming l4_len taken from the udp header.
	 * For tcp pkts the l4_len is derived from the l3_len and l3_hdrs_len
	 * calculated above. */
	l4_len = is_tcp ? (l3_len - l3_hdrs_len) : *l4_len_ptr;

	/* Do a one's complement addition over the IP pseudo-header.
	 * Note that the pseudo-header is different for IPv4 and IPv6. */
	sum = 0;
	for (idx = 0; idx < addrs_len / 2; idx++)
		sum += (uint32_t)*addrs_ptr++;

	/* Need to convert l4_len and protocol into endian independent form */
	swap_buf.bytes[0] = (l4_len >> 8) & 0xFF;
	swap_buf.bytes[1] = (l4_len >> 0) & 0xFF;
	swap_buf.bytes[2] = 0;
	swap_buf.bytes[3] = protocol;

	sum += (uint32_t)swap_buf.words16[0] + (uint32_t)swap_buf.words16[1];

	*l4_len_ptr = l4_len;
	*sum_ptr    = sum;
	return 0;
}

/* Note that this implementation does not including any code or conditionally
 * modified code that is endian specific, yet it works equally well on BIG or
 * LITTLE endian machines.  The reason that this works is primarily because
 * a 16-bit one's complement sum happens to be "endian-agnostic".  Specifically
 * if one does a sum of 16-bit pkt values on a big endian machine and then on
 * a little endian machine, they will not agree.  But after turning it into
 * a one's complement sum by adding the carry bits in and truncating to
 * 16-bits (which may need to be done more than once), the final 16-bit results
 * will be byte-swapped versions of the other.  Then after storing the result
 * back into the pkt (as a 16-bit value), the final byte pattern will be
 * identical for both machines. */

int odph_udp_tcp_chksum(odp_packet_t     odp_pkt,
			odph_chksum_op_t op,
			uint16_t        *chksum_ptr)
{
	odph_l4_hdr_t    udp_tcp_hdr;
	odp_bool_t       split_l4_hdr, is_tcp, is_last;
	odp_bool_t       has_odd_byte_in;
	uint32_t         l4_len, sum, ones_compl_sum;
	uint32_t         data_len, pkt_chksum_offset, offset;
	uint16_t        *pkt_chksum_ptr, chksum;
	uint8_t         *data_ptr, odd_byte_in_out;
	int              rc, ret_code;
	uint32_t remaining_seg_len = 0;

	/* First parse and process the l4 header */
	rc = odph_process_l4_hdr(odp_pkt, op, &udp_tcp_hdr, chksum_ptr, &l4_len,
				 &split_l4_hdr, &is_tcp, &pkt_chksum_offset,
				 &pkt_chksum_ptr);
	if (rc != 0)
		return rc;

	/* Note that in addition to parsing the l3 header, this function
	 * does the sum of the pseudo header. */
	rc = odph_process_l3_hdr(odp_pkt, is_tcp, &l4_len, &sum);
	if (rc != 0)
		return rc;

	/* The following code handles all of the different cases where the
	 * data to be checksummed might be split among an arbitrary number of
	 * segments, each of an arbitrary length (include odd alignments!). */
	data_ptr        = odp_packet_l4_ptr(odp_pkt, &remaining_seg_len);
	offset          = odp_packet_l4_offset(odp_pkt);
	has_odd_byte_in = false;
	odd_byte_in_out = 0;

	while (true) {
		data_len = remaining_seg_len;
		is_last  = false;
		if (l4_len < remaining_seg_len)
			data_len = l4_len;
		else if (l4_len == remaining_seg_len)
			is_last = true;

		sum += data_seg_sum(data_ptr, data_len, is_last,
				    has_odd_byte_in, &odd_byte_in_out);
		l4_len  -= data_len;
		if (l4_len == 0)
			break;

		if (data_len & 1)
			has_odd_byte_in = !has_odd_byte_in;

		offset  += data_len;
		data_ptr = odp_packet_offset(odp_pkt, offset,
					     &remaining_seg_len, NULL);
	}

	/* Now do the one's complement "carry" algorithm.  Up until now this
	 * has just been regular two's complement addition.  Note that it is
	 * important that this regular sum of 16-bit quantities be done with
	 * at least 32-bit arithmetic to prevent the loss of the carries.
	 * Note that it can be proven that only two rounds of the carry
	 * wrap around logic are necessary (assuming 32-bit arithmetic and
	 * a data length of < 64K). */
	ones_compl_sum = (sum              & 0xFFFF) + (sum            >> 16);
	ones_compl_sum = (ones_compl_sum   & 0xFFFF) + (ones_compl_sum >> 16);
	chksum         = (~ones_compl_sum) & 0xFFFF;
	ret_code       = 0;

	/* Now based upon the given op, the calculated chksum and the incoming
	 * chksum value complete the operation. */
	if (op == ODPH_CHKSUM_GENERATE) {
		if (split_l4_hdr)
			odp_packet_copy_from_mem(odp_pkt, pkt_chksum_offset,
						 2, &chksum);
		else
			*pkt_chksum_ptr = chksum;
	} else if (op == ODPH_CHKSUM_VERIFY) {
		if ((*pkt_chksum_ptr == 0) && (!is_tcp))
			ret_code = 1;
		else
			ret_code = (chksum == 0) ? 0 : 2;
	}

	if (chksum_ptr != NULL)
		*chksum_ptr = chksum;

	return ret_code;
}

static uint32_t odph_packet_crc32c(odp_packet_t pkt,
				   uint32_t offset,
				   uint32_t length,
				   uint32_t init_val)
{
	uint32_t sum = init_val;

	if (offset + length > odp_packet_len(pkt))
		return sum;

	while (length > 0) {
		uint32_t seg_len = 0;
		void *data = odp_packet_offset(pkt, offset, &seg_len, NULL);

		if (seg_len > length)
			seg_len = length;

		sum = odp_hash_crc32c(data, seg_len, sum);
		length -= seg_len;
		offset += seg_len;
	}

	return sum;
}

int odph_sctp_chksum_set(odp_packet_t pkt)
{
	uint32_t l4_offset = odp_packet_l4_offset(pkt);
	uint32_t sum = 0;

	if (!odp_packet_has_sctp(pkt))
		return -1;

	if (l4_offset == ODP_PACKET_OFFSET_INVALID)
		return -1;

	odp_packet_copy_from_mem(pkt,
				 l4_offset + ODPH_SCTPHDR_LEN - 4,
				 4,
				 &sum);

	sum = ~odph_packet_crc32c(pkt, l4_offset,
				  odp_packet_len(pkt) - l4_offset,
				  ~0);
	return odp_packet_copy_from_mem(pkt,
					l4_offset + ODPH_SCTPHDR_LEN - 4,
					4,
					&sum);
}

int odph_sctp_chksum_verify(odp_packet_t pkt)
{
	uint32_t l4_offset = odp_packet_l4_offset(pkt);
	uint32_t sum;
	uint32_t temp = 0;

	if (!odp_packet_has_sctp(pkt))
		return -1;

	sum = odph_packet_crc32c(pkt, l4_offset,
				 ODPH_SCTPHDR_LEN - 4,
				 ~0);
	sum = odp_hash_crc32c(&temp, 4, sum);
	sum = ~odph_packet_crc32c(pkt, l4_offset + ODPH_SCTPHDR_LEN,
				  odp_packet_len(pkt) - l4_offset -
				  ODPH_SCTPHDR_LEN,
				  sum);

	odp_packet_copy_to_mem(pkt, l4_offset + ODPH_SCTPHDR_LEN - 4,
			       4, &temp);

	return (temp == sum) ? 0 : 2;
}

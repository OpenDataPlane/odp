/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include "odp_buffer_tests.h"
#include <stdlib.h>

#define PACKET_BUF_LEN	ODP_CONFIG_PACKET_BUF_LEN_MIN
/* Reserve some tailroom for tests */
#define PACKET_TAILROOM_RESERVE  4

static odp_buffer_pool_t packet_pool;
static const uint32_t packet_len = PACKET_BUF_LEN -
				ODP_CONFIG_PACKET_HEADROOM -
				ODP_CONFIG_PACKET_TAILROOM -
				PACKET_TAILROOM_RESERVE;

odp_packet_t test_packet;

int packet_testsuite_init(void)
{
	odp_pool_param_t params = {
		.buf = {
			.size  = PACKET_BUF_LEN,
			.align = ODP_CACHE_LINE_SIZE,
			.num  = 100,
		},
		.type  = ODP_POOL_PACKET,
	};

	packet_pool = odp_buffer_pool_create("packet_pool", ODP_SHM_INVALID,
					     &params);
	if (packet_pool == ODP_BUFFER_POOL_INVALID)
		return -1;

	test_packet = odp_packet_alloc(packet_pool, packet_len);
	if (odp_packet_is_valid(test_packet) == 0)
		return -1;

	return 0;
}

int packet_testsuite_finalize(void)
{
	odp_packet_free(test_packet);
	if (odp_buffer_pool_destroy(packet_pool) != 0)
		return -1;
	return 0;
}

static void packet_alloc_free(void)
{
	odp_buffer_pool_t pool;
	odp_packet_t packet;
	pool = pool_create(1, PACKET_BUF_LEN, ODP_POOL_PACKET);

	/* Allocate the only buffer from the pool */
	packet = odp_packet_alloc(pool, packet_len);
	CU_ASSERT_FATAL(packet != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_len(packet) == packet_len);
	/** @todo: is it correct to assume the pool had only one buffer? */
	CU_ASSERT_FATAL(odp_packet_alloc(pool, packet_len) == ODP_PACKET_INVALID)

	odp_packet_free(packet);

	/* Check that the buffer was returned back to the pool */
	packet = odp_packet_alloc(pool, packet_len);
	CU_ASSERT_FATAL(packet != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_len(packet) == packet_len);

	odp_packet_free(packet);
	CU_ASSERT(odp_buffer_pool_destroy(pool) == 0);
}

static void packet_alloc_segmented(void)
{
	odp_packet_t pkt;
	const uint32_t len = ODP_CONFIG_PACKET_BUF_LEN_MAX -
			ODP_CONFIG_PACKET_HEADROOM -
			ODP_CONFIG_PACKET_TAILROOM;

	pkt = odp_packet_alloc(packet_pool, len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_len(pkt) == len);
	odp_packet_free(pkt);
}

static void packet_event_conversion(void)
{
	odp_packet_t pkt = test_packet;
	odp_packet_t tmp_pkt;
	odp_event_t ev;

	ev = odp_packet_to_event(pkt);
	CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
	CU_ASSERT(odp_event_type(ev) == ODP_EVENT_PACKET);

	tmp_pkt = odp_packet_from_event(ev);
	CU_ASSERT_FATAL(tmp_pkt != ODP_PACKET_INVALID);
	/** @todo: Need an API to compare packets */
}

static void packet_basic_metadata(void)
{
	odp_packet_t pkt = test_packet;
	CU_ASSERT(odp_packet_head(pkt) != NULL);
	CU_ASSERT(odp_packet_data(pkt) != NULL);

	CU_ASSERT(odp_packet_pool(pkt) != ODP_BUFFER_POOL_INVALID);
	/* Packet was allocated by application so shouldn't have valid pktio. */
	CU_ASSERT(odp_packet_input(pkt) == ODP_PKTIO_INVALID);
}

static void packet_length(void)
{
	odp_packet_t pkt = test_packet;
	uint32_t buf_len, headroom, tailroom;

	buf_len = odp_packet_buf_len(pkt);
	headroom = odp_packet_headroom(pkt);
	tailroom = odp_packet_tailroom(pkt);

	CU_ASSERT(odp_packet_len(pkt) == packet_len);
#if ODP_CONFIG_PACKET_HEADROOM != 0 /* Avoid 'always true' warning */
	CU_ASSERT(headroom >= ODP_CONFIG_PACKET_HEADROOM);
#endif
#if ODP_CONFIG_PACKET_TAILROOM != 0 /* Avoid 'always true' warning */
	CU_ASSERT(tailroom >= ODP_CONFIG_PACKET_TAILROOM);
#endif
	CU_ASSERT(buf_len >= packet_len + headroom + tailroom);
}

static void packet_debug(void)
{
	CU_ASSERT(odp_packet_is_valid(test_packet) == 1);
	odp_packet_print(test_packet);
}

static void packet_context(void)
{
	odp_packet_t pkt = test_packet;
	char ptr_test_value = 2;
	uint64_t u64_test_value = 0x0123456789abcdf;

	void *prev_ptr;
	uint64_t prev_u64;

	prev_ptr = odp_packet_user_ptr(pkt);
	odp_packet_user_ptr_set(pkt, &ptr_test_value);
	CU_ASSERT(odp_packet_user_ptr(pkt) == &ptr_test_value);
	odp_packet_user_ptr_set(pkt, prev_ptr);

	prev_u64 = odp_packet_user_u64(pkt);
	odp_packet_user_u64_set(pkt, u64_test_value);
	CU_ASSERT(odp_packet_user_u64(pkt) == u64_test_value);
	odp_packet_user_u64_set(pkt, prev_u64);

	odp_packet_reset(pkt, packet_len);
}

static void packet_layer_offsets(void)
{
	odp_packet_t pkt = test_packet;
	uint8_t *l2_addr, *l3_addr, *l4_addr;
	uint32_t seg_len;
	const uint32_t l2_off = 2;
	const uint32_t l3_off = l2_off + 14;
	const uint32_t l4_off = l3_off + 14;

	/* Set offsets to the same value */
	odp_packet_l2_offset_set(pkt, l2_off);
	odp_packet_l3_offset_set(pkt, l2_off);
	odp_packet_l4_offset_set(pkt, l2_off);

	/* Addresses should be the same */
	l2_addr = odp_packet_l2_ptr(pkt, &seg_len);
	CU_ASSERT(seg_len != 0);
	l3_addr = odp_packet_l3_ptr(pkt, &seg_len);
	CU_ASSERT(seg_len != 0);
	l4_addr = odp_packet_l4_ptr(pkt, &seg_len);
	CU_ASSERT(seg_len != 0);
	CU_ASSERT(l2_addr != NULL);
	CU_ASSERT(l2_addr == l3_addr);
	CU_ASSERT(l2_addr == l4_addr);

	/* Set offsets to the different values */
	odp_packet_l2_offset_set(pkt, l2_off);
	CU_ASSERT(odp_packet_l2_offset(pkt) == l2_off);
	odp_packet_l3_offset_set(pkt, l3_off);
	CU_ASSERT(odp_packet_l3_offset(pkt) == l3_off);
	odp_packet_l4_offset_set(pkt, l4_off);
	CU_ASSERT(odp_packet_l4_offset(pkt) == l4_off);

	/* Addresses should not be the same */
	l2_addr = odp_packet_l2_ptr(pkt, NULL);
	CU_ASSERT(l2_addr != NULL);
	l3_addr = odp_packet_l3_ptr(pkt, NULL);
	CU_ASSERT(l3_addr != NULL);
	l4_addr = odp_packet_l4_ptr(pkt, NULL);
	CU_ASSERT(l4_addr != NULL);

	CU_ASSERT(l2_addr != l3_addr);
	CU_ASSERT(l2_addr != l4_addr);
	CU_ASSERT(l3_addr != l4_addr);
}

static void _verify_headroom_shift(odp_packet_t packet,
				   int shift)
{
	uint32_t room = odp_packet_headroom(packet);
	uint32_t seg_data_len = odp_packet_seg_len(packet);
	uint32_t pkt_data_len = odp_packet_len(packet);
	void *data;
	char *data_orig = odp_packet_data(packet);
	char *head_orig = odp_packet_head(packet);

	if (shift >= 0)
		data = odp_packet_push_head(packet, shift);
	else
		data = odp_packet_pull_head(packet, -shift);

	CU_ASSERT(data != NULL);
	CU_ASSERT(odp_packet_headroom(packet) == room - shift);
	CU_ASSERT(odp_packet_seg_len(packet) == seg_data_len + shift);
	CU_ASSERT(odp_packet_len(packet) == pkt_data_len + shift);
	CU_ASSERT(odp_packet_data(packet) == data);
	CU_ASSERT(odp_packet_head(packet) == head_orig);
	CU_ASSERT(data == data_orig - shift);
}

static void packet_headroom(void)
{
	odp_packet_t pkt = test_packet;
	uint32_t room;
	uint32_t seg_data_len;
	uint32_t push_val, pull_val;

	room = odp_packet_headroom(pkt);

#if ODP_CONFIG_PACKET_HEADROOM != 0 /* Avoid 'always true' warning */
	CU_ASSERT(room >= ODP_CONFIG_PACKET_HEADROOM);
#endif
	seg_data_len = odp_packet_seg_len(pkt);
	CU_ASSERT(seg_data_len >= 1);
	/** @todo: should be len - 1 */
	pull_val = seg_data_len / 2;
	push_val = room;

	_verify_headroom_shift(pkt, -pull_val);
	_verify_headroom_shift(pkt, push_val + pull_val);
	_verify_headroom_shift(pkt, -push_val);
	_verify_headroom_shift(pkt, 0);
}

static void _verify_tailroom_shift(odp_packet_t pkt,
				   int shift)
{
	odp_packet_seg_t seg;
	uint32_t room;
	uint32_t seg_data_len, pkt_data_len;
	void *tail;
	char *tail_orig;

	room = odp_packet_tailroom(pkt);
	pkt_data_len = odp_packet_len(pkt);
	tail_orig = odp_packet_tail(pkt);

	seg = odp_packet_last_seg(pkt);
	CU_ASSERT(seg != ODP_PACKET_SEG_INVALID);
	seg_data_len = odp_packet_seg_data_len(pkt, seg);

	if (shift >= 0) {
		uint32_t l2_off, l3_off, l4_off;
		l2_off = odp_packet_l2_offset(pkt);
		l3_off = odp_packet_l3_offset(pkt);
		l4_off = odp_packet_l4_offset(pkt);

		tail = odp_packet_push_tail(pkt, shift);

		CU_ASSERT(l2_off == odp_packet_l2_offset(pkt));
		CU_ASSERT(l3_off == odp_packet_l3_offset(pkt));
		CU_ASSERT(l4_off == odp_packet_l4_offset(pkt));
	} else {
		tail = odp_packet_pull_tail(pkt, -shift);
	}

	CU_ASSERT(tail != NULL);
	CU_ASSERT(odp_packet_seg_data_len(pkt, seg) == seg_data_len + shift);
	CU_ASSERT(odp_packet_len(pkt) == pkt_data_len + shift);
	CU_ASSERT(odp_packet_tailroom(pkt) == room - shift);
	if (room == 0 || (room - shift) == 0)
		return;
	if (shift >= 0) {
		CU_ASSERT(odp_packet_tail(pkt) == tail_orig + shift);
		CU_ASSERT(tail == tail_orig);
	} else {
		CU_ASSERT(odp_packet_tail(pkt) == tail);
		CU_ASSERT(tail == tail_orig + shift);
	}
}

static void packet_tailroom(void)
{
	odp_packet_t pkt = test_packet;
	odp_packet_seg_t segment;
	uint32_t room;
	uint32_t seg_data_len;
	uint32_t push_val, pull_val;

	segment = odp_packet_last_seg(pkt);
	CU_ASSERT(segment != ODP_PACKET_SEG_INVALID);
	room = odp_packet_tailroom(pkt);
#if ODP_CONFIG_PACKET_TAILROOM != 0 /* Avoid 'always true' warning */
	CU_ASSERT(room >= ODP_CONFIG_PACKET_TAILROOM);
#endif
	seg_data_len = odp_packet_seg_data_len(pkt, segment);
	CU_ASSERT(seg_data_len >= 1);
	/** @todo: should be len - 1 */
	pull_val = seg_data_len / 2;
	/* Leave one byte in a tailroom for odp_packet_tail() to succeed */
	push_val = (room > 0) ? room - 1 : room;

	_verify_tailroom_shift(pkt, -pull_val);
	_verify_tailroom_shift(pkt, push_val + pull_val);
	_verify_tailroom_shift(pkt, -push_val);
	_verify_tailroom_shift(pkt, 0);
}

static void packet_segments(void)
{
	int num_segs, seg_index;
	uint32_t data_len, buf_len;
	odp_packet_seg_t seg;
	odp_packet_t pkt = test_packet;

	CU_ASSERT(odp_packet_is_valid(pkt) == 1);

	num_segs = odp_packet_num_segs(pkt);
	CU_ASSERT(num_segs != 0);

	if (odp_packet_is_segmented(pkt)) {
		CU_ASSERT(num_segs > 1);
	} else {
		CU_ASSERT(num_segs == 1);
	}


	seg = odp_packet_first_seg(pkt);
	buf_len = 0;
	data_len = 0;
	seg_index = 0;
	while (seg_index < num_segs && seg != ODP_PACKET_SEG_INVALID) {
		uint32_t seg_data_len, seg_buf_len;
		void *seg_buf_addr, *seg_data;

		seg_buf_addr = odp_packet_seg_buf_addr(pkt, seg);
		seg_buf_len  = odp_packet_seg_buf_len(pkt, seg);
		seg_data_len = odp_packet_seg_data_len(pkt, seg);
		seg_data     = odp_packet_seg_data(pkt, seg);

		CU_ASSERT(seg_buf_len > 0);
		CU_ASSERT(seg_data_len > 0);
		CU_ASSERT(seg_buf_len >= seg_data_len);
		CU_ASSERT(seg_data != NULL);
		CU_ASSERT(seg_buf_addr != NULL);
		CU_ASSERT(seg_data >= seg_buf_addr);

		buf_len += seg_buf_len;
		data_len += seg_data_len;

		/** @todo: touch memory in a segment */
		seg_index++;
		seg = odp_packet_next_seg(pkt, seg);
	}

	CU_ASSERT(seg_index == num_segs);
	CU_ASSERT(buf_len == odp_packet_buf_len(pkt));
	CU_ASSERT(data_len == odp_packet_len(pkt));

	if (seg_index == num_segs)
		CU_ASSERT(seg == ODP_PACKET_SEG_INVALID);
}

static void packet_segment_last(void)
{
	odp_packet_t pkt = test_packet;
	odp_packet_seg_t seg;

	seg = odp_packet_last_seg(pkt);
	CU_ASSERT_FATAL(seg != ODP_PACKET_SEG_INVALID);

	seg = odp_packet_next_seg(pkt, seg);
	CU_ASSERT(seg == ODP_PACKET_SEG_INVALID);
}

#define TEST_INFLAG(packet, flag) \
do { \
	odp_packet_has_##flag##_set(packet, 0);           \
	CU_ASSERT(odp_packet_has_##flag(packet) == 0);    \
	odp_packet_has_##flag##_set(packet, 1);           \
	CU_ASSERT(odp_packet_has_##flag(packet) == 1);    \
} while (0)

static void packet_in_flags(void)
{
	odp_packet_t pkt = test_packet;

	TEST_INFLAG(pkt, l2);
	TEST_INFLAG(pkt, l3);
	TEST_INFLAG(pkt, l4);
	TEST_INFLAG(pkt, eth);
	TEST_INFLAG(pkt, jumbo);
	TEST_INFLAG(pkt, vlan);
	TEST_INFLAG(pkt, vlan_qinq);
	TEST_INFLAG(pkt, arp);
	TEST_INFLAG(pkt, ipv4);
	TEST_INFLAG(pkt, ipv6);
	TEST_INFLAG(pkt, ipfrag);
	TEST_INFLAG(pkt, ipopt);
	TEST_INFLAG(pkt, ipsec);
	TEST_INFLAG(pkt, udp);
	TEST_INFLAG(pkt, tcp);
	TEST_INFLAG(pkt, sctp);
	TEST_INFLAG(pkt, icmp);
}

static void packet_error_flags(void)
{
	odp_packet_t pkt = test_packet;
	int err;

	/**
	 * The packet have not been classified so it doesn't have error flag
	 * properly set. Just check that function return one of allowed values.
	 * @todo: check classified packet when classifier is added in place.
	 */
	err = odp_packet_error(pkt);
	CU_ASSERT(err == 0 || err == 1);

	err = odp_packet_errflag_frame_len(pkt);
	CU_ASSERT(err == 0 || err == 1);
}

static void packet_out_flags(void)
{
	odp_packet_override_l4_chksum(test_packet);
	CU_PASS("Current API doesn't return any error code\n");
}

struct packet_metadata {
	uint32_t l2_off;
	uint32_t l3_off;
	uint32_t l4_off;
	void *usr_ptr;
	uint64_t usr_u64;
};

static void packet_add_rem_data(void)
{
	odp_packet_t pkt, new_pkt;
	uint32_t pkt_len, offset, add_len;
	void *usr_ptr;
	uint64_t usr_u64;

	pkt = odp_packet_alloc(packet_pool, PACKET_BUF_LEN);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	pkt_len = odp_packet_len(pkt);
	usr_ptr = odp_packet_user_ptr(pkt);
	usr_u64 = odp_packet_user_u64(pkt);
	/* Insert one more packet length in the middle of a packet */
	offset = pkt_len / 2;
	add_len = pkt_len;

	new_pkt = odp_packet_add_data(pkt, offset, add_len);
	CU_ASSERT(new_pkt != ODP_PACKET_INVALID);
	if (new_pkt == ODP_PACKET_INVALID)
		goto free_packet;
	CU_ASSERT(odp_packet_len(new_pkt) == pkt_len + add_len);
	/* Verify that user metadata is preserved */
	CU_ASSERT(odp_packet_user_ptr(new_pkt) == usr_ptr);
	CU_ASSERT(odp_packet_user_u64(new_pkt) == usr_u64);

	pkt = new_pkt;

	pkt_len = odp_packet_len(pkt);
	usr_ptr = odp_packet_user_ptr(pkt);
	usr_u64 = odp_packet_user_u64(pkt);
	new_pkt = odp_packet_rem_data(pkt, offset, add_len);
	CU_ASSERT(new_pkt != ODP_PACKET_INVALID);
	if (new_pkt == ODP_PACKET_INVALID)
		goto free_packet;
	CU_ASSERT(odp_packet_len(new_pkt) == pkt_len - add_len);
	CU_ASSERT(odp_packet_user_ptr(new_pkt) == usr_ptr);
	CU_ASSERT(odp_packet_user_u64(new_pkt) == usr_u64);
	pkt = new_pkt;

free_packet:
	odp_packet_free(pkt);
}


#define COMPARE_INFLAG(p1, p2, flag) \
	CU_ASSERT(odp_packet_has_##flag(p1) == odp_packet_has_##flag(p2))

static void _packet_compare_inflags(odp_packet_t pkt1, odp_packet_t pkt2)
{
	COMPARE_INFLAG(pkt1, pkt2, l2);
	COMPARE_INFLAG(pkt1, pkt2, l3);
	COMPARE_INFLAG(pkt1, pkt2, l4);
	COMPARE_INFLAG(pkt1, pkt2, eth);
	COMPARE_INFLAG(pkt1, pkt2, jumbo);
	COMPARE_INFLAG(pkt1, pkt2, eth);
	COMPARE_INFLAG(pkt1, pkt2, vlan);
	COMPARE_INFLAG(pkt1, pkt2, vlan_qinq);
	COMPARE_INFLAG(pkt1, pkt2, arp);
	COMPARE_INFLAG(pkt1, pkt2, ipv4);
	COMPARE_INFLAG(pkt1, pkt2, ipv6);
	COMPARE_INFLAG(pkt1, pkt2, ipfrag);
	COMPARE_INFLAG(pkt1, pkt2, ipopt);
	COMPARE_INFLAG(pkt1, pkt2, ipsec);
	COMPARE_INFLAG(pkt1, pkt2, udp);
	COMPARE_INFLAG(pkt1, pkt2, tcp);
	COMPARE_INFLAG(pkt1, pkt2, sctp);
	COMPARE_INFLAG(pkt1, pkt2, icmp);
}

static void _packet_compare_data(odp_packet_t pkt1, odp_packet_t pkt2)
{
	uint32_t len = odp_packet_len(pkt1);
	uint32_t offset = 0;
	uint32_t seglen1, seglen2, cmplen;

	CU_ASSERT_FATAL(len == odp_packet_len(pkt2));

	while (len > 0) {
		void *pkt1map = odp_packet_offset(pkt1, offset, &seglen1, NULL);
		void *pkt2map = odp_packet_offset(pkt2, offset, &seglen2, NULL);

		CU_ASSERT_FATAL(pkt1map != NULL);
		CU_ASSERT_FATAL(pkt2map != NULL);
		cmplen = seglen1 < seglen2 ? seglen1 : seglen2;
		CU_ASSERT(!memcmp(pkt1map, pkt2map, cmplen));

		offset += cmplen;
		len    -= cmplen;
	}
}

static void packet_copy(void)
{
	odp_packet_t pkt = test_packet;
	odp_packet_t pkt_copy;
	odp_buffer_pool_t pool;

	/** @todo: fill original packet with some data */
	pool = odp_packet_pool(pkt);
	CU_ASSERT_FATAL(pool != ODP_BUFFER_POOL_INVALID);
	pkt_copy = odp_packet_copy(pkt, odp_packet_pool(pkt));
	CU_ASSERT_FATAL(pkt_copy != ODP_PACKET_INVALID);

	CU_ASSERT(odp_packet_len(pkt) == odp_packet_len(pkt_copy));

	_packet_compare_inflags(pkt, pkt_copy);
	_packet_compare_data(pkt, pkt_copy);
	odp_packet_free(pkt_copy);
}

static void packet_copydata(void)
{
	odp_packet_t pkt = test_packet;
	uint32_t pkt_len = odp_packet_len(pkt);
	uint8_t *data_buf;
	uint32_t i;
	int correct_memory;

	CU_ASSERT_FATAL(pkt_len > 0);

	data_buf = malloc(pkt_len);
	CU_ASSERT_FATAL(data_buf != NULL);

	for (i = 0; i < pkt_len; i++)
		data_buf[i] = (uint8_t)i;

	CU_ASSERT(!odp_packet_copydata_in(pkt, 0, pkt_len, data_buf));
	memset(data_buf, 0, pkt_len);
	CU_ASSERT(!odp_packet_copydata_out(pkt, 0, pkt_len, data_buf));

	correct_memory = 1;
	for (i = 0; i < pkt_len; i++)
		if (data_buf[i] != (uint8_t)i) {
			correct_memory = 0;
			break;
		}
	CU_ASSERT(correct_memory);

	free(data_buf);
}

static void packet_offset(void)
{
	odp_packet_t pkt = test_packet;
	uint32_t seg_len, full_seg_len;
	odp_packet_seg_t seg;
	uint8_t *ptr, *start_ptr;
	uint32_t offset;

	ptr = odp_packet_offset(pkt, 0, &seg_len, &seg);
	CU_ASSERT(seg != ODP_PACKET_SEG_INVALID);
	CU_ASSERT(seg_len > 1);
	CU_ASSERT(seg_len == odp_packet_seg_len(pkt));
	CU_ASSERT(seg_len == odp_packet_seg_data_len(pkt, seg));
	CU_ASSERT(ptr != NULL);
	CU_ASSERT(ptr == odp_packet_data(pkt));
	CU_ASSERT(ptr == odp_packet_seg_data(pkt, seg));

	/* Query a second byte */
	start_ptr = ptr;
	full_seg_len = seg_len;
	offset = 1;

	ptr = odp_packet_offset(pkt, offset, &seg_len, NULL);
	CU_ASSERT(ptr != NULL);
	CU_ASSERT(ptr == start_ptr + offset);
	CU_ASSERT(seg_len == full_seg_len - offset);

	/* Query the last byte in a segment */
	offset = full_seg_len - 1;

	ptr = odp_packet_offset(pkt, offset, &seg_len, NULL);
	CU_ASSERT(ptr != NULL);
	CU_ASSERT(ptr == start_ptr + offset);
	CU_ASSERT(seg_len == full_seg_len - offset);

	/* Query the last byte in a packet */
	offset = odp_packet_len(pkt) - 1;
	ptr = odp_packet_offset(pkt, offset, &seg_len, NULL);
	CU_ASSERT(ptr != NULL);
	CU_ASSERT(seg_len == 1);

	/* Pass NULL to [out] arguments */
	ptr = odp_packet_offset(pkt, 0, NULL, NULL);
	CU_ASSERT(ptr != NULL);
}

CU_TestInfo packet_tests[] = {
	_CU_TEST_INFO(packet_alloc_free),
	_CU_TEST_INFO(packet_alloc_segmented),
	_CU_TEST_INFO(packet_basic_metadata),
	_CU_TEST_INFO(packet_debug),
	_CU_TEST_INFO(packet_length),
	_CU_TEST_INFO(packet_headroom),
	_CU_TEST_INFO(packet_tailroom),
	_CU_TEST_INFO(packet_context),
	_CU_TEST_INFO(packet_event_conversion),
	_CU_TEST_INFO(packet_layer_offsets),
	_CU_TEST_INFO(packet_segments),
	_CU_TEST_INFO(packet_segment_last),
	_CU_TEST_INFO(packet_in_flags),
	_CU_TEST_INFO(packet_out_flags),
	_CU_TEST_INFO(packet_error_flags),
	_CU_TEST_INFO(packet_add_rem_data),
	_CU_TEST_INFO(packet_copy),
	_CU_TEST_INFO(packet_copydata),
	_CU_TEST_INFO(packet_offset),
	CU_TEST_INFO_NULL,
};

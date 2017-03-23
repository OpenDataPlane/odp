/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <stdlib.h>

#include <odp_api.h>
#include <odp_cunit_common.h>
#include "packet.h"

#define PACKET_BUF_LEN	ODP_CONFIG_PACKET_SEG_LEN_MIN
/* Reserve some tailroom for tests */
#define PACKET_TAILROOM_RESERVE  4

static odp_pool_t packet_pool, packet_pool_no_uarea, packet_pool_double_uarea;
static uint32_t packet_len;

static uint32_t segmented_packet_len;
static odp_bool_t segmentation_supported = true;

odp_packet_t test_packet, segmented_test_packet;

static struct udata_struct {
	uint64_t u64;
	uint32_t u32;
	char str[10];
} test_packet_udata = {
	123456,
	789912,
	"abcdefg",
};

#define packet_compare_offset(pkt1, off1, pkt2, off2, len) \
	_packet_compare_offset((pkt1), (off1), (pkt2), (off2), (len), __LINE__)

#define packet_compare_data(pkt1, pkt2) \
	_packet_compare_data((pkt1), (pkt2), __LINE__)

static void _packet_compare_data(odp_packet_t pkt1, odp_packet_t pkt2,
				 int line)
{
	uint32_t len = odp_packet_len(pkt1);
	uint32_t offset = 0;
	uint32_t seglen1, seglen2, cmplen;
	int ret;

	CU_ASSERT_FATAL(len == odp_packet_len(pkt2));

	while (len > 0) {
		void *pkt1map = odp_packet_offset(pkt1, offset, &seglen1, NULL);
		void *pkt2map = odp_packet_offset(pkt2, offset, &seglen2, NULL);

		CU_ASSERT_PTR_NOT_NULL_FATAL(pkt1map);
		CU_ASSERT_PTR_NOT_NULL_FATAL(pkt2map);
		cmplen = seglen1 < seglen2 ? seglen1 : seglen2;
		ret = memcmp(pkt1map, pkt2map, cmplen);

		if (ret) {
			printf("\ncompare_data failed: line %i, offset %"
			       PRIu32 "\n", line, offset);
		}

		CU_ASSERT(ret == 0);

		offset += cmplen;
		len    -= cmplen;
	}
}

static int fill_data_forward(odp_packet_t pkt, uint32_t offset, uint32_t len,
			     uint32_t *cur_data)
{
	uint8_t buf[len];
	uint32_t i, data;

	data = *cur_data;

	for (i = 0; i < len; i++)
		buf[i] = data++;

	*cur_data = data;

	return odp_packet_copy_from_mem(pkt, offset, len, buf);
}

static int fill_data_backward(odp_packet_t pkt, uint32_t offset, uint32_t len,
			      uint32_t *cur_data)
{
	uint8_t buf[len];
	uint32_t i, data;

	data = *cur_data;

	for (i = 0; i < len; i++)
		buf[len - i - 1] = data++;

	*cur_data = data;

	return odp_packet_copy_from_mem(pkt, offset, len, buf);
}

int packet_suite_init(void)
{
	odp_pool_param_t params;
	odp_pool_capability_t capa;
	struct udata_struct *udat;
	uint32_t udat_size;
	uint8_t data = 0;
	uint32_t i;
	uint32_t num = 200;

	if (odp_pool_capability(&capa) < 0) {
		printf("pool_capability failed\n");
		return -1;
	}
	if (capa.pkt.max_segs_per_pkt == 0)
		capa.pkt.max_segs_per_pkt = 10;

	/* Pick a typical packet size and decrement it to the single segment
	 * limit if needed (min_seg_len maybe equal to max_len
	 * on some systems). */
	packet_len = 512;
	while (packet_len > (capa.pkt.min_seg_len - PACKET_TAILROOM_RESERVE))
		packet_len--;

	if (capa.pkt.max_len) {
		segmented_packet_len = capa.pkt.max_len;
	} else {
		segmented_packet_len = capa.pkt.min_seg_len *
				       capa.pkt.max_segs_per_pkt;
	}
	if (capa.pkt.max_num != 0 && capa.pkt.max_num < num)
		num = capa.pkt.max_num;

	odp_pool_param_init(&params);

	params.type           = ODP_POOL_PACKET;
	params.pkt.seg_len    = capa.pkt.min_seg_len;
	params.pkt.len        = capa.pkt.min_seg_len;
	params.pkt.num        = num;
	params.pkt.uarea_size = sizeof(struct udata_struct);

	packet_pool = odp_pool_create("packet_pool", &params);
	if (packet_pool == ODP_POOL_INVALID) {
		printf("pool_create failed: 1\n");
		return -1;
	}

	params.pkt.uarea_size = 0;
	packet_pool_no_uarea = odp_pool_create("packet_pool_no_uarea",
					       &params);
	if (packet_pool_no_uarea == ODP_POOL_INVALID) {
		odp_pool_destroy(packet_pool);
		printf("pool_create failed: 2\n");
		return -1;
	}

	params.pkt.uarea_size = 2 * sizeof(struct udata_struct);
	packet_pool_double_uarea = odp_pool_create("packet_pool_double_uarea",
						   &params);

	if (packet_pool_double_uarea == ODP_POOL_INVALID) {
		odp_pool_destroy(packet_pool_no_uarea);
		odp_pool_destroy(packet_pool);
		printf("pool_create failed: 3\n");
		return -1;
	}

	test_packet = odp_packet_alloc(packet_pool, packet_len);

	for (i = 0; i < packet_len; i++) {
		odp_packet_copy_from_mem(test_packet, i, 1, &data);
		data++;
	}

	/* Try to allocate the largest possible packet to see
	 * if segmentation is supported  */
	do {
		segmented_test_packet = odp_packet_alloc(packet_pool,
							 segmented_packet_len);
		if (segmented_test_packet == ODP_PACKET_INVALID)
			segmented_packet_len -= capa.pkt.min_seg_len;
	} while (segmented_test_packet == ODP_PACKET_INVALID);

	if (odp_packet_is_valid(test_packet) == 0 ||
	    odp_packet_is_valid(segmented_test_packet) == 0) {
		printf("packet_is_valid failed\n");
		return -1;
	}

	segmentation_supported = odp_packet_is_segmented(segmented_test_packet);

	data = 0;
	for (i = 0; i < segmented_packet_len; i++) {
		odp_packet_copy_from_mem(segmented_test_packet, i, 1, &data);
		data++;
	}

	udat = odp_packet_user_area(test_packet);
	udat_size = odp_packet_user_area_size(test_packet);
	if (!udat || udat_size != sizeof(struct udata_struct)) {
		printf("packet_user_area failed: 1\n");
		return -1;
	}

	odp_pool_print(packet_pool);
	memcpy(udat, &test_packet_udata, sizeof(struct udata_struct));

	udat = odp_packet_user_area(segmented_test_packet);
	udat_size = odp_packet_user_area_size(segmented_test_packet);
	if (udat == NULL || udat_size != sizeof(struct udata_struct)) {
		printf("packet_user_area failed: 2\n");
		return -1;
	}

	memcpy(udat, &test_packet_udata, sizeof(struct udata_struct));

	return 0;
}

int packet_suite_term(void)
{
	odp_packet_free(test_packet);
	odp_packet_free(segmented_test_packet);

	if (odp_pool_destroy(packet_pool_double_uarea) != 0 ||
	    odp_pool_destroy(packet_pool_no_uarea) != 0 ||
	    odp_pool_destroy(packet_pool) != 0)
		return -1;

	return 0;
}

void packet_test_alloc_free(void)
{
	odp_pool_t pool;
	odp_packet_t packet;
	odp_pool_param_t params;
	odp_pool_capability_t capa;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	odp_pool_param_init(&params);

	params.type           = ODP_POOL_PACKET;
	params.pkt.seg_len    = capa.pkt.min_seg_len;
	params.pkt.len        = capa.pkt.min_seg_len;
	params.pkt.num        = 1;

	pool = odp_pool_create("packet_pool_alloc", &params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	/* Allocate the only buffer from the pool */
	packet = odp_packet_alloc(pool, packet_len);
	CU_ASSERT_FATAL(packet != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_len(packet) == packet_len);
	CU_ASSERT(odp_event_type(odp_packet_to_event(packet)) ==
			ODP_EVENT_PACKET);
	CU_ASSERT(odp_packet_to_u64(packet) !=
		  odp_packet_to_u64(ODP_PACKET_INVALID));

	/* Pool should have only one packet */
	CU_ASSERT_FATAL(odp_packet_alloc(pool, packet_len)
			== ODP_PACKET_INVALID);

	odp_packet_free(packet);

	/* Check that the buffer was returned back to the pool */
	packet = odp_packet_alloc(pool, packet_len);
	CU_ASSERT_FATAL(packet != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_len(packet) == packet_len);

	odp_packet_free(packet);
	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

/* Wrapper to call odp_packet_alloc_multi multiple times until
 * either no mure buffers are returned, or num buffers were alloced */
static int packet_alloc_multi(odp_pool_t pool, uint32_t pkt_len,
			      odp_packet_t pkt[], int num)
{
	int ret, total = 0;

	do {
		ret = odp_packet_alloc_multi(pool, pkt_len, pkt + total,
					     num - total);
		CU_ASSERT(ret >= 0);
		CU_ASSERT(ret <= num - total);
		total += ret;
	} while (total < num && ret);

	return total;
}

void packet_test_alloc_free_multi(void)
{
	const int num_pkt = 2;
	odp_pool_t pool[2];
	int i, ret;
	odp_packet_t packet[2 * num_pkt + 1];
	odp_packet_t inval_pkt[num_pkt];
	odp_pool_param_t params;
	odp_pool_capability_t capa;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	odp_pool_param_init(&params);

	params.type           = ODP_POOL_PACKET;
	params.pkt.seg_len    = capa.pkt.min_seg_len;
	params.pkt.len        = capa.pkt.min_seg_len;
	params.pkt.num        = num_pkt;

	pool[0] = odp_pool_create("packet_pool_alloc_multi_0", &params);
	pool[1] = odp_pool_create("packet_pool_alloc_multi_1", &params);
	CU_ASSERT_FATAL(pool[0] != ODP_POOL_INVALID);
	CU_ASSERT_FATAL(pool[1] != ODP_POOL_INVALID);

	/* Allocate all the packets from the pools */

	ret = packet_alloc_multi(pool[0], packet_len, &packet[0], num_pkt + 1);
	CU_ASSERT_FATAL(ret == num_pkt);
	ret = packet_alloc_multi(pool[1], packet_len,
				 &packet[num_pkt], num_pkt + 1);
	CU_ASSERT_FATAL(ret == num_pkt);

	for (i = 0; i < 2 * num_pkt; ++i) {
		CU_ASSERT(odp_packet_len(packet[i]) == packet_len);
		CU_ASSERT(odp_event_type(odp_packet_to_event(packet[i])) ==
			  ODP_EVENT_PACKET);
		CU_ASSERT(odp_packet_to_u64(packet[i]) !=
			  odp_packet_to_u64(ODP_PACKET_INVALID));
	}

	/* Pools should have no more packets */
	ret = odp_packet_alloc_multi(pool[0], packet_len, inval_pkt, num_pkt);
	CU_ASSERT(ret == 0);
	ret = odp_packet_alloc_multi(pool[1], packet_len, inval_pkt, num_pkt);
	CU_ASSERT(ret == 0);

	/* Free all packets from all pools at once */
	odp_packet_free_multi(packet, 2 * num_pkt);

	/* Check that all the packets were returned back to their pools */
	ret = packet_alloc_multi(pool[0], packet_len, &packet[0], num_pkt);
	CU_ASSERT(ret);
	ret  = packet_alloc_multi(pool[1], packet_len,
				  &packet[num_pkt], num_pkt);
	CU_ASSERT(ret);

	for (i = 0; i < 2 * num_pkt; ++i) {
		CU_ASSERT_FATAL(packet[i] != ODP_PACKET_INVALID);
		CU_ASSERT(odp_packet_len(packet[i]) == packet_len);
	}
	odp_packet_free_multi(packet, 2 * num_pkt);
	CU_ASSERT(odp_pool_destroy(pool[0]) == 0);
	CU_ASSERT(odp_pool_destroy(pool[1]) == 0);
}

void packet_test_alloc_segmented(void)
{
	const int num = 5;
	odp_packet_t pkts[num];
	odp_packet_t pkt;
	uint32_t max_len;
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_pool_capability_t capa;
	int ret, i, num_alloc;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);
	if (capa.pkt.max_segs_per_pkt == 0)
		capa.pkt.max_segs_per_pkt = 10;

	if (capa.pkt.max_len)
		max_len = capa.pkt.max_len;
	else
		max_len = capa.pkt.min_seg_len * capa.pkt.max_segs_per_pkt;

	odp_pool_param_init(&params);

	params.type           = ODP_POOL_PACKET;
	params.pkt.seg_len    = capa.pkt.min_seg_len;
	params.pkt.len        = max_len;

	/* Ensure that 'num' segmented packets can be allocated */
	params.pkt.num        = num * capa.pkt.max_segs_per_pkt;

	pool = odp_pool_create("pool_alloc_segmented", &params);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);

	/* Less than max len allocs */
	pkt = odp_packet_alloc(pool, max_len / 2);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_len(pkt) == max_len / 2);

	odp_packet_free(pkt);

	num_alloc = 0;
	for (i = 0; i < num; i++) {
		ret = odp_packet_alloc_multi(pool, max_len / 2,
					     &pkts[num_alloc], num - num_alloc);
		CU_ASSERT_FATAL(ret >= 0);
		num_alloc += ret;
		if (num_alloc >= num)
			break;
	}

	CU_ASSERT(num_alloc == num);

	for (i = 0; i < num_alloc; i++)
		CU_ASSERT(odp_packet_len(pkts[i]) == max_len / 2);

	odp_packet_free_multi(pkts, num_alloc);

	/* Max len allocs */
	pkt = odp_packet_alloc(pool, max_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_len(pkt) == max_len);

	odp_packet_free(pkt);

	num_alloc = 0;
	for (i = 0; i < num; i++) {
		ret = odp_packet_alloc_multi(pool, max_len,
					     &pkts[num_alloc], num - num_alloc);
		CU_ASSERT_FATAL(ret >= 0);
		num_alloc += ret;
		if (num_alloc >= num)
			break;
	}

	CU_ASSERT(num_alloc == num);

	for (i = 0; i < num_alloc; i++)
		CU_ASSERT(odp_packet_len(pkts[i]) == max_len);

	odp_packet_free_multi(pkts, num_alloc);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

void packet_test_event_conversion(void)
{
	odp_packet_t pkt = test_packet;
	odp_packet_t tmp_pkt;
	odp_event_t ev;

	ev = odp_packet_to_event(pkt);
	CU_ASSERT_FATAL(ev != ODP_EVENT_INVALID);
	CU_ASSERT(odp_event_type(ev) == ODP_EVENT_PACKET);

	tmp_pkt = odp_packet_from_event(ev);
	CU_ASSERT_FATAL(tmp_pkt != ODP_PACKET_INVALID);
	CU_ASSERT(tmp_pkt == pkt);
	packet_compare_data(tmp_pkt, pkt);
}

void packet_test_basic_metadata(void)
{
	odp_packet_t pkt = test_packet;
	odp_time_t ts;

	CU_ASSERT_PTR_NOT_NULL(odp_packet_head(pkt));
	CU_ASSERT_PTR_NOT_NULL(odp_packet_data(pkt));

	CU_ASSERT(odp_packet_pool(pkt) != ODP_POOL_INVALID);
	/* Packet was allocated by application so shouldn't have valid pktio. */
	CU_ASSERT(odp_packet_input(pkt) == ODP_PKTIO_INVALID);
	CU_ASSERT(odp_packet_input_index(pkt) < 0);

	odp_packet_flow_hash_set(pkt, UINT32_MAX);
	CU_ASSERT(odp_packet_has_flow_hash(pkt));
	CU_ASSERT(odp_packet_flow_hash(pkt) == UINT32_MAX);
	odp_packet_has_flow_hash_clr(pkt);
	CU_ASSERT(!odp_packet_has_flow_hash(pkt));

	ts = odp_time_global();
	odp_packet_ts_set(pkt, ts);
	CU_ASSERT_FATAL(odp_packet_has_ts(pkt));
	CU_ASSERT(!odp_time_cmp(ts, odp_packet_ts(pkt)));
	odp_packet_has_ts_clr(pkt);
	CU_ASSERT(!odp_packet_has_ts(pkt));
}

void packet_test_length(void)
{
	odp_packet_t pkt = test_packet;
	uint32_t buf_len, headroom, tailroom;
	odp_pool_capability_t capa;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	buf_len = odp_packet_buf_len(pkt);
	headroom = odp_packet_headroom(pkt);
	tailroom = odp_packet_tailroom(pkt);

	CU_ASSERT(odp_packet_len(pkt) == packet_len);
	CU_ASSERT(headroom >= capa.pkt.min_headroom);
	CU_ASSERT(tailroom >= capa.pkt.min_tailroom);

	CU_ASSERT(buf_len >= packet_len + headroom + tailroom);
}

void packet_test_prefetch(void)
{
	odp_packet_prefetch(test_packet, 0, odp_packet_len(test_packet));
	CU_PASS();
}

void packet_test_debug(void)
{
	CU_ASSERT(odp_packet_is_valid(test_packet) == 1);
	odp_packet_print(test_packet);
}

void packet_test_context(void)
{
	odp_packet_t pkt = test_packet;
	char ptr_test_value = 2;
	void *prev_ptr;
	struct udata_struct *udat;

	prev_ptr = odp_packet_user_ptr(pkt);
	odp_packet_user_ptr_set(pkt, &ptr_test_value);
	CU_ASSERT(odp_packet_user_ptr(pkt) == &ptr_test_value);
	odp_packet_user_ptr_set(pkt, prev_ptr);

	udat = odp_packet_user_area(pkt);
	CU_ASSERT_PTR_NOT_NULL(udat);
	CU_ASSERT(odp_packet_user_area_size(pkt) ==
		  sizeof(struct udata_struct));
	CU_ASSERT(memcmp(udat, &test_packet_udata, sizeof(struct udata_struct))
		  == 0);

	odp_packet_reset(pkt, packet_len);
}

void packet_test_layer_offsets(void)
{
	odp_packet_t pkt = test_packet;
	uint8_t *l2_addr, *l3_addr, *l4_addr;
	uint32_t seg_len;
	const uint32_t l2_off = 2;
	const uint32_t l3_off = l2_off + 14;
	const uint32_t l4_off = l3_off + 14;
	int ret;

	/* Set offsets to the same value */
	ret = odp_packet_l2_offset_set(pkt, l2_off);
	CU_ASSERT(ret == 0);
	ret = odp_packet_l3_offset_set(pkt, l2_off);
	CU_ASSERT(ret == 0);
	ret = odp_packet_l4_offset_set(pkt, l2_off);
	CU_ASSERT(ret == 0);

	/* Addresses should be the same */
	l2_addr = odp_packet_l2_ptr(pkt, &seg_len);
	CU_ASSERT(seg_len != 0);
	l3_addr = odp_packet_l3_ptr(pkt, &seg_len);
	CU_ASSERT(seg_len != 0);
	l4_addr = odp_packet_l4_ptr(pkt, &seg_len);
	CU_ASSERT(seg_len != 0);
	CU_ASSERT_PTR_NOT_NULL(l2_addr);
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
	CU_ASSERT_PTR_NOT_NULL(l2_addr);
	l3_addr = odp_packet_l3_ptr(pkt, NULL);
	CU_ASSERT_PTR_NOT_NULL(l3_addr);
	l4_addr = odp_packet_l4_ptr(pkt, NULL);
	CU_ASSERT_PTR_NOT_NULL(l4_addr);

	CU_ASSERT(l2_addr != l3_addr);
	CU_ASSERT(l2_addr != l4_addr);
	CU_ASSERT(l3_addr != l4_addr);
}

static void _verify_headroom_shift(odp_packet_t *pkt,
				   int shift)
{
	uint32_t room = odp_packet_headroom(*pkt);
	uint32_t seg_data_len = odp_packet_seg_len(*pkt);
	uint32_t pkt_data_len = odp_packet_len(*pkt);
	void *data;
	char *data_orig = odp_packet_data(*pkt);
	char *head_orig = odp_packet_head(*pkt);
	uint32_t seg_len;
	int extended, rc;

	if (shift >= 0) {
		if ((uint32_t)abs(shift) <= room) {
			data = odp_packet_push_head(*pkt, shift);
			extended = 0;
		} else {
			rc = odp_packet_extend_head(pkt, shift,
						    &data, &seg_len);
			extended = 1;
		}
	} else {
		if ((uint32_t)abs(shift) <= seg_data_len) {
			data = odp_packet_pull_head(*pkt, -shift);
			extended = 0;
		} else {
			rc = odp_packet_trunc_head(pkt, -shift,
						   &data, &seg_len);
			extended = 1;
		}
	}

	CU_ASSERT_PTR_NOT_NULL(data);
	if (extended) {
		CU_ASSERT(rc >= 0);
		if (shift >= 0) {
			CU_ASSERT(odp_packet_seg_len(*pkt) == shift - room);
		} else {
			CU_ASSERT(odp_packet_headroom(*pkt) >=
				  (uint32_t)abs(shift) - seg_data_len);
		}
		CU_ASSERT(odp_packet_head(*pkt) != head_orig);
	} else {
		CU_ASSERT(odp_packet_headroom(*pkt) == room - shift);
		CU_ASSERT(odp_packet_seg_len(*pkt) == seg_data_len + shift);
		CU_ASSERT(data == data_orig - shift);
		CU_ASSERT(odp_packet_head(*pkt) == head_orig);
	}

	CU_ASSERT(odp_packet_len(*pkt) == pkt_data_len + shift);
	CU_ASSERT(odp_packet_data(*pkt) == data);
}

void packet_test_headroom(void)
{
	odp_packet_t pkt = odp_packet_copy(test_packet,
					   odp_packet_pool(test_packet));
	uint32_t room;
	uint32_t seg_data_len;
	uint32_t push_val, pull_val;
	odp_pool_capability_t capa;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	room = odp_packet_headroom(pkt);

	CU_ASSERT(room >= capa.pkt.min_headroom);

	seg_data_len = odp_packet_seg_len(pkt);
	CU_ASSERT(seg_data_len >= 1);

	pull_val = seg_data_len / 2;
	push_val = room;

	_verify_headroom_shift(&pkt, -pull_val);
	_verify_headroom_shift(&pkt, push_val + pull_val);
	_verify_headroom_shift(&pkt, -push_val);
	_verify_headroom_shift(&pkt, 0);

	if (segmentation_supported) {
		push_val = room * 2;
		_verify_headroom_shift(&pkt, push_val);
		_verify_headroom_shift(&pkt, 0);
		_verify_headroom_shift(&pkt, -push_val);
	}

	odp_packet_free(pkt);
}

static void _verify_tailroom_shift(odp_packet_t *pkt,
				   int shift)
{
	odp_packet_seg_t seg;
	uint32_t room;
	uint32_t seg_data_len, pkt_data_len, seg_len;
	void *tail;
	char *tail_orig;
	int extended, rc;

	room = odp_packet_tailroom(*pkt);
	pkt_data_len = odp_packet_len(*pkt);
	tail_orig = odp_packet_tail(*pkt);

	seg = odp_packet_last_seg(*pkt);
	CU_ASSERT(seg != ODP_PACKET_SEG_INVALID);
	seg_data_len = odp_packet_seg_data_len(*pkt, seg);

	if (shift >= 0) {
		uint32_t l2_off, l3_off, l4_off;

		l2_off = odp_packet_l2_offset(*pkt);
		l3_off = odp_packet_l3_offset(*pkt);
		l4_off = odp_packet_l4_offset(*pkt);

		if ((uint32_t)abs(shift) <= room) {
			tail = odp_packet_push_tail(*pkt, shift);
			extended = 0;
		} else {
			rc = odp_packet_extend_tail(pkt, shift,
						    &tail, &seg_len);
			extended = 1;
		}

		CU_ASSERT(l2_off == odp_packet_l2_offset(*pkt));
		CU_ASSERT(l3_off == odp_packet_l3_offset(*pkt));
		CU_ASSERT(l4_off == odp_packet_l4_offset(*pkt));
	} else {
		if ((uint32_t)abs(shift) <= seg_data_len) {
			tail = odp_packet_pull_tail(*pkt, -shift);
			extended = 0;
		} else {
			rc = odp_packet_trunc_tail(pkt, -shift,
						   &tail, &seg_len);
			extended = 1;
		}
	}

	CU_ASSERT_PTR_NOT_NULL(tail);
	if (extended) {
		CU_ASSERT(rc >= 0);
		CU_ASSERT(odp_packet_last_seg(*pkt) != seg);
		seg = odp_packet_last_seg(*pkt);
		if (shift > 0) {
			CU_ASSERT(odp_packet_seg_data_len(*pkt, seg) ==
				  shift - room);
		} else {
			CU_ASSERT(odp_packet_tailroom(*pkt) >=
				  (uint32_t)abs(shift) - seg_data_len);
			CU_ASSERT(seg_len == odp_packet_tailroom(*pkt));
		}
	} else {
		CU_ASSERT(odp_packet_seg_data_len(*pkt, seg) ==
			  seg_data_len + shift);
		CU_ASSERT(odp_packet_tailroom(*pkt) == room - shift);
		if (room == 0 || (room - shift) == 0)
			return;
		if (shift >= 0) {
			CU_ASSERT(odp_packet_tail(*pkt) ==
				  tail_orig + shift);
		} else {
			CU_ASSERT(tail == tail_orig + shift);
		}
	}

	CU_ASSERT(odp_packet_len(*pkt) == pkt_data_len + shift);
	if (shift >= 0) {
		CU_ASSERT(tail == tail_orig);
	} else {
		CU_ASSERT(odp_packet_tail(*pkt) == tail);
	}
}

void packet_test_tailroom(void)
{
	odp_packet_t pkt = odp_packet_copy(test_packet,
					   odp_packet_pool(test_packet));
	odp_packet_seg_t segment;
	uint32_t room;
	uint32_t seg_data_len;
	uint32_t push_val, pull_val;
	odp_pool_capability_t capa;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	segment = odp_packet_last_seg(pkt);
	CU_ASSERT(segment != ODP_PACKET_SEG_INVALID);
	room = odp_packet_tailroom(pkt);
	CU_ASSERT(room >= capa.pkt.min_tailroom);

	seg_data_len = odp_packet_seg_data_len(pkt, segment);
	CU_ASSERT(seg_data_len >= 1);

	pull_val = seg_data_len / 2;
	/* Leave one byte in a tailroom for odp_packet_tail() to succeed */
	push_val = (room > 0) ? room - 1 : room;

	_verify_tailroom_shift(&pkt, -pull_val);
	_verify_tailroom_shift(&pkt, push_val + pull_val);
	_verify_tailroom_shift(&pkt, -push_val);
	_verify_tailroom_shift(&pkt, 0);

	if (segmentation_supported) {
		push_val = room + 100;
		_verify_tailroom_shift(&pkt, push_val);
		_verify_tailroom_shift(&pkt, 0);
		_verify_tailroom_shift(&pkt, -push_val);
	}

	odp_packet_free(pkt);
}

void packet_test_segments(void)
{
	int num_segs, seg_index;
	uint32_t data_len;
	odp_packet_seg_t seg;
	odp_packet_t pkt = test_packet;
	odp_packet_t seg_pkt = segmented_test_packet;

	CU_ASSERT(odp_packet_is_valid(pkt) == 1);

	num_segs = odp_packet_num_segs(pkt);
	CU_ASSERT(num_segs != 0);

	if (odp_packet_is_segmented(pkt)) {
		CU_ASSERT(num_segs > 1);
	} else {
		CU_ASSERT(num_segs == 1);
	}

	CU_ASSERT(odp_packet_is_segmented(pkt) == 0);
	if (segmentation_supported)
		CU_ASSERT(odp_packet_is_segmented(seg_pkt) == 1);

	seg = odp_packet_first_seg(pkt);
	data_len = 0;
	seg_index = 0;
	while (seg_index < num_segs && seg != ODP_PACKET_SEG_INVALID) {
		uint32_t seg_data_len;
		void *seg_data;

		seg_data_len = odp_packet_seg_data_len(pkt, seg);
		seg_data     = odp_packet_seg_data(pkt, seg);

		CU_ASSERT(seg_data_len > 0);
		CU_ASSERT_PTR_NOT_NULL(seg_data);
		CU_ASSERT(odp_packet_seg_to_u64(seg) !=
			  odp_packet_seg_to_u64(ODP_PACKET_SEG_INVALID));
		CU_ASSERT(odp_memcmp(seg_data, seg_data, seg_data_len) == 0);

		data_len += seg_data_len;

		seg_index++;
		seg = odp_packet_next_seg(pkt, seg);
	}

	CU_ASSERT(seg_index == num_segs);
	CU_ASSERT(data_len <= odp_packet_buf_len(pkt));
	CU_ASSERT(data_len == odp_packet_len(pkt));

	if (seg_index == num_segs)
		CU_ASSERT(seg == ODP_PACKET_SEG_INVALID);

	seg = odp_packet_first_seg(seg_pkt);
	num_segs = odp_packet_num_segs(seg_pkt);

	data_len = 0;
	seg_index = 0;

	while (seg_index < num_segs && seg != ODP_PACKET_SEG_INVALID) {
		uint32_t seg_data_len;
		void *seg_data;

		seg_data_len = odp_packet_seg_data_len(seg_pkt, seg);
		seg_data     = odp_packet_seg_data(seg_pkt, seg);

		CU_ASSERT(seg_data_len > 0);
		CU_ASSERT(seg_data != NULL);
		CU_ASSERT(odp_packet_seg_to_u64(seg) !=
			  odp_packet_seg_to_u64(ODP_PACKET_SEG_INVALID));
		CU_ASSERT(odp_memcmp(seg_data, seg_data, seg_data_len) == 0);

		data_len += seg_data_len;

		seg_index++;
		seg = odp_packet_next_seg(seg_pkt, seg);
	}

	CU_ASSERT(seg_index == num_segs);
	CU_ASSERT(data_len <= odp_packet_buf_len(seg_pkt));
	CU_ASSERT(data_len == odp_packet_len(seg_pkt));

	if (seg_index == num_segs)
		CU_ASSERT(seg == ODP_PACKET_SEG_INVALID);
}

void packet_test_segment_last(void)
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
	CU_ASSERT(odp_packet_has_##flag(packet) != 0);    \
} while (0)

void packet_test_in_flags(void)
{
	odp_packet_t pkt = test_packet;

	TEST_INFLAG(pkt, l2);
	TEST_INFLAG(pkt, l3);
	TEST_INFLAG(pkt, l4);
	TEST_INFLAG(pkt, eth);
	TEST_INFLAG(pkt, eth_bcast);
	TEST_INFLAG(pkt, eth_mcast);
	TEST_INFLAG(pkt, jumbo);
	TEST_INFLAG(pkt, vlan);
	TEST_INFLAG(pkt, vlan_qinq);
	TEST_INFLAG(pkt, arp);
	TEST_INFLAG(pkt, ipv4);
	TEST_INFLAG(pkt, ipv6);
	TEST_INFLAG(pkt, ip_bcast);
	TEST_INFLAG(pkt, ip_mcast);
	TEST_INFLAG(pkt, ipfrag);
	TEST_INFLAG(pkt, ipopt);
	TEST_INFLAG(pkt, ipsec);
	TEST_INFLAG(pkt, udp);
	TEST_INFLAG(pkt, tcp);
	TEST_INFLAG(pkt, sctp);
	TEST_INFLAG(pkt, icmp);
}

void packet_test_error_flags(void)
{
	odp_packet_t pkt = test_packet;
	int err;

	/**
	 * The packet have not been classified so it doesn't have error flags
	 * properly set. Just check that functions return one of allowed values.
	 */
	err = odp_packet_has_error(pkt);
	CU_ASSERT(err == 0 || err == 1);

	err = odp_packet_has_l2_error(pkt);
	CU_ASSERT(err == 0 || err == 1);

	err = odp_packet_has_l3_error(pkt);
	CU_ASSERT(err == 0 || err == 1);

	err = odp_packet_has_l4_error(pkt);
	CU_ASSERT(err == 0 || err == 1);
}

struct packet_metadata {
	uint32_t l2_off;
	uint32_t l3_off;
	uint32_t l4_off;
	void *usr_ptr;
	uint64_t usr_u64;
};

void packet_test_add_rem_data(void)
{
	odp_packet_t pkt, new_pkt;
	uint32_t pkt_len, offset, add_len;
	void *usr_ptr;
	struct udata_struct *udat, *new_udat;
	int ret;
	odp_pool_capability_t capa;
	uint32_t min_seg_len;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	min_seg_len = capa.pkt.min_seg_len;

	pkt = odp_packet_alloc(packet_pool, packet_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	pkt_len = odp_packet_len(pkt);
	usr_ptr = odp_packet_user_ptr(pkt);
	udat    = odp_packet_user_area(pkt);
	CU_ASSERT(odp_packet_user_area_size(pkt) ==
		  sizeof(struct udata_struct));
	memcpy(udat, &test_packet_udata, sizeof(struct udata_struct));

	offset = pkt_len / 2;

	if (segmentation_supported) {
		/* Insert one more packet length in the middle of a packet */
		add_len = min_seg_len;
	} else {
		/* Add diff between largest and smaller packets
		 * which is at least tailroom */
		add_len = segmented_packet_len - packet_len;
	}

	new_pkt = pkt;
	ret = odp_packet_add_data(&new_pkt, offset, add_len);
	CU_ASSERT(ret >= 0);
	if (ret < 0)
		goto free_packet;
	CU_ASSERT(odp_packet_len(new_pkt) == pkt_len + add_len);
	/* Verify that user metadata is preserved */
	CU_ASSERT(odp_packet_user_ptr(new_pkt) == usr_ptr);

	/* Verify that user metadata has been preserved */
	new_udat = odp_packet_user_area(new_pkt);
	CU_ASSERT_PTR_NOT_NULL(new_udat);
	CU_ASSERT(odp_packet_user_area_size(new_pkt) ==
		  sizeof(struct udata_struct));
	CU_ASSERT(memcmp(new_udat, &test_packet_udata,
			 sizeof(struct udata_struct)) == 0);

	pkt = new_pkt;

	pkt_len = odp_packet_len(pkt);
	usr_ptr = odp_packet_user_ptr(pkt);

	ret = odp_packet_rem_data(&new_pkt, offset, add_len);
	CU_ASSERT(ret >= 0);
	if (ret < 0)
		goto free_packet;
	CU_ASSERT(odp_packet_len(new_pkt) == pkt_len - add_len);
	CU_ASSERT(odp_packet_user_ptr(new_pkt) == usr_ptr);

	/* Verify that user metadata has been preserved */
	new_udat = odp_packet_user_area(new_pkt);
	CU_ASSERT_PTR_NOT_NULL(new_udat);
	CU_ASSERT(odp_packet_user_area_size(new_pkt) ==
		  sizeof(struct udata_struct));
	CU_ASSERT(memcmp(new_udat, &test_packet_udata,
			 sizeof(struct udata_struct)) == 0);

	pkt = new_pkt;

free_packet:
	odp_packet_free(pkt);
}

#define COMPARE_HAS_INFLAG(p1, p2, flag) \
	CU_ASSERT(odp_packet_has_##flag(p1) == odp_packet_has_##flag(p2))

#define COMPARE_INFLAG(p1, p2, flag) \
	CU_ASSERT(odp_packet_##flag(p1) == odp_packet_##flag(p2))

static void _packet_compare_inflags(odp_packet_t pkt1, odp_packet_t pkt2)
{
	COMPARE_HAS_INFLAG(pkt1, pkt2, l2);
	COMPARE_HAS_INFLAG(pkt1, pkt2, l3);
	COMPARE_HAS_INFLAG(pkt1, pkt2, l4);
	COMPARE_HAS_INFLAG(pkt1, pkt2, eth);
	COMPARE_HAS_INFLAG(pkt1, pkt2, eth_bcast);
	COMPARE_HAS_INFLAG(pkt1, pkt2, eth_mcast);
	COMPARE_HAS_INFLAG(pkt1, pkt2, jumbo);
	COMPARE_HAS_INFLAG(pkt1, pkt2, vlan);
	COMPARE_HAS_INFLAG(pkt1, pkt2, vlan_qinq);
	COMPARE_HAS_INFLAG(pkt1, pkt2, arp);
	COMPARE_HAS_INFLAG(pkt1, pkt2, ipv4);
	COMPARE_HAS_INFLAG(pkt1, pkt2, ipv6);
	COMPARE_HAS_INFLAG(pkt1, pkt2, ip_bcast);
	COMPARE_HAS_INFLAG(pkt1, pkt2, ip_mcast);
	COMPARE_HAS_INFLAG(pkt1, pkt2, ipfrag);
	COMPARE_HAS_INFLAG(pkt1, pkt2, ipopt);
	COMPARE_HAS_INFLAG(pkt1, pkt2, ipsec);
	COMPARE_HAS_INFLAG(pkt1, pkt2, udp);
	COMPARE_HAS_INFLAG(pkt1, pkt2, tcp);
	COMPARE_HAS_INFLAG(pkt1, pkt2, sctp);
	COMPARE_HAS_INFLAG(pkt1, pkt2, icmp);
	COMPARE_HAS_INFLAG(pkt1, pkt2, flow_hash);
	COMPARE_HAS_INFLAG(pkt1, pkt2, ts);

	COMPARE_INFLAG(pkt1, pkt2, color);
	COMPARE_INFLAG(pkt1, pkt2, drop_eligible);
	COMPARE_INFLAG(pkt1, pkt2, shaper_len_adjust);
}

static void _packet_compare_udata(odp_packet_t pkt1, odp_packet_t pkt2)
{
	uint32_t usize1 = odp_packet_user_area_size(pkt1);
	uint32_t usize2 = odp_packet_user_area_size(pkt2);

	void *uaddr1 = odp_packet_user_area(pkt1);
	void *uaddr2 = odp_packet_user_area(pkt2);

	uint32_t cmplen = usize1 <= usize2 ? usize1 : usize2;

	if (cmplen)
		CU_ASSERT(!memcmp(uaddr1, uaddr2, cmplen));
}

static void _packet_compare_offset(odp_packet_t pkt1, uint32_t off1,
				   odp_packet_t pkt2, uint32_t off2,
				   uint32_t len, int line)
{
	uint32_t seglen1, seglen2, cmplen;
	int ret;

	if (off1 + len > odp_packet_len(pkt1) ||
	    off2 + len > odp_packet_len(pkt2))
		return;

	while (len > 0) {
		void *pkt1map = odp_packet_offset(pkt1, off1, &seglen1, NULL);
		void *pkt2map = odp_packet_offset(pkt2, off2, &seglen2, NULL);

		CU_ASSERT_PTR_NOT_NULL_FATAL(pkt1map);
		CU_ASSERT_PTR_NOT_NULL_FATAL(pkt2map);
		cmplen = seglen1 < seglen2 ? seglen1 : seglen2;
		if (len < cmplen)
			cmplen = len;

		ret = memcmp(pkt1map, pkt2map, cmplen);

		if (ret) {
			printf("\ncompare_offset failed: line %i, off1 %"
			       PRIu32 ", off2 %" PRIu32 "\n", line, off1, off2);
		}

		CU_ASSERT(ret == 0);

		off1 += cmplen;
		off2 += cmplen;
		len  -= cmplen;
	}
}

void packet_test_copy(void)
{
	odp_packet_t pkt;
	odp_packet_t pkt_copy, pkt_part;
	odp_pool_t pool;
	uint32_t i, plen, seg_len, src_offset, dst_offset;
	void *pkt_data;

	pkt = odp_packet_copy(test_packet, packet_pool_no_uarea);
	CU_ASSERT(pkt == ODP_PACKET_INVALID);
	if (pkt != ODP_PACKET_INVALID)
		odp_packet_free(pkt);

	pkt = odp_packet_copy(test_packet, odp_packet_pool(test_packet));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	packet_compare_data(pkt, test_packet);
	pool = odp_packet_pool(pkt);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	pkt_copy = odp_packet_copy(pkt, pool);
	CU_ASSERT_FATAL(pkt_copy != ODP_PACKET_INVALID);

	CU_ASSERT(pkt != pkt_copy);
	CU_ASSERT(odp_packet_data(pkt) != odp_packet_data(pkt_copy));
	CU_ASSERT(odp_packet_len(pkt) == odp_packet_len(pkt_copy));

	_packet_compare_inflags(pkt, pkt_copy);
	packet_compare_data(pkt, pkt_copy);
	CU_ASSERT(odp_packet_user_area_size(pkt) ==
		  odp_packet_user_area_size(test_packet));
	_packet_compare_udata(pkt, pkt_copy);
	odp_packet_free(pkt_copy);
	odp_packet_free(pkt);

	pkt = odp_packet_copy(test_packet, packet_pool_double_uarea);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	packet_compare_data(pkt, test_packet);
	pool = odp_packet_pool(pkt);
	CU_ASSERT_FATAL(pool != ODP_POOL_INVALID);
	pkt_copy = odp_packet_copy(pkt, pool);
	CU_ASSERT_FATAL(pkt_copy != ODP_PACKET_INVALID);

	CU_ASSERT(pkt != pkt_copy);
	CU_ASSERT(odp_packet_data(pkt) != odp_packet_data(pkt_copy));
	CU_ASSERT(odp_packet_len(pkt) == odp_packet_len(pkt_copy));

	_packet_compare_inflags(pkt, pkt_copy);
	packet_compare_data(pkt, pkt_copy);
	CU_ASSERT(odp_packet_user_area_size(pkt) ==
		  2 * odp_packet_user_area_size(test_packet));
	_packet_compare_udata(pkt, pkt_copy);
	_packet_compare_udata(pkt, test_packet);
	odp_packet_free(pkt_copy);

	/* Now test copy_part */
	pkt_part = odp_packet_copy_part(pkt, 0, odp_packet_len(pkt) + 1, pool);
	CU_ASSERT(pkt_part == ODP_PACKET_INVALID);
	pkt_part = odp_packet_copy_part(pkt, odp_packet_len(pkt), 1, pool);
	CU_ASSERT(pkt_part == ODP_PACKET_INVALID);

	pkt_part = odp_packet_copy_part(pkt, 0, odp_packet_len(pkt), pool);
	CU_ASSERT_FATAL(pkt_part != ODP_PACKET_INVALID);
	CU_ASSERT(pkt != pkt_part);
	CU_ASSERT(odp_packet_data(pkt) != odp_packet_data(pkt_part));
	CU_ASSERT(odp_packet_len(pkt) == odp_packet_len(pkt_part));

	packet_compare_data(pkt, pkt_part);
	odp_packet_free(pkt_part);

	plen = odp_packet_len(pkt);
	for (i = 0; i < plen / 2; i += 5) {
		pkt_part = odp_packet_copy_part(pkt, i, plen / 4, pool);
		CU_ASSERT_FATAL(pkt_part != ODP_PACKET_INVALID);
		CU_ASSERT(odp_packet_len(pkt_part) == plen / 4);
		packet_compare_offset(pkt_part, 0, pkt, i, plen / 4);
		odp_packet_free(pkt_part);
	}

	/* Test copy and move apis */
	CU_ASSERT(odp_packet_copy_data(pkt, 0, plen - plen / 8, plen / 8) == 0);
	packet_compare_offset(pkt, 0, pkt, plen - plen / 8, plen / 8);
	packet_compare_offset(pkt, 0, test_packet, plen - plen / 8, plen / 8);

	/* Test segment crossing if we support segments */
	pkt_data = odp_packet_offset(pkt, 0, &seg_len, NULL);
	CU_ASSERT(pkt_data != NULL);

	if (seg_len < plen) {
		src_offset = seg_len - 15;
		dst_offset = seg_len - 5;
	} else {
		src_offset = seg_len - 40;
		dst_offset = seg_len - 25;
	}

	pkt_part = odp_packet_copy_part(pkt, src_offset, 20, pool);
	CU_ASSERT(odp_packet_move_data(pkt, dst_offset, src_offset, 20) == 0);
	packet_compare_offset(pkt, dst_offset, pkt_part, 0, 20);

	odp_packet_free(pkt_part);
	odp_packet_free(pkt);
}

void packet_test_copydata(void)
{
	odp_packet_t pkt = test_packet;
	uint32_t pkt_len = odp_packet_len(pkt);
	uint8_t *data_buf;
	uint32_t i;
	int correct_memory;

	CU_ASSERT_FATAL(pkt_len > 0);

	data_buf = malloc(pkt_len);
	CU_ASSERT_PTR_NOT_NULL_FATAL(data_buf);

	for (i = 0; i < pkt_len; i++)
		data_buf[i] = (uint8_t)i;

	CU_ASSERT(!odp_packet_copy_from_mem(pkt, 0, pkt_len, data_buf));
	memset(data_buf, 0, pkt_len);
	CU_ASSERT(!odp_packet_copy_to_mem(pkt, 0, pkt_len, data_buf));

	correct_memory = 1;
	for (i = 0; i < pkt_len; i++)
		if (data_buf[i] != (uint8_t)i) {
			correct_memory = 0;
			break;
		}
	CU_ASSERT(correct_memory);

	free(data_buf);

	pkt = odp_packet_alloc(odp_packet_pool(test_packet), pkt_len / 2);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	CU_ASSERT(odp_packet_copy_from_pkt(pkt, 0, test_packet, 0,
					   pkt_len) < 0);
	CU_ASSERT(odp_packet_copy_from_pkt(pkt, pkt_len, test_packet, 0,
					   1) < 0);

	for (i = 0; i < pkt_len / 2; i++) {
		CU_ASSERT(odp_packet_copy_from_pkt(pkt, i, test_packet, i,
						   1) == 0);
	}

	packet_compare_offset(pkt, 0, test_packet, 0, pkt_len / 2);
	odp_packet_free(pkt);

	pkt = odp_packet_alloc(odp_packet_pool(segmented_test_packet),
			       odp_packet_len(segmented_test_packet) / 2);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	CU_ASSERT(odp_packet_copy_from_pkt(pkt, 0, segmented_test_packet,
					   odp_packet_len(pkt) / 4,
					   odp_packet_len(pkt)) == 0);
	packet_compare_offset(pkt, 0, segmented_test_packet,
			      odp_packet_len(pkt) / 4,
			      odp_packet_len(pkt));
	odp_packet_free(pkt);
}

void packet_test_concatsplit(void)
{
	odp_packet_t pkt, pkt2;
	uint32_t pkt_len;
	odp_packet_t splits[4];
	odp_pool_t pool;

	pool = odp_packet_pool(test_packet);
	pkt  = odp_packet_copy(test_packet, pool);
	pkt2 = odp_packet_copy(test_packet, pool);
	pkt_len = odp_packet_len(test_packet);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT_FATAL(pkt2 != ODP_PACKET_INVALID);
	CU_ASSERT(pkt_len == odp_packet_len(pkt));
	CU_ASSERT(pkt_len == odp_packet_len(pkt2));

	CU_ASSERT(odp_packet_concat(&pkt, pkt2) >= 0);
	CU_ASSERT(odp_packet_len(pkt) == pkt_len * 2);
	packet_compare_offset(pkt, 0, pkt, pkt_len, pkt_len);

	CU_ASSERT(odp_packet_split(&pkt, pkt_len, &pkt2) == 0);
	CU_ASSERT(pkt != pkt2);
	CU_ASSERT(odp_packet_data(pkt) != odp_packet_data(pkt2));
	CU_ASSERT(odp_packet_len(pkt) == odp_packet_len(pkt2));
	packet_compare_data(pkt, pkt2);
	packet_compare_data(pkt, test_packet);

	odp_packet_free(pkt);
	odp_packet_free(pkt2);

	pkt = odp_packet_copy(segmented_test_packet,
			      odp_packet_pool(segmented_test_packet));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	pkt_len = odp_packet_len(pkt);

	packet_compare_data(pkt, segmented_test_packet);
	CU_ASSERT(odp_packet_split(&pkt, pkt_len / 2, &splits[0]) == 0);
	CU_ASSERT(pkt != splits[0]);
	CU_ASSERT(odp_packet_data(pkt) != odp_packet_data(splits[0]));
	CU_ASSERT(odp_packet_len(pkt) == pkt_len / 2);
	CU_ASSERT(odp_packet_len(pkt) + odp_packet_len(splits[0]) == pkt_len);

	packet_compare_offset(pkt, 0, segmented_test_packet, 0, pkt_len / 2);
	packet_compare_offset(splits[0], 0, segmented_test_packet,
			      pkt_len / 2, odp_packet_len(splits[0]));

	CU_ASSERT(odp_packet_concat(&pkt, splits[0]) >= 0);
	packet_compare_offset(pkt, 0, segmented_test_packet, 0, pkt_len / 2);
	packet_compare_offset(pkt, pkt_len / 2, segmented_test_packet,
			      pkt_len / 2, pkt_len / 2);
	packet_compare_offset(pkt, 0, segmented_test_packet, 0,
			      pkt_len);

	CU_ASSERT(odp_packet_len(pkt) == odp_packet_len(segmented_test_packet));
	packet_compare_data(pkt, segmented_test_packet);

	CU_ASSERT(odp_packet_split(&pkt, pkt_len / 2, &splits[0]) == 0);
	CU_ASSERT(odp_packet_split(&pkt, pkt_len / 4, &splits[1]) == 0);
	CU_ASSERT(odp_packet_split(&pkt, pkt_len / 8, &splits[2]) == 0);

	CU_ASSERT(odp_packet_len(splits[0]) + odp_packet_len(splits[1]) +
		  odp_packet_len(splits[2]) + odp_packet_len(pkt) == pkt_len);

	CU_ASSERT(odp_packet_concat(&pkt, splits[2]) >= 0);
	CU_ASSERT(odp_packet_concat(&pkt, splits[1]) >= 0);
	CU_ASSERT(odp_packet_concat(&pkt, splits[0]) >= 0);

	CU_ASSERT(odp_packet_len(pkt) == odp_packet_len(segmented_test_packet));
	packet_compare_data(pkt, segmented_test_packet);

	odp_packet_free(pkt);
}

void packet_test_concat_small(void)
{
	odp_pool_capability_t capa;
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_packet_t pkt, pkt2;
	int ret;
	uint8_t *data;
	uint32_t i;
	uint32_t len = 32000;
	uint8_t buf[len];

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	if (capa.pkt.max_len && capa.pkt.max_len < len)
		len = capa.pkt.max_len;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_PACKET;
	param.pkt.len = len;
	param.pkt.num = 100;

	pool = odp_pool_create("packet_pool_concat", &param);
	CU_ASSERT(packet_pool != ODP_POOL_INVALID);

	pkt = odp_packet_alloc(pool, 1);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	data  = odp_packet_data(pkt);
	*data = 0;

	for (i = 0; i < len - 1; i++) {
		pkt2 = odp_packet_alloc(pool, 1);
		CU_ASSERT_FATAL(pkt2 != ODP_PACKET_INVALID);

		data  = odp_packet_data(pkt2);
		*data = i + 1;

		ret = odp_packet_concat(&pkt, pkt2);
		CU_ASSERT(ret >= 0);

		if (ret < 0) {
			odp_packet_free(pkt2);
			break;
		}
	}

	CU_ASSERT(odp_packet_len(pkt) == len);

	len = odp_packet_len(pkt);

	memset(buf, 0, len);
	CU_ASSERT(odp_packet_copy_to_mem(pkt, 0, len, buf) == 0);

	for (i = 0; i < len; i++)
		CU_ASSERT(buf[i] == (i % 256));

	odp_packet_free(pkt);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

void packet_test_concat_extend_trunc(void)
{
	odp_pool_capability_t capa;
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_packet_t pkt, pkt2;
	int i, ret;
	uint32_t alloc_len, ext_len, trunc_len, cur_len;
	uint32_t len = 1900;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	if (capa.pkt.max_len && capa.pkt.max_len < len)
		len = capa.pkt.max_len;

	alloc_len = len / 8;
	ext_len   = len / 4;
	trunc_len = len / 3;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_PACKET;
	param.pkt.len = len;
	param.pkt.num = 100;

	pool = odp_pool_create("packet_pool_concat", &param);
	CU_ASSERT_FATAL(packet_pool != ODP_POOL_INVALID);

	pkt = odp_packet_alloc(pool, alloc_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	cur_len = odp_packet_len(pkt);

	for (i = 0; i < 2; i++) {
		pkt2 = odp_packet_alloc(pool, alloc_len);
		CU_ASSERT_FATAL(pkt2 != ODP_PACKET_INVALID);

		ret = odp_packet_concat(&pkt, pkt2);
		CU_ASSERT(ret >= 0);

		if (ret < 0)
			odp_packet_free(pkt2);

		CU_ASSERT(odp_packet_len(pkt) == (cur_len + alloc_len));
		cur_len = odp_packet_len(pkt);
		CU_ASSERT(cur_len == odp_packet_unshared_len(pkt));
	}

	ret = odp_packet_extend_tail(&pkt, ext_len, NULL, NULL);
	CU_ASSERT(ret >= 0);

	CU_ASSERT(odp_packet_len(pkt) == (cur_len + ext_len));
	cur_len = odp_packet_len(pkt);
	CU_ASSERT(cur_len == odp_packet_unshared_len(pkt));

	ret = odp_packet_extend_head(&pkt, ext_len, NULL, NULL);
	CU_ASSERT(ret >= 0);

	CU_ASSERT(odp_packet_len(pkt) == (cur_len + ext_len));
	cur_len = odp_packet_len(pkt);
	CU_ASSERT(cur_len == odp_packet_unshared_len(pkt));

	pkt2 = odp_packet_alloc(pool, alloc_len);
	CU_ASSERT_FATAL(pkt2 != ODP_PACKET_INVALID);

	ret = odp_packet_concat(&pkt, pkt2);
	CU_ASSERT(ret >= 0);

	if (ret < 0)
		odp_packet_free(pkt2);

	CU_ASSERT(odp_packet_len(pkt) == (cur_len + alloc_len));
	cur_len = odp_packet_len(pkt);
	CU_ASSERT(cur_len == odp_packet_unshared_len(pkt));

	ret = odp_packet_trunc_head(&pkt, trunc_len, NULL, NULL);
	CU_ASSERT(ret >= 0);

	CU_ASSERT(odp_packet_len(pkt) == (cur_len - trunc_len));
	cur_len = odp_packet_len(pkt);
	CU_ASSERT(cur_len == odp_packet_unshared_len(pkt));

	ret = odp_packet_trunc_tail(&pkt, trunc_len, NULL, NULL);
	CU_ASSERT(ret >= 0);

	CU_ASSERT(odp_packet_len(pkt) == (cur_len - trunc_len));
	cur_len = odp_packet_len(pkt);
	CU_ASSERT(cur_len == odp_packet_unshared_len(pkt));

	odp_packet_free(pkt);

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

void packet_test_extend_small(void)
{
	odp_pool_capability_t capa;
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_packet_t pkt;
	int ret, round;
	uint8_t *data;
	uint32_t i, seg_len;
	int tail = 1;
	uint32_t len = 32000;
	uint8_t buf[len];

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	if (capa.pkt.max_len && capa.pkt.max_len < len)
		len = capa.pkt.max_len;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_PACKET;
	param.pkt.len = len;
	param.pkt.num = 100;

	pool = odp_pool_create("packet_pool_extend", &param);
	CU_ASSERT_FATAL(packet_pool != ODP_POOL_INVALID);

	for (round = 0; round < 2; round++) {
		pkt = odp_packet_alloc(pool, 1);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

		data  = odp_packet_data(pkt);
		*data = 0;

		for (i = 0; i < len - 1; i++) {
			if (tail) {
				ret = odp_packet_extend_tail(&pkt, 1,
							     (void **)&data,
							     &seg_len);
				CU_ASSERT(ret >= 0);
			} else {
				ret = odp_packet_extend_head(&pkt, 1,
							     (void **)&data,
							     &seg_len);
				CU_ASSERT(ret >= 0);
			}

			if (ret < 0)
				break;

			if (tail) {
				/* assert needs brackets */
				CU_ASSERT(seg_len == 1);
			} else {
				CU_ASSERT(seg_len > 0);
			}

			*data = i + 1;
		}

		CU_ASSERT(odp_packet_len(pkt) == len);
		CU_ASSERT(odp_packet_unshared_len(pkt) == len);

		len = odp_packet_len(pkt);

		memset(buf, 0, len);
		CU_ASSERT(odp_packet_copy_to_mem(pkt, 0, len, buf) == 0);

		for (i = 0; i < len; i++) {
			int match;

			if (tail) {
				match = (buf[i] == (i % 256));
				CU_ASSERT(match);
			} else {
				match = (buf[len - 1 - i] == (i % 256));
				CU_ASSERT(match);
			}

			/* Limit the number of failed asserts to
			   one per packet */
			if (!match)
				break;
		}

		odp_packet_free(pkt);

		tail = 0;
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

void packet_test_extend_large(void)
{
	odp_pool_capability_t capa;
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_packet_t pkt;
	int ret, round;
	uint8_t *data;
	uint32_t i, seg_len, ext_len, cur_len, cur_data;
	int tail = 1;
	int num_div = 16;
	int div = 1;
	uint32_t len = 32000;
	uint8_t buf[len];

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	if (capa.pkt.max_len && capa.pkt.max_len < len)
		len = capa.pkt.max_len;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_PACKET;
	param.pkt.len = len;
	param.pkt.num = 100;

	pool = odp_pool_create("packet_pool_extend", &param);
	CU_ASSERT_FATAL(packet_pool != ODP_POOL_INVALID);

	for (round = 0; round < 2 * num_div; round++) {
		ext_len = len / div;
		cur_len = ext_len;

		pkt = odp_packet_alloc(pool, ext_len);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

		cur_data = 0;

		if (tail) {
			ret = fill_data_forward(pkt, 0, ext_len, &cur_data);
			CU_ASSERT(ret == 0);
		} else {
			ret = fill_data_backward(pkt, 0, ext_len, &cur_data);
			CU_ASSERT(ret == 0);
		}

		while (cur_len < len) {
			if ((len - cur_len) < ext_len)
				ext_len = len - cur_len;

			if (tail) {
				ret = odp_packet_extend_tail(&pkt, ext_len,
							     (void **)&data,
							     &seg_len);
				CU_ASSERT(ret >= 0);
			} else {
				ret = odp_packet_extend_head(&pkt, ext_len,
							     (void **)&data,
							     &seg_len);
				CU_ASSERT(ret >= 0);
			}

			if (ret < 0)
				break;

			if (tail) {
				/* assert needs brackets */
				CU_ASSERT((seg_len > 0) &&
					  (seg_len <= ext_len));
				ret = fill_data_forward(pkt, cur_len, ext_len,
							&cur_data);
				CU_ASSERT(ret == 0);
			} else {
				CU_ASSERT(seg_len > 0);
				CU_ASSERT(data == odp_packet_data(pkt));
				ret = fill_data_backward(pkt, 0, ext_len,
							 &cur_data);
				CU_ASSERT(ret == 0);
			}

			cur_len += ext_len;
		}

		CU_ASSERT(odp_packet_len(pkt) == len);

		len = odp_packet_len(pkt);

		memset(buf, 0, len);
		CU_ASSERT(odp_packet_copy_to_mem(pkt, 0, len, buf) == 0);

		for (i = 0; i < len; i++) {
			int match;

			if (tail) {
				match = (buf[i] == (i % 256));
				CU_ASSERT(match);
			} else {
				match = (buf[len - 1 - i] == (i % 256));
				CU_ASSERT(match);
			}

			/* Limit the number of failed asserts to
			   one per packet */
			if (!match)
				break;
		}

		odp_packet_free(pkt);

		div++;
		if (div > num_div) {
			/* test extend head */
			div  = 1;
			tail = 0;
		}
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

void packet_test_extend_mix(void)
{
	odp_pool_capability_t capa;
	odp_pool_t pool;
	odp_pool_param_t param;
	odp_packet_t pkt;
	int ret, round;
	uint8_t *data;
	uint32_t i, seg_len, ext_len, cur_len, cur_data;
	int small_count;
	int tail = 1;
	uint32_t len = 32000;
	uint8_t buf[len];

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	if (capa.pkt.max_len && capa.pkt.max_len < len)
		len = capa.pkt.max_len;

	odp_pool_param_init(&param);

	param.type    = ODP_POOL_PACKET;
	param.pkt.len = len;
	param.pkt.num = 100;

	pool = odp_pool_create("packet_pool_extend", &param);
	CU_ASSERT_FATAL(packet_pool != ODP_POOL_INVALID);

	for (round = 0; round < 2; round++) {
		small_count = 30;
		ext_len = len / 10;
		cur_len = ext_len;

		pkt = odp_packet_alloc(pool, ext_len);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

		cur_data = 0;

		if (tail) {
			ret = fill_data_forward(pkt, 0, ext_len, &cur_data);
			CU_ASSERT(ret == 0);
		} else {
			ret = fill_data_backward(pkt, 0, ext_len, &cur_data);
			CU_ASSERT(ret == 0);
		}

		while (cur_len < len) {
			if (small_count) {
				small_count--;
				ext_len = len / 100;
			} else {
				ext_len = len / 4;
			}

			if ((len - cur_len) < ext_len)
				ext_len = len - cur_len;

			if (tail) {
				ret = odp_packet_extend_tail(&pkt, ext_len,
							     (void **)&data,
							     &seg_len);
				CU_ASSERT(ret >= 0);
				CU_ASSERT((seg_len > 0) &&
					  (seg_len <= ext_len));
				ret = fill_data_forward(pkt, cur_len, ext_len,
							&cur_data);
				CU_ASSERT(ret == 0);
			} else {
				ret = odp_packet_extend_head(&pkt, ext_len,
							     (void **)&data,
							     &seg_len);
				CU_ASSERT(ret >= 0);
				CU_ASSERT(seg_len > 0);
				CU_ASSERT(data == odp_packet_data(pkt));
				ret = fill_data_backward(pkt, 0, ext_len,
							 &cur_data);
				CU_ASSERT(ret == 0);
			}

			cur_len += ext_len;
		}

		CU_ASSERT(odp_packet_len(pkt) == len);

		len = odp_packet_len(pkt);

		memset(buf, 0, len);
		CU_ASSERT(odp_packet_copy_to_mem(pkt, 0, len, buf) == 0);

		for (i = 0; i < len; i++) {
			int match;

			if (tail) {
				match = (buf[i] == (i % 256));
				CU_ASSERT(match);
			} else {
				match = (buf[len - 1 - i] == (i % 256));
				CU_ASSERT(match);
			}

			/* Limit the number of failed asserts to
			   one per packet */
			if (!match)
				break;
		}

		odp_packet_free(pkt);

		tail = 0;
	}

	CU_ASSERT(odp_pool_destroy(pool) == 0);
}

void packet_test_extend_ref(void)
{
	odp_packet_t max_pkt, ref;
	uint32_t hr, tr, max_len;
	odp_pool_capability_t capa;

	CU_ASSERT_FATAL(odp_pool_capability(&capa) == 0);

	max_pkt = odp_packet_copy(segmented_test_packet,
				  odp_packet_pool(segmented_test_packet));
	CU_ASSERT_FATAL(max_pkt != ODP_PACKET_INVALID);
	max_len = odp_packet_len(max_pkt);

	/* Maximize the max pkt */
	hr = odp_packet_headroom(max_pkt);
	tr = odp_packet_tailroom(max_pkt);
	odp_packet_push_head(max_pkt, hr);
	odp_packet_push_tail(max_pkt, tr);

	/* Max packet should not be extendable at either end */
	if (max_len == capa.pkt.max_len) {
		CU_ASSERT(odp_packet_extend_tail(&max_pkt, 1, NULL, NULL) < 0);
		CU_ASSERT(odp_packet_extend_head(&max_pkt, 1, NULL, NULL) < 0);
	}

	/* See if we can trunc and extend anyway */
	CU_ASSERT(odp_packet_trunc_tail(&max_pkt, hr + tr + 1,
					NULL, NULL) >= 0);
	CU_ASSERT(odp_packet_extend_head(&max_pkt, 1, NULL, NULL) >= 0);
	CU_ASSERT(odp_packet_len(max_pkt) == max_len);
	CU_ASSERT(odp_packet_unshared_len(max_pkt) == max_len);

	/* Now try with a reference in place */
	CU_ASSERT(odp_packet_trunc_tail(&max_pkt, 100, NULL, NULL) >= 0);
	ref = odp_packet_ref(max_pkt, 100);

	/* Verify ref lengths */
	CU_ASSERT(ref != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_len(ref) == max_len - 200);
	if (odp_packet_has_ref(ref) == 1) {
		CU_ASSERT(odp_packet_unshared_len(ref) == 0);

		/* And ref's affect on max_pkt */
		CU_ASSERT(odp_packet_has_ref(max_pkt) == 1);
		CU_ASSERT(odp_packet_unshared_len(max_pkt) == 100);
	} else {
		CU_ASSERT(odp_packet_unshared_len(ref) == odp_packet_len(ref));
		CU_ASSERT(odp_packet_unshared_len(max_pkt) ==
			  odp_packet_len(max_pkt));
	}

	/* Now extend max_pkt and verify effect */
	CU_ASSERT(odp_packet_extend_head(&max_pkt, 10, NULL, NULL) >= 0);
	CU_ASSERT(odp_packet_len(max_pkt) == max_len - 90);

	if (odp_packet_has_ref(max_pkt) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(max_pkt) == 110);
	}

	/* Extend on max_pkt should not affect ref */
	CU_ASSERT(odp_packet_len(ref) == max_len - 200);

	if (odp_packet_has_ref(ref) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref) == 0);
	}

	/* Now extend ref and verify effect*/
	CU_ASSERT(odp_packet_extend_head(&ref, 20, NULL, NULL) >= 0);
	CU_ASSERT(odp_packet_len(ref) == max_len - 180);

	if (odp_packet_has_ref(ref) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref) == 20);
	}

	/* Extend on ref should not affect max_pkt */
	CU_ASSERT(odp_packet_len(max_pkt) == max_len - 90);

	if (odp_packet_has_ref(max_pkt) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(max_pkt) == 110);
	}

	/* Trunc max_pkt of all unshared len */
	CU_ASSERT(odp_packet_trunc_head(&max_pkt, 110, NULL, NULL) >= 0);

	/* Verify effect on max_pkt */
	CU_ASSERT(odp_packet_len(max_pkt) == max_len - 200);

	if (odp_packet_has_ref(max_pkt) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(max_pkt) == 0);
	}

	/* Verify that ref is unchanged */
	CU_ASSERT(odp_packet_len(ref) == max_len - 180);

	if (odp_packet_has_ref(ref) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref) == 20);
	}

	/* Free ref and verify that max_pkt is back to being unreferenced */
	odp_packet_free(ref);
	CU_ASSERT(odp_packet_has_ref(max_pkt) == 0);
	CU_ASSERT(odp_packet_len(max_pkt) == max_len - 200);
	CU_ASSERT(odp_packet_unshared_len(max_pkt) == max_len - 200);

	odp_packet_free(max_pkt);
}

void packet_test_align(void)
{
	odp_packet_t pkt;
	uint32_t pkt_len, seg_len, offset, aligned_seglen;
	void *pkt_data, *aligned_data;
	const uint32_t max_align = 32;

	pkt = odp_packet_copy_part(segmented_test_packet, 0,
				   odp_packet_len(segmented_test_packet) / 2,
				   odp_packet_pool(segmented_test_packet));
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	pkt_len = odp_packet_len(pkt);
	seg_len = odp_packet_seg_len(pkt);

	if (odp_packet_is_segmented(pkt)) {
		/* Can't address across segment boundaries */
		CU_ASSERT(odp_packet_align(&pkt, 0, pkt_len, 0) < 0);

		offset = seg_len - 5;
		(void)odp_packet_offset(pkt, offset, &seg_len, NULL);

		/* Realign for addressability */
		CU_ASSERT(odp_packet_align(&pkt, offset,
					   seg_len + 2, 0) >= 0);

		/* Alignment doesn't change packet length or contents */
		CU_ASSERT(odp_packet_len(pkt) == pkt_len);
		(void)odp_packet_offset(pkt, offset, &aligned_seglen, NULL);
		packet_compare_offset(pkt, offset,
				      segmented_test_packet, offset,
				      aligned_seglen);

		/* Verify requested contiguous addressabilty */
		CU_ASSERT(aligned_seglen >= seg_len + 2);
	}

	/* Get a misaligned address */
	pkt_data = odp_packet_offset(pkt, 0, &seg_len, NULL);
	offset = seg_len - 5;
	pkt_data = odp_packet_offset(pkt, offset, &seg_len, NULL);
	if ((uintptr_t)pkt_data % max_align == 0) {
		offset--;
		pkt_data = odp_packet_offset(pkt, offset, &seg_len, NULL);
	}

	/* Realign for alignment */
	CU_ASSERT(odp_packet_align(&pkt, offset, 1, max_align) >= 0);
	aligned_data = odp_packet_offset(pkt, offset, &aligned_seglen, NULL);

	CU_ASSERT(odp_packet_len(pkt) == pkt_len);
	packet_compare_offset(pkt, offset, segmented_test_packet, offset,
			      aligned_seglen);
	CU_ASSERT((uintptr_t)aligned_data % max_align == 0);

	odp_packet_free(pkt);
}

void packet_test_offset(void)
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
	CU_ASSERT_PTR_NOT_NULL(ptr);
	CU_ASSERT(ptr == odp_packet_data(pkt));
	CU_ASSERT(ptr == odp_packet_seg_data(pkt, seg));

	/* Query a second byte */
	start_ptr = ptr;
	full_seg_len = seg_len;
	offset = 1;

	ptr = odp_packet_offset(pkt, offset, &seg_len, NULL);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	CU_ASSERT(ptr == start_ptr + offset);
	CU_ASSERT(seg_len == full_seg_len - offset);

	/* Query the last byte in a segment */
	offset = full_seg_len - 1;

	ptr = odp_packet_offset(pkt, offset, &seg_len, NULL);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	CU_ASSERT(ptr == start_ptr + offset);
	CU_ASSERT(seg_len == full_seg_len - offset);

	/* Query the last byte in a packet */
	offset = odp_packet_len(pkt) - 1;
	ptr = odp_packet_offset(pkt, offset, &seg_len, NULL);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	CU_ASSERT(seg_len == 1);

	/* Pass NULL to [out] arguments */
	ptr = odp_packet_offset(pkt, 0, NULL, NULL);
	CU_ASSERT_PTR_NOT_NULL(ptr);
}

void packet_test_ref(void)
{
	odp_packet_t base_pkt, segmented_base_pkt, hdr_pkt[4],
		ref_pkt[4], refhdr_pkt[4], hdr_cpy;
	uint32_t pkt_len, segmented_pkt_len, hdr_len[4], offset[4], hr[4],
		base_hr, ref_len[4];
	int i;

	base_pkt = odp_packet_copy(test_packet, odp_packet_pool(test_packet));
	base_hr = odp_packet_headroom(base_pkt);
	pkt_len  = odp_packet_len(test_packet);
	CU_ASSERT_FATAL(base_pkt != ODP_PACKET_INVALID);

	segmented_base_pkt =
		odp_packet_copy(segmented_test_packet,
				odp_packet_pool(segmented_test_packet));
	segmented_pkt_len = odp_packet_len(segmented_test_packet);
	CU_ASSERT_FATAL(segmented_base_pkt != ODP_PACKET_INVALID);

	CU_ASSERT(odp_packet_has_ref(base_pkt) == 0);

	hdr_pkt[0] =
		odp_packet_copy_part(segmented_test_packet, 0,
				     odp_packet_len(segmented_test_packet) / 4,
				     odp_packet_pool(segmented_test_packet));
	CU_ASSERT_FATAL(hdr_pkt[0] != ODP_PACKET_INVALID);
	hdr_len[0] = odp_packet_len(hdr_pkt[0]);
	offset[0]  = 0;

	hdr_pkt[1] =
		odp_packet_copy_part(segmented_test_packet, 10,
				     odp_packet_len(segmented_test_packet) / 8,
				     odp_packet_pool(segmented_test_packet));
	CU_ASSERT_FATAL(hdr_pkt[1] != ODP_PACKET_INVALID);
	hdr_len[1] = odp_packet_len(hdr_pkt[1]);
	offset[1]  = 5;

	hdr_pkt[2] = odp_packet_copy_part(test_packet, 0,
					  odp_packet_len(test_packet) / 4,
					  odp_packet_pool(test_packet));
	CU_ASSERT_FATAL(hdr_pkt[2] != ODP_PACKET_INVALID);
	hdr_len[2] = odp_packet_len(hdr_pkt[2]);
	offset[2]  = 64;

	hdr_pkt[3] = odp_packet_copy_part(test_packet, 0,
					  odp_packet_len(test_packet) / 4,
					  odp_packet_pool(test_packet));
	CU_ASSERT_FATAL(hdr_pkt[3] != ODP_PACKET_INVALID);
	hdr_len[3] = odp_packet_len(hdr_pkt[3]);
	offset[3]  = 64;

	/* Nothing is a ref or has a ref before we start */
	for (i = 0; i < 4; i++) {
		CU_ASSERT(odp_packet_has_ref(hdr_pkt[i]) == 0);
		CU_ASSERT(odp_packet_len(hdr_pkt[i]) ==
			  odp_packet_unshared_len(hdr_pkt[i]));
	}

	/* Create a couple of refs */
	refhdr_pkt[0] = odp_packet_ref_pkt(base_pkt, offset[0], hdr_pkt[0]);
	refhdr_pkt[1] = odp_packet_ref_pkt(base_pkt, offset[1], hdr_pkt[1]);

	CU_ASSERT(refhdr_pkt[0] != ODP_PACKET_INVALID);
	CU_ASSERT(refhdr_pkt[1] != ODP_PACKET_INVALID);

	/* If base packet has now references, ref packet should be also
	 * references. */
	if (odp_packet_has_ref(base_pkt) == 1) {
		CU_ASSERT(odp_packet_has_ref(refhdr_pkt[0]) == 1);
		CU_ASSERT(odp_packet_has_ref(refhdr_pkt[1]) == 1);

		CU_ASSERT(odp_packet_unshared_len(base_pkt) == 0);
	} else {
		CU_ASSERT(odp_packet_unshared_len(base_pkt) == pkt_len);
	}

	CU_ASSERT(odp_packet_len(refhdr_pkt[0]) ==
		  hdr_len[0] + pkt_len - offset[0]);
	CU_ASSERT(odp_packet_len(refhdr_pkt[1]) ==
		  hdr_len[1] + pkt_len - offset[1]);

	if (odp_packet_has_ref(refhdr_pkt[0]) == 1) {
		CU_ASSERT(odp_packet_unshared_len(refhdr_pkt[0]) == hdr_len[0]);
	} else {
		CU_ASSERT(odp_packet_unshared_len(refhdr_pkt[0]) ==
			  odp_packet_len(refhdr_pkt[0]));
	}

	if (odp_packet_has_ref(refhdr_pkt[1]) == 1) {
		CU_ASSERT(odp_packet_unshared_len(refhdr_pkt[1]) == hdr_len[1]);
	} else {
		CU_ASSERT(odp_packet_unshared_len(refhdr_pkt[1]) ==
			  odp_packet_len(refhdr_pkt[1]));
	}

	packet_compare_offset(refhdr_pkt[0], hdr_len[0],
			      base_pkt, offset[0],
			      pkt_len - offset[0]);

	packet_compare_offset(refhdr_pkt[1], hdr_len[1],
			      base_pkt, offset[1],
			      pkt_len - offset[1]);

	/* See if compound references are supported and if so that they
	 * operate properly */
	hdr_cpy = odp_packet_copy(hdr_pkt[2], odp_packet_pool(hdr_pkt[2]));
	CU_ASSERT_FATAL(hdr_cpy != ODP_PACKET_INVALID);

	refhdr_pkt[2] = odp_packet_ref_pkt(refhdr_pkt[0], 2, hdr_cpy);
	CU_ASSERT(refhdr_pkt[2] != ODP_PACKET_INVALID);

	if (odp_packet_has_ref(refhdr_pkt[2]) == 1) {
		CU_ASSERT(odp_packet_has_ref(refhdr_pkt[0]) == 1);
		CU_ASSERT(odp_packet_unshared_len(refhdr_pkt[2]) == hdr_len[2]);
		CU_ASSERT(odp_packet_unshared_len(refhdr_pkt[0]) == 2);
	}

	/* Delete the refs */
	odp_packet_free(refhdr_pkt[0]);
	odp_packet_free(refhdr_pkt[1]);
	odp_packet_free(refhdr_pkt[2]);

	/* Verify that base_pkt no longer has a ref */
	CU_ASSERT(odp_packet_has_ref(base_pkt) == 0);

	/* Now create a two more shared refs */
	refhdr_pkt[2] = odp_packet_ref_pkt(base_pkt, offset[2], hdr_pkt[2]);
	refhdr_pkt[3] = odp_packet_ref_pkt(base_pkt, offset[3], hdr_pkt[3]);

	CU_ASSERT(hdr_pkt[2] != ODP_PACKET_INVALID);
	CU_ASSERT(hdr_pkt[3] != ODP_PACKET_INVALID);

	if (odp_packet_has_ref(base_pkt) == 1) {
		CU_ASSERT(odp_packet_has_ref(refhdr_pkt[2]) == 1);
		CU_ASSERT(odp_packet_has_ref(refhdr_pkt[3]) == 1);
	}

	CU_ASSERT(odp_packet_len(refhdr_pkt[2]) ==
		  odp_packet_len(refhdr_pkt[3]));

	packet_compare_offset(refhdr_pkt[2], 0,
			      refhdr_pkt[3], 0,
			      odp_packet_len(hdr_pkt[2]));

	/* Delete the headers */
	odp_packet_free(refhdr_pkt[2]);
	odp_packet_free(refhdr_pkt[3]);

	/* Verify that base_pkt is no longer ref'd */
	CU_ASSERT(odp_packet_has_ref(base_pkt) == 0);

	/* Create a static reference */
	ref_pkt[0] = odp_packet_ref_static(base_pkt);
	CU_ASSERT(ref_pkt[0] != ODP_PACKET_INVALID);

	if (odp_packet_has_ref(base_pkt) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_has_ref(ref_pkt[0]) == 1);
	}

	CU_ASSERT(odp_packet_len(ref_pkt[0]) == odp_packet_len(base_pkt));
	packet_compare_offset(ref_pkt[0], 0, base_pkt, 0,
			      odp_packet_len(base_pkt));

	/* Now delete it */
	odp_packet_free(ref_pkt[0]);
	CU_ASSERT(odp_packet_has_ref(base_pkt) == 0);

	/* Create references */
	ref_pkt[0] = odp_packet_ref(segmented_base_pkt, offset[0]);
	CU_ASSERT_FATAL(ref_pkt[0] != ODP_PACKET_INVALID);

	if (odp_packet_has_ref(ref_pkt[0]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_has_ref(segmented_base_pkt) == 1);
	}

	ref_pkt[1] = odp_packet_ref(segmented_base_pkt, offset[1]);
	CU_ASSERT_FATAL(ref_pkt[1] != ODP_PACKET_INVALID);

	if (odp_packet_has_ref(ref_pkt[1]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_has_ref(segmented_base_pkt) == 1);
	}

	/* Verify reference lengths */
	CU_ASSERT(odp_packet_len(ref_pkt[0]) == segmented_pkt_len - offset[0]);
	CU_ASSERT(odp_packet_len(ref_pkt[1]) == segmented_pkt_len - offset[1]);

	if (odp_packet_has_ref(ref_pkt[0]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[0]) == 0);
	}

	if (odp_packet_has_ref(ref_pkt[1]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[1]) == 0);
	}

	/* Free the base pkts -- references should still be valid */
	odp_packet_free(base_pkt);
	odp_packet_free(segmented_base_pkt);

	packet_compare_offset(ref_pkt[0], 0,
			      segmented_test_packet, offset[0],
			      segmented_pkt_len - offset[0]);
	packet_compare_offset(ref_pkt[1], 0,
			      segmented_test_packet, offset[1],
			      segmented_pkt_len - offset[1]);

	/* Verify we can modify the refs */
	hr[0] = odp_packet_headroom(ref_pkt[0]);
	hr[1] = odp_packet_headroom(ref_pkt[1]);

	CU_ASSERT(odp_packet_push_head(ref_pkt[0], hr[0]) != NULL);

	if (odp_packet_has_ref(ref_pkt[0]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[0]) == hr[0]);
	}

	CU_ASSERT(odp_packet_len(ref_pkt[0]) ==
		  hr[0] + segmented_pkt_len - offset[0]);

	CU_ASSERT(odp_packet_pull_head(ref_pkt[0], hr[0] / 2) != NULL);

	if (odp_packet_has_ref(ref_pkt[0]) == 1) {
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[0]) ==
			  hr[0] - (hr[0] / 2));
	}

	if (hr[1] > 0) {
		CU_ASSERT(odp_packet_push_head(ref_pkt[1], 1) != NULL);
		if (odp_packet_has_ref(ref_pkt[1]) == 1) {
			/* CU_ASSERT needs braces */
			CU_ASSERT(odp_packet_unshared_len(ref_pkt[1]) == 1);
		}
		CU_ASSERT(odp_packet_len(ref_pkt[1]) ==
			  1 + segmented_pkt_len - offset[1]);
		CU_ASSERT(odp_packet_pull_head(ref_pkt[1], 1) != NULL);
		if (odp_packet_has_ref(ref_pkt[1]) == 1) {
			/* CU_ASSERT needs braces */
			CU_ASSERT(odp_packet_unshared_len(ref_pkt[1]) == 0);
		}
		CU_ASSERT(odp_packet_len(ref_pkt[1]) ==
			  segmented_pkt_len - offset[1]);
	}

	odp_packet_free(ref_pkt[0]);
	odp_packet_free(ref_pkt[1]);

	/* Verify we can modify base packet after reference is created */
	base_pkt = odp_packet_copy(test_packet, odp_packet_pool(test_packet));

	ref_pkt[1] = odp_packet_ref(base_pkt, offset[1]);
	CU_ASSERT_FATAL(ref_pkt[1] != ODP_PACKET_INVALID);
	ref_len[1] = odp_packet_len(ref_pkt[1]);
	CU_ASSERT(ref_len[1] == odp_packet_len(base_pkt) - offset[1]);

	if (odp_packet_has_ref(ref_pkt[1]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[1]) == 0);
	}

	CU_ASSERT(odp_packet_push_head(base_pkt, base_hr / 2) != NULL);

	if (odp_packet_has_ref(base_pkt) == 1) {
		CU_ASSERT(odp_packet_unshared_len(base_pkt) ==
			  base_hr / 2 + offset[1]);
	}
	CU_ASSERT(odp_packet_len(ref_pkt[1]) == ref_len[1]);
	if (odp_packet_has_ref(ref_pkt[1]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[1]) == 0);
	}

	ref_pkt[0] = odp_packet_ref(base_pkt, offset[0]);
	CU_ASSERT_FATAL(ref_pkt[0] != ODP_PACKET_INVALID);
	ref_len[0] = odp_packet_len(ref_pkt[0]);
	CU_ASSERT(ref_len[0] = odp_packet_len(base_pkt) - offset[0]);
	if (odp_packet_has_ref(ref_pkt[0]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[0]) == 0);
	}

	CU_ASSERT(odp_packet_push_head(base_pkt,
				       base_hr - base_hr / 2) != NULL);
	if (odp_packet_has_ref(base_pkt) == 1) {
		CU_ASSERT(odp_packet_unshared_len(base_pkt) ==
			  base_hr - base_hr / 2 + offset[0]);
	}
	CU_ASSERT(odp_packet_len(ref_pkt[1]) == ref_len[1]);
	CU_ASSERT(odp_packet_len(ref_pkt[0]) == ref_len[0]);

	if (odp_packet_has_ref(ref_pkt[1]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[1]) == 0);
	}
	if (odp_packet_has_ref(ref_pkt[0]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[0]) == 0);
	}

	hr[0] = odp_packet_headroom(ref_pkt[0]);
	hr[1] = odp_packet_headroom(ref_pkt[1]);
	CU_ASSERT(odp_packet_push_head(ref_pkt[0], hr[0]) != NULL);
	CU_ASSERT(odp_packet_push_head(ref_pkt[1], hr[1]) != NULL);
	if (odp_packet_has_ref(ref_pkt[0]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[0]) == hr[0]);
	}
	if (odp_packet_has_ref(ref_pkt[1]) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(ref_pkt[1]) == hr[1]);
	}
	if (odp_packet_has_ref(base_pkt) == 1) {
		/* CU_ASSERT needs braces */
		CU_ASSERT(odp_packet_unshared_len(base_pkt) ==
			  base_hr - base_hr / 2 + offset[0]);
	}

	odp_packet_free(base_pkt);
	odp_packet_free(ref_pkt[0]);
	odp_packet_free(ref_pkt[1]);
}

odp_testinfo_t packet_suite[] = {
	ODP_TEST_INFO(packet_test_alloc_free),
	ODP_TEST_INFO(packet_test_alloc_free_multi),
	ODP_TEST_INFO(packet_test_alloc_segmented),
	ODP_TEST_INFO(packet_test_basic_metadata),
	ODP_TEST_INFO(packet_test_debug),
	ODP_TEST_INFO(packet_test_segments),
	ODP_TEST_INFO(packet_test_length),
	ODP_TEST_INFO(packet_test_prefetch),
	ODP_TEST_INFO(packet_test_headroom),
	ODP_TEST_INFO(packet_test_tailroom),
	ODP_TEST_INFO(packet_test_context),
	ODP_TEST_INFO(packet_test_event_conversion),
	ODP_TEST_INFO(packet_test_layer_offsets),
	ODP_TEST_INFO(packet_test_segment_last),
	ODP_TEST_INFO(packet_test_in_flags),
	ODP_TEST_INFO(packet_test_error_flags),
	ODP_TEST_INFO(packet_test_add_rem_data),
	ODP_TEST_INFO(packet_test_copy),
	ODP_TEST_INFO(packet_test_copydata),
	ODP_TEST_INFO(packet_test_concatsplit),
	ODP_TEST_INFO(packet_test_concat_small),
	ODP_TEST_INFO(packet_test_concat_extend_trunc),
	ODP_TEST_INFO(packet_test_extend_small),
	ODP_TEST_INFO(packet_test_extend_large),
	ODP_TEST_INFO(packet_test_extend_mix),
	ODP_TEST_INFO(packet_test_extend_ref),
	ODP_TEST_INFO(packet_test_align),
	ODP_TEST_INFO(packet_test_offset),
	ODP_TEST_INFO(packet_test_ref),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t packet_suites[] = {
	{ .pName = "packet tests",
			.pTests = packet_suite,
			.pInitFunc = packet_suite_init,
			.pCleanupFunc = packet_suite_term,
	},
	ODP_SUITE_INFO_NULL,
};

int packet_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	ret = odp_cunit_register(packet_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

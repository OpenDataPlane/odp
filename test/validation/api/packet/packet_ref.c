/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

#include "packet_ref.h"

#include <odp_api.h>
#include <odp_cunit_common.h>
#include <packet_common.h>

#include <odp/helper/odph_api.h>

#include <stdint.h>
#include <stdlib.h>

#define MAX_SEGS 10
#define MAX_PKT_NUM 30
#define MAX_PKT_LEN 100
static uint32_t uarea_size = 8;

static odp_pool_t packet_pool;

typedef struct {
	odp_packet_seg_t handle;
	uint8_t *data;
	uint32_t len;
} seg_info_t;

typedef struct {
	uint32_t total_len;
	uint32_t num_segs;
	seg_info_t segs[MAX_SEGS];
} packet_seg_info_t;

typedef struct {
	test_packet_md_t metadata;
	uint32_t len;
	uint32_t headroom;
	uint32_t tailroom;
	uint8_t *head;
	uint8_t *data;
	uint8_t *tail;
	uint8_t *uarea;
	packet_seg_info_t seg_info;
	uint8_t pkt_data[MAX_PKT_LEN];
} pkt_state_t;

typedef enum pkt_type_t {
	PKT_TYPE_NORMAL,      /* mutable */
	PKT_TYPE_REFERENCING, /* mutable (but shared data may not be written to) */
	PKT_TYPE_STATIC_REF,  /* immutable */
	PKT_TYPE_REFERENCED,  /* immutable (but mutable metadata) */
} pkt_type_t;

/*
 * Operation to be done to the dynamic ref or the base packet (depending on
 * which packet type is being tested) during test packet creation to add
 * more variation to the test packets. This e.g. can add private packet data
 * to referencing packets so that the API functions get tested with such
 * packet too.
 */
typedef enum pre_op_t {
	PRE_OP_NONE,
	PRE_OP_EXTEND_HEAD,
	PRE_OP_EXTEND_TAIL,
	PRE_OP_TRUNC_HEAD,
	PRE_OP_TRUNC_TAIL,
} pre_op_t;

#define NUM_PRE_OPS 5

/*
 * Test packet creation parameters
 */
typedef struct pkt_param_t {
	pkt_type_t pkt_type;    /* normal/static ref/reference/referenced */
	uint32_t base_len;      /* length of the initial packet created */
	uint32_t base_num_segs; /* number of segments in the initial packet */
	uint32_t ref_offset;    /* if dynamic ref, the creation offset */
	pre_op_t pre_op;        /* operation to be done to the base pkt or its reference */
	uint32_t pre_op_param;  /* parameter for the pre_op */
} pkt_param_t;

typedef struct test_pkt_state_t {
	odp_packet_t pkt;      /* base pkt or reference of the test packet */
	pkt_state_t pkt_state; /* saved state of the above packet */
} test_pkt_state_t;

typedef struct {
	uint32_t len;      /* length of base packet */
	uint32_t num_segs; /* number of segments in base packet */
	uint32_t offset;   /* start offset of data to be referenced */
} pkt_layout_t;

typedef void (*pkt_adj_func_t)(odp_packet_t *pkt, uint32_t len);

typedef void (*pkt_func_t)(const pkt_param_t *pkt_param, const void *ctx);

/* We use this to avoid having to cast function pointers to void pointers */
typedef struct pkt_adj_param_t {
	pkt_adj_func_t func;
} pkt_adj_param_t;

static uint32_t minstd_rand(void)
{
	static uint64_t s = 1;
	uint64_t prime = 0x7fffffff;

	s = (48271 * s) % prime;
	return s;
}

static uint32_t random_u32(void)
{
	return minstd_rand();
}

static uint8_t random_u8(void)
{
	return minstd_rand();
}

static void check_metadata_equal(const test_packet_md_t *md_1,
				 const test_packet_md_t *md_2)
{
	CU_ASSERT(test_packet_is_md_equal(md_1, md_2));
}

static const seg_info_t *last_seg(const packet_seg_info_t *seg_info)
{
	CU_ASSERT_FATAL(seg_info->num_segs > 0);
	return &seg_info->segs[seg_info->num_segs - 1];
}

static void save_seg_info(odp_packet_t pkt, packet_seg_info_t *seg_info)
{
	odp_packet_seg_t seg;
	uint32_t num_segs = 0;
	uint32_t total_len = 0;

	for (seg = odp_packet_first_seg(pkt), num_segs = 0;
	     seg != ODP_PACKET_SEG_INVALID;
	     seg = odp_packet_next_seg(pkt, seg), num_segs++) {
		uint8_t *data;
		uint32_t len;

		CU_ASSERT_FATAL(num_segs < MAX_SEGS);

		data = odp_packet_seg_data(pkt, seg);
		len = odp_packet_seg_data_len(pkt, seg);
		CU_ASSERT(data != NULL);
		CU_ASSERT(len != 0);

		seg_info->segs[num_segs].handle = seg;
		seg_info->segs[num_segs].data = data;
		seg_info->segs[num_segs].len = len;

		total_len += len;
	}
	seg_info->num_segs = num_segs;
	seg_info->total_len = total_len;
}

static void check_seg_info_equal(const packet_seg_info_t *a, const packet_seg_info_t *b)
{
	CU_ASSERT(a->total_len == b->total_len);
	CU_ASSERT(a->num_segs == b->num_segs);

	for (uint32_t n = 0; n < a->num_segs; n++) {
		CU_ASSERT(a->segs[n].handle == b->segs[n].handle);
		CU_ASSERT(a->segs[n].data == b->segs[n].data);
		CU_ASSERT(a->segs[n].len == b->segs[n].len);
	}
}

static void check_ptrs_equal(const packet_seg_info_t *a, const packet_seg_info_t *b)
{
	CU_ASSERT(a->total_len == b->total_len);
	CU_ASSERT(a->num_segs == b->num_segs);

	for (uint32_t n = 0; n < a->num_segs; n++) {
		CU_ASSERT_FATAL(a->segs[n].data == b->segs[n].data);
		CU_ASSERT_FATAL(a->segs[n].len == b->segs[n].len);
	}
}

/* combine consecutive segments with adjacent data areas to make comparisons work */
static void compact_seg_info(packet_seg_info_t *si)
{
	uint32_t num_combined = 0;
	seg_info_t *seg = si->segs;

	for (uint32_t n = 1; n < si->num_segs; n++) {
		if (seg->data + seg->len == si->segs[n].data) {
			seg->len += si->segs[n].len;
			num_combined++;
		} else {
			seg++;
			if (num_combined > 0)
				*seg = si->segs[n];
		}
	}
	si->num_segs -= num_combined;
}

/* truncate seg info as if the packet head were truncated */
static void seg_info_trunc_head(packet_seg_info_t *seg, uint32_t trunc_len)
{
	uint32_t len = 0;
	int n;
	int first_seg;

	CU_ASSERT_FATAL(trunc_len < seg->total_len);

	if (trunc_len == 0)
		return;

	/* find the first segment after truncation */
	for (n = 0; len <= trunc_len; n++) {
		CU_ASSERT_FATAL(n < MAX_SEGS);
		len += seg->segs[n].len;
	}
	first_seg = n - 1;
	seg->num_segs -= first_seg;
	memmove(&seg->segs[0], &seg->segs[first_seg], seg->num_segs * sizeof(seg->segs[0]));
	seg->segs[0].data += seg->segs[0].len - len + trunc_len;
	seg->segs[0].len = len - trunc_len;
	seg->total_len -= trunc_len;
}

/* truncate seg info as if the packet tail were truncated */
static void seg_info_trunc_tail(packet_seg_info_t *seg, uint32_t trunc_len)
{
	uint32_t len = 0;
	uint32_t new_len = seg->total_len - trunc_len;
	int n;

	CU_ASSERT_FATAL(trunc_len < seg->total_len);

	if (trunc_len == 0)
		return;

	/* find the last segment after truncation */
	for (n = 0; len < new_len; n++) {
		CU_ASSERT_FATAL(n < MAX_SEGS);
		len += seg->segs[n].len;
	}
	seg->num_segs = n;
	seg->segs[n - 1].len -= len - new_len;
	seg->total_len = new_len;
}

static uint8_t *get_data_ptr(const packet_seg_info_t *si, uint32_t offset,
			     uint32_t *continuous_len)
{
	uint32_t len = 0;
	uint32_t n;

	for (n = 0; ; n++) {
		CU_ASSERT_FATAL(n < si->num_segs);
		len += si->segs[n].len;
		if (len > offset)
			break;
	}
	*continuous_len = len - offset;
	return si->segs[n].data + si->segs[n].len - *continuous_len;
}

static void save_pkt_state(odp_packet_t pkt, pkt_state_t *state)
{
	int rc;

	state->len      = odp_packet_len(pkt);
	state->headroom = odp_packet_headroom(pkt);
	state->tailroom = odp_packet_tailroom(pkt);
	state->head     = odp_packet_head(pkt);
	state->data     = odp_packet_data(pkt);
	state->tail     = odp_packet_tail(pkt);
	state->uarea    = odp_packet_user_area(pkt);

	test_packet_get_md(pkt, &state->metadata);

	save_seg_info(pkt, &state->seg_info);
	CU_ASSERT(state->seg_info.num_segs == (uint32_t)odp_packet_num_segs(pkt));
	CU_ASSERT(state->len == state->seg_info.total_len);
	CU_ASSERT(state->data == state->seg_info.segs[0].data);
	CU_ASSERT(state->tail == (last_seg(&state->seg_info)->data +
				  last_seg(&state->seg_info)->len));

	CU_ASSERT_FATAL(state->len <= sizeof(state->pkt_data));
	rc = odp_packet_copy_to_mem(pkt, 0, state->len, state->pkt_data);
	CU_ASSERT(rc == 0);
}

/* Check that pointers to first 'len' bytes of packet data are the same */
static void check_ptrs_head(const packet_seg_info_t *a,
			    const packet_seg_info_t *b, uint32_t len)
{
	packet_seg_info_t x = *a;
	packet_seg_info_t y = *b;

	if (len == 0)
		return;

	seg_info_trunc_tail(&x, x.total_len - len);
	seg_info_trunc_tail(&y, y.total_len - len);
	compact_seg_info(&x);
	compact_seg_info(&y);
	check_ptrs_equal(&x, &y);
}

/* Check that pointers to last 'tail_len' bytes of packet data are the same */
static void check_ptrs_tail(const packet_seg_info_t *a,
			    const packet_seg_info_t *b, uint32_t tail_len)
{
	packet_seg_info_t x = *a;
	packet_seg_info_t y = *b;

	if (tail_len == 0)
		return;

	seg_info_trunc_head(&x, x.total_len - tail_len);
	seg_info_trunc_head(&y, y.total_len - tail_len);
	compact_seg_info(&x);
	compact_seg_info(&y);
	check_ptrs_equal(&x, &y);
}

static void check_pkt_data(const pkt_state_t *a, uint32_t a_offs,
			   const pkt_state_t *b, uint32_t b_offs,
			   uint32_t len)
{
	CU_ASSERT_FATAL(a_offs + len <= a->len);
	CU_ASSERT_FATAL(b_offs + len <= b->len);
	if (len == 0)
		return;
	CU_ASSERT(memcmp(&a->pkt_data[a_offs], &b->pkt_data[b_offs], len) == 0);
}

static void check_pkt_data_equal(const pkt_state_t *a, const pkt_state_t *b)
{
	CU_ASSERT(a->len == b->len);
	check_pkt_data(a, 0, b, 0, a->len);
}

static void check_pkt_state_equal(const pkt_state_t *state_1, const pkt_state_t *state_2)
{
	check_metadata_equal(&state_1->metadata, &state_2->metadata);

	CU_ASSERT(state_1->len        == state_2->len);
	CU_ASSERT(state_1->headroom   == state_2->headroom);
	CU_ASSERT(state_1->tailroom   == state_2->tailroom);
	CU_ASSERT(state_1->head       == state_2->head);
	CU_ASSERT(state_1->data       == state_2->data);
	CU_ASSERT(state_1->tail       == state_2->tail);
	CU_ASSERT(state_1->uarea      == state_2->uarea);

	check_seg_info_equal(&state_1->seg_info, &state_2->seg_info);
	check_pkt_data_equal(state_1, state_2);
}

/*
 * Create a packet with one or more segments, rounding up len to make it
 * divisible by num_segs.
 *
 * Make reasonable assumptions on the underlying ODP implementation on
 * how segmented packets can be created as ODP API does not have any
 * guaranteed way to do it. Fail if segmented packets cannot be made.
 */
static odp_packet_t alloc_packet(uint32_t len, uint32_t num_segs)
{
	uint32_t seg_len;
	odp_packet_t pkt;

	len = ODPH_ROUNDUP_MULTIPLE(len, num_segs);
	seg_len = len / num_segs;
	CU_ASSERT(seg_len > 0);

	pkt = odp_packet_alloc(packet_pool, seg_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_ref(pkt) == 0);
	CU_ASSERT(odp_packet_is_referencing(pkt) == 0);

	for (uint32_t n = 1; n < num_segs; n++) {
		odp_packet_t seg = odp_packet_alloc(packet_pool, seg_len);

		CU_ASSERT_FATAL(seg != ODP_PACKET_INVALID);
		CU_ASSERT(odp_packet_has_ref(seg) == 0);
		CU_ASSERT(odp_packet_is_referencing(seg) == 0);
		CU_ASSERT_FATAL(odp_packet_concat(&pkt, seg) >= 0);
	}
	CU_ASSERT(odp_packet_is_segmented(pkt) == (num_segs != 1));
	CU_ASSERT((uint32_t)odp_packet_num_segs(pkt) == num_segs);
	CU_ASSERT(odp_packet_seg_len(pkt) == seg_len);
	CU_ASSERT(odp_packet_len(pkt) == len);

	return pkt;
}

static void write_uarea(odp_packet_t pkt)
{
	uint8_t *uarea = odp_packet_user_area(pkt);

	CU_ASSERT(uarea_size == odp_packet_user_area_size(pkt));
	if (uarea_size == 0) {
		CU_ASSERT(uarea == NULL);
		return;
	}
	CU_ASSERT_FATAL(uarea != NULL);

	for (uint32_t n = 0; n < uarea_size; n++)
		uarea[n] = random_u8();
}

/* set some metadata to random values to better see changes and equality */
static void set_random_md(odp_packet_t pkt)
{
	uint32_t len = odp_packet_len(pkt);
	uintptr_t addr = random_u32();

	odp_packet_user_ptr_set(pkt, (const void *)addr);
	odp_packet_flow_hash_set(pkt, random_u32());
	CU_ASSERT(odp_packet_l2_offset_set(pkt, random_u8() % len) == 0);
	CU_ASSERT(odp_packet_l3_offset_set(pkt, random_u8() % len) == 0);
	CU_ASSERT(odp_packet_l4_offset_set(pkt, random_u8() % len) == 0);
	CU_ASSERT(odp_packet_payload_offset_set(pkt, random_u8() % len) == 0);
}

static odp_packet_t make_packet(uint32_t len, uint32_t num_segs)
{
	odp_packet_t pkt;
	uint8_t data[len];
	int rc;

	pkt = alloc_packet(len, num_segs);

	for (uint32_t n = 0; n < len; n++)
		data[n] = random_u8();
	rc = odp_packet_copy_from_mem(pkt, 0, len, data);
	CU_ASSERT(rc == 0);

	test_packet_set_md(pkt);
	set_random_md(pkt);
	write_uarea(pkt);

	return pkt;
}

static void check_metadata_default(odp_packet_t pkt)
{
	packet_check_default_meta(pkt);
}

static void check_packet_data(odp_packet_t ref, const pkt_state_t *base_state, uint32_t offset)
{
	uint32_t len = odp_packet_len(ref);
	uint8_t ref_data[len];
	int rc;

	rc = odp_packet_copy_to_mem(ref, 0, len, ref_data);
	CU_ASSERT(rc == 0);
	CU_ASSERT_FATAL(base_state->len >= len + offset);
	CU_ASSERT(memcmp(ref_data, base_state->pkt_data + offset, len) == 0);
}

static void write_pkt_data(odp_packet_t pkt, uint32_t offset, uint32_t len)
{
	uint8_t w_data[len + 1]; /* +1 to avoid zero length array */
	uint8_t r_data[len + 1];
	int rc;

	if (len == 0)
		return;

	for (uint32_t n = 0; n < len; n++)
		w_data[n] = random_u8();
	rc = odp_packet_copy_from_mem(pkt, offset, len, w_data);
	CU_ASSERT(rc == 0);
	rc = odp_packet_copy_to_mem(pkt, offset, len, r_data);
	CU_ASSERT(rc == 0);
	CU_ASSERT(memcmp(w_data, r_data, len) == 0);
}

static uint32_t iterate_pkt_layout(pkt_layout_t *layout, uint32_t *iterator)
{
	static const pkt_layout_t layouts[] = {
		{.len = 10, .num_segs = 1, .offset = 0},
		{.len = 10, .num_segs = 1, .offset = 5},
		{.len = 10, .num_segs = 1, .offset = 9},

		{.len = 20, .num_segs = 2, .offset = 0},
		{.len = 20, .num_segs = 2, .offset = 5},
		{.len = 20, .num_segs = 2, .offset = 9},
		{.len = 20, .num_segs = 2, .offset = 10},
		{.len = 20, .num_segs = 2, .offset = 15},
		{.len = 20, .num_segs = 2, .offset = 19},

		{.len = 30, .num_segs = 3, .offset = 0},
		{.len = 30, .num_segs = 3, .offset = 5},
		{.len = 20, .num_segs = 2, .offset = 9},
		{.len = 30, .num_segs = 3, .offset = 10},
		{.len = 30, .num_segs = 3, .offset = 15},
		{.len = 20, .num_segs = 2, .offset = 19},
		{.len = 30, .num_segs = 3, .offset = 20},
		{.len = 30, .num_segs = 3, .offset = 25},
		{.len = 30, .num_segs = 3, .offset = 29},
	};

	if (*iterator == ODPH_ARRAY_SIZE(layouts))
		return 0;

	*layout = layouts[*iterator];
	*iterator += 1;
	return 1;
}

static odp_packet_t create_ref(odp_packet_t base, const pkt_state_t *base_state, uint32_t offset)
{
	odp_packet_t ref;
	pkt_state_t after;

	ref = odp_packet_ref(base, offset);
	CU_ASSERT_FATAL(ref != ODP_PACKET_INVALID);
	CU_ASSERT(odp_packet_has_ref(base));
	CU_ASSERT(!odp_packet_has_ref(ref));
	CU_ASSERT(!odp_packet_is_referencing(base));
	CU_ASSERT(odp_packet_is_referencing(ref));

	CU_ASSERT(odp_packet_len(ref) + offset == odp_packet_len(base));
	CU_ASSERT(odp_packet_pool(base) == odp_packet_pool(ref));
	CU_ASSERT(odp_packet_headroom(ref) == 0);
	CU_ASSERT(odp_packet_tailroom(ref) == 0);

	check_metadata_default(ref);
	set_random_md(ref);
	write_uarea(ref);

	save_pkt_state(base, &after);
	check_pkt_state_equal(base_state, &after);
	check_packet_data(ref, base_state, offset);

	return ref;
}

static void test_ref_creation(uint32_t base_len, uint32_t num_segs, uint32_t offset)
{
	odp_packet_t base, ref;
	pkt_state_t base_state;

	CU_ASSERT(base_len > offset);

	base = make_packet(base_len, num_segs);
	save_pkt_state(base, &base_state);
	ref = create_ref(base, &base_state, offset);

	odp_packet_free(ref);
	odp_packet_free(base);
}

static void test_basic_ref_creation(void)
{
	uint32_t iter = 0;
	pkt_layout_t layout;

	while (iterate_pkt_layout(&layout, &iter))
		test_ref_creation(layout.len, layout.num_segs, layout.offset);
}

static void pkt_extend_head(odp_packet_t *pkt, uint32_t push_len)
{
	pkt_state_t before, after;
	void *data_ptr;
	uint32_t seg_len;
	int rc;

	save_pkt_state(*pkt, &before);
	rc = odp_packet_extend_head(pkt, push_len, &data_ptr, &seg_len);
	CU_ASSERT(rc >= 0);
	write_pkt_data(*pkt, 0, push_len);
	save_pkt_state(*pkt, &after);

	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data(&before, 0, &after, push_len, before.len);
	CU_ASSERT(data_ptr == after.seg_info.segs[0].data);
	CU_ASSERT(seg_len  == after.seg_info.segs[0].len);
	CU_ASSERT(after.len == before.len + push_len);

	if (before.headroom >= push_len) {
		CU_ASSERT(rc == 0);
		CU_ASSERT(after.head == before.head);
		CU_ASSERT(after.data == before.data - push_len);
		CU_ASSERT(after.headroom == before.headroom - push_len);
		CU_ASSERT(after.tailroom == before.tailroom);
	}
	if (rc == 0) {
		CU_ASSERT(after.tail  == before.tail);
		CU_ASSERT(after.uarea == before.uarea);
		check_ptrs_tail(&before.seg_info, &after.seg_info, before.len);
	}
}

static void pkt_push_head(odp_packet_t *pkt, uint32_t push_len)
{
	pkt_state_t before, after;
	void *data_ptr;

	save_pkt_state(*pkt, &before);
	data_ptr = odp_packet_push_head(*pkt, push_len);
	save_pkt_state(*pkt, &after);

	if (before.headroom < push_len) {
		CU_ASSERT(data_ptr == NULL);
		check_pkt_state_equal(&before, &after);
		return;
	}
	CU_ASSERT(data_ptr != NULL);

	write_pkt_data(*pkt, 0, push_len);

	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data(&before, 0, &after, push_len, before.len);
	CU_ASSERT(data_ptr == after.seg_info.segs[0].data);
	CU_ASSERT(after.len == before.len + push_len);
	CU_ASSERT(after.head == before.head);
	CU_ASSERT(after.data == before.data - push_len);
	CU_ASSERT(after.tail  == before.tail);
	CU_ASSERT(after.uarea == before.uarea);
	CU_ASSERT(after.seg_info.num_segs == before.seg_info.num_segs);

	check_ptrs_tail(&before.seg_info, &after.seg_info, before.len);
}

static void pkt_trunc_head(odp_packet_t *pkt, uint32_t pull_len)
{
	pkt_state_t before, after;
	void *data_ptr;
	uint32_t seg_len;
	int rc;

	save_pkt_state(*pkt, &before);
	rc = odp_packet_trunc_head(pkt, pull_len, &data_ptr, &seg_len);
	save_pkt_state(*pkt, &after);

	if (before.len <= pull_len) {
		CU_ASSERT(rc < 0);
		check_pkt_state_equal(&before, &after);
		return;
	}
	CU_ASSERT(rc >= 0);

	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data(&before, pull_len, &after, 0, after.len);
	CU_ASSERT(data_ptr == after.seg_info.segs[0].data);
	CU_ASSERT(seg_len  == after.seg_info.segs[0].len);
	CU_ASSERT(after.len == before.len - pull_len);

	if (before.seg_info.segs[0].len > pull_len) {
		bool head_data_maybe_shared = (odp_packet_is_referencing(*pkt) &&
					       before.headroom == 0 &&
					       after.headroom == 0);
		CU_ASSERT(rc == 0);
		CU_ASSERT(after.data == before.data + pull_len);
		if (!head_data_maybe_shared)
			CU_ASSERT(after.headroom == before.headroom + pull_len);
		CU_ASSERT(after.tailroom == before.tailroom);
	}
	if (rc == 0) {
		CU_ASSERT(after.tail  == before.tail);
		CU_ASSERT(after.uarea == before.uarea);
		check_ptrs_tail(&before.seg_info, &after.seg_info, after.len);
	}
}

static void pkt_pull_head(odp_packet_t *pkt, uint32_t pull_len)
{
	pkt_state_t before, after;
	void *data_ptr;

	save_pkt_state(*pkt, &before);
	data_ptr = odp_packet_pull_head(*pkt, pull_len);
	save_pkt_state(*pkt, &after);

	if (before.seg_info.segs[0].len <= pull_len) {
		CU_ASSERT(data_ptr == NULL);
		check_pkt_state_equal(&before, &after);
		return;
	}

	CU_ASSERT(data_ptr != NULL);

	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data(&before, pull_len, &after, 0, after.len);
	CU_ASSERT(data_ptr == after.seg_info.segs[0].data);
	CU_ASSERT(after.len == before.len - pull_len);
	CU_ASSERT(after.data == before.data + pull_len);
	CU_ASSERT(after.tail  == before.tail);
	CU_ASSERT(after.uarea == before.uarea);
	CU_ASSERT(after.seg_info.num_segs == before.seg_info.num_segs);

	check_ptrs_tail(&before.seg_info, &after.seg_info, after.len);
}

static void pkt_extend_tail(odp_packet_t *pkt, uint32_t push_len)
{
	pkt_state_t before, after;
	void *data_ptr, *data_ptr_2;
	uint32_t seg_len, seg_len_2;
	int rc;

	save_pkt_state(*pkt, &before);
	rc = odp_packet_extend_tail(pkt, push_len, &data_ptr, &seg_len);
	CU_ASSERT(rc >= 0);
	write_pkt_data(*pkt, before.len, push_len);
	save_pkt_state(*pkt, &after);

	data_ptr_2 = get_data_ptr(&after.seg_info, before.len, &seg_len_2);
	CU_ASSERT(data_ptr == data_ptr_2);
	CU_ASSERT(seg_len == seg_len_2);

	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data(&before, 0, &after, 0, before.len);

	CU_ASSERT(after.len == before.len + push_len);

	if (before.tailroom >= push_len) {
		CU_ASSERT(rc == 0);
		CU_ASSERT(after.tail == before.tail + push_len);
		CU_ASSERT(data_ptr == before.tail);
		CU_ASSERT(after.headroom == before.headroom);
		CU_ASSERT(after.tailroom == before.tailroom - push_len);
	}
	if (rc == 0) {
		CU_ASSERT(after.head == before.head);
		CU_ASSERT(after.data == before.data);
		CU_ASSERT(after.uarea == before.uarea);
		check_ptrs_head(&before.seg_info, &after.seg_info, before.len);
	}
}

static void pkt_push_tail(odp_packet_t *pkt, uint32_t push_len)
{
	pkt_state_t before, after;
	void *old_tail_ptr;

	save_pkt_state(*pkt, &before);
	old_tail_ptr = odp_packet_push_tail(*pkt, push_len);
	save_pkt_state(*pkt, &after);

	if (before.tailroom < push_len) {
		CU_ASSERT(old_tail_ptr == NULL);
		check_pkt_state_equal(&before, &after);
		return;
	}
	CU_ASSERT(old_tail_ptr != NULL);
	CU_ASSERT(old_tail_ptr == before.tail);

	write_pkt_data(*pkt, before.len, push_len);

	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data(&before, 0, &after, 0, before.len);

	CU_ASSERT(after.len == before.len + push_len);
	CU_ASSERT(after.head == before.head);
	CU_ASSERT(after.data == before.data);
	CU_ASSERT(after.tail  == before.tail + push_len);
	CU_ASSERT(after.uarea == before.uarea);
	CU_ASSERT(after.seg_info.num_segs == before.seg_info.num_segs);

	check_ptrs_head(&before.seg_info, &after.seg_info, before.len);
}

static void pkt_trunc_tail(odp_packet_t *pkt, uint32_t pull_len)
{
	pkt_state_t before, after;
	void *tail;
	uint32_t tailroom;
	int rc;

	save_pkt_state(*pkt, &before);
	rc = odp_packet_trunc_tail(pkt, pull_len, &tail, &tailroom);
	save_pkt_state(*pkt, &after);

	if (before.len <= pull_len) {
		CU_ASSERT(rc < 0);
		check_pkt_state_equal(&before, &after);
		return;
	}
	CU_ASSERT(rc >= 0);

	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data(&before, 0, &after, 0, after.len);

	CU_ASSERT(tail == after.tail);
	CU_ASSERT(tailroom  == after.tailroom);
	CU_ASSERT(after.len == before.len - pull_len);

	if (last_seg(&before.seg_info)->len > pull_len) {
		bool tail_data_maybe_shared = (odp_packet_is_referencing(*pkt) &&
					       before.tailroom == 0 &&
					       after.tailroom == 0);
		CU_ASSERT(rc == 0);
		CU_ASSERT(after.tail == before.tail - pull_len);
		CU_ASSERT(after.headroom == before.headroom);
		if (!tail_data_maybe_shared)
			CU_ASSERT(after.tailroom == before.tailroom + pull_len);
	}
	if (rc == 0) {
		CU_ASSERT(after.data == before.data);
		CU_ASSERT(after.head == before.head);
		CU_ASSERT(after.uarea == before.uarea);
		check_ptrs_head(&before.seg_info, &after.seg_info, after.len);
	}
}

static void pkt_pull_tail(odp_packet_t *pkt, uint32_t pull_len)
{
	pkt_state_t before, after;
	void *data_ptr;

	save_pkt_state(*pkt, &before);
	data_ptr = odp_packet_pull_tail(*pkt, pull_len);
	save_pkt_state(*pkt, &after);

	if (last_seg(&before.seg_info)->len <= pull_len) {
		CU_ASSERT(data_ptr == NULL);
		check_pkt_state_equal(&before, &after);
		return;
	}
	CU_ASSERT(data_ptr != NULL);
	CU_ASSERT(data_ptr == after.tail);

	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data(&before, 0, &after, 0, after.len);

	CU_ASSERT(after.len == before.len - pull_len);
	CU_ASSERT(after.head == before.head);
	CU_ASSERT(after.data == before.data);
	CU_ASSERT(after.tail  == before.tail - pull_len);
	CU_ASSERT(after.uarea == before.uarea);
	CU_ASSERT(after.seg_info.num_segs == before.seg_info.num_segs);

	check_ptrs_head(&before.seg_info, &after.seg_info, after.len);
}

static void prepare_pkt(odp_packet_t *pkt, uint32_t op, uint32_t op_param)
{
	switch (op) {
	case PRE_OP_NONE:
	default:
		return;
	case PRE_OP_EXTEND_HEAD:
		pkt_extend_head(pkt, op_param);
		break;
	case PRE_OP_EXTEND_TAIL:
		pkt_extend_tail(pkt, op_param);
		break;
	case PRE_OP_TRUNC_HEAD:
		pkt_trunc_head(pkt, op_param);
		break;
	case PRE_OP_TRUNC_TAIL:
		pkt_trunc_tail(pkt, op_param);
		break;
	}
}

static odp_packet_t make_test_packet(const pkt_param_t *param, test_pkt_state_t *state)
{
	odp_packet_t pkt;

	pkt = make_packet(param->base_len, param->base_num_segs);

	switch (param->pkt_type) {
	case PKT_TYPE_NORMAL:
		prepare_pkt(&pkt, param->pre_op, param->pre_op_param);
		state->pkt = ODP_PACKET_INVALID;
		break;
	case PKT_TYPE_STATIC_REF:
		prepare_pkt(&pkt, param->pre_op, param->pre_op_param);
		state->pkt = pkt;
		save_pkt_state(state->pkt, &state->pkt_state);
		pkt = odp_packet_ref_static(pkt);
		CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);
		break;
	case PKT_TYPE_REFERENCING:
		state->pkt = pkt;
		save_pkt_state(state->pkt, &state->pkt_state);
		pkt = create_ref(pkt, &state->pkt_state, param->ref_offset);
		prepare_pkt(&pkt, param->pre_op, param->pre_op_param);
		break;
	case PKT_TYPE_REFERENCED:
		save_pkt_state(pkt, &state->pkt_state);
		state->pkt = create_ref(pkt, &state->pkt_state, param->ref_offset);
		prepare_pkt(&state->pkt, param->pre_op, param->pre_op_param);
		save_pkt_state(state->pkt, &state->pkt_state);
		break;
	default:
		CU_FAIL("internal error: invalid packet type");
		state->pkt = ODP_PACKET_INVALID;
		break;
	}

	return pkt;
}

static void test_packet_done(test_pkt_state_t *state)
{
	pkt_state_t after;

	if (state->pkt != ODP_PACKET_INVALID) {
		save_pkt_state(state->pkt, &after);
		check_pkt_state_equal(&state->pkt_state, &after);
		odp_packet_free(state->pkt);
	}
}

/* return the length of the test packet corresponding to the parameters */
static uint32_t test_pkt_len(const pkt_param_t *pkt_param)
{
	test_pkt_state_t state;
	odp_packet_t pkt;
	uint32_t len;

	if (pkt_param->pre_op == PRE_OP_NONE) {
		if (pkt_param->pkt_type == PKT_TYPE_REFERENCING)
			return pkt_param->base_len - pkt_param->ref_offset;
		else
			return pkt_param->base_len;
	}
	/* let's probe what really happens with pre op applied */
	pkt = make_test_packet(pkt_param, &state);
	len = odp_packet_len(pkt);
	test_packet_done(&state);
	odp_packet_free(pkt);
	return len;
}

static uint32_t ref_shared_offs(const pkt_param_t *param)
{
	CU_ASSERT(param->pkt_type == PKT_TYPE_REFERENCING);

	if (param->pre_op == PRE_OP_EXTEND_HEAD)
		return param->pre_op_param;
	return 0;
}

static uint32_t ref_shared_len(const pkt_param_t *param)
{
	CU_ASSERT(param->pkt_type == PKT_TYPE_REFERENCING);

	uint32_t len = param->base_len - param->ref_offset;

	if (param->pre_op == PRE_OP_TRUNC_HEAD ||
	    param->pre_op == PRE_OP_TRUNC_TAIL)
		len -= param->pre_op_param;
	return len;
}

static void for_each_pkt_variant(pkt_type_t pkt_type, pkt_func_t func, const void *ctx)
{
	uint32_t iter = 0;
	pkt_layout_t layout;
	uint32_t pre_op_params[] = {2, 13};

	while (iterate_pkt_layout(&layout, &iter))
		for (uint32_t op = 0; op < NUM_PRE_OPS; op++)
			for (uint32_t opp = 0; opp < ODPH_ARRAY_SIZE(pre_op_params); opp++) {
				pkt_param_t pkt_param = {
					.pkt_type = pkt_type,
					.base_len = layout.len,
					.base_num_segs = layout.num_segs,
					.ref_offset = layout.offset,
					.pre_op = op,
					.pre_op_param = pre_op_params[opp],
				};

				func(&pkt_param, ctx);
			}
}

static void for_each_mutable_packet_variant(pkt_func_t func, const void *ctx)
{
	pkt_type_t pkt_types[] = {PKT_TYPE_NORMAL, PKT_TYPE_REFERENCING};

	for (uint32_t type = 0; type < ODPH_ARRAY_SIZE(pkt_types); type++)
		for_each_pkt_variant(pkt_types[type], func, ctx);
}

static void for_each_packet_variant(pkt_func_t func, const void *ctx)
{
	pkt_type_t pkt_types[] = {
		PKT_TYPE_NORMAL,
		PKT_TYPE_REFERENCING,
		PKT_TYPE_REFERENCED,
		PKT_TYPE_STATIC_REF,
	};

	for (uint32_t type = 0; type < ODPH_ARRAY_SIZE(pkt_types); type++)
		for_each_pkt_variant(pkt_types[type], func, ctx);
}

static void do_test_ref(const pkt_param_t *pkt_param, const void *ctx ODP_UNUSED)
{
	uint32_t pkt_len = test_pkt_len(pkt_param);
	test_pkt_state_t state;
	odp_packet_t pkt, ref;
	pkt_state_t base_state;

	for (uint32_t offset = 0; offset < pkt_len; offset++) {
		pkt = make_test_packet(pkt_param, &state);
		save_pkt_state(pkt, &base_state);
		ref = create_ref(pkt, &base_state, offset);
		odp_packet_free(ref);
		test_packet_done(&state);
		odp_packet_free(pkt);
	}
}

static void test_ref(void)
{
	/* pkt types that can be passed to odp_packet_ref() */
	pkt_type_t pkt_types[] = {PKT_TYPE_NORMAL, PKT_TYPE_REFERENCED};

	for (uint32_t type = 0; type < ODPH_ARRAY_SIZE(pkt_types); type++)
		for_each_pkt_variant(pkt_types[type], do_test_ref, NULL);
}

/*
 * Run the provided function (push/pull/extend/trunc head/tail) with
 * different len parameters.
 */
static void do_test_pkt_adj(const pkt_param_t *pkt_param, const void *ctx)
{
	uint32_t pkt_len = test_pkt_len(pkt_param);
	test_pkt_state_t state;
	odp_packet_t pkt;
	const pkt_adj_param_t *param = ctx;

	/*
	 * We assume ODP implementations check too big values and
	 * intentionally loop all the way to pkt_len + 1.
	 */
	for (uint32_t len = 1; len <= pkt_len + 1; len++) {
		pkt = make_test_packet(pkt_param, &state);
		param->func(&pkt, len);
		test_packet_done(&state);
		odp_packet_free(pkt);
	}
}

static void test_pkt_adj(pkt_adj_func_t func)
{
	const pkt_adj_param_t param = {.func = func};

	for_each_mutable_packet_variant(do_test_pkt_adj, &param);
}

static void test_extend_head(void)
{
	test_pkt_adj(pkt_extend_head);
}

static void test_push_head(void)
{
	test_pkt_adj(pkt_push_head);
}

static void test_trunc_head(void)
{
	test_pkt_adj(pkt_trunc_head);
}

static void test_pull_head(void)
{
	test_pkt_adj(pkt_pull_head);
}

static void test_extend_tail(void)
{
	test_pkt_adj(pkt_extend_tail);
}

static void test_push_tail(void)
{
	test_pkt_adj(pkt_push_tail);
}

static void test_trunc_tail(void)
{
	test_pkt_adj(pkt_trunc_tail);
}

static void test_pull_tail(void)
{
	test_pkt_adj(pkt_pull_tail);
}

static void pkt_reset_meta(odp_packet_t pkt)
{
	pkt_state_t before, after;
	int is_ref, has_ref;

	is_ref = odp_packet_is_referencing(pkt);
	has_ref = odp_packet_has_ref(pkt);

	save_pkt_state(pkt, &before);
	odp_packet_reset_meta(pkt);
	save_pkt_state(pkt, &after);

	CU_ASSERT(before.len        == after.len);
	CU_ASSERT(before.headroom   == after.headroom);
	CU_ASSERT(before.tailroom   == after.tailroom);
	CU_ASSERT(before.head       == after.head);
	CU_ASSERT(before.data       == after.data);
	CU_ASSERT(before.tail       == after.tail);
	/* We assume user area pointer is preserved. API does not say it */
	CU_ASSERT(before.uarea      == after.uarea);

	check_pkt_data_equal(&before, &after);
	check_seg_info_equal(&before.seg_info, &after.seg_info);
	check_metadata_default(pkt);

	CU_ASSERT(before.metadata.user_area_chksum == after.metadata.user_area_chksum);

	CU_ASSERT(odp_packet_is_referencing(pkt) == is_ref);
	CU_ASSERT(odp_packet_has_ref(pkt) == has_ref);
}

static void do_test_reset_meta(const pkt_param_t *pkt_param, const void *ctx ODP_UNUSED)
{
	test_pkt_state_t state;
	odp_packet_t pkt;

	if (pkt_param->pkt_type == PKT_TYPE_STATIC_REF)
		return;

	pkt = make_test_packet(pkt_param, &state);
	pkt_reset_meta(pkt);
	test_packet_done(&state);
	odp_packet_free(pkt);
}

static void test_reset_meta(void)
{
	for_each_packet_variant(do_test_reset_meta, NULL);
}

static void pkt_copy(odp_packet_t pkt)
{
	pkt_state_t before, after, state_copy;
	odp_packet_t copy;

	save_pkt_state(pkt, &before);
	copy = odp_packet_copy(pkt, odp_packet_pool(pkt));
	save_pkt_state(pkt, &after);
	CU_ASSERT_FATAL(copy != ODP_PACKET_INVALID);
	save_pkt_state(copy, &state_copy);

	check_pkt_state_equal(&before, &after);
	check_metadata_equal(&before.metadata, &state_copy.metadata);
	check_pkt_data_equal(&before, &state_copy);
	set_random_md(copy);
	write_uarea(copy);
	CU_ASSERT(odp_packet_has_ref(copy) == 0);
	CU_ASSERT(odp_packet_is_referencing(copy) == 0);

	write_pkt_data(copy, 0, state_copy.len);
	check_pkt_state_equal(&before, &after);

	odp_packet_free(copy);
}

static void do_test_copy(const pkt_param_t *pkt_param, const void *ctx ODP_UNUSED)
{
	test_pkt_state_t state;
	odp_packet_t pkt;

	pkt = make_test_packet(pkt_param, &state);
	pkt_copy(pkt);
	test_packet_done(&state);
	odp_packet_free(pkt);
}

static void test_copy(void)
{
	for_each_packet_variant(do_test_copy, NULL);
}

static void pkt_copy_part(odp_packet_t pkt, uint32_t offset, uint32_t len)
{
	pkt_state_t before, after, state_copy;
	odp_packet_t copy;

	save_pkt_state(pkt, &before);
	copy = odp_packet_copy_part(pkt, offset, len, odp_packet_pool(pkt));
	save_pkt_state(pkt, &after);
	CU_ASSERT_FATAL(copy != ODP_PACKET_INVALID);
	save_pkt_state(copy, &state_copy);

	check_pkt_state_equal(&before, &after);
	CU_ASSERT(state_copy.len == len);
	check_metadata_default(copy);
	check_pkt_data(&before, offset, &state_copy, 0, len);
	set_random_md(copy);
	write_uarea(copy);
	CU_ASSERT(odp_packet_has_ref(copy) == 0);
	CU_ASSERT(odp_packet_is_referencing(copy) == 0);

	write_pkt_data(copy, 0, state_copy.len);
	check_pkt_state_equal(&before, &after);

	odp_packet_free(copy);
}

static void do_test_copy_part(const pkt_param_t *pkt_param, const void *ctx ODP_UNUSED)
{
	uint32_t pkt_len = test_pkt_len(pkt_param);
	test_pkt_state_t state;
	odp_packet_t pkt;

	for (uint32_t offs = 0; offs < pkt_len; offs++) {
		for (uint32_t len = 1; len < 20; len++) {
			if (offs + len > pkt_len)
				continue;
			pkt = make_test_packet(pkt_param, &state);
			pkt_copy_part(pkt, offs, len);
			test_packet_done(&state);
			odp_packet_free(pkt);
		}
	}
}

static void test_copy_part(void)
{
	for_each_packet_variant(do_test_copy_part, NULL);
}

static void pkt_concat(odp_packet_t *dst, odp_packet_t src)
{
	pkt_state_t dst_before, dst_after, src_before;
	int rc;

	save_pkt_state(*dst, &dst_before);
	save_pkt_state(src, &src_before);

	rc = odp_packet_concat(dst, src);
	CU_ASSERT(rc >= 0);
	save_pkt_state(*dst, &dst_after);

	check_metadata_equal(&dst_before.metadata, &dst_after.metadata);
	check_pkt_data(&dst_before, 0, &dst_after, 0, dst_before.len);
	check_pkt_data(&src_before, 0, &dst_after, dst_before.len, src_before.len);
	CU_ASSERT(dst_before.len + src_before.len == dst_after.len);

	if (rc == 0) {
		check_ptrs_head(&dst_after.seg_info, &dst_before.seg_info, dst_before.len);
		check_ptrs_tail(&dst_after.seg_info, &src_before.seg_info, src_before.len);
		CU_ASSERT(dst_before.uarea == dst_after.uarea);
	}
}

static void do_test_concat(const pkt_param_t *dst_param, const void *ctx)
{
	const pkt_param_t *src_param = ctx;

	odp_packet_t dst, src;
	test_pkt_state_t dst_state, src_state;

	dst = make_test_packet(dst_param, &dst_state);
	src = make_test_packet(src_param, &src_state);

	pkt_concat(&dst, src);

	test_packet_done(&dst_state);
	test_packet_done(&src_state);
	odp_packet_free(dst);
}

static void test_concat_iterate_dst(const pkt_param_t *src_param, const void *ctx ODP_UNUSED)
{
	for_each_mutable_packet_variant(do_test_concat, src_param);
}

static void test_concat(void)
{
	for_each_mutable_packet_variant(test_concat_iterate_dst, NULL);
}

static void pkt_split(odp_packet_t *pkt, uint32_t len)
{
	pkt_state_t before, after_head, after_tail;
	odp_packet_t tail = ODP_PACKET_INVALID;
	int rc;

	save_pkt_state(*pkt, &before);
	rc = odp_packet_split(pkt, len, &tail);
	save_pkt_state(*pkt, &after_head);

	if (len == 0 || len >= before.len) {
		CU_ASSERT(rc < 0);
		check_pkt_state_equal(&before, &after_head);
		return;
	}

	CU_ASSERT(rc >= 0);
	CU_ASSERT_FATAL(tail != ODP_PACKET_INVALID);
	save_pkt_state(tail, &after_tail);

	check_metadata_equal(&before.metadata, &after_head.metadata);
	check_metadata_default(tail);
	CU_ASSERT(after_head.len == len);
	CU_ASSERT(after_tail.len == before.len - len);
	check_pkt_data(&after_head, 0, &before, 0, len);
	check_pkt_data(&after_tail, 0, &before, len, after_tail.len);

	if (rc == 0) {
		/*
		 * We do not check tail since the intention, if not the letter,
		 * of the API may be that the no-ptrs-changed status is only
		 * about the data that stays in the head part.
		 */
		check_ptrs_head(&before.seg_info, &after_head.seg_info, len);
		CU_ASSERT(before.uarea == after_head.uarea);
	}

	odp_packet_free(tail);
}

static void do_test_split(const pkt_param_t *pkt_param, const void *ctx ODP_UNUSED)
{
	uint32_t pkt_len = test_pkt_len(pkt_param);
	test_pkt_state_t state;
	odp_packet_t pkt;

	for (uint32_t offs = 1 ; offs < pkt_len; offs++) {
		pkt = make_test_packet(pkt_param, &state);
		pkt_split(&pkt, offs);
		test_packet_done(&state);
		odp_packet_free(pkt);
	}
}

static void test_split(void)
{
	for_each_mutable_packet_variant(do_test_split, NULL);
}

static void pkt_add_data(odp_packet_t *pkt, uint32_t offs, uint32_t len)
{
	pkt_state_t before, after;
	int rc;

	save_pkt_state(*pkt, &before);
	rc = odp_packet_add_data(pkt, offs, len);
	CU_ASSERT_FATAL(rc >= 0);
	write_pkt_data(*pkt, offs, len);
	save_pkt_state(*pkt, &after);

	if (len == 0) {
		if (rc == 0) {
			check_pkt_state_equal(&before, &after);
		} else {
			check_metadata_equal(&before.metadata, &after.metadata);
			check_pkt_data_equal(&before, &after);
		}
		return;
	}

	CU_ASSERT(after.len == before.len + len);
	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data(&before, 0, &after, 0, offs);
	check_pkt_data(&before, offs, &after, offs + len, before.len - offs);

	if (rc == 0) {
		if (offs != 0) {
			CU_ASSERT(before.data == after.data);
			CU_ASSERT(before.head == after.head);
		}
		CU_ASSERT(before.uarea == after.uarea);
		check_ptrs_head(&before.seg_info, &after.seg_info, offs);
		check_ptrs_tail(&before.seg_info, &after.seg_info, before.len - offs);
	}
}

static void do_test_add_data(const pkt_param_t *pkt_param, const void *ctx ODP_UNUSED)
{
	test_pkt_state_t state;
	odp_packet_t pkt;
	uint32_t pkt_len = test_pkt_len(pkt_param);

	for (uint32_t offs = 0; offs < pkt_len; offs++) {
		for (uint32_t len = 1; len < 20; len++) {
			pkt = make_test_packet(pkt_param, &state);
			pkt_add_data(&pkt, offs, len);
			test_packet_done(&state);
			odp_packet_free(pkt);
		}
	}
}

static void test_add_data(void)
{
	for_each_mutable_packet_variant(do_test_add_data, NULL);
}

static void pkt_rem_data(odp_packet_t *pkt, uint32_t offs, uint32_t len)
{
	pkt_state_t before, after;
	int rc;

	save_pkt_state(*pkt, &before);
	rc = odp_packet_rem_data(pkt, offs, len);
	CU_ASSERT_FATAL(rc >= 0);
	save_pkt_state(*pkt, &after);

	if (len == 0) {
		if (rc == 0) {
			check_pkt_state_equal(&before, &after);
		} else {
			check_metadata_equal(&before.metadata, &after.metadata);
			check_pkt_data_equal(&before, &after);
		}
		return;
	}

	CU_ASSERT(after.len == before.len - len);
	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data(&before, 0, &after, 0, offs);
	check_pkt_data(&before, offs + len, &after, offs, after.len - offs);

	if (rc == 0) {
		if (offs != 0) {
			CU_ASSERT(before.data == after.data);
			CU_ASSERT(before.head == after.head);
		}
		CU_ASSERT(before.uarea == after.uarea);
		check_ptrs_head(&before.seg_info, &after.seg_info, offs);
		check_ptrs_tail(&before.seg_info, &after.seg_info, after.len - offs);
	}
}

static void do_test_rem_data(const pkt_param_t *pkt_param, const void *ctx ODP_UNUSED)
{
	uint32_t pkt_len = test_pkt_len(pkt_param);
	test_pkt_state_t state;
	odp_packet_t pkt;

	for (uint32_t offs = 0; offs < pkt_len; offs++) {
		for (uint32_t len = 1; len < 20; len++) {
			if (offs + len > pkt_len || len >= pkt_len)
				continue;
			pkt = make_test_packet(pkt_param, &state);
			pkt_rem_data(&pkt, offs, len);
			test_packet_done(&state);
			odp_packet_free(pkt);
		}
	}
}

static void test_rem_data(void)
{
	for_each_mutable_packet_variant(do_test_rem_data, NULL);
}

static void pkt_align(odp_packet_t *pkt, uint32_t offset, uint32_t len, uint32_t align)
{
	pkt_state_t before, after;
	int rc;
	uint32_t *ptr;
	uint32_t seg_len;
	odp_packet_seg_t seg;

	CU_ASSERT((align & (align - 1)) == 0);

	save_pkt_state(*pkt, &before);

	if (offset >= before.len)
		offset = before.len == 1 ? 0 : before.len - 2;
	if (len > before.len - offset)
		len = before.len - offset;

	rc = odp_packet_align(pkt, offset, len, align);
	CU_ASSERT_FATAL(rc >= 0);
	save_pkt_state(*pkt, &after);

	check_metadata_equal(&before.metadata, &after.metadata);
	check_pkt_data_equal(&before, &after);

	ptr = odp_packet_offset(*pkt, offset, &seg_len, &seg);

	/*
	 * The linux-gen ODP implementation for regular packets is and has
	 * always been buggy. When the result is segmented, the requested area
	 * may not be continuous and properly aligned. We skip the tests
	 * for regular segmented packets until the bug gets fixed.
	 */
	if (odp_packet_is_referencing(*pkt) || !odp_packet_is_segmented(*pkt)) {
		CU_ASSERT(seg_len >= len);
		if (align > 1)
			CU_ASSERT((((uintptr_t)ptr) & (align - 1)) == 0);
	}

	if (rc == 0) {
		if (offset > 0) {
			CU_ASSERT(before.data == after.data);
			CU_ASSERT(before.head == after.head);
		}
		check_ptrs_head(&before.seg_info, &after.seg_info, offset);
		check_ptrs_tail(&before.seg_info, &after.seg_info, after.len - offset);
	}
}

static void do_test_align(const pkt_param_t *pkt_param, const void *ctx ODP_UNUSED)
{
	uint32_t offsets[] = {0, 1, 5, 10, 11, 17};
	uint32_t lengths[] = {0, 1, 2, 5, 15, 100};
	uint32_t alignments[] = {0, 1, 2, 4, 8};

	for (uint32_t off = 0; off < ODPH_ARRAY_SIZE(offsets); off++) {
		for (uint32_t len = 0; len < ODPH_ARRAY_SIZE(lengths); len++) {
			uint32_t offset = offsets[off];
			uint32_t length = lengths[len];

			if (pkt_param->pkt_type == PKT_TYPE_REFERENCING) {
				uint32_t shared_offs = ref_shared_offs(pkt_param);
				uint32_t shared_len = ref_shared_len(pkt_param);

				/* Skip test if we would align shared data */
				if ((offset >= shared_offs ||
				     offset + length > shared_offs) &&
				    (offset < shared_offs + shared_len))
					continue;
			}

			for (uint32_t ali = 0; ali < ODPH_ARRAY_SIZE(alignments); ali++) {
				test_pkt_state_t state;
				odp_packet_t pkt;

				pkt = make_test_packet(pkt_param, &state);
				pkt_align(&pkt, offset, length, alignments[ali]);
				test_packet_done(&state);
				odp_packet_free(pkt);
			}
		}
	}
}

static void test_align(void)
{
	for_each_mutable_packet_variant(do_test_align, NULL);
}

odp_testinfo_t packet_ref_suite[] = {
	ODP_TEST_INFO(test_basic_ref_creation),
	ODP_TEST_INFO(test_ref),
	ODP_TEST_INFO(test_extend_head),
	ODP_TEST_INFO(test_push_head),
	ODP_TEST_INFO(test_trunc_head),
	ODP_TEST_INFO(test_pull_head),
	ODP_TEST_INFO(test_extend_tail),
	ODP_TEST_INFO(test_push_tail),
	ODP_TEST_INFO(test_trunc_tail),
	ODP_TEST_INFO(test_pull_tail),
	ODP_TEST_INFO(test_reset_meta),
	ODP_TEST_INFO(test_copy),
	ODP_TEST_INFO(test_copy_part),
	ODP_TEST_INFO(test_concat),
	ODP_TEST_INFO(test_split),
	ODP_TEST_INFO(test_add_data),
	ODP_TEST_INFO(test_rem_data),
	ODP_TEST_INFO(test_align),
	ODP_TEST_INFO_NULL,
};

int packet_ref_suite_init(void)
{
	odp_pool_capability_t pool_capa;
	odp_pool_param_t params;

	memset(&pool_capa, 0, sizeof(odp_pool_capability_t));

	if (odp_pool_capability(&pool_capa) < 0) {
		ODPH_ERR("odp_pool_capability() failed\n");
		return -1;
	}
	if (pool_capa.pkt.max_uarea_size < uarea_size) {
		printf("Warning: Packet user area too small\n");
		uarea_size = 0;
	}
	if (pool_capa.pkt.max_num != 0 && pool_capa.pkt.max_num < MAX_PKT_NUM) {
		ODPH_ERR("Max packet pool size is too small\n");
		return -1;
	}
	if (pool_capa.pkt.max_len != 0 && pool_capa.pkt.max_len < MAX_PKT_LEN) {
		ODPH_ERR("Max packet length is too small\n");
		return -1;
	}
	if (pool_capa.pkt.max_seg_len != 0 && pool_capa.pkt.max_seg_len < MAX_PKT_LEN) {
		ODPH_ERR("Max packet length is too small\n");
		return -1;
	}
	if (pool_capa.pkt.max_segs_per_pkt < 4)
		printf("Warning: Max segments per packet is too small\n");

	odp_pool_param_init(&params);

	params.type           = ODP_POOL_PACKET;
	params.pkt.seg_len    = MAX_PKT_LEN;
	params.pkt.len        = MAX_PKT_LEN;
	params.pkt.max_len    = MAX_PKT_LEN;
	params.pkt.num        = MAX_PKT_NUM;
	params.pkt.uarea_size = uarea_size;

	packet_pool = odp_pool_create("packet_pool", &params);
	if (packet_pool == ODP_POOL_INVALID) {
		ODPH_ERR("Packet pool creation failed\n");
		return -1;
	}

	return 0;
}

int packet_ref_suite_term(void)
{
	if (odp_pool_destroy(packet_pool) != 0)
		return -1;

	return 0;
}

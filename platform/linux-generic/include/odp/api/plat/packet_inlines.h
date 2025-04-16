/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 * Copyright (c) 2019-2022 Nokia
 */

/**
 * @file
 *
 * Packet inline functions
 */

#ifndef _ODP_PLAT_PACKET_INLINES_H_
#define _ODP_PLAT_PACKET_INLINES_H_

#include <odp/api/cpu.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp/api/packet_types.h>
#include <odp/api/pool_types.h>
#include <odp/api/time_types.h>

#include <odp/api/plat/debug_inlines.h>
#include <odp/api/plat/packet_io_inlines.h>
#include <odp/api/plat/packet_inline_types.h>
#include <odp/api/plat/pool_inline_types.h>
#include <odp/api/plat/event_inline_types.h>

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef _ODP_NO_INLINE
	/* Inline functions by default */
	#define _ODP_INLINE static inline
	#define odp_packet_data __odp_packet_data
	#define odp_packet_seg_len __odp_packet_seg_len
	#define odp_packet_data_seg_len __odp_packet_data_seg_len
	#define odp_packet_len __odp_packet_len
	#define odp_packet_headroom __odp_packet_headroom
	#define odp_packet_tailroom __odp_packet_tailroom
	#define odp_packet_pool __odp_packet_pool
	#define odp_packet_input __odp_packet_input
	#define odp_packet_input_set __odp_packet_input_set
	#define odp_packet_input_index __odp_packet_input_index
	#define odp_packet_num_segs __odp_packet_num_segs
	#define odp_packet_user_ptr __odp_packet_user_ptr
	#define odp_packet_user_ptr_set __odp_packet_user_ptr_set
	#define odp_packet_user_area __odp_packet_user_area
	#define odp_packet_user_area_size __odp_packet_user_area_size
	#define odp_packet_user_flag __odp_packet_user_flag
	#define odp_packet_user_flag_set __odp_packet_user_flag_set
	#define odp_packet_l2_offset __odp_packet_l2_offset
	#define odp_packet_l3_offset __odp_packet_l3_offset
	#define odp_packet_l4_offset __odp_packet_l4_offset
	#define odp_packet_l2_offset_set __odp_packet_l2_offset_set
	#define odp_packet_l3_offset_set __odp_packet_l3_offset_set
	#define odp_packet_l4_offset_set __odp_packet_l4_offset_set
	#define odp_packet_l2_ptr __odp_packet_l2_ptr
	#define odp_packet_l3_ptr __odp_packet_l3_ptr
	#define odp_packet_l4_ptr __odp_packet_l4_ptr
	#define odp_packet_l2_type __odp_packet_l2_type
	#define odp_packet_l3_type __odp_packet_l3_type
	#define odp_packet_l4_type __odp_packet_l4_type
	#define odp_packet_l3_chksum_status __odp_packet_l3_chksum_status
	#define odp_packet_l4_chksum_status __odp_packet_l4_chksum_status
	#define odp_packet_l3_chksum_insert __odp_packet_l3_chksum_insert
	#define odp_packet_l4_chksum_insert __odp_packet_l4_chksum_insert
	#define odp_packet_flow_hash __odp_packet_flow_hash
	#define odp_packet_ts __odp_packet_ts
	#define odp_packet_ts_set __odp_packet_ts_set
	#define odp_packet_ts_request __odp_packet_ts_request
	#define odp_packet_head __odp_packet_head
	#define odp_packet_is_segmented __odp_packet_is_segmented
	#define odp_packet_first_seg __odp_packet_first_seg
	#define odp_packet_seg_data __odp_packet_seg_data
	#define odp_packet_seg_data_len __odp_packet_seg_data_len
	#define odp_packet_next_seg __odp_packet_next_seg
	#define odp_packet_prefetch __odp_packet_prefetch
	#define odp_packet_copy_from_mem __odp_packet_copy_from_mem
	#define odp_packet_copy_to_mem __odp_packet_copy_to_mem
	#define odp_packet_from_event __odp_packet_from_event
	#define odp_packet_to_event __odp_packet_to_event
	#define odp_packet_from_event_multi __odp_packet_from_event_multi
	#define odp_packet_to_event_multi __odp_packet_to_event_multi
	#define odp_packet_subtype __odp_packet_subtype
	#define odp_packet_tx_compl_from_event __odp_packet_tx_compl_from_event
	#define odp_packet_tx_compl_to_event __odp_packet_tx_compl_to_event
	#define odp_packet_color __odp_packet_color
	#define odp_packet_drop_eligible __odp_packet_drop_eligible
	#define odp_packet_shaper_len_adjust __odp_packet_shaper_len_adjust
	#define odp_packet_cls_mark __odp_packet_cls_mark
	#define odp_packet_buf_data_len __odp_packet_buf_data_len
	#define odp_packet_buf_size __odp_packet_buf_size
	#define odp_packet_buf_head __odp_packet_buf_head
	#define odp_packet_buf_data_offset __odp_packet_buf_data_offset
	#define odp_packet_buf_data_set __odp_packet_buf_data_set
	#define odp_packet_buf_from_head __odp_packet_buf_from_head

#else
	#undef _ODP_INLINE
	#define _ODP_INLINE
#endif

void *_odp_packet_map(void *pkt_ptr, uint32_t offset, uint32_t *seg_len,
		      odp_packet_seg_t *seg);

int _odp_packet_copy_from_mem_seg(odp_packet_t pkt, uint32_t offset,
				  uint32_t len, const void *src);

int _odp_packet_copy_to_mem_seg(odp_packet_t pkt, uint32_t offset,
				uint32_t len, void *dst);

_ODP_INLINE void *odp_packet_data(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, seg_data);
}

_ODP_INLINE uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, seg_len);
}

_ODP_INLINE void *odp_packet_data_seg_len(odp_packet_t pkt,
					     uint32_t *seg_len)
{
	*seg_len = odp_packet_seg_len(pkt);
	return odp_packet_data(pkt);
}

_ODP_INLINE uint32_t odp_packet_len(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, frame_len);
}

_ODP_INLINE uint32_t odp_packet_headroom(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, headroom);
}

_ODP_INLINE uint32_t odp_packet_tailroom(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, tailroom);
}

_ODP_INLINE odp_pool_t odp_packet_pool(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_pool_t, pool);
}

_ODP_INLINE odp_pktio_t odp_packet_input(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_pktio_t, input);
}

_ODP_INLINE void odp_packet_input_set(odp_packet_t pkt, odp_pktio_t pktio)
{
	odp_pktio_t *pktio_ptr = _odp_pkt_get_ptr(pkt, odp_pktio_t, input);

	*pktio_ptr = pktio;
}

_ODP_INLINE int odp_packet_input_index(odp_packet_t pkt)
{
	odp_pktio_t pktio = odp_packet_input(pkt);

	return odp_pktio_index(pktio);
}

_ODP_INLINE int odp_packet_num_segs(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint8_t, seg_count);
}

_ODP_INLINE void *odp_packet_user_ptr(odp_packet_t pkt)
{
	_odp_packet_flags_t flags;

	flags.all_flags = _odp_pkt_get(pkt, uint32_t, flags);

	if (flags.user_ptr_set == 0)
		return NULL;

	return _odp_pkt_get(pkt, void *, user_ptr);
}

_ODP_INLINE void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ptr)
{
	_odp_packet_flags_t *flags = _odp_pkt_get_ptr(pkt, _odp_packet_flags_t, flags);
	const void **user_ptr = _odp_pkt_get_ptr(pkt, const void *, user_ptr);

	if (odp_unlikely(ptr == NULL)) {
		flags->user_ptr_set = 0;
		return;
	}

	*user_ptr = ptr;
	flags->user_ptr_set = 1;
}

_ODP_INLINE void *odp_packet_user_area(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, void *, user_area);
}

_ODP_INLINE uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	void *pool = _odp_pkt_get(pkt, void *, pool);

	return _odp_pool_get(pool, uint32_t, uarea_size);
}

_ODP_INLINE int odp_packet_user_flag(odp_packet_t pkt)
{
	_odp_packet_flags_t flags;

	flags.all_flags = _odp_pkt_get(pkt, uint32_t, flags);

	return flags.user_flag;
}

_ODP_INLINE void odp_packet_user_flag_set(odp_packet_t pkt, int val)
{
	_odp_packet_flags_t *flags = _odp_pkt_get_ptr(pkt, _odp_packet_flags_t, flags);

	flags->user_flag = !!val;
}

_ODP_INLINE uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l2_offset);
}

_ODP_INLINE uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l3_offset);
}

_ODP_INLINE uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint16_t, l4_offset);
}

_ODP_INLINE int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset)
{
	uint16_t *l2_offset = _odp_pkt_get_ptr(pkt, uint16_t, l2_offset);
	_odp_packet_input_flags_t *input_flags = _odp_pkt_get_ptr(pkt, _odp_packet_input_flags_t,
								  input_flags);

	if (odp_unlikely(offset >= odp_packet_len(pkt)))
		return -1;

	input_flags->l2 = 1;
	*l2_offset = (uint16_t)offset;
	return 0;
}

_ODP_INLINE int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	uint16_t *l3_offset = _odp_pkt_get_ptr(pkt, uint16_t, l3_offset);

	if (odp_unlikely(offset >= odp_packet_len(pkt)))
		return -1;

	*l3_offset = (uint16_t)offset;
	return 0;
}

_ODP_INLINE int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	uint16_t *l4_offset = _odp_pkt_get_ptr(pkt, uint16_t, l4_offset);

	if (odp_unlikely(offset >= odp_packet_len(pkt)))
		return -1;

	*l4_offset = (uint16_t)offset;
	return 0;
}

_ODP_INLINE void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	uint32_t offset  = odp_packet_l2_offset(pkt);
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);

	if (odp_unlikely(offset >= seg_len)) {
		void *pkt_hdr = (void *)pkt;

		return _odp_packet_map(pkt_hdr, offset, len, NULL);
	}

	if (len)
		*len = seg_len - offset;

	return data + offset;
}

_ODP_INLINE void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	uint32_t offset  = odp_packet_l3_offset(pkt);
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);

	if (odp_unlikely(offset >= seg_len)) {
		void *pkt_hdr = (void *)pkt;

		return _odp_packet_map(pkt_hdr, offset, len, NULL);
	}

	if (len)
		*len = seg_len - offset;

	return data + offset;
}

_ODP_INLINE void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	uint32_t offset  = odp_packet_l4_offset(pkt);
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);

	if (odp_unlikely(offset >= seg_len)) {
		void *pkt_hdr = (void *)pkt;

		return _odp_packet_map(pkt_hdr, offset, len, NULL);
	}

	if (len)
		*len = seg_len - offset;

	return data + offset;
}

_ODP_INLINE odp_proto_l2_type_t odp_packet_l2_type(odp_packet_t pkt)
{
	_odp_packet_input_flags_t input_flags;

	input_flags.all = _odp_pkt_get(pkt, uint64_t, input_flags);

	return input_flags.eth ? ODP_PROTO_L2_TYPE_ETH : ODP_PROTO_L2_TYPE_NONE;
}

_ODP_INLINE odp_proto_l3_type_t odp_packet_l3_type(odp_packet_t pkt)
{
	_odp_packet_input_flags_t input_flags;

	input_flags.all = _odp_pkt_get(pkt, uint64_t, input_flags);

	if (input_flags.ipv4)
		return ODP_PROTO_L3_TYPE_IPV4;
	else if (input_flags.ipv6)
		return ODP_PROTO_L3_TYPE_IPV6;
	else if (input_flags.arp)
		return ODP_PROTO_L3_TYPE_ARP;

	return ODP_PROTO_L3_TYPE_NONE;
}

_ODP_INLINE odp_proto_l4_type_t odp_packet_l4_type(odp_packet_t pkt)
{
	_odp_packet_input_flags_t input_flags;

	input_flags.all = _odp_pkt_get(pkt, uint64_t, input_flags);

	if (input_flags.tcp)
		return ODP_PROTO_L4_TYPE_TCP;
	else if (input_flags.udp)
		return ODP_PROTO_L4_TYPE_UDP;
	else if (input_flags.sctp)
		return ODP_PROTO_L4_TYPE_SCTP;
	else if (input_flags.ipsec_ah)
		return ODP_PROTO_L4_TYPE_AH;
	else if (input_flags.ipsec_esp)
		return ODP_PROTO_L4_TYPE_ESP;
	else if (input_flags.icmp && input_flags.ipv4)
		return ODP_PROTO_L4_TYPE_ICMPV4;
	else if (input_flags.icmp && input_flags.ipv6)
		return ODP_PROTO_L4_TYPE_ICMPV6;
	else if (input_flags.no_next_hdr)
		return ODP_PROTO_L4_TYPE_NO_NEXT;

	return ODP_PROTO_L4_TYPE_NONE;
}

_ODP_INLINE odp_packet_chksum_status_t odp_packet_l3_chksum_status(odp_packet_t pkt)
{
	_odp_packet_flags_t flags;
	_odp_packet_input_flags_t input_flags;

	flags.all_flags = _odp_pkt_get(pkt, uint32_t, flags);
	input_flags.all = _odp_pkt_get(pkt, uint64_t, input_flags);

	if (!input_flags.l3_chksum_done)
		return ODP_PACKET_CHKSUM_UNKNOWN;

	if (flags.l3_chksum_err)
		return ODP_PACKET_CHKSUM_BAD;

	return ODP_PACKET_CHKSUM_OK;
}

_ODP_INLINE odp_packet_chksum_status_t odp_packet_l4_chksum_status(odp_packet_t pkt)
{
	_odp_packet_flags_t flags;
	_odp_packet_input_flags_t input_flags;

	flags.all_flags = _odp_pkt_get(pkt, uint32_t, flags);
	input_flags.all = _odp_pkt_get(pkt, uint64_t, input_flags);

	if (!input_flags.l4_chksum_done)
		return ODP_PACKET_CHKSUM_UNKNOWN;

	if (flags.l4_chksum_err)
		return ODP_PACKET_CHKSUM_BAD;

	return ODP_PACKET_CHKSUM_OK;
}

_ODP_INLINE void odp_packet_l3_chksum_insert(odp_packet_t pkt, int insert)
{
	_odp_packet_flags_t *flags = _odp_pkt_get_ptr(pkt, _odp_packet_flags_t, flags);

	flags->l3_chksum_set = 1;
	flags->l3_chksum = !!insert;
}

_ODP_INLINE void odp_packet_l4_chksum_insert(odp_packet_t pkt, int insert)
{
	_odp_packet_flags_t *flags = _odp_pkt_get_ptr(pkt, _odp_packet_flags_t, flags);

	flags->l4_chksum_set = 1;
	flags->l4_chksum = !!insert;
}

_ODP_INLINE uint32_t odp_packet_flow_hash(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint32_t, flow_hash);
}

_ODP_INLINE odp_time_t odp_packet_ts(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, odp_time_t, timestamp);
}

_ODP_INLINE void odp_packet_ts_set(odp_packet_t pkt, odp_time_t timestamp)
{
	odp_time_t *ts = _odp_pkt_get_ptr(pkt, odp_time_t, timestamp);
	_odp_packet_input_flags_t *input_flags = _odp_pkt_get_ptr(pkt, _odp_packet_input_flags_t,
								  input_flags);

	*ts = timestamp;
	input_flags->timestamp = 1;
}

_ODP_INLINE void odp_packet_ts_request(odp_packet_t pkt, int enable)
{
	_odp_packet_flags_t *flags = _odp_pkt_get_ptr(pkt, _odp_packet_flags_t, flags);

	flags->ts_set = !!enable;
}

_ODP_INLINE void *odp_packet_head(odp_packet_t pkt)
{
	return (uint8_t *)odp_packet_data(pkt) - odp_packet_headroom(pkt);
}

_ODP_INLINE int odp_packet_is_segmented(odp_packet_t pkt)
{
	return _odp_pkt_get(pkt, uint8_t, seg_count) > 1;
}

_ODP_INLINE odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)pkt;
}

_ODP_INLINE void *odp_packet_seg_data(odp_packet_t pkt ODP_UNUSED,
				      odp_packet_seg_t seg)
{
	return _odp_pkt_get((odp_packet_t)seg, void *, seg_data);
}

_ODP_INLINE uint32_t odp_packet_seg_data_len(odp_packet_t pkt ODP_UNUSED,
					     odp_packet_seg_t seg)
{
	return _odp_pkt_get((odp_packet_t)seg, uint32_t, seg_len);
}

_ODP_INLINE odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt ODP_UNUSED,
						 odp_packet_seg_t seg)
{
	void *next_seg = _odp_pkt_get((odp_packet_t)seg, void *, seg_next);

	if (odp_unlikely(next_seg == NULL))
		return ODP_PACKET_SEG_INVALID;

	return (odp_packet_seg_t)next_seg;
}

_ODP_INLINE void odp_packet_prefetch(odp_packet_t pkt, uint32_t offset,
					uint32_t len)
{
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);
	(void)len;

	if (odp_unlikely(offset >= seg_len))
		return;

	odp_prefetch(data + offset);
}

_ODP_INLINE int odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
					    uint32_t len, const void *src)
{
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);

	if (odp_unlikely(offset + len > seg_len))
		return _odp_packet_copy_from_mem_seg(pkt, offset, len, src);

	memcpy(data + offset, src, len);

	return 0;
}

_ODP_INLINE int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
					  uint32_t len, void *dst)
{
	uint32_t seg_len = odp_packet_seg_len(pkt);
	uint8_t *data    = (uint8_t *)odp_packet_data(pkt);

	if (odp_unlikely(offset + len > seg_len))
		return _odp_packet_copy_to_mem_seg(pkt, offset, len, dst);

	memcpy(dst, data + offset, len);

	return 0;
}

_ODP_INLINE odp_packet_t odp_packet_from_event(odp_event_t ev)
{
	_ODP_ASSERT(odp_event_type(ev) == ODP_EVENT_PACKET);

	return (odp_packet_t)ev;
}

_ODP_INLINE odp_event_t odp_packet_to_event(odp_packet_t pkt)
{
	return (odp_event_t)pkt;
}

_ODP_INLINE void odp_packet_from_event_multi(odp_packet_t pkt[],
						const odp_event_t ev[],
						int num)
{
	int i;

	for (i = 0; i < num; i++)
		pkt[i] = odp_packet_from_event(ev[i]);
}

_ODP_INLINE void odp_packet_to_event_multi(const odp_packet_t pkt[],
					      odp_event_t ev[], int num)
{
	int i;

	for (i = 0; i < num; i++)
		ev[i] = odp_packet_to_event(pkt[i]);
}

_ODP_INLINE odp_event_subtype_t odp_packet_subtype(odp_packet_t pkt)
{
	return (odp_event_subtype_t)_odp_event_hdr_field((odp_event_t)(uintptr_t)pkt,
							 int8_t, subtype);
}

_ODP_INLINE odp_packet_tx_compl_t odp_packet_tx_compl_from_event(odp_event_t ev)
{
	_ODP_ASSERT(odp_event_type(ev) == ODP_EVENT_PACKET_TX_COMPL);

	return (odp_packet_tx_compl_t)(uintptr_t)ev;
}

_ODP_INLINE odp_event_t odp_packet_tx_compl_to_event(odp_packet_tx_compl_t tx_compl)
{
	return (odp_event_t)(uintptr_t)tx_compl;
}

_ODP_INLINE odp_packet_color_t odp_packet_color(odp_packet_t pkt)
{
	_odp_packet_input_flags_t input_flags;

	input_flags.all = _odp_pkt_get(pkt, uint64_t, input_flags);

	return (odp_packet_color_t)input_flags.color;
}

_ODP_INLINE odp_bool_t odp_packet_drop_eligible(odp_packet_t pkt)
{
	_odp_packet_input_flags_t input_flags;

	input_flags.all = _odp_pkt_get(pkt, uint64_t, input_flags);

	return !input_flags.nodrop;
}

_ODP_INLINE int8_t odp_packet_shaper_len_adjust(odp_packet_t pkt)
{
	_odp_packet_flags_t flags;

	flags.all_flags = _odp_pkt_get(pkt, uint32_t, flags);

	return (int8_t)flags.shaper_len_adj;
}

_ODP_INLINE uint64_t odp_packet_cls_mark(odp_packet_t pkt)
{
	_odp_packet_input_flags_t input_flags;

	input_flags.all = _odp_pkt_get(pkt, uint64_t, input_flags);

	return input_flags.cls_mark ? _odp_pkt_get(pkt, uint16_t, cls_mark) : 0;
}

_ODP_INLINE uint32_t odp_packet_buf_data_len(odp_packet_buf_t pkt_buf)
{
	return _odp_pkt_get(pkt_buf, uint32_t, seg_len);
}

_ODP_INLINE uint32_t odp_packet_buf_size(odp_packet_buf_t pkt_buf)
{
	odp_pool_t pool = _odp_pkt_get(pkt_buf, odp_pool_t, pool);

	return _odp_pool_get(pool, uint32_t, ext_pkt_buf_size) -
			_odp_pool_get(pool, uint32_t, ext_head_offset) -
			_odp_pool_get(pool, uint32_t, trailer_size);
}

_ODP_INLINE void *odp_packet_buf_head(odp_packet_buf_t pkt_buf)
{
	odp_pool_t pool = _odp_pkt_get(pkt_buf, odp_pool_t, pool);
	const uint32_t head_offset = _odp_pool_get(pool, uint32_t, ext_head_offset);

	/* Check that pool is external */
	if (odp_unlikely(!head_offset))
		return NULL;

	return (uint8_t *)(uintptr_t)pkt_buf + head_offset;
}

_ODP_INLINE uint32_t odp_packet_buf_data_offset(odp_packet_buf_t pkt_buf)
{
	void *buf_head = odp_packet_buf_head(pkt_buf);

	return (uint32_t)((uintptr_t)_odp_pkt_get(pkt_buf, void *, seg_data) - (uintptr_t)buf_head);
}

_ODP_INLINE void odp_packet_buf_data_set(odp_packet_buf_t pkt_buf, uint32_t data_offset,
					 uint32_t data_len)
{
	uint8_t *head = (uint8_t *)odp_packet_buf_head(pkt_buf);
	uint32_t *seg_len = _odp_pkt_get_ptr(pkt_buf, uint32_t, seg_len);
	void **seg_data = _odp_pkt_get_ptr(pkt_buf, void *, seg_data);

	*seg_len  = data_len;
	*seg_data = head + data_offset;
}

_ODP_INLINE odp_packet_buf_t odp_packet_buf_from_head(odp_pool_t pool, void *head)
{
	const uint32_t head_offset = _odp_pool_get(pool, uint32_t, ext_head_offset);

	/* Check that pool is external */
	if (odp_unlikely(!head_offset))
		return ODP_PACKET_BUF_INVALID;

	return (odp_packet_buf_t)((uintptr_t)head - head_offset);
}

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif

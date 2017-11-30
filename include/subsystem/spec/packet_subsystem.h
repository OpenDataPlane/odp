/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef ODP_PACKET_SUBSYSTEM_H_
#define ODP_PACKET_SUBSYSTEM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_module.h>
#include <odp/api/packet.h>

#define PACKET_SUBSYSTEM_VERSION 0x00010000UL

/* ODP packet public APIs subsystem */
ODP_SUBSYSTEM_DECLARE(packet);

/* Subsystem APIs declarations */
ODP_SUBSYSTEM_API(packet, odp_packet_t, alloc, odp_pool_t pool,
		  uint32_t len);
ODP_SUBSYSTEM_API(packet, int, alloc_multi, odp_pool_t pool,
		  uint32_t len, odp_packet_t pkt[], int num);
ODP_SUBSYSTEM_API(packet, void, free, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, free_multi, const odp_packet_t pkt[], int num);
ODP_SUBSYSTEM_API(packet, int, has_error, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, prefetch, odp_packet_t pkt,
		  uint32_t offset, uint32_t len);
ODP_SUBSYSTEM_API(packet, void *, data, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, input_index, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, reset, odp_packet_t pkt, uint32_t len);
ODP_SUBSYSTEM_API(packet, odp_packet_t, from_event, odp_event_t ev);
ODP_SUBSYSTEM_API(packet, odp_event_t, to_event, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void *, head, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, uint32_t, buf_len, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, uint32_t, seg_len, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, uint32_t, len, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, uint32_t, headroom, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, uint32_t, tailroom, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void *, tail, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void *, offset, odp_packet_t pkt, uint32_t offset,
		  uint32_t *len, odp_packet_seg_t *seg);
ODP_SUBSYSTEM_API(packet, void *, push_head, odp_packet_t pkt, uint32_t len);
ODP_SUBSYSTEM_API(packet, void *, pull_head, odp_packet_t pkt, uint32_t len);
ODP_SUBSYSTEM_API(packet, void *, push_tail, odp_packet_t pkt, uint32_t len);
ODP_SUBSYSTEM_API(packet, void *, pull_tail, odp_packet_t pkt, uint32_t len);
ODP_SUBSYSTEM_API(packet, int, extend_head, odp_packet_t *pkt,
		  uint32_t len, void **data_ptr, uint32_t *seg_len);
ODP_SUBSYSTEM_API(packet, int, trunc_head, odp_packet_t *pkt,
		  uint32_t len, void **data_ptr, uint32_t *seg_len);
ODP_SUBSYSTEM_API(packet, int, extend_tail, odp_packet_t *pkt,
		  uint32_t len, void **data_ptr, uint32_t *seg_len);
ODP_SUBSYSTEM_API(packet, int, trunc_tail, odp_packet_t *pkt,
		  uint32_t len, void **tail_ptr, uint32_t *tailroom);
ODP_SUBSYSTEM_API(packet, int, add_data, odp_packet_t *pkt,
		  uint32_t offset, uint32_t len);
ODP_SUBSYSTEM_API(packet, int, rem_data, odp_packet_t *pkt,
		  uint32_t offset, uint32_t len);
ODP_SUBSYSTEM_API(packet, int, align, odp_packet_t *pkt,
		  uint32_t offset, uint32_t len, uint32_t align);
ODP_SUBSYSTEM_API(packet, int, is_segmented, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, num_segs, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, odp_packet_seg_t, first_seg, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, odp_packet_seg_t, last_seg, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, odp_packet_seg_t, next_seg,
		  odp_packet_t pkt, odp_packet_seg_t seg);
ODP_SUBSYSTEM_API(packet, void *, seg_data, odp_packet_t pkt,
		  odp_packet_seg_t seg);
ODP_SUBSYSTEM_API(packet, uint32_t, seg_data_len, odp_packet_t pkt,
		  odp_packet_seg_t seg);
ODP_SUBSYSTEM_API(packet, int, concat, odp_packet_t *dst, odp_packet_t src);
ODP_SUBSYSTEM_API(packet, int, split, odp_packet_t *pkt,
		  uint32_t len, odp_packet_t *tail);
ODP_SUBSYSTEM_API(packet, odp_packet_t, ref_static, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, odp_packet_t, ref, odp_packet_t pkt, uint32_t offset);
ODP_SUBSYSTEM_API(packet, odp_packet_t, ref_pkt, odp_packet_t pkt,
		  uint32_t offset, odp_packet_t hdr);
ODP_SUBSYSTEM_API(packet, uint32_t, unshared_len, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_ref, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, odp_packet_t, copy,
		  odp_packet_t pkt, odp_pool_t pool);
ODP_SUBSYSTEM_API(packet, odp_packet_t, copy_part, odp_packet_t pkt,
		  uint32_t offset, uint32_t len, odp_pool_t pool);
ODP_SUBSYSTEM_API(packet, int, copy_to_mem, odp_packet_t pkt,
		  uint32_t offset, uint32_t len, void *dst);
ODP_SUBSYSTEM_API(packet, int, copy_from_mem, odp_packet_t pkt,
		  uint32_t offset, uint32_t len, const void *src);
ODP_SUBSYSTEM_API(packet, int, copy_from_pkt, odp_packet_t dst,
		  uint32_t dst_offset, odp_packet_t src,
		  uint32_t src_offset, uint32_t len);
ODP_SUBSYSTEM_API(packet, int, copy_data, odp_packet_t pkt,
		  uint32_t dst_offset, uint32_t src_offset, uint32_t len);
ODP_SUBSYSTEM_API(packet, int, move_data, odp_packet_t pkt,
		  uint32_t dst_offset, uint32_t src_offset, uint32_t len);
ODP_SUBSYSTEM_API(packet, odp_pool_t, pool, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, odp_pktio_t, input, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void *, user_ptr, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, user_ptr_set,
		  odp_packet_t pkt, const void *ctx);
ODP_SUBSYSTEM_API(packet, void *, user_area, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, uint32_t, user_area_size, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void *, l2_ptr, odp_packet_t pkt, uint32_t *len);
ODP_SUBSYSTEM_API(packet, uint32_t, l2_offset, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, l2_offset_set,
		  odp_packet_t pkt, uint32_t offset);
ODP_SUBSYSTEM_API(packet, void *, l3_ptr, odp_packet_t pkt, uint32_t *len);
ODP_SUBSYSTEM_API(packet, uint32_t, l3_offset, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, l3_offset_set,
		  odp_packet_t pkt, uint32_t offset);
ODP_SUBSYSTEM_API(packet, void *, l4_ptr, odp_packet_t pkt, uint32_t *len);
ODP_SUBSYSTEM_API(packet, uint32_t, l4_offset, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, l4_offset_set,
		  odp_packet_t pkt, uint32_t offset);
ODP_SUBSYSTEM_API(packet, void, l3_chksum_insert, odp_packet_t pkt, int l3);
ODP_SUBSYSTEM_API(packet, void, l4_chksum_insert, odp_packet_t pkt, int l4);
ODP_SUBSYSTEM_API(packet, uint32_t, flow_hash, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, flow_hash_set, odp_packet_t pkt,
		  uint32_t flow_hash);
ODP_SUBSYSTEM_API(packet, odp_time_t, ts, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, ts_set, odp_packet_t pkt, odp_time_t timestamp);
ODP_SUBSYSTEM_API(packet, odp_packet_color_t, color, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, color_set, odp_packet_t pkt,
		  odp_packet_color_t color);
ODP_SUBSYSTEM_API(packet, odp_bool_t, drop_eligible, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, drop_eligible_set,
		  odp_packet_t pkt, odp_bool_t status);
ODP_SUBSYSTEM_API(packet, int8_t, shaper_len_adjust, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, shaper_len_adjust_set,
		  odp_packet_t pkt, int8_t adj);
ODP_SUBSYSTEM_API(packet, void, print, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, print_data, odp_packet_t pkt,
		  uint32_t offset, uint32_t len);
ODP_SUBSYSTEM_API(packet, int, is_valid, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, uint64_t, to_u64, odp_packet_t hdl);
ODP_SUBSYSTEM_API(packet, uint64_t, seg_to_u64, odp_packet_seg_t hdl);
ODP_SUBSYSTEM_API(packet, int, has_l2_error, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_l2, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_l3_error, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_l3, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_l4_error, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_l4, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_eth, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_eth_bcast, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_eth_mcast, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_jumbo, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_vlan, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_vlan_qinq, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_arp, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_ipv4, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_ipv6, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_ip_bcast, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_ip_mcast, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_ipfrag, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_ipopt, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_ipsec, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_udp, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_tcp, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_sctp, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_icmp, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_flow_hash, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, int, has_ts, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, has_l2_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_l3_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_l4_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_eth_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_eth_bcast_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_eth_mcast_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_jumbo_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_vlan_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_vlan_qinq_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_arp_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_ipv4_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_ipv6_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_ip_bcast_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_ip_mcast_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_ipfrag_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_ipopt_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_ipsec_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_udp_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_tcp_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_sctp_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_icmp_set, odp_packet_t pkt, int val);
ODP_SUBSYSTEM_API(packet, void, has_flow_hash_clr, odp_packet_t pkt);
ODP_SUBSYSTEM_API(packet, void, has_ts_clr, odp_packet_t pkt);

typedef ODP_MODULE_CLASS(packet) {
	odp_module_base_t base;

	odp_api_proto(packet, alloc_multi) packet_alloc_multi ODP_ALIGNED_CACHE;
	odp_api_proto(packet, free_multi) packet_free_multi;
	odp_api_proto(packet, has_error) packet_has_error;
	odp_api_proto(packet, prefetch) packet_prefetch;
	odp_api_proto(packet, data) packet_data;
	odp_api_proto(packet, input_index) packet_input_index;
	odp_api_proto(packet, alloc) packet_alloc;
	odp_api_proto(packet, free) packet_free;
	odp_api_proto(packet, reset) packet_reset;
	odp_api_proto(packet, from_event) packet_from_event;
	odp_api_proto(packet, to_event) packet_to_event;
	odp_api_proto(packet, head) packet_head;
	odp_api_proto(packet, buf_len) packet_buf_len;
	odp_api_proto(packet, seg_len) packet_seg_len;
	odp_api_proto(packet, len) packet_len;
	odp_api_proto(packet, headroom) packet_headroom;
	odp_api_proto(packet, tailroom) packet_tailroom;
	odp_api_proto(packet, tail) packet_tail;
	odp_api_proto(packet, offset) packet_offset;
	odp_api_proto(packet, push_head) packet_push_head;
	odp_api_proto(packet, pull_head) packet_pull_head;
	odp_api_proto(packet, push_tail) packet_push_tail;
	odp_api_proto(packet, pull_tail) packet_pull_tail;
	odp_api_proto(packet, extend_head) packet_extend_head;
	odp_api_proto(packet, trunc_head) packet_trunc_head;
	odp_api_proto(packet, extend_tail) packet_extend_tail;
	odp_api_proto(packet, trunc_tail) packet_trunc_tail;
	odp_api_proto(packet, add_data) packet_add_data;
	odp_api_proto(packet, rem_data) packet_rem_data;
	odp_api_proto(packet, align) packet_align;
	odp_api_proto(packet, is_segmented) packet_is_segmented;
	odp_api_proto(packet, num_segs) packet_num_segs;
	odp_api_proto(packet, first_seg) packet_first_seg;
	odp_api_proto(packet, last_seg) packet_last_seg;
	odp_api_proto(packet, next_seg) packet_next_seg;
	odp_api_proto(packet, seg_data) packet_seg_data;
	odp_api_proto(packet, seg_data_len) packet_seg_data_len;
	odp_api_proto(packet, concat) packet_concat;
	odp_api_proto(packet, split) packet_split;
	odp_api_proto(packet, ref_static) packet_ref_static;
	odp_api_proto(packet, ref) packet_ref;
	odp_api_proto(packet, ref_pkt) packet_ref_pkt;
	odp_api_proto(packet, has_ref) packet_has_ref;
	odp_api_proto(packet, copy) packet_copy;
	odp_api_proto(packet, copy_part) packet_copy_part;
	odp_api_proto(packet, copy_to_mem) packet_copy_to_mem;
	odp_api_proto(packet, copy_from_mem) packet_copy_from_mem;
	odp_api_proto(packet, copy_from_pkt) packet_copy_from_pkt;
	odp_api_proto(packet, copy_data) packet_copy_data;
	odp_api_proto(packet, move_data) packet_move_data;
	odp_api_proto(packet, pool) packet_pool;
	odp_api_proto(packet, input) packet_input;
	odp_api_proto(packet, user_ptr) packet_user_ptr;
	odp_api_proto(packet, user_ptr_set) packet_user_ptr_set;
	odp_api_proto(packet, user_area) packet_user_area;
	odp_api_proto(packet, user_area_size) packet_user_area_size;
	odp_api_proto(packet, l2_ptr) packet_l2_ptr;
	odp_api_proto(packet, l2_offset) packet_l2_offset;
	odp_api_proto(packet, l2_offset_set) packet_l2_offset_set;
	odp_api_proto(packet, l3_ptr) packet_l3_ptr;
	odp_api_proto(packet, l3_offset) packet_l3_offset;
	odp_api_proto(packet, l3_offset_set) packet_l3_offset_set;
	odp_api_proto(packet, l4_ptr) packet_l4_ptr;
	odp_api_proto(packet, l4_offset) packet_l4_offset;
	odp_api_proto(packet, l4_offset_set) packet_l4_offset_set;
	odp_api_proto(packet, l3_chksum_insert) packet_l3_chksum_insert;
	odp_api_proto(packet, l4_chksum_insert) packet_l4_chksum_insert;
	odp_api_proto(packet, flow_hash) packet_flow_hash;
	odp_api_proto(packet, flow_hash_set) packet_flow_hash_set;
	odp_api_proto(packet, ts) packet_ts;
	odp_api_proto(packet, ts_set) packet_ts_set;
	odp_api_proto(packet, color) packet_color;
	odp_api_proto(packet, color_set) packet_color_set;
	odp_api_proto(packet, drop_eligible) packet_drop_eligible;
	odp_api_proto(packet, drop_eligible_set) packet_drop_eligible_set;
	odp_api_proto(packet, shaper_len_adjust) packet_shaper_len_adjust;
	odp_api_proto(packet, shaper_len_adjust_set)
		packet_shaper_len_adjust_set;
	odp_api_proto(packet, print) packet_print;
	odp_api_proto(packet, print_data) packet_print_data;
	odp_api_proto(packet, is_valid) packet_is_valid;
	odp_api_proto(packet, to_u64) packet_to_u64;
	odp_api_proto(packet, seg_to_u64) packet_seg_to_u64;
	odp_api_proto(packet, has_l2_error) packet_has_l2_error;
	odp_api_proto(packet, has_l2) packet_has_l2;
	odp_api_proto(packet, has_l3_error) packet_has_l3_error;
	odp_api_proto(packet, has_l3) packet_has_l3;
	odp_api_proto(packet, has_l4_error) packet_has_l4_error;
	odp_api_proto(packet, has_l4) packet_has_l4;
	odp_api_proto(packet, has_eth) packet_has_eth;
	odp_api_proto(packet, has_eth_bcast) packet_has_eth_bcast;
	odp_api_proto(packet, has_eth_mcast) packet_has_eth_mcast;
	odp_api_proto(packet, has_jumbo) packet_has_jumbo;
	odp_api_proto(packet, has_vlan) packet_has_vlan;
	odp_api_proto(packet, has_vlan_qinq) packet_has_vlan_qinq;
	odp_api_proto(packet, has_arp) packet_has_arp;
	odp_api_proto(packet, has_ipv4) packet_has_ipv4;
	odp_api_proto(packet, has_ipv6) packet_has_ipv6;
	odp_api_proto(packet, has_ip_bcast) packet_has_ip_bcast;
	odp_api_proto(packet, has_ip_mcast) packet_has_ip_mcast;
	odp_api_proto(packet, has_ipfrag) packet_has_ipfrag;
	odp_api_proto(packet, has_ipopt) packet_has_ipopt;
	odp_api_proto(packet, has_ipsec) packet_has_ipsec;
	odp_api_proto(packet, has_udp) packet_has_udp;
	odp_api_proto(packet, has_tcp) packet_has_tcp;
	odp_api_proto(packet, has_sctp) packet_has_sctp;
	odp_api_proto(packet, has_icmp) packet_has_icmp;
	odp_api_proto(packet, has_flow_hash) packet_has_flow_hash;
	odp_api_proto(packet, has_ts) packet_has_ts;
	odp_api_proto(packet, has_l2_set) packet_has_l2_set;
	odp_api_proto(packet, has_l3_set) packet_has_l3_set;
	odp_api_proto(packet, has_l4_set) packet_has_l4_set;
	odp_api_proto(packet, has_eth_set) packet_has_eth_set;
	odp_api_proto(packet, has_eth_bcast_set) packet_has_eth_bcast_set;
	odp_api_proto(packet, has_eth_mcast_set) packet_has_eth_mcast_set;
	odp_api_proto(packet, has_jumbo_set) packet_has_jumbo_set;
	odp_api_proto(packet, has_vlan_set) packet_has_vlan_set;
	odp_api_proto(packet, has_vlan_qinq_set) packet_has_vlan_qinq_set;
	odp_api_proto(packet, has_arp_set) packet_has_arp_set;
	odp_api_proto(packet, has_ipv4_set) packet_has_ipv4_set;
	odp_api_proto(packet, has_ipv6_set) packet_has_ipv6_set;
	odp_api_proto(packet, has_ip_bcast_set) packet_has_ip_bcast_set;
	odp_api_proto(packet, has_ip_mcast_set) packet_has_ip_mcast_set;
	odp_api_proto(packet, has_ipfrag_set) packet_has_ipfrag_set;
	odp_api_proto(packet, has_ipopt_set) packet_has_ipopt_set;
	odp_api_proto(packet, has_ipsec_set) packet_has_ipsec_set;
	odp_api_proto(packet, has_udp_set) packet_has_udp_set;
	odp_api_proto(packet, has_tcp_set) packet_has_tcp_set;
	odp_api_proto(packet, has_sctp_set) packet_has_sctp_set;
	odp_api_proto(packet, has_icmp_set) packet_has_icmp_set;
	odp_api_proto(packet, has_flow_hash_clr) packet_has_flow_hash_clr;
	odp_api_proto(packet, has_ts_clr) packet_has_ts_clr;
} odp_packet_module_t;

#ifdef __cplusplus
}
#endif

#endif

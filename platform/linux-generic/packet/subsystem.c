/* Copyright (c) 2017, ARM Limited. All rights reserved.
 *
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <subsystem/spec/packet_subsystem.h>
#include <odp_module.h>

odp_packet_module_t *mod;

#define ODP_PACKET_API_INVOKE(api, ...) \
	odp_subsystem_active_module(packet, mod)->api(__VA_ARGS__)

ODP_SUBSYSTEM_DEFINE(packet, "packet public APIs",
		     PACKET_SUBSYSTEM_VERSION);

ODP_SUBSYSTEM_CONSTRUCTOR(packet)
{
	odp_subsystem_constructor(packet);
}

odp_packet_t odp_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_alloc, pool_hdl, len);
}

int odp_packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
			   odp_packet_t pkt[], int max_num)
{
	return ODP_PACKET_API_INVOKE(packet_alloc_multi, pool_hdl,
				     len, pkt, max_num);
}

void odp_packet_free(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_free, pkt);
}

void odp_packet_free_multi(const odp_packet_t pkt[], int num)
{
	return ODP_PACKET_API_INVOKE(packet_free_multi, pkt, num);
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_reset, pkt, len);
}

odp_packet_t odp_packet_from_event(odp_event_t ev)
{
	return ODP_PACKET_API_INVOKE(packet_from_event, ev);
}

odp_event_t odp_packet_to_event(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_to_event, pkt);
}

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_buf_len, pkt);
}

void *odp_packet_tail(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_tail, pkt);
}

void *odp_packet_offset(odp_packet_t pkt, uint32_t offset, uint32_t *len,
			odp_packet_seg_t *seg)
{
	return ODP_PACKET_API_INVOKE(packet_offset, pkt, offset, len, seg);
}

void *odp_packet_push_head(odp_packet_t pkt, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_push_head, pkt, len);
}

void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_pull_head, pkt, len);
}

void *odp_packet_push_tail(odp_packet_t pkt, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_push_tail, pkt, len);
}

void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_pull_tail, pkt, len);
}

int odp_packet_extend_head(odp_packet_t *pkt, uint32_t len, void **data_ptr,
			   uint32_t *seg_len)
{
	return ODP_PACKET_API_INVOKE(packet_extend_head, pkt,
				     len, data_ptr, seg_len);
}

int odp_packet_trunc_head(odp_packet_t *pkt, uint32_t len, void **data_ptr,
			  uint32_t *seg_len)
{
	return ODP_PACKET_API_INVOKE(packet_trunc_head, pkt,
				     len, data_ptr, seg_len);
}

int odp_packet_extend_tail(odp_packet_t *pkt, uint32_t len, void **data_ptr,
			   uint32_t *seg_len)
{
	return ODP_PACKET_API_INVOKE(packet_extend_tail, pkt,
				     len, data_ptr, seg_len);
}

int odp_packet_trunc_tail(odp_packet_t *pkt, uint32_t len, void **tail_ptr,
			  uint32_t *tailroom)
{
	return ODP_PACKET_API_INVOKE(packet_trunc_tail, pkt,
				     len, tail_ptr, tailroom);
}

int odp_packet_add_data(odp_packet_t *pkt, uint32_t offset, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_add_data, pkt, offset, len);
}

int odp_packet_rem_data(odp_packet_t *pkt, uint32_t offset, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_rem_data, pkt, offset, len);
}

int odp_packet_align(odp_packet_t *pkt, uint32_t offset, uint32_t len,
		     uint32_t align)
{
	return ODP_PACKET_API_INVOKE(packet_align, pkt, offset, len, align);
}

void *odp_packet_seg_data(odp_packet_t pkt, odp_packet_seg_t seg)
{
	return ODP_PACKET_API_INVOKE(packet_seg_data, pkt, seg);
}

uint32_t odp_packet_seg_data_len(odp_packet_t pkt, odp_packet_seg_t seg)
{
	return ODP_PACKET_API_INVOKE(packet_seg_data_len, pkt, seg);
}

int odp_packet_concat(odp_packet_t *dst, odp_packet_t src)
{
	return ODP_PACKET_API_INVOKE(packet_concat, dst, src);
}

int odp_packet_split(odp_packet_t *pkt, uint32_t len, odp_packet_t *tail)
{
	return ODP_PACKET_API_INVOKE(packet_split, pkt, len, tail);
}

odp_packet_t odp_packet_ref_static(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_ref_static, pkt);
}

odp_packet_t odp_packet_ref(odp_packet_t pkt, uint32_t offset)
{
	return ODP_PACKET_API_INVOKE(packet_ref, pkt, offset);
}

odp_packet_t odp_packet_ref_pkt(odp_packet_t pkt, uint32_t offset,
				odp_packet_t hdr)
{
	return ODP_PACKET_API_INVOKE(packet_ref_pkt, pkt, offset, hdr);
}

int odp_packet_has_ref(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_ref, pkt);
}

odp_packet_t odp_packet_copy(odp_packet_t pkt, odp_pool_t pool)
{
	return ODP_PACKET_API_INVOKE(packet_copy, pkt, pool);
}

odp_packet_t odp_packet_copy_part(odp_packet_t pkt, uint32_t offset,
				  uint32_t len, odp_pool_t pool)
{
	return ODP_PACKET_API_INVOKE(packet_copy_part, pkt, offset, len, pool);
}

int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
			   uint32_t len, void *dst)
{
	return ODP_PACKET_API_INVOKE(packet_copy_to_mem, pkt, offset, len, dst);
}

int odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
			     uint32_t len, const void *src)
{
	return ODP_PACKET_API_INVOKE(packet_copy_from_mem, pkt,
				     offset, len, src);
}

int odp_packet_copy_from_pkt(odp_packet_t dst, uint32_t dst_offset,
			     odp_packet_t src, uint32_t src_offset,
			     uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_copy_from_pkt, dst,
			      dst_offset, src, src_offset, len);
}

int odp_packet_copy_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_copy_data, pkt,
			      dst_offset, src_offset, len);
}

int odp_packet_move_data(odp_packet_t pkt, uint32_t dst_offset,
			 uint32_t src_offset, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_move_data, pkt,
			      dst_offset, src_offset, len);
}

int odp_packet_input_index(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_input_index, pkt);
}

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx)
{
	return ODP_PACKET_API_INVOKE(packet_user_ptr_set, pkt, ctx);
}

uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_user_area_size, pkt);
}

void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	return ODP_PACKET_API_INVOKE(packet_l2_ptr, pkt, len);
}

uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_l2_offset, pkt);
}

int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset)
{
	return ODP_PACKET_API_INVOKE(packet_l2_offset_set, pkt, offset);
}

void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	return ODP_PACKET_API_INVOKE(packet_l3_ptr, pkt, len);
}

uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_l3_offset, pkt);
}

int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	return ODP_PACKET_API_INVOKE(packet_l3_offset_set, pkt, offset);
}

void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	return ODP_PACKET_API_INVOKE(packet_l4_ptr, pkt, len);
}

uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_l4_offset, pkt);
}

int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	return ODP_PACKET_API_INVOKE(packet_l4_offset_set, pkt, offset);
}

void odp_packet_l3_chksum_insert(odp_packet_t pkt, int l3)
{
	return ODP_PACKET_API_INVOKE(packet_l3_chksum_insert, pkt, l3);
}

void odp_packet_l4_chksum_insert(odp_packet_t pkt, int l4)
{
	return ODP_PACKET_API_INVOKE(packet_l4_chksum_insert, pkt, l4);
}

void odp_packet_ts_set(odp_packet_t pkt, odp_time_t timestamp)
{
	return ODP_PACKET_API_INVOKE(packet_ts_set, pkt, timestamp);
}

odp_packet_color_t odp_packet_color(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_color, pkt);
}

void odp_packet_color_set(odp_packet_t pkt, odp_packet_color_t color)
{
	return ODP_PACKET_API_INVOKE(packet_color_set, pkt, color);
}

odp_bool_t odp_packet_drop_eligible(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_drop_eligible, pkt);
}

void odp_packet_drop_eligible_set(odp_packet_t pkt, odp_bool_t status)
{
	return ODP_PACKET_API_INVOKE(packet_drop_eligible_set, pkt, status);
}

int8_t odp_packet_shaper_len_adjust(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_shaper_len_adjust, pkt);
}

void odp_packet_shaper_len_adjust_set(odp_packet_t pkt, int8_t adj)
{
	return ODP_PACKET_API_INVOKE(packet_shaper_len_adjust_set, pkt, adj);
}

void odp_packet_print(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_print, pkt);
}

void odp_packet_print_data(odp_packet_t pkt, uint32_t offset, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_print_data, pkt, offset, len);
}

int odp_packet_is_valid(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_is_valid, pkt);
}

uint64_t odp_packet_to_u64(odp_packet_t hdl)
{
	return ODP_PACKET_API_INVOKE(packet_to_u64, hdl);
}

uint64_t odp_packet_seg_to_u64(odp_packet_seg_t hdl)
{
	return ODP_PACKET_API_INVOKE(packet_seg_to_u64, hdl);
}

int odp_packet_has_error(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_error, pkt);
}

int odp_packet_has_l2_error(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_l2_error, pkt);
}

int odp_packet_has_l3_error(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_l3_error, pkt);
}

int odp_packet_has_l3(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_l3, pkt);
}

int odp_packet_has_l4_error(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_l4_error, pkt);
}

int odp_packet_has_l4(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_l4, pkt);
}

int odp_packet_has_eth_bcast(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_eth_bcast, pkt);
}

int odp_packet_has_eth_mcast(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_eth_mcast, pkt);
}

int odp_packet_has_vlan(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_vlan, pkt);
}

int odp_packet_has_vlan_qinq(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_vlan_qinq, pkt);
}

int odp_packet_has_arp(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_arp, pkt);
}

int odp_packet_has_ipv4(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_ipv4, pkt);
}

int odp_packet_has_ipv6(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_ipv6, pkt);
}

int odp_packet_has_ip_bcast(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_ip_bcast, pkt);
}

int odp_packet_has_ip_mcast(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_ip_mcast, pkt);
}

int odp_packet_has_ipfrag(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_ipfrag, pkt);
}

int odp_packet_has_ipopt(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_ipopt, pkt);
}

int odp_packet_has_ipsec(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_ipsec, pkt);
}

int odp_packet_has_udp(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_udp, pkt);
}

int odp_packet_has_tcp(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_tcp, pkt);
}

int odp_packet_has_sctp(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_sctp, pkt);
}

int odp_packet_has_icmp(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_icmp, pkt);
}

void odp_packet_has_l2_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_l2_set, pkt, val);
}

void odp_packet_has_l3_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_l3_set, pkt, val);
}

void odp_packet_has_l4_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_l4_set, pkt, val);
}

void odp_packet_has_eth_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_eth_set, pkt, val);
}

void odp_packet_has_eth_bcast_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_eth_bcast_set, pkt, val);
}

void odp_packet_has_eth_mcast_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_eth_mcast_set, pkt, val);
}

void odp_packet_has_jumbo_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_jumbo_set, pkt, val);
}

void odp_packet_has_vlan_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_vlan_set, pkt, val);
}

void odp_packet_has_vlan_qinq_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_vlan_qinq_set, pkt, val);
}

void odp_packet_has_arp_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_arp_set, pkt, val);
}

void odp_packet_has_ipv4_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_ipv4_set, pkt, val);
}

void odp_packet_has_ipv6_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_ipv6_set, pkt, val);
}

void odp_packet_has_ip_bcast_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_ip_bcast_set, pkt, val);
}

void odp_packet_has_ip_mcast_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_ip_mcast_set, pkt, val);
}

void odp_packet_has_ipfrag_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_ipfrag_set, pkt, val);
}

void odp_packet_has_ipopt_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_ipopt_set, pkt, val);
}

void odp_packet_has_ipsec_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_ipsec_set, pkt, val);
}

void odp_packet_has_udp_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_udp_set, pkt, val);
}

void odp_packet_has_tcp_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_tcp_set, pkt, val);
}

void odp_packet_has_sctp_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_sctp_set, pkt, val);
}

void odp_packet_has_icmp_set(odp_packet_t pkt, int val)
{
	return ODP_PACKET_API_INVOKE(packet_has_icmp_set, pkt, val);
}

void odp_packet_has_flow_hash_clr(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_flow_hash_clr, pkt);
}

void odp_packet_has_ts_clr(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_ts_clr, pkt);
}

void odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	return ODP_PACKET_API_INVOKE(packet_flow_hash_set, pkt, flow_hash);
}

#if ODP_ABI_COMPAT == 1
int odp_packet_has_l2(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_l2, pkt);
}

int odp_packet_has_eth(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_eth, pkt);
}

int odp_packet_has_jumbo(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_jumbo, pkt);
}

int odp_packet_has_flow_hash(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_flow_hash, pkt);
}

int odp_packet_has_ts(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_has_ts, pkt);
}

void *odp_packet_data(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_data, pkt);
}

uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_seg_len, pkt);
}

uint32_t odp_packet_len(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_len, pkt);
}

uint32_t odp_packet_headroom(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_headroom, pkt);
}

uint32_t odp_packet_tailroom(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_tailroom, pkt);
}

odp_pool_t odp_packet_pool(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_pool, pkt);
}

odp_pktio_t odp_packet_input(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_input, pkt);
}

int odp_packet_num_segs(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_num_segs, pkt);
}

void *odp_packet_user_ptr(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_user_ptr, pkt);
}

void *odp_packet_user_area(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_user_area, pkt);
}

uint32_t odp_packet_flow_hash(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_flow_hash, pkt);
}

odp_time_t odp_packet_ts(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_ts, pkt);
}

void *odp_packet_head(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_head, pkt);
}

int odp_packet_is_segmented(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_is_segmented, pkt);
}

odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_first_seg, pkt);
}

odp_packet_seg_t odp_packet_last_seg(odp_packet_t pkt)
{
	return ODP_PACKET_API_INVOKE(packet_last_seg, pkt);
}

odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt, odp_packet_seg_t seg)
{
	return ODP_PACKET_API_INVOKE(packet_next_seg, pkt, seg);
}

void odp_packet_prefetch(odp_packet_t pkt, uint32_t offset, uint32_t len)
{
	return ODP_PACKET_API_INVOKE(packet_prefetch, pkt, offset, len);
}

#endif

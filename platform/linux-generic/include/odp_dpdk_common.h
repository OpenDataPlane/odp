/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2018 Linaro Limited
 * Copyright (c) 2019-2026 Nokia
 */

#ifndef ODP_DPDK_COMMON_H
#define ODP_DPDK_COMMON_H

#include <odp/api/packet_io.h>

#include <odp_packet_internal.h>
#include <odp_parse_internal.h>

#include <protocols/ip.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <stdint.h>

#define IP4_CSUM_RESULT(ol_flags) ((ol_flags) & RTE_MBUF_F_RX_IP_CKSUM_MASK)
#define L4_CSUM_RESULT(ol_flags) ((ol_flags) & RTE_MBUF_F_RX_L4_CKSUM_MASK)

/** Packet parser using DPDK interface */
static inline int _odp_dpdk_packet_parse_common(odp_packet_hdr_t *pkt_hdr, const uint8_t *ptr,
						uint32_t frame_len, uint32_t seg_len,
						struct rte_mbuf *mbuf, int layer,
						odp_pktin_config_opt_t pktin_cfg)
{
	packet_parser_t *prs = &pkt_hdr->p;
	uint64_t mbuf_ol = mbuf->ol_flags;

	if (odp_unlikely(layer == ODP_PROTO_LAYER_NONE))
		return 0;

	/* Assume valid L2 header, no CRC/FCS check in SW */
	prs->l2_offset = 0;

	if (layer >= ODP_PROTO_LAYER_L3) {
		int ip_chksum = IP4_CSUM_RESULT(mbuf_ol);

		if (ip_chksum == RTE_MBUF_F_RX_IP_CKSUM_GOOD) {
			prs->input_flags.l3_chksum_done = 1;
		} else if (ip_chksum != RTE_MBUF_F_RX_IP_CKSUM_UNKNOWN) {
			prs->input_flags.l3_chksum_done = 1;
			prs->flags.l3_chksum_err = 1;
		}
	}

	if (layer >= ODP_PROTO_LAYER_L4) {
		int l4_chksum = L4_CSUM_RESULT(mbuf_ol);

		if (l4_chksum == RTE_MBUF_F_RX_L4_CKSUM_GOOD) {
			prs->input_flags.l4_chksum_done = 1;
		} else if (l4_chksum != RTE_MBUF_F_RX_L4_CKSUM_UNKNOWN) {
			prs->input_flags.l4_chksum_done = 1;
			prs->flags.l4_chksum_err = 1;
		}
	}

	pktin_cfg.bit.ipv4_chksum = 0;
	pktin_cfg.bit.udp_chksum = 0;
	pktin_cfg.bit.tcp_chksum = 0;
	pktin_cfg.bit.sctp_chksum = 0;

	return _odp_packet_parse_common(pkt_hdr, ptr, frame_len, seg_len, layer,
					pktin_cfg);
}

static inline int _odp_dpdk_check_proto(void *l3_hdr, odp_bool_t *l3_proto_v4, uint8_t *l4_proto)
{
	uint8_t l3_proto_ver = _ODP_IPV4HDR_VER(*(uint8_t *)l3_hdr);

	if (l3_proto_ver == _ODP_IPV4) {
		struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)l3_hdr;

		*l3_proto_v4 = 1;
		if (!rte_ipv4_frag_pkt_is_fragmented(ip))
			*l4_proto = ip->next_proto_id;
		else
			*l4_proto = 0;

		return 0;
	} else if (l3_proto_ver == _ODP_IPV6) {
		struct rte_ipv6_hdr *ipv6 = (struct rte_ipv6_hdr *)l3_hdr;

		*l3_proto_v4 = 0;
		*l4_proto = ipv6->proto;
		return 0;
	}

	return -1;
}

static inline uint16_t _odp_dpdk_phdr_csum(odp_bool_t ipv4, void *l3_hdr, uint64_t ol_flags)
{
	if (ipv4)
		return rte_ipv4_phdr_cksum(l3_hdr, ol_flags);
	else /*ipv6*/
		return rte_ipv6_phdr_cksum(l3_hdr, ol_flags);
}

#define OL_TX_CHKSUM_PKT(_cfg, _capa, _proto, _ovr_set, _ovr) \
	((_capa) && (_proto) && ((_ovr_set) ? (_ovr) : (_cfg)))

static inline void _odp_dpdk_pkt_set_ol_tx(odp_pktout_config_opt_t *pktout_cfg,
					   odp_pktout_config_opt_t *pktout_capa,
					   odp_packet_hdr_t *pkt_hdr,
					   struct rte_mbuf *mbuf,
					   char *mbuf_data)
{
	void *l3_hdr, *l4_hdr;
	uint8_t l4_proto;
	odp_bool_t l3_proto_v4;
	odp_bool_t ipv4_chksum_pkt, udp_chksum_pkt, tcp_chksum_pkt;
	packet_parser_t *pkt_p = &pkt_hdr->p;

	if (pkt_p->l3_offset == ODP_PACKET_OFFSET_INVALID)
		return;

	l3_hdr = (void *)(mbuf_data + pkt_p->l3_offset);

	if (_odp_dpdk_check_proto(l3_hdr, &l3_proto_v4, &l4_proto))
		return;

	ipv4_chksum_pkt = OL_TX_CHKSUM_PKT(pktout_cfg->bit.ipv4_chksum,
					   pktout_capa->bit.ipv4_chksum,
					   l3_proto_v4,
					   pkt_p->flags.l3_chksum_set,
					   pkt_p->flags.l3_chksum);
	udp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.udp_chksum,
					   pktout_capa->bit.udp_chksum,
					   (l4_proto == _ODP_IPPROTO_UDP),
					   pkt_p->flags.l4_chksum_set,
					   pkt_p->flags.l4_chksum);
	tcp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.tcp_chksum,
					   pktout_capa->bit.tcp_chksum,
					   (l4_proto == _ODP_IPPROTO_TCP),
					   pkt_p->flags.l4_chksum_set,
					   pkt_p->flags.l4_chksum);

	if (!ipv4_chksum_pkt && !udp_chksum_pkt && !tcp_chksum_pkt)
		return;

	mbuf->l2_len = pkt_p->l3_offset - pkt_p->l2_offset;

	if (l3_proto_v4)
		mbuf->ol_flags = RTE_MBUF_F_TX_IPV4;
	else
		mbuf->ol_flags = RTE_MBUF_F_TX_IPV6;

	if (ipv4_chksum_pkt) {
		mbuf->ol_flags |=  RTE_MBUF_F_TX_IP_CKSUM;

		((struct rte_ipv4_hdr *)l3_hdr)->hdr_checksum = 0;
		mbuf->l3_len = _ODP_IPV4HDR_IHL(*(uint8_t *)l3_hdr) * 4;
	}

	if (pkt_p->l4_offset == ODP_PACKET_OFFSET_INVALID)
		return;

	mbuf->l3_len = pkt_p->l4_offset - pkt_p->l3_offset;

	l4_hdr = (void *)(mbuf_data + pkt_p->l4_offset);

	if (udp_chksum_pkt) {
		mbuf->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;

		((struct rte_udp_hdr *)l4_hdr)->dgram_cksum =
			_odp_dpdk_phdr_csum(l3_proto_v4, l3_hdr, mbuf->ol_flags);
	} else if (tcp_chksum_pkt) {
		mbuf->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

		((struct rte_tcp_hdr *)l4_hdr)->cksum =
			_odp_dpdk_phdr_csum(l3_proto_v4, l3_hdr, mbuf->ol_flags);
	}
}

int _odp_dpdk_netdev_is_valid(const char *s);

void _odp_dpdk_hash_proto_to_rss_conf(struct rte_eth_rss_conf *rss_conf,
				      const odp_pktin_hash_proto_t *hash_proto);

int _odp_dpdk_stats_common(uint16_t port_id, odp_pktio_stats_t *stats);
int _odp_dpdk_stats_reset_common(uint16_t port_id);

int _odp_dpdk_extra_stat_info_common(uint16_t port_id, odp_pktio_extra_stat_info_t info[], int num);
int _odp_dpdk_extra_stats_common(uint16_t port_id, uint64_t stats[], int num);
int _odp_dpdk_extra_stat_counter_common(uint16_t port_id, uint32_t id, uint64_t *stat);

int _odp_dpdk_pktin_stats_common(uint16_t port_id, uint32_t index,
				 odp_pktin_queue_stats_t *pktin_stats);
int _odp_dpdk_pktout_stats_common(uint16_t port_id, uint32_t index,
				  odp_pktout_queue_stats_t *pktout_stats);

#endif

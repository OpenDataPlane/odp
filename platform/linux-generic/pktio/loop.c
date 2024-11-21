/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2013-2023 Nokia Solutions and Networks
 */

#include <odp/api/debug.h>
#include <odp/api/deprecated.h>
#include <odp/api/event.h>
#include <odp/api/hash.h>
#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/queue.h>
#include <odp/api/time.h>

#include <odp/api/plat/byteorder_inlines.h>
#include <odp/api/plat/packet_flag_inlines.h>
#include <odp/api/plat/queue_inlines.h>

#include <odp_parse_internal.h>
#include <odp_classification_internal.h>
#include <odp_debug_internal.h>
#include <odp_event_internal.h>
#include <odp_global_data.h>
#include <odp_ipsec_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_macros_internal.h>
#include <odp_queue_if.h>

#include <protocols/eth.h>
#include <protocols/ip.h>

#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_QUEUES (ODP_PKTIN_MAX_QUEUES > ODP_PKTOUT_MAX_QUEUES ? \
			ODP_PKTIN_MAX_QUEUES : ODP_PKTOUT_MAX_QUEUES)

#define MAX_LOOP 16

#define LOOP_MTU_MIN 68
#define LOOP_MTU_MAX UINT16_MAX

#define LOOP_MAX_QUEUE_SIZE 1024

typedef struct {
	odp_atomic_u64_t in_octets;
	odp_atomic_u64_t in_packets;
	odp_atomic_u64_t in_discards;
	odp_atomic_u64_t in_errors;
	odp_atomic_u64_t out_octets;
	odp_atomic_u64_t out_packets;
} stats_t;

typedef struct ODP_ALIGNED_CACHE {
	/* queue handle as the "wire" */
	odp_queue_t queue;
	/* queue specific statistics */
	stats_t stats;
	/* config input queue size */
	uint32_t in_size;
	/* config output queue size */
	uint32_t out_size;
} loop_queue_t;

typedef struct {
	/* loopback entries for "loop" device */
	loop_queue_t loopqs[MAX_QUEUES];
	/* hash config */
	odp_pktin_hash_proto_t hash;
	/* config queue count */
	uint32_t num_conf_qs;
	/* actual number queues */
	uint32_t num_qs;
	/* link MTU */
	uint16_t mtu;
	/* index of "loop" device */
	uint8_t idx;
	/* create or re-create queue during start */
	uint8_t queue_create;
} pkt_loop_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_loop_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_loop_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_loop_t *)(uintptr_t)(pktio_entry->pkt_priv);
}

/* MAC address for the "loop" interface */
static const uint8_t pktio_loop_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x01};

static int loopback_init_capability(pktio_entry_t *pktio_entry);

static int loopback_open(odp_pktio_t id ODP_UNUSED, pktio_entry_t *pktio_entry,
			 const char *devname, odp_pool_t pool ODP_UNUSED)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);
	long idx;

	if (!strcmp(devname, "loop")) {
		idx = 0;
	} else if (!strncmp(devname, "loop", 4)) {
		char *end;

		idx = strtol(devname + 4, &end, 10);
		if (idx <= 0 || idx >= MAX_LOOP || *end)
			return -1;
	} else {
		return -1;
	}

	memset(pkt_loop, 0, sizeof(pkt_loop_t));
	pkt_loop->mtu = LOOP_MTU_MAX;
	pkt_loop->idx = idx;
	pkt_loop->queue_create = 1;
	loopback_init_capability(pktio_entry);

	for (uint32_t i = 0; i < MAX_QUEUES; i++) {
		odp_atomic_init_u64(&pkt_loop->loopqs[i].stats.in_octets, 0);
		odp_atomic_init_u64(&pkt_loop->loopqs[i].stats.in_packets, 0);
		odp_atomic_init_u64(&pkt_loop->loopqs[i].stats.in_discards, 0);
		odp_atomic_init_u64(&pkt_loop->loopqs[i].stats.in_errors, 0);
		odp_atomic_init_u64(&pkt_loop->loopqs[i].stats.out_octets, 0);
		odp_atomic_init_u64(&pkt_loop->loopqs[i].stats.out_packets, 0);
	}

	return 0;
}

static int loopback_queue_destroy(odp_queue_t queue)
{
	odp_event_t event;

	do {
		event = odp_queue_deq(queue);
		if (event != ODP_EVENT_INVALID)
			odp_event_free(event);

	} while (event != ODP_EVENT_INVALID);

	if (odp_queue_destroy(queue)) {
		_ODP_ERR("Destroying loopback pktio queue failed\n");
		return -1;
	}
	return 0;
}

static int loopback_queues_destroy(loop_queue_t *queues, uint32_t num_queues)
{
	int ret = 0;

	for (uint32_t i = 0; i < num_queues; i++) {
		if (loopback_queue_destroy(queues[i].queue))
			ret = -1;
	}

	return ret;
}

static int loopback_start(pktio_entry_t *pktio_entry)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);
	odp_queue_param_t queue_param;
	char queue_name[ODP_QUEUE_NAME_LEN];

	/* Re-create queue only when necessary */
	if (!pkt_loop->queue_create)
		return 0;

	/* Destroy old queues */
	if (loopback_queues_destroy(pkt_loop->loopqs, pkt_loop->num_qs))
		return -1;

	pkt_loop->num_qs = 0;

	for (uint32_t i = 0; i < pkt_loop->num_conf_qs; i++) {
		odp_queue_param_init(&queue_param);
		queue_param.size = _ODP_MAX(pkt_loop->loopqs[i].in_size,
					    pkt_loop->loopqs[i].out_size);
		snprintf(queue_name, sizeof(queue_name), "_odp_pktio_loopq-%" PRIu64 "-%u",
			 odp_pktio_to_u64(pktio_entry->handle), i);
		pkt_loop->loopqs[i].queue = odp_queue_create(queue_name, &queue_param);

		if (pkt_loop->loopqs[i].queue == ODP_QUEUE_INVALID) {
			_ODP_ERR("Creating loopback pktio queue %s failed\n", queue_name);
			(void)loopback_queues_destroy(pkt_loop->loopqs, i);
			return -1;
		}
	}

	pkt_loop->num_qs = pkt_loop->num_conf_qs;

	return 0;
}

static int loopback_pktin_queue_config(pktio_entry_t *pktio_entry,
				       const odp_pktin_queue_param_t *param)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);

	pkt_loop->num_conf_qs = param->num_queues;
	pkt_loop->queue_create = 1;
	pkt_loop->hash.all_bits = param->hash_enable ? param->hash_proto.all_bits : 0;

	if (pktio_entry->param.in_mode == ODP_PKTIN_MODE_DIRECT) {
		for (uint32_t i = 0; i < MAX_QUEUES; i++) {
			if (i < pkt_loop->num_conf_qs)
				pkt_loop->loopqs[i].in_size = param->queue_size[i];
			else
				pkt_loop->loopqs[i].in_size = 0;
		}
	}

	return 0;
}

static int loopback_pktout_queue_config(pktio_entry_t *pktio_entry,
					const odp_pktout_queue_param_t *param)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);

	pkt_loop->queue_create = 1;

	for (uint32_t i = 0; i < MAX_QUEUES; i++) {
		if (i < param->num_queues)
			pkt_loop->loopqs[i].out_size = param->queue_size[i];
		else
			pkt_loop->loopqs[i].out_size = 0;
	}

	return 0;
}

static int loopback_close(pktio_entry_t *pktio_entry)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);

	return loopback_queues_destroy(pkt_loop->loopqs, pkt_loop->num_qs);
}

static int loopback_recv(pktio_entry_t *pktio_entry, int index, odp_packet_t pkts[], int num)
{
	int nbr, i;
	loop_queue_t *entry = &pkt_priv(pktio_entry)->loopqs[index];
	odp_queue_t queue = entry->queue;
	stats_t *stats = &entry->stats;
	_odp_event_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	odp_packet_t cls_tbl[QUEUE_MULTI_MAX];
	odp_packet_hdr_t *pkt_hdr;
	odp_packet_t pkt;
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	int num_rx = 0;
	int packets = 0;
	int num_cls = 0;
	const int cls_enabled = pktio_cls_enabled(pktio_entry);
	uint32_t octets = 0;
	const odp_proto_layer_t layer = pktio_entry->parse_layer;
	const odp_pktin_config_opt_t opt = pktio_entry->config.pktin;

	if (odp_unlikely(num > QUEUE_MULTI_MAX))
		num = QUEUE_MULTI_MAX;

	nbr = odp_queue_deq_multi(queue, (odp_event_t *)hdr_tbl, num);

	if (opt.bit.ts_all || opt.bit.ts_ptp) {
		ts_val = odp_time_global();
		ts = &ts_val;
	}

	for (i = 0; i < nbr; i++) {
		uint32_t pkt_len;
		int do_ipsec_enq = 0;

		pkt = packet_from_event_hdr(hdr_tbl[i]);
		pkt_len = odp_packet_len(pkt);
		pkt_hdr = packet_hdr(pkt);

		if (layer) {
			uint8_t *pkt_addr;
			uint8_t buf[PARSE_BYTES];
			int ret;
			uint32_t seg_len = odp_packet_seg_len(pkt);

			/* Make sure there is enough data for the packet
			 * parser in the case of a segmented packet. */
			if (odp_unlikely(seg_len < PARSE_BYTES &&
					 pkt_len > seg_len)) {
				seg_len = _ODP_MIN(pkt_len, PARSE_BYTES);
				odp_packet_copy_to_mem(pkt, 0, seg_len, buf);
				pkt_addr = buf;
			} else {
				pkt_addr = odp_packet_data(pkt);
			}

			packet_parse_reset(pkt_hdr, 1);
			ret = _odp_packet_parse_common(pkt_hdr, pkt_addr, pkt_len,
						       seg_len, layer, opt);
			if (ret)
				odp_atomic_inc_u64(&stats->in_errors);

			if (ret < 0) {
				odp_packet_free(pkt);
				continue;
			}

			if (cls_enabled) {
				odp_pool_t new_pool;

				ret = _odp_cls_classify_packet(pktio_entry, pkt_addr,
							       &new_pool, pkt_hdr);
				if (ret < 0)
					odp_atomic_inc_u64(&stats->in_discards);

				if (ret) {
					odp_packet_free(pkt);
					continue;
				}

				if (odp_unlikely(_odp_pktio_packet_to_pool(
					    &pkt, &pkt_hdr, new_pool))) {
					odp_packet_free(pkt);
					odp_atomic_inc_u64(&stats->in_discards);
					continue;
				}
			}
		}

		packet_set_ts(pkt_hdr, ts);
		pkt_hdr->input = pktio_entry->handle;

		/* Try IPsec inline processing */
		if (pktio_entry->config.inbound_ipsec &&
		    !pkt_hdr->p.flags.ip_err &&
		    odp_packet_has_ipsec(pkt)) {
			do_ipsec_enq = !_odp_ipsec_try_inline(&pkt);
			pkt_hdr = packet_hdr(pkt);
		}

		if (!pkt_hdr->p.flags.all.error) {
			octets += pkt_len;
			packets++;
		}

		if (do_ipsec_enq) {
			if (odp_unlikely(odp_queue_enq(pkt_hdr->dst_queue,
						       odp_packet_to_event(pkt)))) {
				odp_atomic_inc_u64(&stats->in_discards);
				if (!pkt_hdr->p.flags.all.error) {
					octets -= pkt_len;
					packets--;
				}
				odp_packet_free(pkt);
			}
		} else if (cls_enabled) {
			/* Enqueue packets directly to classifier destination queue */
			cls_tbl[num_cls++] = pkt;
			num_cls = _odp_cls_enq(cls_tbl, num_cls, (i + 1 == nbr));
		} else {
			pkts[num_rx++] = pkt;
		}
	}

	/* Enqueue remaining classified packets */
	if (odp_unlikely(num_cls))
		_odp_cls_enq(cls_tbl, num_cls, true);

	odp_atomic_add_u64(&stats->in_octets, octets);
	odp_atomic_add_u64(&stats->in_packets, packets);

	return num_rx;
}

#define OL_TX_CHKSUM_PKT(_cfg, _capa, _proto, _ovr_set, _ovr) \
	(_capa && _proto && (_ovr_set ? _ovr : _cfg))

static inline int check_proto(void *l3_hdr,
			      uint32_t l3_len,
			      odp_bool_t *l3_proto_v4,
			      uint8_t *l4_proto)
{
	uint8_t l3_proto_ver = _ODP_IPV4HDR_VER(*(uint8_t *)l3_hdr);

	if (l3_proto_ver == _ODP_IPV4 && l3_len >= _ODP_IPV4HDR_LEN) {
		_odp_ipv4hdr_t *ip = l3_hdr;
		uint16_t frag_offset = odp_be_to_cpu_16(ip->frag_offset);

		*l3_proto_v4 = 1;
		if (!_ODP_IPV4HDR_IS_FRAGMENT(frag_offset))
			*l4_proto = ip->proto;
		else
			*l4_proto = 255;

		return 0;
	} else if (l3_proto_ver == _ODP_IPV6 && l3_len >= _ODP_IPV6HDR_LEN) {
		_odp_ipv6hdr_t *ipv6 = l3_hdr;

		*l3_proto_v4 = 0;
		*l4_proto = ipv6->next_hdr;

		/* FIXME: check that packet is not a fragment !!!
		 * Might require parsing headers spanning several segments, so
		 * not implemented yet. */
		return 0;
	}

	return -1;
}

static inline void loopback_fix_checksums(odp_packet_t pkt,
					  odp_pktout_config_opt_t *pktout_cfg,
					  odp_pktout_config_opt_t *pktout_capa)
{
	odp_bool_t l3_proto_v4 = false;
	uint8_t l4_proto;
	void *l3_hdr;
	uint32_t l3_len;
	odp_bool_t ipv4_chksum_pkt, udp_chksum_pkt, tcp_chksum_pkt,
		   sctp_chksum_pkt;
	odp_packet_hdr_t *pkt_hdr = packet_hdr(pkt);

	l3_hdr = odp_packet_l3_ptr(pkt, &l3_len);

	if (l3_hdr == NULL ||
	    check_proto(l3_hdr, l3_len, &l3_proto_v4, &l4_proto))
		return;

	ipv4_chksum_pkt = OL_TX_CHKSUM_PKT(pktout_cfg->bit.ipv4_chksum,
					   pktout_capa->bit.ipv4_chksum,
					   l3_proto_v4,
					   pkt_hdr->p.flags.l3_chksum_set,
					   pkt_hdr->p.flags.l3_chksum);
	udp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.udp_chksum,
					   pktout_capa->bit.udp_chksum,
					   l4_proto == _ODP_IPPROTO_UDP,
					   pkt_hdr->p.flags.l4_chksum_set,
					   pkt_hdr->p.flags.l4_chksum);
	tcp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.tcp_chksum,
					   pktout_capa->bit.tcp_chksum,
					   l4_proto == _ODP_IPPROTO_TCP,
					   pkt_hdr->p.flags.l4_chksum_set,
					   pkt_hdr->p.flags.l4_chksum);
	sctp_chksum_pkt =  OL_TX_CHKSUM_PKT(pktout_cfg->bit.sctp_chksum,
					    pktout_capa->bit.sctp_chksum,
					    l4_proto == _ODP_IPPROTO_SCTP,
					    pkt_hdr->p.flags.l4_chksum_set,
					    pkt_hdr->p.flags.l4_chksum);

	if (ipv4_chksum_pkt)
		_odp_packet_ipv4_chksum_insert(pkt);

	if (tcp_chksum_pkt)
		_odp_packet_tcp_chksum_insert(pkt);

	if (udp_chksum_pkt)
		_odp_packet_udp_chksum_insert(pkt);

	if (sctp_chksum_pkt)
		_odp_packet_sctp_chksum_insert(pkt);
}

static inline uint8_t *add_data(uint8_t *data, void *src, uint32_t len)
{
	return (uint8_t *)memcpy(data, src, len) + len;
}

static inline odp_queue_t get_dest_queue(const pkt_loop_t *pkt_loop, odp_packet_t pkt, int index)
{
	const odp_pktin_hash_proto_t *hash = &pkt_loop->hash;
	_odp_udphdr_t udp;
	_odp_tcphdr_t tcp;
	_odp_ipv4hdr_t ipv4;
	_odp_ipv6hdr_t ipv6;
	uint32_t off;
	/* Space for UDP/TCP source and destination ports and IPv4/IPv6 source and destination
	 * addresses. */
	uint8_t data[2 * sizeof(uint16_t) + 2 * 4 * sizeof(uint32_t)];
	uint8_t *head = data;

	if (hash->all_bits == 0)
		return pkt_loop->loopqs[index % pkt_loop->num_qs].queue;

	memset(data, 0, sizeof(data));
	off = odp_packet_l4_offset(pkt);

	if (off != ODP_PACKET_OFFSET_INVALID) {
		if ((hash->proto.ipv4_udp || hash->proto.ipv6_udp) && odp_packet_has_udp(pkt)) {
			if (odp_packet_copy_to_mem(pkt, off, _ODP_UDPHDR_LEN, &udp) == 0) {
				head = add_data(head, &udp.src_port, sizeof(udp.src_port));
				head = add_data(head, &udp.dst_port, sizeof(udp.dst_port));
			}
		} else if ((hash->proto.ipv4_tcp || hash->proto.ipv6_tcp) &&
			   odp_packet_has_tcp(pkt)) {
			if (odp_packet_copy_to_mem(pkt, off, _ODP_TCPHDR_LEN, &tcp) == 0) {
				head = add_data(head, &tcp.src_port, sizeof(tcp.src_port));
				head = add_data(head, &tcp.dst_port, sizeof(tcp.dst_port));
			}
		}
	}

	off = odp_packet_l3_offset(pkt);

	if (off != ODP_PACKET_OFFSET_INVALID) {
		if (hash->proto.ipv4 && odp_packet_has_ipv4(pkt)) {
			if (odp_packet_copy_to_mem(pkt, off, _ODP_IPV4HDR_LEN, &ipv4) == 0) {
				head = add_data(head, &ipv4.src_addr, sizeof(ipv4.src_addr));
				head = add_data(head, &ipv4.dst_addr, sizeof(ipv4.dst_addr));
			}
		} else if (hash->proto.ipv6 && odp_packet_has_ipv6(pkt)) {
			if (odp_packet_copy_to_mem(pkt, off, _ODP_IPV6HDR_LEN, &ipv6) == 0) {
				head = add_data(head, &ipv6.src_addr, sizeof(ipv6.src_addr));
				head = add_data(head, &ipv6.dst_addr, sizeof(ipv6.dst_addr));
			}
		}
	}

	return pkt_loop->loopqs[odp_hash_crc32c(data, head - data, 0) % pkt_loop->num_qs].queue;
}

static int loopback_send(pktio_entry_t *pktio_entry, int index, const odp_packet_t pkt_tbl[],
			 int num)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);
	odp_queue_t queue;
	stats_t *stats;
	int i;
	int ret;
	int nb_tx = 0;
	int tx_ts_idx = 0;
	uint8_t tx_ts_enabled = _odp_pktio_tx_ts_enabled(pktio_entry);
	odp_pktout_config_opt_t *pktout_cfg = &pktio_entry->config.pktout;
	odp_pktout_config_opt_t *pktout_capa = &pktio_entry->capa.config.pktout;

	if (pkt_loop->num_qs == 0)
		return 0;

	stats =	&pkt_loop->loopqs[index].stats;

	if (odp_unlikely(num > QUEUE_MULTI_MAX))
		num = QUEUE_MULTI_MAX;

	for (i = 0; i < num; ++i) {
		uint32_t pkt_len = odp_packet_len(pkt_tbl[i]);

		if (odp_unlikely(pkt_len > pkt_loop->mtu)) {
			if (nb_tx == 0)
				return -1;
			break;
		}

		if (tx_ts_enabled && tx_ts_idx == 0) {
			if (odp_unlikely(packet_hdr(pkt_tbl[i])->p.flags.ts_set))
				tx_ts_idx = i + 1;
		}

		packet_subtype_set(pkt_tbl[i], ODP_EVENT_PACKET_BASIC);
		loopback_fix_checksums(pkt_tbl[i], pktout_cfg, pktout_capa);
		queue = get_dest_queue(pkt_loop, pkt_tbl[i], index);
		ret = odp_queue_enq(queue, odp_packet_to_event(pkt_tbl[i]));

		if (ret < 0) {
			_ODP_DBG("queue enqueue failed %i to queue: %" PRIu64 "\n", ret,
				 odp_queue_to_u64(queue));
			break;
		}

		nb_tx++;
		odp_atomic_inc_u64(&stats->out_packets);
		odp_atomic_add_u64(&stats->out_octets, pkt_len);
	}

	if (nb_tx > 0) {
		if (odp_unlikely(tx_ts_idx) && nb_tx >= tx_ts_idx)
			_odp_pktio_tx_ts_set(pktio_entry);
	}

	return nb_tx;
}

static uint32_t loopback_mtu_get(pktio_entry_t *pktio_entry)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);

	return pkt_loop->mtu;
}

static int loopback_mtu_set(pktio_entry_t *pktio_entry, uint32_t maxlen_input,
			    uint32_t maxlen_output ODP_UNUSED)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);

	pkt_loop->mtu = maxlen_input;

	return 0;
}

static int loopback_mac_addr_get(pktio_entry_t *pktio_entry, void *mac_addr)
{
	memcpy(mac_addr, pktio_loop_mac, ETH_ALEN);
	((uint8_t *)mac_addr)[ETH_ALEN - 1] += pkt_priv(pktio_entry)->idx;
	return ETH_ALEN;
}

static int loopback_link_status(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	/* loopback interfaces are always up */
	return ODP_PKTIO_LINK_STATUS_UP;
}

static int loopback_link_info(pktio_entry_t *pktio_entry ODP_UNUSED, odp_pktio_link_info_t *info)
{
	memset(info, 0, sizeof(odp_pktio_link_info_t));

	info->autoneg = ODP_PKTIO_LINK_AUTONEG_OFF;
	info->duplex = ODP_PKTIO_LINK_DUPLEX_FULL;
	info->media = "virtual";
	info->pause_rx = ODP_PKTIO_LINK_PAUSE_OFF;
	info->pause_tx = ODP_PKTIO_LINK_PAUSE_OFF;
	info->speed = ODP_PKTIO_LINK_SPEED_UNKNOWN;
	info->status = ODP_PKTIO_LINK_STATUS_UP;

	return 0;
}

static int loopback_init_capability(pktio_entry_t *pktio_entry)
{
	odp_pktio_capability_t *capa = &pktio_entry->capa;
	odp_queue_capability_t queue_capa;

	if (odp_queue_capability(&queue_capa)) {
		_ODP_ERR("Queue capability failed\n");
		return -1;
	}

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues = ODP_PKTIN_MAX_QUEUES;
	capa->max_output_queues = ODP_PKTOUT_MAX_QUEUES;
	capa->set_op.op.promisc_mode = 0;
	capa->set_op.op.maxlen = 1;

	capa->maxlen.equal = true;
	capa->maxlen.min_input = LOOP_MTU_MIN;
	capa->maxlen.max_input = LOOP_MTU_MAX;
	capa->maxlen.min_output = LOOP_MTU_MIN;
	capa->maxlen.max_output = LOOP_MTU_MAX;

	capa->min_input_queue_size = 1;
	capa->max_input_queue_size = queue_capa.plain.max_size;
	if (capa->max_input_queue_size == 0)
		capa->max_input_queue_size = LOOP_MAX_QUEUE_SIZE;

	capa->min_output_queue_size = 1;
	capa->max_output_queue_size = queue_capa.plain.max_size;
	if (capa->max_output_queue_size == 0)
		capa->max_output_queue_size = LOOP_MAX_QUEUE_SIZE;

	odp_pktio_config_init(&capa->config);
	capa->config.enable_loop = 1;
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;
	capa->config.pktin.bit.ipv4_chksum = 1;
	capa->config.pktin.bit.tcp_chksum = 1;
	capa->config.pktin.bit.udp_chksum = 1;
	capa->config.pktin.bit.sctp_chksum = 1;
	capa->config.pktout.bit.ipv4_chksum = 1;
	capa->config.pktout.bit.tcp_chksum = 1;
	capa->config.pktout.bit.udp_chksum = 1;
	capa->config.pktout.bit.sctp_chksum = 1;
	capa->config.pktout.bit.ts_ena = 1;
	capa->config.pktout.bit.tx_compl_ena = 1;
#if ODP_DEPRECATED_API
	capa->tx_compl.mode_all = 1;
#endif
	capa->tx_compl.mode_event = 1;
	capa->tx_compl.mode_poll = 1;

	if (odp_global_ro.disable.ipsec == 0) {
		capa->config.inbound_ipsec = 1;
		capa->config.outbound_ipsec = 1;
	}

	capa->config.pktout.bit.ipv4_chksum_ena =
		capa->config.pktout.bit.ipv4_chksum;
	capa->config.pktout.bit.udp_chksum_ena =
		capa->config.pktout.bit.udp_chksum;
	capa->config.pktout.bit.tcp_chksum_ena =
		capa->config.pktout.bit.tcp_chksum;
	capa->config.pktout.bit.sctp_chksum_ena =
		capa->config.pktout.bit.sctp_chksum;

	capa->stats.pktio.counter.in_octets = 1;
	capa->stats.pktio.counter.in_packets = 1;
	capa->stats.pktio.counter.in_errors = 1;
	capa->stats.pktio.counter.in_discards = 1;
	capa->stats.pktio.counter.out_octets = 1;
	capa->stats.pktio.counter.out_packets = 1;
	capa->stats.pktin_queue.counter.octets = 1;
	capa->stats.pktin_queue.counter.packets = 1;
	capa->stats.pktin_queue.counter.errors = 1;
	capa->stats.pktin_queue.counter.discards = 1;
	capa->stats.pktout_queue.counter.octets = 1;
	capa->stats.pktout_queue.counter.packets = 1;
	return 0;
}

static int loopback_capability(pktio_entry_t *pktio_entry, odp_pktio_capability_t *capa)
{
	*capa = pktio_entry->capa;
	return 0;
}

static int loopback_promisc_mode_get(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return 1;
}

static int loopback_stats(pktio_entry_t *pktio_entry, odp_pktio_stats_t *stats)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);

	memset(stats, 0, sizeof(odp_pktio_stats_t));

	for (uint32_t i = 0; i < MAX_QUEUES; i++) {
		stats_t *qs = &pkt_loop->loopqs[i].stats;

		stats->in_octets += odp_atomic_load_u64(&qs->in_octets);
		stats->in_packets += odp_atomic_load_u64(&qs->in_packets);
		stats->in_discards += odp_atomic_load_u64(&qs->in_discards);
		stats->in_errors += odp_atomic_load_u64(&qs->in_errors);
		stats->out_octets += odp_atomic_load_u64(&qs->out_octets);
		stats->out_packets += odp_atomic_load_u64(&qs->out_packets);
	}

	return 0;
}

static int loopback_stats_reset(pktio_entry_t *pktio_entry)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);

	for (uint32_t i = 0; i < MAX_QUEUES; i++) {
		stats_t *qs = &pkt_loop->loopqs[i].stats;

		odp_atomic_store_u64(&qs->in_octets, 0);
		odp_atomic_store_u64(&qs->in_packets, 0);
		odp_atomic_store_u64(&qs->in_discards, 0);
		odp_atomic_store_u64(&qs->in_errors, 0);
		odp_atomic_store_u64(&qs->out_octets, 0);
		odp_atomic_store_u64(&qs->out_packets, 0);
	}

	return 0;
}

static int loopback_pktin_stats(pktio_entry_t *pktio_entry, uint32_t index,
				odp_pktin_queue_stats_t *pktin_stats)
{
	stats_t *qs = &pkt_priv(pktio_entry)->loopqs[index].stats;

	memset(pktin_stats, 0, sizeof(odp_pktin_queue_stats_t));
	pktin_stats->octets = odp_atomic_load_u64(&qs->in_octets);
	pktin_stats->packets = odp_atomic_load_u64(&qs->in_packets);
	pktin_stats->discards = odp_atomic_load_u64(&qs->in_discards);
	pktin_stats->errors = odp_atomic_load_u64(&qs->in_errors);

	return 0;
}

static int loopback_pktout_stats(pktio_entry_t *pktio_entry, uint32_t index,
				 odp_pktout_queue_stats_t *pktout_stats)
{
	stats_t *qs = &pkt_priv(pktio_entry)->loopqs[index].stats;

	memset(pktout_stats, 0, sizeof(odp_pktout_queue_stats_t));
	pktout_stats->octets = odp_atomic_load_u64(&qs->out_octets);
	pktout_stats->packets = odp_atomic_load_u64(&qs->out_packets);

	return 0;
}

static int loop_init_global(void)
{
	_ODP_PRINT("PKTIO: initialized loop interface.\n");
	return 0;
}

const pktio_if_ops_t _odp_loopback_pktio_ops = {
	.name = "loop",
	.print = NULL,
	.init_global = loop_init_global,
	.init_local = NULL,
	.term = NULL,
	.open = loopback_open,
	.close = loopback_close,
	.start = loopback_start,
	.stop = NULL,
	.stats = loopback_stats,
	.stats_reset = loopback_stats_reset,
	.pktin_queue_stats = loopback_pktin_stats,
	.pktout_queue_stats = loopback_pktout_stats,
	.recv = loopback_recv,
	.send = loopback_send,
	.maxlen_get = loopback_mtu_get,
	.maxlen_set = loopback_mtu_set,
	.promisc_mode_set = NULL,
	.promisc_mode_get = loopback_promisc_mode_get,
	.mac_get = loopback_mac_addr_get,
	.mac_set = NULL,
	.link_status = loopback_link_status,
	.link_info = loopback_link_info,
	.capability = loopback_capability,
	.pktio_ts_res = NULL,
	.pktio_ts_from_ns = NULL,
	.pktio_time = NULL,
	.config = NULL,
	.input_queues_config = loopback_pktin_queue_config,
	.output_queues_config = loopback_pktout_queue_config,
};

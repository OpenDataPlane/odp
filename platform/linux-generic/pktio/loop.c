/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2013-2022, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/debug.h>
#include <odp/api/event.h>
#include <odp/api/hints.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/queue.h>
#include <odp/api/ticketlock.h>
#include <odp/api/time.h>

#include <odp/api/plat/byteorder_inlines.h>
#include <odp/api/plat/packet_flag_inlines.h>
#include <odp/api/plat/queue_inlines.h>

#include <odp_parse_internal.h>
#include <odp_classification_internal.h>
#include <odp_debug_internal.h>
#include <odp_errno_define.h>
#include <odp_event_internal.h>
#include <odp_global_data.h>
#include <odp_ipsec_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_macros_internal.h>
#include <odp_queue_if.h>

#include <protocols/eth.h>
#include <protocols/ip.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_LOOP 16

#define LOOP_MTU_MIN 68
#define LOOP_MTU_MAX UINT16_MAX

#define LOOP_MAX_TX_QUEUE_SIZE 1024

typedef struct {
	odp_queue_t loopq;		/**< loopback queue for "loop" device */
	uint16_t mtu;			/**< link MTU */
	uint8_t idx;			/**< index of "loop" device */
} pkt_loop_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_loop_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_loop_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_loop_t *)(uintptr_t)(pktio_entry->pkt_priv);
}

/* MAC address for the "loop" interface */
static const uint8_t pktio_loop_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x01};

static int loopback_stats_reset(pktio_entry_t *pktio_entry);
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

	pkt_loop->idx = idx;
	pkt_loop->mtu = LOOP_MTU_MAX;
	pkt_loop->loopq = ODP_QUEUE_INVALID;

	loopback_stats_reset(pktio_entry);
	loopback_init_capability(pktio_entry);

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
		ODP_ERR("Destroying loopback pktio queue failed\n");
		return -1;
	}
	return 0;
}

static int loopback_pktout_queue_config(pktio_entry_t *pktio_entry,
					const odp_pktout_queue_param_t *param)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);
	odp_queue_param_t queue_param;
	char queue_name[ODP_QUEUE_NAME_LEN];

	/* Destroy old queue */
	if (pkt_loop->loopq != ODP_QUEUE_INVALID && loopback_queue_destroy(pkt_loop->loopq))
		return -1;

	odp_queue_param_init(&queue_param);
	queue_param.size = param->queue_size[0];

	snprintf(queue_name, sizeof(queue_name), "_odp_pktio_loopq-%" PRIu64 "",
		 odp_pktio_to_u64(pktio_entry->handle));

	pkt_loop->loopq = odp_queue_create(queue_name, &queue_param);
	if (pkt_loop->loopq == ODP_QUEUE_INVALID) {
		ODP_ERR("Creating loopback pktio queue failed\n");
		return -1;
	}

	return 0;
}

static int loopback_close(pktio_entry_t *pktio_entry)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);

	if (pkt_loop->loopq != ODP_QUEUE_INVALID)
		return loopback_queue_destroy(pkt_loop->loopq);

	return 0;
}

static int loopback_recv(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			 odp_packet_t pkts[], int num)
{
	int nbr, i;
	_odp_event_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	odp_queue_t queue;
	odp_packet_hdr_t *pkt_hdr;
	odp_packet_t pkt;
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	int num_rx = 0;
	int packets = 0;
	uint32_t octets = 0;
	const odp_proto_layer_t layer = pktio_entry->parse_layer;
	const odp_pktin_config_opt_t opt = pktio_entry->config.pktin;

	if (odp_unlikely(num > QUEUE_MULTI_MAX))
		num = QUEUE_MULTI_MAX;

	odp_ticketlock_lock(&pktio_entry->rxl);

	queue = pkt_priv(pktio_entry)->loopq;
	nbr = odp_queue_deq_multi(queue, (odp_event_t *)hdr_tbl, num);

	if (opt.bit.ts_all || opt.bit.ts_ptp) {
		ts_val = odp_time_global();
		ts = &ts_val;
	}

	for (i = 0; i < nbr; i++) {
		uint32_t pkt_len;

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
				odp_atomic_inc_u64(&pktio_entry->stats_extra.in_errors);

			if (ret < 0) {
				odp_packet_free(pkt);
				continue;
			}

			if (pktio_cls_enabled(pktio_entry)) {
				odp_pool_t new_pool;

				ret = _odp_cls_classify_packet(pktio_entry, pkt_addr,
							       &new_pool, pkt_hdr);
				if (ret < 0)
					odp_atomic_inc_u64(&pktio_entry->stats_extra.in_discards);

				if (ret) {
					odp_packet_free(pkt);
					continue;
				}

				if (odp_unlikely(_odp_pktio_packet_to_pool(
					    &pkt, &pkt_hdr, new_pool))) {
					odp_packet_free(pkt);
					odp_atomic_inc_u64(&pktio_entry->stats_extra.in_discards);
					continue;
				}
			}
		}

		packet_set_ts(pkt_hdr, ts);
		pkt_hdr->input = pktio_entry->handle;

		/* Try IPsec inline processing */
		if (pktio_entry->config.inbound_ipsec &&
		    !pkt_hdr->p.flags.ip_err &&
		    odp_packet_has_ipsec(pkt))
			_odp_ipsec_try_inline(&pkt);

		if (!pkt_hdr->p.flags.all.error) {
			octets += pkt_len;
			packets++;
		}

		pkts[num_rx++] = pkt;
	}

	pktio_entry->stats.in_octets += octets;
	pktio_entry->stats.in_packets += packets;

	odp_ticketlock_unlock(&pktio_entry->rxl);

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

static int loopback_send(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			 const odp_packet_t pkt_tbl[], int num)
{
	pkt_loop_t *pkt_loop = pkt_priv(pktio_entry);
	_odp_event_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	odp_queue_t queue;
	int i;
	int ret;
	int nb_tx = 0;
	int tx_ts_idx = 0;
	uint8_t tx_ts_enabled = _odp_pktio_tx_ts_enabled(pktio_entry);
	uint32_t bytes = 0;
	uint32_t out_octets_tbl[num];
	odp_pktout_config_opt_t *pktout_cfg = &pktio_entry->config.pktout;
	odp_pktout_config_opt_t *pktout_capa =
		&pktio_entry->capa.config.pktout;

	if (odp_unlikely(num > QUEUE_MULTI_MAX))
		num = QUEUE_MULTI_MAX;

	for (i = 0; i < num; ++i) {
		uint32_t pkt_len = odp_packet_len(pkt_tbl[i]);

		if (odp_unlikely(pkt_len > pkt_loop->mtu)) {
			if (nb_tx == 0) {
				_odp_errno = EMSGSIZE;
				return -1;
			}
			break;
		}
		hdr_tbl[i] = packet_to_event_hdr(pkt_tbl[i]);
		bytes += pkt_len;
		/* Store cumulative byte counts to update 'stats.out_octets'
		 * correctly in case enq_multi() fails to enqueue all packets.
		 */
		out_octets_tbl[i] = bytes;
		nb_tx++;

		if (tx_ts_enabled && tx_ts_idx == 0) {
			if (odp_unlikely(packet_hdr(pkt_tbl[i])->p.flags.ts_set))
				tx_ts_idx = i + 1;
		}
	}

	for (i = 0; i < nb_tx; ++i) {
		packet_subtype_set(pkt_tbl[i], ODP_EVENT_PACKET_BASIC);
		loopback_fix_checksums(pkt_tbl[i], pktout_cfg, pktout_capa);
	}

	odp_ticketlock_lock(&pktio_entry->txl);

	queue = pkt_priv(pktio_entry)->loopq;
	ret = odp_queue_enq_multi(queue, (odp_event_t *)hdr_tbl, nb_tx);

	if (ret > 0) {
		if (odp_unlikely(tx_ts_idx) && ret >= tx_ts_idx)
			_odp_pktio_tx_ts_set(pktio_entry);

		pktio_entry->stats.out_packets += ret;
		pktio_entry->stats.out_octets += out_octets_tbl[ret - 1];
	} else {
		ODP_DBG("queue enqueue failed %i\n", ret);
		ret = -1;
	}

	odp_ticketlock_unlock(&pktio_entry->txl);

	return ret;
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
		ODP_ERR("Queue capability failed\n");
		return -1;
	}

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues  = 1;
	capa->max_output_queues = 1;
	capa->set_op.op.promisc_mode = 0;
	capa->set_op.op.maxlen = 1;

	capa->maxlen.equal = true;
	capa->maxlen.min_input = LOOP_MTU_MIN;
	capa->maxlen.max_input = LOOP_MTU_MAX;
	capa->maxlen.min_output = LOOP_MTU_MIN;
	capa->maxlen.max_output = LOOP_MTU_MAX;

	capa->min_output_queue_size = 1;
	capa->max_output_queue_size = queue_capa.plain.max_size;
	if (capa->max_output_queue_size == 0)
		capa->max_output_queue_size = LOOP_MAX_TX_QUEUE_SIZE;

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

static int loopback_stats(pktio_entry_t *pktio_entry,
			  odp_pktio_stats_t *stats)
{
	memcpy(stats, &pktio_entry->stats, sizeof(odp_pktio_stats_t));
	return 0;
}

static int loopback_stats_reset(pktio_entry_t *pktio_entry)
{
	memset(&pktio_entry->stats, 0, sizeof(odp_pktio_stats_t));
	return 0;
}

static int loopback_pktin_stats(pktio_entry_t *pktio_entry,
				uint32_t index ODP_UNUSED,
				odp_pktin_queue_stats_t *pktin_stats)
{
	memset(pktin_stats, 0, sizeof(odp_pktin_queue_stats_t));
	pktin_stats->octets = pktio_entry->stats.in_octets;
	pktin_stats->packets = pktio_entry->stats.in_packets;
	pktin_stats->errors = pktio_entry->stats.in_errors;
	return 0;
}

static int loopback_pktout_stats(pktio_entry_t *pktio_entry,
				 uint32_t index ODP_UNUSED,
				 odp_pktout_queue_stats_t *pktout_stats)
{
	memset(pktout_stats, 0, sizeof(odp_pktout_queue_stats_t));
	pktout_stats->octets = pktio_entry->stats.out_octets;
	pktout_stats->packets = pktio_entry->stats.out_packets;
	return 0;
}

static int loop_init_global(void)
{
	ODP_PRINT("PKTIO: initialized loop interface.\n");
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
	.start = NULL,
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
	.input_queues_config = NULL,
	.output_queues_config = loopback_pktout_queue_config,
};

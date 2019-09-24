/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2013, Nokia Solutions and Networks
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_internal.h>
#include <odp_ipsec_internal.h>
#include <odp_debug_internal.h>
#include <odp_errno_define.h>
#include <odp/api/plat/packet_flag_inlines.h>
#include <odp/api/hints.h>
#include <odp/api/plat/byteorder_inlines.h>
#include <odp_queue_if.h>
#include <odp/api/plat/queue_inlines.h>

#include <protocols/eth.h>
#include <protocols/ip.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>

#define MAX_LOOP 16
#define LOOP_MTU (64 * 1024)

typedef struct {
	odp_queue_t loopq;		/**< loopback queue for "loop" device */
	odp_bool_t promisc;		/**< promiscuous mode state */
	uint8_t idx;			/**< index of "loop" device */
} pkt_loop_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_loop_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_loop_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_loop_t *)(uintptr_t)(pktio_entry->s.pkt_priv);
}

/* MAC address for the "loop" interface */
static const char pktio_loop_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x01};

static int loopback_stats_reset(pktio_entry_t *pktio_entry);
static int loopback_init_capability(pktio_entry_t *pktio_entry);

static int loopback_open(odp_pktio_t id, pktio_entry_t *pktio_entry,
			 const char *devname, odp_pool_t pool ODP_UNUSED)
{
	long idx;
	char loopq_name[ODP_QUEUE_NAME_LEN];

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

	snprintf(loopq_name, sizeof(loopq_name), "%" PRIu64 "-pktio_loopq",
		 odp_pktio_to_u64(id));
	pkt_priv(pktio_entry)->loopq =
		odp_queue_create(loopq_name, NULL);
	pkt_priv(pktio_entry)->idx = idx;

	if (pkt_priv(pktio_entry)->loopq == ODP_QUEUE_INVALID)
		return -1;

	loopback_stats_reset(pktio_entry);
	loopback_init_capability(pktio_entry);

	return 0;
}

static int loopback_close(pktio_entry_t *pktio_entry)
{
	return odp_queue_destroy(pkt_priv(pktio_entry)->loopq);
}

static int loopback_recv(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			 odp_packet_t pkts[], int num)
{
	int nbr, i;
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	odp_queue_t queue;
	odp_packet_hdr_t *pkt_hdr;
	odp_packet_t pkt;
	odp_time_t ts_val;
	odp_time_t *ts = NULL;
	int num_rx = 0;
	int failed = 0;

	if (odp_unlikely(num > QUEUE_MULTI_MAX))
		num = QUEUE_MULTI_MAX;

	odp_ticketlock_lock(&pktio_entry->s.rxl);

	queue = pkt_priv(pktio_entry)->loopq;
	nbr = odp_queue_deq_multi(queue, (odp_event_t *)hdr_tbl, num);

	if (pktio_entry->s.config.pktin.bit.ts_all ||
	    pktio_entry->s.config.pktin.bit.ts_ptp) {
		ts_val = odp_time_global();
		ts = &ts_val;
	}

	for (i = 0; i < nbr; i++) {
		uint32_t pkt_len;

		pkt = packet_from_buf_hdr(hdr_tbl[i]);
		pkt_len = odp_packet_len(pkt);
		pkt_hdr = packet_hdr(pkt);

		packet_parse_reset(pkt_hdr);
		if (pktio_cls_enabled(pktio_entry)) {
			odp_packet_t new_pkt;
			odp_pool_t new_pool;
			uint8_t *pkt_addr;
			uint8_t buf[PACKET_PARSE_SEG_LEN];
			int ret;
			uint32_t seg_len = odp_packet_seg_len(pkt);

			/* Make sure there is enough data for the packet
			 * parser in the case of a segmented packet. */
			if (odp_unlikely(seg_len < PACKET_PARSE_SEG_LEN &&
					 pkt_len > PACKET_PARSE_SEG_LEN)) {
				odp_packet_copy_to_mem(pkt, 0,
						       PACKET_PARSE_SEG_LEN,
						       buf);
				seg_len = PACKET_PARSE_SEG_LEN;
				pkt_addr = buf;
			} else {
				pkt_addr = odp_packet_data(pkt);
			}

			ret = cls_classify_packet(pktio_entry, pkt_addr,
						  pkt_len, seg_len,
						  &new_pool, pkt_hdr, true);
			if (ret) {
				failed++;
				odp_packet_free(pkt);
				continue;
			}

			if (new_pool != odp_packet_pool(pkt)) {
				new_pkt = odp_packet_copy(pkt, new_pool);

				odp_packet_free(pkt);

				if (new_pkt == ODP_PACKET_INVALID) {
					failed++;
					continue;
				}
				pkt = new_pkt;
			}
		} else {
			packet_parse_layer(pkt_hdr,
					   pktio_entry->s.config.parser.layer,
					   pktio_entry->s.in_chksums);
		}

		packet_set_ts(pkt_hdr, ts);
		pkt_hdr->input = pktio_entry->s.handle;

		/* Try IPsec inline processing */
		if (pktio_entry->s.config.inbound_ipsec &&
		    !pkt_hdr->p.flags.ip_err &&
		    odp_packet_has_ipsec(pkt))
			_odp_ipsec_try_inline(&pkt);

		pktio_entry->s.stats.in_octets += pkt_len;
		pkts[num_rx++] = pkt;
	}

	pktio_entry->s.stats.in_errors += failed;
	pktio_entry->s.stats.in_ucast_pkts += num_rx - failed;

	odp_ticketlock_unlock(&pktio_entry->s.rxl);

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
	odp_buffer_hdr_t *hdr_tbl[QUEUE_MULTI_MAX];
	odp_queue_t queue;
	int i;
	int ret;
	int nb_tx = 0;
	uint32_t bytes = 0;
	uint32_t out_octets_tbl[num];
	odp_pktout_config_opt_t *pktout_cfg = &pktio_entry->s.config.pktout;
	odp_pktout_config_opt_t *pktout_capa =
		&pktio_entry->s.capa.config.pktout;

	if (odp_unlikely(num > QUEUE_MULTI_MAX))
		num = QUEUE_MULTI_MAX;

	for (i = 0; i < num; ++i) {
		uint32_t pkt_len = odp_packet_len(pkt_tbl[i]);

		if (pkt_len > LOOP_MTU) {
			if (nb_tx == 0) {
				__odp_errno = EMSGSIZE;
				return -1;
			}
			break;
		}
		hdr_tbl[i] = packet_to_buf_hdr(pkt_tbl[i]);
		bytes += pkt_len;
		/* Store cumulative byte counts to update 'stats.out_octets'
		 * correctly in case enq_multi() fails to enqueue all packets.
		 */
		out_octets_tbl[i] = bytes;
		nb_tx++;
	}

	for (i = 0; i < nb_tx; ++i) {
		odp_ipsec_packet_result_t result;

		if (odp_packet_subtype(pkt_tbl[i]) ==
				ODP_EVENT_PACKET_IPSEC &&
		    pktio_entry->s.config.outbound_ipsec) {

			/* Possibly postprocessing packet */
			odp_ipsec_result(&result, pkt_tbl[i]);
		}
		packet_subtype_set(pkt_tbl[i], ODP_EVENT_PACKET_BASIC);
	}

	for (i = 0; i < nb_tx; ++i)
		loopback_fix_checksums(pkt_tbl[i], pktout_cfg, pktout_capa);

	odp_ticketlock_lock(&pktio_entry->s.txl);

	queue = pkt_priv(pktio_entry)->loopq;
	ret = odp_queue_enq_multi(queue, (odp_event_t *)hdr_tbl, nb_tx);

	if (ret > 0) {
		pktio_entry->s.stats.out_ucast_pkts += ret;
		pktio_entry->s.stats.out_octets += out_octets_tbl[ret - 1];
	} else {
		ODP_DBG("queue enqueue failed %i\n", ret);
		ret = -1;
	}

	odp_ticketlock_unlock(&pktio_entry->s.txl);

	return ret;
}

static uint32_t loopback_mtu_get(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return LOOP_MTU;
}

static int loopback_mac_addr_get(pktio_entry_t *pktio_entry ODP_UNUSED,
				 void *mac_addr)
{
	memcpy(mac_addr, pktio_loop_mac, ETH_ALEN);
	((uint8_t *)mac_addr)[ETH_ALEN - 1] += pkt_priv(pktio_entry)->idx;
	return ETH_ALEN;
}

static int loopback_link_status(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	/* loopback interfaces are always up */
	return 1;
}

static int loopback_init_capability(pktio_entry_t *pktio_entry)
{
	odp_pktio_capability_t *capa = &pktio_entry->s.capa;

	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues  = 1;
	capa->max_output_queues = 1;
	capa->set_op.op.promisc_mode = 1;

	odp_pktio_config_init(&capa->config);
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
	capa->config.inbound_ipsec = 1;
	capa->config.outbound_ipsec = 1;

	capa->config.pktout.bit.ipv4_chksum_ena =
		capa->config.pktout.bit.ipv4_chksum;
	capa->config.pktout.bit.udp_chksum_ena =
		capa->config.pktout.bit.udp_chksum;
	capa->config.pktout.bit.tcp_chksum_ena =
		capa->config.pktout.bit.tcp_chksum;
	capa->config.pktout.bit.sctp_chksum_ena =
		capa->config.pktout.bit.sctp_chksum;

	return 0;
}

static int loopback_capability(pktio_entry_t *pktio_entry ODP_UNUSED,
			       odp_pktio_capability_t *capa)
{
	*capa = pktio_entry->s.capa;
	return 0;
}

static int loopback_promisc_mode_set(pktio_entry_t *pktio_entry,
				     odp_bool_t enable)
{
	pkt_priv(pktio_entry)->promisc = enable;
	return 0;
}

static int loopback_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return pkt_priv(pktio_entry)->promisc ? 1 : 0;
}

static int loopback_stats(pktio_entry_t *pktio_entry,
			  odp_pktio_stats_t *stats)
{
	memcpy(stats, &pktio_entry->s.stats, sizeof(odp_pktio_stats_t));
	return 0;
}

static int loopback_stats_reset(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	memset(&pktio_entry->s.stats, 0, sizeof(odp_pktio_stats_t));
	return 0;
}

static int loop_init_global(void)
{
	ODP_PRINT("PKTIO: initialized loop interface.\n");
	return 0;
}

const pktio_if_ops_t loopback_pktio_ops = {
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
	.recv = loopback_recv,
	.send = loopback_send,
	.mtu_get = loopback_mtu_get,
	.promisc_mode_set = loopback_promisc_mode_set,
	.promisc_mode_get = loopback_promisc_mode_get,
	.mac_get = loopback_mac_addr_get,
	.mac_set = NULL,
	.link_status = loopback_link_status,
	.capability = loopback_capability,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL,
};

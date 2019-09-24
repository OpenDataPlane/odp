/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * PCAP pktio type
 *
 * This file provides a pktio interface that allows for reading from
 * and writing to pcap capture files. It is intended to be used as
 * simple way of injecting test packets into an application for the
 * purpose of functional testing.
 *
 * To use this interface the name passed to odp_pktio_open() must begin
 * with "pcap:" and be in the format;
 *
 * pcap:in=test.pcap:out=test_out.pcap:loops=10
 *
 *   in      the name of the input pcap file. If no input file is given
 *           attempts to receive from the pktio will just return no
 *           packets. If an input file is specified it must exist and be
 *           a readable pcap file with a link type of DLT_EN10MB.
 *   out     the name of the output pcap file. If no output file is
 *           given any packets transmitted over the interface will just
 *           be freed. If an output file is specified and the file
 *           doesn't exist it will be created, if it does exist it will
 *           be overwritten.
 *   loops   the number of times to iterate through the input file, set
 *           to 0 to loop indefinitely. The default value is 1.
 *
 * The total length of the string is limited by PKTIO_NAME_LEN.
 */

#include <odp_posix_extensions.h>

#include <odp_api.h>
#include <odp/api/plat/packet_inlines.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>

#include <protocols/eth.h>

#include <errno.h>
#include <pcap/pcap.h>
#include <pcap/bpf.h>

typedef struct {
	char *fname_rx;		/**< name of pcap file for rx */
	char *fname_tx;		/**< name of pcap file for tx */
	void *rx;		/**< rx pcap handle */
	void *tx;		/**< tx pcap handle */
	void *tx_dump;		/**< tx pcap dumper handle */
	odp_pool_t pool;	/**< rx pool */
	int loops;		/**< number of times to loop rx pcap */
	int loop_cnt;		/**< number of loops completed */
	odp_bool_t promisc;	/**< promiscuous mode state */
} pkt_pcap_t;

ODP_STATIC_ASSERT(PKTIO_PRIVATE_SIZE >= sizeof(pkt_pcap_t),
		  "PKTIO_PRIVATE_SIZE too small");

static inline pkt_pcap_t *pkt_priv(pktio_entry_t *pktio_entry)
{
	return (pkt_pcap_t *)(uintptr_t)(pktio_entry->s.pkt_priv);
}

#define PKTIO_PCAP_MTU (64 * 1024)
static const char pcap_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x04};

static int pcapif_stats_reset(pktio_entry_t *pktio_entry);

static int _pcapif_parse_devname(pkt_pcap_t *pcap, const char *devname)
{
	char *tok;
	char in[PKTIO_NAME_LEN];

	if (strncmp(devname, "pcap:", 5) != 0)
		return -1;

	snprintf(in, sizeof(in), "%s", devname);

	for (tok = strtok(in + 5, ":"); tok; tok = strtok(NULL, ":")) {
		if (strncmp(tok, "in=", 3) == 0 && !pcap->fname_rx) {
			tok += 3;
			pcap->fname_rx = strdup(tok);
		} else if (strncmp(tok, "out=", 4) == 0 && !pcap->fname_tx) {
			tok += 4;
			pcap->fname_tx = strdup(tok);
		} else if (strncmp(tok, "loops=", 6) == 0) {
			pcap->loops = atoi(tok + 6);
			if (pcap->loops < 0) {
				ODP_ERR("invalid loop count\n");
				return -1;
			}
		}
	}

	return 0;
}

static int _pcapif_init_rx(pkt_pcap_t *pcap)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int linktype;

	pcap->rx = pcap_open_offline(pcap->fname_rx, errbuf);
	if (!pcap->rx) {
		ODP_ERR("failed to open pcap file %s (%s)\n",
			pcap->fname_rx, errbuf);
		return -1;
	}

	linktype = pcap_datalink(pcap->rx);
	if (linktype != DLT_EN10MB) {
		ODP_ERR("unsupported datalink type: %d\n", linktype);
		return -1;
	}

	return 0;
}

static int _pcapif_init_tx(pkt_pcap_t *pcap)
{
	pcap_t *tx = pcap->rx;

	if (!tx) {
		/* if there is no rx pcap_t already open for rx, a dummy
		 * one needs to be opened for writing the dump */
		tx = pcap_open_dead(DLT_EN10MB, PKTIO_PCAP_MTU);
		if (!tx) {
			ODP_ERR("failed to open TX dump\n");
			return -1;
		}

		pcap->tx = tx;
	}

	pcap->tx_dump = pcap_dump_open(tx, pcap->fname_tx);
	if (!pcap->tx_dump) {
		ODP_ERR("failed to open dump file %s (%s)\n",
			pcap->fname_tx, pcap_geterr(tx));
		return -1;
	}

	return pcap_dump_flush(pcap->tx_dump);
}

static int pcapif_init(odp_pktio_t id ODP_UNUSED, pktio_entry_t *pktio_entry,
		       const char *devname, odp_pool_t pool)
{
	pkt_pcap_t *pcap = pkt_priv(pktio_entry);
	int ret;

	memset(pcap, 0, sizeof(pkt_pcap_t));
	pcap->loop_cnt = 1;
	pcap->loops = 1;
	pcap->pool = pool;
	pcap->promisc = 1;

	ret = _pcapif_parse_devname(pcap, devname);

	if (ret == 0 && pcap->fname_rx)
		ret = _pcapif_init_rx(pcap);

	if (ret == 0 && pcap->fname_tx)
		ret = _pcapif_init_tx(pcap);

	if (ret == 0 && (!pcap->rx && !pcap->tx_dump))
		ret = -1;

	(void)pcapif_stats_reset(pktio_entry);

	return ret;
}

static int pcapif_close(pktio_entry_t *pktio_entry)
{
	pkt_pcap_t *pcap = pkt_priv(pktio_entry);

	if (pcap->tx_dump)
		pcap_dump_close(pcap->tx_dump);

	if (pcap->tx)
		pcap_close(pcap->tx);

	if (pcap->rx)
		pcap_close(pcap->rx);

	free(pcap->fname_rx);
	free(pcap->fname_tx);

	return 0;
}

static int _pcapif_reopen(pkt_pcap_t *pcap)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap->loops != 0 && ++pcap->loop_cnt >= pcap->loops)
		return 1;

	if (pcap->rx)
		pcap_close(pcap->rx);

	pcap->rx = pcap_open_offline(pcap->fname_rx, errbuf);
	if (!pcap->rx) {
		ODP_ERR("failed to reopen pcap file %s (%s)\n",
			pcap->fname_rx, errbuf);
		return 1;
	}

	return 0;
}

static int pcapif_recv_pkt(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			   odp_packet_t pkts[], int num)
{
	int i;
	struct pcap_pkthdr *hdr;
	const u_char *data;
	odp_packet_t pkt;
	odp_packet_hdr_t *pkt_hdr;
	uint32_t pkt_len;
	pkt_pcap_t *pcap = pkt_priv(pktio_entry);
	odp_time_t ts_val;
	odp_time_t *ts = NULL;

	odp_ticketlock_lock(&pktio_entry->s.rxl);

	if (pktio_entry->s.state != PKTIO_STATE_STARTED || !pcap->rx) {
		odp_ticketlock_unlock(&pktio_entry->s.rxl);
		return 0;
	}
	if (pktio_entry->s.config.pktin.bit.ts_all ||
	    pktio_entry->s.config.pktin.bit.ts_ptp)
		ts = &ts_val;

	for (i = 0; i < num; ) {
		int ret;

		ret = pcap_next_ex(pcap->rx, &hdr, &data);

		/* end of file, attempt to reopen if within loop limit */
		if (ret == -2 && _pcapif_reopen(pcap) == 0)
			continue;

		if (ret != 1)
			break;

		pkt_len = hdr->caplen;

		ret = packet_alloc_multi(pcap->pool, pkt_len, &pkt, 1);
		if (odp_unlikely(ret != 1))
			break;

		if (ts != NULL)
			ts_val = odp_time_global();

		pkt_hdr = packet_hdr(pkt);

		if (odp_packet_copy_from_mem(pkt, 0, hdr->caplen, data) != 0) {
			ODP_ERR("failed to copy packet data\n");
			break;
		}

		packet_parse_layer(pkt_hdr,
				   pktio_entry->s.config.parser.layer,
				   pktio_entry->s.in_chksums);
		pktio_entry->s.stats.in_octets += pkt_hdr->frame_len;

		packet_set_ts(pkt_hdr, ts);
		pkt_hdr->input = pktio_entry->s.handle;

		pkts[i] = pkt;

		i++;
	}
	pktio_entry->s.stats.in_ucast_pkts += i;

	odp_ticketlock_unlock(&pktio_entry->s.rxl);

	return i;
}

static int _pcapif_dump_pkt(pkt_pcap_t *pcap, odp_packet_t pkt)
{
	struct pcap_pkthdr hdr;
	uint8_t tx_buf[PKTIO_PCAP_MTU];

	if (!pcap->tx_dump)
		return 0;

	hdr.caplen = odp_packet_len(pkt);
	hdr.len = hdr.caplen;
	(void)gettimeofday(&hdr.ts, NULL);

	if (odp_packet_copy_to_mem(pkt, 0, hdr.len, tx_buf) != 0)
		return -1;

	pcap_dump(pcap->tx_dump, &hdr, tx_buf);
	(void)pcap_dump_flush(pcap->tx_dump);

	return 0;
}

static int pcapif_send_pkt(pktio_entry_t *pktio_entry, int index ODP_UNUSED,
			   const odp_packet_t pkts[], int num)
{
	pkt_pcap_t *pcap = pkt_priv(pktio_entry);
	int i;

	odp_ticketlock_lock(&pktio_entry->s.txl);

	if (pktio_entry->s.state != PKTIO_STATE_STARTED) {
		odp_ticketlock_unlock(&pktio_entry->s.txl);
		return 0;
	}

	for (i = 0; i < num; ++i) {
		int pkt_len = odp_packet_len(pkts[i]);

		if (pkt_len > PKTIO_PCAP_MTU) {
			if (i == 0) {
				odp_ticketlock_unlock(&pktio_entry->s.txl);
				return -1;
			}
			break;
		}

		if (_pcapif_dump_pkt(pcap, pkts[i]) != 0)
			break;

		pktio_entry->s.stats.out_octets += pkt_len;
		odp_packet_free(pkts[i]);
	}

	pktio_entry->s.stats.out_ucast_pkts += i;

	odp_ticketlock_unlock(&pktio_entry->s.txl);

	return i;
}

static uint32_t pcapif_mtu_get(pktio_entry_t *pktio_entry ODP_UNUSED)
{
	return PKTIO_PCAP_MTU;
}

static int pcapif_mac_addr_get(pktio_entry_t *pktio_entry ODP_UNUSED,
			       void *mac_addr)
{
	memcpy(mac_addr, pcap_mac, _ODP_ETHADDR_LEN);

	return _ODP_ETHADDR_LEN;
}

static int pcapif_capability(pktio_entry_t *pktio_entry ODP_UNUSED,
			     odp_pktio_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_pktio_capability_t));

	capa->max_input_queues  = 1;
	capa->max_output_queues = 1;
	capa->set_op.op.promisc_mode = 1;

	odp_pktio_config_init(&capa->config);
	capa->config.pktin.bit.ts_all = 1;
	capa->config.pktin.bit.ts_ptp = 1;
	return 0;
}

static int pcapif_promisc_mode_set(pktio_entry_t *pktio_entry,
				   odp_bool_t enable)
{
	char filter_exp[64] = {0};
	struct bpf_program bpf;
	pkt_pcap_t *pcap = pkt_priv(pktio_entry);

	if (!pcap->rx) {
		pcap->promisc = enable;
		return 0;
	}

	if (!enable) {
		char mac_str[18];

		snprintf(mac_str, sizeof(mac_str),
			 "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			 pcap_mac[0], pcap_mac[1], pcap_mac[2],
			 pcap_mac[3], pcap_mac[4], pcap_mac[5]);

		snprintf(filter_exp, sizeof(filter_exp),
			 "ether dst %s or broadcast or multicast",
			 mac_str);
	}

	if (pcap_compile(pcap->rx, &bpf, filter_exp,
			 0, PCAP_NETMASK_UNKNOWN) != 0) {
		ODP_ERR("failed to compile promisc mode filter: %s\n",
			pcap_geterr(pcap->rx));
		return -1;
	}

	if (pcap_setfilter(pcap->rx, &bpf) != 0) {
		ODP_ERR("failed to set promisc mode filter: %s\n",
			pcap_geterr(pcap->rx));
		return -1;
	}

	pcap->promisc = enable;

	return 0;
}

static int pcapif_promisc_mode_get(pktio_entry_t *pktio_entry)
{
	return pkt_priv(pktio_entry)->promisc;
}

static int pcapif_stats_reset(pktio_entry_t *pktio_entry)
{
	memset(&pktio_entry->s.stats, 0, sizeof(odp_pktio_stats_t));
	return 0;
}

static int pcapif_stats(pktio_entry_t *pktio_entry,
			odp_pktio_stats_t *stats)
{
	memcpy(stats, &pktio_entry->s.stats, sizeof(odp_pktio_stats_t));
	return 0;
}

static int pcapif_init_global(void)
{
	ODP_PRINT("PKTIO: initialized pcap interface.\n");
	return 0;
}

const pktio_if_ops_t pcap_pktio_ops = {
	.name = "pcap",
	.print = NULL,
	.init_global = pcapif_init_global,
	.init_local = NULL,
	.open = pcapif_init,
	.close = pcapif_close,
	.stats = pcapif_stats,
	.stats_reset = pcapif_stats_reset,
	.recv = pcapif_recv_pkt,
	.send = pcapif_send_pkt,
	.mtu_get = pcapif_mtu_get,
	.promisc_mode_set = pcapif_promisc_mode_set,
	.promisc_mode_get = pcapif_promisc_mode_get,
	.mac_get = pcapif_mac_addr_get,
	.mac_set = NULL,
	.capability = pcapif_capability,
	.pktin_ts_res = NULL,
	.pktin_ts_from_ns = NULL,
	.config = NULL,
	.input_queues_config = NULL,
	.output_queues_config = NULL,
};

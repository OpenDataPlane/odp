/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 * Copyright (c) 2020-2024 Nokia
 */

#include "odp_classification_testsuites.h"
#include "classification.h"
#include <odp_cunit_common.h>
#include <odp/helper/odph_api.h>

typedef struct cls_test_packet {
	odp_u32be_t magic;
	odp_u32be_t seq;
} cls_test_packet_t;

static uint8_t IPV6_SRC_ADDR[ODPH_IPV6ADDR_LEN] = {
	/* I.e. ::ffff:10.0.0.1 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 0, 0, 1
};

static uint8_t IPV6_DST_ADDR[ODPH_IPV6ADDR_LEN] = {
	/* I.e. ::ffff:10.0.0.100 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 10, 0, 0, 100
};

#define ODP_GTPU_UDP_PORT 2152
#define AH_HDR_LEN 24

odp_pktio_t create_pktio(odp_queue_type_t q_type, odp_pool_t pool,
			 odp_bool_t cls_enable)
{
	odp_pktio_t pktio;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	int ret;

	if (pool == ODP_POOL_INVALID)
		return ODP_PKTIO_INVALID;

	odp_pktio_param_init(&pktio_param);
	if (q_type == ODP_QUEUE_TYPE_PLAIN)
		pktio_param.in_mode = ODP_PKTIN_MODE_QUEUE;
	else
		pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open("loop", pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		ret = odp_pool_destroy(pool);
		if (ret)
			ODPH_ERR("Unable to destroy pool\n");
		return ODP_PKTIO_INVALID;
	}

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
	pktin_param.classifier_enable = cls_enable;
	pktin_param.hash_enable = false;

	if (odp_pktin_queue_config(pktio, &pktin_param)) {
		ODPH_ERR("Pktin queue config failed\n");
		return ODP_PKTIO_INVALID;
	}

	if (odp_pktout_queue_config(pktio, NULL)) {
		ODPH_ERR("Pktout queue config failed\n");
		return ODP_PKTIO_INVALID;
	}

	return pktio;
}

int stop_pktio(odp_pktio_t pktio)
{
	odp_event_t ev;

	if (odp_pktio_stop(pktio)) {
		ODPH_ERR("Pktio stop failed\n");
		return -1;
	}

	while (1) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);

		if (ev != ODP_EVENT_INVALID)
			odp_event_free(ev);
		else
			break;
	}

	return 0;
}

static uint32_t seqno_offset(odp_packet_t pkt)
{
	uint32_t l3_offset = odp_packet_l3_offset(pkt);
	int rc;
	uint16_t len = 0;

	CU_ASSERT_FATAL(l3_offset != ODP_PACKET_OFFSET_INVALID);

	if (odp_packet_has_ipv4(pkt)) {
		odph_ipv4hdr_t ip;

		rc = odp_packet_copy_to_mem(pkt, l3_offset, sizeof(ip), &ip);
		CU_ASSERT_FATAL(rc == 0);
		len = odp_be_to_cpu_16(ip.tot_len);
	} else if (odp_packet_has_ipv6(pkt)) {
		odph_ipv6hdr_t ip;

		rc = odp_packet_copy_to_mem(pkt, l3_offset, sizeof(ip), &ip);
		CU_ASSERT_FATAL(rc == 0);
		len = sizeof(ip) + odp_be_to_cpu_16(ip.payload_len);
	} else {
		CU_FAIL_FATAL("Unexpected packet type");
	}

	return l3_offset + len - sizeof(cls_test_packet_t);
}

int cls_pkt_set_seq(odp_packet_t pkt)
{
	cls_test_packet_t data;
	static uint32_t seq;
	uint32_t offset;
	int status;

	data.magic = DATA_MAGIC;
	data.seq = ++seq;

	offset = seqno_offset(pkt);

	status = odp_packet_copy_from_mem(pkt, offset, sizeof(data), &data);

	return status;
}

uint32_t cls_pkt_get_seq(odp_packet_t pkt)
{
	cls_test_packet_t data;
	uint32_t offset;
	int rc;

	offset = seqno_offset(pkt);

	rc = odp_packet_copy_to_mem(pkt, offset, sizeof(data), &data);
	CU_ASSERT_FATAL(rc == 0);

	if (data.magic == DATA_MAGIC)
		return data.seq;

	return TEST_SEQ_INVALID;
}

int parse_ipv4_string(const char *ipaddress, uint32_t *addr, uint32_t *mask)
{
	int b[4];
	int qualifier = 32;
	int converted;

	if (strchr(ipaddress, '/')) {
		converted = sscanf(ipaddress, "%d.%d.%d.%d/%d",
				   &b[3], &b[2], &b[1], &b[0],
				   &qualifier);
		if (5 != converted)
			return -1;
	} else {
		converted = sscanf(ipaddress, "%d.%d.%d.%d",
				   &b[3], &b[2], &b[1], &b[0]);
		if (4 != converted)
			return -1;
	}

	if ((b[0] > 255) || (b[1] > 255) || (b[2] > 255) || (b[3] > 255))
		return -1;
	if (!qualifier || (qualifier > 32))
		return -1;

	*addr = b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
	if (mask)
		*mask = ~(0xFFFFFFFF & ((1ULL << (32 - qualifier)) - 1));

	return 0;
}

void enqueue_pktio_interface(odp_packet_t pkt, odp_pktio_t pktio)
{
	odp_pktout_queue_t pktout;
	int ret;

	ret = odp_pktout_queue(pktio, &pktout, 1);

	if (ret != 1) {
		CU_FAIL_FATAL("No pktout queue");
		return;
	}

	CU_ASSERT(odp_pktout_send(pktout, &pkt, 1) == 1);
}

odp_packet_t receive_packet(odp_queue_t *queue, uint64_t ns, odp_bool_t enable_pktv)
{
	odp_event_t ev;
	uint64_t wait = odp_schedule_wait_time(ns);

	ev = odp_schedule(queue, wait);
	if (ev == ODP_EVENT_INVALID)
		return ODP_PACKET_INVALID;

	if (odp_event_type(ev) == ODP_EVENT_PACKET) {
		return odp_packet_from_event(ev);
	} else if (enable_pktv && odp_event_type(ev) == ODP_EVENT_PACKET_VECTOR) {
		odp_packet_vector_t pktv;
		odp_packet_t *pkt_tbl;
		odp_packet_t pkt;
		uint32_t pktv_len;

		pktv = odp_packet_vector_from_event(ev);
		pktv_len = odp_packet_vector_tbl(pktv, &pkt_tbl);

		CU_ASSERT_FATAL(pktv_len > 0);

		pkt = pkt_tbl[0];
		if (pktv_len > 1)
			odp_packet_free_multi(&pkt_tbl[1], pktv_len - 1);
		odp_packet_vector_free(pktv);
		return pkt;
	}

	odp_event_free(ev);
	return ODP_PACKET_INVALID;

}

odp_queue_t queue_create(const char *queuename, bool sched)
{
	odp_queue_t queue;
	odp_queue_param_t qparam;

	if (sched) {
		odp_queue_param_init(&qparam);
		qparam.type       = ODP_QUEUE_TYPE_SCHED;
		qparam.sched.prio = odp_schedule_max_prio();
		qparam.sched.sync = ODP_SCHED_SYNC_PARALLEL;
		qparam.sched.group = ODP_SCHED_GROUP_ALL;

		queue = odp_queue_create(queuename, &qparam);
	} else {
		queue = odp_queue_create(queuename, NULL);
	}

	return queue;
}

odp_pool_t pool_create(const char *poolname)
{
	odp_pool_param_t param;

	odp_pool_param_init(&param);
	param.pkt.seg_len = SHM_PKT_BUF_SIZE;
	param.pkt.len     = SHM_PKT_BUF_SIZE;
	param.pkt.num     = SHM_PKT_NUM_BUFS;
	param.type        = ODP_POOL_PACKET;

	return odp_pool_create(poolname, &param);
}

odp_pool_t pktv_pool_create(const char *poolname)
{
	odp_pool_capability_t capa;
	odp_pool_param_t param;

	if (odp_pool_capability(&capa)) {
		ODPH_ERR("Pool capability failed\n");
		return ODP_POOL_INVALID;
	}

	if (capa.vector.max_pools == 0) {
		ODPH_ERR("No packet vector pools available\n");
		return ODP_POOL_INVALID;
	}

	if (capa.vector.max_num && capa.vector.max_num < SHM_PKT_NUM_BUFS) {
		ODPH_ERR("Unable to create large enough (%d) packet vector pool\n",
			 SHM_PKT_NUM_BUFS);
		return ODP_POOL_INVALID;
	}

	odp_pool_param_init(&param);
	param.type = ODP_POOL_VECTOR;
	param.vector.num = SHM_PKT_NUM_BUFS;
	param.vector.max_size = capa.vector.max_size;

	return odp_pool_create(poolname, &param);
}

odp_packet_t create_packet(cls_packet_info_t pkt_info)
{
	uint32_t seqno;
	odph_ethhdr_t *ethhdr;
	odph_udphdr_t *udp;
	odph_tcphdr_t *tcp;
	odph_sctphdr_t *sctp;
	odph_icmphdr_t *icmp;
	odph_ipv4hdr_t *ip;
	odph_ipv6hdr_t *ipv6;
	odph_gtphdr_t *gtpu;
	odph_igmphdr_t *igmp;
	odph_ahhdr_t *ah;
	odph_esphdr_t *esp;
	uint8_t *hlen = 0;
	uint16_t payload_len;
	uint32_t addr = 0;
	uint32_t mask;
	odp_packet_t pkt;
	int packet_len = 0;
	uint32_t        version, tc, flow, ver_tc_flow;
	uint8_t         *buf, next_hdr;
	uint32_t        l4_len, l3_len, l2_len, l3_offset, l4_offset;
	uint16_t vlan_hdr_len = 0;
	uint16_t l2_hdr_len = 0;
	uint16_t l3_hdr_len = 0;
	uint16_t l4_hdr_len = 0;
	uint16_t eth_type;
	odph_vlanhdr_t *vlan_hdr;
	uint8_t src_mac[] = CLS_DEFAULT_SMAC;
	uint8_t dst_mac[] = CLS_DEFAULT_DMAC;

	payload_len = sizeof(cls_test_packet_t) + pkt_info.len;
	if (pkt_info.l4_type == CLS_PKT_L4_GTP)
		payload_len += sizeof(odph_gtphdr_t);

	seqno = odp_atomic_fetch_inc_u32(pkt_info.seq);

	vlan_hdr_len = pkt_info.vlan ? ODPH_VLANHDR_LEN : 0;
	vlan_hdr_len = pkt_info.vlan_qinq ? 2 * vlan_hdr_len : vlan_hdr_len;
	l3_hdr_len = pkt_info.ipv6 ? ODPH_IPV6HDR_LEN : ODPH_IPV4HDR_LEN;
	eth_type = pkt_info.ipv6 ? ODPH_ETHTYPE_IPV6 : ODPH_ETHTYPE_IPV4;
	next_hdr = ODPH_IPPROTO_TCP;
	l4_hdr_len = ODPH_TCPHDR_LEN;

	switch (pkt_info.l4_type) {
	case CLS_PKT_L4_TCP:
		next_hdr = ODPH_IPPROTO_TCP;
		l4_hdr_len = ODPH_TCPHDR_LEN;
		break;
	case CLS_PKT_L4_GTP:
	case CLS_PKT_L4_UDP:
		next_hdr = ODPH_IPPROTO_UDP;
		l4_hdr_len = ODPH_UDPHDR_LEN;
		break;
	case CLS_PKT_L4_SCTP:
		next_hdr = ODPH_IPPROTO_SCTP;
		l4_hdr_len = ODPH_SCTPHDR_LEN;
		break;
	case CLS_PKT_L4_ICMP:
		next_hdr = ODPH_IPPROTO_ICMPV4;
		l4_hdr_len = ODPH_ICMPHDR_LEN;
		break;
	case CLS_PKT_L4_IGMP:
		next_hdr = ODPH_IPPROTO_IGMP;
		l4_hdr_len = ODPH_IGMP_HLEN;
		break;
	case CLS_PKT_L4_AH:
		next_hdr = ODPH_IPPROTO_AH;
		l4_hdr_len = AH_HDR_LEN;
		break;
	case CLS_PKT_L4_ESP:
		next_hdr = ODPH_IPPROTO_ESP;
		l4_hdr_len = ODPH_ESPHDR_LEN;
		break;
	default:
		ODPH_ASSERT(0);
	}

	l2_hdr_len   = ODPH_ETHHDR_LEN + vlan_hdr_len;
	l4_len	= l4_hdr_len + payload_len;
	l3_len	= l3_hdr_len + l4_len;
	l2_len	= l2_hdr_len + l3_len;
	packet_len	= l2_len;

	pkt = odp_packet_alloc(pkt_info.pool, packet_len);
	CU_ASSERT_FATAL(pkt != ODP_PACKET_INVALID);

	/* Ethernet Header */
	buf = odp_packet_data(pkt);
	odp_packet_l2_offset_set(pkt, 0);
	ethhdr = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
	memcpy(ethhdr->src.addr, &src_mac, ODPH_ETHADDR_LEN);
	memcpy(ethhdr->dst.addr, &dst_mac, ODPH_ETHADDR_LEN);
	vlan_hdr = (odph_vlanhdr_t *)(ethhdr + 1);

	if (pkt_info.vlan) {
		if (pkt_info.vlan_qinq) {
			odp_packet_has_vlan_qinq_set(pkt, 1);
			ethhdr->type = odp_cpu_to_be_16(ODPH_ETHTYPE_VLAN_OUTER);
			vlan_hdr->tci = odp_cpu_to_be_16(0);
			vlan_hdr->type = odp_cpu_to_be_16(ODPH_ETHTYPE_VLAN);
			vlan_hdr++;
		} else {
			odp_packet_has_vlan_set(pkt, 1);
			ethhdr->type = odp_cpu_to_be_16(ODPH_ETHTYPE_VLAN);
		}
		/* Default vlan header */
		vlan_hdr->tci = odp_cpu_to_be_16(0);
		vlan_hdr->type = odp_cpu_to_be_16(eth_type);
	} else {
		CU_ASSERT_FATAL(!pkt_info.vlan_qinq);
		ethhdr->type = odp_cpu_to_be_16(eth_type);
	}

	l3_offset = l2_hdr_len;
	odp_packet_l3_offset_set(pkt, l3_offset);

	if (!pkt_info.ipv6) {
		/* ipv4 */
		ip = (odph_ipv4hdr_t *)(buf + l3_offset);

		parse_ipv4_string(CLS_DEFAULT_DADDR, &addr, &mask);
		ip->dst_addr = odp_cpu_to_be_32(addr);

		parse_ipv4_string(CLS_DEFAULT_SADDR, &addr, &mask);
		ip->src_addr = odp_cpu_to_be_32(addr);
		ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
		ip->id = odp_cpu_to_be_16(seqno);
		ip->proto = next_hdr;
		ip->tot_len = odp_cpu_to_be_16(l3_len);
		ip->ttl = DEFAULT_TTL;
		ip->frag_offset = 0;
		ip->tos = pkt_info.dscp << ODPH_IP_TOS_DSCP_SHIFT;
		odp_packet_has_ipv4_set(pkt, 1);
		odph_ipv4_csum_update(pkt);
	} else {
		/* ipv6 */
		odp_packet_has_ipv6_set(pkt, 1);
		ipv6 = (odph_ipv6hdr_t *)odp_packet_l3_ptr(pkt, NULL);
		version     = ODPH_IPV6        << ODPH_IPV6HDR_VERSION_SHIFT;
		tc   = pkt_info.dscp << ODPH_IP_TOS_DSCP_SHIFT;
		tc <<= ODPH_IPV6HDR_TC_SHIFT;
		flow        = seqno       << ODPH_IPV6HDR_FLOW_LABEL_SHIFT;
		ver_tc_flow = version | tc | flow;

		ipv6->ver_tc_flow = odp_cpu_to_be_32(ver_tc_flow);
		ipv6->payload_len = odp_cpu_to_be_16(l4_len);
		ipv6->next_hdr    = next_hdr;
		ipv6->hop_limit   = DEFAULT_TTL;
		memcpy(ipv6->src_addr, IPV6_SRC_ADDR, ODPH_IPV6ADDR_LEN);
		memcpy(ipv6->dst_addr, IPV6_DST_ADDR, ODPH_IPV6ADDR_LEN);
	}

	l4_offset = l3_offset + l3_hdr_len;
	odp_packet_l4_offset_set(pkt, l4_offset);
	tcp = (odph_tcphdr_t *)(buf + l4_offset);
	udp = (odph_udphdr_t *)(buf + l4_offset);
	sctp = (odph_sctphdr_t *)(buf + l4_offset);
	icmp = (odph_icmphdr_t *)(buf + l4_offset);
	igmp = (odph_igmphdr_t *)(buf + l4_offset);
	ah = (odph_ahhdr_t *)(buf + l4_offset);
	esp = (odph_esphdr_t *)(buf + l4_offset);

	if (pkt_info.l4_type == CLS_PKT_L4_IGMP) {
		igmp->group = odp_cpu_to_be_32(CLS_MAGIC_VAL);
		igmp->type = 0x12;
		igmp->code = 0;
		igmp->csum = 0;
	} else if (pkt_info.l4_type == CLS_PKT_L4_ICMP) {
		icmp->type = ODPH_ICMP_ECHO;
		icmp->code = 0;
		icmp->un.echo.id = 0;
		icmp->un.echo.sequence = 0;
		icmp->chksum = 0;
	} else if (pkt_info.l4_type == CLS_PKT_L4_SCTP) {
		sctp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT);
		sctp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);
		sctp->tag = 0;
		sctp->chksum = 0;
		odp_packet_has_sctp_set(pkt, 1);
		if (odph_sctp_chksum_set(pkt) != 0) {
			ODPH_ERR("odph_sctp_chksum failed\n");
			return ODP_PACKET_INVALID;
		}
	} else if (pkt_info.l4_type == CLS_PKT_L4_UDP) {
		/* udp */
		udp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT);
		udp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);
		udp->length = odp_cpu_to_be_16(payload_len + ODPH_UDPHDR_LEN);
		udp->chksum = 0;
		odp_packet_has_udp_set(pkt, 1);
		if (odph_udp_tcp_chksum(pkt, ODPH_CHKSUM_GENERATE, NULL) != 0) {
			ODPH_ERR("odph_udp_tcp_chksum failed\n");
			return ODP_PACKET_INVALID;
		}
	} else if (pkt_info.l4_type == CLS_PKT_L4_GTP) {
		udp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT);
		udp->dst_port = odp_cpu_to_be_16(ODP_GTPU_UDP_PORT);
		udp->length = odp_cpu_to_be_16(payload_len + ODPH_UDPHDR_LEN);
		udp->chksum = 0;
		odp_packet_has_udp_set(pkt, 1);
		hlen = (uint8_t *)odp_packet_l4_ptr(pkt, NULL);
		gtpu = (odph_gtphdr_t *)(hlen + sizeof(odph_udphdr_t));
		gtpu->teid = odp_cpu_to_be_32(CLS_MAGIC_VAL);
		/* GTPv1 without optional headers */
		gtpu->gtp_hdr_info = 0x30;
		/* GTP echo request */
		gtpu->msg_type = 1;
		gtpu->plen = sizeof(cls_test_packet_t);
		if (odph_udp_tcp_chksum(pkt, ODPH_CHKSUM_GENERATE, NULL) != 0) {
			ODPH_ERR("odph_udp_tcp_chksum failed\n");
			return ODP_PACKET_INVALID;
		}
	} else if (pkt_info.l4_type == CLS_PKT_L4_AH) {
		ah->next_header = ODPH_IPV4;
		ah->ah_len = AH_HDR_LEN / 4 - 2;
		ah->pad = 0;
		ah->spi = 256;
		ah->seq_no = 1;
	} else if (pkt_info.l4_type == CLS_PKT_L4_ESP) {
		esp->spi = 256;
		esp->seq_no = 1;
	} else {
		tcp->src_port = odp_cpu_to_be_16(CLS_DEFAULT_SPORT);
		tcp->dst_port = odp_cpu_to_be_16(CLS_DEFAULT_DPORT);
		tcp->doffset_flags = 0;
		tcp->seq_no = 0;
		tcp->ack_no = 0;
		tcp->window = 0;
		tcp->urgptr = 0;
		tcp->hl = ODPH_TCPHDR_LEN / 4;
		tcp->ack = 1;
		tcp->cksm = 0;
		odp_packet_has_tcp_set(pkt, 1);
		if (odph_udp_tcp_chksum(pkt, ODPH_CHKSUM_GENERATE, NULL) != 0) {
			ODPH_ERR("odph_udp_tcp_chksum failed\n");
			return ODP_PACKET_INVALID;
		}

	}

	/* set pkt sequence number */
	cls_pkt_set_seq(pkt);

	return pkt;
}

odp_cls_pmr_term_t find_first_supported_l3_pmr(void)
{
	odp_cls_pmr_term_t term = ODP_PMR_TCP_DPORT;
	odp_cls_capability_t capability;

	if (odp_cls_capability(&capability)) {
		CU_FAIL("odp_cls_capability() failed");
		return term;
	}

	/* choose supported PMR */
	if (capability.supported_terms.bit.udp_sport)
		term = ODP_PMR_UDP_SPORT;
	else if (capability.supported_terms.bit.udp_dport)
		term = ODP_PMR_UDP_DPORT;
	else if (capability.supported_terms.bit.tcp_sport)
		term = ODP_PMR_TCP_SPORT;
	else if (capability.supported_terms.bit.tcp_dport)
		term = ODP_PMR_TCP_DPORT;
	else
		CU_FAIL("Implementation doesn't support any TCP/UDP PMR");

	return term;
}

cls_packet_l4_info find_first_supported_proto(void)
{
	odp_cls_capability_t capability;

	if (odp_cls_capability(&capability)) {
		CU_FAIL("odp_cls_capability() failed");
		return CLS_PKT_L4_UDP;
	}

	if (capability.supported_terms.bit.udp_sport ||
	    capability.supported_terms.bit.udp_dport)
		return CLS_PKT_L4_UDP;
	else if (capability.supported_terms.bit.tcp_sport ||
		 capability.supported_terms.bit.tcp_dport)
		return CLS_PKT_L4_TCP;

	CU_FAIL("TCP or UDP port matching is not supported");
	return CLS_PKT_L4_UDP;
}

int set_first_supported_pmr_port(odp_packet_t pkt, uint16_t port)
{
	odph_udphdr_t *udp;
	odph_tcphdr_t *tcp;
	odp_cls_pmr_term_t term;

	udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	tcp = (odph_tcphdr_t *)odp_packet_l4_ptr(pkt, NULL);
	port = odp_cpu_to_be_16(port);
	term = find_first_supported_l3_pmr();
	switch (term) {
	case ODP_PMR_UDP_SPORT:
		udp->src_port = port;
		break;
	case ODP_PMR_UDP_DPORT:
		udp->dst_port = port;
		break;
	case ODP_PMR_TCP_DPORT:
		tcp->dst_port = port;
		break;
	case ODP_PMR_TCP_SPORT:
		tcp->src_port = port;
		break;
	default:
		CU_FAIL("Unsupported L3 term");
		return -1;
	}

	return 0;
}

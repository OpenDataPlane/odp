/* Copyright (c) 2015-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

struct udata_struct {
	uint64_t u64;
	uint32_t u32;
	char str[10];
} test_packet_udata = {
	123456,
	789912,
	"abcdefg",
};

/* Create additional dataplane threads */
int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	odp_instance_t instance;
	int status = 0;
	odp_pool_t packet_pool;
	odp_packet_t test_packet;
	struct udata_struct *udat;
	uint32_t udat_size;
	char *buf;
	odph_ethhdr_t *eth;
	odph_ipv4hdr_t *ip;
	odph_udphdr_t *udp;
	odph_ethaddr_t des;
	odph_ethaddr_t src;
	uint32_t srcip;
	uint32_t dstip;
	odp_pool_param_t params;
	odp_pool_capability_t capa;

	if (odp_init_global(&instance, NULL, NULL)) {
		ODPH_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_WORKER)) {
		ODPH_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_pool_capability(&capa) < 0) {
		ODPH_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_pool_param_init(&params);

	params.type           = ODP_POOL_PACKET;
	params.pkt.seg_len    = capa.pkt.min_seg_len;
	params.pkt.len        = capa.pkt.min_seg_len;
	params.pkt.num        = 100;
	params.pkt.uarea_size = sizeof(struct udata_struct);

	packet_pool = odp_pool_create("packet_pool", &params);
	if (packet_pool == ODP_POOL_INVALID)
		return -1;

	test_packet = odp_packet_alloc(packet_pool, capa.pkt.min_seg_len);
	if (odp_packet_is_valid(test_packet) == 0)
		return -1;

	udat = odp_packet_user_area(test_packet);
	udat_size = odp_packet_user_area_size(test_packet);
	if (!udat || udat_size != sizeof(struct udata_struct))
		return -1;

	/* Bug: User area is not packet payload, it's user defined metadata */
	memcpy(udat, &test_packet_udata, sizeof(struct udata_struct));

	buf = odp_packet_data(test_packet);
	odph_eth_addr_parse(&des, "fe:0f:97:c9:e0:44");
	odph_eth_addr_parse(&src, "fe:0f:97:c9:e0:44");

	/* ether */
	odp_packet_l2_offset_set(test_packet, 0);
	eth = (odph_ethhdr_t *)buf;
	memcpy((char *)eth->src.addr, &src, ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, &des, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	if (odph_ipv4_addr_parse(&dstip, "192.168.0.1")) {
		ODPH_ERR("Error: parse ip\n");
		return -1;
	}

	if (odph_ipv4_addr_parse(&srcip, "192.168.0.2")) {
		ODPH_ERR("Error: parse ip\n");
		return -1;
	}

	/* ip */
	odp_packet_l3_offset_set(test_packet, ODPH_ETHHDR_LEN);
	ip = (odph_ipv4hdr_t *)(buf + ODPH_ETHHDR_LEN);
	ip->dst_addr = odp_cpu_to_be_32(srcip);
	ip->src_addr = odp_cpu_to_be_32(dstip);
	ip->ver_ihl = ODPH_IPV4 << 4 | ODPH_IPV4HDR_IHL_MIN;
	ip->tot_len = odp_cpu_to_be_16(udat_size + ODPH_UDPHDR_LEN +
				       ODPH_IPV4HDR_LEN);
	ip->proto = ODPH_IPPROTO_UDP;
	ip->id = odp_cpu_to_be_16(1);
	odp_packet_has_ipv4_set(test_packet, 1);
	if (odph_ipv4_csum_update(test_packet) < 0)
		status = -1;

	if (!odph_ipv4_csum_valid(test_packet))
		status = -1;

	printf("IP chksum = 0x%x\n", odp_be_to_cpu_16(ip->chksum));

	if (odp_be_to_cpu_16(ip->chksum) != 0x3965)
		status = -1;

	/* udp */
	odp_packet_l4_offset_set(test_packet, ODPH_ETHHDR_LEN
				 + ODPH_IPV4HDR_LEN);
	udp = (odph_udphdr_t *)(buf + ODPH_ETHHDR_LEN
				+ ODPH_IPV4HDR_LEN);
	udp->src_port = 0;
	udp->dst_port = 0;
	udp->length = odp_cpu_to_be_16(udat_size + ODPH_UDPHDR_LEN);
	udp->chksum = 0;
	odp_packet_has_udp_set(test_packet, 1);
	udp->chksum = odph_ipv4_udp_chksum(test_packet);

	if (udp->chksum == 0)
		return -1;

	printf("chksum = 0x%x\n", odp_be_to_cpu_16(udp->chksum));

	if (odp_be_to_cpu_16(udp->chksum) != 0x7e5a)
		status = -1;

	odp_packet_free(test_packet);
	if (odp_pool_destroy(packet_pool) != 0)
		return -1;

	if (odp_term_local()) {
		ODPH_ERR("Error: ODP local term failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: ODP global term failed.\n");
		exit(EXIT_FAILURE);
	}

	return status;
}

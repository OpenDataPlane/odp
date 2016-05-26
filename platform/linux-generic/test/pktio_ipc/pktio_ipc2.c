/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example pktio_ipc2.c  ODP IPC example application.
 *		This application works in pair with pktio_ipc1 application.
 *		It opens ipc pktio, reads packets and updates magic number.
 *		Also it allocates some packets from internal pool and sends
 *		to ipc pktio.
 */

#include "ipc_common.h"

static int ipc_second_process(void)
{
	odp_pktio_t ipc_pktio;
	odp_pool_param_t params;
	odp_pool_t pool;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	odp_packet_t alloc_pkt;
	int pkts;
	int ret;
	int i;
	odp_time_t start_cycle;
	odp_time_t cycle;
	odp_time_t diff;
	odp_time_t wait;
	uint64_t stat_pkts = 0;
	odp_pktin_queue_t pktin;

	/* Create packet pool */
	memset(&params, 0, sizeof(params));
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool2", &params);
	if (pool == ODP_POOL_INVALID) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	ipc_pktio = create_pktio(pool);

	wait = odp_time_local_from_ns(run_time_sec * ODP_TIME_SEC_IN_NS);
	start_cycle = odp_time_local();

	if (odp_pktin_queue(ipc_pktio, &pktin, 1) != 1) {
		EXAMPLE_ERR("no input queue\n");
		return -1;
	}

	/* start ipc pktio, i.e. wait until other process connects */
	for (;;) {
		/* 1. exit loop if time specified */
		if (run_time_sec) {
			cycle = odp_time_local();
			diff = odp_time_diff(cycle, start_cycle);
			if (odp_time_cmp(wait, diff) < 0) {
				printf("timeout exit, run_time_sec %d\n",
				       run_time_sec);
				goto exit;
			}
		}

		ret = odp_pktio_start(ipc_pktio);
		if (!ret)
			break;
	}

	for (;;) {
		/* exit loop if time specified */
		if (run_time_sec) {
			cycle = odp_time_local();
			diff = odp_time_diff(cycle, start_cycle);
			if (odp_time_cmp(wait, diff) < 0) {
				EXAMPLE_DBG("exit after %d seconds\n",
					    run_time_sec);
				break;
			}
		}

		/* recv some packets and change MAGIC to MAGIC_2 */
		pkts = odp_pktin_recv(pktin, pkt_tbl, MAX_PKT_BURST);
		if (pkts <= 0)
			continue;

		for (i = 0; i < pkts; i++) {
			odp_packet_t pkt = pkt_tbl[i];
			pkt_head_t head;
			size_t off;

			off = odp_packet_l4_offset(pkt);
			if (off ==  ODP_PACKET_OFFSET_INVALID)
				EXAMPLE_ABORT("invalid l4 offset\n");

			off += ODPH_UDPHDR_LEN;
			ret = odp_packet_copy_to_mem(pkt, off, sizeof(head),
						     &head);
			if (ret)
				EXAMPLE_ABORT("unable copy out head data");

			if (head.magic != TEST_SEQ_MAGIC)
				EXAMPLE_ABORT("Wrong head magic!");

			/* Modify magic number in packet */
			head.magic = TEST_SEQ_MAGIC_2;
			ret = odp_packet_copy_from_mem(pkt, off, sizeof(head),
						       &head);
			if (ret)
				EXAMPLE_ABORT("unable to copy in head data");
		}

		/* send all packets back */
		ret = ipc_odp_packet_sendall(ipc_pktio, pkt_tbl, pkts);
		if (ret < 0)
			EXAMPLE_ABORT("can not send packets\n");
		stat_pkts += pkts;

		/* alloc packet from local pool, set magic to ALLOC_MAGIC,
		 * and send it.*/
		alloc_pkt = odp_packet_alloc(pool, SHM_PKT_POOL_BUF_SIZE);
		if (alloc_pkt != ODP_PACKET_INVALID) {
			pkt_head_t head;
			size_t off;

			odp_packet_l4_offset_set(alloc_pkt, 30);

			head.magic = TEST_ALLOC_MAGIC;

			off = odp_packet_l4_offset(alloc_pkt);
			off += ODPH_UDPHDR_LEN;
			ret = odp_packet_copy_from_mem(alloc_pkt, off,
						       sizeof(head),
						       &head);
			if (ret)
				EXAMPLE_ABORT("unable to copy in head data");

			pkt_tbl[0] = alloc_pkt;
			ret = ipc_odp_packet_sendall(ipc_pktio, pkt_tbl, 1);
			if (ret < 0)
				EXAMPLE_ABORT("can not send packets\n");
			stat_pkts += 1;
		}
	}

	/* cleanup and exit */
	ret = odp_pktio_stop(ipc_pktio);
	if (ret) {
		EXAMPLE_DBG("odp_pktio_stop error %d\n", ret);
		return -1;
	}

exit:
	ret = odp_pktio_close(ipc_pktio);
	if (ret) {
		EXAMPLE_DBG("odp_pktio_close error %d\n", ret);
		return -1;
	}

	ret = odp_pool_destroy(pool);
	if (ret)
		EXAMPLE_DBG("pool_destroy error %d\n", ret);

	return stat_pkts > 1000 ? 0 : -1;
}

int main(int argc, char *argv[])
{
	odp_instance_t instance;
	odp_platform_init_t plat_idata;

	/* Parse and store the application arguments */
	parse_args(argc, argv);

	memset(&plat_idata, 0, sizeof(odp_platform_init_t));
	plat_idata.ipc_ns = ipc_name_space;

	if (odp_init_global(&instance, NULL, &plat_idata)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	return ipc_second_process();
}

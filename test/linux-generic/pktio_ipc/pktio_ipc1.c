/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ipc_common.h"

/**
 * @file
 * @example pktio_ipc1.c  ODP IPC example application.
 *		This application works in pair with pktio_ipc2 application.
 *		It opens ipc pktio, allocates packets, sets magic number and
 *		sends packets to ipc pktio. Then app reads packets and checks
 *		that magic number was properly updated and there is no packet
 *		loss (i.e. sequesce counter continiusly incrementing.)
 */

/**
 * Packet IO loopback worker thread using bursts from/to IO resources
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static int pktio_run_loop(odp_pool_t pool)
{
	int thr;
	int pkts;
	odp_pktio_t ipc_pktio;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	uint64_t cnt = 0; /* increasing counter on each send packet */
	uint64_t cnt_recv = 0; /* increasing counter to validate
				  cnt on receive */
	uint64_t stat_pkts = 0;
	uint64_t stat_pkts_alloc = 0;
	uint64_t stat_pkts_prev = 0;
	uint64_t stat_errors = 0;
	uint64_t stat_free = 0;
	odp_time_t start_cycle;
	odp_time_t current_cycle;
	odp_time_t cycle;
	odp_time_t diff;
	odp_time_t wait;
	int ret;
	odp_pktin_queue_t pktin;

	thr = odp_thread_id();

	ipc_pktio = odp_pktio_lookup("ipc_pktio");
	if (ipc_pktio == ODP_PKTIO_INVALID) {
		EXAMPLE_ERR("  [%02i] Error: lookup of pktio %s failed\n",
			    thr, "ipc_pktio");
		return -2;
	}
	printf("  [%02i] looked up ipc_pktio:%02" PRIu64 ", burst mode\n",
	       thr, odp_pktio_to_u64(ipc_pktio));

	wait = odp_time_local_from_ns(run_time_sec * ODP_TIME_SEC_IN_NS);
	start_cycle = odp_time_local();
	current_cycle = start_cycle;

	if (odp_pktin_queue(ipc_pktio, &pktin, 1) != 1) {
		EXAMPLE_ERR("no input queue\n");
		return -1;
	}

	/* start ipc pktio, i.e. wait until other process connects */
	for (;;) {
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

	/* packets loop */
	for (;;) {
		int i;

		/* 1. exit loop if time specified */
		if (run_time_sec) {
			cycle = odp_time_local();
			diff = odp_time_diff(cycle, start_cycle);
			if (odp_time_cmp(wait, diff) < 0) {
				EXAMPLE_DBG("exit after %d seconds\n",
					    run_time_sec);
				break;
			}
		}

		/* 2. Receive packets back from ipc_pktio, validate magic
		 *    number sequence counter and free that packet
		 */
		while (1) {
			pkts = odp_pktin_recv(pktin, pkt_tbl, MAX_PKT_BURST);
			if (pkts <= 0)
				break;

			for (i = 0; i < pkts; i++) {
				odp_packet_t pkt = pkt_tbl[i];
				pkt_head_t head;
				pkt_tail_t tail;
				size_t off;

				off = odp_packet_l4_offset(pkt);
				if (off ==  ODP_PACKET_OFFSET_INVALID)
					EXAMPLE_ABORT("invalid l4 offset\n");

				off += ODPH_UDPHDR_LEN;
				ret = odp_packet_copy_to_mem(pkt, off,
							     sizeof(head),
							     &head);
				if (ret) {
					stat_errors++;
					stat_free++;
					odp_packet_free(pkt);
					EXAMPLE_DBG("error\n");
					continue;
				}

				if (head.magic == TEST_ALLOC_MAGIC) {
					stat_free++;
					odp_packet_free(pkt);
					continue;
				}

				if (head.magic != TEST_SEQ_MAGIC_2) {
					stat_errors++;
					stat_free++;
					odp_packet_free(pkt);
					EXAMPLE_DBG("error\n");
					continue;
				}

				off = odp_packet_len(pkt) - sizeof(pkt_tail_t);
				ret = odp_packet_copy_to_mem(pkt, off,
							     sizeof(tail),
							     &tail);
				if (ret) {
					stat_errors++;
					stat_free++;
					odp_packet_free(pkt);
					continue;
				}

				if (tail.magic != TEST_SEQ_MAGIC) {
					stat_errors++;
					stat_free++;
					odp_packet_free(pkt);
					continue;
				}

				cnt_recv++;

				if (head.seq != cnt_recv) {
					stat_errors++;
					odp_packet_free(pkt);
					EXAMPLE_DBG("head.seq %d - "
						    "cnt_recv %" PRIu64 ""
						    " = %" PRIu64 "\n",
						    head.seq, cnt_recv,
						    head.seq - cnt_recv);
					cnt_recv = head.seq;
					stat_errors++;
					stat_free++;
					continue;
				}

				stat_pkts++;
				odp_packet_free(pkt);
			}
		}

		/* 3. emulate that pkts packets were received  */
		odp_random_data((uint8_t *)&pkts, sizeof(pkts), 0);
		pkts = ((pkts & 0xffff) % MAX_PKT_BURST) + 1;

		for (i = 0; i < pkts; i++) {
			odp_packet_t pkt;

			pkt = odp_packet_alloc(pool, SHM_PKT_POOL_BUF_SIZE);
			if (pkt == ODP_PACKET_INVALID)
				break;

			stat_pkts_alloc++;
			odp_packet_l4_offset_set(pkt, 30);
			pkt_tbl[i] = pkt;
		}

		/* exit if no packets allocated */
		if (i == 0) {
			EXAMPLE_DBG("unable to alloc packet pkts %d/%d\n",
				    i, pkts);
			break;
		}

		pkts = i;

		/* 4. Copy counter and magic numbers to that packets */
		for (i = 0; i < pkts; i++) {
			pkt_head_t head;
			pkt_tail_t tail;
			size_t off;
			odp_packet_t pkt = pkt_tbl[i];

			off = odp_packet_l4_offset(pkt);
			if (off == ODP_PACKET_OFFSET_INVALID)
				EXAMPLE_ABORT("packet L4 offset not set");

			head.magic = TEST_SEQ_MAGIC;
			head.seq   = cnt++;

			off += ODPH_UDPHDR_LEN;
			ret = odp_packet_copy_from_mem(pkt, off, sizeof(head),
						       &head);
			if (ret)
				EXAMPLE_ABORT("unable to copy in head data");

			tail.magic = TEST_SEQ_MAGIC;
			off = odp_packet_len(pkt) - sizeof(pkt_tail_t);
			ret = odp_packet_copy_from_mem(pkt, off, sizeof(tail),
						       &tail);
			if (ret)
				EXAMPLE_ABORT("unable to copy in tail data");
		}

		/* 5. Send packets to ipc_pktio */
		ret = ipc_odp_packet_send_or_free(ipc_pktio, pkt_tbl, pkts);
		if (ret < 0) {
			EXAMPLE_DBG("unable to sending to ipc pktio\n");
			break;
		}

		cycle = odp_time_local();
		diff = odp_time_diff(cycle, current_cycle);
		if (odp_time_cmp(odp_time_local_from_ns(ODP_TIME_SEC_IN_NS),
				 diff) < 0) {
			current_cycle = cycle;
			printf("\rpkts:  %" PRIu64 ", alloc  %" PRIu64 ","
			       " errors %" PRIu64 ", pps  %" PRIu64 ","
			       " free %" PRIu64 ".",
			       stat_pkts, stat_pkts_alloc, stat_errors,
			       (stat_pkts + stat_pkts_alloc - stat_pkts_prev),
			       stat_free);
			fflush(stdout);
			stat_pkts_prev = stat_pkts + stat_pkts_alloc;
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

	return (stat_errors > 10 || stat_pkts < 1000) ? -1 : 0;
}

/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_instance_t instance;
	odp_platform_init_t plat_idata;
	int ret;

	/* Parse and store the application arguments */
	parse_args(argc, argv);

	memset(&plat_idata, 0, sizeof(odp_platform_init_t));
	plat_idata.ipc_ns = ipc_name_space;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, &plat_idata)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]));

	/* Create packet pool */
	memset(&params, 0, sizeof(params));
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool1", &params);
	if (pool == ODP_POOL_INVALID) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_pool_print(pool);

	create_pktio(pool);

	ret = pktio_run_loop(pool);

	if (odp_pool_destroy(pool)) {
		EXAMPLE_ERR("Error: odp_pool_destroy() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		EXAMPLE_ERR("Error: odp_term_local() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		EXAMPLE_ERR("Error: odp_term_global() failed.\n");
		exit(EXIT_FAILURE);
	}

	EXAMPLE_DBG("return %d\n", ret);
	return ret;
}

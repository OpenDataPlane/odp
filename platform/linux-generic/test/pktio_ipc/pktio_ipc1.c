/* Copyright (c) 2015-2018, Linaro Limited
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
	int pkts;
	odp_pktio_t ipc_pktio = ODP_PKTIO_INVALID;
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
	char name[30];
	int sync_cnt = 0;

	if (master_pid)
		sprintf(name, TEST_IPC_PKTIO_PID_NAME, master_pid);
	else
		sprintf(name, TEST_IPC_PKTIO_NAME);

	wait = odp_time_local_from_ns(run_time_sec * ODP_TIME_SEC_IN_NS);
	start_cycle = odp_time_local();
	current_cycle = start_cycle;

	for (;;) {
		if (run_time_sec) {
			cycle = odp_time_local();
			diff = odp_time_diff(cycle, start_cycle);
			if (odp_time_cmp(wait, diff) < 0) {
				printf("timeout exit, run_time_sec %d\n",
				       run_time_sec);
				return -1;
			}
		}

		ipc_pktio = create_pktio(pool, master_pid);
		if (ipc_pktio != ODP_PKTIO_INVALID)
			break;
		if (!master_pid)
			break;
	}

	if (ipc_pktio == ODP_PKTIO_INVALID)
		return -1;

	if (odp_pktin_queue(ipc_pktio, &pktin, 1) != 1) {
		ODPH_ERR("no input queue\n");
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

		/* Reduce polling frequency to once per 50ms */
		odp_time_wait_ns(50 * ODP_TIME_MSEC_IN_NS);
	}

	/* packets loop */
	for (;;) {
		int i;

		/* 1. exit loop if time specified */
		if (run_time_sec) {
			cycle = odp_time_local();
			diff = odp_time_diff(cycle, start_cycle);
			if (odp_time_cmp(wait, diff) < 0) {
				ODPH_DBG("exit after %d seconds\n",
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
				if (off ==  ODP_PACKET_OFFSET_INVALID) {
					stat_errors++;
					stat_free++;
					odp_packet_free(pkt);
					ODPH_ERR("invalid l4 offset\n");
				}

				off += ODPH_UDPHDR_LEN;
				ret = odp_packet_copy_to_mem(pkt, off,
							     sizeof(head),
							     &head);
				if (ret) {
					stat_errors++;
					stat_free++;
					odp_packet_free(pkt);
					ODPH_DBG("error\n");
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
					ODPH_DBG("error\n");
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

				if (head.seq != cnt_recv && sync_cnt) {
					stat_errors++;
					odp_packet_free(pkt);
					ODPH_DBG("head.seq %d - cnt_recv "
						 "%" PRIu64 " = %" PRIu64 "\n",
						 head.seq, cnt_recv,
						 head.seq - cnt_recv);
					cnt_recv = head.seq;
					stat_free++;
					continue;
				}

				stat_pkts++;
				odp_packet_free(pkt);
			}
		}

		/* 3. emulate that pkts packets were received  */
		ret = odp_random_data((uint8_t *)&pkts, sizeof(pkts),
				      ODP_RANDOM_BASIC);
		if (ret != sizeof(pkts)) {
			ODPH_ABORT("random failed");
			break;
		}
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

		pkts = i;

		/* 4. Copy counter and magic numbers to that packets */
		for (i = 0; i < pkts; i++) {
			pkt_head_t head;
			pkt_tail_t tail;
			size_t off;
			odp_packet_t pkt = pkt_tbl[i];

			off = odp_packet_l4_offset(pkt);
			if (off == ODP_PACKET_OFFSET_INVALID)
				ODPH_ABORT("packet L4 offset not set");

			head.magic = TEST_SEQ_MAGIC;
			head.seq   = cnt++;

			off += ODPH_UDPHDR_LEN;
			ret = odp_packet_copy_from_mem(pkt, off, sizeof(head),
						       &head);
			if (ret)
				ODPH_ABORT("unable to copy in head data");

			tail.magic = TEST_SEQ_MAGIC;
			off = odp_packet_len(pkt) - sizeof(pkt_tail_t);
			ret = odp_packet_copy_from_mem(pkt, off, sizeof(tail),
						       &tail);
			if (ret)
				ODPH_ABORT("unable to copy in tail data");
		}

		/* 5. Send packets to ipc_pktio */
		ret = ipc_odp_packet_send_or_free(ipc_pktio, pkt_tbl, pkts);
		if (ret < 0) {
			ODPH_DBG("unable to sending to ipc pktio\n");
			break;
		}

		cycle = odp_time_local();
		diff = odp_time_diff(cycle, current_cycle);
		if (odp_time_cmp(odp_time_local_from_ns(ODP_TIME_SEC_IN_NS),
				 diff) < 0) {
			current_cycle = cycle;
			if (!sync_cnt && stat_errors == (MAX_PKT_BURST + 2)) {
				stat_errors = 0;
				sync_cnt = 1;
			}
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
		ODPH_DBG("odp_pktio_stop error %d\n", ret);
		return -1;
	}

exit:
	ret = odp_pktio_close(ipc_pktio);
	if (ret) {
		ODPH_DBG("odp_pktio_close error %d\n", ret);
		return -1;
	}

	return (stat_errors || stat_pkts < 1000) ? -1 : 0;
}

/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odp_pool_t pool;
	odp_pool_param_t params;
	odp_instance_t instance;
	int ret;
	cpu_set_t cpu_set;
	odp_cpumask_t mask;
	int cpu;
	pid_t pid;

	/* Parse and store the application arguments */
	parse_args(argc, argv);

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		ODPH_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_cpumask_default_worker(&mask, 0);
	cpu = odp_cpumask_first(&mask);

	CPU_ZERO(&cpu_set);
	CPU_SET(cpu, &cpu_set);

	pid = getpid();

	if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpu_set)) {
		printf("Set CPU affinity failed.\n");
		return -1;
	}

	printf("ipc_pktio1 %d run on cpu %d\n", pid, cpu);

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_WORKER)) {
		ODPH_ERR("Error: ODP local init failed.\n");
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

	pool = odp_pool_create(TEST_IPC_POOL_NAME, &params);
	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_pool_print(pool);

	ret = pktio_run_loop(pool);

	if (odp_pool_destroy(pool)) {
		ODPH_ERR("Error: odp_pool_destroy() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_local()) {
		ODPH_ERR("Error: odp_term_local() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: odp_term_global() failed.\n");
		exit(EXIT_FAILURE);
	}

	ODPH_DBG("return %d\n", ret);
	return ret;
}

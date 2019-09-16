/* Copyright (c) 2015-2018, Linaro Limited
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

static int ipc_second_process(int master_pid)
{
	odp_pktio_t ipc_pktio = ODP_PKTIO_INVALID;
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

	pool = odp_pool_create(TEST_IPC_POOL_NAME, &params);
	if (pool == ODP_POOL_INVALID) {
		ODPH_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	wait = odp_time_local_from_ns(run_time_sec * ODP_TIME_SEC_IN_NS);
	start_cycle = odp_time_local();

	for (;;) {
		/*  exit loop if time specified */
		if (run_time_sec) {
			cycle = odp_time_local();
			diff = odp_time_diff(cycle, start_cycle);
			if (odp_time_cmp(wait, diff) < 0) {
				printf("timeout exit, run_time_sec %d\n",
				       run_time_sec);
				goto not_started;
			}
		}

		ipc_pktio = create_pktio(pool, master_pid);
		if (ipc_pktio != ODP_PKTIO_INVALID)
			break;
		if (!master_pid)
			break;
	}

	if (ipc_pktio == ODP_PKTIO_INVALID) {
		odp_pool_destroy(pool);
		return -1;
	}

	if (odp_pktin_queue(ipc_pktio, &pktin, 1) != 1) {
		odp_pool_destroy(pool);
		ODPH_ERR("no input queue\n");
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
				goto not_started;
			}
		}

		ret = odp_pktio_start(ipc_pktio);
		if (!ret)
			break;

		/* Reduce polling frequency to once per 50ms */
		odp_time_wait_ns(50 * ODP_TIME_MSEC_IN_NS);
	}

	for (;;) {
		/* exit loop if time specified */
		if (run_time_sec) {
			cycle = odp_time_local();
			diff = odp_time_diff(cycle, start_cycle);
			if (odp_time_cmp(wait, diff) < 0) {
				ODPH_DBG("exit after %d seconds\n",
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
			if (off ==  ODP_PACKET_OFFSET_INVALID) {
				ODPH_ERR("invalid l4 offset\n");
				for (int j = i; j < pkts; j++)
					odp_packet_free(pkt_tbl[j]);
				break;
			}

			off += ODPH_UDPHDR_LEN;
			ret = odp_packet_copy_to_mem(pkt, off, sizeof(head),
						     &head);
			if (ret)
				ODPH_ABORT("unable copy out head data");

			if (head.magic != TEST_SEQ_MAGIC) {
				ODPH_ERR("Wrong head magic! %x", head.magic);
				for (int j = i; j < pkts; j++)
					odp_packet_free(pkt_tbl[j]);
				break;
			}

			/* Modify magic number in packet */
			head.magic = TEST_SEQ_MAGIC_2;
			ret = odp_packet_copy_from_mem(pkt, off, sizeof(head),
						       &head);
			if (ret)
				ODPH_ABORT("unable to copy in head data");
		}

		/* send all packets back */
		ret = ipc_odp_packet_send_or_free(ipc_pktio, pkt_tbl, i);
		if (ret < 0)
			ODPH_ABORT("can not send packets\n");

		stat_pkts += ret;

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
				ODPH_ABORT("unable to copy in head data");

			pkt_tbl[0] = alloc_pkt;
			ret = ipc_odp_packet_send_or_free(ipc_pktio,
							  pkt_tbl, 1);
			if (ret < 0)
				ODPH_ABORT("can not send packets\n");
			stat_pkts += 1;
		}
	}

	/* cleanup and exit */
	ret = odp_pktio_stop(ipc_pktio);
	if (ret) {
		ODPH_DBG("ipc2: odp_pktio_stop error %d\n", ret);
		return -1;
	}

not_started:
	ret = odp_pktio_close(ipc_pktio);
	if (ret) {
		ODPH_DBG("ipc2: odp_pktio_close error %d\n", ret);
		return -1;
	}

	ret = odp_pool_destroy(pool);
	if (ret)
		ODPH_DBG("ipc2: pool_destroy error %d\n", ret);

	return stat_pkts > 1000 ? 0 : -1;
}

int main(int argc, char *argv[])
{
	odp_instance_t instance;
	int ret;
	cpu_set_t cpu_set;
	odp_cpumask_t mask;
	int cpu;
	pid_t pid;

	/* Parse and store the application arguments */
	parse_args(argc, argv);

	if (odp_init_global(&instance, NULL, NULL)) {
		ODPH_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	odp_cpumask_default_worker(&mask, 0);
	cpu = odp_cpumask_first(&mask);
	ret = odp_cpumask_next(&mask, cpu);
	if (ret != -1)
		cpu = ret;

	CPU_ZERO(&cpu_set);
	CPU_SET(cpu, &cpu_set);

	pid = getpid();

	if (sched_setaffinity(pid, sizeof(cpu_set_t), &cpu_set)) {
		printf("Set CPU affinity failed to cpu %d.\n", cpu);
		return -1;
	}

	printf("ipc_pktio2 %d run on cpu %d\n", pid, cpu);

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_WORKER)) {
		ODPH_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	ret = ipc_second_process(master_pid);

	if (odp_term_local()) {
		ODPH_ERR("Error: odp_term_local() failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_term_global(instance)) {
		ODPH_ERR("Error: odp_term_global() failed.\n");
		exit(EXIT_FAILURE);
	}

	return ret;
}

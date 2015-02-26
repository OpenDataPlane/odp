/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_init.h>
#include <odp_internal.h>
#include <odp_debug.h>
#include <odp_packet_dpdk.h>

int odp_init_dpdk(void)
{
	int test_argc = 5;
	char *test_argv[6];
	int core_count, i, num_cores = 0;
	char core_mask[8];

	core_count  = odp_sys_core_count();
	for (i = 0; i < core_count; i++)
		num_cores += (0x1 << i);
	sprintf(core_mask, "%x", num_cores);

	test_argv[0] = malloc(sizeof("odp_dpdk"));
	strcpy(test_argv[0], "odp_dpdk");
	test_argv[1] = malloc(sizeof("-c"));
	strcpy(test_argv[1], "-c");
	test_argv[2] = malloc(sizeof(core_mask));
	strcpy(test_argv[2], core_mask);
	test_argv[3] = malloc(sizeof("-n"));
	strcpy(test_argv[3], "-n");
	test_argv[4] = malloc(sizeof("3"));
	strcpy(test_argv[4], "3");

	if (rte_eal_init(test_argc, (char **)test_argv) < 0) {
		ODP_ERR("Cannot init the Intel DPDK EAL!");
		return -1;
	}

	if (rte_eal_pci_probe() < 0) {
		ODP_ERR("Cannot probe PCI\n");
		return -1;
	}

	return 0;
}

int odp_init_global(void)
{
	odp_system_info_init();

	if (odp_init_dpdk()) {
		ODP_ERR("ODP dpdk init failed.\n");
		return -1;
	}

	if (odp_shm_init_global()) {
		ODP_ERR("ODP shm init failed.\n");
		return -1;
	}

	if (odp_thread_init_global()) {
		ODP_ERR("ODP thread init failed.\n");
	return -1;
	}

	if (odp_buffer_pool_init_global()) {
		ODP_ERR("ODP buffer pool init failed.\n");
		return -1;
	}

	if (odp_queue_init_global()) {
		ODP_ERR("ODP queue init failed.\n");
		return -1;
	}

	if (odp_schedule_init_global()) {
		ODP_ERR("ODP schedule init failed.\n");
		return -1;
	}

	if (odp_pktio_init_global()) {
		ODP_ERR("ODP packet io init failed.\n");
		return -1;
	}

	if (odp_timer_init_global()) {
		ODP_ERR("ODP timer init failed.\n");
		return -1;
	}

	if (odp_crypto_init_global()) {
		ODP_ERR("ODP crypto init failed.\n");
		return -1;
	}

	return 0;
}


int odp_init_local()
{
	if (odp_thread_init_local()) {
		ODP_ERR("ODP thread local init failed.\n");
		return -1;
	}

	if (odp_pktio_init_local()) {
		ODP_ERR("ODP packet io local init failed.\n");
		return -1;
	}

	if (odp_schedule_init_local()) {
		ODP_ERR("ODP schedule local init failed.\n");
		return -1;
	}

	return 0;
}

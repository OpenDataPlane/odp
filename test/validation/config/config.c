/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <odp.h>
#include "odp_cunit_common.h"
#include "config.h"

int config_suite_init(void)
{
	return 0;
}

int config_suite_term(void)
{
	return 0;
}

void config_test(void)
{
	CU_ASSERT(odp_config_pools() == ODP_CONFIG_POOLS);
	CU_ASSERT(odp_config_queues() == ODP_CONFIG_QUEUES);
	CU_ASSERT(odp_config_max_ordered_locks_per_queue() ==
		  ODP_CONFIG_MAX_ORDERED_LOCKS_PER_QUEUE);
	CU_ASSERT(odp_config_sched_prios() == ODP_CONFIG_SCHED_PRIOS);
	CU_ASSERT(odp_config_sched_grps() == ODP_CONFIG_SCHED_GRPS);
	CU_ASSERT(odp_config_pktio_entries() == ODP_CONFIG_PKTIO_ENTRIES);
	CU_ASSERT(odp_config_buffer_align_min() == ODP_CONFIG_BUFFER_ALIGN_MIN);
	CU_ASSERT(odp_config_buffer_align_max() == ODP_CONFIG_BUFFER_ALIGN_MAX);
	CU_ASSERT(odp_config_packet_headroom() == ODP_CONFIG_PACKET_HEADROOM);
	CU_ASSERT(odp_config_packet_tailroom() == ODP_CONFIG_PACKET_TAILROOM);
	CU_ASSERT(odp_config_packet_seg_len_min() ==
		  ODP_CONFIG_PACKET_SEG_LEN_MIN);
	CU_ASSERT(odp_config_packet_seg_len_max() ==
		  ODP_CONFIG_PACKET_SEG_LEN_MAX);
	CU_ASSERT(odp_config_packet_buf_len_max() ==
		  ODP_CONFIG_PACKET_BUF_LEN_MAX);
	CU_ASSERT(odp_config_shm_blocks() == ODP_CONFIG_SHM_BLOCKS);
}

CU_TestInfo config_suite[] = {
	_CU_TEST_INFO(config_test),
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo config_suites[] = {
	{ .pName = "config tests",
			.pTests = config_suite,
			.pInitFunc = config_suite_init,
			.pCleanupFunc = config_suite_term,
	},
	CU_SUITE_INFO_NULL,
};

int config_main(void)
{
	return odp_cunit_run(config_suites);
}

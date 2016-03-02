/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <odp_cunit_common.h>
#include "shmem_odp.h"
#include "shmem_common.h"

#define TEST_SHARE_FOO (0xf0f0f0f0)
#define TEST_SHARE_BAR (0xf0f0f0f)

void shmem_test_odp_shm_proc(void)
{
	char fifo_name[PATH_MAX];
	int fd;
	odp_shm_t shm;
	test_shared_data_t *test_shared_data;
	char test_result;

	shm = odp_shm_reserve(ODP_SHM_NAME,
			      sizeof(test_shared_data_t),
			      ALIGN_SIZE, ODP_SHM_PROC);
	CU_ASSERT_FATAL(ODP_SHM_INVALID != shm);
	test_shared_data = odp_shm_addr(shm);
	CU_ASSERT_FATAL(NULL != test_shared_data);
	test_shared_data->foo = TEST_SHARE_FOO;
	test_shared_data->bar = TEST_SHARE_BAR;

	odp_mb_full();

	/* open the fifo: this will indicate to linux process that it can
	 * start the shmem lookup and check if it sees the data */
	sprintf(fifo_name, FIFO_NAME_FMT, getpid());
	CU_ASSERT_FATAL(mkfifo(fifo_name, 0666) == 0);

	/* read from the fifo: the linux process result: */
	fd = open(fifo_name, O_RDONLY);
	CU_ASSERT_FATAL(fd >= 0);

	CU_ASSERT(read(fd, &test_result, sizeof(char)) == 1);
	CU_ASSERT_FATAL(test_result == TEST_SUCCESS);

	CU_ASSERT(odp_shm_free(shm) == 0);
}

odp_testinfo_t shmem_suite[] = {
	ODP_TEST_INFO(shmem_test_odp_shm_proc),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t shmem_suites[] = {
	{"Shared Memory", NULL, NULL, shmem_suite},
	ODP_SUITE_INFO_NULL,
};

int main(void)
{
	int ret = odp_cunit_register(shmem_suites);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

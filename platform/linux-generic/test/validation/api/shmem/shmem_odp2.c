/* Copyright (c) 2016-2018, Linaro Limited
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
#include <stdlib.h>

#include <odp_cunit_common.h>
#include "shmem_odp2.h"
#include "shmem_common.h"

#define TEST_SHARE_FOO (0xf0f0f0f0)
#define TEST_SHARE_BAR (0xf0f0f0f)

/* The C unit test harness is run by ODP1 app which will be told the return
 * staus of this process. See top of shmem_linux.c for chart flow of events
 */
int main(int argc, char *argv[])
{
	odp_instance_t odp1;
	odp_instance_t odp2;
	odp_shm_t shm;
	odp_shm_info_t  info;
	test_shared_data_t *test_shared_data;

	/* odp init: */
	if (0 != odp_init_global(&odp2, NULL, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return 1;
	}
	if (0 != odp_init_local(odp2, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return 1;
	}

	/* test: map ODP1 memory and check its contents:
	 * The pid of the ODP instantiation process sharing its memory
	 * is given as first arg. In linux-generic ODP, this pid is actually
	 * the ODP instance */
	if (argc != 2) {
		fprintf(stderr, "One single parameter expected, %d found.\n",
			argc);
		return 1;
	}
	odp1 = (odp_instance_t)atoi(argv[1]);

	printf("shmem_odp2: trying to grab %s from pid %d\n",
	       SHM_NAME, (int)odp1);
	shm = odp_shm_import(SHM_NAME, odp1, SHM_NAME);
	if (shm == ODP_SHM_INVALID) {
		fprintf(stderr, "error: odp_shm_lookup_external failed.\n");
		return 1;
	}

	/* check that the read size matches the allocated size (in other ODP):*/
	if ((odp_shm_info(shm, &info)) ||
	    (info.size != sizeof(*test_shared_data))) {
		fprintf(stderr, "error: odp_shm_info failed.\n");
		return 1;
	}

	test_shared_data = odp_shm_addr(shm);
	if (test_shared_data == NULL) {
		fprintf(stderr, "error: odp_shm_addr failed.\n");
		return 1;
	}

	if (test_shared_data->foo != TEST_SHARE_FOO) {
		fprintf(stderr, "error: Invalid data TEST_SHARE_FOO.\n");
		return 1;
	}

	if (test_shared_data->bar != TEST_SHARE_BAR) {
		fprintf(stderr, "error: Invalid data TEST_SHARE_BAR.\n");
		return 1;
	}

	if (odp_shm_free(shm) != 0) {
		fprintf(stderr, "error: odp_shm_free() failed.\n");
		return 1;
	}

	/* odp term: */
	if (0 != odp_term_local()) {
		fprintf(stderr, "error: odp_term_local() failed.\n");
		return 1;
	}

	if (0 != odp_term_global(odp2)) {
		fprintf(stderr, "error: odp_term_global() failed.\n");
		return 1;
	}

	printf("%s SUCSESS\n", __FILE__);
	return 0;
}

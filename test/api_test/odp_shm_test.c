/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Linaro Limited nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIALDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *
 * ODP test shared memory
 */

#include <stdio.h>
#include <string.h>
#include <odp.h>
#include "odp_common.h"
#include "odp_shm_test.h"

static void *run_thread(void *arg)
{
	pthrd_arg *parg = (pthrd_arg *)arg;
	int thr;

	thr = odp_thread_id();

	printf("Thread %i starts\n", thr);

	switch (parg->testcase) {
	case ODP_SHM_TEST:
		test_shared_data = odp_shm_lookup("test_shared_data");
		printf("  [%i] shared data at %p\n", thr, test_shared_data);
		break;
	default:
		printf("Invalid test case [%d]\n", parg->testcase);
	}
	fflush(stdout);

	return parg;
}

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	pthrd_arg thrdarg;

	if (odp_test_global_init() != 0)
		return -1;

	odp_print_system_info();

	test_shared_data = odp_shm_reserve("test_shared_data",
					   sizeof(test_shared_data_t), 128);
	memset(test_shared_data, 0, sizeof(test_shared_data_t));
	printf("test shared data at %p\n\n", test_shared_data);

	thrdarg.testcase = ODP_SHM_TEST;
	odp_test_thread_create(run_thread, &thrdarg);

	odp_test_thread_exit();

	return 0;
}

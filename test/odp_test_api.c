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
 * ODP test application
 */


#include <string.h>
#include <stdio.h>
#include <odp.h>
#include <odp_linux.h>
#include "odp_test_atomic.h"

#define MAX_WORKERS 31


#ifdef ODP_TEST_ATOMIC
	struct odp_test_atomic_ops test_atomic_ops = {
		.init = test_atomic_init,
		.store = test_atomic_store,
		.run_test = test_atomic_basic,
		.validate_test = test_atomic_validate,
	};
#endif

static void *run_thread(void *arg)
{
#ifndef ODP_TEST_ATOMIC
	printf("Thread %i starts\n", odp_thread_id());
	fflush(stdout);
#else
	test_atomic_ops.run_test();
#endif
	return arg;
}


int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	odp_coremask_t coremask;
	odp_linux_pthread_t thread_tbl[MAX_WORKERS];
	char str[32];
	int thr_id;
	int num_workers;

	memset(thread_tbl, 0, sizeof(thread_tbl));
	memset(str, 1, sizeof(str));


	odp_init_global();

	odp_coremask_zero(&coremask);

	odp_coremask_from_str("0x1", &coremask);
	odp_coremask_to_str(str, sizeof(str), &coremask);
	printf("\n");
	printf("ODP system info\n");
	printf("---------------\n");
	printf("ODP API version: %s\n",        odp_version_api_str());
	printf("CPU model:       %s\n",        odp_sys_cpu_model_str());
	printf("CPU freq (hz):   %"PRIu64"\n", odp_sys_cpu_hz());
	printf("Cache line size: %i\n",        odp_sys_cache_line_size());
	printf("Core count:      %i\n",        odp_sys_core_count());
	printf("Core mask:       %s\n",        str);

	printf("\n");

	num_workers = odp_sys_core_count() - 1;

	if(num_workers > MAX_WORKERS)
	{
		num_workers = MAX_WORKERS;
	}

	/* Init this thread */
	thr_id = odp_thread_create(0);
	odp_init_local(thr_id);


#ifdef ODP_TEST_ATOMIC
	printf("test atomic basic ops add/sub/inc/dec\n");
	test_atomic_ops.init();
#endif


#ifdef ODP_TEST_ATOMIC
	test_atomic_ops.store();
#endif

	/* Create and init additional threads */
	odp_linux_pthread_create(thread_tbl, num_workers, 1, run_thread, NULL);

	/* Run this thread */
	run_thread(NULL);

	/* Wait for other threads to exit */
	odp_linux_pthread_join(thread_tbl, num_workers);


#ifdef ODP_TEST_ATOMIC
	test_atomic_ops.validate_test();
#endif

	printf("Exit\n\n");

	return 0;
}










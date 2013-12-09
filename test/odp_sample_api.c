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
#include "odp_sample_atomic.h"



#define MAX_WORKERS           31
#define SHM_MSG_POOL_SIZE    (256*1024)
#define SHM_PACKET_POOL_SIZE (256*1024)





#ifdef ODP_TEST_ATOMIC
	struct odp_test_atomic_ops test_atomic_ops = {
		.init = test_atomic_init,
		.store = test_atomic_store,
		.run_test = test_atomic_basic,
		.validate_test = test_atomic_validate,
	};
#endif


typedef struct {
	int msg_id;
	int seq;
} test_message_t;


typedef struct {
	uint32_t h1;
	uint32_t h2;
	uint32_t h3;
	uint32_t h4;
	uint8_t  payload[];
} test_packet_t;


typedef struct {
	odp_spinlock_t lock;
	int counter;
	int foo;
	int bar;
} test_shared_data_t;


static __thread test_shared_data_t *test_shared_data;


#include <time.h>

static void test_shared(int thr)
{
	struct timespec delay;
	delay.tv_sec = 0;
	delay.tv_nsec = 1000;

	while (1) {
		nanosleep(&delay, NULL);

		odp_spinlock_lock(&test_shared_data->lock);

		if (test_shared_data->counter >= 10) {
			odp_spinlock_unlock(&test_shared_data->lock);
			break;
		}

		test_shared_data->counter++;
		printf("  [%i] shared counter %i\n", thr,
		       test_shared_data->counter);

		odp_spinlock_unlock(&test_shared_data->lock);
	}
}


static void *run_thread(void *arg)
{
	int thr;
	odp_buffer_pool_t msg_pool;
	odp_buffer_pool_t pkt_pool;
	odp_buffer_t buf;
	odp_packet_t pkt;

	thr = odp_thread_id();

	printf("Thread %i starts\n", thr);

	test_shared_data = odp_shm_lookup("test_shared_data");
	printf("  [%i] shared data at 0x%p\n",
	       thr, test_shared_data);
	fflush(stdout);

	test_shared(thr);

	/* alloc from message pool*/
	msg_pool = odp_buffer_pool_lookup("msg_pool");

	if (msg_pool == ODP_BUFFER_POOL_INVALID) {
		printf("  [%i] msg_pool not found\n", thr);
		return NULL;
	}

	buf = odp_buffer_alloc(msg_pool);

	if (!odp_buffer_is_valid(buf)) {
		printf("  [%i] msg_pool alloc failed\n", thr);
		return NULL;
	}

	odp_buffer_print(buf);

	/* odp_buffer_free(buf); */

	/* alloc from packet pool*/
	pkt_pool = odp_buffer_pool_lookup("packet_pool");

	if (pkt_pool == ODP_BUFFER_POOL_INVALID)
		printf("  [%i] pkt_pool not found\n", thr);


	buf = odp_buffer_alloc(pkt_pool);

	if (!odp_buffer_is_valid(buf)) {
		printf("  [%i] packet_pool alloc failed\n", thr);
		return NULL;
	}

	pkt = (odp_packet_t) buf;

	odp_packet_print(pkt);

#ifdef ODP_TEST_ATOMIC
	test_atomic_ops.run_test();
#endif

	fflush(stdout);
	return arg;
}



int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	odp_coremask_t coremask;
	odp_linux_pthread_t thread_tbl[MAX_WORKERS];
	char str[32];
	int thr_id;
	int num_workers;
	odp_buffer_pool_t pool;
	void *pool_base;

	memset(thread_tbl, 0, sizeof(thread_tbl));
	memset(str, 1, sizeof(str));


	if (odp_init_global()) {
		printf("ODP global init failed.\n");
		return -1;
	}

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

	if (num_workers > MAX_WORKERS) {
		/* force to max core count */
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

	test_shared_data = odp_shm_reserve("test_shared_data",
					  sizeof(test_shared_data_t), 128);
	memset(test_shared_data, 0, sizeof(test_shared_data_t));
	odp_spinlock_init(&test_shared_data->lock);

	printf("test shared data at %p\n\n", test_shared_data);

	/* Create message pool */

	pool_base = odp_shm_reserve("shm_msg_pool",
				    SHM_MSG_POOL_SIZE, ODP_CACHE_LINE_SIZE);

	pool = odp_buffer_pool_create("msg_pool", pool_base, SHM_MSG_POOL_SIZE,
				      sizeof(test_message_t),
				      ODP_CACHE_LINE_SIZE, ODP_BUFFER_TYPE_RAW);

	if (pool == ODP_BUFFER_POOL_INVALID) {
		printf("Pool create failed.\n");
		return -1;
	}

	/* odp_buffer_pool_print(pool); */


	/* Create packet pool */

	pool_base = odp_shm_reserve("shm_packet_pool",
				    SHM_PACKET_POOL_SIZE, ODP_CACHE_LINE_SIZE);

	pool = odp_buffer_pool_create("packet_pool", pool_base,
				      SHM_PACKET_POOL_SIZE,
				      sizeof(test_packet_t),
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_PACKET);

	if (pool == ODP_BUFFER_POOL_INVALID) {
		printf("Pool create failed.\n");
		return -1;
	}

	/* odp_buffer_pool_print(pool); */


	odp_shm_print_all();

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


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





#include <odp_init.h>
#include <odp_internal.h>

#include <stdio.h>


int odp_init_global(void)
{
	odp_thread_init_global();

	odp_system_info_init();

	if (odp_shm_init_global()) {
		fprintf(stderr, "ODP shm init failed.\n");
		return -1;
	}

	if (odp_buffer_pool_init_global()) {
		fprintf(stderr, "ODP buffer pool init failed.\n");
		return -1;
	}

	if (odp_queue_init_global()) {
		fprintf(stderr, "ODP queue init failed.\n");
		return -1;
	}

	if (odp_schedule_init_global()) {
		fprintf(stderr, "ODP schedule init failed.\n");
		return -1;
	}

	if (odp_pktio_init_global()) {
		fprintf(stderr, "ODP packet io init failed.\n");
		return -1;
	}

	return 0;
}



int odp_init_local(int thr_id)
{
	odp_thread_init_local(thr_id);

	if (odp_pktio_init_local()) {
		fprintf(stderr, "ODP packet io local init failed.\n");
		return -1;
	}

	return 0;
}






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


#include <odp_thread.h>
#include <odp_internal.h>
#include <odp_atomic.h>

#include <string.h>
#include <stdio.h>

#define ODP_MAX_THREADS  128


typedef struct {

	int thr_id;
	int phy_core;

} odp_thread_tbl_t;




/* Globals */
static odp_thread_tbl_t odp_thread_tbl[ODP_MAX_THREADS];
static odp_atomic_int_t num_threads;

/* Thread local */
static __thread odp_thread_tbl_t *odp_this_thread = NULL;



void odp_thread_init_global(void)
{
	memset(odp_thread_tbl, 0, sizeof(odp_thread_tbl));
	num_threads = 0;
}


void odp_thread_init_local(int thr_id)
{
	odp_this_thread = &odp_thread_tbl[thr_id];
}


int odp_thread_create(int phy_core)
{
	int id = -1;

	id = odp_atomic_fetch_add_int(&num_threads, 1);

	if (id < ODP_MAX_THREADS) {

		odp_thread_tbl[id].thr_id   = id;
		odp_thread_tbl[id].phy_core = phy_core;
	}

	return id;
}


int odp_thread_id(void)
{
	return odp_this_thread->thr_id;
}





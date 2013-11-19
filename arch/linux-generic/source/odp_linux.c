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


#define _GNU_SOURCE
#include <sched.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <odp_linux.h>
#include <odp_internal.h>


typedef struct {

	int thr_id;
	void *(*start_routine) (void *);
	void *arg;

} odp_start_args_t;



static void *odp_run_start_routine(void *arg)
{
	odp_start_args_t *start_args = arg;

	/* ODP thread local init */
	odp_init_local(start_args->thr_id);

	return start_args->start_routine(start_args->arg);
}




void odp_linux_pthread_create(odp_linux_pthread_t *thread_tbl, int num, int first_core, void *(*start_routine) (void *), void *arg)
{
	int i;
	cpu_set_t cpu_set;
	odp_start_args_t *start_args;


	memset(thread_tbl, 0, num * sizeof(odp_linux_pthread_t));


	for (i = 0; i < num; i++) {

		pthread_attr_init(&thread_tbl[i].attr);

		CPU_ZERO(&cpu_set);

		/* TODO: cpu id from odp */
		CPU_SET(first_core /*+ i*/, &cpu_set);

		pthread_attr_setaffinity_np(&thread_tbl[i].attr, sizeof(cpu_set_t), &cpu_set);

		start_args = malloc(sizeof(odp_start_args_t));
		memset(start_args, 0, sizeof(odp_start_args_t));
		start_args->start_routine = start_routine;
		start_args->arg           = arg;

		start_args->thr_id        = odp_thread_create(i);

		pthread_create(&thread_tbl[i].thread, &thread_tbl[i].attr, odp_run_start_routine, start_args);
	}

}



void odp_linux_pthread_join(odp_linux_pthread_t *thread_tbl, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		/* Wait thread to exit */
		pthread_join(thread_tbl[i].thread, NULL);
	}

}



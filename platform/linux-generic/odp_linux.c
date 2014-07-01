/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>

#include <helper/odp_linux.h>
#include <odp_internal.h>
#include <odp_thread.h>
#include <odp_init.h>
#include <odp_system_info.h>


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


void odp_linux_pthread_create(odp_linux_pthread_t *thread_tbl, int num,
		int first_core, void *(*start_routine) (void *), void *arg)
{
	int i;
	cpu_set_t cpu_set;
	odp_start_args_t *start_args;
	int core_count;
	int cpu;

	core_count = odp_sys_core_count();

	assert((first_core >= 0) && (first_core < core_count));
	assert((num >= 0) && (num <= core_count));

	memset(thread_tbl, 0, num * sizeof(odp_linux_pthread_t));

	for (i = 0; i < num; i++) {
		pthread_attr_init(&thread_tbl[i].attr);

		CPU_ZERO(&cpu_set);

		cpu = (first_core + i) % core_count;
		CPU_SET(cpu, &cpu_set);

		pthread_attr_setaffinity_np(&thread_tbl[i].attr,
					    sizeof(cpu_set_t), &cpu_set);

		start_args = malloc(sizeof(odp_start_args_t));
		memset(start_args, 0, sizeof(odp_start_args_t));
		start_args->start_routine = start_routine;
		start_args->arg           = arg;

		start_args->thr_id        = odp_thread_create(cpu);

		pthread_create(&thread_tbl[i].thread, &thread_tbl[i].attr,
			       odp_run_start_routine, start_args);
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

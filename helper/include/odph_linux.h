/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Linux helper API
 *
 * This file is an optional helper to odp.h APIs. These functions are provided
 * to ease common setups in a Linux system. User is free to implement the same
 * setups in otherways (not via this API).
 */

#ifndef ODP_LINUX_H_
#define ODP_LINUX_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <pthread.h>
#include <sys/types.h>

/** Linux pthread state information */
typedef struct {
	pthread_t      thread; /**< Pthread ID */
	pthread_attr_t attr;   /**< Pthread attributes */
	int            cpu;    /**< CPU ID */
} odph_linux_pthread_t;


/** Linux process state information */
typedef struct {
	pid_t pid;      /**< Process ID */
	int   cpu;      /**< CPU ID */
	int   status;   /**< Process state change status */
} odph_linux_process_t;


/**
 * Creates and launches pthreads
 *
 * Creates, pins and launches num threads to separate CPU's starting from
 * first_cpu.
 *
 * @param thread_tbl    Thread table
 * @param num           Number of threads to create
 * @param first_cpu     First physical CPU
 * @param start_routine Thread start function
 * @param arg           Thread argument
 */
void odph_linux_pthread_create(odph_linux_pthread_t *thread_tbl,
			      int num, int first_cpu,
			      void *(*start_routine) (void *), void *arg);


/**
 * Waits pthreads to exit
 *
 * Returns when all threads have been exit.
 *
 * @param thread_tbl    Thread table
 * @param num           Number of threads to create
 *
 */
void odph_linux_pthread_join(odph_linux_pthread_t *thread_tbl, int num);


/**
 * Fork a process
 *
 * Forks and sets CPU affinity for the child process
 *
 * @param proc          Pointer to process state info (for output)
 * @param cpu           Destination CPU for the child process
 *
 * @return On success: 1 for the parent, 0 for the child
 *         On failure: -1 for the parent, -2 for the child
 */
int odph_linux_process_fork(odph_linux_process_t *proc, int cpu);


/**
 * Fork a number of processes
 *
 * Forks and sets CPU affinity for child processes
 *
 * @param proc_tbl      Process state info table (for output)
 * @param num           Number of processes to create
 * @param first_cpu     Destination CPU for the first process
 *
 * @return On success: 1 for the parent, 0 for the child
 *         On failure: -1 for the parent, -2 for the child
 */
int odph_linux_process_fork_n(odph_linux_process_t *proc_tbl,
			      int num, int first_cpu);


/**
 * Wait for a number of processes
 *
 * Waits for a number of child processes to terminate. Records process state
 * change status into the process state info structure.
 *
 * @param proc_tbl      Process state info table (previously filled by fork)
 * @param num           Number of processes to wait
 *
 * @return 0 on success, -1 on failure
 */
int odph_linux_process_wait_n(odph_linux_process_t *proc_tbl, int num);


#ifdef __cplusplus
}
#endif

#endif

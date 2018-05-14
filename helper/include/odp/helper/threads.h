/* Copyright (c) 2013-2018, Linaro Limited
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

#ifndef ODPH_LINUX_H_
#define ODPH_LINUX_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <getopt.h>
#include <sys/types.h>

/** @addtogroup odph_linux ODPH LINUX
 *  @{
 */

/** Thread parameter for Linux pthreads and processes */
typedef struct {
	void *(*start)(void *);    /**< Thread entry point function */
	void *arg;                  /**< Argument for the function */
	odp_thread_type_t thr_type; /**< ODP thread type */
	odp_instance_t instance;    /**< ODP instance handle */
} odph_linux_thr_params_t;

/** Linux pthread state information */
typedef struct {
	pthread_t      thread; /**< Pthread ID */
	pthread_attr_t attr;   /**< Pthread attributes */
	int            cpu;    /**< CPU ID */
	/** Copy of thread params */
	odph_linux_thr_params_t thr_params;
} odph_linux_pthread_t;

/** Linux process state information */
typedef struct {
	pid_t pid;      /**< Process ID */
	int   cpu;      /**< CPU ID */
	int   status;   /**< Process state change status */
} odph_linux_process_t;

/** odpthread linux type: whether an ODP thread is a linux thread or process */
typedef enum odph_odpthread_linuxtype_e {
	ODPTHREAD_NOT_STARTED = 0,
	ODPTHREAD_PROCESS,
	ODPTHREAD_PTHREAD
} odph_odpthread_linuxtype_t;

/** odpthread parameters for odp threads (pthreads and processes) */
typedef struct {
	int (*start)(void *);       /**< Thread entry point function */
	void *arg;                  /**< Argument for the function */
	odp_thread_type_t thr_type; /**< ODP thread type */
	odp_instance_t instance;    /**< ODP instance handle */
} odph_odpthread_params_t;

/** The odpthread starting arguments, used both in process or thread mode */
typedef struct {
	odph_odpthread_linuxtype_t linuxtype; /**< process or pthread */
	odph_odpthread_params_t thr_params; /**< odpthread start parameters */
} odph_odpthread_start_args_t;

/** Linux odpthread state information, used both in process or thread mode */
typedef struct {
	odph_odpthread_start_args_t	start_args; /**< start arguments */
	int				cpu;	/**< CPU ID */
	int				last;   /**< true if last table entry */
	/** Variant field mappings for thread/process modes */
	union {
		/** For thread implementation */
		struct {
			pthread_t	thread_id; /**< Pthread ID */
			pthread_attr_t	attr;	/**< Pthread attributes */
		} thread;
		/** For process implementation */
		struct {
			pid_t		pid;	/**< Process ID */
			int		status;	/**< Process state chge status*/
		} proc;
	};
} odph_odpthread_t;

/**
 * Creates and launches odpthreads (as linux threads or processes)
 *
 * Creates, pins and launches threads to separate CPU's based on the cpumask.
 *
 * @param thread_tbl    Thread table
 * @param mask          CPU mask
 * @param thr_params    ODP thread parameters
 *
 * @return Number of threads created
 */
int odph_odpthreads_create(odph_odpthread_t *thread_tbl,
			   const odp_cpumask_t *mask,
			   const odph_odpthread_params_t *thr_params);

/**
 * Waits odpthreads (as linux threads or processes) to exit.
 *
 * Returns when all odpthreads have terminated.
 *
 * @param thread_tbl    Thread table
 * @return The number of joined threads or -1 on error.
 * (error occurs if any of the start_routine return non-zero or if
 *  the thread join/process wait itself failed -e.g. as the result of a kill)
 *
 */
int odph_odpthreads_join(odph_odpthread_t *thread_tbl);

/**
 * Set CPU affinity of the current odp thread
 *
 * CPU affinity determines the CPU core on which the thread is
 * eligible to run.
 *
 * @param cpu           The affinity CPU core
 *
 * @return 0 on success, -1 on failure
 */
int odph_odpthread_setaffinity(const int cpu);

/**
 * Get CPU affinity of the current odp thread
 *
 * CPU affinity determines the CPU core on which the thread is
 * eligible to run.
 *
 * @return positive cpu ID on success, -1 on failure
 */
int odph_odpthread_getaffinity(void);

/**
 * Parse linux helper options
 *
 * Parse the command line options. Pick up (--odph_ prefixed) options meant for
 * the helper itself. When helper options are found, those are removed from
 * argv[] and remaining options are packed to the beginning of the array.
 *
 * @param argc   Argument count
 * @param argv   Argument vector
 *
 * @return New argument count. Original argument count decremented by
 *         the number of removed helper options.
 */
int odph_parse_options(int argc, char *argv[]);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

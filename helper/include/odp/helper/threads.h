/* Copyright (c) 2013-2018, Linaro Limited
 * Copyright (c) 2019, Nokia
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

/** Thread parameters (pthreads and processes) */
typedef struct {
	/** Thread entry point function */
	int (*start)(void *arg);

	/** Argument for the function */
	void *arg;

	/** ODP thread type */
	odp_thread_type_t thr_type;

	/** @deprecated ODP instance handle for odph_odpthreads_create(). */
	odp_instance_t instance;

} odph_thread_param_t;

/** Helper internal thread start arguments. Used both in process and thread
 *  mode */
typedef struct {
	/** Atomic variable to sync status */
	odp_atomic_u32_t status;

	/** Process or thread */
	odp_mem_model_t mem_model;

	/** ODP instance handle */
	odp_instance_t instance;

	/** Thread parameters */
	odph_thread_param_t thr_params;

} odph_thread_start_args_t;

/** Thread state information. Used both in process and thread mode */
typedef struct {
	/** Start arguments */
	odph_thread_start_args_t start_args;

	/** CPU ID */
	int cpu;

	/** 1: last table entry */
	uint8_t last;

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

} odph_thread_t;

/** Linux helper options */
typedef struct {
	odp_mem_model_t mem_model; /**< Process or thread */
} odph_helper_options_t;

/** Legacy thread table entry */
typedef odph_thread_t odph_odpthread_t;

/** Legacy thread parameters */
typedef odph_thread_param_t odph_odpthread_params_t;

/** Common parameters for odph_thread_create() call */
typedef struct {
	/**
	 * ODP instance handle
	 *
	 * This is used for all threads, instead of 'instance' field of per
	 * thread parameters (odph_thread_param_t).
	 */
	odp_instance_t instance;

	/**
	 * CPU mask for thread pinning
	 */
	const odp_cpumask_t *cpumask;

	/**
	 * Select between Linux pthreads and processes
	 *
	 * 0: Use pthreads
	 * 1: Use processes
	 *
	 * Default value is 0.
	 */
	int thread_model;

	/**
	 * Synchronized thread creation
	 *
	 * 0: Don't synchronize thread creation
	 * 1: Create threads in series so that the next thread is created
	 *    only after the previous thread have signaled that it has passed
	 *    ODP local initialization.
	 *
	 * Default value is 0.
	 */
	int sync;

	/**
	 * Thread parameter sharing
	 *
	 * 0: Thread parameters are not shared. The thread parameter table
	 *    contains 'num' elements.
	 * 1: The thread parameter table contains a single element, which is
	 *    used for creating all 'num' threads.
	 *
	 * Default value is 0.
	 */
	int share_param;

} odph_thread_common_param_t;

/**
 * Create and pin threads (as Linux pthreads or processes)
 *
 * This is an updated version of odph_odpthreads_create() call. It may be called
 * multiple times to create threads in steps. Each call launches 'num' threads
 * and pins those to separate CPUs based on the cpumask. Use 'thread_model'
 * parameter to select if Linux pthreads or processes are used. This selection
 * may be overridden with ODP helper options. See e.g. --odph_proc under
 * odph_options() documentation.
 *
 * Thread creation may be synchronized by setting 'sync' parameter. It
 * serializes thread start up (odp_init_local() calls), which helps to
 * stabilize application start up sequence.
 *
 * By default, the thread parameter table contains 'num' elements, one for
 * each thread to be created. However, all threads may be created
 * with a single thread parameter table element by setting 'share_param'
 * parameter.
 *
 * Thread table must be large enough to hold 'num' elements. Also the cpumask
 * must contain 'num' CPUs. Threads are pinned to CPUs in order - the first
 * thread goes to the smallest CPU number of the mask, etc.
 *
 * Launched threads may be waited for exit with odph_thread_join(), or with
 * direct Linux system calls.
 *
 * @param[out] thread        Thread table for output
 * @param      param         Common parameters for all threads to be created
 * @param      thr_param     Table of thread parameters
 * @param      num           Number of threads to create
 *
 * @return Number of threads created
 * @retval -1  On failure
 *
 * @see odph_thread_join()
 */
int odph_thread_create(odph_thread_t thread[],
		       const odph_thread_common_param_t *param,
		       const odph_thread_param_t thr_param[],
		       int num);

/**
 * Wait previously launched threads to exit
 *
 * This is an updated version of odph_odpthreads_join() call. It waits for
 * threads launched with odph_thread_create() to exit. Threads may be waited to
 * exit in a different order than those were created. A function call may be
 * used to wait any number of launched threads to exit. A particular thread
 * may be waited only once.
 *
 * @param thread        Table of threads to exit
 * @param num           Number of threads to exit
 *
 * @return Number of threads exited
 * @retval -1  On failure
 *
 * @see odph_thread_create()
 */
int odph_thread_join(odph_thread_t thread[], int num);

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
 *
 * @deprecated Use odph_thread_create() instead.
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
 * @deprecated Use odph_thread_join() instead.
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
 * <table> <caption> Currently supported options </caption>
 *
 * <tr><th>Command line <th>Environment variable <th>Description
 * <tr><td>--odph_proc  <td>ODPH_PROC_MODE       <td>When defined, threads are
 *                                                   Linux processes. Otherwise,
 *                                                   pthreads are used instead.
 * </table>
 *
 * @param argc   Argument count
 * @param argv   Argument vector
 *
 * @return New argument count. Original argument count decremented by
 *         the number of removed helper options.
 */
int odph_parse_options(int argc, char *argv[]);

/**
 * Get linux helper options
 *
 * Return used ODP helper options. odph_parse_options() must be called before
 * using this function.
 *
 * @param[out] options  ODP helper options
 *
 * @return 0 on success, -1 on failure
 */
int odph_options(odph_helper_options_t *options);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

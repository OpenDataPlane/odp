/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2013-2018 Linaro Limited
 * Copyright (c) 2019-2024 Nokia
 */


/**
 * @file
 *
 * ODP Linux helper API
 *
 * This file is an optional helper to ODP APIs. These functions are provided
 * to ease common setups in a Linux system. User is free to implement the same
 * setups in other ways (not via this API).
 */

#ifndef ODPH_LINUX_H_
#define ODPH_LINUX_H_

#include <odp_api.h>

#include <pthread.h>
#include <getopt.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup odph_thread ODPH THREAD
 * Setup threads/processes
 *
 * @{
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

	/** Minimum stack size in bytes. 0 = use default. */
	uint64_t stack_size;

} odph_thread_param_t;

/** Helper internal thread start arguments. Used both in process and thread
 *  mode */
typedef struct {
	/** Thread status */
	uint32_t status;

	/** Thread initialization status */
	odp_atomic_u32_t *init_status;

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
	 * Synchronized thread creation timeout in nanoseconds
	 *
	 * When synchronized thread creation has been requested, waiting for the
	 * synchronization signal times out once the time indicated by this
	 * parameter has passed.
	 *
	 * If this parameter is 0, the default value is used.
	 *
	 * Default value is ODP_TIME_SEC_IN_NS.
	 */
	uint64_t sync_timeout;

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

/** Thread join result */
typedef struct {
	/** Exit caused by signal */
	odp_bool_t is_sig;

	/**
	 * Exit status of the joined thread/process
	 *
	 * If 'is_sig' is true, then this is the signal number that caused
	 * process exit. Otherwise status of the exited thread/process.
	 */
	int ret;
} odph_thread_join_result_t;

/**
 * Initialize thread params
 *
 * Initialize an odph_thread_param_t to its default values for all fields.
 *
 * @param[out] param Pointer to parameter structure
 */
void odph_thread_param_init(odph_thread_param_t *param);

/**
 * Initialize thread common params
 *
 * Initialize an odph_thread_common_param_t to its default values for all
 * fields.
 *
 * @param[out] param Pointer to parameter structure
 */
void odph_thread_common_param_init(odph_thread_common_param_t *param);

/**
 * Create and pin threads (as Linux pthreads or processes)
 *
 * Function may be called multiple times to create threads in steps. Each call
 * launches 'num' threads and pins those to separate CPUs based on the cpumask.
 * Use 'thread_model' parameter to select if Linux pthreads or processes are
 * used. This selection may be overridden with ODP helper options. See e.g.
 * --odph_proc under odph_options() documentation.
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
 * Use odph_thread_common_param_init() and odph_thread_param_init() to
 * initialize parameters with default values.
 *
 * Thread table must be large enough to hold 'num' elements. Also the cpumask
 * must contain 'num' CPUs. Threads are pinned to CPUs in order - the first
 * thread goes to the smallest CPU number of the mask, etc.
 *
 * Launched threads may be waited for exit with odph_thread_join(), or with
 * direct Linux system calls. If odph_thread_join() is used, the output thread
 * table elements must not be modified during the life time of the threads.
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
 * Function waits for threads launched with odph_thread_create() to exit.
 * Threads may be waited to exit in a different order than those were created.
 * A function call may be used to wait any number of launched threads to exit.
 * A particular thread may be waited only once.
 *
 * Threads are joined in the order they are in 'thread' table. Returns on the
 * first non-zero exit status or other failure.
 *
 * @param thread        Table of threads to exit
 * @param num           Number of threads to exit
 *
 * @return Number of threads successfully joined with zero exit status
 *         (0 ... num)
 * @retval -1  On failure
 *
 * @see odph_thread_create()
 */
int odph_thread_join(odph_thread_t thread[], int num);

/**
 * Wait previously launched threads to exit
 *
 * Similar to odph_thread_join() but outputs results of joined threads and
 * stops only if the actual join operation fails for some thread. Threads are
 * joined in the order they are in 'thread' table. Returns number of threads
 * successfully joined and writes respective exit statuses into the 'res'
 * table.
 *
 * @param thread        Table of threads to exit
 * @param[out] res      Table for result output
 * @param num           Number of threads to exit and results to output
 *
 * @return Number of threads successfully joined (0 ... num)
 * @retval -1  On failure
 *
 * @see odph_thread_create()
 */
int odph_thread_join_result(odph_thread_t thread[], odph_thread_join_result_t res[], int num);

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
 * This function may be called before ODP initialization.
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
 * This function may be called before ODP initialization.
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

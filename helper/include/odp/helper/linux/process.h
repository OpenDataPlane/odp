/* Copyright (c) 2017-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Linux helper for processes
 *
 * This file is not part of ODP APIs, but can be optionally used to ease common
 * setups in a Linux system. User is free to implement the same setups in
 * other ways (not via this file).
 */

#ifndef ODPH_LINUX_PROCESS_H_
#define ODPH_LINUX_PROCESS_H_

#include <odp/helper/threads.h>
#include <odp_api.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odph_linux
 *  @{
 */

/**
 * Fork a process
 *
 * Forks and sets CPU affinity for the child process. Ignores 'start' and 'arg'
 * thread parameters.
 *
 * @param[out] proc        Pointer to process state info (for output)
 * @param      cpu         Destination CPU for the child process
 * @param      thr_params  Linux helper thread parameters
 *
 * @return On success: 1 for the parent, 0 for the child
 *         On failure: -1 for the parent, -2 for the child
 */
int odph_linux_process_fork(odph_linux_process_t *proc, int cpu,
			    const odph_linux_thr_params_t *thr_params);

/**
 * Fork a number of processes
 *
 * Forks and sets CPU affinity for child processes. Ignores 'start' and 'arg'
 * thread parameters.
 *
 * @param[out] proc_tbl    Process state info table (for output)
 * @param      mask        CPU mask of processes to create
 * @param      thr_params  Linux helper thread parameters
 *
 * @return On success: 1 for the parent, 0 for the child
 *         On failure: -1 for the parent, -2 for the child
 */
int odph_linux_process_fork_n(odph_linux_process_t *proc_tbl,
			      const odp_cpumask_t *mask,
			      const odph_linux_thr_params_t *thr_params);

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

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

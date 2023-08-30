/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Linaro Limited
 */

/**
 * @file
 *
 * ODP CPU API
 */

#ifndef ODP_API_SPEC_CPU_H_
#define ODP_API_SPEC_CPU_H_
#include <odp/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>

/** @defgroup odp_cpu ODP CPU
 *  CPU cycle count, frequency, etc. information.
 *  @{
 */

/**
 * CPU identifier
 *
 * Determine CPU identifier on which the calling is running. CPU numbering is
 * system specific.
 *
 * @return CPU identifier
 */
int odp_cpu_id(void);

/**
 * CPU count
 *
 * Report the number of CPU's available to this ODP program.
 * This may be smaller than the number of (online) CPU's in the system.
 *
 * @return Number of available CPU's
 */
int odp_cpu_count(void);

/**
 * CPU model name of this CPU
 *
 * Returns the CPU model name of this CPU.
 *
 * @return Pointer to CPU model name string
 */
const char *odp_cpu_model_str(void);

/**
 * CPU model name of a CPU
 *
 * Return CPU model name of the specified CPU.
 *
 * @param id    CPU ID
 *
 * @return Pointer to CPU model name string
 */
const char *odp_cpu_model_str_id(int id);

/**
 * Current CPU frequency in Hz
 *
 * Returns current frequency of this CPU. Returns zero if the frequency
 * request is not supported.
 *
 * @return CPU frequency in Hz
 * @retval 0 Not supported or a failure
 */
uint64_t odp_cpu_hz(void);

/**
 * Current CPU frequency of a CPU (in Hz)
 *
 * Returns current frequency of the specified CPU. Returns zero if the frequency
 * request is not supported.
 *
 * @param id    CPU ID
 *
 * @return CPU frequency in Hz
 * @retval 0 Not supported or a failure
 */
uint64_t odp_cpu_hz_id(int id);

/**
 * Maximum CPU frequency in Hz
 *
 * Returns the maximum frequency of this CPU. Returns zero if the frequency
 * request is not supported.
 *
 * @return CPU frequency in Hz
 * @retval 0 Not supported or a failure
 */
uint64_t odp_cpu_hz_max(void);

/**
 * Maximum CPU frequency of a CPU (in Hz)
 *
 * Returns the maximum frequency of the specified CPU. Returns zero if the
 * frequency request is not supported.
 *
 * @param id    CPU ID
 *
 * @return CPU frequency in Hz
 * @retval 0 Not supported or a failure
 */
uint64_t odp_cpu_hz_max_id(int id);

/**
 * Current CPU cycle count
 *
 * Return current CPU cycle count. Cycle count may not be reset at ODP init
 * and thus may wrap back to zero between two calls. Use odp_cpu_cycles_max()
 * to read the maximum count value after which it wraps. Cycle count frequency
 * follows the CPU frequency and thus may change at any time. Cycle count should
 * not be used for time measurements due to the possibility of frequency
 * variation. The count may advance in steps larger than one. Use
 * odp_cpu_cycles_resolution() to read the step size.
 *
 * Returns zero if CPU cycle counter is not supported.
 *
 * @return Current CPU cycle count
 * @retval 0 Not supported
 */
uint64_t odp_cpu_cycles(void);

/**
 * CPU cycle count difference
 *
 * Calculate difference between cycle counts c1 and c2. Parameter c1 must be the
 * first cycle count sample and c2 the second. The function handles correctly
 * single cycle count wrap between c1 and c2.
 *
 * @param c2    Second cycle count
 * @param c1    First cycle count
 *
 * @return CPU cycles from c1 to c2
 */
uint64_t odp_cpu_cycles_diff(uint64_t c2, uint64_t c1);

/**
 * Maximum CPU cycle count
 *
 * Maximum CPU cycle count value before it wraps back to zero. Returns zero
 * if CPU cycle counter is not supported.
 *
 * @return Maximum CPU cycle count value
 * @retval 0 Not supported
 */
uint64_t odp_cpu_cycles_max(void);

/**
 * Resolution of CPU cycle count
 *
 * CPU cycle count may advance in steps larger than one. This function returns
 * resolution of odp_cpu_cycles() in CPU cycles. Returns zero if CPU cycle
 * counter is not supported.
 *
 * @return CPU cycle count resolution in CPU cycles
 * @retval 0 Not supported
 */
uint64_t odp_cpu_cycles_resolution(void);

/**
 * Pause CPU execution for a short while
 *
 * This call is intended for tight loops which poll a shared resource. A short
 * pause within the loop may save energy and improve system performance as
 * CPU polling frequency is reduced.
 */
void odp_cpu_pause(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/visibility_end.h>
#endif

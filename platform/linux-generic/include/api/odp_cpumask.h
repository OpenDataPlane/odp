/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP CPU masks and enumeration
 */

#ifndef ODP_CPUMASK_H_
#define ODP_CPUMASK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <sched.h>

#include <odp_std_types.h>

/** @addtogroup odp_scheduler
 *  CPU mask operations.
 *  @{
 */

/**
 * CPU mask
 *
 * Don't access directly, use access functions.
 */
typedef struct odp_cpumask_t {
	cpu_set_t set; /**< @private Mask*/
} odp_cpumask_t;

/**
 * Add CPU mask bits from a string
 *
 * @param mask   CPU mask to modify
 * @param str    Hexadecimal digits in a string. CPU #0 is located
 *               at the least significant bit (0x1).
 */
void odp_cpumask_from_str(odp_cpumask_t *mask, const char *str);

/**
 * Write CPU mask as a string of hexadecimal digits
 *
 * @param mask   CPU mask
 * @param str    String for output
 * @param len    Size of string length (incl. ending zero)
 */
void odp_cpumask_to_str(const odp_cpumask_t *mask, char *str, int len);

/**
 * Clear entire mask
 * @param mask	CPU mask to flush with zero value
 */
void odp_cpumask_zero(odp_cpumask_t *mask);

/**
 * Add cpu to mask
 * @param mask  add cpu number in CPU mask
 * @param cpu   CPU number
 */
void odp_cpumask_set(odp_cpumask_t *mask, int cpu);

/**
 * Remove cpu from mask
 * @param mask  clear cpu number from CPU mask
 * @param cpu   CPU number
 */
void odp_cpumask_clr(odp_cpumask_t *mask, int cpu);

/**
 * Test if cpu is a member of mask
 * @param mask  CPU mask to check if cpu num set or not
 * @param cpu   CPU number
 * @return      non-zero if set otherwise 0
 */
int odp_cpumask_isset(const odp_cpumask_t *mask, int cpu);

/**
 * Count number of cpus in mask
 * @param mask  CPU mask
 * @return cpumask count
 */
int odp_cpumask_count(const odp_cpumask_t *mask);

/**
 * Logical AND over two source masks.
 *
 * @param dest    Destination mask, can be one of the source masks
 * @param src1    Source mask 1
 * @param src2    Source mask 2
 */
void odp_cpumask_and(odp_cpumask_t *dest, odp_cpumask_t *src1,
		     odp_cpumask_t *src2);

/**
 * Logical OR over two source masks.
 *
 * @param dest    Destination mask, can be one of the source masks
 * @param src1    Source mask 1
 * @param src2    Source mask 2
 */
void odp_cpumask_or(odp_cpumask_t *dest, odp_cpumask_t *src1,
		    odp_cpumask_t *src2);

/**
 * Logical XOR over two source masks.
 *
 * @param dest    Destination mask, can be one of the source masks
 * @param src1    Source mask 1
 * @param src2    Source mask 2
 */
void odp_cpumask_xor(odp_cpumask_t *dest, odp_cpumask_t *src1,
		     odp_cpumask_t *src2);

/**
 * Test if two masks contain the same cpus
 */
int odp_cpumask_equal(const odp_cpumask_t *mask1,
		      const odp_cpumask_t *mask2);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

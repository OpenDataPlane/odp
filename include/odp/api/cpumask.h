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

#include <sys/types.h>
#include <odp/config.h>

/** @addtogroup odp_scheduler
 *  CPU mask operations.
 *  @{
 */

/**
 * @def ODP_CPUMASK_STR_SIZE
 * Minimum size of output buffer for odp_cpumask_to_str()
 */

/**
 * Add CPU mask bits from a string
 *
 * @param mask   CPU mask to modify
 * @param str    Hexadecimal digits in a string. CPU #0 is located
 *               at the least significant bit (0x1).
 */
void odp_cpumask_from_str(odp_cpumask_t *mask, const char *str);

/**
 * Format CPU mask as a string of hexadecimal digits
 *
 * @param mask CPU mask to format
 * @param[out] str Output buffer (use ODP_CPUMASK_STR_SIZE)
 * @param size Size of output buffer
 *
 * @return number of characters written (including terminating null char)
 * @retval <0 on failure (buffer too small)
 */
ssize_t odp_cpumask_to_str(const odp_cpumask_t *mask, char *str, ssize_t size);

/**
 * Clear entire CPU mask
 * @param mask CPU mask to clear
 */
void odp_cpumask_zero(odp_cpumask_t *mask);

/**
 * Add CPU to mask
 * @param mask  CPU mask to update
 * @param cpu   CPU number
 */
void odp_cpumask_set(odp_cpumask_t *mask, int cpu);

/**
 * Remove CPU from mask
 * @param mask  CPU mask to update
 * @param cpu   CPU number
 */
void odp_cpumask_clr(odp_cpumask_t *mask, int cpu);

/**
 * Test if CPU is a member of mask
 *
 * @param mask  CPU mask to test
 * @param cpu   CPU number
 * @return      non-zero if set
 * @retval      0 if not set
 */
int odp_cpumask_isset(const odp_cpumask_t *mask, int cpu);

/**
 * Count number of CPU's in mask
 *
 * @param mask  CPU mask
 * @return population count
 */
int odp_cpumask_count(const odp_cpumask_t *mask);

/**
 * Member-wise AND over two CPU masks
 *
 * @param dest    Destination CPU mask (may be one of the source masks)
 * @param src1    Source CPU mask 1
 * @param src2    Source CPU mask 2
 */
void odp_cpumask_and(odp_cpumask_t *dest, const odp_cpumask_t *src1,
		     const odp_cpumask_t *src2);

/**
 * Member-wise OR over two CPU masks
 *
 * @param dest    Destination CPU mask (may be one of the source masks)
 * @param src1    Source CPU mask 1
 * @param src2    Source CPU mask 2
 */
void odp_cpumask_or(odp_cpumask_t *dest, const odp_cpumask_t *src1,
		    const odp_cpumask_t *src2);

/**
 * Member-wise XOR over two CPU masks
 *
 * @param dest    Destination CPU mask (may be one of the source masks)
 * @param src1    Source CPU mask 1
 * @param src2    Source CPU mask 2
 */
void odp_cpumask_xor(odp_cpumask_t *dest, const odp_cpumask_t *src1,
		     const odp_cpumask_t *src2);

/**
 * Test if two CPU masks contain the same CPU's
 *
 * @param mask1    CPU mask 1
 * @param mask2    CPU mask 2
 *
 * @retval non-zero if CPU masks equal
 * @retval 0 if CPU masks not equal
 */
int odp_cpumask_equal(const odp_cpumask_t *mask1,
		      const odp_cpumask_t *mask2);

/**
 * Copy a CPU mask
 *
 * @param dest    Destination CPU mask
 * @param src     Source CPU mask
 */
void odp_cpumask_copy(odp_cpumask_t *dest, const odp_cpumask_t *src);

/**
 * Find first set CPU in mask
 *
 * @param mask    CPU mask
 *
 * @return cpu number
 * @retval <0 if no CPU found
 */
int odp_cpumask_first(const odp_cpumask_t *mask);

/**
 * Find last set CPU in mask
 *
 * @param mask    CPU mask
 *
 * @return cpu number
 * @retval <0 if no CPU found
 */
int odp_cpumask_last(const odp_cpumask_t *mask);

/**
 * Find next set CPU in mask
 *
 * Finds the next CPU in the CPU mask, starting at the CPU passed.
 * Use with odp_cpumask_first to traverse a CPU mask, e.g.
 *
 * int cpu = odp_cpumask_first(&mask);
 * while (0 <= cpu) {
 *     ...
 *     ...
 *     cpu = odp_cpumask_next(&mask, cpu);
 * }
 *
 * @param mask        CPU mask
 * @param cpu         CPU to start from
 *
 * @return cpu number
 * @retval <0 if no CPU found
 *
 * @see odp_cpumask_first()
 */
int odp_cpumask_next(const odp_cpumask_t *mask, int cpu);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

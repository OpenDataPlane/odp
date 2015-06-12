/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP thread masks
 */

#ifndef ODP_API_THRMASK_H_
#define ODP_API_THRMASK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/std_types.h>

/** @addtogroup odp_thread
 *  Thread mask operations.
 *  @{
 */

/**
 * @def ODP_THRMASK_STR_SIZE
 * Minimum size of output buffer for odp_thrmask_to_str()
 */

/**
 * Add thread mask bits from a string
 *
 * @param[out] mask  Thread mask to modify
 * @param      str   Hexadecimal digits in a string. Thread ID zero is located
 *                   at the least significant bit (0x1).
 */
void odp_thrmask_from_str(odp_thrmask_t *mask, const char *str);

/**
 * Format Thread mask as a string of hexadecimal digits
 *
 * @param mask       Thread mask to format
 * @param[out] str   Output buffer (use ODP_THRMASK_STR_SIZE)
 * @param size       Size of output buffer
 *
 * @return number of characters written (including terminating null char)
 * @retval <0 on failure (buffer too small)
 */
int32_t odp_thrmask_to_str(const odp_thrmask_t *mask, char *str, int32_t size);

/**
 * Clear entire thread mask
 * @param mask       Thread mask to clear
 */
void odp_thrmask_zero(odp_thrmask_t *mask);

/**
 * Add thread to mask
 * @param mask       Thread mask to update
 * @param thr        Thread ID
 */
void odp_thrmask_set(odp_thrmask_t *mask, int thr);

/**
 * Set all threads in mask
 *
 * Set all possible threads in the mask. All threads from 0 to
 * odp_thrmask_count() minus one are set, regardless of which threads are
 * actually active.
 *
 * @param mask       Thread mask to set
 */
void odp_thrmask_setall(odp_thrmask_t *mask);

/**
 * Remove thread from mask
 * @param mask       Thread mask to update
 * @param thr        Thread ID
 */
void odp_thrmask_clr(odp_thrmask_t *mask, int thr);

/**
 * Test if thread is a member of mask
 *
 * @param mask       Thread mask to test
 * @param thr        Thread ID
 *
 * @return non-zero if set
 * @retval 0 if not set
 */
int odp_thrmask_isset(const odp_thrmask_t *mask, int thr);

/**
 * Count number of threads set in mask
 *
 * @param mask       Thread mask
 *
 * @return population count
 */
int odp_thrmask_count(const odp_thrmask_t *mask);

/**
 * Member-wise AND over two thread masks
 *
 * @param dest       Destination thread mask (may be one of the source masks)
 * @param src1       Source thread mask 1
 * @param src2       Source thread mask 2
 */
void odp_thrmask_and(odp_thrmask_t *dest, const odp_thrmask_t *src1,
		     const odp_thrmask_t *src2);

/**
 * Member-wise OR over two thread masks
 *
 * @param dest       Destination thread mask (may be one of the source masks)
 * @param src1       Source thread mask 1
 * @param src2       Source thread mask 2
 */
void odp_thrmask_or(odp_thrmask_t *dest, const odp_thrmask_t *src1,
		    const odp_thrmask_t *src2);

/**
 * Member-wise XOR over two thread masks
 *
 * @param dest       Destination thread mask (may be one of the source masks)
 * @param src1       Source thread mask 1
 * @param src2       Source thread mask 2
 */
void odp_thrmask_xor(odp_thrmask_t *dest, const odp_thrmask_t *src1,
		     const odp_thrmask_t *src2);

/**
 * Test if two thread masks contain the same threads
 *
 * @param mask1      Thread mask 1
 * @param mask2      Thread mask 2
 *
 * @retval non-zero if thread masks equal
 * @retval 0 if thread masks not equal
 */
int odp_thrmask_equal(const odp_thrmask_t *mask1,
		      const odp_thrmask_t *mask2);

/**
 * Copy a thread mask
 *
 * @param dest       Destination thread mask
 * @param src        Source thread mask
 */
void odp_thrmask_copy(odp_thrmask_t *dest, const odp_thrmask_t *src);

/**
 * Find first set thread in mask
 *
 * @param mask       thread mask
 *
 * @return Thread ID
 * @retval <0 if no thread found
 */
int odp_thrmask_first(const odp_thrmask_t *mask);

/**
 * Find last set thread in mask
 *
 * @param mask       Thread mask
 *
 * @return Thread ID
 * @retval <0 if no thread found
 */
int odp_thrmask_last(const odp_thrmask_t *mask);

/**
 * Find next set thread in mask
 *
 * Finds the next thread in the thread mask, starting at the thread passed.
 * Use with odp_thrmask_first to traverse a thread mask, e.g.
 *
 * int thr = odp_thrmask_first(&mask);
 * while (0 <= thr) {
 *     ...
 *     ...
 *     thr = odp_thrmask_next(&mask, thr);
 * }
 *
 * @param mask       Thread mask
 * @param thr        Thread to start from
 *
 * @return Thread ID
 * @retval <0 if no thread found
 *
 * @see odp_thrmask_first()
 */
int odp_thrmask_next(const odp_thrmask_t *mask, int thr);

/**
 * Worker thread mask
 *
 * Initializes thread mask with current worker threads and returns the count
 * set.
 *
 * @param[out] mask  Thread mask to initialize
 *
 * @return Number of threads in the mask
 */
int odp_thrmask_worker(odp_thrmask_t *mask);

/**
 * Control thread mask
 *
 * Initializes thread mask with current control threads and returns the count
 * set.
 *
 * @param[out] mask  Thread mask to initialize
 *
 * @return Number of threads in the mask
 */
int odp_thrmask_control(odp_thrmask_t *mask);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

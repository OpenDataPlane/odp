/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP core masks and enumeration
 */

#ifndef ODP_COREMASK_H_
#define ODP_COREMASK_H_

#ifdef __cplusplus
extern "C" {
#endif



#include <odp_std_types.h>

/** @addtogroup odp_scheduler
 *  Core mask operations.
 *  @{
 */

/** @internal */
#define ODP_COREMASK_SIZE_U64  1

/**
 * Core mask
 *
 * Don't access directly, use access functions.
 */
typedef struct odp_coremask_t {
	uint64_t _u64[ODP_COREMASK_SIZE_U64]; /**< @private Mask*/

} odp_coremask_t;



/**
 * Add core mask bits from a string
 *
 * @param str    Hexadecimal digits in a string. Core #0 is located
 *               at the least significant bit (0x1).
 * @param mask   Core mask to modify
 *
 * @note Supports currently only core indexes upto 63
 */
void odp_coremask_from_str(const char *str, odp_coremask_t *mask);

/**
 * Write core mask as a string of hexadecimal digits
 *
 * @param str    String for output
 * @param len    Size of string length (incl. ending zero)
 * @param mask   Core mask
 *
 * @note Supports currently only core indexes upto 63
 */
void odp_coremask_to_str(char *str, int len, const odp_coremask_t *mask);


/**
 * Add core mask bits from a u64 array
 *
 * In the array core #0 is located at the least significant bit
 * of the first word (u64[0] = 0x1).
 *
 * Examples
 * core 0:  u64[0] = 0x1
 * core 1:  u64[0] = 0x2
 * ...
 * core 63: u64[0] = 0x8000 0000 0000 0000
 * core 64: u64[0] = 0x0, u64[1] = 0x1
 * core 65: u64[0] = 0x0, u64[1] = 0x2
 *
 * @param u64    An array of u64 bit words
 * @param num    Number of u64 words in the array
 * @param mask   Core mask to modify
 *
 * @note Supports currently only core indexes upto 63
 */
void odp_coremask_from_u64(const uint64_t *u64, int num, odp_coremask_t *mask);

/**
 * Clear entire mask
 * @param mask	Core mask to flush with zero value
 */
static inline void odp_coremask_zero(odp_coremask_t *mask)
{
	mask->_u64[0] = 0;
}

/**
 * Add core to mask
 * @param core  Core number
 * @param mask  add core number in core mask
 */
void odp_coremask_set(int core, odp_coremask_t *mask);

/**
 * Remove core from mask
 * @param core  Core number
 * @param mask  clear core number from core mask
 */
void odp_coremask_clr(int core, odp_coremask_t *mask);

/**
 * Test if core is a member of mask
 * @param core  Core number
 * @param mask  Core mask to check if core num set or not
 * @return      non-zero if set otherwise 0
 */
int odp_coremask_isset(int core, const odp_coremask_t *mask);

/**
 * Count number of cores in mask
 * @param mask  Core mask
 * @return coremask count
 */
int odp_coremask_count(const odp_coremask_t *mask);



/**
 * Logical AND over two source masks.
 *
 * @param dest    Destination mask, can be one of the source masks
 * @param src1    Source mask 1
 * @param src2    Source mask 2
 */
static inline void odp_coremask_and(odp_coremask_t *dest, odp_coremask_t *src1,
				    odp_coremask_t *src2)
{
	dest->_u64[0] = src1->_u64[0] & src2->_u64[0];
}

/**
 * Logical OR over two source masks.
 *
 * @param dest    Destination mask, can be one of the source masks
 * @param src1    Source mask 1
 * @param src2    Source mask 2
 */
static inline void odp_coremask_or(odp_coremask_t *dest, odp_coremask_t *src1,
				   odp_coremask_t *src2)
{
	dest->_u64[0] = src1->_u64[0] | src2->_u64[0];
}

/**
 * Logical XOR over two source masks.
 *
 * @param dest    Destination mask, can be one of the source masks
 * @param src1    Source mask 1
 * @param src2    Source mask 2
 */
static inline void odp_coremask_xor(odp_coremask_t *dest, odp_coremask_t *src1,
				    odp_coremask_t *src2)
{
	dest->_u64[0] = src1->_u64[0] ^ src2->_u64[0];
}

/**
 * Test if two masks contain the same cores
 */
static inline int odp_coremask_equal(odp_coremask_t *mask1,
				     odp_coremask_t *mask2)
{
	return (mask1->_u64[0] == mask2->_u64[0]);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif

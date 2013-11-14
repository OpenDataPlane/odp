/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *    * Neither the name of Linaro Limited nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIALDAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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



#define ODP_COREMASK_SIZE_U64  1


/**
 * Core mask
 *
 * Don't access directly, use access functions.
 */
typedef struct odp_coremask_t {

	uint64_t _u64[ODP_COREMASK_SIZE_U64];

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
 */
void odp_coremask_zero(odp_coremask_t *mask);

/**
 * Add core to mask
 */
void odp_coremask_set(int core, odp_coremask_t *mask);

/**
 * Remove core from mask
 */
void odp_coremask_clr(int core, odp_coremask_t *mask);

/**
 * Test if core is a member of mask
 */
int odp_coremask_isset(int core, odp_coremask_t *mask);

/**
 * Count number of cores in mask
 */
int odp_coremask_count(odp_coremask_t *mask);

/**
 * Logical AND over two source masks.
 *
 * @param dest    Destination mask, can be one of the source masks
 * @param src1    Source mask 1
 * @param src2    Source mask 2
 */
void odp_coremask_and(odp_coremask_t *dest, odp_coremask_t *src1, odp_coremask_t *src2);

/**
 * Logical OR over two source masks.
 *
 * @param dest    Destination mask, can be one of the source masks
 * @param src1    Source mask 1
 * @param src2    Source mask 2
 */
void odp_coremask_or(odp_coremask_t *dest, odp_coremask_t *src1, odp_coremask_t *src2);

/**
 * Logical XOR over two source masks.
 *
 * @param dest    Destination mask, can be one of the source masks
 * @param src1    Source mask 1
 * @param src2    Source mask 2
 */
void odp_coremask_xor(odp_coremask_t *dest, odp_coremask_t *src1, odp_coremask_t *src2);


/**
 * Test if two masks contain the same cores
 */
int odp_coremask_equal(odp_coremask_t *mask1, odp_coremask_t *mask2);












#ifdef __cplusplus
}
#endif

#endif








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
 * ODP atomic operations
 */

#ifndef ODP_ATOMIC_H_
#define ODP_ATOMIC_H_

#ifdef __cplusplus
extern "C" {
#endif



#include <odp_std_types.h>




/**
 * Atomic int
 */
typedef int32_t odp_atomic_int_t;

/**
 * Atomic unsigned int 64 bits
 */
typedef uint64_t odp_atomic_u64_t;

/**
 * Atomic unsigned int 32 bits
 */
typedef uint32_t odp_atomic_u32_t;



/**
 * Initialize an atomic variable
 *
 * @param ptr    An integer atomic variable
 *
 */
void odp_atomic_init_int(odp_atomic_int_t *ptr);

/**
 * Read a value from a atomic int variable
 *
 * @param ptr    An atomic variable
 *
 */
int odp_atomic_load_int(odp_atomic_int_t *ptr);

/**
 * Store a value to a atomic int variable
 *
 * @param ptr    An atomic variable
 * @param new_value  Store new_value to a variable
 *
 */
void odp_atomic_store_int(odp_atomic_int_t *ptr, int new_value);

/**
 * Atomic fetch and add an integer value
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 */
int odp_atomic_fetch_add_int(odp_atomic_int_t *ptr, int value);

/**
 * Atomic fetch and sub an int value
 *
 * @param ptr    An atomic int variable
 * @param value  A value to be subtracted from the variable
 *
 */
int odp_atomic_fetch_sub_int(odp_atomic_int_t *ptr, int value);

/**
 * Implicit increment operation by 1 on odp_atomic_fetch_add_int
 * api
 *
 * @param ptr    An atomic variable
 *
 */
void odp_atomic_inc_int(odp_atomic_int_t *ptr);

/**
 * Implicit decrement operation by 1 on odp_atomic_fetch_sub_int
 * api
 *
 * @param ptr    An atomic variable
 *
 */
void odp_atomic_dec_int(odp_atomic_int_t *ptr);


/**
 * Initialize an atomic u32 variable
 *
 * @param ptr    An atomic variable
 *
 */
void odp_atomic_init_u32(odp_atomic_u32_t *ptr);

/**
 * Read a value from a atomic u32 variable
 *
 * @param ptr    An atomic variable
 *
 */
uint32_t odp_atomic_load_u32(odp_atomic_u32_t *ptr);

/**
 * Store a value to a atomic u32 variable
 *
 * @param ptr    An atomic variable
 * @param new_value  Store new_value to a variable
 *
 */
void odp_atomic_store_u32(odp_atomic_u32_t *ptr, uint32_t new_value);

/**
 * Atomic fetch and add  u32 value
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 */
uint32_t odp_atomic_fetch_add_u32(odp_atomic_u32_t *ptr, uint32_t value);

/**
 * Atomic fetch and sub u32 value
 *
 * @param ptr    An atomic variable
 * @param value  A value to be sub to the variable
 *
 */
uint32_t odp_atomic_fetch_sub_u32(odp_atomic_u32_t *ptr, uint32_t value);

/**
 * Implicit increment operation by 1 on odp_atomic_fetch_add_u32
 * api
 *
 * @param ptr    An atomic variable
 *
 */
void odp_atomic_inc_u32(odp_atomic_u32_t *ptr);

/**
 * Implicit decrement operation by 1 on odp_atomic_fetch_sub_u32
 * api
 *
 * @param ptr    An atomic variable
 *
 */
void odp_atomic_dec_u32(odp_atomic_u32_t *ptr);

/**
 * Adds a value to an atomic 64 bit variable
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 */
void odp_atomic_add_u64(odp_atomic_u64_t *ptr, uint64_t value);


/**
 * Initialize an atomic counter
 *
 * @param ptr    An atomic variable
 *
 */
void odp_atomic_init_u64(odp_atomic_u64_t *ptr);

/**
 * Read a value from a atomic 64 bit variable
 *
 * @param ptr    An atomic variable
 *
 */
uint64_t odp_atomic_load_u64(odp_atomic_u64_t *ptr);

/**
 * Store a value to a atomic 64 bit variable
 *
 * @param ptr    An atomic variable
 * @param new_value  Store new_value to a variable
 *
 */
void odp_atomic_store_u64(odp_atomic_u64_t *ptr, uint64_t new_value);

/**
 * Atomic fetch and add an 64 bit value
 *
 * @param ptr    An atomic variable
 * @param value  A value to be added to the variable
 *
 */
uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *ptr, uint64_t value);

/**
 * Atomic fetch and sub an 64 bit value
 *
 * @param ptr    An atomic variable
 * @param value  A value to be sub to the variable
 *
 */
uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *ptr, uint64_t value);

/**
 * Implicit increment operation by 1 on odp_atomic_fetch_add_u64
 * api
 *
 * @param ptr    An atomic variable
 *
 */
void odp_atomic_inc_u64(odp_atomic_u64_t *ptr);

/**
 * Implicit decrement operation by 1 on odp_atomic_fetch_sub_u64
 * api
 *
 * @param ptr    An atomic variable
 *
 */
void odp_atomic_dec_u64(odp_atomic_u64_t *ptr);


#ifdef __cplusplus
}
#endif

#endif

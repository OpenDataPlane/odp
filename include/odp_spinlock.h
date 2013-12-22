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
 * ODP spinlock
 */

#ifndef ODP_SPINLOCK_H_
#define ODP_SPINLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp_std_types.h>


/**
 * ODP spinlock
 */
typedef struct odp_spinlock_t {
	int lock;
} odp_spinlock_t;


/**
 * Init spinlock
 *
 * @param spinlock  Spinlock
 */
void odp_spinlock_init(odp_spinlock_t *spinlock);


/**
 * Lock spinlock
 *
 * @param spinlock  Spinlock
 */
void odp_spinlock_lock(odp_spinlock_t *spinlock);


/**
 * Try to lock spinlock
 *
 * @param spinlock  Spinlock
 *
 * @return 1 if the lock was taken, otherwise 0.
 */
int odp_spinlock_trylock(odp_spinlock_t *spinlock);


/**
 * Unlock spinlock
 *
 * @param spinlock  Spinlock
 */
void odp_spinlock_unlock(odp_spinlock_t *spinlock);


/**
 * Test if spinlock is locked
 *
 * @param spinlock  Spinlock
 *
 * @return 1 if the lock is locked, otherwise 0.
 */
int odp_spinlock_is_locked(odp_spinlock_t *spinlock);




#ifdef __cplusplus
}
#endif

#endif








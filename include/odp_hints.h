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
 * ODP compiler hints
 */

#ifndef ODP_HINTS_H_
#define ODP_HINTS_H_

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __GNUC__



#define ODP_HOT_CODE    __attribute__((__hot__))
#define ODP_COLD_CODE   __attribute__((__cold__))


#define odp_likely(x)   __builtin_expect((x), 1)
#define odp_unlikely(x) __builtin_expect((x), 0)


/*
 * __builtin_prefetch (const void *addr, rw, locality)
 *
 * rw 0..1       (0: read, 1: write)
 * locality 0..3 (0: dont leave to cache, 3: leave on all cache levels)
 */
#define odp_prefetch(x)         __builtin_prefetch((x), 0, 3)

#define odp_prefetch_store(x)   __builtin_prefetch((x), 0, 3)



#else

#define ODP_HOT_CODE
#define ODP_COLD_CODE
#define odp_likely(x)
#define odp_unlikely(x)
#define odp_prefetch(x)
#define odp_prefetch_store(x)

#endif



#ifdef __cplusplus
}
#endif

#endif








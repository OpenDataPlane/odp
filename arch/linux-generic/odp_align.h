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
 * ODP alignments
 */

#ifndef ODP_ALIGN_H_
#define ODP_ALIGN_H_

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __GNUC__

#define ODP_ALIGNED(x)      __attribute__((__aligned__(x)))

#if defined __x86_64__ || defined __i386__

#define ODP_CACHE_LINE_SIZE 64

#elif defined __arm__

#define ODP_CACHE_LINE_SIZE 64

#elif defined __OCTEON__

#define ODP_CACHE_LINE_SIZE 128

#else
#error GCC target not found
#endif

#else
#error Non-gcc compatible compiler
#endif


#define ODP_PAGE_SIZE       4096

#define ODP_CACHE_LINE_SIZE_ROUNDUP(x)\
		(ODP_CACHE_LINE_SIZE * (((x) + ODP_CACHE_LINE_SIZE - 1) / ODP_CACHE_LINE_SIZE))

#define ODP_PAGE_SIZE_ROUNDUP(x)\
		(ODP_PAGE_SIZE * (((x) + ODP_PAGE_SIZE - 1) / ODP_PAGE_SIZE))


#define ODP_ALIGNED_CACHE   ODP_ALIGNED(ODP_CACHE_LINE_SIZE)
#define ODP_ALIGNED_PAGE    ODP_ALIGNED(ODP_PAGE_SIZE)




#ifdef __cplusplus
}
#endif

#endif








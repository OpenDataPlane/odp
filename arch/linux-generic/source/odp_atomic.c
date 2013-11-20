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





#include <odp_atomic.h>

void odp_atomic_init_int(odp_atomic_int_t *ptr)
{
	*ptr = 0;
}

int odp_atomic_load_int(odp_atomic_int_t *ptr)
{
	return *ptr;
}

void odp_atomic_store_int(odp_atomic_int_t *ptr, int new_value)
{
	*ptr = new_value;
}

int odp_atomic_fetch_add_int(odp_atomic_int_t *ptr, int value)
{
	return __sync_fetch_and_add(ptr, value);
}

int odp_atomic_fetch_sub_int(odp_atomic_int_t *ptr, int value)
{
	return __sync_fetch_and_sub(ptr, value);
}

void odp_atomic_inc_int(odp_atomic_int_t *ptr)
{
	odp_atomic_fetch_add_int(ptr, 1);
}

void odp_atomic_dec_int(odp_atomic_int_t *ptr)
{
	odp_atomic_fetch_sub_int(ptr, 1);
}

void odp_atomic_init_u32(odp_atomic_u32_t *ptr)
{
	*ptr = 0;
}

uint32_t odp_atomic_load_u32(odp_atomic_u32_t *ptr)
{
	return *ptr;
}


void odp_atomic_store_u32(odp_atomic_u32_t *ptr, uint32_t new_value)
{
	*ptr = new_value;
}

uint32_t odp_atomic_fetch_add_u32(odp_atomic_u32_t *ptr, uint32_t value)
{
	return __sync_fetch_and_add(ptr, value);
}

uint32_t odp_atomic_fetch_sub_u32(odp_atomic_u32_t *ptr, uint32_t value)
{
	return __sync_fetch_and_sub(ptr, value);
}


void odp_atomic_inc_u32(odp_atomic_u32_t *ptr)
{
	odp_atomic_fetch_add_u32(ptr, 1);
}


void odp_atomic_dec_u32(odp_atomic_u32_t *ptr)
{
	odp_atomic_fetch_sub_u32(ptr, 1);
}


void odp_atomic_init_u64(odp_atomic_u64_t *ptr)
{
	*ptr = 0;
}

uint64_t odp_atomic_load_u64(odp_atomic_u64_t *ptr)
{
	return *ptr;
}

void odp_atomic_store_u64(odp_atomic_u64_t *ptr, uint64_t new_value)
{
	*ptr = new_value;
}


uint64_t odp_atomic_fetch_add_u64(odp_atomic_u64_t *ptr, uint64_t value)
{
	return __sync_fetch_and_add(ptr, value);
}


uint64_t odp_atomic_fetch_sub_u64(odp_atomic_u64_t *ptr, uint64_t value)
{
	return __sync_fetch_and_sub(ptr, value);
}


void odp_atomic_inc_u64(odp_atomic_u64_t *ptr)
{
	odp_atomic_fetch_add_u64(ptr, 1);
}


void odp_atomic_dec_u64(odp_atomic_u64_t *ptr)
{
	odp_atomic_fetch_sub_u64(ptr, 1);
}




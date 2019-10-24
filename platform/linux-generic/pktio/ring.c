/* Copyright (c) 2014-2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Derived from FreeBSD's bufring.c
 *
 **************************************************************************
 *
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. The name of Kip Macy nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ***************************************************************************/

#include <odp_api.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <odp_packet_io_ring_internal.h>
#include <odp_errno_define.h>
#include <odp_global_data.h>
#include <odp_align_internal.h>

#include <odp_ring_ptr_internal.h>

#include <odp/api/plat/cpu_inlines.h>

typedef struct {
	/* Rings tailq lock */
	odp_rwlock_t qlock;
	odp_shm_t shm;
} global_data_t;

static global_data_t *global;

/* Initialize tailq_ring */
int _ring_global_init(void)
{	odp_shm_t shm;

	/* Allocate globally shared memory */
	shm = odp_shm_reserve("_odp_ring_global", sizeof(global_data_t),
			      ODP_CACHE_LINE_SIZE, 0);
	if (ODP_SHM_INVALID == shm) {
		ODP_ERR("Shm reserve failed for pktio ring\n");
		return -1;
	}

	global = odp_shm_addr(shm);
	memset(global, 0, sizeof(global_data_t));
	global->shm = shm;

	return 0;
}

int _ring_global_term(void)
{
	if (odp_shm_free(global->shm)) {
		ODP_ERR("Shm free failed for pktio ring\n");
		return -1;
	}
	return 0;
}

/* create the ring */
ring_ptr_t *
_ring_create(const char *name, unsigned count, unsigned flags)
{
	char ring_name[_RING_NAMESIZE];
	ring_ptr_t *r;
	size_t ring_size;
	uint32_t shm_flag;
	odp_shm_t shm;

	if (flags & _RING_SHM_PROC)
		shm_flag = ODP_SHM_PROC | ODP_SHM_EXPORT;
	else
		shm_flag = 0;
	if (odp_global_ro.shm_single_va)
		shm_flag |= ODP_SHM_SINGLE_VA;

	/* count must be a power of 2 */
	if (!CHECK_IS_POWER2(count)) {
		ODP_ERR("Requested size is invalid, must be power of 2,"
			"and do not exceed the size limit %u\n",
			_RING_SZ_MASK);
		__odp_errno = EINVAL;
		return NULL;
	}

	snprintf(ring_name, sizeof(ring_name), "%s", name);
	ring_size = sizeof(ring_ptr_t) + count * sizeof(void *);

	/* reserve a memory zone for this ring.*/
	shm = odp_shm_reserve(ring_name, ring_size, ODP_CACHE_LINE_SIZE,
			      shm_flag);

	r = odp_shm_addr(shm);
	if (r != NULL) {
		/* init the ring structure */
		ring_ptr_init(r);

	} else {
		__odp_errno = ENOMEM;
		ODP_ERR("Cannot reserve memory\n");
	}

	return r;
}

int _ring_destroy(const char *name)
{
	odp_shm_t shm = odp_shm_lookup(name);

	if (shm != ODP_SHM_INVALID)
		return odp_shm_free(shm);

	return 0;
}

/**
 * Return the number of entries in a ring.
 */
unsigned _ring_count(ring_ptr_t *r, uint32_t mask)
{
	uint32_t prod_tail = odp_atomic_load_u32(&r->r.w_tail);
	uint32_t cons_tail = odp_atomic_load_u32(&r->r.r_tail);

	return (prod_tail - cons_tail) & mask;
}

/**
 * Return the number of free entries in a ring.
 */
unsigned _ring_free_count(ring_ptr_t *r, uint32_t mask)
{
	uint32_t prod_tail = odp_atomic_load_u32(&r->r.w_tail);
	uint32_t cons_tail = odp_atomic_load_u32(&r->r.r_tail);

	return (cons_tail - prod_tail - 1) & mask;
}

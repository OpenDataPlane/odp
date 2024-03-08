/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 */

#ifndef ODP_ISHMBUDDY_INTERNAL_H_
#define ODP_ISHMBUDDY_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <odp/api/spinlock.h>

typedef struct _odp_ishm_pool_ctrl_t {
	uint32_t element_sz;    /* 0 for buddy pools, >0 for slab.           */
	int ishm_blk_idx;       /* the block index returned by _ishm_resrve()*/
	odp_spinlock_t  lock;   /* for pool access mutex		     */
	void *user_addr;	/* user pool area ('real user pool')         */
	union {
		struct {	/* things needed for buddy pools:	     */
			uint8_t order;	/* pool is 2^order bytes long	     */
			uint8_t min_order; /*alloc won't go below 2^min_order*/
			void **free_heads; /* 'order' free list heads.	     */
			uint8_t *alloced_order;	/* size of blocks, 0=free    */
		};
		struct {	/* things needed for slab pools:	     */
			void *free_head; /* free element list head	     */
			uint64_t nb_elem;/* total number of elements in pool */
		};
	};
} _odp_ishm_pool_ctrl_t;

typedef struct _odp_ishm_pool_t {
	_odp_ishm_pool_ctrl_t ctrl;	/* control part			     */
	uint8_t mem[1];		/* area for heads, saved alloc'd orders, data*/
} _odp_ishm_pool_t;

_odp_ishm_pool_t *_odp_ishm_pool_create(const char *pool_name,
					uint64_t size,
					uint64_t min_alloc,
					uint64_t max_alloc, int flags);
int _odp_ishm_pool_destroy(_odp_ishm_pool_t *pool);
void *_odp_ishm_pool_alloc(_odp_ishm_pool_t *pool, uint64_t size);
int _odp_ishm_pool_free(_odp_ishm_pool_t *pool, void *addr);
void _odp_ishm_pool_init(void);

#ifdef __cplusplus
}
#endif

#endif

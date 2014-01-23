/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP test ring
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <odp.h>
#include <odp_common.h>
#include <odp_spinlock.h>
#include <odp_ring.h>


#define RING_SIZE 4096
#define MAX_BULK 32

odp_spinlock_t thr_lock;
static odp_ring_t *r;


static int test_ring_basic(void)
{
	void **src = NULL, **cur_src = NULL, **dst = NULL, **cur_dst = NULL;
	int ret;
	unsigned i, num_elems;

	/* alloc dummy object pointers */
	src = malloc(RING_SIZE*2*sizeof(void *));
	if (src == NULL)
		goto fail;

	for (i = 0; i < RING_SIZE*2; i++)
		src[i] = (void *)(unsigned long)i;

	cur_src = src;

	/* alloc some room for copied objects */
	dst = malloc(RING_SIZE*2*sizeof(void *));
	if (dst == NULL)
		goto fail;

	memset(dst, 0, RING_SIZE*2*sizeof(void *));
	cur_dst = dst;

	printf("enqueue 1 obj\n");
	ret = odp_ring_mp_enqueue_bulk(r, cur_src, 1);
	cur_src += 1;
	if (ret != 0)
		goto fail;

	odp_ring_dump(r);

	printf("enqueue 2 objs\n");
	ret = odp_ring_mp_enqueue_bulk(r, cur_src, 2);
	cur_src += 2;
	if (ret != 0)
		goto fail;

	odp_ring_dump(r);

	printf("enqueue MAX_BULK objs\n");
	ret = odp_ring_mp_enqueue_bulk(r, cur_src, MAX_BULK);
	cur_src += MAX_BULK;
	if (ret != 0)
		goto fail;

	odp_ring_dump(r);

	printf("dequeue 1 obj\n");
	ret = odp_ring_mc_dequeue_bulk(r, cur_dst, 1);
	cur_dst += 1;
	if (ret != 0)
		goto fail;

	odp_ring_dump(r);

	printf("dequeue 2 objs\n");
	ret = odp_ring_mc_dequeue_bulk(r, cur_dst, 2);
	cur_dst += 2;
	if (ret != 0)
		goto fail;

	odp_ring_dump(r);

	printf("dequeue MAX_BULK objs\n");
	ret = odp_ring_mc_dequeue_bulk(r, cur_dst, MAX_BULK);
	cur_dst += MAX_BULK;
	if (ret != 0)
		goto fail;

	odp_ring_dump(r);

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		printf("data after dequeue is not the same\n");
		goto fail;
	}

	cur_src = src;
	cur_dst = dst;

	printf("test watermark and default bulk enqueue / dequeue\n");
	odp_ring_set_water_mark(r, 20);
	num_elems = 16;

	cur_src = src;
	cur_dst = dst;

	ret = odp_ring_mp_enqueue_bulk(r, cur_src, num_elems);
	cur_src += num_elems;
	if (ret != 0) {
		printf("Cannot enqueue\n");
		goto fail;
	}
	ret = odp_ring_mp_enqueue_bulk(r, cur_src, num_elems);
	cur_src += num_elems;
	if (ret != -EDQUOT) {
		printf("Watermark not exceeded\n");
		goto fail;
	}
	ret = odp_ring_mc_dequeue_bulk(r, cur_dst, num_elems);
	cur_dst += num_elems;
	if (ret != 0) {
		printf("Cannot dequeue\n");
		goto fail;
	}
	ret = odp_ring_mc_dequeue_bulk(r, cur_dst, num_elems);
	cur_dst += num_elems;
	if (ret != 0) {
		printf("Cannot dequeue2\n");
		goto fail;
	}

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		printf("data after dequeue is not the same\n");
		goto fail;
	}

	printf("basic ring enqueu, dequeue test passed\n");

	if (src)
		free(src);
	if (dst)
		free(dst);
	return 0;

 fail:
	if (src)
		free(src);
	if (dst)
		free(dst);
	return -1;
}

static void *test_ring(void *arg)
{
	pthrd_arg *parg = (pthrd_arg *)arg;
	int thr;
	char ring_name[ODP_RING_NAMESIZE];

	thr = odp_thread_id();

	printf("Thread %i starts\n", thr);

	odp_spinlock_lock(&thr_lock);
	switch (parg->testcase) {
	case ODP_RING_TEST_BASIC:
		snprintf(ring_name, sizeof(ring_name), "test_ring_%i", thr);

		r = odp_ring_create(ring_name, RING_SIZE,
					0 /* not used, alignement
					 taken care inside func : todo */);
		if (r == NULL) {
			printf("ring create failed\n");
			break;
		}

		/* lookup ring from its name :
		add ring_list lookup method (todo) */
		if (odp_ring_lookup(ring_name) != r) {
			printf("ring lookup failed\n");
			break;
		}

		/* basic operations */
		if (test_ring_basic() < 0)
			printf("ring basic enqueue/dequeu ops failed\n");

		break;
	default:
		printf("Invalid test case [%d]\n", parg->testcase);
	}
	odp_spinlock_unlock(&thr_lock);
	fflush(stdout);

	return parg;
}


int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	pthrd_arg thrdarg;

	if (odp_test_global_init() != 0)
		return -1;

	odp_print_system_info();
	odp_spinlock_init(&thr_lock);

	thrdarg.testcase = ODP_RING_TEST_BASIC;
	odp_test_thread_create(test_ring, &thrdarg);

	odp_test_thread_exit();

	return 0;
}


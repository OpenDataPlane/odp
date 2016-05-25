/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP time service
 */

#ifndef ODP_TIME_INTERNAL_H_
#define ODP_TIME_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t (*time_to_ns_fn) (odp_time_t time);
typedef odp_time_t (*time_diff_fn) (odp_time_t t2, odp_time_t t1);
typedef odp_time_t (*time_curr_fn)(void);
typedef int (*time_cmp_fn) (odp_time_t t2, odp_time_t t1);
typedef odp_time_t (*time_sum_fn) (odp_time_t t1, odp_time_t t2);
typedef odp_time_t (*time_local_from_ns_fn) (uint64_t ns);
typedef uint64_t (*time_local_res_fn)(void);
typedef uint64_t (*time_to_u64_fn) (odp_time_t time);

typedef struct time_handler_ {
	time_to_ns_fn         time_to_ns;
	time_diff_fn          time_diff;
	time_curr_fn          time_curr;
	time_cmp_fn           time_cmp;
	time_sum_fn           time_sum;
	time_local_from_ns_fn time_local_from_ns;
	time_local_res_fn     time_local_res;
	time_to_u64_fn        time_to_u64;
} time_handler_t;

#ifdef __cplusplus
}
#endif

#endif

/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#include <odp_queue_if.h>

extern const queue_fn_t queue_scalable_fn;
extern const queue_fn_t queue_default_fn;

#ifdef ODP_SCHEDULE_SCALABLE
const queue_fn_t *queue_fn = &queue_scalable_fn;
#else
const queue_fn_t *queue_fn = &queue_default_fn;
#endif

/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_schedule_internal.h>

extern const schedule_fn_t default_schedule_fn;

const schedule_fn_t *sched_fn = &default_schedule_fn;

/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_schedule_if.h>

extern const schedule_fn_t schedule_sp_fn;
extern const schedule_fn_t schedule_default_fn;

#ifdef ODP_SCHEDULE_SP
const schedule_fn_t *sched_fn = &schedule_sp_fn;
#else
const schedule_fn_t *sched_fn = &schedule_default_fn;
#endif

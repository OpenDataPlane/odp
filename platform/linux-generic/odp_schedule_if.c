/* Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "config.h"

#include <odp_schedule_if.h>

extern const schedule_fn_t schedule_sp_fn;
extern const schedule_fn_t schedule_iquery_fn;
extern const schedule_fn_t schedule_scalable_fn;
extern const schedule_fn_t schedule_default_fn;

#if defined(ODP_SCHEDULE_SP)
const schedule_fn_t *sched_fn = &schedule_sp_fn;
#elif defined(ODP_SCHEDULE_IQUERY)
const schedule_fn_t *sched_fn = &schedule_iquery_fn;
#elif defined(ODP_SCHEDULE_SCALABLE)
const schedule_fn_t *sched_fn = &schedule_scalable_fn;
#else
const schedule_fn_t *sched_fn = &schedule_default_fn;
#endif

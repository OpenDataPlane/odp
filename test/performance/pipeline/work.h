/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef WORK_H_
#define WORK_H_

#include <odp_api.h>

#include "odp_pipeline_work.h"

typedef void *work_t;

work_t work_create_work(const work_param_t *param);

int work_issue(work_t work, odp_event_t ev[], int num);

void work_print_work(work_t work, const char *queue);

void work_destroy_work(work_t work);

#endif

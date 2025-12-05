/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef FLOW_H_
#define FLOW_H_

#include <stdint.h>

#include <odp_api.h>

#include "work.h"

typedef void *flow_t;

typedef enum {
	F_IN = 0,
	F_OUT
} flow_type_t;

flow_t flow_create_flow(char *queue);

uint32_t flow_get_data_size(void);

odp_bool_t flow_add_input(flow_t flow,  work_t *work, uint32_t num);

odp_bool_t flow_add_output(flow_t flow,  work_t *work, uint32_t num);

int flow_issue(flow_type_t type, flow_t flow, odp_event_t ev[], int num);

void flow_destroy_flow(flow_t flow);

#endif

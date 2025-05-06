/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef ORCHESTRATOR_H_
#define ORCHESTRATOR_H_

#include <odp_api.h>

odp_bool_t orchestrator_init(void);

void orchestrator_deploy(void);

void orchestrator_destroy(void);

#endif

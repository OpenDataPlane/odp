/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#ifndef HELPERS_H_
#define HELPERS_H_

#include <stdint.h>

#include <libconfig.h>
#include <odp_api.h>

#define CONCAT_HELPER(a, b) a##b
#define CONCAT(a, b) CONCAT_HELPER(a, b)

odp_bool_t helper_get_uint_elem_checked(const config_setting_t *cs, int idx, uint32_t *val);

#endif

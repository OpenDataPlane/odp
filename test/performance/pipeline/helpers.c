/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Nokia
 */

/** @cond _ODP_HIDE_FROM_DOXYGEN_ */

#include <stdint.h>

#include <libconfig.h>
#include <odp_api.h>

#include "helpers.h"

odp_bool_t helper_get_uint_elem_checked(const config_setting_t *cs, int idx, uint32_t *val)
{
	const config_setting_t *elem = config_setting_get_elem(cs, idx);
	int val_i;

	if (elem == NULL || config_setting_type(elem) != CONFIG_TYPE_INT)
		return false;

	val_i = config_setting_get_int(elem);

	if (val_i < 0)
		return false;

	*val = val_i;

	return true;
}

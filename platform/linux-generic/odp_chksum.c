/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2017-2018 Linaro Limited
 */

#include <odp/api/chksum.h>
#include <odp/api/std_types.h>
#include <odp_chksum_internal.h>

uint16_t odp_chksum_ones_comp16(const void *p, uint32_t len)
{
	return chksum_finalize(chksum_partial(p, len, 0));
}

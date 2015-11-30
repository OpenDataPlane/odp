/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/cpu.h>
#include <odp/hints.h>
#include <odp_cpu_internal.h>

uint64_t odp_cpu_cycles_diff(uint64_t c2, uint64_t c1)
{
	return _odp_cpu_cycles_diff(c2, c1);
}

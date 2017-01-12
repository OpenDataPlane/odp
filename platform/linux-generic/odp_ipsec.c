/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/ipsec.h>

#include <string.h>

int odp_ipsec_capability(odp_ipsec_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_ipsec_capability_t));

	return 0;
}

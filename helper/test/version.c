/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019 Nokia
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdio.h>
#include <string.h>

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
{
	printf("\nHelper library versions is: %s\n\n", odph_version_str());

	return 0;
}

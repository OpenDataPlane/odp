/* Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdio.h>
#include <string.h>

int main(void)
{
	printf("\nHelper library versions is: %s\n\n", odph_version_str());

	return 0;
}

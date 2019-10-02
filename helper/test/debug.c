/* Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/autoheader_external.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdio.h>
#include <string.h>

int main(void)
{
	printf("\nHelper library version is: %s\n\n", odph_version_str());

	printf("Helper debugging:\n");
	printf("  ODPH_DEBUG:       %i\n", ODPH_DEBUG);
	printf("  ODPH_DEBUG_PRINT: %i\n\n", ODPH_DEBUG_PRINT);

	/* ASSERT(true) should work always */
	ODPH_ASSERT(1);

	/* ASSERT(false) should not abort when not debugging */
	if (ODPH_DEBUG == 0)
		ODPH_ASSERT(0);

	return 0;
}

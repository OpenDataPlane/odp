/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019 Nokia
 */

#include <odp/helper/autoheader_external.h>

#include <odp_api.h>
#include <odp/helper/odph_api.h>

#include <stdio.h>
#include <string.h>

int main(int argc ODP_UNUSED, char *argv[] ODP_UNUSED)
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

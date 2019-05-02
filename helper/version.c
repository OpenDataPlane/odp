/* Copyright (c) 2019, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/helper/version.h>

#define VERSION_STR_EXPAND(x)  #x
#define VERSION_TO_STR(x)      VERSION_STR_EXPAND(x)

#define VERSION_STR \
VERSION_TO_STR(ODPH_VERSION_GENERATION) "." \
VERSION_TO_STR(ODPH_VERSION_MAJOR) "." \
VERSION_TO_STR(ODPH_VERSION_MINOR)

const char *odph_version_str(void)
{
	return VERSION_STR;
}

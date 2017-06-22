/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/** enable strtok */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>

#include <example_debug.h>
#include <odp_api.h>
#include <odp_drv.h>
#include <odp/helper/odph_api.h>

int main(int argc, char *argv[])
{
	odp_instance_t instance;

	(void)argc;
	(void)argv;

	EXAMPLE_DBG("Start DDF Application...\n");

	/* Initialize ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Print ddf objects*/
	odpdrv_print_all();

	/* Terminate ODP */
	odp_term_local();
	odp_term_global(instance);

	EXAMPLE_DBG("Exit DDF Application.\n");
	return 0;
}

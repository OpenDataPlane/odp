/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include "odp_drv.h"
#include "ddf_ifs_api.h"
#include "ddf_ifs_enumr_generic.h"

static odpdrv_enumr_t gen_enumr;

static int gen_enumr_probe(void *data __attribute__((__unused__)))
{
	printf("%s() - no devices found\n", __func__);
	return 0;
}

static int gen_enumr_remove(void *data __attribute__((__unused__)))
{
	printf("%s()\n", __func__);
	return 0;
}

static int gen_enumr_register_notif(void (*event_handler) (uint64_t event),
				    int64_t event_mask)
{
	(void)event_handler;
	(void)event_mask;

	printf("%s()\n", __func__);

	return 0;
}

int register_enumerator_generic(odpdrv_enumr_class_t enumr_class)
{
	struct odpdrv_enumr_param_t param = {
		.enumr_class = enumr_class,
		.api_name = DDF_IFS_DEV_API_NAME,
		.api_version = DDF_IFS_DEV_API_VER,
		.probe = gen_enumr_probe,
		.remove = gen_enumr_remove,
		.register_notifier = gen_enumr_register_notif
	};

	printf("\t%s()\n", __func__);

	gen_enumr = odpdrv_enumr_register(&param);
	if (ODPDRV_ENUMR_INVALID == gen_enumr) {
		printf("\tError:failed to %s()\n", __func__);
		return -1;
	}

	return 0;
}

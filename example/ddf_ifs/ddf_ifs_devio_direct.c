/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include "odp_drv.h"
#include "ddf_ifs_api.h"
#include "ddf_ifs_devio_direct.h"

static odpdrv_devio_t devio_direct;

static int devio_direct_probe(odpdrv_device_t dev)
{
	(void)dev;

	printf("%s()\n", __func__);

	return 0;
}

static int devio_direct_remove(void)
{
	printf("%s()\n", __func__);

	return 0;
}

int register_devio_direct(void)
{
	odpdrv_devio_param_t param = {
		.api_name = DDF_IFS_DEVIO_API_NAME,
		.api_version = DDF_IFS_DEVIO_API_VER,
		.enumr_api_name = DDF_IFS_DEV_API_NAME,
		.enumr_api_version = DDF_IFS_DEV_API_VER,
		.probe = devio_direct_probe,
		.remove = devio_direct_remove,
		.ops = NULL
		};

	printf("\t%s()\n", __func__);

	devio_direct = odpdrv_devio_register(&param);
	if (ODPDRV_DEVIO_INVALID == devio_direct) {
		printf("\tError: failed to %s()\n", __func__);
		return -1;
	}

	return 0;
}

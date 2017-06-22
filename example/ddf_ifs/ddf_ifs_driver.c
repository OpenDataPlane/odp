/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include "odp_drv.h"
#include "ddf_ifs_api.h"
#include "ddf_ifs_driver.h"

static odpdrv_driver_t ddf_ifs_driver;
static int drv_data = 12;

static int ddf_ifs_driver_probe(odpdrv_device_t dev, odpdrv_devio_t devio,
				int devio_idx)
{
	printf("%s(dev, devio, devio_idx = %d)\n", __func__, devio_idx);

	(void)devio;

	odpdrv_device_set_data(dev, (void *)&drv_data);

	return 0;
}

static int ddf_ifs_driver_unbind(odpdrv_device_t dev,
				 void (*callback)(odpdrv_device_t dev),
				 uint32_t flags)
{
	printf("%s()\n", __func__);

	if (!(flags & ODPDRV_DRV_UNBIND_IMMEDIATE))
		return -1; /* unsupported*/

	callback(dev);

	return 0;
}

static int ddf_ifs_driver_remove(void)
{
	printf("%s()\n", __func__);

	return 0;
}

int register_driver(void)
{
	odpdrv_driver_param_t param = {
		.name = DDF_IFS_DRV_NAME,
		.devios = {{DDF_IFS_DEVIO_API_NAME, DDF_IFS_DEVIO_API_VER},
				   {"", 0}, {"", 0} },
		.probe = ddf_ifs_driver_probe,
		.unbind = ddf_ifs_driver_unbind,
		.remove = ddf_ifs_driver_remove,
		};

	printf("\t%s()\n", __func__);

	ddf_ifs_driver = odpdrv_driver_register(&param);
	if (ODPDRV_DRIVER_INVALID == ddf_ifs_driver) {
		printf("Error: Failed to %s()\n", __func__);
		return -1;
	}

	return 0;
}

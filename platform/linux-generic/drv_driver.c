/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_config_internal.h>

#include <odp/api/std_types.h>
#include <odp/api/debug.h>
#include <odp/drv/driver.h>
#include <odp_debug_internal.h>

odpdrv_enumr_class_t odpdrv_enumr_class_register(odpdrv_enumr_class_param_t
						 *param)
{
	ODP_ERR("NOT Supported yet! Enumerator Class %s Registration!\n.",
		param->name);

	return ODPDRV_ENUMR_CLASS_INVALID;
}

odpdrv_enumr_t odpdrv_enumr_register(odpdrv_enumr_param_t *param)
{
	ODP_ERR("NOT Supported yet! Enumerator API %s Registration!\n.",
		param->api_name);

	return ODPDRV_ENUMR_INVALID;
}

odpdrv_device_t odpdrv_device_create(odpdrv_device_param_t *param)
{
	ODP_ERR("odpdrv_device_create not Supported yet! devaddress: %s\n.",
		param->address);
	return ODPDRV_DEVICE_INVALID;
}

void odpdrv_device_destroy(odpdrv_device_t dev)
{
	if (dev == ODPDRV_DEVICE_INVALID)
		ODP_ERR("Invalid device\n");
}

odpdrv_devio_t odpdrv_devio_register(odpdrv_devio_param_t *param)
{
	ODP_ERR("NOT Supported yet! Driver %s Registration!\n.",
		param->api_name);

	return ODPDRV_DEVIO_INVALID;
}

odpdrv_driver_t odpdrv_driver_register(odpdrv_driver_param_t *param)
{
	ODP_ERR("NOT Supported yet! Driver %s Registration!\n.",
		param->name);

	return ODPDRV_DRIVER_INVALID;
}

int odpdrv_print_all(void)
{
	ODP_ERR("odpdrv_print_all not Supported yet!\n.");
	return 0;
}

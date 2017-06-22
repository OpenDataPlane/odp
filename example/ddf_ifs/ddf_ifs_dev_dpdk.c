/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include "odp_drv.h"
#include "ddf_ifs_dev_dpdk.h"

odpdrv_device_t dpdk_device_create(odpdrv_enumr_t enumr,
				   const char *dev_addr,
				   void *enum_data)
{
	odpdrv_device_param_t param;

	printf("\t%s(%s)\n", __func__, dev_addr);

	param.enumerator = enumr;
	strcpy(param.address, dev_addr);
	param.enum_dev = enum_data;

	return odpdrv_device_create(&param);
}

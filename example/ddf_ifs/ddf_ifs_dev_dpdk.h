/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _ODP_DDF_IFS_DEV_DPDK_H_
#define _ODP_DDF_IFS_DEV_DPDK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "odp_drv.h"

odpdrv_device_t dpdk_device_create(odpdrv_enumr_t enumr,
				   const char *dev_addr,
				   void *enum_data);

#ifdef __cplusplus
}
#endif

#endif /*_ODP_DDF_IFS_DEV_DPDK_H_*/

/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include "odp_drv.h"
#include "ddf_ifs_api.h"
#include "ddf_ifs_enumr_dpdk.h"
#include "ddf_ifs_dev_dpdk.h"

static odpdrv_enumr_t dpdk_enumr;

#define TEST_DPDK_DEV_CNT 3
#define DDF_DPDK_DEV_MAX 10

static odpdrv_device_t dpdk_dev[DDF_DPDK_DEV_MAX];
static int dpdk_dev_cnt;
static int dpdk_enumr_probe(void *data __attribute__((__unused__)))
{
	int dpdk_dev_cnt_detected = TEST_DPDK_DEV_CNT; /* detected with
							  dpdk APIs*/
	char dev_addr[ODPDRV_NAME_ADDR_SZ];
	int i;

	printf("%s() - %d devices found\n", __func__, dpdk_dev_cnt_detected);

	if (dpdk_dev_cnt_detected > DDF_DPDK_DEV_MAX) {
		dpdk_dev_cnt_detected = DDF_DPDK_DEV_MAX;
		printf("\tWarning: dpdk device count scaled down to %d\n",
		       dpdk_dev_cnt_detected);
	}
	for (i = 0; i < dpdk_dev_cnt_detected; i++) {
		sprintf(dev_addr, "0000:01:00.%d", i);
		dpdk_dev[dpdk_dev_cnt] = dpdk_device_create(dpdk_enumr,
							    dev_addr,
							    NULL);
		if (dpdk_dev[dpdk_dev_cnt] == ODPDRV_DEVICE_INVALID)
			printf("\tError: unable to create device: %s\n",
			       dev_addr);
		else
			dpdk_dev_cnt++;
	}

	return 0;
}

static int dpdk_enumr_remove(void *data __attribute__((__unused__)))
{
	printf("%s()\n", __func__);
	return 0;
}

static int dpdk_enumr_register_notif(void (*event_handler) (uint64_t event),
				     int64_t event_mask)
{
	(void)event_handler;
	(void)event_mask;

	printf("%s()\n", __func__);

	return 0;
}

int register_enumerator_dpdk(odpdrv_enumr_class_t enumr_class)
{
	struct odpdrv_enumr_param_t param = {
		.enumr_class = enumr_class,
		.api_name = DDF_IFS_DEV_API_NAME,
		.api_version = DDF_IFS_DEV_API_VER,
		.probe = dpdk_enumr_probe,
		.remove = dpdk_enumr_remove,
		.register_notifier = dpdk_enumr_register_notif
	};

	printf("\t%s()\n", __func__);

	dpdk_enumr = odpdrv_enumr_register(&param);
	if (ODPDRV_ENUMR_INVALID == dpdk_enumr) {
		printf("\tError: failed to register_enumerator_dpdk()\n");
		return -1;
	}

	return 0;
}

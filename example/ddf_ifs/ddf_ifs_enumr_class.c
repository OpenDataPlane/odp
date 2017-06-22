/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include "odp_drv.h"
#include "ddf_ifs_enumr_class.h"
#include "ddf_ifs_enumr_dpdk.h"
#include "ddf_ifs_enumr_generic.h"

static odpdrv_enumr_class_t enumr_class;

static int enumr_class_ifs_probe(void)
{
	printf("%s()\n", __func__);

	if (register_enumerator_dpdk(enumr_class))
		return -1;

	if (register_enumerator_generic(enumr_class))
		return -1;

	return 0;
}

static int enumr_class_ifs_remove(void)
{
	printf("%s()\n", __func__);

	return 0;
}

int register_enumerator_class(void)
{
	odpdrv_enumr_class_param_t param = {
		.name = "enumr_class_ifs",
		.probe = enumr_class_ifs_probe,
		.remove = enumr_class_ifs_remove
		};

	printf("\t%s()\n", __func__);
	enumr_class = odpdrv_enumr_class_register(&param);

	return 0;
}

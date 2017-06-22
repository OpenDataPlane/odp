/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include "odp_drv.h"
#include "ddf_ifs.h"
#include "ddf_ifs_enumr_class.h"
#include "ddf_ifs_devio_direct.h"
#include "ddf_ifs_driver.h"

static ODPDRV_CONSTRUCTOR void ddf_ifs_construct(void)
{
	printf("%s()\n", __func__);

	register_enumerator_class();

	register_devio_direct();

	register_driver();
}

static __attribute__((destructor)) void ddf_ifs_destruct(void)
{
	printf("%s()\n", __func__);
}

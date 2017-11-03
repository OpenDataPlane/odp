/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* This file is a bit long as it tries to simulate the presence of 2
 * enumerator classes, 2 enumerators, and 3 drivers in one go to
 * see how things are handled by the driver framework.
 * The following is done:
 * - create 2 enumerator classes,
 * - each with its own enumerator providing interfaces: E1 and E2.
 * - E1 and E2 create 4 devices each.
 * - the following devio are created:
 *   devio1 enabling device handling from DRVIF-1 to E1
 *   devio2 enabling device handling from DRVIF-2 to E2
 *   devio3 enabling device handling from DRVIF-3 to E2
 *   devio4 enabling device handling from DRVIF-3 to E3 (does not exist)
 *   devio5 enabling device handling from DRVIF-4 to E3 (does not exist)
 *
 * -then the following driver are created:
 *  driver1, requiring devio DRVIF-1
 *  driver2, requiring devio DRVIF-2 (preferred) and DRVIF-3
 *  driver3, requiring devio DRVIF-4
 *
 * The test amkes sure that:
 * driver 1 is probed (and accepts) the 4 devices of E1 with devio1
 * driver 2 is probed (and rejects) the 4 devices of E2 with devio2 and devio4
 * driver3 is never probed.
 */

#include <odp_drv.h>
#include <odp_api.h>
#include <odp_cunit_common.h>
#include "drvdriver_driver.h"
#include <stdlib.h>

static odp_instance_t odp_instance;
static odpdrv_enumr_class_t enumr_class1;
static odpdrv_enumr_class_t enumr_class2;
static odpdrv_enumr_t enumr1;
static odpdrv_enumr_t enumr2;
#define NB_DEVICES 4
static odpdrv_device_t E1_devs[NB_DEVICES];
static odpdrv_device_t E2_devs[NB_DEVICES];
static odpdrv_devio_t devio1;
static odpdrv_devio_t devio2;
static odpdrv_devio_t devio3;
static odpdrv_devio_t devio4;
static odpdrv_devio_t devio5;
static odpdrv_driver_t driver1;
static odpdrv_driver_t driver2;
static odpdrv_driver_t driver3;

static int driver1_probed_index;
static int driver2_probed_index;

/* forward declaration */
static int enumr1_probe(void);
static int enumr2_probe(void);
static int enumr1_remove(void);
static int enumr2_remove(void);
static int enumr_class1_probe(void);
static int enumr_class2_probe(void);
static int driver1_probe(odpdrv_device_t dev, odpdrv_devio_t devio, int idx);
static int driver2_probe(odpdrv_device_t dev, odpdrv_devio_t devio, int idx);
static int driver3_probe(odpdrv_device_t dev, odpdrv_devio_t devio, int idx);
static int driver1_unbind(odpdrv_device_t dev,
			  void (*callback)(odpdrv_device_t dev),
			  uint32_t flags);
static int driver2_unbind(odpdrv_device_t dev,
			  void (*callback)(odpdrv_device_t dev),
			  uint32_t flags);
static int driver3_unbind(odpdrv_device_t dev,
			  void (*callback)(odpdrv_device_t dev),
			  uint32_t flags);

/* because many things to be checked are performed during ODP initialisation,
 * the initialisation functions have to be a part of the test
 */
static int tests_global_init(void)
{
	if (0 != odp_init_global(&odp_instance, NULL, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}
	if (0 != odp_init_local(odp_instance, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}

	return 0;
}

static int tests_global_term(void)
{
	if (0 != odp_term_local()) {
		fprintf(stderr, "error: odp_term_local() failed.\n");
		return -1;
	}

	if (0 != odp_term_global(odp_instance)) {
		fprintf(stderr, "error: odp_term_global() failed.\n");
		return -1;
	}

	return 0;
}

/*enumerator class register functions, all "statically linked"
 *(i.e. directely run at start), due to the fact that platorm independent
 * shared lib loading in autotools is a mess */
static void ODPDRV_CONSTRUCTOR enumr_class1_register(void)
{
	odpdrv_enumr_class_param_t param = {
		.name = "C1",
		.probe = enumr_class1_probe,
		.remove = NULL
	};

	enumr_class1 = odpdrv_enumr_class_register(&param);
}

static void ODPDRV_CONSTRUCTOR enumr_class2_register(void)
{
	odpdrv_enumr_class_param_t param = {
		.name = "C2",
		.probe = enumr_class2_probe,
		.remove = NULL
	};

	enumr_class2 = odpdrv_enumr_class_register(&param);
}

/*enumerator class probe functions, registering enumerators E1 and E2: */
static int enumr_class1_probe(void)
{
	odpdrv_enumr_param_t param = {
		.enumr_class = enumr_class1,
		.api_name = "E1",
		.api_version = 1,
		.probe = enumr1_probe,
		.remove = enumr1_remove,
		.register_notifier = NULL
	};

	enumr1 = odpdrv_enumr_register(&param);
	CU_ASSERT(enumr1 != ODPDRV_ENUMR_INVALID);

	return 0;
}

static int enumr_class2_probe(void)
{
	odpdrv_enumr_param_t param = {
		.enumr_class = enumr_class2,
		.api_name = "E2",
		.api_version = 1,
		.probe = enumr2_probe,
		.remove = enumr2_remove,
		.register_notifier = NULL
	};

	enumr2 = odpdrv_enumr_register(&param);
	CU_ASSERT(enumr2 != ODPDRV_ENUMR_INVALID);

	return 0;
}

/*enumerator probe functions, creating four devices each: */
static int enumr1_probe(void)
{
	int dev;

	odpdrv_device_param_t param = {
		.enumerator = enumr1,
		.address = "E1:00:0X",
		.enum_dev = NULL
	};

	/* create devices: */
	for (dev = 0; dev < NB_DEVICES; dev++) {
		param.address[7] = '0' + dev; /* change X in the address */
		param.enum_dev = NULL;
		E1_devs[dev] = odpdrv_device_create(&param);
		CU_ASSERT(E1_devs[dev] != ODPDRV_DEVICE_INVALID);
	}

	return 0;
}

static int enumr2_probe(void)
{
	int dev;

	odpdrv_device_param_t param = {
		.enumerator = enumr2,
		.address = "E2:00:0X",
		.enum_dev = NULL
	};

	/* create devices: */
	for (dev = 0; dev < NB_DEVICES; dev++) {
		param.address[7] = '0' + dev; /* change X in the address */
		param.enum_dev = NULL;
		E2_devs[dev] = odpdrv_device_create(&param);
		CU_ASSERT(E1_devs[dev] != ODPDRV_DEVICE_INVALID);
	}

	return 0;
}

/*enumerator remove functions, to remove the enumerated devices: */
static int enumr1_remove(void)
{
	odpdrv_device_t *my_devices;
	odpdrv_device_t *dev;
	int count = 0;

	/* destroy all devices created by enumerator 5: */
	my_devices = odpdrv_device_query(enumr1, NULL);

	for (dev = my_devices; *dev != ODPDRV_DEVICE_INVALID; dev++) {
		odpdrv_device_destroy(*dev, NULL, 0);
		count++;
	}

	CU_ASSERT(count == NB_DEVICES);

	free(my_devices);
	return 0;
}

static int enumr2_remove(void)
{
	odpdrv_device_t *my_devices;
	odpdrv_device_t *dev;
	int count = 0;

	/* destroy all devices created by enumerator 5: */
	my_devices = odpdrv_device_query(enumr2, NULL);

	for (dev = my_devices; *dev != ODPDRV_DEVICE_INVALID; dev++) {
		odpdrv_device_destroy(*dev, NULL, 0);
		count++;
	}

	CU_ASSERT(count == NB_DEVICES);

	free(my_devices);
	return 0;
}

/* devios: */
static void ODPDRV_CONSTRUCTOR devio1_register(void)
{
	odpdrv_devio_param_t param = {
		.api_name = "DRVIF-1",
		.api_version = 1,
		.enumr_api_name = "E1",
		.enumr_api_version = 1,
		.probe = NULL,
		.remove = NULL,
		.ops = NULL,
	};

	devio1 = odpdrv_devio_register(&param);
}

static void ODPDRV_CONSTRUCTOR devio2_register(void)
{
	odpdrv_devio_param_t param = {
		.api_name = "DRVIF-2",
		.api_version = 1,
		.enumr_api_name = "E2",
		.enumr_api_version = 1,
		.probe = NULL,
		.remove = NULL,
		.ops = NULL,
	};

	devio2 = odpdrv_devio_register(&param);
}

static void ODPDRV_CONSTRUCTOR devio3_register(void)
{
	odpdrv_devio_param_t param = {
		.api_name = "DRVIF-3",
		.api_version = 1,
		.enumr_api_name = "E2",
		.enumr_api_version = 1,
		.probe = NULL,
		.remove = NULL,
		.ops = NULL,
	};

	devio3 = odpdrv_devio_register(&param);
}

static void ODPDRV_CONSTRUCTOR devio4_register(void)
{
	odpdrv_devio_param_t param = {
		.api_name = "DRVIF-3",
		.api_version = 1,
		.enumr_api_name = "E3",
		.enumr_api_version = 1,
		.probe = NULL,
		.remove = NULL,
		.ops = NULL,
	};

	devio4 = odpdrv_devio_register(&param);
}

static void ODPDRV_CONSTRUCTOR devio5_register(void)
{
	odpdrv_devio_param_t param = {
		.api_name = "DRVIF-4",
		.api_version = 1,
		.enumr_api_name = "E3",
		.enumr_api_version = 1,
		.probe = NULL,
		.remove = NULL,
		.ops = NULL,
	};

	devio5 = odpdrv_devio_register(&param);
}

static void ODPDRV_CONSTRUCTOR driver1_register(void)
{
	odpdrv_driver_param_t param = {
		.name = "driver1",
		.devios = { {"DRVIF-1", 1}, {"", -1}, {"", -1} },
		.probe = driver1_probe,
		.unbind = driver1_unbind,
		.remove = NULL,
	};

	driver1 = odpdrv_driver_register(&param);
}

static void ODPDRV_CONSTRUCTOR driver2_register(void)
{
	odpdrv_driver_param_t param = {
		.name = "driver2",
		.devios = { {"DRVIF-2", 1}, {"DRVIF-3", 1}, {"", -1} },
		.probe = driver2_probe,
		.unbind = driver2_unbind,
		.remove = NULL,
	};

	driver2 = odpdrv_driver_register(&param);
}

static void ODPDRV_CONSTRUCTOR driver3_register(void)
{
	odpdrv_driver_param_t param = {
		.name = "driver3",
		.devios = { {"DRVIF-4", 1}, {"", -1}, {"", -1} },
		.probe = driver3_probe,
		.unbind = driver3_unbind,
		.remove = NULL,
	};

	driver3 = odpdrv_driver_register(&param);
}

static int driver1_probe(odpdrv_device_t dev, odpdrv_devio_t devio, int idx)
{
	int i;
	int dev_found = 0;

	CU_ASSERT(dev != ODPDRV_DEVICE_INVALID);
	CU_ASSERT(devio == devio1);
	CU_ASSERT(idx < 1);

	/*makes sure the device is from E1 */
	for (i = 0; i < NB_DEVICES; i++) {
		if (dev == E1_devs[i]) {
			driver1_probed_index |= (1 << i);
			dev_found = 1;
			/* just set dev index as driver data */
			odpdrv_device_set_data(dev, (void *)(uintptr_t)i);
		}
	}
	CU_ASSERT(dev_found);
	return 0; /* accept the device */
}

static int driver2_probe(odpdrv_device_t dev, odpdrv_devio_t devio, int idx)
{
	int i;
	int dev_found = 0;

	CU_ASSERT(dev != ODPDRV_DEVICE_INVALID);

	/* check that we are probed with one of the required deviios */
	CU_ASSERT(((devio == devio2) && (idx == 0)) ||
		  ((devio == devio3) && (idx == 1)));

	/*make sure the device is from E2, and probed twice */
	for (i = 0; i < NB_DEVICES; i++) {
		if (dev == E2_devs[i]) {
			/* check that device was probed with idx=0 first */
			if (idx > 0)
				CU_ASSERT(driver2_probed_index & (1 << i));
			/* marked as probed: */
			driver2_probed_index |= (1 << (i + idx * NB_DEVICES));
			dev_found = 1;
		}
	}
	CU_ASSERT(dev_found);
	if (idx == 0)
		return -1; /* reject the device, when probed with idx = 0 */
	return 0; /* accept second probe*/
}

static int driver3_probe(odpdrv_device_t dev, odpdrv_devio_t devio, int idx)
{
	/* we can look for some strangeness here ... */
	CU_ASSERT(dev != ODPDRV_DEVICE_INVALID);
	CU_ASSERT(devio != ODPDRV_DEVIO_INVALID);
	CU_ASSERT(idx >= 0);

	/* but we should not be probing this driver anyway! */
	CU_FAIL("This driver should not be probed");
	return -1; /* reject the device */
}

static int driver1_unbind(odpdrv_device_t dev,
			  void (*callback)(odpdrv_device_t dev),
			  uint32_t flags)
{
	CU_ASSERT(E1_devs[(uintptr_t)odpdrv_device_get_data(dev)] == dev);
	CU_ASSERT(dev != ODPDRV_DEVICE_INVALID);
	CU_ASSERT(flags == ODPDRV_DRV_UNBIND_IMMEDIATE);
	callback(dev);

	return 0;
}

static int driver2_unbind(odpdrv_device_t dev,
			  void (*callback)(odpdrv_device_t dev),
			  uint32_t flags)
{
	CU_ASSERT(dev != ODPDRV_DEVICE_INVALID);
	CU_ASSERT(flags == ODPDRV_DRV_UNBIND_IMMEDIATE);
	callback(dev);

	return 0;
}

static int driver3_unbind(odpdrv_device_t dev,
			  void (*callback)(odpdrv_device_t dev),
			  uint32_t flags)
{
	CU_ASSERT(dev != ODPDRV_DEVICE_INVALID);
	CU_ASSERT(flags == ODPDRV_DRV_UNBIND_IMMEDIATE);
	callback(dev);

	return 0;
}

void drvdriver_test_driver_register(void)
{
	CU_ASSERT(enumr_class1 != ODPDRV_ENUMR_CLASS_INVALID);
	CU_ASSERT(enumr_class2 != ODPDRV_ENUMR_CLASS_INVALID);
	CU_ASSERT(devio1 != ODPDRV_DEVIO_INVALID);
	CU_ASSERT(devio2 != ODPDRV_DEVIO_INVALID);
	CU_ASSERT(devio3 != ODPDRV_DEVIO_INVALID);
	CU_ASSERT(devio4 != ODPDRV_DEVIO_INVALID);
	CU_ASSERT(devio5 != ODPDRV_DEVIO_INVALID);
	CU_ASSERT(driver1 != ODPDRV_DRIVER_INVALID);
	CU_ASSERT(driver2 != ODPDRV_DRIVER_INVALID);
	CU_ASSERT(driver3 != ODPDRV_DRIVER_INVALID);

	CU_ASSERT(tests_global_init() == 0);

	CU_ASSERT(odpdrv_print_all() == 0);

	/* check that expected probing occurred: */
	CU_ASSERT(driver1_probed_index == (1 << NB_DEVICES) - 1);
	CU_ASSERT(driver2_probed_index == (1 << (NB_DEVICES * 2)) - 1);

	CU_ASSERT(tests_global_term() == 0);
}

odp_testinfo_t drvdriver_suite_driver[] = {
	ODP_TEST_INFO(drvdriver_test_driver_register),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t drvdriver_suites_driver[] = {
	{"Enumerator registration", NULL, NULL, drvdriver_suite_driver},
	ODP_SUITE_INFO_NULL,
};

int drvdriver_driver_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	/* prevent default ODP init: */
	odp_cunit_register_global_init(NULL);
	odp_cunit_register_global_term(NULL);

	/* register the tests: */
	ret = odp_cunit_register(drvdriver_suites_driver);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

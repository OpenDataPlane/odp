/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_drv.h>
#include <odp_api.h>
#include <odp_cunit_common.h>
#include "drvdriver_device.h"
#include <stdlib.h>

static odp_instance_t odp_instance;
static odpdrv_enumr_class_t enumr_class1;
static odpdrv_enumr_t enumr1;

typedef struct dev_enumr_data_t { /* enumerator data for registered devices */
	odpdrv_shm_t	shm_handle;
	int		device_number;
} dev_enumr_data_t;

#define NB_DEVICES 5

/* forward declaration */
static int enumr1_probe(void);
static int enumr1_remove(void);
static int enumr_class1_probe(void);
static int enumr_class1_remove(void);

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

/*enumerator register functions */
static odpdrv_enumr_t enumr1_register(void)
{
	odpdrv_enumr_param_t param = {
		.enumr_class = enumr_class1,
		.api_name = "Enumerator_interface_1",
		.api_version = 1,
		.probe = enumr1_probe,
		.remove = enumr1_remove,
		.register_notifier = NULL
	};

	enumr1 = odpdrv_enumr_register(&param);
	return enumr1;
}

/*enumerator probe functions, just making sure they have been run: */
static int enumr1_probe(void)
{
	int dev;
	odpdrv_shm_t shm;
	dev_enumr_data_t *dev_data;

	odpdrv_device_param_t param = {
		.enumerator = enumr1,
		.address = "00:00:0X",
		.enum_dev = NULL
	};

	/* create 5 devices: */
	for (dev = 0; dev < NB_DEVICES; dev++) {
		shm = odpdrv_shm_reserve(NULL, sizeof(dev_enumr_data_t),
					 0, ODPDRV_SHM_SINGLE_VA);
		CU_ASSERT(ODPDRV_SHM_INVALID != shm);
		dev_data = odpdrv_shm_addr(shm);
		CU_ASSERT_PTR_NOT_NULL(dev_data);

		dev_data->shm_handle = shm;
		dev_data->device_number = dev;

		param.address[7] = '0' + dev; /* change X in the address */
		param.enum_dev = dev_data;

		CU_ASSERT(odpdrv_device_create(&param) !=
							ODPDRV_DEVICE_INVALID);
	}

	CU_ASSERT(odpdrv_print_all() == 0);

	return 0;
}

/* enumerator device removal callback function: */
static void  enumr5_device_destroy_terminate(void *priv_data)
{
	dev_enumr_data_t *dev_data;
	int dev_nb;
	odpdrv_shm_t shm;

	dev_data = (dev_enumr_data_t *)priv_data;
	dev_nb = dev_data->device_number;
	printf("removing device number: %d\n", dev_nb);
	CU_ASSERT(dev_nb < NB_DEVICES);
	CU_ASSERT(dev_nb >= 0);
	shm = dev_data->shm_handle;
	CU_ASSERT(!odpdrv_shm_free_by_handle(shm));
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
		odpdrv_device_destroy(*dev, enumr5_device_destroy_terminate, 0);
		count++;
	}

	CU_ASSERT(count == NB_DEVICES);

	free(my_devices);
	return 0;
}

/*enumerator class register functions, all "statically linked"
 *(i.e. directely run at start), due to the fact that platorm independent
 * shared lib loading in autotools is a mess */
static void ODPDRV_CONSTRUCTOR enumr_class1_register(void)
{
	odpdrv_enumr_class_param_t param = {
		.name = "Enumerator_class1",
		.probe = enumr_class1_probe,
		.remove = enumr_class1_remove
	};

	enumr_class1 = odpdrv_enumr_class_register(&param);
}

/*enumerator class probe functions, registering enumerators: */
static int enumr_class1_probe(void)
{
	CU_ASSERT(enumr1_register() != ODPDRV_ENUMR_INVALID);
	return 0;
}

/*enumerator class remove functions, just making sure they have been run: */
static int enumr_class1_remove(void)
{
	return 0;
}

void drvdriver_test_device_register(void)
{
	CU_ASSERT(tests_global_init() == 0);

	/* at this point (after odp init), the 5 devices should be there:
	 */
	CU_ASSERT(odpdrv_print_all() == 0);

	CU_ASSERT(tests_global_term() == 0);
}

odp_testinfo_t drvdriver_suite_device[] = {
	ODP_TEST_INFO(drvdriver_test_device_register),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t drvdriver_suites_device[] = {
	{"Enumerator registration", NULL, NULL, drvdriver_suite_device},
	ODP_SUITE_INFO_NULL,
};

int drvdriver_device_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	/* prevent default ODP init: */
	odp_cunit_register_global_init(NULL);
	odp_cunit_register_global_term(NULL);

	/* register the tests: */
	ret = odp_cunit_register(drvdriver_suites_device);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

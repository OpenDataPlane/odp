/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_drv.h>
#include <odp_api.h>
#include <odp_cunit_common.h>
#include "drvdriver_devio.h"
#include <stdlib.h>

static odp_instance_t odp_instance;

static int devio1_removed;
static int devio2_removed;
static int devio3_removed;
static int devio4_removed;

static int devio1_remove(void);
static int devio2_remove(void);
static int devio3_remove(void);

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

/*devio register functions, all "statically linked"
 *(i.e. directely run at start), due to the fact that platorm independent
 * shared lib loading in autotools is a mess */
static void ODPDRV_CONSTRUCTOR devio1_register(void)
{
	odpdrv_devio_param_t param = {
		.api_name = "devio_api_1",
		.api_version = 1,
		.enumr_api_name = "Enumerator_interface_1",
		.enumr_api_version = 1,
		.remove = devio1_remove,
		.ops = NULL,
	};

	odpdrv_devio_register(&param);
}

static void ODPDRV_CONSTRUCTOR devio2_register(void)
{
	odpdrv_devio_param_t param = {
		.api_name = "devio_api_2",
		.api_version = 1,
		.enumr_api_name = "Enumerator_interface_1",
		.enumr_api_version = 1,
		.probe = NULL,
		.remove = devio2_remove,
		.ops = NULL,
	};

	odpdrv_devio_register(&param);
}

static odpdrv_devio_t devio2_register_retry(void)
{
	odpdrv_devio_param_t param = {
		.api_name = "devio_api_2",
		.api_version = 1,
		.enumr_api_name = "Enumerator_interface_1",
		.enumr_api_version = 1,
		.probe = NULL,
		.remove = NULL,
		.ops = NULL,
	};

	return odpdrv_devio_register(&param);
}

static void ODPDRV_CONSTRUCTOR devio3_register(void)
{
	odpdrv_devio_param_t param = {
		.api_name = "devio_api_2",
		.api_version = 1,
		.enumr_api_name = "Enumerator_interface_2",
		.enumr_api_version = 1,
		.probe = NULL,
		.remove = devio3_remove,
		.ops = NULL,
	};

	odpdrv_devio_register(&param);
}

static void ODPDRV_CONSTRUCTOR devio4_register(void)
{
	odpdrv_devio_param_t param = {
		.api_name = "devio_api_3",
		.api_version = 1,
		.enumr_api_name = "Enumerator_interface_3",
		.enumr_api_version = 1,
		.probe = NULL,
		.remove = NULL,
		.ops = NULL,
	};

	odpdrv_devio_register(&param);
}

/*devio remove functions, just making sure they have been run: */
static int devio1_remove(void)
{
	devio1_removed = 1;
	return 0;
}

/*devio remove functions, just making sure they have been run: */
static int devio2_remove(void)
{
	devio2_removed = 1;
	return 0;
}

/*devio remove functions, just making sure they have been run: */
static int devio3_remove(void)
{
	devio3_removed = 1;
	return 0;
}

void drvdriver_test_devio_register(void)
{
	CU_ASSERT(devio1_removed == 0);
	CU_ASSERT(devio2_removed == 0);
	CU_ASSERT(devio3_removed == 0);
	CU_ASSERT(devio4_removed == 0);

	CU_ASSERT(tests_global_init() == 0);

	/* at this point (after odp init), the constructor
	 * devios should have registered. just print them:
	 */
	CU_ASSERT(odpdrv_print_all() == 0);

	/* re-register devio2: this should be kicked-out! */
	CU_ASSERT(devio2_register_retry() == ODPDRV_DEVIO_INVALID);

	CU_ASSERT(tests_global_term() == 0);

	/* after ODP termination completion, all devios have been removed*/
	CU_ASSERT(devio1_removed == 1);
	CU_ASSERT(devio2_removed == 1);
	CU_ASSERT(devio3_removed == 1);
	CU_ASSERT(devio4_removed == 0); /* has no remove function */
}

odp_testinfo_t drvdriver_suite_devio[] = {
	ODP_TEST_INFO(drvdriver_test_devio_register),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t drvdriver_suites_devio[] = {
	{"Devio registration", NULL, NULL, drvdriver_suite_devio},
	ODP_SUITE_INFO_NULL,
};

int drvdriver_devio_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	/* prevent default ODP init: */
	odp_cunit_register_global_init(NULL);
	odp_cunit_register_global_term(NULL);

	/* register the tests: */
	ret = odp_cunit_register(drvdriver_suites_devio);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

/* Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp_drv.h>
#include <odp_api.h>
#include <odp_cunit_common.h>
#include "drvdriver_enumr_class.h"
#include <stdlib.h>

static odp_instance_t odp_instance;

static int enumr_class1_probed;
static int enumr_class2_probed;

/* forward declaration */
static int enumr_class1_probe(void);
static int enumr_class2_probe(void);

static int enumr_class1_remove(void);
static int enumr_class2_remove(void);

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
		.name = "Enumerator_class1",
		.probe = enumr_class1_probe,
		.remove = enumr_class1_remove
	};

	odpdrv_enumr_class_register(&param);
}

static void ODPDRV_CONSTRUCTOR enumr_class2_register(void)
{
	odpdrv_enumr_class_param_t param = {
		.name = "Enumerator_class2",
		.probe = enumr_class2_probe,
		.remove = enumr_class2_remove
	};

	odpdrv_enumr_class_register(&param);
}

static odpdrv_enumr_class_t enumr_class2_register_retry(void)
{
	odpdrv_enumr_class_param_t param = {
		.name = "Enumerator_class2",
		.probe = enumr_class2_probe,
		.remove = enumr_class2_remove
	};

	return odpdrv_enumr_class_register(&param);
}

/*enumerator class probe functions, just making sure they have been run: */
static int enumr_class1_probe(void)
{
	enumr_class1_probed = 1;
	return 0;
}

static int enumr_class2_probe(void)
{
	enumr_class2_probed = 1;
	return 0;
}

/*enumerator class remove functions, just making sure they have been run: */
static int enumr_class1_remove(void)
{
	enumr_class1_probed = -1;
	return 0;
}

static int enumr_class2_remove(void)
{
	enumr_class2_probed = -1;
	return 0;
}

void drvdriver_test_enumr_class_register(void)
{
	CU_ASSERT(enumr_class1_probed == 0);
	CU_ASSERT(enumr_class2_probed == 0);

	CU_ASSERT(tests_global_init() == 0);

	/* at this point (after odp init), the constructor
	 * enumerator classes should have registered and been probed:
	 */
	CU_ASSERT(odpdrv_print_all() == 0);

	CU_ASSERT(enumr_class1_probed == 1);
	CU_ASSERT(enumr_class2_probed == 1);
	CU_ASSERT(odpdrv_print_all() == 0);

	/* re-register enumr_class2: this should be kicked-out! */
	CU_ASSERT(enumr_class2_register_retry() == ODPDRV_ENUMR_CLASS_INVALID);

	CU_ASSERT(tests_global_term() == 0);

	/* after ODP termination completion, all enumerators should be removed*/
	CU_ASSERT(enumr_class1_probed == -1);
	CU_ASSERT(enumr_class2_probed == -1);
}

odp_testinfo_t drvdriver_suite_enumr_class[] = {
	ODP_TEST_INFO(drvdriver_test_enumr_class_register),
	ODP_TEST_INFO_NULL,
};

odp_suiteinfo_t drvdriver_suites_enumr_class[] = {
	{"Enumerator registration", NULL, NULL, drvdriver_suite_enumr_class},
	ODP_SUITE_INFO_NULL,
};

int drvdriver_enumr_class_main(int argc, char *argv[])
{
	int ret;

	/* parse common options: */
	if (odp_cunit_parse_options(argc, argv))
		return -1;

	/* prevent default ODP init: */
	odp_cunit_register_global_init(NULL);
	odp_cunit_register_global_term(NULL);

	/* register the tests: */
	ret = odp_cunit_register(drvdriver_suites_enumr_class);

	if (ret == 0)
		ret = odp_cunit_run();

	return ret;
}

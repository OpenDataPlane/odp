/* Copyright (c) 2014-2018, Linaro Limited
 * Copyright (c) 2019-2022, Nokia
 * Copyright (c) 2021, Marvell
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <odp_api.h>
#include "odp_cunit_common.h"
#include <odp/helper/odph_api.h>

#include <CUnit/TestDB.h>

#if defined __GNUC__ && (((__GNUC__ == 4) && \
			(__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#endif
#include <CUnit/Automated.h>
#if defined __GNUC__ && (((__GNUC__ == 4) && \
			(__GNUC_MINOR__ >= 4)) || (__GNUC__ > 4))
#pragma GCC diagnostic pop
#endif

/* Globals */
static int allow_skip_result;
static odph_thread_t thread_tbl[MAX_WORKERS];
static int threads_running;
static odp_instance_t instance;
static char *progname;
static int (*thread_func)(void *);

/*
 * global init/term functions which may be registered
 * defaults to functions performing odp init/term.
 */
static int tests_global_init(odp_instance_t *inst);
static int tests_global_term(odp_instance_t inst);
static struct {
	int (*global_init_ptr)(odp_instance_t *inst);
	int (*global_term_ptr)(odp_instance_t inst);
} global_init_term = {tests_global_init, tests_global_term};

static odp_suiteinfo_t *global_testsuites;

#define MAX_STR_LEN 256
#define MAX_FAILURES 10

/* Recorded assertion failure for later CUnit call in the initial thread */
typedef struct assertion_failure_t {
	char cond[MAX_STR_LEN];
	char file[MAX_STR_LEN];
	unsigned int line;
	int fatal;
} assertion_failure_t;

typedef struct thr_global_t {
	assertion_failure_t failure[MAX_FAILURES];
	unsigned long num_failures;
} thr_global_t;

static thr_global_t *thr_global;

static __thread int initial_thread = 1; /* Are we the initial thread? */
static __thread jmp_buf longjmp_env;

void odp_cu_assert(CU_BOOL value, unsigned int line,
		   const char *condition, const char *file, CU_BOOL fatal)
{
	unsigned long idx;

	if (initial_thread) {
		CU_assertImplementation(value, line, condition, file, "", fatal);
		return;
	}

	/* Assertion ok, just return */
	if (value)
		return;

	/*
	 * Non-initial thread/process cannot call CUnit assert because:
	 *
	 * - CU_assertImplementation() is not thread-safe
	 * - In process mode an assertion failure would be lost because it
	 *   would not be recorded in the memory of the initial process.
	 * - Fatal asserts in CUnit perform longjmp which cannot be done in
	 *   an other thread or process that did the setjmp.
	 *
	 * --> Record the assertion failure in shared memory so that it can be
	 *     processed later in the context of the initial thread/process.
	 * --> In fatal assert, longjmp within the current thread.
	 */

	idx = __atomic_fetch_add(&thr_global->num_failures, 1, __ATOMIC_RELAXED);

	if (idx < MAX_FAILURES) {
		assertion_failure_t *a = &thr_global->failure[idx];

		strncpy(a->cond, condition, sizeof(a->cond));
		strncpy(a->file, file, sizeof(a->file));
		a->cond[sizeof(a->cond) - 1] = 0;
		a->file[sizeof(a->file) - 1] = 0;
		a->line = line;
		a->fatal = fatal;
	}

	if (fatal)
		longjmp(longjmp_env, 1);
}

static void handle_postponed_asserts(void)
{
	unsigned long num = thr_global->num_failures;

	if (num > MAX_FAILURES)
		num = MAX_FAILURES;

	for (unsigned long n = 0; n < num; n++) {
		assertion_failure_t *a = &thr_global->failure[n];

		/*
		 * Turn fatal failures into non-fatal failures as we are just
		 * reporting them. Threads that saw fatal failures which
		 * prevented them from continuing have already been stopped.
		 */
		CU_assertImplementation(0, a->line, a->cond, a->file, "", CU_FALSE);
	}
	thr_global->num_failures = 0;
}

static int threads_init(void)
{
	static int initialized;

	if (initialized)
		return 0;

	/*
	 * Use shared memory mapping for the global structure to make it
	 * visible in the child processes if running in process mode.
	 */
	thr_global = mmap(NULL, sizeof(thr_global_t),
			  PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS,
			  -1, 0);
	if (thr_global == MAP_FAILED)
		return -1;

	initialized = 1;
	return 0;
}

static int run_thread(void *arg)
{
	int rc;

	/* Make sure this is zero also in process mode "threads" */
	initial_thread = 0;

	if (setjmp(longjmp_env) == 0) {
		/* Normal return, proceed to the thread function. */
		rc = (*thread_func)(arg);
	} else {
		/*
		 * Return from longjmp done by the thread function.
		 * We return 0 here since odph_thread_join() does not like
		 * nonzero exit statuses.
		 */
		rc = 0;
	}

	return rc;
}

int odp_cunit_thread_create(int num, int func_ptr(void *), void *const arg[], int priv)
{
	int i, ret;
	odp_cpumask_t cpumask;
	odph_thread_common_param_t thr_common;
	odph_thread_param_t thr_param[num];

	if (threads_running) {
		/* thread_tbl is already in use */
		fprintf(stderr, "error: %s: threads already running\n", __func__);
		return -1;
	}

	thread_func = func_ptr;

	odph_thread_common_param_init(&thr_common);

	if (arg == NULL)
		priv = 0;

	for (i = 0; i < num; i++) {
		odph_thread_param_init(&thr_param[i]);

		thr_param[i].start    = run_thread;
		thr_param[i].thr_type = ODP_THREAD_WORKER;

		if (arg)
			thr_param[i].arg = arg[i];
		else
			thr_param[i].arg = NULL;

		if (priv == 0)
			break;
	}

	odp_cpumask_default_worker(&cpumask, num);

	thr_common.instance    = instance;
	thr_common.cpumask     = &cpumask;
	thr_common.share_param = !priv;

	/* Create and start additional threads */
	ret = odph_thread_create(thread_tbl, &thr_common, thr_param, num);

	if (ret != num)
		fprintf(stderr, "error: odph_thread_create() failed.\n");

	threads_running = (ret > 0);

	return ret;
}

int odp_cunit_thread_join(int num)
{
	/* Wait for threads to exit */
	if (odph_thread_join(thread_tbl, num) != num) {
		fprintf(stderr, "error: odph_thread_join() failed.\n");
		return -1;
	}
	threads_running = 0;
	thread_func = 0;

	handle_postponed_asserts();

	return 0;
}

static int tests_global_init(odp_instance_t *inst)
{
	odp_init_t init_param;
	odph_helper_options_t helper_options;

	if (odph_options(&helper_options)) {
		fprintf(stderr, "error: odph_options() failed.\n");
		return -1;
	}

	odp_init_param_init(&init_param);
	init_param.mem_model = helper_options.mem_model;

	if (0 != odp_init_global(inst, &init_param, NULL)) {
		fprintf(stderr, "error: odp_init_global() failed.\n");
		return -1;
	}
	if (0 != odp_init_local(*inst, ODP_THREAD_CONTROL)) {
		fprintf(stderr, "error: odp_init_local() failed.\n");
		return -1;
	}
	if (0 != odp_schedule_config(NULL)) {
		fprintf(stderr, "error: odp_schedule_config(NULL) failed.\n");
		return -1;
	}

	return 0;
}

static int tests_global_term(odp_instance_t inst)
{
	if (0 != odp_term_local()) {
		fprintf(stderr, "error: odp_term_local() failed.\n");
		return -1;
	}

	if (0 != odp_term_global(inst)) {
		fprintf(stderr, "error: odp_term_global() failed.\n");
		return -1;
	}

	return 0;
}

/*
 * register tests_global_init and tests_global_term functions.
 * If some of these functions are not registered, the defaults functions
 * (tests_global_init() and tests_global_term()) defined above are used.
 * One should use these register functions when defining these hooks.
 * Note that passing NULL as function pointer is valid and will simply
 * prevent the default (odp init/term) to be done.
 */
void odp_cunit_register_global_init(int (*func_init_ptr)(odp_instance_t *inst))
{
	global_init_term.global_init_ptr = func_init_ptr;
}

void odp_cunit_register_global_term(int (*func_term_ptr)(odp_instance_t inst))
{
	global_init_term.global_term_ptr = func_term_ptr;
}

static odp_suiteinfo_t *cunit_get_suite_info(const char *suite_name)
{
	odp_suiteinfo_t *sinfo;

	for (sinfo = global_testsuites; sinfo->name; sinfo++)
		if (strcmp(sinfo->name, suite_name) == 0)
			return sinfo;

	return NULL;
}

static odp_testinfo_t *cunit_get_test_info(odp_suiteinfo_t *sinfo,
					   const char *test_name)
{
	odp_testinfo_t *tinfo;

	for (tinfo = sinfo->testinfo_tbl; tinfo->name; tinfo++)
		if (strcmp(tinfo->name, test_name) == 0)
				return tinfo;

	return NULL;
}

/* A wrapper for the suite's init function. This is done to allow for a
 * potential runtime check to determine whether each test in the suite
 * is active (enabled by using ODP_TEST_INFO_CONDITIONAL()). If present,
 * the conditional check is run after the suite's init function.
 */
static int _cunit_suite_init(void)
{
	int ret = 0;
	CU_pSuite cur_suite = CU_get_current_suite();
	odp_suiteinfo_t *sinfo;
	odp_testinfo_t *tinfo;

	/* find the suite currently being run */
	cur_suite = CU_get_current_suite();
	if (!cur_suite)
		return -1;

	sinfo = cunit_get_suite_info(cur_suite->pName);
	if (!sinfo)
		return -1;

	/* execute its init function */
	if (sinfo->init_func) {
		ret = sinfo->init_func();
		if (ret)
			return ret;
	}

	/* run any configured conditional checks and mark inactive tests */
	for (tinfo = sinfo->testinfo_tbl; tinfo->name; tinfo++) {
		CU_pTest ptest;
		CU_ErrorCode err;

		if (!tinfo->check_active || tinfo->check_active())
			continue;

		/* test is inactive, mark it as such */
		ptest = CU_get_test_by_name(tinfo->name, cur_suite);
		if (ptest)
			err = CU_set_test_active(ptest, CU_FALSE);
		else
			err = CUE_NOTEST;

		if (err != CUE_SUCCESS) {
			fprintf(stderr, "%s: failed to set test %s inactive\n",
				__func__, tinfo->name);
			return -1;
		}
	}

	return ret;
}

/* Print names of all inactive tests of the suite. This should be called by
 * every suite terminate function. Otherwise, inactive tests are not listed in
 * test suite results. */
int odp_cunit_print_inactive(void)
{
	CU_pSuite cur_suite;
	CU_pTest ptest;
	odp_suiteinfo_t *sinfo;
	odp_testinfo_t *tinfo;
	int first = 1;

	cur_suite = CU_get_current_suite();
	if (cur_suite == NULL)
		return -1;

	sinfo = cunit_get_suite_info(cur_suite->pName);
	if (sinfo == NULL)
		return -1;

	for (tinfo = sinfo->testinfo_tbl; tinfo->name; tinfo++) {
		ptest = CU_get_test_by_name(tinfo->name, cur_suite);
		if (ptest == NULL) {
			fprintf(stderr, "%s: test not found: %s\n",
				__func__, tinfo->name);
			return -1;
		}

		if (ptest->fActive)
			continue;

		if (first) {
			printf("\n\nSuite: %s\n", sinfo->name);
			printf("  Inactive tests:\n");
			first = 0;
		}

		printf("    %s\n", tinfo->name);
	}

	return 0;
}

int odp_cunit_set_inactive(void)
{
	CU_pSuite cur_suite;
	CU_pTest ptest;
	odp_suiteinfo_t *sinfo;
	odp_testinfo_t *tinfo;

	cur_suite = CU_get_current_suite();
	if (cur_suite == NULL)
		return -1;

	sinfo = cunit_get_suite_info(cur_suite->pName);
	if (sinfo == NULL)
		return -1;

	for (tinfo = sinfo->testinfo_tbl; tinfo->name; tinfo++) {
		ptest = CU_get_test_by_name(tinfo->name, cur_suite);
		if (ptest == NULL) {
			fprintf(stderr, "%s: test not found: %s\n",
				__func__, tinfo->name);
			return -1;
		}
		CU_set_test_active(ptest, false);
	}

	return 0;
}

static int default_term_func(void)
{
	return odp_cunit_print_inactive();
}

static void _cunit_test_setup_func(void)
{
	CU_AllTestsCompleteMessageHandler all_test_comp_handler;
	CU_SuiteCompleteMessageHandler suite_comp_handler;
	CU_pFailureRecord failrec;
	CU_pSuite suite;

	if (!getenv("ODP_CUNIT_FAIL_IMMEDIATE"))
		return;

	if (CU_get_number_of_failure_records() == 0)
		return;

	/* User wants the suite to fail immediately once a test hits an error */
	suite = CU_get_current_suite();
	failrec = CU_get_failure_list();

	printf("Force aborting as a previous test failed\n");

	/* Call the Cleanup functions before aborting */
	suite->pCleanupFunc();

	suite_comp_handler = CU_get_suite_complete_handler();
	if (suite_comp_handler)
		suite_comp_handler(suite, failrec);

	all_test_comp_handler = CU_get_all_test_complete_handler();
	if (all_test_comp_handler)
		all_test_comp_handler(failrec);

	exit(EXIT_FAILURE);
}

/*
 * Register suites and tests with CUnit.
 *
 * Similar to CU_register_suites() but using locally defined wrapper
 * types.
 */
static int cunit_register_suites(odp_suiteinfo_t testsuites[])
{
	odp_suiteinfo_t *sinfo;
	odp_testinfo_t *tinfo;
	CU_pSuite suite;
	CU_pTest test;
	CU_CleanupFunc term_func;

	for (sinfo = testsuites; sinfo->name; sinfo++) {
		term_func = default_term_func;
		if (sinfo->term_func)
			term_func = sinfo->term_func;

		suite = CU_add_suite_with_setup_and_teardown(sinfo->name, _cunit_suite_init,
							     term_func, _cunit_test_setup_func,
							     NULL);
		if (!suite)
			return CU_get_error();

		for (tinfo = sinfo->testinfo_tbl; tinfo->name; tinfo++) {
			test = CU_add_test(suite, tinfo->name,
					   tinfo->test_func);
			if (!test)
				return CU_get_error();
		}
	}

	return 0;
}

static int cunit_update_test(CU_pSuite suite,
			     odp_suiteinfo_t *sinfo,
			     odp_testinfo_t *updated_tinfo)
{
	CU_pTest test = NULL;
	CU_ErrorCode err;
	odp_testinfo_t *tinfo;
	const char *test_name = updated_tinfo->name;

	tinfo = cunit_get_test_info(sinfo, test_name);
	if (tinfo)
		test = CU_get_test(suite, test_name);

	if (!tinfo || !test) {
		fprintf(stderr, "%s: unable to find existing test named %s\n",
			__func__, test_name);
		return -1;
	}

	err = CU_set_test_func(test, updated_tinfo->test_func);
	if (err != CUE_SUCCESS) {
		fprintf(stderr, "%s: failed to update test func for %s\n",
			__func__, test_name);
		return -1;
	}

	tinfo->check_active = updated_tinfo->check_active;

	return 0;
}

static int cunit_update_suite(odp_suiteinfo_t *updated_sinfo)
{
	CU_pSuite suite = NULL;
	CU_ErrorCode err;
	odp_suiteinfo_t *sinfo;
	odp_testinfo_t *tinfo;

	/* find previously registered suite with matching name */
	sinfo = cunit_get_suite_info(updated_sinfo->name);

	if (sinfo) {
		/* lookup the associated CUnit suite */
		suite = CU_get_suite_by_name(updated_sinfo->name,
					     CU_get_registry());
	}

	if (!sinfo || !suite) {
		fprintf(stderr, "%s: unable to find existing suite named %s\n",
			__func__, updated_sinfo->name);
		return -1;
	}

	sinfo->init_func = updated_sinfo->init_func;
	sinfo->term_func = updated_sinfo->term_func;

	err = CU_set_suite_cleanupfunc(suite, updated_sinfo->term_func);
	if (err != CUE_SUCCESS) {
		fprintf(stderr, "%s: failed to update cleanup func for %s\n",
			__func__, updated_sinfo->name);
		return -1;
	}

	for (tinfo = updated_sinfo->testinfo_tbl; tinfo->name; tinfo++) {
		int ret;

		ret = cunit_update_test(suite, sinfo, tinfo);
		if (ret != 0)
			return ret;
	}

	return 0;
}

/*
 * Run tests previously registered via odp_cunit_register()
 */
int odp_cunit_run(void)
{
	int ret;

	printf("\tODP API version: %s\n", odp_version_api_str());
	printf("\tODP implementation name:    %s\n", odp_version_impl_name());
	printf("\tODP implementation version: %s\n", odp_version_impl_str());

	if (getenv("ODP_TEST_OUT_XML")) {
		CU_set_output_filename(progname);
		CU_automated_run_tests();
	} else {
		CU_basic_set_mode(CU_BRM_VERBOSE);
		CU_basic_run_tests();
	}

	ret = CU_get_number_of_failure_records();

	CU_cleanup_registry();

	/* call test executable terminason hook, if any */
	if (global_init_term.global_term_ptr &&
	    ((*global_init_term.global_term_ptr)(instance) != 0))
		return -1;

	return (ret) ? -1 : 0;
}

/*
 * Update suites/tests previously registered via odp_cunit_register().
 *
 * Note that this is intended for modifying the properties of already
 * registered suites/tests. New suites/tests can only be registered via
 * odp_cunit_register().
 */
int odp_cunit_update(odp_suiteinfo_t testsuites[])
{
	int ret = 0;
	odp_suiteinfo_t *sinfo;

	for (sinfo = testsuites; sinfo->name && ret == 0; sinfo++)
		ret = cunit_update_suite(sinfo);

	return ret;
}

/*
 * Register test suites to be run via odp_cunit_run()
 */
int odp_cunit_register(odp_suiteinfo_t testsuites[])
{
	if (threads_init())
		return -1;

	/* call test executable init hook, if any */
	if (global_init_term.global_init_ptr) {
		if ((*global_init_term.global_init_ptr)(&instance) == 0) {
			/* After ODP initialization, set main thread's
			 * CPU affinity to the 1st available control CPU core
			 */
			int cpu = 0;
			odp_cpumask_t cpuset;

			odp_cpumask_zero(&cpuset);
			if (odp_cpumask_default_control(&cpuset, 1) == 1) {
				cpu = odp_cpumask_first(&cpuset);
				odph_odpthread_setaffinity(cpu);
			}
		} else {
			/* ODP initialization failed */
			return -1;
		}
	}

	CU_set_error_action(CUEA_ABORT);

	CU_initialize_registry();
	global_testsuites = testsuites;
	cunit_register_suites(testsuites);
	CU_set_fail_on_inactive(CU_FALSE);

	return 0;
}

/*
 * Parse command line options to extract options affectiong cunit_common.
 * (hence also helpers options as cunit_common uses the helpers)
 * Options private to the test calling cunit_common are not parsed here.
 */
int odp_cunit_parse_options(int argc, char *argv[])
{
	const char *env = getenv("CI");

	progname = argv[0];
	odph_parse_options(argc, argv);

	if (env && !strcmp(env, "true")) {
		allow_skip_result = 1;
		ODPH_DBG("\nWARNING: test result can be used for code coverage only.\n"
			 "CI=true env variable is set!\n");
	}

	return 0;
}

int odp_cunit_ret(int val)
{
	return allow_skip_result ? 0 : val;
}

int odp_cunit_ci_skip(const char *test_name)
{
	const char *ci_skip;
	const char *found;

	ci_skip = getenv("CI_SKIP");
	if (ci_skip == NULL)
		return 0;

	found = strstr(ci_skip, test_name);

	return found != NULL;
}

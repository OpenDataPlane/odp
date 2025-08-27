/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2014-2018 Linaro Limited
 * Copyright (c) 2020-2025 Nokia
 */

/**
 * @file
 *
 * ODP test application common headers
 */

#ifndef ODP_CUNIT_COMMON_H
#define ODP_CUNIT_COMMON_H

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <CUnit/Basic.h>
#include <odp_api.h>

typedef int (*cunit_test_check_active)(void);

typedef struct {
	const char             *name;
	CU_TestFunc             test_func;
	cunit_test_check_active check_active;
} odp_testinfo_t;

typedef struct {
	const char       *name;
	CU_InitializeFunc init_func;
	CU_CleanupFunc    term_func;
	odp_testinfo_t   *testinfo_tbl;
} odp_suiteinfo_t;

static inline int odp_cunit_test_inactive(void) { return 0; }
static inline void odp_cunit_test_missing(void) { }

/* An active test case, with the test name matching the test function name */
#define ODP_TEST_INFO(test_func) \
	{#test_func, test_func, NULL}

/* A test case that is unconditionally inactive. Its name will be registered
 * with CUnit but it won't be executed and will be reported as inactive in
 * the result summary. */
#define ODP_TEST_INFO_INACTIVE(test_func, ...) \
	{#test_func, odp_cunit_test_missing, odp_cunit_test_inactive}

#define ODP_TEST_INACTIVE 0
#define ODP_TEST_ACTIVE   1

/* A test case that may be marked as inactive at runtime based on the
 * return value of the cond_func function. A return value of ODP_TEST_INACTIVE
 * means inactive, ODP_TEST_ACTIVE means active. */
#define ODP_TEST_INFO_CONDITIONAL(test_func, cond_func) \
	{#test_func, test_func, cond_func}

#define ODP_TEST_INFO_NULL {NULL, NULL, NULL}
#define ODP_SUITE_INFO_NULL {NULL, NULL, NULL, NULL}

typedef struct {
	uint32_t foo;
	uint32_t bar;
} test_shared_data_t;

/* parse parameters that affect the behaviour of odp_cunit_common */
int odp_cunit_parse_options(int *argc, char *argv[]);
/* register suites to be run via odp_cunit_run() */
int odp_cunit_register(odp_suiteinfo_t testsuites[]);
/* update tests previously registered via odp_cunit_register() */
int odp_cunit_update(odp_suiteinfo_t testsuites[]);
/* the function, called by module main(), to run the testsuites: */
int odp_cunit_run(void);

/* Create threads for a validation test
 *
 * Thread arguments table (arg[]) can be set to NULL, when there are no arguments.
 * When 'priv' is 0, the same argument pointer (arg[0]) is passed to all threads. Otherwise,
 * a pointer is passed (from arg[]) to each thread. When 'sync' is 1, thread
 * creation is synchronized (odph_thread_common_param_t.sync).
 * Returns number of threads created on success, < 0 on error.
 */
int odp_cunit_thread_create(int num, int func_ptr(void *arg), void *const arg[],
			    int priv, int sync);

/* Wait for previously created threads to exit */
int odp_cunit_thread_join(int num);

/**
 * Global tests initialization/termination.
 *
 * Initialize global resources needed by the test executable. Default
 * definition does ODP init / term (both global and local).
 * Test executables can override it by calling one of the register function
 * below.
 * The functions are called at the very beginning and very end of the test
 * execution. Passing NULL to odp_cunit_register_global_init() and/or
 * odp_cunit_register_global_term() is legal and will simply prevent the
 * default (ODP init/term) to be done.
 */
void odp_cunit_register_global_init(int (*func_init_ptr)(odp_instance_t *inst));

void odp_cunit_register_global_term(int (*func_term_ptr)(odp_instance_t inst));

int odp_cunit_ret(int val);
int odp_cunit_ci(void);
int odp_cunit_print_inactive(void);
int odp_cunit_set_inactive(void);

/* Check from CI_SKIP environment variable if the test case should be skipped by CI */
int odp_cunit_ci_skip(const char *test_name);

void odp_cu_assert(CU_BOOL value, unsigned int line,
		   const char *condition, const char *file, CU_BOOL fatal);

/*
 * Wrapper for CU_assertImplementation for the fatal asserts to show the
 * compiler and static analyzers that the function does not return if the
 * assertion fails. This reduces bogus warnings generated from the code
 * after the fatal assert.
 */
static inline void odp_cu_assert_fatal(CU_BOOL value, unsigned int line,
				       const char *condition, const char *file)
{
	odp_cu_assert(value, line, condition, file, CU_TRUE);

	if (!value) {
		/* not reached */
		abort();  /* this has noreturn function attribute */
		for (;;) /* this also shows that return is not possible */
			;
	}
}

/*
 * Redefine the macros used in ODP. Do it without the do-while idiom for
 * compatibility with CU and existing code that assumes this kind of macros.
 */

#undef CU_ASSERT
#define CU_ASSERT(value) \
	{ odp_cu_assert((value), __LINE__, #value, __FILE__, CU_FALSE); }

#undef CU_ASSERT_FATAL
#define CU_ASSERT_FATAL(value) \
	{ odp_cu_assert_fatal((value), __LINE__, #value, __FILE__); }

#undef CU_FAIL
#define CU_FAIL(msg) \
	{ odp_cu_assert(CU_FALSE, __LINE__, ("CU_FAIL(" #msg ")"), __FILE__, CU_FALSE); }

#undef CU_FAIL_FATAL
#define CU_FAIL_FATAL(msg) \
	{ odp_cu_assert_fatal(CU_FALSE, __LINE__, ("CU_FAIL_FATAL(" #msg ")"), __FILE__); }

#undef CU_ASSERT_TRUE
#undef CU_ASSERT_TRUE_FATAL
#undef CU_ASSERT_FALSE
#undef CU_ASSERT_FALSE_FATAL
#undef CU_ASSERT_EQUAL
#undef CU_ASSERT_EQUAL_FATAL
#undef CU_ASSERT_NOT_EQUAL
#undef CU_ASSERT_NOT_EQUAL_FATAL
#undef CU_ASSERT_PTR_EQUAL
#undef CU_ASSERT_PTR_EQUAL_FATAL
#undef CU_ASSERT_PTR_NOT_EQUAL
#undef CU_ASSERT_PTR_NOT_EQUAL_FATAL
#undef CU_ASSERT_PTR_NULL
#undef CU_ASSERT_PTR_NULL_FATAL
#undef CU_ASSERT_PTR_NOT_NULL
#undef CU_ASSERT_PTR_NOT_NULL_FATAL
#undef CU_ASSERT_STRING_EQUAL
#undef CU_ASSERT_STRING_EQUAL_FATAL
#undef CU_ASSERT_STRING_NOT_EQUAL
#undef CU_ASSERT_STRING_NOT_EQUAL_FATAL
#undef CU_ASSERT_NSTRING_EQUAL
#undef CU_ASSERT_NSTRING_EQUAL_FATAL
#undef CU_ASSERT_NSTRING_NOT_EQUAL
#undef CU_ASSERT_NSTRING_NOT_EQUAL_FATAL
#undef CU_ASSERT_DOUBLE_EQUAL
#undef CU_ASSERT_DOUBLE_EQUAL_FATAL
#undef CU_ASSERT_DOUBLE_NOT_EQUAL
#undef CU_ASSERT_DOUBLE_NOT_EQUAL_FATAL

#endif /* ODP_CUNIT_COMMON_H */

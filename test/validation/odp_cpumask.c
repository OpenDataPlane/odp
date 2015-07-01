/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include "odp_cunit_common.h"


/*
 * The following string are used to build cpu masks with
 * odp_cpumask_from_str(). Both 0x prefixed and non prefixed
 * hex values are supported by odp_cpumask_from_str()
 */
#define TEST_MASK_NO_CPU      "0x0"
#define TEST_MASK_CPU_0       "0x1"
#define TEST_MASK_CPU_1       "0x2"
#define TEST_MASK_CPU_2       "0x4"
#define TEST_MASK_CPU_0_2     "0x5"
#define TEST_MASK_CPU_0_3     "0x9"
#define TEST_MASK_CPU_1_2     "0x6"
#define TEST_MASK_CPU_1_3     "0xA"
#define TEST_MASK_CPU_0_1_2   "0x7"
#define TEST_MASK_CPU_0_2_4_6 "0x55"
#define TEST_MASK_CPU_1_2_4_6 "0x56"

#define TEST_MASK_CPU_0_NO_PREFIX       "1"

/* padding pattern used to check buffer overflow: */
#define FILLING_PATTERN 0x55



/*
 * returns the length of a string, excluding terminating NULL.
 * As its C lib strlen equivalent. Just rewritten here to avoid C lib
 * dependency in ODP tests (for platform independent / bare metal testing)
 */
static unsigned int stringlen(const char *str)
{
	unsigned int i = 0;

	while (str[i] != 0)
		i++;
	return i;
}

/*
 * builds a string containing a 0x prefixed hex number
 * where a single bit (corresponding to cpu) is set.
 * The string is null terminated.
 * cpu_to_str(0) returns "0x1".
 * cpu_to_str(10) returns "0x400".
 * The buffer should be at least ceil(cpu/4)+3 bytes long,
 * to accommodate with 4 cpus per nibble + "0x" prefix + null.
 */
#define CPUS_PER_NIBBLE 4
static void cpu_to_str(char *buff, int cpu)
{
	const char *hex_nibble = "1248";
	int i = 0;
	buff[i++] = '0';
	buff[i++] = 'x';
	buff[i++] = hex_nibble[cpu % CPUS_PER_NIBBLE];
	while (cpu > 3) {
		buff[i++] = '0';
		cpu -= CPUS_PER_NIBBLE;
	}
	buff[i++] = 0; /* null */
}

/*
 * returns the mask size to be tested...
 * There is a bit of confusion right now about how to get this,
 * so this is centralized here... in case of change...
 */
static unsigned int get_max_number_of_cpus_in_a_mask(void)
{
	return odp_cpu_count();
}


static void test_odp_cpumask_to_from_str(void)
{
	odp_cpumask_t mask;
	int32_t str_sz;
	unsigned int buf_sz; /* buf size for the 2 following bufs */
	char *buf_in;
	char *buf_out;
	unsigned int cpu;
	unsigned int i;

	/* makes sure the mask has room for at least 1 CPU...: */
	CU_ASSERT_FATAL(get_max_number_of_cpus_in_a_mask() > 0);

	/* allocate memory for the buffers containing the mask strings:
	   1 char per nibble, i.e. 1 char per 4 cpus +extra for "0x" and null:*/
	buf_sz = (get_max_number_of_cpus_in_a_mask() >> 2) + 20;
	buf_in  = malloc(buf_sz);
	buf_out = malloc(buf_sz);
	CU_ASSERT_FATAL((buf_in != NULL) && (buf_out != NULL));

	/* test 1 CPU at a time for all possible cpu positions in the mask */
	for (cpu = 0; cpu < get_max_number_of_cpus_in_a_mask(); cpu++) {
		/* init buffer for overwrite check: */
		for (i = 0; i < buf_sz; i++)
			buf_out[i] = FILLING_PATTERN;

		/* generate a hex string with that cpu set: */
		cpu_to_str(buf_in, cpu);

		/* generate mask: */
		odp_cpumask_from_str(&mask, buf_in);

		/* reverse cpu mask computation to get string back: */
		str_sz = odp_cpumask_to_str(&mask, buf_out,
					    stringlen(buf_in) + 1);

		/* check that returned size matches original (with NULL): */
		CU_ASSERT(str_sz == (int32_t)stringlen(buf_in) + 1);

		/* check that returned string matches original (with NULL): */
		CU_ASSERT_NSTRING_EQUAL(buf_out, buf_in, stringlen(buf_in) + 1);

		/* check that no extra buffer writes occurred: */
		CU_ASSERT(buf_out[stringlen(buf_in) + 2] == FILLING_PATTERN);
	}

	/* re-init buffer for overwrite check: */
	for (i = 0; i < buf_sz; i++)
		buf_out[i] = FILLING_PATTERN;

	/* check for buffer overflow when too small buffer given: */
	odp_cpumask_from_str(&mask, TEST_MASK_CPU_0);
	str_sz = odp_cpumask_to_str(&mask, buf_out, stringlen(TEST_MASK_CPU_0));

	CU_ASSERT(str_sz == -1);

	for (i = 0; i < buf_sz; i++)
		CU_ASSERT(buf_out[i] == FILLING_PATTERN);

	/* check for handling of missing "0x" prefix: */
	odp_cpumask_from_str(&mask, TEST_MASK_CPU_0_NO_PREFIX);

	str_sz = odp_cpumask_to_str(&mask, buf_out,
				    stringlen(TEST_MASK_CPU_0) + 1);

	CU_ASSERT_NSTRING_EQUAL(buf_out, TEST_MASK_CPU_0,
				stringlen(TEST_MASK_CPU_0) + 1);

	free(buf_out);
	free(buf_in);
}

static void test_odp_cpumask_equal(void)
{
	odp_cpumask_t mask1;
	odp_cpumask_t mask2;
	odp_cpumask_t mask3;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask3, TEST_MASK_NO_CPU);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));
	CU_ASSERT_FALSE(odp_cpumask_equal(&mask1, &mask3));

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0_2);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0_2);
	odp_cpumask_from_str(&mask3, TEST_MASK_CPU_1_2);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));
	CU_ASSERT_FALSE(odp_cpumask_equal(&mask1, &mask3));

	if (get_max_number_of_cpus_in_a_mask() < 8)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0_2_4_6);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0_2_4_6);
	odp_cpumask_from_str(&mask3, TEST_MASK_CPU_1_2_4_6);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));
	CU_ASSERT_FALSE(odp_cpumask_equal(&mask1, &mask3));
}

static void test_odp_cpumask_zero(void)
{
	odp_cpumask_t mask1;
	odp_cpumask_t mask2;
	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0);
	odp_cpumask_zero(&mask2);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));
}

static void test_odp_cpumask_set(void)
{
	odp_cpumask_t mask1;
	odp_cpumask_t mask2;
	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0);
	odp_cpumask_set(&mask1, 0);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0_3);
	odp_cpumask_set(&mask1, 3);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));

	/* make sure that re-asserting a cpu has no impact: */
	odp_cpumask_set(&mask1, 3);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));
}

static void test_odp_cpumask_clr(void)
{
	odp_cpumask_t mask1;
	odp_cpumask_t mask2;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask2, TEST_MASK_NO_CPU);
	odp_cpumask_clr(&mask1, 0);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0_2);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0);
	odp_cpumask_clr(&mask1, 2);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));

	odp_cpumask_from_str(&mask2, TEST_MASK_NO_CPU);
	odp_cpumask_clr(&mask1, 0);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));

	/* make sure that re-clearing a cpu has no impact: */
	odp_cpumask_clr(&mask1, 0);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));
}

static void test_odp_cpumask_isset(void)
{
	odp_cpumask_t mask1;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	CU_ASSERT(odp_cpumask_isset(&mask1, 0));

	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	CU_ASSERT_FALSE(odp_cpumask_isset(&mask1, 0));

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0_2);
	CU_ASSERT(odp_cpumask_isset(&mask1, 0));
	CU_ASSERT_FALSE(odp_cpumask_isset(&mask1, 1));
	CU_ASSERT(odp_cpumask_isset(&mask1, 2));
	CU_ASSERT_FALSE(odp_cpumask_isset(&mask1, 3));
}

static void test_odp_cpumask_count(void)
{
	odp_cpumask_t mask1;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	CU_ASSERT(odp_cpumask_count(&mask1) == 1);

	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	CU_ASSERT(odp_cpumask_count(&mask1) == 0);

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0_2);
	CU_ASSERT(odp_cpumask_count(&mask1) == 2);
}

static void test_odp_cpumask_and(void)
{
	odp_cpumask_t mask1;
	odp_cpumask_t mask2;
	odp_cpumask_t mask3;
	odp_cpumask_t mask4;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask4, TEST_MASK_CPU_0);
	odp_cpumask_and(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));

	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask4, TEST_MASK_NO_CPU);
	odp_cpumask_and(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));

	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask2, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask4, TEST_MASK_NO_CPU);
	odp_cpumask_and(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0_2);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_1_2);
	odp_cpumask_from_str(&mask4, TEST_MASK_CPU_2);
	odp_cpumask_and(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));
}

static void test_odp_cpumask_or(void)
{
	odp_cpumask_t mask1;
	odp_cpumask_t mask2;
	odp_cpumask_t mask3;
	odp_cpumask_t mask4;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask4, TEST_MASK_CPU_0);
	odp_cpumask_or(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));

	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask4, TEST_MASK_CPU_0);
	odp_cpumask_or(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));

	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask2, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask4, TEST_MASK_NO_CPU);
	odp_cpumask_or(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0_2);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_1);
	odp_cpumask_from_str(&mask4, TEST_MASK_CPU_0_1_2);
	odp_cpumask_or(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));
}

static void test_odp_cpumask_xor(void)
{
	odp_cpumask_t mask1;
	odp_cpumask_t mask2;
	odp_cpumask_t mask3;
	odp_cpumask_t mask4;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask4, TEST_MASK_NO_CPU);
	odp_cpumask_xor(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));

	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_0);
	odp_cpumask_from_str(&mask4, TEST_MASK_CPU_0);
	odp_cpumask_xor(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));

	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask2, TEST_MASK_NO_CPU);
	odp_cpumask_from_str(&mask4, TEST_MASK_NO_CPU);
	odp_cpumask_xor(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_2);
	odp_cpumask_from_str(&mask2, TEST_MASK_CPU_1_2);
	odp_cpumask_from_str(&mask4, TEST_MASK_CPU_1);
	odp_cpumask_xor(&mask3, &mask1, &mask2);
	CU_ASSERT(odp_cpumask_equal(&mask3, &mask4));
}

static void test_odp_cpumask_copy(void)
{
	odp_cpumask_t mask1;
	odp_cpumask_t mask2;
	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	odp_cpumask_copy(&mask2, &mask1);
	CU_ASSERT(odp_cpumask_equal(&mask1, &mask2));
}

static void test_odp_cpumask_first(void)
{
	odp_cpumask_t mask1;

	/* check when there is no first */
	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	CU_ASSERT(odp_cpumask_first(&mask1) == -1);

	/* single CPU case: */
	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	CU_ASSERT(odp_cpumask_first(&mask1) == 0);

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_1_3);
	CU_ASSERT(odp_cpumask_first(&mask1) == 1);
}

static void test_odp_cpumask_last(void)
{
	odp_cpumask_t mask1;

	/* check when there is no last: */
	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	CU_ASSERT(odp_cpumask_last(&mask1) == -1);

	/* single CPU case: */
	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	CU_ASSERT(odp_cpumask_last(&mask1) == 0);

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_1_3);
	CU_ASSERT(odp_cpumask_last(&mask1) == 3);
}

static void test_odp_cpumask_next(void)
{
	unsigned int i;
	int expected[] = {1, 3, 3, -1};
	odp_cpumask_t mask1;

	/* case when the mask does not contain any CPU: */
	odp_cpumask_from_str(&mask1, TEST_MASK_NO_CPU);
	CU_ASSERT(odp_cpumask_next(&mask1, -1) == -1);

	/* case when the mask just contain CPU 0: */
	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_0);
	CU_ASSERT(odp_cpumask_next(&mask1, -1) == 0);
	CU_ASSERT(odp_cpumask_next(&mask1, 0)  == -1);

	if (get_max_number_of_cpus_in_a_mask() < 4)
		return;

	odp_cpumask_from_str(&mask1, TEST_MASK_CPU_1_3);

	for (i = 0; i < sizeof(expected) / sizeof(int); i++)
		CU_ASSERT(odp_cpumask_next(&mask1, i) == expected[i]);
}

static CU_TestInfo test_odp_cpumask[] = {
	{"odp_cpumask_to/from_str()", test_odp_cpumask_to_from_str},
	{"odp_cpumask_equal()"	    , test_odp_cpumask_equal},
	{"odp_cpumask_zero()"	    , test_odp_cpumask_zero},
	{"odp_cpumask_set()"	    , test_odp_cpumask_set},
	{"odp_cpumask_clr()"	    , test_odp_cpumask_clr},
	{"odp_cpumask_isset()"	    , test_odp_cpumask_isset},
	{"odp_cpumask_count()"	    , test_odp_cpumask_count},
	{"odp_cpumask_and()"	    , test_odp_cpumask_and},
	{"odp_cpumask_or()"	    , test_odp_cpumask_or},
	{"odp_cpumask_xor()"	    , test_odp_cpumask_xor},
	{"odp_cpumask_copy()"	    , test_odp_cpumask_copy},
	{"odp_cpumask_first()"	    , test_odp_cpumask_first},
	{"odp_cpumask_last()"	    , test_odp_cpumask_last},
	{"odp_cpumask_next()"	    , test_odp_cpumask_next},
	CU_TEST_INFO_NULL,
};

static CU_SuiteInfo cpumask_suites[] = {
	{"Cpumask", NULL, NULL, NULL, NULL, test_odp_cpumask},
	CU_SUITE_INFO_NULL,
};

static int cpumask_main(void)
{
	return odp_cunit_run(cpumask_suites);
}

/* the following main function will be separated when lib is created */
int main(void)
{
	return cpumask_main();
}

include $(top_srcdir)/example/Makefile.inc

bin_PROGRAMS = odp_generator

odp_generator_SOURCES = odp_generator.c

TEST_EXTENSIONS = .sh

if test_example
TESTS = generator_null_test.sh
TESTS_ENVIRONMENT += ODP_PLATFORM=$(with_platform)
endif
EXTRA_DIST = generator_null_test.sh

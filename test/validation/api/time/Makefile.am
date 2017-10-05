include ../Makefile.inc

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

TESTSCRIPTS = time.sh
TEST_EXTENSIONS = .sh

TESTS = $(TESTSCRIPTS)

test_PROGRAMS = time_main$(EXEEXT)
time_main_SOURCES = time_main.c time.c time_test.h
time_main_LDADD = $(LIBCUNIT_COMMON) $(LIBODP)

dist_check_SCRIPTS = $(TESTSCRIPTS)
test_SCRIPTS = $(dist_check_SCRIPTS)

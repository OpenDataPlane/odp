include ../Makefile.inc

TESTS_ENVIRONMENT += TEST_DIR=${builddir}

TESTSCRIPTS = time.sh
TEST_EXTENSIONS = .sh

TESTS = $(TESTSCRIPTS)

noinst_LTLIBRARIES = libtesttime.la
libtesttime_la_SOURCES = time.c

test_PROGRAMS = time_main$(EXEEXT)
dist_time_main_SOURCES = time_main.c
time_main_LDADD = libtesttime.la $(LIBCUNIT_COMMON) $(LIBODP)

EXTRA_DIST = time_test.h $(TESTSCRIPTS)
dist_check_SCRIPTS = $(TESTSCRIPTS)

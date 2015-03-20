include $(top_srcdir)/test/Makefile.inc

TESTS_ENVIRONMENT = TEST_DIR=${builddir}

EXECUTABLES = odp_atomic

COMPILE_ONLY = odp_scheduling

TESTSCRIPTS = odp_scheduling_run

if test_perf
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

odp_atomic_LDFLAGS = $(AM_LDFLAGS) -static
odp_atomic_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/test
odp_scheduling_LDFLAGS = $(AM_LDFLAGS) -static
odp_scheduling_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/test

noinst_HEADERS = \
		  $(top_srcdir)/test/test_debug.h

dist_odp_atomic_SOURCES = odp_atomic.c
dist_odp_scheduling_SOURCES = odp_scheduling.c

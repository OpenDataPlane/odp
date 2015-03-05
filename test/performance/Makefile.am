include $(top_srcdir)/test/Makefile.inc

EXECUTABLES =

COMPILE_ONLY = odp_scheduling

TESTSCRIPTS = odp_scheduling_run

if test_perf
TESTS = $(EXECUTABLES) $(TESTSCRIPTS)
endif

bin_PROGRAMS = $(EXECUTABLES) $(COMPILE_ONLY)

odp_scheduling_LDFLAGS = $(AM_LDFLAGS) -static
odp_scheduling_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/test

noinst_HEADERS = \
		  $(top_srcdir)/test/test_debug.h

dist_odp_scheduling_SOURCES = odp_scheduling.c

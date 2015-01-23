include $(top_srcdir)/test/Makefile.inc

if test_perf
TESTS = odp_scheduling
check_PROGRAMS = ${bin_PROGRAMS}
endif

bin_PROGRAMS = odp_scheduling
odp_scheduling_LDFLAGS = $(AM_LDFLAGS) -static
odp_scheduling_CFLAGS = $(AM_CFLAGS) -I${top_srcdir}/test

noinst_HEADERS = \
		  $(top_srcdir)/test/test_debug.h

dist_odp_scheduling_SOURCES = odp_scheduling.c
